"use strict";

const $ = (selector) => document.querySelector(selector);
const placeholders = {
  domain: "example.com",
  ip: "203.0.113.10",
  url: "https://example.com/about",
  email: "consenting.user@example.com",
  username: "public_handle",
  hash: "64-character SHA-256 hash",
};

function isPrivateIPv4(value) {
  const parts = value.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  return parts[0] === 10 || parts[0] === 127 || parts[0] === 0 ||
    (parts[0] === 169 && parts[1] === 254) || (parts[0] === 192 && parts[1] === 168) ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31);
}

function validateTarget(type, raw) {
  const value = raw.trim();
  if (!value || value.length > 2048 || /[\r\n\0]/.test(value)) throw new Error("Enter one valid target.");
  if (type === "domain" && !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(value)) throw new Error("Enter a valid public domain.");
  if (type === "ip") {
    if (!TraceAtlasTargetValidation.isPublicIpAddress(value)) throw new Error("Enter a public IP address.");
  }
  if (type === "url") {
    let parsed;
    try { parsed = new URL(value); } catch { throw new Error("Enter a valid HTTP or HTTPS URL."); }
    const host = parsed.hostname.replace(/^\[|\]$/g, "");
    if ((host.includes(":") || /^[0-9.]+$/.test(host)) && !TraceAtlasTargetValidation.isPublicIpAddress(host)) throw new Error("Enter a public HTTP or HTTPS URL.");
    if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname || parsed.username || parsed.password || parsed.hostname === "localhost" || isPrivateIPv4(parsed.hostname)) throw new Error("Enter a public HTTP or HTTPS URL without credentials.");
  }
  if (type === "email" && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) throw new Error("Enter a valid email address with consent.");
  if (type === "username" && !/^[a-z0-9_.-]{1,64}$/i.test(value)) throw new Error("Use 1–64 letters, numbers, dot, underscore or hyphen.");
  if (type === "hash" && !/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(value)) throw new Error("Enter an MD5, SHA-1 or SHA-256 hex digest.");
  return value;
}

function shellQuote(value) {
  if (/^[a-zA-Z0-9_@%+=:,./-]+$/.test(value)) return value;
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

async function caseId(target) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(target));
  return `rk-${Array.from(new Uint8Array(digest)).slice(0, 6).map((part) => part.toString(16).padStart(2, "0")).join("")}`;
}

function buildCommand(argv, target, id) {
  return argv.map((token) => shellQuote(token.replaceAll("{target}", target).replaceAll("{case_id}", id))).join(" ");
}

function renderPlan(plan, target, id) {
  const list = $("#commands");
  list.replaceChildren();
  for (const step of plan.steps) {
    const item = document.createElement("li");
    const label = document.createElement("b");
    const code = document.createElement("code");
    const button = document.createElement("button");
    const command = buildCommand(step.argv, target, id);
    label.textContent = step.label;
    code.textContent = command;
    button.type = "button";
    button.className = "copy";
    button.textContent = "COPY";
    button.addEventListener("click", async () => {
      await navigator.clipboard.writeText(command);
      button.textContent = "COPIED";
      setTimeout(() => { button.textContent = "COPY"; }, 1400);
    });
    item.append(label, button, code);
    list.append(item);
  }
  $("#result-title").textContent = `${plan.engine} / ${plan.target_type} / ${id}`;
  $("#result").hidden = false;
  $("#result").scrollIntoView({ behavior: "smooth", block: "start" });
}

$("#target-type").addEventListener("change", (event) => {
  $("#target").placeholder = placeholders[event.target.value];
});

$("#plan-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const error = $("#form-error");
  error.textContent = "";
  try {
    if (!$("#authorized").checked) throw new Error("Authorization confirmation is required.");
    const type = $("#target-type").value;
    const target = validateTarget(type, $("#target").value);
    const response = await fetch("/api/plan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target_type: type, engine: $("#engine").value, authorized: true }),
    });
    const plan = await response.json();
    if (!response.ok) throw new Error(plan.error || "Planner request failed.");
    renderPlan(plan, target, await caseId(target));
  } catch (reason) {
    error.textContent = reason instanceof Error ? reason.message : "Unable to create the plan.";
  }
});

fetch("/api/catalog").then((response) => response.ok ? response.json() : Promise.reject())
  .then((catalog) => {
    $("#version").textContent = catalog.version;
    for (const [name, value] of Object.entries(catalog.metrics)) {
      const element = document.querySelector(`[data-metric="${name}"]`);
      if (element) element.textContent = String(value);
    }
  }).catch(() => {});

const control = { organisations: [], cases: [], assets: [], jobs: [], reviews: [], notes: [] };
const workflowForType = { domain: "domain_passive", ip: "ip_passive", url: "url_metadata", hash: "hash_reputation" };

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin", ...options,
    headers: options.body ? { "Content-Type": "application/json", ...(options.headers || {}) } : options.headers,
  });
  let body = {};
  try { body = await response.json(); } catch { body = {}; }
  if (!response.ok) throw new Error(body.error || `request_failed_${response.status}`);
  return body;
}

function option(value, label) {
  const item = document.createElement("option");
  item.value = value;
  item.textContent = label;
  return item;
}

function fillSelect(element, rows, label) {
  element.replaceChildren();
  element.append(option("", rows.length ? `Select ${label}` : `No ${label} available`));
  for (const row of rows) element.append(option(row.id, row.name || row.title || row.label || row.id));
}

function renderJobs() {
  const list = $("#job-list");
  list.replaceChildren();
  if (!control.jobs.length) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "No jobs queued.";
    list.append(empty);
    return;
  }
  for (const job of control.jobs.slice(0, 30)) {
    const row = document.createElement("div");
    row.className = "record";
    const title = document.createElement("b");
    const state = document.createElement("span");
    const meta = document.createElement("span");
    title.textContent = job.kind;
    state.textContent = job.status.toUpperCase();
    state.className = ["completed", "running"].includes(job.status) ? "ready" : job.status === "failed" ? "failed" : "";
    meta.textContent = `${job.id.slice(0, 8)} · attempt ${job.attempt}`;
    row.append(title, state, meta);
    list.append(row);
  }
}

function renderReviews() {
  const list = $("#review-list");
  list.replaceChildren();
  if (!control.reviews.length) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "No review tasks for this case.";
    list.append(empty);
    $("#review-decision-form").hidden = true;
    return;
  }
  for (const task of control.reviews) {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "record review-record";
    const title = document.createElement("b");
    const state = document.createElement("span");
    const meta = document.createElement("span");
    title.textContent = task.title;
    state.textContent = task.status.toUpperCase();
    state.className = task.status === "pending" ? "running" : task.status === "accepted" ? "ready" : "failed";
    meta.textContent = `${task.kind} · ${task.priority}`;
    row.append(title, state, meta);
    if (task.status === "pending") row.addEventListener("click", () => {
      $("#review-task").value = task.id;
      $("#review-rationale").value = "";
      $("#review-decision-form").hidden = false;
      $("#review-rationale").focus();
    });
    list.append(row);
    if (task.context?.type === "employee-brief") {
      const details = document.createElement("details");
      const summary = document.createElement("summary");
      const snapshot = document.createElement("pre");
      summary.textContent = "Read the evidence and scenario snapshot before deciding";
      snapshot.className = "employee-evidence";
      snapshot.textContent = JSON.stringify(task.context, null, 2);
      details.append(summary, snapshot);
      list.append(details);
    }
  }
}

function renderNotes() {
  const list = $("#note-list");
  list.replaceChildren();
  for (const note of control.notes) {
    const row = document.createElement("div");
    row.className = "record";
    const title = document.createElement("b");
    const body = document.createElement("span");
    title.textContent = note.classification.toUpperCase();
    body.textContent = note.body;
    row.append(title, body);
    list.append(row);
  }
}

function renderInvestigation(view) {
  const summary = $("#investigation-summary");
  const coverage = $("#investigation-coverage");
  const timeline = $("#investigation-timeline");
  summary.replaceChildren();
  coverage.replaceChildren();
  timeline.replaceChildren();
  if (!view) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "Select a case.";
    summary.append(empty);
    return;
  }
  const metrics = document.createElement("div");
  metrics.className = "investigation-metrics";
  for (const [label, value] of Object.entries(view.overview || {})) {
    const metric = document.createElement("div");
    const number = document.createElement("b");
    const name = document.createElement("span");
    number.textContent = String(value);
    name.textContent = label.replaceAll("_", " ");
    metric.append(number, name);
    metrics.append(metric);
  }
  const review = document.createElement("p");
  review.className = "boundary";
  review.textContent = `Pending review: ${view.review_queue?.pending || 0} · failed sources: ${view.review_queue?.failed_runs || 0}`;
  summary.append(metrics, review);
  for (const [source, states] of Object.entries(view.coverage || {})) {
    const row = document.createElement("div");
    row.className = "coverage-record";
    const name = document.createElement("b");
    const values = document.createElement("span");
    name.textContent = source;
    values.textContent = Object.entries(states || {}).map(([state, count]) => `${state}: ${count}`).join(" · ");
    row.append(name, values);
    coverage.append(row);
  }
  for (const item of (view.timeline || []).slice(0, 20)) {
    const row = document.createElement("div");
    row.className = "record";
    const label = document.createElement("b");
    const state = document.createElement("span");
    const date = document.createElement("span");
    label.textContent = `${item.kind}: ${item.label}`;
    state.textContent = String(item.state).toUpperCase();
    state.className = item.state === "failed" ? "failed" : item.state === "completed" ? "ready" : "";
    date.textContent = new Date(item.at).toLocaleString();
    row.append(label, state, date);
    timeline.append(row);
  }
}

async function loadInvestigation(caseIdValue) {
  renderInvestigation(caseIdValue ? await api(`/api/workspace?case_id=${encodeURIComponent(caseIdValue)}`) : null);
}

async function loadReviews(caseIdValue) {
  control.reviews = caseIdValue ? (await api(`/api/reviews?case_id=${encodeURIComponent(caseIdValue)}`)).reviews || [] : [];
  renderReviews();
}

async function loadNotes(caseIdValue) {
  control.notes = caseIdValue ? (await api(`/api/notes?case_id=${encodeURIComponent(caseIdValue)}`)).notes || [] : [];
  renderNotes();
}

function syncAssetChoices() {
  const selectedCase = control.cases.find((item) => item.id === $("#job-case").value);
  const assets = selectedCase ? control.assets.filter((item) => item.organisation_id === selectedCase.organisation_id) : [];
  fillSelect($("#job-asset"), assets, "owned asset");
}

async function loadWorkspace() {
  const [organisations, cases, assets, jobs] = await Promise.all([
    api("/api/organisations"), api("/api/cases"), api("/api/assets"), api("/api/jobs"),
  ]);
  control.organisations = organisations.organisations || [];
  control.cases = cases.cases || [];
  control.assets = assets.assets || [];
  control.jobs = jobs.jobs || [];
  fillSelect($("#case-organisation"), control.organisations, "organisation");
  fillSelect($("#asset-organisation"), control.organisations, "organisation");
  fillSelect($("#job-case"), control.cases, "case");
  fillSelect($("#investigation-case"), control.cases, "case");
  fillSelect($("#graph-case"), control.cases, "case");
  fillSelect($("#review-case"), control.cases, "case");
  fillSelect($("#notes-case"), control.cases, "case");
  fillSelect($("#employee-case"), control.cases, "case");
  document.dispatchEvent(new Event("traceatlas-workspace-changed"));
  syncAssetChoices();
  renderJobs();
}

function graphElement(name, attributes = {}) {
  const element = document.createElementNS("http://www.w3.org/2000/svg", name);
  for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, String(value));
  return element;
}

let activeGraph = null;
let activePath = null;
let graphRequest = 0;

function resetGraph() {
  graphRequest++;
  activeGraph = null;
  activePath = null;
  $("#case-graph").replaceChildren();
  $("#graph-details").replaceChildren();
  $("#graph-status").textContent = "";
  $("#graph-empty").hidden = false;
  $("#graph-empty").textContent = "Select a case or import an export.";
  for (const selector of ["#graph-from", "#graph-to"]) $(selector).replaceChildren(option("", "Select entity"));
}

function graphFilters() {
  return { query: $("#graph-query").value, classification: $("#graph-class").value,
    minConfidence: Number($("#graph-confidence").value) };
}

function graphDetails(node) {
  const panel = $("#graph-details");
  panel.replaceChildren();
  const title = document.createElement("b");
  title.textContent = `${node.type}: ${node.label}`;
  const metadata = document.createElement("p");
  metadata.textContent = `${node.classification} · confidence ${node.confidence ?? "unknown"} · source ${node.source} · ${node.at || "time unknown"}`;
  panel.append(title, metadata);
  const description = document.createElement("p");
  description.textContent = node.details;
  panel.append(description);
  for (const ref of node.evidence_ids) {
    const evidence = activeGraph.evidence.find((item) => item.id === ref);
    const row = document.createElement("p");
    row.textContent = evidence ? `Evidence ${ref} · ${evidence.source} · SHA-256 ${evidence.content_hash || "unavailable"}` : `Evidence ${ref} · unavailable in this snapshot`;
    panel.append(row);
  }
}

function renderGraph() {
  const canvas = $("#case-graph");
  const empty = $("#graph-empty");
  canvas.replaceChildren();
  if (!activeGraph) return;
  const model = TraceAtlasGraph;
  const visible = model.filterGraph(activeGraph, graphFilters());
  const nodes = visible.nodes.slice(0, model.LIMITS.drawNodes);
  const ids = new Set(nodes.map((node) => node.id));
  const edges = visible.edges.filter((edge) => ids.has(edge.source) && ids.has(edge.target)).slice(0, model.LIMITS.drawEdges);
  const drawn = { nodes, edges };
  const positions = model.layout(drawn, $("#graph-layout").value);
  let bounds = model.viewport(positions);
  const setViewport = () => canvas.setAttribute("viewBox", `${bounds.x} ${bounds.y} ${bounds.width} ${bounds.height}`);
  setViewport();
  empty.hidden = nodes.length > 0;
  empty.textContent = "No entities match these filters.";
  const warnings = activeGraph.warnings.slice(0, 3).join(" ");
  const clipping = visible.nodes.length > nodes.length || visible.edges.length > edges.length;
  $("#graph-status").textContent = `${activeGraph.format} · ${visible.nodes.length} entities · ${visible.edges.length} links · completeness ${activeGraph.completeness.state}${clipping ? " · drawing capped; narrow filters to inspect more" : ""}. ${warnings}`;
  const pathNodes = new Set(activePath?.nodes || []), pathEdges = new Set(activePath?.edges || []);
  for (const edge of edges) {
    const source = positions.get(edge.source), target = positions.get(edge.target);
    canvas.append(graphElement("line", { x1: source.x, y1: source.y, x2: target.x, y2: target.y,
      class: pathEdges.has(edge.id) ? "edge path" : "edge" }));
  }
  for (const node of nodes) {
    const point = positions.get(node.id);
    const group = graphElement("g", { class: "graph-node", tabindex: "0", role: "button", "aria-label": `${node.type}: ${node.label}` });
    const circle = graphElement("circle", { cx: point.x, cy: point.y, r: 18,
      class: `node ${node.classification === "observed" ? "observed" : "model"}${pathNodes.has(node.id) ? " path" : ""}` });
    const label = graphElement("text", { x: point.x, y: point.y + 36 });
    label.textContent = node.label.slice(0, 28);
    const title = graphElement("title");
    title.textContent = `${node.type}: ${node.label} · confidence ${node.confidence ?? "unknown"}`;
    group.append(circle, label, title);
    group.addEventListener("click", () => graphDetails(node));
    group.addEventListener("keydown", (event) => { if (["Enter", " "].includes(event.key)) { event.preventDefault(); graphDetails(node); } });
    canvas.append(group);
  }
  if (nodes.length) {
    try {
      const painted = canvas.getBBox();
      if ([painted.x, painted.y, painted.width, painted.height].every(Number.isFinite) &&
          painted.width >= 0 && painted.height >= 0) bounds = model.viewport(positions, painted);
    } catch {
      // Coordinate bounds remain available if this SVG is not currently rendered.
    }
  }
  setViewport();
  for (const selector of ["#graph-from", "#graph-to"]) {
    const select = $(selector), current = select.value;
    select.replaceChildren(option("", "Select entity"));
    for (const node of visible.nodes) select.append(option(node.id, `${node.type}: ${node.label}`));
    if (visible.nodes.some((node) => node.id === current)) select.value = current;
  }
}

async function loadGraph(caseIdValue) {
  resetGraph();
  if (!caseIdValue) return;
  const request = graphRequest;
  const response = await api(`/api/graph?case_id=${encodeURIComponent(caseIdValue)}`);
  if (request !== graphRequest || $("#workspace").hidden) return;
  if (response.case_id !== caseIdValue) throw new Error("Graph response belongs to another case.");
  activeGraph = TraceAtlasGraph.normalize(response);
  renderGraph();
}

async function bootControlPlane() {
  try {
    const config = await api("/api/config");
    if (config.control_plane !== "configured") {
      $("#platform-status").textContent = "LOCAL PLANNER ONLINE · CLOUD CONTROL DISABLED";
      $("#control-disabled").hidden = false;
      return;
    }
    $("#platform-status").textContent = "CONTROL PLANE ONLINE · WORKER ISOLATED";
    try {
      const session = await api("/api/session");
      $("#analyst-label").textContent = session.user?.email || "Authenticated analyst";
      $("#workspace").hidden = false;
      await loadWorkspace();
    } catch { $("#login-form").hidden = false; }
  } catch {
    $("#platform-status").textContent = "LOCAL PLANNER ONLINE · STATUS UNAVAILABLE";
    $("#control-disabled").hidden = false;
  }
}

$("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("#login-error").textContent = "";
  try {
    const result = await api("/api/session", { method: "POST", body: JSON.stringify({ email: $("#login-email").value, password: $("#login-password").value }) });
    $("#login-password").value = "";
    $("#analyst-label").textContent = result.user?.email || "Authenticated analyst";
    $("#login-form").hidden = true;
    $("#workspace").hidden = false;
    await loadWorkspace();
  } catch { $("#login-error").textContent = "Sign-in failed. Check credentials and project configuration."; }
});

$("#logout").addEventListener("click", async () => {
  pendingJobKeys.clear();
  try { await api("/api/session", { method: "DELETE" }); } catch { /* best effort */ }
  resetGraph();
  $("#graph-import").value = "";
  $("#workspace").hidden = true;
  $("#login-form").hidden = false;
});

$("#organisation-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await api("/api/organisations", { method: "POST", body: JSON.stringify({ name: $("#organisation-name").value }) });
    $("#organisation-name").value = "";
    await loadWorkspace();
  } catch (error) { $("#workspace-error").textContent = error.message; }
});

$("#case-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await api("/api/cases", { method: "POST", body: JSON.stringify({
      organisation_id: $("#case-organisation").value, title: $("#case-title").value,
      purpose: $("#case-purpose").value, authorization_confirmed: true,
      scope: { cloud_targets: ["domain", "ip", "url", "hash"], identity_targets: false },
    }) });
    event.target.reset();
    await loadWorkspace();
  } catch (error) { $("#workspace-error").textContent = error.message; }
});

$("#asset-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    if (!$("#asset-authorized").checked) throw new Error("authority_confirmation_required");
    await api("/api/assets", { method: "POST", body: JSON.stringify({
      organisation_id: $("#asset-organisation").value, label: $("#asset-label").value,
      target_type: $("#asset-type").value, target_value: $("#asset-value").value,
      ownership_basis: $("#asset-basis").value, authorization_confirmed: true,
    }) });
    event.target.reset();
    await loadWorkspace();
  } catch (error) { $("#workspace-error").textContent = error.message; }
});

$("#job-case").addEventListener("change", syncAssetChoices);
// Reuse the operation key after an uncertain response; clear only on acknowledgement.
const pendingJobKeys = new Map();
let submittingJob = false;
$("#job-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (submittingJob) return;
  submittingJob = true;
  try {
    if (!$("#job-authorized").checked) throw new Error("authorization_confirmation_required");
    const asset = control.assets.find((item) => item.id === $("#job-asset").value);
    if (!asset) throw new Error("select_owned_asset");
    const requestKey = JSON.stringify([$("#analyst-label").textContent, $("#job-case").value, asset.id, workflowForType[asset.target_type]]);
    if (!pendingJobKeys.has(requestKey)) {
      const nonce = crypto.getRandomValues(new Uint32Array(4));
      pendingJobKeys.set(requestKey, Array.from(nonce).map((value) => value.toString(16).padStart(8, "0")).join(""));
    }
    const idempotency = pendingJobKeys.get(requestKey);
    await api("/api/jobs", { method: "POST", body: JSON.stringify({
      case_id: $("#job-case").value, asset_id: asset.id, kind: workflowForType[asset.target_type],
      idempotency_key: idempotency, authorization_confirmed: true,
    }) });
    pendingJobKeys.delete(requestKey);
    $("#job-authorized").checked = false;
    await loadWorkspace();
  } catch (error) { $("#workspace-error").textContent = error.message; }
  finally { submittingJob = false; }
});

$("#graph-case").addEventListener("change", (event) => {
  $("#graph-import").value = "";
  loadGraph(event.target.value).catch((error) => { $("#graph-status").textContent = error.message; });
});

$("#graph-import").addEventListener("change", async (event) => {
  const file = event.target.files?.[0];
  if (!file) return;
  try {
    if (file.size > TraceAtlasGraph.LIMITS.bytes) throw new Error("Choose a JSON export of at most 10 MiB.");
    const request = ++graphRequest;
    const parsed = TraceAtlasGraph.parseJSON(await file.text());
    if (request !== graphRequest || $("#workspace").hidden) return;
    activeGraph = parsed;
    activePath = null;
    $("#graph-case").value = "";
    $("#graph-details").replaceChildren();
    renderGraph();
  } catch (error) { $("#graph-status").textContent = error.message; }
  finally { event.target.value = ""; }
});

for (const selector of ["#graph-query", "#graph-class", "#graph-confidence", "#graph-layout"]) {
  $(selector).addEventListener("input", () => {
    if (!activeGraph) return;
    try { activePath = null; renderGraph(); }
    catch (error) { $("#graph-status").textContent = error.message; }
  });
}

$("#graph-path").addEventListener("click", () => {
  if (!activeGraph) return;
  try {
    const visible = TraceAtlasGraph.filterGraph(activeGraph, graphFilters());
    activePath = TraceAtlasGraph.shortestPath(visible, $("#graph-from").value, $("#graph-to").value);
    renderGraph();
    $("#graph-status").textContent += ` Path: ${activePath.state}${activePath.state === "found" ? ` (${activePath.edges.length} hops)` : ""}. Links show association, not attribution or causality.`;
  } catch (error) { $("#graph-status").textContent = error.message; }
});

$("#investigation-case").addEventListener("change", (event) => {
  loadInvestigation(event.target.value).catch((error) => { $("#workspace-error").textContent = error.message; });
});

$("#review-case").addEventListener("change", (event) => {
  loadReviews(event.target.value).catch((error) => { $("#workspace-error").textContent = error.message; });
});

$("#notes-case").addEventListener("change", (event) => {
  loadNotes(event.target.value).catch((error) => { $("#workspace-error").textContent = error.message; });
});

$("#review-decision-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const submitter = event.submitter;
    await api("/api/reviews", { method: "POST", body: JSON.stringify({
      task_id: $("#review-task").value,
      decision: submitter?.value || "rejected",
      rationale: $("#review-rationale").value,
    }) });
    await loadReviews($("#review-case").value);
  } catch (error) { $("#workspace-error").textContent = error.message; }
});

$("#note-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await api("/api/notes", { method: "POST", body: JSON.stringify({
      case_id: $("#notes-case").value,
      classification: $("#note-classification").value,
      body: $("#note-body").value,
    }) });
    $("#note-body").value = "";
    await loadNotes($("#notes-case").value);
  } catch (error) { $("#workspace-error").textContent = error.message; }
});

bootControlPlane();
