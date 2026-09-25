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
    const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) && value.split(".").every((part) => Number(part) <= 255);
    const ipv6 = /^[0-9a-f:]+$/i.test(value) && value.includes(":");
    if ((!ipv4 && !ipv6) || isPrivateIPv4(value) || value === "::1") throw new Error("Enter a public IP address.");
  }
  if (type === "url") {
    let parsed;
    try { parsed = new URL(value); } catch { throw new Error("Enter a valid HTTP or HTTPS URL."); }
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
  fillSelect($("#graph-case"), control.cases, "case");
  fillSelect($("#review-case"), control.cases, "case");
  fillSelect($("#notes-case"), control.cases, "case");
  syncAssetChoices();
  renderJobs();
}

function graphElement(name, attributes = {}) {
  const element = document.createElementNS("http://www.w3.org/2000/svg", name);
  for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, String(value));
  return element;
}

async function loadGraph(caseIdValue) {
  const canvas = $("#case-graph");
  const empty = $("#graph-empty");
  canvas.replaceChildren();
  if (!caseIdValue) { empty.hidden = false; return; }
  const graph = await api(`/api/graph?case_id=${encodeURIComponent(caseIdValue)}`);
  const nodes = (graph.entities || []).slice(0, 100);
  const edges = (graph.edges || []).slice(0, 250);
  empty.hidden = nodes.length > 0;
  empty.textContent = nodes.length ? "" : "No evidence-backed entities have been produced for this case.";
  if (!nodes.length) return;
  const positions = new Map();
  nodes.forEach((node, index) => {
    const angle = (Math.PI * 2 * index) / nodes.length - Math.PI / 2;
    const radius = Math.min(155, 55 + nodes.length * 4);
    positions.set(node.id, { x: 400 + Math.cos(angle) * radius, y: 210 + Math.sin(angle) * radius });
  });
  for (const edge of edges) {
    const source = positions.get(edge.source_entity_id);
    const target = positions.get(edge.target_entity_id);
    if (source && target) canvas.append(graphElement("line", { x1: source.x, y1: source.y, x2: target.x, y2: target.y, class: "edge" }));
  }
  for (const node of nodes) {
    const point = positions.get(node.id);
    const group = graphElement("g");
    const circle = graphElement("circle", { cx: point.x, cy: point.y, r: 18, class: node.classification === "observed" ? "node" : "node model" });
    const text = graphElement("text", { x: point.x, y: point.y + 36 });
    text.textContent = String(node.label).slice(0, 28);
    const title = graphElement("title");
    title.textContent = `${node.entity_type}: ${node.label} · confidence ${node.confidence}`;
    group.append(circle, text, title);
    canvas.append(group);
  }
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
  try { await api("/api/session", { method: "DELETE" }); } catch { /* best effort */ }
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
$("#job-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    if (!$("#job-authorized").checked) throw new Error("authorization_confirmation_required");
    const asset = control.assets.find((item) => item.id === $("#job-asset").value);
    if (!asset) throw new Error("select_owned_asset");
    const nonce = crypto.getRandomValues(new Uint32Array(4));
    const idempotency = Array.from(nonce).map((value) => value.toString(16).padStart(8, "0")).join("");
    await api("/api/jobs", { method: "POST", body: JSON.stringify({
      case_id: $("#job-case").value, asset_id: asset.id, kind: workflowForType[asset.target_type],
      idempotency_key: idempotency, authorization_confirmed: true,
    }) });
    $("#job-authorized").checked = false;
    await loadWorkspace();
  } catch (error) { $("#workspace-error").textContent = error.message; }
});

$("#graph-case").addEventListener("change", (event) => {
  loadGraph(event.target.value).catch((error) => { $("#workspace-error").textContent = error.message; });
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
