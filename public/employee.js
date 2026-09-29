"use strict";

// Shares the existing authenticated API and case selector. Source/model text is
// always inserted as text; no remote HTML, Markdown or scripts are rendered.
(() => {
  let brief = null;
  let generation = 0;
  const el = (id) => document.getElementById(id);
  function node(tag, text, className) {
    const item = document.createElement(tag);
    item.textContent = text;
    if (className) item.className = className;
    return item;
  }
  function reset() {
    generation++;
    brief = null;
    el("employee-result").hidden = true;
    el("employee-error").textContent = "";
    el("employee-status").textContent = "Build a new brief for the selected case and objective.";
    el("employee-build").disabled = false;
    el("employee-queue").disabled = false;
    for (const id of ["employee-facts", "employee-scenarios", "employee-knowledge", "employee-summary"]) el(id).replaceChildren();
  }
  function render(value) {
    brief = value;
    el("employee-result").hidden = false;
    const s = value.summary;
    el("employee-summary").textContent = `${s.observations} source observations · ${s.scenarios} hypotheses · ${s.withheld} withheld · ${s.coverage_failures} coverage gaps${s.truncated ? " · limited evidence window" : ""}`;
    const facts = el("employee-facts");
    facts.replaceChildren();
    if (!value.facts.length) facts.append(node("p", "No eligible observations. Collect or import evidence before reaching a conclusion."));
    for (const fact of value.facts) {
      const detail = document.createElement("details");
      detail.append(node("summary", `${fact.title} · ${fact.source} · ${fact.freshness}`));
      detail.append(node("p", `Evidence: ${fact.id}`));
      detail.append(node("pre", JSON.stringify(fact.data, null, 2), "employee-evidence"));
      detail.append(node("p", fact.interpretation));
      facts.append(detail);
    }
    const scenarios = el("employee-scenarios");
    scenarios.replaceChildren();
    if (!value.scenarios.length) scenarios.append(node("p", "No scenario rule is supported by the current evidence. The employee has abstained."));
    for (const item of value.scenarios) {
      const card = node("article", "", "employee-scenario");
      card.append(node("h4", item.title), node("p", item.statement),
        node("p", `Alternative: ${item.alternative_explanation}`), node("p", `Next check: ${item.next_check}`),
        node("small", `Unvalidated hypothesis · evidence: ${item.evidence_ids.join(", ")}`));
      scenarios.append(card);
    }
    for (const item of value.insights) scenarios.append(node("p", `${item.statement} Evidence: ${item.evidence_ids.join(", ")}`));
    const knowledge = el("employee-knowledge");
    knowledge.replaceChildren();
    for (const skill of value.skills) {
      knowledge.append(node("h4", skill.title));
      const steps = document.createElement("ol");
      for (const step of skill.steps) steps.append(node("li", step));
      knowledge.append(steps, node("p", `Required evidence: ${skill.required_evidence}`));
    }
    for (const reference of value.knowledge_references) {
      const p = document.createElement("p");
      const link = node("a", reference.title);
      // These are server-owned methodology URLs, still constrained to HTTPS.
      try {
        const url = new URL(reference.url);
        if (url.protocol === "https:" && !url.username && !url.password) {
          link.href = url.href; link.target = "_blank"; link.rel = "noopener noreferrer";
        }
      } catch { /* Render label only for malformed references. */ }
      p.append(link); knowledge.append(p);
    }
    for (const gap of value.coverage_gaps) knowledge.append(node("p", `${gap.source}: ${gap.status} (${gap.reason})`));
    for (const item of value.withheld) knowledge.append(node("p", `Withheld ${item.id}: ${item.reason}`));
    for (const question of value.questions) knowledge.append(node("p", `Question: ${question}`));
    for (const limitation of value.limitations) knowledge.append(node("p", limitation));
    el("employee-status").textContent = "Brief ready for your review. Analysis used stored case evidence; no new scan was executed.";
  }
  for (const id of ["employee-case", "employee-mode", "employee-objective"]) el(id).addEventListener("input", reset);
  document.addEventListener("traceatlas-workspace-changed", reset);
  el("logout").addEventListener("click", reset);
  el("employee-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    reset();
    const current = generation;
    el("employee-build").disabled = true;
    el("employee-status").textContent = "Reading case evidence and evaluating scenarios…";
    try {
      const result = await api("/api/employee", {method: "POST", body: JSON.stringify({
        action: "brief", case_id: el("employee-case").value,
        objective: el("employee-objective").value, mode: el("employee-mode").value,
      })});
      if (current === generation) render(result.brief);
    } catch (error) {
      if (current === generation) { el("employee-error").textContent = error.message; el("employee-status").textContent = "Brief unavailable. No conclusion was generated."; }
    } finally { if (current === generation) el("employee-build").disabled = false; }
  });
  el("employee-queue").addEventListener("click", async () => {
    if (!brief) return;
    const current = generation;
    const selected = brief;
    el("employee-queue").disabled = true;
    try {
      await api("/api/employee", {method: "POST", body: JSON.stringify({
        action: "queue-review", case_id: selected.case_id, objective: selected.objective,
        mode: selected.mode, expected_evidence_digest: selected.evidence_digest,
      })});
      if (current !== generation) return;
      el("employee-status").textContent = "Saved to your human review queue. Read the snapshot and record your rationale there.";
      el("review-case").value = selected.case_id;
      await loadReviews(selected.case_id);
    } catch (error) {
      if (current === generation) { el("employee-error").textContent = error.message; el("employee-queue").disabled = false; }
    }
  });
  el("employee-download").addEventListener("click", () => {
    if (!brief) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(brief, null, 2)], {type: "application/json"}));
    const link = document.createElement("a");
    link.href = url; link.download = `traceatlas-employee-${brief.case_id}.json`;
    link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
})();
