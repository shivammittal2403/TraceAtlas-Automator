"use strict";
(() => {
  const list = document.getElementById("academy-list");
  const lesson = document.getElementById("academy-lesson");
  const status = document.getElementById("academy-status");
  const search = document.getElementById("academy-search");
  const level = document.getElementById("academy-level");
  const resourcesPage = location.pathname.endsWith("resources.html");
  let records = [];

  function node(tag, text, className) {
    const el = document.createElement(tag);
    if (text !== undefined) el.textContent = String(text);
    if (className) el.className = className;
    return el;
  }
  function safeURL(value) {
    try {
      const url = new URL(value, location.origin);
      return ["https:", "http:"].includes(url.protocol) ? url.href : null;
    } catch { return null; }
  }
  const richTags = new Set(["P", "H2", "H3", "H4", "UL", "OL", "LI", "STRONG", "B", "EM",
    "I", "PRE", "CODE", "BR", "BLOCKQUOTE", "TABLE", "THEAD", "TBODY", "TR", "TH", "TD", "A"]);
  const dropTags = new Set(["SCRIPT", "STYLE", "IFRAME", "OBJECT", "EMBED", "SVG", "FORM", "INPUT"]);
  function rich(value) {
    const fragment = document.createDocumentFragment();
    const template = document.createElement("template");
    template.innerHTML = String(value); // Inert fragment; only allowlisted nodes below enter the DOM.
    function copy(source, target) {
      for (const child of source.childNodes) {
        if (child.nodeType === Node.TEXT_NODE) { target.append(document.createTextNode(child.textContent)); continue; }
        if (child.nodeType !== Node.ELEMENT_NODE || dropTags.has(child.tagName)) continue;
        if (!richTags.has(child.tagName)) { copy(child, target); continue; }
        const out = document.createElement(child.tagName.toLowerCase());
        if (child.tagName === "A") {
          const href = safeURL(child.getAttribute("href"));
          if (href) { out.href = href; out.rel = "noreferrer noopener"; out.target = "_blank"; }
        }
        copy(child, out); target.append(out);
      }
    }
    copy(template.content, fragment);
    return fragment;
  }
  function showError(error) {
    status.textContent = "Local content could not be loaded. Retry this page; no investigation was started.";
    console.error("Academy content:", error.message);
  }
  async function localJSON(url) {
    const response = await fetch(url, {credentials: "same-origin", redirect: "error"});
    if (!response.ok) throw new Error("Local content unavailable");
    return response.json();
  }
  function renderList() {
    const query = search.value.toLowerCase().trim();
    const visible = records.filter(item => (!level.value || item.difficulty === level.value) &&
      [item.title, item.description, ...(item.tags || [])].join(" ").toLowerCase().includes(query));
    list.replaceChildren();
    status.textContent = `${visible.length} of ${records.length} ${resourcesPage ? "resource references" : "training modules"}`;
    for (const item of visible) {
      const card = node("article", undefined, "card");
      card.append(node("h2", item.title), node("p", item.description || item.url));
      if (resourcesPage) {
        const link = node("a", "Open external reference ↗");
        const href = safeURL(item.url);
        if (href) { link.href = href; link.rel = "noreferrer noopener"; link.target = "_blank"; card.append(link); }
      } else {
        card.append(node("p", `${item.difficulty || "Unspecified"} · ${item.duration || "?"} minutes`, "meta"));
        const link = node("a", "Open module →");
        link.href = `/academy/training.html?module=${encodeURIComponent(item.id)}`;
        card.append(link);
      }
      list.append(card);
    }
  }
  function quiz(question, parent) {
    const form = node("form", undefined, "quiz");
    const fieldset = node("fieldset");
    fieldset.append(node("legend", question.question || "Knowledge check"));
    const options = question.options || question.choices || [];
    if (!Array.isArray(options)) return;
    for (let index = 0; index < options.length; index++) {
      const label = node("label", undefined, "quiz-option");
      const input = node("input"); input.type = "radio"; input.name = "answer"; input.value = String(index);
      label.append(input, document.createTextNode(typeof options[index] === "object" ?
        String(options[index].text || options[index].label || "Option") : String(options[index])));
      fieldset.append(label);
    }
    const submit = node("button", "Check answer"); submit.type = "submit";
    const feedback = node("p"); feedback.setAttribute("role", "status");
    form.append(fieldset, submit, feedback);
    form.addEventListener("submit", event => {
      event.preventDefault();
      const selected = new FormData(form).get("answer");
      if (selected === null) { feedback.textContent = "Choose an answer first."; return; }
      const answer = question.correctAnswer ?? question.correct_answer ?? question.answer;
      const index = Number(selected);
      const correct = typeof answer === "number" ? index === answer :
        typeof answer === "string" ? String(options[index]) === answer || selected === answer : null;
      feedback.textContent = correct === null ? "No machine-readable answer key; review the lesson." :
        correct ? "Correct. " + (question.explanation || "") : "Review this topic and try again.";
    });
    parent.append(form);
  }
  function renderMaterial(value, parent, heading = "") {
    if (value === null || value === undefined) return;
    if (typeof value === "string") { const block = node("div"); block.append(rich(value)); parent.append(block); return; }
    if (Array.isArray(value)) { for (const item of value) renderMaterial(item, parent); return; }
    if (typeof value !== "object") { parent.append(node("p", value)); return; }
    if (value.question && (value.options || value.choices)) { quiz(value, parent); return; }
    const title = value.title || value.name || heading;
    if (title) parent.append(node("h3", title));
    for (const [key, content] of Object.entries(value)) {
      if (["id", "title", "name", "image", "correctAnswer", "correct_answer"].includes(key)) continue;
      if (!["content", "description", "sections", "lessons", "questions"].includes(key)) {
        parent.append(node("h4", key.replaceAll("_", " ")));
      }
      renderMaterial(content, parent);
    }
  }
  async function openModule(id) {
    if (!/^[a-z0-9-]+$/.test(id) || !records.some(item => item.id === id)) throw new Error("Unknown module");
    const module = await localJSON(`/academy/modules/${encodeURIComponent(id)}.json`);
    lesson.replaceChildren(node("h2", module.title), node("p", module.description));
    renderMaterial(module.sections || module.lessons || [], lesson);
    lesson.hidden = false;
    list.hidden = true;
    document.getElementById("filter-form").hidden = true;
    status.textContent = `${module.difficulty} · ${module.duration} minutes · Educational material`;
    const back = node("a", "← All modules"); back.href = "/academy/training.html"; lesson.prepend(back);
  }
  document.getElementById("filter-form").addEventListener("submit", event => event.preventDefault());
  search.addEventListener("input", renderList); level.addEventListener("change", renderList);
  if (resourcesPage) document.getElementById("difficulty-label").hidden = true;
  (async () => {
    records = await localJSON(resourcesPage ? "/academy/resources.json" : "/academy/modules/index.json");
    if (!Array.isArray(records)) throw new Error("Invalid local catalog");
    renderList();
    const id = new URLSearchParams(location.search).get("module");
    if (id && !resourcesPage) await openModule(id);
  })().catch(showError);
})();
