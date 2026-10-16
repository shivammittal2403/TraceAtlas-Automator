/* TraceAtlas native library panel: same-origin and CSRF-protected, never runs vendor code. */
(() => {
  "use strict";
  const base = location.pathname.startsWith("/employee/") ? "/employee" : "";
  const el = id => document.getElementById(id);
  const status = el("library-health");
  const list = el("library-results");
  const detail = el("library-detail");
  const searchButton = el("library-search");
  const planButton = el("library-plan");
  if (!status || !list || !detail || !searchButton || !planButton) return;

  function line(host, value, name = "p") {
    const node = document.createElement(name);
    node.textContent = String(value);
    host.append(node);
    return node;
  }
  async function request(path, payload) {
    const config = payload ? {
      method: "POST",
      headers: {"Content-Type": "application/json",
                "X-TraceAtlas-CSRF": (await (await fetch(base + "/api/session")).json()).csrf_token},
      body: JSON.stringify(payload)
    } : undefined;
    const response = await fetch(base + path, config);
    const body = await response.json();
    if (!response.ok) throw Error(body.error || "Library request failed");
    return body;
  }
  function show(items) {
    list.replaceChildren();
    if (!items.length) {
      line(list, "No matching references. Check the spelling or try a broader concept.");
      return;
    }
    for (const item of items) {
      const div = document.createElement("div");
      div.className = "record";
      line(div, item.kind.toUpperCase() + "  ·  " + item.name, "strong");
      line(div, item.description || "No description");
      line(div, item.category + "  ·  " + item.ref, "small");
      if (item.kind === "skill") {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "secondary";
        button.textContent = "Inspect reference";
        button.onclick = async () => {
          try {
            const ref = await request("/api/library/reference?ref=" + encodeURIComponent(item.ref));
            detail.textContent = ref.warning + "\nSHA-256: " + ref.sha256 + "\n\n" + ref.markdown.slice(0, 16000);
          } catch (err) { detail.textContent = err.message; }
        };
        div.append(button);
      } else if (item.url && /^https:\/\/(?:github\.com|gitlab\.com|codeberg\.org)\/[a-z0-9_.-]+(?:\/[a-z0-9_.-]+){1,6}\/?$/i.test(item.url)) {
        const a = document.createElement("a");
        a.href = item.url;
        a.target = "_blank";
        a.rel = "noopener noreferrer";
        a.textContent = "Upstream repository";
        div.append(a);
      }
      list.append(div);
    }
  }
  const busy = async fn => {
    searchButton.disabled = true;
    planButton.disabled = true;
    try { await fn(); } catch (err) { detail.textContent = err.message || String(err); }
    finally { searchButton.disabled = false; planButton.disabled = false; }
  };
  searchButton.onclick = () => busy(async () => {
    const q = el("library-query").value.trim();
    const kind = el("library-kind").value;
    const data = await request("/api/library/search?q=" + encodeURIComponent(q) +
                               "&kind=" + encodeURIComponent(kind) + "&limit=12");
    status.textContent = data.matched + " relevant references. Nothing was executed.";
    detail.textContent = "Descriptions and referenced documents are untrusted source material.";
    show(data.results);
  });
  planButton.onclick = () => busy(async () => {
    const objective = el("library-query").value.trim();
    const localModel = document.querySelector("#investigate input[name=model]");
    const model = (localModel && localModel.value.trim()) || "qwen2.5:7b";
    const use_ollama = el("library-use-ollama").checked;
    const result = await request("/api/library/plan", {objective, model, use_ollama});
    show(result.suggestions);
    status.textContent = "Planner: " + result.status + ". Execution not authorized.";
    detail.textContent = result.rationale + "\n\nModel: " + (result.model || "none") +
      "\nAll referenced capabilities require human review and existing case approval.";
  });
  Promise.all([request("/api/library/status"), request("/api/ollama/status")])
    .then(([lib, model]) => {
      status.textContent = lib.skills_indexed + " skills + " + lib.repositories_indexed +
        " OSINT repositories indexed. Ollama: " + (model.available ? "online" : "offline") +
        ". Vendor execution disabled.";
      const hint = model.models.length ? "Available local models: " + model.models.join(", ") :
        "To use local AI planning, start Ollama at 127.0.0.1:11434.";
      detail.textContent = hint;
    })
    .catch(err => { status.textContent = "Library status unavailable"; detail.textContent = err.message; });
})();
