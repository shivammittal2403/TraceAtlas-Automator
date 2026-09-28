(function (root, factory) {
  "use strict";
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.TraceAtlasGraph = api;
})(globalThis, function () {
  "use strict";
  const SCHEMA = "traceatlas-graph/1";
  const LIMITS = Object.freeze({ nodes: 2000, edges: 5000, evidence: 2000, bytes: 10 * 1024 * 1024, drawNodes: 250, drawEdges: 1000 });
  const CLASSES = Object.freeze(["observed", "inference", "model-output", "unclassified"]);
  const object = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
  const text = (v, max = 500) => typeof v === "string" ? v.slice(0, max) : "";
  function id(v) {
    if (typeof v !== "string" || !v.trim() || v.length > 256 || /[\u0000-\u001f\u007f]/.test(v)) throw new Error("Invalid graph record ID.");
    return v;
  }
  function rows(v, name, max, optional = false) {
    if (optional && v === undefined) return [];
    if (!Array.isArray(v) || !v.every(object)) throw new Error(`${name} must be an array of records.`);
    if (v.length > max) throw new Error(`${name} exceeds the ${max} record limit. Export a smaller scan.`);
    return v;
  }
  const score = (v) => typeof v === "number" && Number.isFinite(v) && v >= 0 && v <= 100 ? v : null;
  const kind = (v) => CLASSES.includes(v) ? v : "unclassified";
  function date(v) {
    if (typeof v !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(v)) return null;
    const day = v.slice(0, 10), midnight = Date.parse(`${day}T00:00:00Z`);
    if (!Number.isFinite(midnight) || new Date(midnight).toISOString().slice(0, 10) !== day || !Number.isFinite(Date.parse(v))) return null;
    return new Date(v).toISOString();
  }
  function details(v) { try { return (typeof v === "string" ? v : JSON.stringify(v ?? "", null, 2)).slice(0, 12000); } catch { return "Details cannot be represented."; } }
  function refs(row) {
    const values = row.evidence_ids ?? (row.evidence_id ? [row.evidence_id] : []);
    if (!Array.isArray(values) || values.length > 100) throw new Error("Invalid evidence references.");
    return [...new Set(values.map(id))];
  }
  function unique(values, label) {
    const seen = new Set();
    for (const row of values) { if (seen.has(row.id)) throw new Error(`Duplicate ${label} ID. Nothing was merged.`); seen.add(row.id); }
    return values;
  }
  function checkScope(items, caseId, scanId) {
    for (const row of items) {
      if (caseId && row.case_id && row.case_id !== caseId) throw new Error("Record belongs to another case.");
      if (scanId && row.scan_id && row.scan_id !== scanId) throw new Error("Record belongs to another scan.");
    }
    return items;
  }
  function normalize(input) {
    if (!object(input)) throw new Error("Choose a TraceAtlas graph, case report or Spider JSON export.");
    if (typeof input.schema_version === "string" && input.schema_version.startsWith("traceatlas-graph/") && input.schema_version !== SCHEMA) throw new Error("Unsupported graph schema version.");
    let ns, es, caseId, title, format, partial = false;
    const warnings = [];
    if (input.schema_version === SCHEMA) {
      ns = input.nodes; es = input.edges; caseId = input.case_id; title = input.title;
      format = ["cloud graph", "case report", "Spider export"].includes(input.format) ? input.format : "workbench export";
      partial = input.completeness?.state === "partial";
      if (Array.isArray(input.warnings)) warnings.push(...input.warnings.slice(0, 20).map((v) => text(v)).filter(Boolean));
    } else if (Array.isArray(input.entities)) {
      ns = input.entities; es = input.edges; caseId = input.case_id; title = "Case evidence graph"; format = "cloud graph";
      for (const [name, capped] of Object.entries(input.truncated || {})) if (capped === true) { partial = true; warnings.push(`${text(name, 40)} reached the server cap; this snapshot is partial.`); }
      warnings.push("Cloud reads are bounded and non-atomic. RLS, backend limits and concurrent writes can affect completeness.");
    } else if (Array.isArray(input.spider_scans)) {
      ns = []; es = []; caseId = input.case?.id; title = input.case?.title; format = "case report";
      for (const scan of rows(input.spider_scans, "Scans", 2000)) {
        if (caseId && scan.case_id && scan.case_id !== caseId) throw new Error("Scan belongs to another case.");
        ns.push(...checkScope(rows(scan.events, "Events", LIMITS.nodes), caseId || scan.case_id, scan.id));
        es.push(...checkScope(rows(scan.edges, "Edges", LIMITS.edges), caseId || scan.case_id, scan.id).map((e, i) => ({ ...e, id: e.id ?? `${id(scan.id)}:edge:${i}` })));
        if (ns.length > LIMITS.nodes || es.length > LIMITS.edges) throw new Error("Case exceeds graph limits. Export an individual scan.");
      }
      warnings.push("Only Spider events and explicit links are graphed. Findings are not converted into invented relationships.");
    } else if (object(input.scan) && Array.isArray(input.events)) {
      ns = input.events; es = input.edges; caseId = input.scan.case_id || input.scan.id;
      checkScope(rows(ns, "Events", LIMITS.nodes), input.scan.case_id, input.scan.id);
      checkScope(rows(es, "Edges", LIMITS.edges), input.scan.case_id, input.scan.id);
      title = `Spider scan ${text(input.scan.id, 80)}`; format = "Spider export";
    } else throw new Error("Unsupported JSON. Use a TraceAtlas case report, Spider export or workbench graph.");
    const nodes = unique(checkScope(rows(ns, "Nodes", LIMITS.nodes), caseId).map((row) => ({
      id: id(row.id), label: text(row.label) || (row.data !== undefined ? details(row.data).slice(0, 500) : "") || row.id,
      type: text(row.type || row.entity_type || row.event_type, 80) || "UNKNOWN", source: text(row.source_module || row.source, 200) || "unknown",
      classification: kind(row.classification), confidence: score(row.confidence), at: date(row.at || row.created_at), evidence_ids: refs(row), details: details(row.details ?? row.data ?? row.properties),
    })), "node");
    const nodeIds = new Set(nodes.map((n) => n.id));
    let edges = unique(checkScope(rows(es, "Edges", LIMITS.edges), caseId).map((row, i) => ({
      id: id(row.id ?? `edge:${i}`), source: id(row.source_entity_id || row.parent_id || row.source), target: id(row.target_entity_id || row.child_id || row.target),
      label: text(row.relationship || row.module || row.label, 120) || "related", source_name: text(row.source_name || row.module, 200) || "unknown",
      classification: kind(row.classification), confidence: score(row.confidence), at: date(row.at || row.created_at), evidence_ids: refs(row), details: details(row.details ?? row.properties),
    })), "edge");
    const absent = edges.filter((e) => !nodeIds.has(e.source) || !nodeIds.has(e.target)).length;
    if (absent) { warnings.push(`${absent} link(s) reference absent nodes and were excluded from analysis.`); partial = true; edges = edges.filter((e) => nodeIds.has(e.source) && nodeIds.has(e.target)); }
    const evidence = unique(checkScope(rows(input.evidence, "Evidence", LIMITS.evidence, true), caseId).map((row) => ({
      id: id(row.id || row.sha256), source: text(row.source, 200) || "unknown", classification: kind(row.classification),
      content_hash: text(row.content_hash || row.sha256, 128), at: date(row.at || row.created_at || row.captured_at),
    })), "evidence");
    const evidenceMap = new Map(evidence.map((e) => [e.id, e]));
    for (const [items, key] of [[nodes, "source"], [edges, "source_name"]]) for (const row of items) {
      const sources = [...new Set(row.evidence_ids.map((r) => evidenceMap.get(r)?.source).filter(Boolean))];
      if (row[key] === "unknown" && sources.length === 1) row[key] = sources[0];
    }
    const unavailable = new Set([...nodes, ...edges].flatMap((r) => r.evidence_ids).filter((r) => !evidenceMap.has(r)));
    if (unavailable.size) warnings.push(`${unavailable.size} evidence reference(s) are unavailable; references are retained for review.`);
    if (nodes.some((n) => n.classification === "unclassified")) warnings.push("Records without an explicit classification remain unclassified, not verified observations.");
    return { schema_version: SCHEMA, case_id: text(caseId, 256) || "local-import", title: text(title, 160) || "Local investigation", format, synthetic: input.synthetic === true,
      nodes, edges, evidence, warnings: [...new Set(warnings)], completeness: { state: partial ? "partial" : "unknown" } };
  }
  function parseJSON(value) {
    if (typeof value !== "string" || value.length > LIMITS.bytes || new TextEncoder().encode(value).byteLength > LIMITS.bytes) throw new Error("Choose a JSON file of at most 10 MiB.");
    let parsed; try { parsed = JSON.parse(value); } catch { throw new Error("Invalid JSON. The current graph was not replaced."); }
    return normalize(parsed);
  }
  function filterGraph(graph, f = {}) {
    const min = f.minConfidence ?? 0;
    if (score(min) === null) throw new Error("Minimum confidence must be 0–100.");
    function day(v, end) {
      if (!v) return null;
      const result = /^\d{4}-\d{2}-\d{2}$/.test(v) ? Date.parse(`${v}T${end ? "23:59:59.999" : "00:00:00"}Z`) : NaN;
      if (!Number.isFinite(result) || new Date(result).toISOString().slice(0, 10) !== v) throw new Error("Invalid UTC date range.");
      return result;
    }
    const from = day(f.from, false), until = day(f.until, true), query = text(f.query).trim().toLowerCase();
    if (from !== null && until !== null && from > until) throw new Error("Start date must be on or before end date.");
    const matches = (r) => (!f.classification || r.classification === f.classification) && (!min || r.confidence !== null && r.confidence >= min);
    const nodes = graph.nodes.filter((n) => matches(n) && (!query || `${n.label} ${n.id} ${n.type}`.toLowerCase().includes(query)) && (!f.type || n.type === f.type) && (!f.source || n.source === f.source) && (from === null || n.at && Date.parse(n.at) >= from) && (until === null || n.at && Date.parse(n.at) <= until));
    const ids = new Set(nodes.map((n) => n.id));
    return { nodes, edges: graph.edges.filter((e) => ids.has(e.source) && ids.has(e.target) && matches(e)) };
  }
  function adjacency(graph, directed = false) {
    const map = new Map(graph.nodes.map((n) => [n.id, []]));
    for (const e of graph.edges) if (map.has(e.source) && map.has(e.target)) { map.get(e.source).push({ node: e.target, edge: e.id }); if (!directed) map.get(e.target).push({ node: e.source, edge: e.id }); }
    return map;
  }
  function shortestPath(graph, start, end, { maxHops = 6, directed = true } = {}) {
    if (!Number.isInteger(maxHops) || maxHops < 1 || maxHops > 12) throw new Error("Path depth must be 1–12 hops.");
    const map = adjacency(graph, directed), prev = new Map([[start, null]]), queue = [{ node: start, depth: 0 }];
    if (!map.has(start) || !map.has(end)) return { state: "endpoint-hidden", nodes: [], edges: [] };
    for (let i = 0; i < queue.length; i++) {
      const item = queue[i];
      if (item.node === end) {
        const nodes = [end], edges = []; let current = end;
        while (prev.get(current)) { const p = prev.get(current); nodes.push(p.node); edges.push(p.edge); current = p.node; }
        return { state: "found", nodes: nodes.reverse(), edges: edges.reverse() };
      }
      if (item.depth >= maxHops) continue;
      for (const next of map.get(item.node)) if (!prev.has(next.node)) { prev.set(next.node, { node: item.node, edge: next.edge }); queue.push({ node: next.node, depth: item.depth + 1 }); }
    }
    return { state: "not-found", nodes: [], edges: [] };
  }
  function neighborhood(graph, center, hops = 1) {
    if (![1, 2].includes(hops)) throw new Error("Neighborhood must be 1 or 2 hops.");
    const map = adjacency(graph), ids = new Set(map.has(center) ? [center] : []); let frontier = [...ids];
    for (let i = 0; i < hops; i++) { const next = []; for (const n of frontier) for (const e of map.get(n)) if (!ids.has(e.node)) { ids.add(e.node); next.push(e.node); } frontier = next; }
    return { nodes: graph.nodes.filter((n) => ids.has(n.id)), edges: graph.edges.filter((e) => ids.has(e.source) && ids.has(e.target)) };
  }
  function layout(graph, mode = "layered") {
    const nodes = [...graph.nodes].sort((a, b) => a.id.localeCompare(b.id)), result = new Map();
    if (mode === "grid") { const cols = Math.max(1, Math.ceil(Math.sqrt(nodes.length))); nodes.forEach((n, i) => result.set(n.id, { x: 140 + i % cols * 220, y: 90 + Math.floor(i / cols) * 120 })); }
    else if (mode === "radial") { const radius = Math.max(160, nodes.length * 20); nodes.forEach((n, i) => result.set(n.id, { x: 500 + radius * Math.cos(i * Math.PI * 2 / nodes.length), y: 300 + radius * Math.sin(i * Math.PI * 2 / nodes.length) })); }
    else {
      const map = adjacency(graph), incoming = new Set(graph.edges.map((e) => e.target)), seen = new Set(); let ox = 0, oy = 0, height = 0;
      for (const root of [...nodes.filter((n) => !incoming.has(n.id)), ...nodes.filter((n) => incoming.has(n.id))]) {
        if (seen.has(root.id)) continue;
        const queue = [{ id: root.id, depth: 0 }], levels = new Map(), points = []; seen.add(root.id);
        for (let i = 0; i < queue.length; i++) { const n = queue[i], row = levels.get(n.depth) || 0; levels.set(n.depth, row + 1); points.push({ id: n.id, x: 140 + n.depth * 260, y: 90 + row * 120 }); for (const e of map.get(n.id)) if (!seen.has(e.node)) { seen.add(e.node); queue.push({ id: e.node, depth: n.depth + 1 }); } }
        const w = levels.size * 260, h = Math.max(...levels.values()) * 120 + 50;
        if (ox && ox + w > Math.max(1000, Math.sqrt(nodes.length) * 220)) { ox = 0; oy += height; height = 0; }
        for (const p of points) result.set(p.id, { x: p.x + ox, y: p.y + oy }); ox += w; height = Math.max(height, h);
      }
    }
    return result;
  }
  function identity(graph) {
    // Bind views to normalized evidence as well as topology; not an authenticity signature.
    const ordered = (rows) => rows.sort((a, b) => a[0].localeCompare(b[0]));
    return JSON.stringify([graph.schema_version, graph.case_id, graph.synthetic, graph.completeness?.state,
      ordered(graph.nodes.map((n) => [n.id, n.label, n.type, n.source, n.classification, n.confidence, n.at, [...n.evidence_ids].sort(), n.details])),
      ordered(graph.edges.map((e) => [e.id, e.source, e.target, e.label, e.source_name, e.classification, e.confidence, e.at, [...e.evidence_ids].sort(), e.details])),
      ordered(graph.evidence.map((e) => [e.id, e.source, e.classification, e.content_hash, e.at]))]);
  }
  function validateView(value, graph) {
    if (!object(value) || value.schema_version !== "traceatlas-view/1" || value.graph_identity !== identity(graph)) throw new Error("This view belongs to a different graph. Load its original graph first.");
    const f = object(value.filters) ? value.filters : {};
    const filters = { query: text(f.query), type: text(f.type, 80), source: text(f.source, 200), classification: CLASSES.includes(f.classification) ? f.classification : "", minConfidence: score(f.minConfidence) ?? 0, from: text(f.from, 10), until: text(f.until, 10) };
    filterGraph(graph, filters);
    const ids = new Set(graph.nodes.map((n) => n.id)), positions = new Map();
    for (const p of rows(value.positions, "Positions", LIMITS.nodes, true)) { if (!ids.has(p.id) || positions.has(p.id) || !Number.isFinite(p.x) || !Number.isFinite(p.y) || Math.abs(p.x) > 1e6 || Math.abs(p.y) > 1e6) throw new Error("Invalid saved positions."); positions.set(p.id, { x: p.x, y: p.y }); }
    return { filters, positions, selected: ids.has(value.selected) ? value.selected : null };
  }
  return Object.freeze({ SCHEMA, LIMITS, CLASSES, normalize, parseJSON, filterGraph, shortestPath, neighborhood, layout, identity, validateView });
});
