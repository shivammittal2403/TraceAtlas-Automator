"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { spawnSync } = require("node:child_process");
const path = require("node:path");
const vm = require("node:vm");
const fs = require("node:fs");
const G = require("../public/graph-model.js");

function fixture() {
  return {
    schema_version: G.SCHEMA, case_id: "case-a", synthetic: true,
    nodes: [
      { id: "a", label: "example.org", type: "DOMAIN", source: "dns", confidence: 90, classification: "observed", at: "2026-09-27T10:00:00Z", evidence_ids: ["ev-a"], details: "DNS observation" },
      { id: "b", label: "203.0.113.10", type: "IP_ADDRESS", source: "dns", confidence: 80, classification: "observed", at: "2026-09-28T10:00:00Z" },
      { id: "c", label: "Candidate", type: "LABEL", source: "analysis", confidence: 60, classification: "inference" },
      { id: "d", label: "Isolated", type: "LABEL" },
    ],
    edges: [
      { id: "ab", source: "a", target: "b", classification: "observed", confidence: 80, source_name: "dns", label: "resolves_to", evidence_ids: ["ev-a"] },
      { id: "bc", source: "b", target: "c", classification: "inference", confidence: 60 },
    ],
    evidence: [{ id: "ev-a", source: "dns", classification: "observed", content_hash: "a".repeat(64), at: "2026-09-27T10:00:00Z" }],
  };
}
const graph = () => G.normalize(fixture());
const ids = (rows) => rows.map((row) => row.id);
const view = (g, overrides = {}) => ({ schema_version: "traceatlas-view/1", graph_identity: G.identity(g), positions: [], ...overrides });

test("browser loading exposes the same read-only API without Node globals", () => {
  const context = vm.createContext({ TextEncoder });
  vm.runInContext(fs.readFileSync(path.join(__dirname, "../public/graph-model.js"), "utf8"), context);
  assert.equal(context.TraceAtlasGraph.SCHEMA, G.SCHEMA);
  assert.ok(Object.isFrozen(context.TraceAtlasGraph));
  assert.ok(Object.isFrozen(G.CLASSES));
});

test("normalization round-trip preserves evidence, claims and identity", () => {
  const first = graph();
  const second = G.parseJSON(JSON.stringify(first));
  assert.deepEqual(second, first);
  assert.equal(G.identity(first), G.identity(second));
  assert.equal(first.nodes[3].classification, "unclassified");
  assert.equal(first.nodes[3].confidence, null);
});

test("cloud adapter resolves explicit evidence provenance and reports bounded snapshots", () => {
  const g = G.normalize({ case_id: "case-a", entities: [{ id: "a", entity_type: "DOMAIN", evidence_ids: ["e"] }], edges: [],
    evidence: [{ id: "e", source: "dns", content_hash: "a".repeat(64) }], truncated: { entities: true } });
  assert.equal(g.nodes[0].source, "dns");
  assert.equal(g.nodes[0].classification, "unclassified");
  assert.equal(g.completeness.state, "partial");
  assert.match(g.warnings.join(" "), /non-atomic/);
});

test("dangling links are excluded, and missing evidence references are retained", () => {
  const f = fixture();
  f.edges.push({ id: "missing", source: "a", target: "absent" });
  f.nodes[0].evidence_ids.push("unavailable");
  const g = G.normalize(f);
  assert.equal(g.edges.length, 2);
  assert.equal(g.completeness.state, "partial");
  assert.deepEqual(g.nodes[0].evidence_ids, ["ev-a", "unavailable"]);
  assert.match(g.warnings.join(" "), /evidence reference\(s\) are unavailable/);
});

test("duplicate record IDs fail instead of silently merging unrelated records", () => {
  for (const field of ["nodes", "edges", "evidence"]) {
    const f = fixture();
    f[field].push({ ...f[field][0] });
    assert.throws(() => G.normalize(f), /Duplicate/);
  }
});

test("invalid supplied IDs are rejected, including empty edge IDs", () => {
  for (const bad of ["", " ", "bad\u0000id", "x".repeat(257), 0]) {
    const f = fixture();
    f.edges[0].id = bad;
    assert.throws(() => G.normalize(f), /Invalid graph record ID/);
  }
});

test("explicit cross-case records fail for nodes, edges and evidence", () => {
  for (const field of ["nodes", "edges", "evidence"]) {
    const f = fixture();
    f[field][0].case_id = "another-case";
    assert.throws(() => G.normalize(f), /another case/);
  }
});

test("Spider imports reject mixed scans and case reports reject mixed cases", () => {
  assert.throws(() => G.normalize({ scan: { id: "s1", case_id: "case-a" }, events: [{ id: "a", scan_id: "s2" }], edges: [] }), /another scan/);
  assert.throws(() => G.normalize({ case: { id: "case-a" }, spider_scans: [{ id: "s1", case_id: "case-b", events: [], edges: [] }] }), /another case/);
});

test("multiple scan imports namespace generated edge IDs without inventing links", () => {
  const g = G.normalize({ case: { id: "case-a" }, findings: [{ id: "not-a-node" }], spider_scans: [1, 2].map((n) => ({
    id: `s${n}`, case_id: "case-a", events: [{ id: `a${n}` }, { id: `b${n}` }], edges: [{ parent_id: `a${n}`, child_id: `b${n}`, module: "dns" }],
  })) });
  assert.deepEqual(ids(g.edges), ["s1:edge:0", "s2:edge:0"]);
  assert.equal(g.nodes.length, 4);
  assert.equal(g.edges[0].source_name, "dns");
});

test("record counts and evidence references are bounded before graph analysis", () => {
  const f = fixture();
  f.nodes = Array.from({ length: G.LIMITS.nodes + 1 }, (_, i) => ({ id: `n${i}` }));
  assert.throws(() => G.normalize(f), /record limit/);
  const f2 = fixture();
  f2.nodes[0].evidence_ids = Array.from({ length: 101 }, (_, i) => `e${i}`);
  assert.throws(() => G.normalize(f2), /Invalid evidence references/);
});

test("JSON size limit counts UTF-8 bytes, not just string length", () => {
  const raw = JSON.stringify({ ...fixture(), padding: "€".repeat(Math.floor(G.LIMITS.bytes / 3)) });
  assert.ok(raw.length < G.LIMITS.bytes);
  assert.throws(() => G.parseJSON(raw), /10 MiB/);
});

test("malformed, unsupported and future schema imports fail explicitly", () => {
  assert.throws(() => G.parseJSON("{"), /Invalid JSON/);
  for (const invalid of [null, [], {}, { schema_version: "traceatlas-graph/2", entities: [], edges: [] }]) {
    assert.throws(() => G.normalize(invalid));
  }
});

test("unknown confidence and classification are not upgraded to verified observations", () => {
  for (const confidence of [-1, 101, "80", NaN, Infinity, undefined]) {
    const g = G.normalize({ ...fixture(), nodes: [{ id: "a", confidence, classification: "verified" }], edges: [] });
    assert.equal(g.nodes[0].confidence, null);
    assert.equal(g.nodes[0].classification, "unclassified");
  }
});

test("timestamps require a timezone and a real calendar date", () => {
  for (const at of ["2026-02-30T10:00:00Z", "2026-09-27T10:00:00", "not-a-date"]) {
    assert.equal(G.normalize({ ...fixture(), nodes: [{ id: "a", at }], edges: [] }).nodes[0].at, null);
  }
  assert.equal(G.normalize({ ...fixture(), nodes: [{ id: "a", at: "2026-09-27T10:00:00+05:30" }], edges: [] }).nodes[0].at, "2026-09-27T04:30:00.000Z");
});

test("filters combine classifications, sources and confidence without dangling links", () => {
  const result = G.filterGraph(graph(), { source: "dns", classification: "observed", minConfidence: 80 });
  assert.deepEqual(ids(result.nodes), ["a", "b"]);
  assert.deepEqual(ids(result.edges), ["ab"]);
  assert.deepEqual(ids(G.filterGraph(graph(), { query: "EXAMPLE", type: "DOMAIN" }).nodes), ["a"]);
  assert.equal(G.filterGraph(graph(), { minConfidence: 1 }).nodes.some((n) => n.id === "d"), false);
});

test("date filters use inclusive UTC days and reject impossible or inverted dates", () => {
  assert.deepEqual(ids(G.filterGraph(graph(), { from: "2026-09-28", until: "2026-09-28" }).nodes), ["b"]);
  assert.throws(() => G.filterGraph(graph(), { from: "2026-02-30" }), /Invalid UTC date/);
  assert.throws(() => G.filterGraph(graph(), { from: "2026-09-28", until: "2026-09-27" }), /Start date/);
  assert.throws(() => G.filterGraph(graph(), { minConfidence: 101 }), /0–100/);
});

test("bounded shortest paths respect direction and report hidden endpoints", () => {
  const g = graph();
  assert.deepEqual(G.shortestPath(g, "a", "c"), { state: "found", nodes: ["a", "b", "c"], edges: ["ab", "bc"] });
  assert.equal(G.shortestPath(g, "a", "c", { maxHops: 1 }).state, "not-found");
  assert.equal(G.shortestPath(g, "c", "a").state, "not-found");
  assert.equal(G.shortestPath(g, "c", "a", { directed: false }).state, "found");
  assert.equal(G.shortestPath(G.filterGraph(g, { source: "dns" }), "a", "c").state, "endpoint-hidden");
  assert.throws(() => G.shortestPath(g, "a", "c", { maxHops: 13 }), /1–12/);
});

test("shortest paths terminate on cycles and disconnected graphs", () => {
  const f = fixture();
  f.edges.push({ id: "ca", source: "c", target: "a" });
  const g = G.normalize(f);
  assert.equal(G.shortestPath(g, "a", "d").state, "not-found");
  assert.deepEqual(G.shortestPath(g, "a", "a").nodes, ["a"]);
});

test("neighborhood exploration supports only one or two undirected hops", () => {
  assert.deepEqual(ids(G.neighborhood(graph(), "a", 1).nodes), ["a", "b"]);
  assert.deepEqual(ids(G.neighborhood(graph(), "a", 2).nodes), ["a", "b", "c"]);
  assert.equal(G.neighborhood(graph(), "missing").nodes.length, 0);
  assert.throws(() => G.neighborhood(graph(), "a", 3), /1 or 2/);
});

test("all layouts place every node, including disconnected nodes, deterministically", () => {
  for (const mode of ["grid", "radial", "layered"]) {
    const g = graph(), positions = G.layout(g, mode);
    assert.equal(positions.size, g.nodes.length);
    for (const p of positions.values()) assert.ok(Number.isFinite(p.x) && Number.isFinite(p.y));
    assert.deepEqual(positions, G.layout(g, mode));
    assert.equal(G.layout({ nodes: [], edges: [] }, mode).size, 0);
  }
});


test("viewports enclose node glyphs at both extremes in every layout", () => {
  for (const count of [1, 20, G.LIMITS.drawNodes]) {
    const g = { nodes: Array.from({ length: count }, (_, i) => ({ id: `n-${i}` })), edges: [] };
    for (const mode of ["grid", "radial", "layered"]) {
      const positions = G.layout(g, mode), box = G.viewport(positions);
      assert.ok(box.width >= 800 && box.height >= 420);
      for (const p of positions.values()) {
        assert.ok(p.x - 18 >= box.x && p.x + 18 <= box.x + box.width);
        assert.ok(p.y - 18 >= box.y && p.y + 48 <= box.y + box.height);
      }
      if (mode === "radial" && count >= 20) assert.ok(box.y < 0);
      if (mode === "radial" && count === G.LIMITS.drawNodes) assert.ok(box.x < 0);
      assert.deepEqual(box, G.viewport(positions));
    }
  }
  assert.deepEqual(G.viewport(new Map()), { x: 0, y: 0, width: 800, height: 420 });
});

test("measured label bounds expand the viewport beyond coordinate padding", () => {
  const painted = { x: -900.5, y: -300.5, width: 2800.25, height: 1500.25 };
  const box = G.viewport(new Map([["label", { x: 0, y: 0 }]]), painted);
  assert.ok(box.x <= painted.x - 24 && box.y <= painted.y - 24);
  assert.ok(box.x + box.width >= painted.x + painted.width + 24);
  assert.ok(box.y + box.height >= painted.y + painted.height + 24);
});

test("saved views reject changes to graph evidence, source or record details", () => {
  const original = graph(), saved = view(original);
  for (const mutate of [
    (g) => { g.evidence[0].content_hash = "b".repeat(64); },
    (g) => { g.nodes[0].details = "Changed observation"; },
    (g) => { g.edges[0].source_name = "another source"; },
    (g) => { g.case_id = "case-b"; },
    (g) => { g.synthetic = false; },
  ]) {
    const changed = structuredClone(original);
    mutate(changed);
    assert.throws(() => G.validateView(saved, changed), /different graph/);
  }
});

test("saved view identity is independent of record order", () => {
  const a = graph(), b = structuredClone(a);
  b.nodes.reverse(); b.edges.reverse(); b.evidence.reverse();
  assert.equal(G.identity(a), G.identity(b));
});

test("saved views validate coordinates, duplicates and node membership", () => {
  const g = graph();
  const restored = G.validateView(view(g, { selected: "a", positions: [{ id: "a", x: 1, y: 2 }], filters: { source: "dns" } }), g);
  assert.deepEqual(restored.positions.get("a"), { x: 1, y: 2 });
  assert.equal(restored.selected, "a");
  for (const positions of [
    [{ id: "missing", x: 1, y: 2 }], [{ id: "a", x: Infinity, y: 2 }],
    [{ id: "a", x: 1e7, y: 2 }], [{ id: "a", x: 1, y: 2 }, { id: "a", x: 3, y: 4 }],
  ]) assert.throws(() => G.validateView(view(g, { positions }), g), /Invalid saved positions/);
});

test("actual Python case report and Spider export import without network or credentials", () => {
  const script = `
import json, tempfile
from pathlib import Path
from traceatlas.db import CaseDB
from traceatlas.spider.events import Event, child
from traceatlas.spider.export import export_scan
from traceatlas.report import build_report
with tempfile.TemporaryDirectory() as directory:
    db = CaseDB(Path(directory) / "case.sqlite3")
    db.create_case("case-a", "Synthetic fixture", "Offline integration test")
    db.start_spider_scan("scan-a", "case-a", "DOMAIN", "example.org", "passive")
    seed = Event("DOMAIN", "example.org", "seed", "scan-a", "case-a")
    db.add_spider_event(seed.to_dict())
    db.add_spider_event(child(seed, "IP_ADDRESS", "203.0.113.10", "dns").to_dict())
    exported = export_scan(db, "scan-a", Path(directory) / "scan.json", "json")
    print(json.dumps({"report": build_report(db, "case-a"), "spider": json.loads(exported.read_text())}))
    db.conn.close()
`;
  const root = path.resolve(__dirname, "..");
  const result = spawnSync(process.env.PYTHON || "python", ["-c", script], { cwd: root, env: { ...process.env, PYTHONPATH: path.join(root, "src") }, encoding: "utf8", timeout: 10000 });
  assert.equal(result.status, 0, result.stderr || String(result.error));
  const exports = JSON.parse(result.stdout);
  for (const input of [exports.report, exports.spider]) {
    const g = G.normalize(input);
    assert.equal(g.case_id, "case-a");
    assert.equal(g.nodes.length, 2);
    assert.equal(g.edges.length, 1);
    assert.equal(g.nodes[0].classification, "unclassified");
    assert.equal(G.shortestPath(g, g.edges[0].source, g.edges[0].target).state, "found");
  }
});
