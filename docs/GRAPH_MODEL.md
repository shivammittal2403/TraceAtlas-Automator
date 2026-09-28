# Graph model module

`public/graph-model.js` is a dependency-free graph-analysis library for Node.js
and browsers. It is available as CommonJS `module.exports` or the browser global
`TraceAtlasGraph`. The authenticated dashboard uses it for cloud case graphs
and browser-only local JSON imports. Analysts can filter by label,
classification and confidence, switch layouts, inspect evidence references
and highlight a bounded directed path. Imported files are never uploaded.
The UI draws at most 250 nodes and 1,000 links; narrow filters to inspect
larger exports. Browser graph state is cleared at sign-out.

## Supported input

- TraceAtlas Spider JSON exports (`scan`, `events`, `edges`).
- TraceAtlas case JSON reports (`case`, `spider_scans`, optional `evidence`). Only
  explicit Spider events and links become graph records; findings do not create
  speculative relationships.
- Cloud `/api/graph` response objects (`case_id`, `entities`, `edges`, `evidence`).
  A response is a bounded snapshot; the model does not fetch it or authenticate.
- Normalized `traceatlas-graph/1` records. Unknown future graph versions fail.

Duplicate IDs and explicit case/scan mismatches fail. Links with missing
endpoints are excluded and produce a partial-snapshot warning. Missing evidence
references remain visible in the normalized data with a warning. Supplied
classification and confidence are preserved; unknown values do not become
verified observations. No input is treated as complete by default.

## Usage

```javascript
const fs = require("node:fs");
const graphModel = require("./public/graph-model.js");
const graph = graphModel.parseJSON(fs.readFileSync("scan.json", "utf8"));
const visible = graphModel.filterGraph(graph, { minConfidence: 60 });
const path = graphModel.shortestPath(visible, "node-a", "node-b", {
  directed: true, maxHops: 6,
});
const positions = graphModel.layout(visible, "layered");
```

| Function | Behavior |
| --- | --- |
| `normalize(object)` | Validate and adapt an already parsed export. |
| `parseJSON(string)` | Enforce the UTF-8 byte limit, parse and normalize. |
| `filterGraph(graph, filters)` | Filter nodes by query, type, source, classification, confidence and inclusive UTC dates. Edges must have visible endpoints and meet classification/confidence filters. |
| `shortestPath(graph, start, end, options)` | Directed by default, 1–12 hops; returns `found`, `not-found` or `endpoint-hidden`. A path is an explicit graph connection, not proof of attribution or causality. |
| `neighborhood(graph, center, hops)` | One or two undirected hops over explicit links. |
| `layout(graph, mode)` | Deterministic `grid`, `radial` or `layered` coordinates, including disconnected nodes. Placement has no evidentiary meaning. |
| `identity(graph)` | Serialized view binding to normalized records and evidence. This contains graph data and is not a cryptographic signature. |
| `validateView(view, graph)` | Reject mismatched evidence/graph content, invalid coordinates and duplicate or unknown nodes. Returns filters, positions and selected node; does not persist them. |

## Limits and integration boundary

Imports are limited to 10 MiB of UTF-8 JSON, 2,000 nodes, 5,000 edges and 2,000
evidence records. Labels and details are bounded display projections; keep the
original export as evidence. `normalize` takes an already parsed object and
enforces record limits; callers accepting files should use `parseJSON` and check
file size before reading. Dates must include a timezone. Invalid record dates
become unknown; invalid filter dates fail.

The library performs no network requests, collection, DOM rendering, storage,
entity merging or cryptographic verification. Render labels with `textContent`;
never interpret imported strings as HTML. View binding checks normalized content,
not the authenticity of the original evidence file. `LIMITS.drawNodes` and
`LIMITS.drawEdges` are suggested renderer budgets; this library has no renderer.

The cloud endpoint supplies per-record evidence IDs and explicit truncation
flags. Its reads remain bounded and non-atomic; missing evidence records and
links to entities outside a capped result remain visible as warnings.

## Verification

```bash
node --test tests/test_graph_model.cjs
PYTHONPATH=src python -m unittest discover -s tests -v
```

The JavaScript suite includes real Python-generated case and Spider exports,
UTF-8 size limits, malformed/mixed-case data, bounded paths, filtering, layouts
and stale-evidence view rejection. CI runs it with both supported Python matrix
versions. No provider credentials or live lookups are needed.
