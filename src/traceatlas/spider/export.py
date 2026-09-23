from __future__ import annotations

import json
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, ElementTree

from ..db import CaseDB
from .correlation import correlate


def export_scan(db: CaseDB, scan_id: str, output: Path, fmt: str) -> Path:
    scan = db.spider_scan(scan_id)
    if not scan:
        raise ValueError(f"Unknown spider scan: {scan_id}")
    events, edges = db.spider_events(scan_id), db.spider_edges(scan_id)
    output.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        output.write_text(json.dumps({
            "scan": scan, "events": events, "edges": edges,
            "correlations": correlate(events),
        }, indent=2, ensure_ascii=False), encoding="utf-8")
    elif fmt == "gexf":
        root = Element("gexf", xmlns="http://www.gexf.net/1.3", version="1.3")
        graph = SubElement(root, "graph", mode="static", defaultedgetype="directed")
        nodes = SubElement(graph, "nodes")
        for event in events:
            SubElement(nodes, "node", id=event["id"],
                       label=f"{event['event_type']}: {str(event['data'])[:120]}")
        xml_edges = SubElement(graph, "edges")
        for index, edge in enumerate(edges):
            SubElement(xml_edges, "edge", id=str(index), source=edge["parent_id"],
                       target=edge["child_id"], label=edge["module"])
        ElementTree(root).write(output, encoding="utf-8", xml_declaration=True)
    else:
        raise ValueError("Format must be json or gexf")
    return output

