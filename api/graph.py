import urllib.parse
from http.server import BaseHTTPRequestHandler

from vercel_control import authenticated_gateway, handle_error, require_uuid, send_json


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        try:
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            case_id = require_uuid((query.get("case_id") or [""])[0], "case_id")
            gateway, _ = authenticated_gateway(self)
            common = {"case_id": f"eq.{case_id}", "limit": "501"}
            entities = gateway.select("graph_entities", {**common,
                "select": "id,entity_type,label,confidence,classification,evidence_id,created_at", "order": "created_at.asc"})
            edges = gateway.select("graph_edges", {**common,
                "select": "id,source_entity_id,target_entity_id,relationship,confidence,classification,evidence_id,created_at",
                "order": "created_at.asc"})
            evidence = gateway.select("evidence_items", {**common,
                "select": "id,source,classification,content_hash,created_at", "order": "created_at.desc",
                "limit": "201"})
            truncated = {"entities": len(entities) > 500, "edges": len(edges) > 500,
                         "evidence": len(evidence) > 200}
            for row in entities[:500] + edges[:500]:
                row["evidence_ids"] = [row["evidence_id"]] if row.get("evidence_id") else []
                row.pop("evidence_id", None)
            send_json(self, 200, {"case_id": case_id, "entities": entities[:500], "edges": edges[:500],
                                  "evidence": evidence[:200], "truncated": truncated, "review_required": True})
        except Exception as exc:
            handle_error(self, exc)

    def do_POST(self) -> None:
        send_json(self, 405, {"error": "method_not_allowed"})
