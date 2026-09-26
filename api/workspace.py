import urllib.parse
from collections import Counter
from http.server import BaseHTTPRequestHandler

from vercel_control import (
    ControlPlaneError, authenticated_gateway, handle_error, require_uuid, send_json,
)


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        try:
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            case_id = require_uuid((query.get("case_id") or [""])[0], "case_id")
            gateway, _ = authenticated_gateway(self)
            cases = gateway.select("cases", {
                "id": f"eq.{case_id}",
                "select": "id,organisation_id,title,purpose,status,created_at,updated_at",
                "limit": "1",
            })
            if len(cases) != 1:
                raise ControlPlaneError(404, "case_not_found")
            common = {"case_id": f"eq.{case_id}", "order": "created_at.desc"}
            jobs = gateway.select("investigation_jobs", {
                **common, "select": "id,kind,status,attempt,created_at,completed_at", "limit": "200",
            })
            evidence = gateway.select("evidence_items", {
                **common, "select": "id,source,classification,content_hash,created_at", "limit": "500",
            })
            runs = gateway.select("source_runs", {
                **common,
                "select": "id,source,mode,status,records_received,records_stored,failure_code,started_at,completed_at",
                "limit": "500", "order": "started_at.desc",
            })
            reviews = gateway.select("review_tasks", {
                **common, "select": "id,kind,title,priority,status,created_at,decided_at", "limit": "200",
            })
            notes = gateway.select("case_notes", {
                **common, "select": "id,classification,created_at", "limit": "200",
            })
            source_states = Counter((row["source"], row["status"]) for row in runs)
            coverage = {}
            for (source, state), count in sorted(source_states.items()):
                coverage.setdefault(source, {})[state] = count
            timeline = sorted([
                *({"at": row["started_at"], "kind": "source-run", "id": row["id"],
                   "label": row["source"], "state": row["status"]} for row in runs),
                *({"at": row["created_at"], "kind": "evidence", "id": row["id"],
                   "label": row["source"], "state": row["classification"]} for row in evidence),
                *({"at": row["created_at"], "kind": "review", "id": row["id"],
                   "label": row["kind"], "state": row["status"]} for row in reviews),
            ], key=lambda row: (row["at"], row["kind"], row["id"]), reverse=True)[:500]
            send_json(self, 200, {
                "case": cases[0],
                "overview": {"jobs": len(jobs), "source_runs": len(runs),
                             "evidence_items": len(evidence), "review_tasks": len(reviews),
                             "notes": len(notes)},
                "coverage": coverage,
                "review_queue": {
                    "pending": sum(row["status"] == "pending" for row in reviews),
                    "failed_runs": sum(row["status"] == "failed" for row in runs),
                },
                "timeline": timeline,
                "limitations": [
                    "Missing source coverage is not negative evidence.",
                    "Model output and inferred entities require analyst review.",
                ],
            })
        except Exception as exc:
            handle_error(self, exc)

    def do_POST(self) -> None:
        send_json(self, 405, {"error": "method_not_allowed"})
