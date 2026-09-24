from __future__ import annotations

import hashlib
import json
import math
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from .db import CaseDB
from .evidence import EvidenceStore
from .policy import PolicyError


MAX_FUSION_BYTES = 10 * 1024 * 1024
SCOPES = {"location", "source", "claim", "identity", "organisation", "infrastructure"}
CLASSIFICATIONS = {"observed", "inference", "model-output"}
SECRET_KEY = re.compile(r"password|passwd|secret|token|api[_-]?key|cookie|authorization", re.I)


class FusionBoard:
    """Transparent multi-source candidate ranking without identity attribution."""

    def __init__(self, db: CaseDB, workspace: Path):
        self.db = db
        self.workspace = workspace

    @staticmethod
    def _load(path: Path) -> list[dict[str, Any]]:
        if not path.is_file() or path.stat().st_size > MAX_FUSION_BYTES:
            raise PolicyError("Fusion input must be a JSON/JSONL file up to 10 MiB")
        text = path.read_text(encoding="utf-8", errors="replace")
        try:
            raw = json.loads(text)
            rows = raw.get("signals", raw.get("records", [])) if isinstance(raw, dict) else raw
        except json.JSONDecodeError:
            try:
                rows = [json.loads(line) for line in text.splitlines() if line.strip()]
            except json.JSONDecodeError as exc:
                raise PolicyError(f"Invalid fusion JSON/JSONL: {exc}") from exc
        if not isinstance(rows, list) or len(rows) > 10_000:
            raise PolicyError("Fusion input must contain at most 10,000 signal records")
        return [row for row in rows if isinstance(row, dict)]

    @staticmethod
    def _coarse_coordinates(row: dict[str, Any]) -> dict[str, float] | None:
        try:
            lat = float(row.get("latitude", row.get("lat")))
            lon = float(row.get("longitude", row.get("lon")))
        except (TypeError, ValueError):
            return None
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            return None
        return {"latitude_coarse": round(lat, 2), "longitude_coarse": round(lon, 2)}

    @staticmethod
    def rank_rows(rows: list[dict[str, Any]], scope: str) -> dict[str, Any]:
        if scope not in SCOPES:
            raise PolicyError("Unsupported fusion scope")
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        seen: set[str] = set()
        dropped = 0
        for row in rows:
            if any(SECRET_KEY.search(str(key)) for key in row):
                dropped += 1
                continue
            candidate = str(row.get("candidate") or row.get("label") or "").strip()[:300]
            source = str(row.get("source") or "").strip()[:200]
            signal = str(row.get("signal") or row.get("observation") or "").strip()[:1000]
            evidence = str(row.get("evidence") or row.get("evidence_sha256") or "")[:500]
            classification = str(row.get("classification") or "observed").lower()
            if not candidate or not source or not signal or classification not in CLASSIFICATIONS:
                dropped += 1
                continue
            fingerprint = hashlib.sha256(
                json.dumps([candidate.lower(), source.lower(), signal, evidence], sort_keys=True).encode()
            ).hexdigest()
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            confidence = max(1, min(99, int(row.get("confidence", 50))))
            supports = bool(row.get("supports", True))
            multiplier = {"observed": 1.0, "inference": 0.5, "model-output": 0.35}[classification]
            reliability = 0.5 + (confidence / 100) * 0.49
            log_weight = math.log(reliability / (1 - reliability)) * multiplier
            grouped[candidate].append({
                "source": source, "signal": signal, "evidence": evidence,
                "classification": classification, "confidence": confidence,
                "supports": supports, "log_weight": log_weight if supports else -log_weight,
                "coarse_coordinates": FusionBoard._coarse_coordinates(row),
            })

        candidates = []
        for candidate, signals in grouped.items():
            # One provider cannot dominate by repeating its own conclusion.
            per_source: dict[str, float] = defaultdict(float)
            for item in signals:
                value = item["log_weight"]
                per_source[item["source"]] += max(-2.2, min(2.2, value))
            total = sum(max(-3.0, min(3.0, value)) for value in per_source.values())
            score = round(100 / (1 + math.exp(-max(-8.0, min(8.0, total)))), 2)
            coordinates = [
                item["coarse_coordinates"] for item in signals
                if item["supports"] and item["coarse_coordinates"]
            ]
            contradictions = [item for item in signals if not item["supports"]]
            candidates.append({
                "candidate": candidate, "score": score,
                "independent_sources": len(per_source), "signals": len(signals),
                "supporting_signals": [
                    {key: item[key] for key in ("source", "signal", "evidence", "classification", "confidence")}
                    for item in signals if item["supports"]
                ],
                "contradictions": [
                    {key: item[key] for key in ("source", "signal", "evidence", "classification", "confidence")}
                    for item in contradictions
                ],
                "coarse_coordinates": coordinates[0] if coordinates else None,
                "review_required": True,
            })
        candidates.sort(key=lambda row: (-row["score"], -row["independent_sources"], row["candidate"].lower()))
        return {
            "schema": "traceatlas-fusion-board-1.0", "scope": scope,
            "candidates": candidates[:250], "records_received": len(rows),
            "records_dropped": dropped, "records_deduplicated": len(rows) - dropped - len(seen),
            "method": "bounded log-odds; per-source caps; inference and model-output discounts",
            "limitations": [
                "Scores rank supplied evidence; they are not probabilities of identity or guilt.",
                "Source independence is operator-asserted and must be reviewed.",
                "Coordinates are reduced to two decimal places before storage.",
            ],
        }

    def rank(self, case_id: str, path: Path, scope: str, *, authorized: bool,
             subject_consent: bool = False, owned_asset: bool = False,
             owned_org: bool = False) -> dict[str, Any]:
        if not authorized:
            raise PolicyError("Fusion ranking requires explicit --authorized confirmation")
        if not self.db.get_case(case_id):
            raise PolicyError(f"Unknown case: {case_id}")
        if scope == "identity" and not subject_consent:
            raise PolicyError("Identity fusion requires explicit --subject-consent")
        if scope == "location" and not (subject_consent or owned_asset):
            raise PolicyError("Location fusion requires --subject-consent or --owned-asset")
        if scope in {"organisation", "infrastructure"} and not owned_org:
            raise PolicyError("Organisation/infrastructure fusion requires --owned-org")
        result = self.rank_rows(self._load(path), scope)
        result["case_id"] = case_id
        output_dir = self.workspace / "fusion" / case_id
        output_dir.mkdir(parents=True, exist_ok=True)
        output = output_dir / f"{path.stem}-{scope}.ranked.json"
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        record = EvidenceStore(self.workspace, self.db, case_id).preserve_file(output, f"fusion:{scope}")
        return {"status": "completed", "candidates": len(result["candidates"]),
                "output": str(output), "sha256": record["sha256"], "review_required": True}

    def geojson(self, case_id: str, ranked_file: Path, output: Path, *, authorized: bool,
                subject_consent: bool = False, owned_asset: bool = False) -> dict[str, Any]:
        if not authorized or not (subject_consent or owned_asset):
            raise PolicyError("GeoJSON export requires authorization plus consent or asset ownership")
        if not self.db.get_case(case_id):
            raise PolicyError(f"Unknown case: {case_id}")
        if not ranked_file.is_file() or ranked_file.stat().st_size > MAX_FUSION_BYTES:
            raise PolicyError("Ranked fusion file is missing or too large")
        data = json.loads(ranked_file.read_text(encoding="utf-8"))
        if data.get("scope") != "location" or data.get("case_id") != case_id:
            raise PolicyError("GeoJSON export requires a location fusion result from the same case")
        features = []
        for row in data.get("candidates", [])[:250]:
            point = row.get("coarse_coordinates")
            if not point:
                continue
            features.append({
                "type": "Feature",
                "geometry": {"type": "Point", "coordinates": [point["longitude_coarse"], point["latitude_coarse"]]},
                "properties": {"candidate": row["candidate"], "score": row["score"],
                               "review_required": True, "precision": "coarse-2-decimals"},
            })
        collection = {"type": "FeatureCollection", "features": features}
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(collection, ensure_ascii=False, indent=2), encoding="utf-8")
        record = EvidenceStore(self.workspace, self.db, case_id).preserve_file(output, "fusion:geojson")
        return {"status": "completed", "features": len(features), "output": str(output), "sha256": record["sha256"]}
