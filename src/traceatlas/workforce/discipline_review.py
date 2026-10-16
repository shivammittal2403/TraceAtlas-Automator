"""Trusted canonical projection of bounded, supplied-record hypothesis reviews."""
from __future__ import annotations

from .contracts import Hypothesis
from .discipline_engines import invoke_employee
from .discipline_engines.common import canonical, digest

REVIEWED_DISCIPLINES = frozenset({"HYPOTHESISINT", "FALSIFICATIONINT"})
REVIEWED_PRODUCT_SCHEMA = "traceatlas-discipline-product/v2"
MAX_REVIEW_BYTES = 2 * 1024 * 1024


def project_discipline_review(payload, evidence_id, acquisition_id):
    """Recompute native review; callback artifacts never establish canonical hypotheses."""
    label = payload["discipline"]
    if label not in REVIEWED_DISCIPLINES:
        return (), None, ()
    native = invoke_employee(payload, evidence_ids=(evidence_id,))
    records = {row["record_id"]: row for row in payload["records"]}
    hypotheses, projections = [], []
    omitted = {"canonical_limit": 0, "invalid_statement": 0}
    for matrix in native["artifacts"].get("hypotheses", []):
        record = records[matrix["record_id"]]
        supplied = {item["id"].strip(): item["statement"]
                    for item in record["data"]["hypotheses"]
                    if isinstance(item, dict) and isinstance(item.get("id"), str)
                    and item["id"].strip() and isinstance(item.get("statement"), str)
                    and item["statement"].strip()}
        for ranking in matrix["ranking"]:
            local_id = ranking["hypothesis_id"]
            identifier = "hypothesis-" + digest([
                payload["case_id"], payload["task_id"], matrix["record_id"], local_id])[:32]
            projection = {"matrix_record_id": matrix["record_id"],
                          "supplied_hypothesis_id": local_id,
                          "hypothesis_id": None, "status": "NOT_PROJECTED"}
            if len(hypotheses) >= 100:
                omitted["canonical_limit"] += 1
                projection["status"] = "CANONICAL_LIMIT"
            else:
                try:
                    hypothesis = Hypothesis(
                        identifier, supplied[local_id], (evidence_id,),
                        ("review-supplied-assessments", "review-source-authenticity",
                         "seek-scope-bound-counterevidence"))
                except ValueError:
                    omitted["invalid_statement"] += 1
                    projection["status"] = "INVALID_CANONICAL_STATEMENT"
                else:
                    hypotheses.append(hypothesis)
                    projection.update(hypothesis_id=identifier, status="PROJECTED")
            projections.append(projection)
    gaps = ["discipline-review-native-issue-" + digest(issue)[:24]
            for issue in native["issues"]]
    gaps.extend("discipline-review-" + reason.replace("_", "-")
                for reason, count in omitted.items() if count)
    if label == "FALSIFICATIONINT":
        gaps.append("standalone-falsification-no-typed-proposition")
    sidecar = {
        "schema": "traceatlas.discipline.hypothesis-review.v1",
        "input_sha256": native["input_sha256"],
        "input_evidence_id": evidence_id,
        "native_review_status": native["status"],
        "recomputed_from_preserved_input": True,
        "source_authenticity_verified": False,
        "origin_group_independence_verified": False,
        "factual_entailment_verified": False,
        "requires_human_review": True,
        "record_provenance": [
            {"record_id": row["record_id"], "asserted_source_id": row["source_id"],
             "evidence_id": evidence_id, "acquisition_id": acquisition_id,
             "input_pointer": "/records/" + str(index)}
            for index, row in enumerate(payload["records"])],
        "native_artifacts": native["artifacts"],
        "native_metrics": native["metrics"],
        "native_issues": native["issues"],
        "limitations": native["limitations"],
        "canonical_projection": projections,
        "hypotheses_omitted": omitted,
        "canonical_hypotheses": [item.to_dict() for item in hypotheses],
    }
    if len(canonical(sidecar).encode("utf-8")) > MAX_REVIEW_BYTES:
        raise ValueError("Canonical discipline review exceeds its bounded output; split submitted records")
    return tuple(hypotheses), sidecar, tuple(dict.fromkeys(gaps))
