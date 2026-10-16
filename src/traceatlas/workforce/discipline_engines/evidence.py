"""Evidence reasoning with explicit citation, lineage and uncertainty semantics."""
from __future__ import annotations

from collections import defaultdict
import hashlib
import json
import math
import re

from .common import AnalysisContext
from .discovery import _interval, _strong_components, _value_key
from .media import canonical_measurement, number

HEX256 = re.compile(r"[0-9a-fA-F]{64}")


def _text(value):
    return value.strip() if isinstance(value, str) else ""


def _hash(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _known(ctx):
    return {record.record_id: record for record in ctx.records}


def _origin(ctx, source_id):
    path, current = [], source_id
    while current in ctx.sources:
        if current in path:
            return None, path[path.index(current):] + [current]
        path.append(current)
        source = ctx.sources[current]
        parent = _text(source.get("original_source_id"))
        if not parent:
            publisher = _text(source.get("publisher_id"))
            return ("publisher:" + publisher if publisher else
                    "origin:" + current if current != source_id else None), path
        if parent not in ctx.sources:
            return "external-origin:" + parent, path + [parent]
        current = parent
    return None, path


def _in_scope(data, as_of):
    lower = _interval(data["valid_from"])[0] if data.get("valid_from") else None
    upper = _interval(data["valid_to"])[1] if data.get("valid_to") else None
    if lower is not None and upper is not None and upper <= lower:
        raise ValueError("Reversed validity interval")
    return not ((lower is not None and as_of < lower) or
                (upper is not None and as_of >= upper))


def sourceint(ctx: AnalysisContext):
    rows, hash_groups, cycles, cycle_keys = [], defaultdict(list), [], set()
    for source_id, metadata in sorted(ctx.sources.items()):
        group, chain = _origin(ctx, source_id)
        ids = [r.record_id for r in ctx.records if r.source_id == source_id]
        cyclic = len(chain) != len(set(chain))
        if cyclic:
            cycle_key = tuple(sorted(set(chain)))
            if cycle_key not in cycle_keys:
                cycles.append(list(cycle_key))
                cycle_keys.add(cycle_key)
            ctx.issue(ids[0] if ids else None, "source_lineage_cycle",
                      "Declared original-source links contain a cycle.")
        digest = metadata.get("content_sha256")
        if isinstance(digest, str):
            hash_groups[digest.lower()].append(source_id)
        item = {"source_id": source_id, "declared_chain": chain,
                "declared_origin_group": group, "cycle": cyclic,
                "lineage_complete": group is not None and not cyclic,
                "independence_verified": False}
        rows.append(item)
        if ids:
            ctx.finding("declared_source_lineage", "Traced declared source ancestry without assuming independence.",
                        ids, data=item)
    duplicate_hashes = [{"sha256": digest, "source_ids": ids} for digest, ids in sorted(hash_groups.items())
                        if len(ids) > 1]
    return ctx.output(
        metrics={"sources": len(rows), "unresolved_origins": sum(
            row["declared_origin_group"] is None for row in rows),
            "lineage_cycles": len(cycles), "shared_declared_hash_groups": len(duplicate_hashes)},
        artifacts={"source_lineage": rows, "shared_declared_hashes": duplicate_hashes},
        limitations=("Source metadata and content hashes are asserted; different source IDs do not prove independence.",),
    )


def provenanceint(ctx: AnalysisContext):
    artifacts, by_id = [], defaultdict(list)
    for record in ctx.records:
        artifact_id = _text(record.data.get("artifact_id"))
        parents = record.data.get("parents", [])
        if not artifact_id or not isinstance(parents, list):
            ctx.issue(record.record_id, "invalid_artifact_manifest", "Artifact requires artifact_id and parents array.")
            continue
        declared = record.data.get("sha256")
        if declared is not None and (not isinstance(declared, str) or not HEX256.fullmatch(declared)):
            ctx.issue(record.record_id, "invalid_artifact_hash", "Declared SHA-256 must contain 64 hexadecimal characters.")
            continue
        computed = _hash(record.data["content_text"]) if isinstance(record.data.get("content_text"), str) else None
        if "content_text" in record.data and computed is None:
            ctx.issue(record.record_id, "invalid_artifact_content", "content_text must be text.")
            continue
        mismatch = bool(computed and declared and computed != declared.lower())
        if mismatch:
            ctx.issue(record.record_id, "artifact_hash_mismatch", "Supplied content differs from the declared artifact hash.")
        if not computed and not declared:
            ctx.issue(record.record_id, "artifact_digest_missing", "Artifact has no supplied content or declared digest.")
        links = []
        for parent in parents:
            if isinstance(parent, str):
                parent = {"artifact_id": parent}
            if not isinstance(parent, dict) or not _text(parent.get("artifact_id")):
                ctx.issue(record.record_id, "invalid_artifact_parent", "Parent requires an artifact identifier.")
                continue
            expected = parent.get("sha256")
            if expected is not None and (not isinstance(expected, str) or not HEX256.fullmatch(expected)):
                ctx.issue(record.record_id, "invalid_parent_hash", "Parent digest is malformed.")
                continue
            links.append({"artifact_id": parent["artifact_id"].strip(),
                          "expected_sha256": expected.lower() if expected else None})
        item = {"record": record, "artifact_id": artifact_id, "parents": links,
                "effective_sha256": computed or (declared.lower() if declared else None),
                "computed_from_supplied_text": computed is not None, "hash_mismatch": mismatch,
                "transformation": _text(record.data.get("transformation")) or "undeclared"}
        artifacts.append(item)
        by_id[artifact_id].append(item)
    unique = {key: rows[0] for key, rows in by_id.items() if len(rows) == 1}
    for key, rows in by_id.items():
        if len(rows) > 1:
            ctx.issue(rows[0]["record"].record_id, "ambiguous_artifact_id",
                      "Repeated artifact IDs remain separate manifests: " + key)
    edges, gaps, parent_mismatches = [], [], []
    for item in artifacts:
        unresolved_count, mismatch_count = 0, 0
        for parent in item["parents"]:
            target = unique.get(parent["artifact_id"])
            if target is None:
                gaps.append({"artifact_id": item["artifact_id"], "parent_id": parent["artifact_id"]})
                unresolved_count += 1
                continue
            if item["artifact_id"] in unique:
                edges.append((item["artifact_id"], parent["artifact_id"]))
            expected = parent["expected_sha256"]
            if expected and target["effective_sha256"] and expected != target["effective_sha256"]:
                parent_mismatches.append({"artifact_id": item["artifact_id"], "parent_id": parent["artifact_id"]})
                mismatch_count += 1
        if unresolved_count:
            ctx.issue(item["record"].record_id, "unresolved_artifact_parent",
                      str(unresolved_count) + " parent artifact references are missing or ambiguous.")
        if mismatch_count:
            ctx.issue(item["record"].record_id, "parent_hash_mismatch",
                      str(mismatch_count) + " expected parent hashes differ from their manifests.")
    cycles = _strong_components(unique, edges)
    cyclic = {item for group in cycles for item in group}
    cache, traversal = {}, {"uncached_visits": 0, "limited": False, "depth_limited": False}
    def chain_hash(key, active=()):
        if key in cache:
            return cache[key]
        if len(active) >= 200:
            traversal["depth_limited"] = True
            cache[key] = None
            return None
        if traversal["uncached_visits"] >= 10000:
            traversal["limited"] = True
            cache[key] = None
            return None
        traversal["uncached_visits"] += 1
        if key in active or key not in unique or key in cyclic:
            cache[key] = None
            return None
        item = unique[key]
        if item["hash_mismatch"] or item["effective_sha256"] is None:
            cache[key] = None
            return None
        parents = []
        for parent in item["parents"]:
            digest = chain_hash(parent["artifact_id"], active + (key,))
            target = unique.get(parent["artifact_id"])
            if digest is None or (parent["expected_sha256"] and
                                  parent["expected_sha256"] != target["effective_sha256"]):
                cache[key] = None
                return None
            parents.append((parent["artifact_id"], digest))
        digest = _hash(json.dumps({"artifact_id": key, "sha256": item["effective_sha256"],
                                  "parents": sorted(parents), "transformation": item["transformation"]},
                                 sort_keys=True, separators=(",", ":")))
        cache[key] = digest
        return digest
    results = []
    for item in artifacts:
        result = {key: value for key, value in item.items() if key != "record"}
        result["record_id"] = item["record"].record_id
        result["parent_count"] = len(item["parents"])
        result["parents"] = item["parents"][:200]
        result["parents_truncated"] = len(item["parents"]) > 200
        result["chain_digest"] = chain_hash(item["artifact_id"]) if item["artifact_id"] in unique else None
        result["authenticity_verified"] = False
        results.append(result)
        ctx.finding("artifact_provenance_consistency", "Checked supplied artifact hashes and derivation links.",
                    [item["record"].record_id], data=result)
    if traversal["limited"]:
        ctx.issue(None, "provenance_traversal_limit", "Chain digest work exceeded the bounded traversal budget.")
    if traversal["depth_limited"]:
        ctx.issue(None, "provenance_depth_limit", "Chain digest exceeds the supported lineage depth.")
    return ctx.output(
        metrics={"artifact_manifests": len(results), "ambiguous_artifact_ids": sum(
            len(rows) > 1 for rows in by_id.values()), "parent_gaps": len(gaps),
            "parent_hash_mismatches": len(parent_mismatches), "lineage_cycles": len(cycles),
            "chain_traversal_visits": traversal["uncached_visits"],
            "chain_traversal_limited": traversal["limited"], "chain_depth_limited": traversal["depth_limited"]},
        artifacts={"artifacts": results, "cycles": cycles[:200], "parent_gaps": gaps[:200],
                   "parent_hash_mismatches": parent_mismatches[:200],
                   "lineage_artifacts_truncated": {"cycles": len(cycles) > 200,
                       "parent_gaps": len(gaps) > 200, "parent_hash_mismatches": len(parent_mismatches) > 200}},
        limitations=("A consistent local chain digest does not prove historical custody, transformation execution or source authenticity.",),
    )


def corroborationint(ctx: AnalysisContext):
    groups = defaultdict(list)
    for record in ctx.records:
        claim_id, stance = _text(record.data.get("claim_id")), record.data.get("stance")
        if not claim_id or not isinstance(stance, str) or stance not in {"support", "refute", "neutral"}:
            ctx.issue(record.record_id, "invalid_corroboration_record", "Record requires claim_id and support/refute/neutral stance.")
            continue
        try:
            if not _in_scope(record.data, ctx.as_of):
                ctx.issue(record.record_id, "corroboration_outside_as_of", "Assessment is outside its validity interval.")
                continue
        except (ValueError, OverflowError):
            ctx.issue(record.record_id, "invalid_corroboration_time", "Assessment validity is malformed.")
            continue
        origin, _ = _origin(ctx, record.source_id)
        groups[claim_id].append((record, stance, origin))
    assessments = []
    for claim_id, rows in sorted(groups.items()):
        support = sorted({origin for _, stance, origin in rows if stance == "support" and origin})
        refute = sorted({origin for _, stance, origin in rows if stance == "refute" and origin})
        unknown = sorted({record.source_id for record, stance, origin in rows if stance != "neutral" and not origin})
        item = {"claim_id": claim_id, "declared_support_groups": support, "declared_refute_groups": refute,
                "unknown_origin_sources": unknown, "support_records": sum(stance == "support" for _, stance, _ in rows),
                "refute_records": sum(stance == "refute" for _, stance, _ in rows),
                "assessment": "CONTESTED" if any(stance == "refute" for _, stance, _ in rows) and
                any(stance == "support" for _, stance, _ in rows) else
                "SUPPORT_ASSERTIONS_ONLY" if any(stance == "support" for _, stance, _ in rows) else
                "REFUTATION_ASSERTIONS_ONLY" if any(stance == "refute" for _, stance, _ in rows) else "NEUTRAL_ONLY",
                "independence_verified": False, "factual_truth_verified": False}
        assessments.append(item)
        ctx.finding("claim_corroboration_coverage", "Counted source-origin support and refutation without counting copies as independence.",
                    [record.record_id for record, _, _ in rows], data=item)
    return ctx.output(
        metrics={"claims": len(assessments)}, artifacts={"corroboration": assessments},
        limitations=("Stance and lineage are supplied assessments; corroboration coverage is not a truth verdict.",),
    )


def _claim(data):
    if not isinstance(data, dict) or not _text(data.get("subject")) or not _text(data.get("predicate")) or "value" not in data:
        raise ValueError("Claim requires subject, predicate and explicit value")
    polarity = data.get("polarity", "affirmed")
    cardinality = data.get("cardinality", "undeclared")
    if not isinstance(polarity, str) or not isinstance(cardinality, str) or polarity not in {"affirmed", "denied"} or cardinality not in {"one", "many", "undeclared"}:
        raise ValueError("Claim polarity/cardinality is unsupported")
    measurement = canonical_measurement(data) if "unit" in data else None
    return {"subject": data["subject"].strip(), "predicate": data["predicate"].strip(),
            "value": data["value"], "value_key": _value_key(data["value"]), "polarity": polarity,
            "cardinality": cardinality, "measurement": measurement}


def _equal_value(a, b):
    if a["measurement"] is not None or b["measurement"] is not None:
        if a["measurement"] is None or b["measurement"] is None:
            return False
        return a["measurement"]["dimension"] == b["measurement"]["dimension"] and math.isclose(
            a["measurement"]["value"], b["measurement"]["value"], rel_tol=1e-12, abs_tol=1e-12)
    return a["value_key"] == b["value_key"]


def _opposition(a, b):
    if a["subject"] != b["subject"] or a["predicate"] != b["predicate"]:
        return None
    if _equal_value(a, b):
        return a["polarity"] != b["polarity"]
    if a["polarity"] == b["polarity"] == "affirmed" and a["cardinality"] == b["cardinality"] == "one":
        if a["measurement"] is not None or b["measurement"] is not None:
            if a["measurement"] is None or b["measurement"] is None or (
                a["measurement"]["dimension"] != b["measurement"]["dimension"]
            ):
                return None
            ar, br = a["measurement"]["uncertainty_interval"], b["measurement"]["uncertainty_interval"]
            if ar is None or br is None:
                return None
            return max(ar[0], br[0]) > min(ar[1], br[1])
        return True
    return None


def _overlap(a, b):
    left = _interval(a["valid_from"])[0] if a.get("valid_from") else None
    right = _interval(b["valid_from"])[0] if b.get("valid_from") else None
    left_end = _interval(a["valid_to"])[1] if a.get("valid_to") else None
    right_end = _interval(b["valid_to"])[1] if b.get("valid_to") else None
    return not ((left_end is not None and right is not None and left_end <= right) or
                (right_end is not None and left is not None and right_end <= left))


def contradictionint(ctx: AnalysisContext):
    claims = []
    for record in ctx.records:
        try:
            claim = _claim(record.data)
            _in_scope(record.data, ctx.as_of)  # Validate interval even when historical.
            claims.append((record, claim))
        except (ValueError, TypeError, OverflowError) as exc:
            ctx.issue(record.record_id, "invalid_contradiction_claim", str(exc))
    conflicts, unresolved, compatible = [], [], 0
    for index, (ar, a) in enumerate(claims):
        for br, b in claims[index + 1:]:
            if a["subject"] != b["subject"] or a["predicate"] != b["predicate"]:
                continue
            if not _overlap(ar.data, br.data):
                continue
            opposed = _opposition(a, b)
            pair = {"left_record_id": ar.record_id, "right_record_id": br.record_id,
                    "subject": a["subject"], "predicate": a["predicate"]}
            if opposed is True:
                conflicts.append(pair)
            elif opposed is None:
                unresolved.append(pair)
            else:
                compatible += 1
    if conflicts:
        ctx.finding("typed_assertion_conflicts", "Found overlapping, logically incompatible supplied assertions.",
                    sorted({row[key] for row in conflicts for key in ("left_record_id", "right_record_id")}),
                    data={"conflicts": conflicts[:200], "conflict_count": len(conflicts),
                          "truncated": len(conflicts) > 200})
    return ctx.output(
        metrics={"valid_claims": len(claims), "conflicting_pairs": len(conflicts),
                 "unassessed_pairs": len(unresolved), "compatible_pairs": compatible},
        artifacts={"conflicts": conflicts[:200], "unassessed_pairs": unresolved[:200],
                   "pair_artifacts_truncated": len(conflicts) > 200 or len(unresolved) > 200},
        limitations=("Multiple values are not contradictions without exclusivity/polarity semantics and overlapping validity.",),
    )


def verificationint(ctx: AnalysisContext):
    known, results = _known(ctx), []
    for record in ctx.records:
        if "claim" not in record.data:
            if not isinstance(record.data.get("claims"), list):
                ctx.issue(record.record_id, "invalid_verification_record", "Record requires claim or evidence claims.")
            continue
        try:
            target = _claim(record.data["claim"])
            if not _in_scope(record.data["claim"], ctx.as_of):
                ctx.issue(record.record_id, "verification_target_outside_as_of", "Target claim is outside the requested temporal snapshot.")
                continue
        except (ValueError, TypeError, OverflowError) as exc:
            ctx.issue(record.record_id, "invalid_verification_claim", str(exc))
            continue
        supports, refutes, cited, invalid = [], [], [], []
        for field, destination in (("support_record_ids", supports), ("refute_record_ids", refutes)):
            refs = record.data.get(field, [])
            if not isinstance(refs, list) or any(not isinstance(ref, str) for ref in refs):
                ctx.issue(record.record_id, "invalid_verification_citations", "Citations require record-ID arrays.")
                continue
            for ref in sorted(set(refs)):
                evidence = known.get(ref)
                if evidence is None or ref == record.record_id:
                    invalid.append(ref)
                    ctx.issue(record.record_id, "unknown_verification_citation", "Citation is missing or self-referential.")
                    continue
                cited.append(ref)
                if isinstance(evidence.data.get("content_text"), str) and evidence.data.get("sha256") is not None:
                    digest = evidence.data["sha256"]
                    if not isinstance(digest, str) or _hash(evidence.data["content_text"]) != digest.lower():
                        invalid.append(ref)
                        ctx.issue(record.record_id, "cited_content_hash_mismatch", "Cited content does not match its supplied hash.")
                        continue
                assertions = evidence.data.get("claims", [])
                matched = False
                if isinstance(assertions, list):
                    for assertion in assertions:
                        if not isinstance(assertion, dict):
                            ctx.issue(record.record_id, "malformed_cited_assertion", "Cited claim must be an object.")
                            continue
                        try:
                            if not _in_scope(assertion, ctx.as_of):
                                continue
                            candidate = _claim(assertion)
                            if field == "support_record_ids":
                                matched |= (candidate["subject"] == target["subject"] and
                                            candidate["predicate"] == target["predicate"] and
                                            candidate["polarity"] == target["polarity"] and _equal_value(candidate, target))
                            else:
                                matched |= _opposition(candidate, target) is True
                        except (ValueError, TypeError, OverflowError):
                            continue
                if matched:
                    destination.append(ref)
                else:
                    invalid.append(ref)
                    ctx.issue(record.record_id, "citation_does_not_entail_claim",
                              "Cited record does not contain the required in-scope typed assertion.")
        groups = sorted({group for ref in supports for group in [_origin(ctx, known[ref].source_id)[0]] if group})
        assessment = "CONTESTED_SUPPLIED_ASSERTIONS" if supports and refutes else (
            "SUPPORTED_BY_SUPPLIED_ASSERTIONS" if supports else
            "REFUTED_BY_SUPPLIED_ASSERTIONS" if refutes else "INSUFFICIENT_CITED_ASSERTIONS")
        item = {"record_id": record.record_id, "assessment": assessment,
                "support_record_ids": supports, "refute_record_ids": refutes,
                "invalid_or_nonentailing_citations": sorted(set(invalid)),
                "declared_support_origin_groups": groups, "factual_truth_verified": False,
                "source_authenticity_verified": False, "independence_verified": False}
        results.append(item)
        ctx.finding("citation_entailment_assessment", "Checked typed claim correspondence against cited supplied evidence.",
                    sorted(set([record.record_id] + cited)), data=item)
    return ctx.output(
        metrics={"claim_assessments": len(results)}, artifacts={"verification": results},
        limitations=("Typed assertion correspondence and local hash checks do not independently establish factual truth.",),
    )


def hypothesisint(ctx: AnalysisContext):
    known, matrices = _known(ctx), []
    for record in ctx.records:
        if "hypotheses" not in record.data and "evidence" not in record.data:
            continue
        hypotheses, evidence = record.data.get("hypotheses"), record.data.get("evidence")
        if not isinstance(hypotheses, list) or not isinstance(evidence, list):
            ctx.issue(record.record_id, "invalid_hypothesis_matrix", "Hypotheses and evidence require arrays.")
            continue
        ids = []
        for hypothesis in hypotheses:
            if isinstance(hypothesis, dict) and _text(hypothesis.get("id")) and _text(hypothesis.get("statement")):
                ids.append(hypothesis["id"].strip())
            else:
                ctx.issue(record.record_id, "invalid_hypothesis", "Hypothesis requires id and statement.")
        if len(ids) != len(set(ids)) or not ids:
            ctx.issue(record.record_id, "ambiguous_hypothesis_ids", "Hypothesis IDs must be nonempty and unique.")
            continue
        try:
            perturbation = number(record.data.get("sensitivity_delta", 0.1), "sensitivity_delta", 0, 1)
        except ValueError as exc:
            ctx.issue(record.record_id, "invalid_hypothesis_sensitivity", str(exc))
            continue
        scores = {key: {"support": {}, "refute": {}, "unknown": 0} for key in ids}
        citations, seen = [], set()
        for assessment in evidence:
            if not isinstance(assessment, dict) or not isinstance(assessment.get("record_id"), str) or assessment["record_id"] not in known:
                ctx.issue(record.record_id, "unknown_hypothesis_evidence", "Assessment cites an unknown evidence record.")
                continue
            ref = assessment["record_id"]
            if ref in seen:
                ctx.issue(record.record_id, "duplicate_hypothesis_evidence", "Repeated evidence rows cannot multiply weight.")
                continue
            seen.add(ref)
            try:
                weight = number(assessment.get("weight", 1), "evidence weight", 0, 1)
            except ValueError as exc:
                ctx.issue(record.record_id, "invalid_hypothesis_weight", str(exc))
                continue
            labels = assessment.get("assessments", {})
            if not isinstance(labels, dict):
                ctx.issue(record.record_id, "invalid_hypothesis_assessment", "assessments requires an object.")
                continue
            citations.append(ref)
            group = _origin(ctx, known[ref].source_id)[0] or "unresolved-origin"
            for key in ids:
                stance = labels.get(key, "unknown")
                if not isinstance(stance, str) or stance not in {"supports", "refutes", "neutral", "unknown"}:
                    ctx.issue(record.record_id, "invalid_hypothesis_stance", "Unsupported hypothesis stance.")
                    stance = "unknown"
                if stance in {"supports", "refutes"}:
                    bucket = scores[key]["support" if stance == "supports" else "refute"]
                    bucket[group] = max(bucket.get(group, 0), weight)
                elif stance == "unknown":
                    scores[key]["unknown"] += 1
        ranking = []
        for key in ids:
            score = scores[key]
            support, refute = math.fsum(score["support"].values()), math.fsum(score["refute"].values())
            lower = math.fsum(max(0, value - perturbation) for value in score["support"].values()) - math.fsum(min(1, value + perturbation) for value in score["refute"].values())
            upper = math.fsum(min(1, value + perturbation) for value in score["support"].values()) - math.fsum(max(0, value - perturbation) for value in score["refute"].values())
            ranking.append({"hypothesis_id": key, "support_weight": support, "refute_weight": refute,
                            "net_assessed_support": support - refute,
                            "sensitivity_interval": [lower, upper],
                            "unknown_assessments": score["unknown"]})
        ranking.sort(key=lambda row: (-row["net_assessed_support"], row["hypothesis_id"]))
        unstable = bool(len(ranking) > 1 and ranking[0]["sensitivity_interval"][0] <=
                        max(row["sensitivity_interval"][1] for row in ranking[1:]))
        item = {"record_id": record.record_id, "ranking": ranking, "ranking_sensitive": unstable,
                "weights_are_analyst_assessments": True, "probabilities_calibrated": False,
                "origin_group_independence_verified": False}
        matrices.append(item)
        ctx.finding("competing_hypotheses_matrix", "Computed source-group-aware support/refutation and sensitivity.",
                    sorted(set([record.record_id] + citations)), data=item)
    if not matrices:
        ctx.issue(None, "no_hypothesis_matrix", "No valid competing-hypotheses matrix was supplied.")
    return ctx.output(
        metrics={"hypothesis_matrices": len(matrices)}, artifacts={"hypotheses": matrices},
        limitations=("ACH scores are explainable supplied assessments, not posterior probabilities or verified conclusions.",),
    )


_MISSING = object()


def _lookup(data, path):
    if not isinstance(path, str) or not path or len(path.split(".")) > 10:
        return _MISSING
    for key in path.split("."):
        if not isinstance(data, dict) or key not in data:
            return _MISSING
        data = data[key]
    return data


def _test(value, operator, expected):
    if value is _MISSING:
        return None
    if operator == "eq":
        return _value_key(value) == _value_key(expected)
    if operator == "ne":
        return _value_key(value) != _value_key(expected)
    if operator in {"lt", "lte", "gt", "gte"}:
        if any(isinstance(item, bool) or not isinstance(item, (int, float)) for item in (value, expected)):
            return None
        return {"lt": value < expected, "lte": value <= expected,
                "gt": value > expected, "gte": value >= expected}[operator]
    if operator == "contains":
        if isinstance(value, str) and isinstance(expected, str):
            return expected in value
        if isinstance(value, list):
            return any(_value_key(item) == _value_key(expected) for item in value)
        return None
    return None


def falsificationint(ctx: AnalysisContext):
    known, results = _known(ctx), []
    for record in ctx.records:
        if "hypothesis_id" not in record.data and "tests" not in record.data:
            continue
        hypothesis = _text(record.data.get("hypothesis_id"))
        tests = record.data.get("tests")
        if not hypothesis or not isinstance(tests, list):
            ctx.issue(record.record_id, "invalid_falsification_protocol", "Protocol requires hypothesis_id and tests.")
            continue
        outcomes, citations, seen = [], [], set()
        for test in tests:
            if not isinstance(test, dict) or not _text(test.get("test_id")):
                ctx.issue(record.record_id, "invalid_falsification_test", "Test requires an identifier.")
                continue
            test_id = test["test_id"]
            if test_id in seen:
                ctx.issue(record.record_id, "duplicate_falsification_test", "Duplicate test IDs are not overwritten.")
                continue
            seen.add(test_id)
            refs, operator, claim_kind = test.get("record_ids"), test.get("operator"), test.get("claim_kind", "universal")
            if not isinstance(refs, list) or any(not isinstance(ref, str) for ref in refs) or (
                not isinstance(operator, str) or not isinstance(claim_kind, str) or
                operator not in {"eq", "ne", "lt", "lte", "gt", "gte", "contains"} or
                claim_kind not in {"universal", "existential"} or "expected_value" not in test
            ):
                ctx.issue(record.record_id, "unsupported_falsification_test", "Test comparison or scope is unsupported.")
                continue
            passed, failed, unknown = [], [], []
            for ref in sorted(set(refs)):
                target = known.get(ref)
                if target is None:
                    unknown.append(ref)
                    ctx.issue(record.record_id, "unknown_falsification_evidence", "Test refers to an unknown record.")
                    continue
                citations.append(ref)
                outcome = _test(_lookup(target.data, test.get("field")), operator, test["expected_value"])
                (unknown if outcome is None else passed if outcome else failed).append(ref)
            if claim_kind == "universal":
                state = "COUNTEREXAMPLE_IN_SUPPLIED_RECORDS" if failed else (
                    "INCONCLUSIVE" if unknown or not passed else "NOT_REFUTED_BY_SUPPLIED_RECORDS")
            else:
                state = "WITNESS_IN_SUPPLIED_RECORDS" if passed else (
                    "NO_WITNESS_IN_DECLARED_COMPLETE_SCOPE" if refs and not unknown and
                    test.get("coverage_complete") is True else "INCONCLUSIVE")
            outcomes.append({"test_id": test_id, "claim_kind": claim_kind, "state": state,
                             "passing_record_ids": passed, "counterexample_record_ids": failed,
                             "unknown_record_ids": unknown})
        item = {"record_id": record.record_id, "hypothesis_id": hypothesis, "tests": outcomes,
                "hypothesis_proven_true": False}
        results.append(item)
        ctx.finding("falsification_protocol_results", "Applied declared test predicates to cited supplied observations.",
                    sorted(set([record.record_id] + citations)), data=item)
    if not results:
        ctx.issue(None, "no_falsification_protocol", "No valid falsification protocol was supplied.")
    return ctx.output(
        metrics={"protocols": len(results), "counterexample_tests": sum(
            test["state"] == "COUNTEREXAMPLE_IN_SUPPLIED_RECORDS"
            for row in results for test in row["tests"])},
        artifacts={"falsification": results},
        limitations=("A supplied counterexample is scope-bound; failure to refute is not proof of truth or exhaustive coverage.",),
    )


def trustint(ctx: AnalysisContext):
    candidates, groups = defaultdict(list), defaultdict(list)
    unresolved, ambiguous = 0, 0
    for record in ctx.records:
        context = _text(record.data.get("context"))
        assessments = record.data.get("assessments")
        if not context or not isinstance(assessments, list):
            ctx.issue(record.record_id, "invalid_trust_assessments", "Record requires context and assessments.")
            continue
        for index, assessment in enumerate(assessments):
            if not isinstance(assessment, dict):
                ctx.issue(record.record_id, "invalid_trust_assessment", "Assessment requires an object.")
                continue
            prediction_id = _text(assessment.get("prediction_id")) or record.record_id + ":" + str(index)
            candidates[(record.source_id, context, prediction_id)].append((record, assessment))
    for (source_id, context, _), assessments in sorted(candidates.items()):
        if len(assessments) != 1:
            ambiguous += 1
            for record, _assessment in assessments:
                ctx.issue(record.record_id, "duplicate_trust_prediction",
                          "Repeated prediction IDs are excluded until their revision/outcome ambiguity is resolved.")
            continue
        record, assessment = assessments[0]
        if assessment.get("outcome") is None:
            unresolved += 1
            continue
        try:
            if type(assessment["outcome"]) is not bool:
                raise ValueError("Outcome requires a literal boolean")
            probability = number(assessment.get("prediction"), "prediction", 0, 1)
            if assessment.get("resolved_at") is not None:
                stamp, _, _ = _interval(assessment["resolved_at"])
                if stamp > ctx.as_of:
                    unresolved += 1
                    continue
            groups[(source_id, context)].append((record, probability, int(assessment["outcome"])))
        except (ValueError, OverflowError) as exc:
            ctx.issue(record.record_id, "invalid_trust_outcome", str(exc))
    results = []
    for (source_id, context), rows in sorted(groups.items()):
        n = len(rows)
        correct = sum((probability >= 0.5) == bool(outcome) for _, probability, outcome in rows)
        proportion, z = correct / n, 1.96
        denominator = 1 + z * z / n
        center = (proportion + z * z / (2 * n)) / denominator
        half = z * math.sqrt(proportion * (1 - proportion) / n + z * z / (4 * n * n)) / denominator
        bins = defaultdict(list)
        for _, probability, outcome in rows:
            bins[min(9, int(probability * 10))].append((probability, outcome))
        item = {"source_id": source_id, "context": context, "resolved_samples": n,
                "brier_score": math.fsum((probability - outcome) ** 2 / n for _, probability, outcome in rows),
                "threshold_accuracy": proportion, "accuracy_wilson_95": [max(0, center - half), min(1, center + half)],
                "calibration_bins": [{"bin": key, "samples": len(values),
                    "mean_prediction": math.fsum(p / len(values) for p, _ in values),
                    "observed_frequency": sum(y for _, y in values) / len(values)}
                    for key, values in sorted(bins.items())],
                "global_source_trust_verified": False}
        results.append(item)
        ctx.finding("context_specific_calibration", "Calculated supplied forecast calibration with sample uncertainty.",
                    sorted({record.record_id for record, _, _ in rows}), data=item)
    return ctx.output(
        metrics={"calibration_contexts": len(results), "unresolved_outcomes": unresolved,
                 "ambiguous_prediction_groups": ambiguous},
        artifacts={"calibration": results},
        limitations=("Outcomes are supplied labels; calibration is context/sample-specific and does not establish global source reliability.",),
    )


HANDLERS = {"SOURCEINT": sourceint, "PROVENANCEINT": provenanceint,
            "CORROBORATIONINT": corroborationint, "CONTRADICTIONINT": contradictionint,
            "VERIFICATIONINT": verificationint, "HYPOTHESISINT": hypothesisint,
            "FALSIFICATIONINT": falsificationint, "TRUSTINT": trustint}
