#!/usr/bin/env python3
"""
RISKINT mini-engine: compact Python skeleton for lawful enterprise-risk intelligence.

Boundaries:
- Evidence-first, explainable, temporal, human-governed.
- Not an autonomous enforcement, legal, financial, employment, credit, insurance,
  targeting, offensive-cyber, sabotage, or account/action automation system.
- Risk is not threat, vulnerability, exposure, incident, alert, finding, or issue.
- No fabricated probabilities, losses, controls, dependencies, or zero-risk claims.
"""

from __future__ import annotations

import json
import re
import hashlib
from datetime import datetime, timezone

VERSION = "0.1.0"
MODES = {"LOCAL_ONLY", "HYBRID", "CLOUD"}

TAXONOMY = {
    "CYBER",
    "OPERATIONAL",
    "FINANCIAL",
    "FRAUD",
    "SUPPLY_CHAIN",
    "THIRD_PARTY",
    "TECHNOLOGY",
    "SOFTWARE_SUPPLY_CHAIN",
    "IDENTITY",
    "DATA",
    "PRIVACY",
    "REGULATORY",
    "LEGAL",
    "REPUTATIONAL",
    "BUSINESS_CONTINUITY",
    "PHYSICAL",
    "GEOPOLITICAL",
    "STRATEGIC",
    "PROJECT",
    "PEOPLE",
    "CONCENTRATION",
    "SYSTEMIC",
    "OTHER",
    "UNKNOWN",
}

LIKELIHOOD_STATES = {
    "RARE",
    "UNLIKELY",
    "POSSIBLE",
    "LIKELY",
    "VERY_LIKELY",
    "UNKNOWN",
}

PLAUSIBILITY_STATES = {
    "NOT_SUPPORTED",
    "LOW_PLAUSIBILITY",
    "PLAUSIBLE",
    "HIGHLY_PLAUSIBLE",
    "UNKNOWN",
}

IMPACT_STATES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "SEVERE",
    "CRITICAL",
    "UNKNOWN",
}

CRITICALITY_STATES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "MISSION_CRITICAL",
    "UNKNOWN",
}

CONTROL_STATES = {
    "DESIGNED",
    "IMPLEMENTED_REPORTED",
    "IMPLEMENTED_VERIFIED",
    "TESTED",
    "PARTIALLY_EFFECTIVE",
    "EFFECTIVE",
    "INEFFECTIVE",
    "NOT_APPLICABLE",
    "UNKNOWN",
}

RISK_STATUSES = {
    "IDENTIFIED",
    "UNDER_ASSESSMENT",
    "OPEN",
    "TREATMENT_PLANNED",
    "TREATMENT_IN_PROGRESS",
    "MONITORING",
    "ACCEPTED_BY_AUTHORIZED_OWNER",
    "MITIGATED",
    "CLOSED",
    "REOPENED",
    "INCONCLUSIVE",
}

POLICY_BLOCK_KEYWORDS = {
    "attack",
    "exploit",
    "sabotage",
    "disable system",
    "disconnect supplier",
    "cause outage",
    "probe unauthorized",
    "block customer",
    "freeze account",
    "fire employee",
    "deny credit",
    "deny insurance",
    "autonomously notify regulator",
    "autonomously contact law enforcement",
    "offensive cyber",
    "targeting guidance",
}

PROTECTED_TRAIT_KEYWORDS = {
    "race",
    "religion",
    "ethnicity",
    "sex",
    "gender",
    "sexual orientation",
    "health",
    "disability",
    "political affiliation",
    "political belief",
    "nationality",
}

LIMITATIONS = [
    "Skeleton engine: no live enterprise telemetry, CMDB, GRC, scanner, or incident system is connected.",
    "Risk assessment is decision support only; consequential actions require authorized human governance.",
    "Threat, vulnerability, exposure, incident, alert, finding, and issue are not automatically risk.",
    "Unknown evidence is not zero risk and not automatically critical risk.",
    "No autonomous acceptance, firing, credit denial, insurance denial, account freezing, regulator notification, or enforcement action.",
    "No offensive cyber, sabotage, targeting, suppression, or system-disruption guidance.",
]

LIKELIHOOD_SCORE = {
    "RARE": 1,
    "UNLIKELY": 2,
    "POSSIBLE": 3,
    "LIKELY": 4,
    "VERY_LIKELY": 5,
    "UNKNOWN": 3,
}

PLAUSIBILITY_TO_LIKELIHOOD = {
    "NOT_SUPPORTED": "RARE",
    "LOW_PLAUSIBILITY": "UNLIKELY",
    "PLAUSIBLE": "POSSIBLE",
    "HIGHLY_PLAUSIBLE": "LIKELY",
    "UNKNOWN": "UNKNOWN",
}

IMPACT_SCORE = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "SEVERE": 4,
    "CRITICAL": 5,
    "UNKNOWN": 3,
}

CRITICALITY_SCORE = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "MISSION_CRITICAL": 4,
    "UNKNOWN": 3,
}

VELOCITY_SCORE = {
    "SLOW": 1,
    "MEDIUM": 2,
    "FAST": 3,
    "IMMEDIATE": 4,
    "UNKNOWN": 2,
}

PERSISTENCE_SCORE = {
    "BRIEF": 1,
    "MEDIUM": 2,
    "LONG": 3,
    "STRUCTURAL": 4,
    "UNKNOWN": 2,
}

CONFIDENCE_SCORE = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "UNKNOWN": 1,
}

CONTROL_CREDIT = {
    "INEFFECTIVE": 0.0,
    "NOT_APPLICABLE": 0.0,
    "UNKNOWN": 0.10,
    "DESIGNED": 0.20,
    "IMPLEMENTED_REPORTED": 0.40,
    "IMPLEMENTED_VERIFIED": 0.65,
    "TESTED": 0.80,
    "PARTIALLY_EFFECTIVE": 0.50,
    "EFFECTIVE": 0.85,
}

VELOCITY_MULT = {
    "SLOW": 0.90,
    "MEDIUM": 1.00,
    "FAST": 1.20,
    "IMMEDIATE": 1.50,
    "UNKNOWN": 1.00,
}

CRITICALITY_MULT = {
    "LOW": 0.85,
    "MEDIUM": 1.00,
    "HIGH": 1.20,
    "MISSION_CRITICAL": 1.50,
    "UNKNOWN": 1.00,
}

CONFIDENCE_MULT = {
    "LOW": 1.20,
    "MEDIUM": 1.00,
    "HIGH": 0.90,
    "UNKNOWN": 1.10,
}

LIKELIHOOD_ORDER = ["RARE", "UNLIKELY", "POSSIBLE", "LIKELY", "VERY_LIKELY"]
IMPACT_ORDER = ["LOW", "MEDIUM", "HIGH", "SEVERE", "CRITICAL"]
PRIORITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
BAND_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"]


# ----------------------------------------------------------------------
# Basic helpers
# ----------------------------------------------------------------------

def sha(value) -> str:
    if isinstance(value, (dict, list, tuple, set)):
        payload = json.dumps(value, sort_keys=True, default=str)
    else:
        payload = str(value)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def norm_text(value) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().lower())


def contains_any(text, keywords) -> bool:
    t = norm_text(text)
    return any(norm_text(k) in t for k in keywords)


def clean_number(value):
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)

    s = str(value).strip().replace(",", "").replace("%", "")
    s = s.replace("−", "-").replace("–", "-")

    negative_paren = s.startswith("(") and s.endswith(")")
    if negative_paren:
        s = s[1:-1]

    m = re.search(r"-?\d+(?:\.\d+)?", s)
    if not m:
        return None

    x = float(m.group())
    return -x if negative_paren else x


def parse_datetime(value):
    if not value:
        return None
    s = str(value).strip()
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        pass
    try:
        return datetime.strptime(s[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except Exception:
        return None


def unique(seq):
    return list(dict.fromkeys(seq))


def clamp(x, lo, hi):
    return max(lo, min(hi, x))


def band_index(band, order):
    try:
        return order.index(band)
    except Exception:
        return None


def shift_state(state, order, delta):
    idx = band_index(state, order)
    if idx is None:
        return state
    return order[clamp(idx + delta, 0, len(order) - 1)]


def score_to_risk_band(score):
    if score is None:
        return "UNKNOWN"
    if score <= 4:
        return "LOW"
    if score <= 9:
        return "MEDIUM"
    if score <= 16:
        return "HIGH"
    return "CRITICAL"


def priority_score_to_band(score):
    if score is None:
        return "UNKNOWN"
    if score <= 12:
        return "LOW"
    if score <= 25:
        return "MEDIUM"
    if score <= 45:
        return "HIGH"
    return "CRITICAL"


# ----------------------------------------------------------------------
# Source reliability / evidence
# ----------------------------------------------------------------------

def source_reliability(evidence):
    st = norm_text(evidence.get("source_type"))

    high_terms = [
        "official",
        "internal_verified_inventory",
        "cmdb",
        "asset_inventory",
        "incident_record",
        "audit_report",
        "control_assessment",
        "penetration_test_summary",
        "authorized_scanner",
        "business_impact_analysis",
        "bcp_dr_record",
        "recovery_exercise",
        "legal_register",
        "regulatory_register",
        "court",
        "central_bank",
        "ministry",
        "treasury",
        "customs",
        "multilateral",
    ]

    medium_terms = [
        "vendor",
        "policy_document",
        "commercial",
        "platform",
        "dataset",
        "survey",
        "academic",
        "industry_association",
        "company_filing",
        "public_advisory",
    ]

    low_terms = ["media", "anonymous", "unverified", "unknown", "blog"]

    if any(t in st for t in high_terms):
        return "HIGH"
    if any(t in st for t in medium_terms):
        return "MEDIUM"
    if any(t in st for t in low_terms):
        return "LOW"
    return "MEDIUM_LOW"


def make_evidence(source_id, source_type, content, **kwargs):
    ev = {
        "source_id": source_id,
        "source_type": source_type,
        "content": content,
    }
    ev.update(kwargs)
    ev["evidence_id"] = "EV-" + sha([source_id, kwargs.get("observed_at"), content])
    return ev


def normalize_evidence(evidence, authorized_source_types=None):
    ev = dict(evidence or {})
    ev.setdefault("evidence_id", "EV-" + sha([ev.get("source_id"), ev.get("observed_at"), ev.get("content")]))
    ev.setdefault("retrieved_at", now())
    ev.setdefault("content_hash", sha(ev.get("content", "")))
    ev.setdefault("pedigree", [ev.get("source_type", "unknown")])
    ev.setdefault("observed_at", None)
    ev.setdefault("valid_from", ev.get("observed_at"))
    ev.setdefault("valid_to", None)
    ev["reliability"] = source_reliability(ev)

    if authorized_source_types and ev.get("source_type") not in authorized_source_types:
        ev["authorization_warning"] = "SOURCE_NOT_AUTHORIZED_OR_UNCONFIGURED"

    return ev


def source_independence(evidences):
    roots = {}
    root_by_id = {}

    for e in evidences:
        root = (e.get("pedigree") or [e.get("source_type", "unknown")])[0]
        root_by_id[e["evidence_id"]] = root
        roots.setdefault(root, []).append(e["evidence_id"])

    pairs = []
    ids = list(root_by_id.keys())

    for i, a in enumerate(ids):
        for b in ids[i + 1:]:
            pairs.append({
                "evidence_a": a,
                "evidence_b": b,
                "state": "INDEPENDENT" if root_by_id[a] != root_by_id[b] else "DEPENDENT",
                "root_a": root_by_id[a],
                "root_b": root_by_id[b],
            })

    return {
        "by_root": roots,
        "pairs": pairs,
        "note": "Multiple copied alerts or vendor reports from the same upstream source are not independent confirmations.",
    }


def compute_evidence_confidence(evidence_ids, evidences_by_id):
    ids = [x for x in unique(evidence_ids) if x in evidences_by_id]
    if not ids:
        return "LOW", []

    rels = [evidences_by_id[i].get("reliability", "LOW") for i in ids]
    roots = []
    for i in ids:
        pedigree = evidences_by_id[i].get("pedigree") or [evidences_by_id[i].get("source_type", "unknown")]
        roots.append(pedigree[0])

    independent_roots = unique(roots)
    high = sum(1 for r in rels if r == "HIGH")
    medium = sum(1 for r in rels if r == "MEDIUM")

    if len(independent_roots) >= 2 and high >= 1:
        conf = "HIGH"
    elif high >= 1 or (len(independent_roots) >= 2 and medium >= 1):
        conf = "MEDIUM"
    else:
        conf = "LOW"

    return conf, independent_roots


# ----------------------------------------------------------------------
# Entity normalizers
# ----------------------------------------------------------------------

def normalize_asset(asset):
    a = dict(asset or {})
    a.setdefault("asset_id", "ASSET-" + sha(a.get("name") or a.get("type")))
    a.setdefault("name", a["asset_id"])
    a.setdefault("type", "UNKNOWN")
    a.setdefault("criticality", "UNKNOWN")
    a.setdefault("business_function_ids", [])
    a.setdefault("provider", None)
    a.setdefault("region", None)
    a.setdefault("data_sensitivity", "UNKNOWN")
    a.setdefault("tags", [])
    a.setdefault("evidence_ids", [])
    a["criticality"] = str(a.get("criticality", "UNKNOWN")).upper()
    return a


def normalize_business_function(function):
    f = dict(function or {})
    f.setdefault("function_id", "FUNC-" + sha(f.get("name")))
    f.setdefault("name", f["function_id"])
    f.setdefault("criticality", "UNKNOWN")
    f.setdefault("owner_candidate", None)
    f.setdefault("asset_ids", [])
    f.setdefault("evidence_ids", [])
    f["criticality"] = str(f.get("criticality", "UNKNOWN")).upper()
    return f


def normalize_threat(threat):
    t = dict(threat or {})
    t.setdefault("threat_id", "THREAT-" + sha(t.get("name") or t.get("type")))
    t.setdefault("name", t["threat_id"])
    t.setdefault("type", "UNKNOWN")
    t.setdefault("source", None)
    t.setdefault("capability", "UNKNOWN")
    t.setdefault("intent_if_supported", "UNKNOWN")
    t.setdefault("activity_level", "UNKNOWN")
    t.setdefault("targeting_relevance", "UNKNOWN")
    t.setdefault("time", None)
    t.setdefault("confidence", "UNKNOWN")
    t.setdefault("evidence_ids", [])
    return t


def normalize_hazard(hazard):
    h = dict(hazard or {})
    h.setdefault("hazard_id", "HAZ-" + sha(h.get("name") or h.get("type")))
    h.setdefault("name", h["hazard_id"])
    h.setdefault("type", "UNKNOWN")
    h.setdefault("source", None)
    h.setdefault("severity", "UNKNOWN")
    h.setdefault("time", None)
    h.setdefault("evidence_ids", [])
    return h


def normalize_vulnerability(vuln):
    v = dict(vuln or {})
    v.setdefault("vulnerability_id", "VULN-" + sha(v.get("name") or v.get("cve") or v.get("kind")))
    v.setdefault("name", v["vulnerability_id"])
    v.setdefault("kind", "UNKNOWN")
    v.setdefault("applicability_state", "UNKNOWN")
    v.setdefault("exploitability", "UNKNOWN")
    v.setdefault("cvss", None)
    v.setdefault("epss", None)
    v.setdefault("kev", None)
    v.setdefault("exposure_ids", [])
    v.setdefault("evidence_ids", [])
    return v


def normalize_exposure(exposure):
    e = dict(exposure or {})
    e.setdefault("exposure_id", "EXP-" + sha(e.get("name") or e.get("type")))
    e.setdefault("name", e["exposure_id"])
    e.setdefault("type", "UNKNOWN")
    e.setdefault("description", e.get("name"))
    e.setdefault("asset_ids", [])
    e.setdefault("evidence_ids", [])
    return e


def normalize_control(control):
    c = dict(control or {})
    c.setdefault("control_id", "CTRL-" + sha(c.get("name") or c.get("type")))
    c.setdefault("name", c["control_id"])
    c.setdefault("type", "UNKNOWN")
    c.setdefault("owner", None)
    c.setdefault("scope", {})
    c.setdefault("design_state", "UNKNOWN")
    c.setdefault("implementation_state", "UNKNOWN")
    c.setdefault("effectiveness_state", "UNKNOWN")
    c.setdefault("last_tested", None)
    c.setdefault("evidence_ids", [])

    scope = dict(c.get("scope") or {})
    scope.setdefault("asset_ids", [])
    scope.setdefault("function_ids", [])
    scope.setdefault("environments", [])
    c["scope"] = scope

    state = (
        c.get("effectiveness_state")
        or c.get("implementation_state")
        or c.get("design_state")
        or "UNKNOWN"
    )
    state = str(state).upper()
    if state not in CONTROL_STATES:
        state = "UNKNOWN"

    c["state"] = state
    base_credit = CONTROL_CREDIT.get(state, 0.10)

    if not c.get("evidence_ids"):
        base_credit = min(base_credit, 0.30)

    c["credit"] = round(base_credit, 3)
    c["verified"] = bool(
        c.get("evidence_ids")
        and state in {"IMPLEMENTED_VERIFIED", "TESTED", "EFFECTIVE", "PARTIALLY_EFFECTIVE"}
    )
    return c


def normalize_dependency(dependency):
    d = dict(dependency or {})
    d.setdefault("dependency_id", "DEP-" + sha([d.get("from_asset_id"), d.get("to_asset_id"), d.get("to_provider")]))
    d.setdefault("from_asset_id", None)
    d.setdefault("to_asset_id", None)
    d.setdefault("to_provider", None)
    d.setdefault("type", "UNKNOWN")
    d.setdefault("critical", False)
    d.setdefault("no_alternative", False)
    d.setdefault("failover_verified", False)
    d.setdefault("evidence_ids", [])
    return d


def normalize_scenario(scenario):
    s = dict(scenario or {})
    s.setdefault("scenario_id", "SC-" + sha(s.get("title") or s.get("event")))
    s.setdefault("title", s.get("event") or s["scenario_id"])
    s.setdefault("event", s.get("title"))
    s.setdefault("trigger", None)
    s.setdefault("preconditions", [])

    s["affected_asset_ids"] = unique(s.get("affected_asset_ids", []))
    s["affected_function_ids"] = unique(s.get("affected_function_ids", []))

    drivers = dict(s.get("driver_ids") or {})
    for key in ["threat_ids", "hazard_ids", "vulnerability_ids", "exposure_ids"]:
        s[key] = unique(list(drivers.get(key, [])) + list(s.get(key, [])))

    s["control_ids"] = unique(s.get("control_ids", []))
    s["dependency_ids"] = unique(s.get("dependency_ids", []))

    cat = s.get("category", [])
    if isinstance(cat, str):
        cat = [cat]
    s["category"] = unique([str(x).upper() for x in cat if x]) or ["UNKNOWN"]

    s.setdefault("likelihood", None)
    s.setdefault("plausibility", None)
    s.setdefault("likelihood_probability", None)
    s.setdefault("impact_level", None)
    s.setdefault("impact_dimensions", [])
    s.setdefault("financial_impact", None)
    s.setdefault("velocity", "UNKNOWN")
    s.setdefault("persistence", "UNKNOWN")
    s.setdefault("horizon", "UNKNOWN")
    s.setdefault("assumptions", [])
    s.setdefault("evidence_ids", [])
    s.setdefault("owner_candidate", None)
    s.setdefault("status", "IDENTIFIED")

    if s.get("likelihood"):
        s["likelihood"] = str(s["likelihood"]).upper()
    if s.get("plausibility"):
        s["plausibility"] = str(s["plausibility"]).upper()
    if s.get("impact_level"):
        s["impact_level"] = str(s["impact_level"]).upper()

    return s


def normalize_assumption(assumption):
    a = dict(assumption or {})
    a.setdefault("assumption_id", "ASM-" + sha(a.get("statement")))
    a.setdefault("statement", a["assumption_id"])
    a.setdefault("status", "UNKNOWN")
    a.setdefault("evidence_ids", [])
    a.setdefault("sensitivity", "UNKNOWN")
    a.setdefault("owner_candidate", None)
    return a


def normalize_contradiction(contradiction):
    c = dict(contradiction or {})
    c.setdefault("contradiction_id", "CONTRA-" + sha([c.get("type"), c.get("description")]))
    c.setdefault("type", "UNKNOWN")
    c.setdefault("description", c["contradiction_id"])
    c.setdefault("evidence_ids", [])
    c.setdefault("status", "PRESERVED")
    return c


# ----------------------------------------------------------------------
# Risk construction
# ----------------------------------------------------------------------

def get_object_labels(ids, registry, prefix, id_field):
    labels = []
    missing = []
    for x in ids or []:
        obj = registry.get(x)
        if obj:
            labels.append(f"{prefix}:{obj.get('name') or obj.get(id_field) or x}")
        else:
            labels.append(f"{prefix}:MISSING:{x}")
            missing.append(x)
    return labels, missing


def infer_categories(scenario, assets_by_id, functions_by_id, vulnerabilities_by_id, threats_by_id, dependencies_by_id):
    cats = list(scenario.get("category") or [])
    text = norm_text(" ".join([
        str(scenario.get("event", "")),
        str(scenario.get("trigger", "")),
        " ".join(scenario.get("impact_dimensions", [])),
    ]))

    if any("outage" in text or "unavailable" in text or "disrupt" in text for _ in [0]):
        cats.append("BUSINESS_CONTINUITY")

    for vid in scenario.get("vulnerability_ids", []):
        v = vulnerabilities_by_id.get(vid, {})
        if v.get("kind") in {"technical", "software", "configuration", "identity"}:
            cats.append("CYBER")
            cats.append("TECHNOLOGY")

    for tid in scenario.get("threat_ids", []):
        t = threats_by_id.get(tid, {})
        if t.get("type") in {"cyber", "malicious_actor", "ransomware", "intrusion"}:
            cats.append("CYBER")

    for dep_id in scenario.get("dependency_ids", []):
        d = dependencies_by_id.get(dep_id, {})
        if d.get("type") in {"supplier", "vendor", "third_party", "fourth_party"}:
            cats.append("THIRD_PARTY")
            cats.append("SUPPLY_CHAIN")

    for aid in scenario.get("affected_asset_ids", []):
        a = assets_by_id.get(aid, {})
        if a.get("type") in {"data", "database", "pii_repository"}:
            cats.append("DATA")
            cats.append("PRIVACY")
        if a.get("type") in {"payment", "financial_system"}:
            cats.append("FINANCIAL")

    cleaned = []
    for c in cats:
        c = str(c).upper()
        if c in TAXONOMY:
            cleaned.append(c)

    return unique(cleaned) or ["UNKNOWN"]


def combine_likelihood(scenario):
    issues = []
    lik = scenario.get("likelihood")

    if lik in LIKELIHOOD_SCORE:
        return lik, None, issues

    prob = clean_number(scenario.get("likelihood_probability"))
    if prob is not None:
        if not scenario.get("evidence_ids"):
            issues.append("Numeric likelihood supplied without linked evidence.")

        if prob < 0.05:
            mapped = "RARE"
        elif prob < 0.20:
            mapped = "UNLIKELY"
        elif prob < 0.50:
            mapped = "POSSIBLE"
        elif prob < 0.80:
            mapped = "LIKELY"
        else:
            mapped = "VERY_LIKELY"

        return mapped, prob, issues

    plaus = scenario.get("plausibility")
    if plaus in PLAUSIBILITY_TO_LIKELIHOOD:
        return PLAUSIBILITY_TO_LIKELIHOOD[plaus], None, issues

    issues.append("Likelihood/plausibility unresolved.")
    return "UNKNOWN", None, issues


def derive_impact_from_criticality(scenario, assets_by_id, functions_by_id):
    crits = []

    for aid in scenario.get("affected_asset_ids", []):
        a = assets_by_id.get(aid)
        if a:
            crits.append(a.get("criticality", "UNKNOWN"))

    for fid in scenario.get("affected_function_ids", []):
        f = functions_by_id.get(fid)
        if f:
            crits.append(f.get("criticality", "UNKNOWN"))

    if not crits:
        return "UNKNOWN", ["No affected asset/function criticality evidence."]

    best = max(crits, key=lambda x: CRITICALITY_SCORE.get(x, 3))

    mapping = {
        "LOW": "LOW",
        "MEDIUM": "MEDIUM",
        "HIGH": "HIGH",
        "MISSION_CRITICAL": "CRITICAL",
        "UNKNOWN": "UNKNOWN",
    }

    impact = mapping.get(best, "UNKNOWN")
    issues = []
    if impact == "UNKNOWN":
        issues.append("Impact unresolved due to unknown criticality.")

    return impact, issues


def assess_controls(scenario, controls_by_id):
    relevant_ids = unique(scenario.get("control_ids", []))
    credits = []
    summary = []
    gaps = []

    for cid in relevant_ids:
        c = controls_by_id.get(cid)
        if not c:
            gaps.append(f"Control {cid} referenced but not found.")
            continue

        credit = float(c.get("credit", 0.10))
        credits.append(credit)
        summary.append({
            "control_id": cid,
            "name": c.get("name"),
            "type": c.get("type"),
            "state": c.get("state"),
            "credit": credit,
            "verified": c.get("verified", False),
            "evidence_ids": c.get("evidence_ids", []),
        })

        if c.get("state") in {"UNKNOWN", "DESIGNED", "IMPLEMENTED_REPORTED"}:
            gaps.append(f"Control {cid} is not operationally verified for this scenario.")

    if not relevant_ids:
        gaps.append("No mapped control evidence for this scenario.")

    avg = round(sum(credits) / len(credits), 3) if credits else 0.0
    return avg, relevant_ids, summary, gaps


def data_completeness_score(risk):
    checks = [
        bool(risk.get("evidence_ids")),
        bool(risk.get("affected_asset_ids")),
        bool(risk.get("affected_function_ids")),
        bool(risk.get("driver_labels")),
        risk.get("likelihood") != "UNKNOWN",
        risk.get("impact_level") != "UNKNOWN",
        risk.get("velocity") != "UNKNOWN",
    ]
    pct = sum(1 for x in checks if x) / float(len(checks))

    if pct >= 0.85:
        return "COMPLETE", round(pct * 100, 1)
    if pct >= 0.60:
        return "SUBSTANTIAL", round(pct * 100, 1)
    if pct >= 0.30:
        return "PARTIAL", round(pct * 100, 1)
    return "SPARSE", round(pct * 100, 1)


def build_risk_from_scenario(scenario, registries, as_of):
    assets_by_id = registries["assets"]
    functions_by_id = registries["functions"]
    threats_by_id = registries["threats"]
    hazards_by_id = registries["hazards"]
    vulns_by_id = registries["vulnerabilities"]
    exposures_by_id = registries["exposures"]
    controls_by_id = registries["controls"]
    dependencies_by_id = registries["dependencies"]
    evidences_by_id = registries["evidences"]

    issues = []

    affected_asset_ids = unique(scenario.get("affected_asset_ids", []))
    affected_function_ids = unique(scenario.get("affected_function_ids", []))

    for aid in affected_asset_ids:
        if aid not in assets_by_id:
            issues.append({"severity": "HIGH", "message": f"Scenario {scenario['scenario_id']}: affected asset {aid} unresolved."})

    for fid in affected_function_ids:
        if fid not in functions_by_id:
            issues.append({"severity": "HIGH", "message": f"Scenario {scenario['scenario_id']}: affected function {fid} unresolved."})

    threat_labels, missing_threats = get_object_labels(scenario.get("threat_ids", []), threats_by_id, "THREAT", "threat_id")
    hazard_labels, missing_hazards = get_object_labels(scenario.get("hazard_ids", []), hazards_by_id, "HAZARD", "hazard_id")
    vuln_labels, missing_vulns = get_object_labels(scenario.get("vulnerability_ids", []), vulns_by_id, "VULN", "vulnerability_id")
    exposure_labels, missing_exposures = get_object_labels(scenario.get("exposure_ids", []), exposures_by_id, "EXPOSURE", "exposure_id")

    for x in missing_threats + missing_hazards + missing_vulns + missing_exposures:
        issues.append({"severity": "MEDIUM", "message": f"Scenario {scenario['scenario_id']}: driver {x} unresolved."})

    driver_labels = threat_labels + hazard_labels + vuln_labels + exposure_labels

    likelihood, likelihood_probability, lik_issues = combine_likelihood(scenario)
    for msg in lik_issues:
        issues.append({"severity": "MEDIUM", "message": msg})

    impact_level = scenario.get("impact_level")
    impact_issues = []
    if impact_level not in IMPACT_SCORE:
        impact_level, impact_issues = derive_impact_from_criticality(scenario, assets_by_id, functions_by_id)
    for msg in impact_issues:
        issues.append({"severity": "MEDIUM", "message": msg})

    control_effect, control_ids, control_summary, control_gaps = assess_controls(scenario, controls_by_id)

    dependency_ids = unique(
        scenario.get("dependency_ids", [])
        + [
            dep_id
            for dep_id, dep in dependencies_by_id.items()
            if dep.get("from_asset_id") in affected_asset_ids
        ]
    )

    evidence_ids = unique(
        scenario.get("evidence_ids", [])
        + [assets_by_id[a].get("evidence_ids", []) for a in affected_asset_ids if a in assets_by_id for _ in [0]]
        + [functions_by_id[f].get("evidence_ids", []) for f in affected_function_ids if f in functions_by_id for _ in [0]]
        + [controls_by_id[c].get("evidence_ids", []) for c in control_ids if c in controls_by_id for _ in [0]]
        + [dependencies_by_id[d].get("evidence_ids", []) for d in dependency_ids if d in dependencies_by_id for _ in [0]]
    )

    # Flatten accidental nested lists from comprehension above.
    flat_evidence_ids = []
    for x in evidence_ids:
        if isinstance(x, list):
            flat_evidence_ids.extend(x)
        elif x:
            flat_evidence_ids.append(x)
    evidence_ids = unique(flat_evidence_ids)

    evidence_confidence, independent_roots = compute_evidence_confidence(evidence_ids, evidences_by_id)

    inherent_score = LIKELIHOOD_SCORE.get(likelihood, 3) * IMPACT_SCORE.get(impact_level, 3)
    residual_raw = inherent_score * (1.0 - control_effect)

    if evidence_confidence == "LOW":
        residual_score = max(residual_raw, inherent_score * 0.60)
    elif evidence_confidence == "UNKNOWN":
        residual_score = max(residual_raw, inherent_score * 0.65)
    else:
        residual_score = residual_raw

    residual_band = score_to_risk_band(residual_score)
    if likelihood == "UNKNOWN" or impact_level == "UNKNOWN":
        residual_band = "UNKNOWN"

    criticalities = []
    for aid in affected_asset_ids:
        if aid in assets_by_id:
            criticalities.append(assets_by_id[aid].get("criticality", "UNKNOWN"))
    for fid in affected_function_ids:
        if fid in functions_by_id:
            criticalities.append(functions_by_id[fid].get("criticality", "UNKNOWN"))

    criticality = max(criticalities, key=lambda x: CRITICALITY_SCORE.get(x, 3)) if criticalities else "UNKNOWN"

    velocity = str(scenario.get("velocity", "UNKNOWN")).upper()
    persistence = str(scenario.get("persistence", "UNKNOWN")).upper()
    horizon = str(scenario.get("horizon", "UNKNOWN")).upper()

    priority_score = (
        residual_score
        * VELOCITY_MULT.get(velocity, 1.0)
        * CRITICALITY_MULT.get(criticality, 1.0)
        * CONFIDENCE_MULT.get(evidence_confidence, 1.0)
    )
    priority_band = priority_score_to_band(priority_score)

    if residual_band == "UNKNOWN":
        priority_band = "HIGH" if criticality in {"HIGH", "MISSION_CRITICAL"} else "MEDIUM"

    categories = infer_categories(
        scenario,
        assets_by_id,
        functions_by_id,
        vulns_by_id,
        threats_by_id,
        dependencies_by_id,
    )

    function_names = [functions_by_id[f].get("name", f) for f in affected_function_ids if f in functions_by_id]
    asset_names = [assets_by_id[a].get("name", a) for a in affected_asset_ids if a in assets_by_id]

    cause = "; ".join(driver_labels) if driver_labels else "an unresolved condition"
    event = scenario.get("event") or "a plausible disruptive event"
    impacted = ", ".join(function_names or asset_names) or "an unresolved asset or business function"
    impact_text = ", ".join(scenario.get("impact_dimensions", [])) or f"{impact_level.lower()} operational/business impact"

    risk_statement = (
        f"Because {cause}, {event} could affect {impacted}, "
        f"potentially causing {impact_text}. This is a scenario-supported risk candidate, not a certainty."
    )

    owner_candidate = scenario.get("owner_candidate")
    if not owner_candidate:
        owners = [functions_by_id[f].get("owner_candidate") for f in affected_function_ids if f in functions_by_id]
        owners = [o for o in owners if o]
        owner_candidate = owners[0] if len(unique(owners)) == 1 else "UNKNOWN"

    canonical_key = sha({
        "event": scenario.get("event"),
        "assets": sorted(affected_asset_ids),
        "functions": sorted(affected_function_ids),
        "drivers": sorted(
            scenario.get("threat_ids", [])
            + scenario.get("hazard_ids", [])
            + scenario.get("vulnerability_ids", [])
            + scenario.get("exposure_ids", [])
        ),
    })

    completeness, completeness_pct = data_completeness_score({
        "evidence_ids": evidence_ids,
        "affected_asset_ids": affected_asset_ids,
        "affected_function_ids": affected_function_ids,
        "driver_labels": driver_labels,
        "likelihood": likelihood,
        "impact_level": impact_level,
        "velocity": velocity,
    })

    risk = {
        "risk_id": "RISK-" + canonical_key,
        "canonical_key": canonical_key,
        "scenario_ids": [scenario.get("scenario_id")],
        "risk_title": scenario.get("title") or event,
        "risk_statement": risk_statement,
        "risk_category": categories,
        "status": "UNDER_ASSESSMENT" if evidence_confidence in {"LOW", "UNKNOWN"} or likelihood == "UNKNOWN" or impact_level == "UNKNOWN" else "OPEN",
        "asset_ids": affected_asset_ids,
        "business_function_ids": affected_function_ids,
        "threat_ids": scenario.get("threat_ids", []),
        "hazard_ids": scenario.get("hazard_ids", []),
        "vulnerability_ids": scenario.get("vulnerability_ids", []),
        "exposure_ids": scenario.get("exposure_ids", []),
        "control_ids": control_ids,
        "dependency_ids": dependency_ids,
        "driver_labels": driver_labels,
        "likelihood": likelihood,
        "likelihood_probability": likelihood_probability,
        "plausibility": scenario.get("plausibility"),
        "impact_level": impact_level,
        "impact_dimensions": scenario.get("impact_dimensions", []),
        "financial_impact": scenario.get("financial_impact"),
        "velocity": velocity,
        "persistence": persistence,
        "time_horizon": horizon,
        "criticality": criticality,
        "inherent_risk_score": round(inherent_score, 2),
        "inherent_risk_band": score_to_risk_band(inherent_score),
        "control_effect": control_effect,
        "control_effectiveness_summary": control_summary,
        "control_gaps": control_gaps,
        "residual_risk_score": round(residual_score, 2),
        "residual_risk_band": residual_band,
        "target_risk": scenario.get("target_risk", "UNKNOWN"),
        "priority_score": round(priority_score, 2),
        "priority_band": priority_band,
        "evidence_ids": evidence_ids,
        "evidence_confidence": evidence_confidence,
        "independent_source_roots": independent_roots,
        "data_completeness": completeness,
        "data_completeness_pct": completeness_pct,
        "model_uncertainty": "MEDIUM" if evidence_confidence != "HIGH" else "LOW",
        "risk_owner_candidate": owner_candidate,
        "assumptions": scenario.get("assumptions", []),
        "relationships": [],
        "correlated_risk_ids": [],
        "cascading_risk_ids": [],
        "common_cause_ids": [],
        "single_point_of_failure_candidate": False,
        "spof_dependency_ids": [],
        "concentration_candidate": False,
        "systemic_candidate": False,
        "trend": scenario.get("trend", "UNKNOWN"),
        "valid_from": as_of,
        "valid_to": None,
        "contradictions": [],
        "issues": issues,
        "limitations": [
            "Scenario-based risk candidate; not an incident, finding, alert, or certainty.",
            "Control effectiveness is only credited to the extent evidenced.",
        ],
    }

    return risk


# ----------------------------------------------------------------------
# Enrichment: dedupe, correlation, cascade, SPOF, concentration, systemic
# ----------------------------------------------------------------------

def deduplicate_risks(risks, contradictions):
    seen = {}
    deduped = []

    for risk in risks:
        key = risk["canonical_key"]
        if key not in seen:
            seen[key] = risk
            deduped.append(risk)
            continue

        old = seen[key]
        old["scenario_ids"] = unique(old.get("scenario_ids", []) + risk.get("scenario_ids", []))
        old["evidence_ids"] = unique(old.get("evidence_ids", []) + risk.get("evidence_ids", []))
        old["control_ids"] = unique(old.get("control_ids", []) + risk.get("control_ids", []))
        old["dependency_ids"] = unique(old.get("dependency_ids", []) + risk.get("dependency_ids", []))
        old["driver_labels"] = unique(old.get("driver_labels", []) + risk.get("driver_labels", []))
        old["assumptions"] = unique(old.get("assumptions", []) + risk.get("assumptions", []))

        if old.get("likelihood") != risk.get("likelihood") or old.get("impact_level") != risk.get("impact_level"):
            contra = normalize_contradiction({
                "type": "DUPLICATE_SCENARIO_CONFLICT",
                "description": (
                    f"Duplicate risk {old['risk_id']} has conflicting likelihood/impact: "
                    f"{old.get('likelihood')}/{old.get('impact_level')} vs {risk.get('likelihood')}/{risk.get('impact_level')}."
                ),
                "evidence_ids": unique(old.get("evidence_ids", []) + risk.get("evidence_ids", [])),
            })
            contradictions.append(contra)
            old["contradictions"].append(contra["contradiction_id"])

        # Conservative update: keep higher provisional score but preserve conflict.
        if risk.get("inherent_risk_score", 0) > old.get("inherent_risk_score", 0):
            old["inherent_risk_score"] = risk["inherent_risk_score"]
            old["inherent_risk_band"] = risk["inherent_risk_band"]

        old.setdefault("duplicate_merged_risk_ids", []).append(risk["risk_id"])

    return deduped


def correlate_risks(risks, assets_by_id):
    for i in range(len(risks)):
        for j in range(i + 1, len(risks)):
            a = risks[i]
            b = risks[j]
            shared = []

            for field in ["threat_ids", "hazard_ids", "vulnerability_ids", "exposure_ids", "control_ids"]:
                inter = set(a.get(field, [])) & set(b.get(field, []))
                if inter:
                    shared.append({"field": field, "ids": sorted(inter)})

            providers_a = set()
            providers_b = set()
            regions_a = set()
            regions_b = set()

            for aid in a.get("asset_ids", []):
                asset = assets_by_id.get(aid, {})
                if asset.get("provider"):
                    providers_a.add(asset["provider"])
                if asset.get("region"):
                    regions_a.add(asset["region"])

            for aid in b.get("asset_ids", []):
                asset = assets_by_id.get(aid, {})
                if asset.get("provider"):
                    providers_b.add(asset["provider"])
                if asset.get("region"):
                    regions_b.add(asset["region"])

            shared_providers = providers_a & providers_b
            shared_regions = regions_a & regions_b

            if shared_providers:
                shared.append({"field": "provider", "ids": sorted(shared_providers)})
            if shared_regions:
                shared.append({"field": "region", "ids": sorted(shared_regions)})

            if shared:
                common_cause = any(x["field"] in {"threat_ids", "hazard_ids", "vulnerability_ids", "provider"} for x in shared)

                rel_a = {
                    "type": "CORRELATED_WITH",
                    "with_risk_id": b["risk_id"],
                    "shared": shared,
                    "common_cause": common_cause,
                    "certainty": "CANDIDATE",
                }
                rel_b = {
                    "type": "CORRELATED_WITH",
                    "with_risk_id": a["risk_id"],
                    "shared": shared,
                    "common_cause": common_cause,
                    "certainty": "CANDIDATE",
                }

                a["relationships"].append(rel_a)
                b["relationships"].append(rel_b)
                a["correlated_risk_ids"] = unique(a.get("correlated_risk_ids", []) + [b["risk_id"]])
                b["correlated_risk_ids"] = unique(b.get("correlated_risk_ids", []) + [a["risk_id"]])

                if common_cause:
                    a["common_cause_ids"] = unique(a.get("common_cause_ids", []) + [b["risk_id"]])
                    b["common_cause_ids"] = unique(b.get("common_cause_ids", []) + [a["risk_id"]])


def detect_cascades(risks, dependencies_by_id, assets_by_id):
    risks_by_asset = {}
    for risk in risks:
        for aid in risk.get("asset_ids", []):
            risks_by_asset.setdefault(aid, []).append(risk["risk_id"])

    risk_by_id = {r["risk_id"]: r for r in risks}

    for dep_id, dep in dependencies_by_id.items():
        from_id = dep.get("from_asset_id")
        to_id = dep.get("to_asset_id")

        if not from_id or not to_id:
            continue

        from_risks = risks_by_asset.get(from_id, [])
        to_risks = risks_by_asset.get(to_id, [])

        for rid in from_risks:
            for oid in to_risks:
                if rid == oid:
                    continue
                risk = risk_by_id.get(rid)
                other = risk_by_id.get(oid)
                if not risk or not other:
                    continue

                rel = {
                    "type": "CASCADE_TO",
                    "with_risk_id": oid,
                    "dependency_id": dep_id,
                    "certainty": "POTENTIAL_PROPAGATION" if dep.get("critical") else "CANDIDATE",
                    "reason": f"Asset {from_id} depends on {to_id}; failure may propagate if dependency is critical or unrecoverable.",
                }

                # Avoid duplicate cascade relation.
                exists = any(
                    x.get("type") == "CASCADE_TO" and x.get("with_risk_id") == oid and x.get("dependency_id") == dep_id
                    for x in risk.get("relationships", [])
                )
                if not exists:
                    risk["relationships"].append(rel)
                    risk["cascading_risk_ids"] = unique(risk.get("cascading_risk_ids", []) + [oid])


def detect_spofs(risks, dependencies_by_id, assets_by_id, functions_by_id):
    spofs = []
    risk_by_asset = {}

    for risk in risks:
        for aid in risk.get("asset_ids", []):
            risk_by_asset.setdefault(aid, []).append(risk["risk_id"])

    for dep_id, dep in dependencies_by_id.items():
        if not dep.get("critical") or not dep.get("no_alternative") or dep.get("failover_verified"):
            continue

        from_asset = assets_by_id.get(dep.get("from_asset_id"), {})
        to_asset = assets_by_id.get(dep.get("to_asset_id"), {})

        critical = from_asset.get("criticality") in {"HIGH", "MISSION_CRITICAL"}
        if not critical:
            continue

        spof = {
            "spof_id": "SPOF-" + sha(dep_id),
            "dependency_id": dep_id,
            "from_asset_id": dep.get("from_asset_id"),
            "to_asset_id": dep.get("to_asset_id"),
            "provider": dep.get("to_provider") or to_asset.get("provider"),
            "status": "CANDIDATE",
            "reason": "Critical dependency with no evidenced independent alternative or verified failover.",
            "evidence_ids": dep.get("evidence_ids", []),
        }
        spofs.append(spof)

        for rid in risk_by_asset.get(dep.get("from_asset_id"), []):
            for risk in risks:
                if risk["risk_id"] == rid:
                    risk["single_point_of_failure_candidate"] = True
                    risk["spof_dependency_ids"] = unique(risk.get("spof_dependency_ids", []) + [dep_id])

    return spofs


def detect_concentration(risks, dependencies_by_id, assets_by_id):
    provider_assets = {}

    for dep_id, dep in dependencies_by_id.items():
        provider = dep.get("to_provider")
        if not provider:
            to_asset = assets_by_id.get(dep.get("to_asset_id"), {})
            provider = to_asset.get("provider")

        if provider:
            provider_assets.setdefault(provider, set()).add(dep.get("from_asset_id"))

    concentrations = []

    for provider, asset_set in provider_assets.items():
        asset_list = sorted([x for x in asset_set if x])
        if len(asset_list) < 2:
            continue

        critical_assets = [
            aid for aid in asset_list
            if assets_by_id.get(aid, {}).get("criticality") in {"HIGH", "MISSION_CRITICAL"}
        ]
        if not critical_assets:
            continue

        conc = {
            "concentration_id": "CONC-" + sha(provider),
            "provider": provider,
            "affected_asset_ids": asset_list,
            "critical_asset_ids": critical_assets,
            "status": "CANDIDATE",
            "reason": "Multiple critical assets depend on the same provider/component; concentration may amplify common-mode failure.",
        }
        concentrations.append(conc)

        for risk in risks:
            if set(risk.get("asset_ids", [])) & set(asset_list):
                risk["concentration_candidate"] = True
                risk.setdefault("concentration_ids", []).append(conc["concentration_id"])

    return concentrations


def detect_systemic(risks):
    for risk in risks:
        functions = risk.get("business_function_ids", [])
        assets = risk.get("asset_ids", [])
        correlated = risk.get("correlated_risk_ids", [])

        if len(functions) >= 3 or len(assets) >= 5 or len(correlated) >= 3:
            risk["systemic_candidate"] = True


# ----------------------------------------------------------------------
# Governance / appetite / treatment / priority
# ----------------------------------------------------------------------

def resolve_appetite_status(risk, appetite, tolerance):
    if risk.get("residual_risk_band") == "UNKNOWN":
        return "APPETITE_UNKNOWN"

    order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4, "UNKNOWN": 0}
    cat = risk.get("risk_category", ["DEFAULT"])[0]

    app = appetite.get(cat) or appetite.get("DEFAULT")
    tol = tolerance.get(cat) or tolerance.get("DEFAULT")

    if not app and not tol:
        return "APPETITE_UNKNOWN"

    res = order.get(risk.get("residual_risk_band"), 0)
    app_score = order.get(app, 99) if app else 99
    tol_score = order.get(tol, 99) if tol else 99

    if tol and res > tol_score:
        return "EXCEEDS_TOLERANCE"
    if app and res > app_score:
        return "NEAR_TOLERANCE"
    return "WITHIN_APPETITE"


def choose_treatment_options(risk):
    options = []

    if risk.get("priority_band") in {"HIGH", "CRITICAL"} or risk.get("appetite_status") == "EXCEEDS_TOLERANCE":
        options += ["REDUCE", "ESCALATE"]

    if risk.get("evidence_confidence") in {"LOW", "UNKNOWN"}:
        options += ["VERIFY", "MONITOR"]

    if risk.get("residual_risk_band") == "LOW" and risk.get("trend") in {"STABLE", "IMPROVING"}:
        options += ["MONITOR", "CONSIDER_ACCEPTANCE_BY_AUTHORIZED_OWNER"]

    if risk.get("financial_impact") or "FINANCIAL" in risk.get("risk_category", []):
        options += ["TRANSFER_CONTEXT"]

    if risk.get("systemic_candidate") or risk.get("concentration_candidate"):
        options += ["ESCALATE", "ARCHITECTURE_REVIEW"]

    return unique(options) or ["MONITOR"]


def generate_remediation_actions(risk, exposures_by_id, dependencies_by_id):
    actions = []

    if risk.get("control_gaps"):
        actions.append("Obtain independent control-effectiveness evidence or implement a safe compensating control pending primary remediation.")

    if risk.get("single_point_of_failure_candidate"):
        actions.append("Verify failover or independent alternative through authorized resilience testing before funding major replacement.")

    for exp_id in risk.get("exposure_ids", []):
        exp = exposures_by_id.get(exp_id, {})
        etype = norm_text(exp.get("type"))
        if any(k in etype for k in ["credential", "token", "privileged", "session"]):
            actions.append("If credential exposure is confirmed by authorized evidence, rotate/revoke affected privileged credentials and review session invalidation.")
        if "internet" in etype or "public" in etype:
            actions.append("Review whether public/internet exposure is intentional and least-privilege; restrict only through authorized change management.")

    if risk.get("vulnerability_ids"):
        actions.append("Request VULNINT applicability and exploitability assessment. Do not execute exploits or unauthorized probing.")

    if risk.get("threat_ids"):
        actions.append("Request CTI relevance assessment: actor capability, targeting relevance, and campaign evidence.")

    for dep_id in risk.get("dependency_ids", []):
        dep = dependencies_by_id.get(dep_id, {})
        if dep.get("type") in {"supplier", "vendor", "third_party", "fourth_party"}:
            actions.append("Review supplier continuity, subcontractor/fourth-party exposure, and contractual remedies with SUPPLYCHAININT.")

    if risk.get("evidence_confidence") in {"LOW", "UNKNOWN"}:
        actions.append("Collect at least one independent authoritative evidence source before consequential treatment decisions.")

    if risk.get("appetite_status") == "EXCEEDS_TOLERANCE":
        actions.append("Escalate to authorized risk owner/governance forum; AI cannot accept or waive tolerance breach.")

    return unique(actions)


def generate_monitoring_triggers(risk):
    triggers = []

    if risk.get("hazard_ids") or risk.get("threat_ids"):
        triggers.append("New incident, advisory, or credible threat activity affecting the risk driver.")

    if risk.get("dependency_ids"):
        triggers.append("Provider outage, degraded SLA, failed failover test, or supplier financial/continuity deterioration.")

    if risk.get("control_gaps"):
        triggers.append("Control exception, audit finding, failed test, or configuration drift affecting mitigation.")

    if "REGULATORY" in risk.get("risk_category", []) or "LEGAL" in risk.get("risk_category", []):
        triggers.append("Regulatory deadline, enforcement action, or legal interpretation change.")

    if "DATA" in risk.get("risk_category", []) or "PRIVACY" in risk.get("risk_category", []):
        triggers.append("New data exposure, unauthorized access, retention breach, or affected-population change.")

    return unique(triggers) or ["Review evidence freshness at next scheduled risk governance cycle."]


def recompute_priority_band(risk, l_delta=0, i_delta=0, c_delta=0):
    likelihood = shift_state(risk.get("likelihood", "UNKNOWN"), LIKELIHOOD_ORDER, l_delta)
    impact = shift_state(risk.get("impact_level", "UNKNOWN"), IMPACT_ORDER, i_delta)
    effect = clamp(float(risk.get("control_effect", 0.0)) + c_delta, 0.0, 0.95)

    inherent = LIKELIHOOD_SCORE.get(likelihood, 3) * IMPACT_SCORE.get(impact, 3)
    residual = inherent * (1.0 - effect)

    if risk.get("evidence_confidence") == "LOW":
        residual = max(residual, inherent * 0.60)

    priority = (
        residual
        * VELOCITY_MULT.get(risk.get("velocity", "UNKNOWN"), 1.0)
        * CRITICALITY_MULT.get(risk.get("criticality", "UNKNOWN"), 1.0)
        * CONFIDENCE_MULT.get(risk.get("evidence_confidence", "UNKNOWN"), 1.0)
    )

    return priority_score_to_band(priority), round(priority, 2)


def sensitivity_analysis(risks):
    results = []
    top = sorted(risks, key=lambda r: r.get("priority_score", 0), reverse=True)[:10]

    for risk in top:
        base_band = risk.get("priority_band", "UNKNOWN")
        tests = []

        variations = [
            ("likelihood_down", {"l_delta": -1}),
            ("likelihood_up", {"l_delta": 1}),
            ("impact_down", {"i_delta": -1}),
            ("impact_up", {"i_delta": 1}),
            ("control_effect_lower", {"c_delta": -0.20}),
            ("control_effect_higher", {"c_delta": 0.20}),
        ]

        sensitive = False
        for name, kwargs in variations:
            band, score = recompute_priority_band(risk, **kwargs)
            base_idx = band_index(base_band, PRIORITY_ORDER)
            test_idx = band_index(band, PRIORITY_ORDER)
            delta = abs(test_idx - base_idx) if base_idx is not None and test_idx is not None else 99
            status = "STABLE" if delta <= 1 else "PRIORITY_SENSITIVE"
            if status == "PRIORITY_SENSITIVE":
                sensitive = True
            tests.append({
                "test": name,
                "base_band": base_band,
                "variant_band": band,
                "variant_score": score,
                "status": status,
            })

        if sensitive:
            risk["priority_sensitive"] = True
            risk.setdefault("limitations", []).append("Priority ranking is sensitive to reasonable assumption changes; human review recommended.")

        results.append({
            "risk_id": risk["risk_id"],
            "base_priority_band": base_band,
            "tests": tests,
            "overall": "PRIORITY_SENSITIVE" if sensitive else "ROBUST_ENOUGH_FOR_TRIAGE",
        })

    return results


# ----------------------------------------------------------------------
# Fact gate / contradictions / hypotheses / dual AI
# ----------------------------------------------------------------------

def fact_gate(case, risks, evidences, assets_by_id, functions_by_id, controls_by_id, dependencies_by_id, contradictions, data_completeness):
    issues = []
    candidate_facts = []
    supported_facts = []
    partial_facts = []
    disputed_facts = []
    unknowns = []

    objective = case.get("objective", "")
    questions = case.get("questions", [])
    text_blob = " ".join([objective] + [str(q) for q in questions])

    policy_blocked = contains_any(text_blob, POLICY_BLOCK_KEYWORDS)
    if policy_blocked:
        issues.append({
            "severity": "BLOCK",
            "message": "Prohibited offensive/autonomous/consequential action language detected. Only defensive, human-governed risk intelligence is allowed.",
        })

    protected_blob = json.dumps({
        "assets": list(assets_by_id.values()),
        "functions": list(functions_by_id.values()),
        "risks": risks,
    }, default=str).lower()

    protected_hits = [k for k in PROTECTED_TRAIT_KEYWORDS if k in protected_blob]
    if protected_hits:
        issues.append({
            "severity": "HIGH",
            "message": f"Protected-trait keyword detected in risk features/tags: {protected_hits}. Remove from individual/consequential risk logic.",
        })

    ev_ids = {e["evidence_id"] for e in evidences}

    for risk in risks:
        rid = risk["risk_id"]

        if not risk.get("evidence_ids"):
            issues.append({"severity": "HIGH", "message": f"{rid}: no evidence linked."})

        missing_ev = [x for x in risk.get("evidence_ids", []) if x not in ev_ids]
        if missing_ev:
            issues.append({"severity": "HIGH", "message": f"{rid}: missing evidence ids {missing_ev}."})

        if not risk.get("asset_ids") and not risk.get("business_function_ids"):
            issues.append({"severity": "HIGH", "message": f"{rid}: no resolved asset or business function."})

        if risk.get("likelihood") == "UNKNOWN":
            issues.append({"severity": "MEDIUM", "message": f"{rid}: likelihood unresolved."})
            unknowns.append(f"{rid}: likelihood uncertain.")

        if risk.get("impact_level") == "UNKNOWN":
            issues.append({"severity": "MEDIUM", "message": f"{rid}: impact unresolved."})
            unknowns.append(f"{rid}: impact uncertain.")

        if risk.get("likelihood_probability") is not None and risk.get("evidence_confidence") in {"LOW", "UNKNOWN"}:
            issues.append({
                "severity": "MEDIUM",
                "message": f"{rid}: numeric likelihood present but evidence confidence is weak; avoid false precision.",
            })

        if risk.get("financial_impact") and not risk.get("evidence_ids"):
            issues.append({
                "severity": "HIGH",
                "message": f"{rid}: financial impact supplied without evidence.",
            })

        for cid in risk.get("control_ids", []):
            if cid not in controls_by_id:
                issues.append({"severity": "MEDIUM", "message": f"{rid}: control {cid} unresolved."})

        for did in risk.get("dependency_ids", []):
            if did not in dependencies_by_id:
                issues.append({"severity": "MEDIUM", "message": f"{rid}: dependency {did} unresolved."})

        risk_contra = [c for c in contradictions if rid in str(c.get("description", "")) or rid in c.get("risk_ids", [])]

        fact = {
            "type": "RISK_CANDIDATE",
            "risk_id": rid,
            "statement": risk.get("risk_statement"),
            "category": risk.get("risk_category"),
            "likelihood": risk.get("likelihood"),
            "impact": risk.get("impact_level"),
            "residual_risk": risk.get("residual_risk_band"),
            "priority": risk.get("priority_band"),
            "evidence_confidence": risk.get("evidence_confidence"),
            "evidence_ids": risk.get("evidence_ids", []),
        }

        if risk_contra:
            fact["status"] = "DISPUTED"
            disputed_facts.append(fact)
        elif risk.get("evidence_confidence") == "HIGH" and risk.get("likelihood") != "UNKNOWN" and risk.get("impact_level") != "UNKNOWN":
            fact["status"] = "SUPPORTED"
            supported_facts.append(fact)
        elif risk.get("evidence_confidence") == "MEDIUM":
            fact["status"] = "PARTIALLY_SUPPORTED"
            partial_facts.append(fact)
        else:
            fact["status"] = "INCONCLUSIVE"
            unknowns.append(f"{rid}: insufficient confidence for supported fact.")

        candidate_facts.append(fact)

    blocking_or_high = any(i.get("severity") in {"BLOCK", "HIGH"} for i in issues)

    return {
        "pass": not blocking_or_high,
        "policy_blocked": policy_blocked,
        "issues": issues,
        "candidate_facts": candidate_facts,
        "supported_facts": supported_facts,
        "partial_facts": partial_facts,
        "disputed_facts": disputed_facts,
        "unknowns": unique(unknowns),
        "data_completeness": data_completeness,
    }


def generate_hypotheses(risks, contradictions, fg):
    hypotheses = []
    top = sorted(risks, key=lambda r: r.get("priority_score", 0), reverse=True)[:5]

    for risk in top:
        rid = risk["risk_id"]

        hypotheses.append({
            "hypothesis_id": "H-" + sha([rid, "primary-driver"]),
            "risk_id": rid,
            "statement": "The identified driver plausibly creates the stated impact pathway.",
            "support": [
                f"Evidence confidence: {risk.get('evidence_confidence')}",
                "Drivers: " + "; ".join(risk.get("driver_labels", [])[:5]),
            ],
            "opposition": [
                "Failover, compensating controls, or alternate paths may not be fully evidenced.",
                "Asset/function inventory may be stale.",
            ],
            "assumptions": risk.get("assumptions", []),
            "falsification_tests": [
                "Verify current dependency inventory and asset criticality.",
                "Test or retrieve evidence of independent failover/alternative.",
                "Check whether control evidence demonstrates operating effectiveness.",
            ],
            "status": "CANDIDATE_NOT_PROVEN",
        })

        if risk.get("single_point_of_failure_candidate"):
            hypotheses.append({
                "hypothesis_id": "H-" + sha([rid, "spof"]),
                "risk_id": rid,
                "statement": "A critical dependency may be a single point of failure because no verified independent alternative is evidenced.",
                "support": [
                    "Dependency marked critical and no_alternative=true.",
                    "Failover not verified in current evidence.",
                ],
                "opposition": [
                    "Undocumented manual workaround may exist.",
                    "Secondary provider may be contracted but not tested.",
                    "Dependency inventory may be incomplete.",
                ],
                "falsification_tests": [
                    "Retrieve failover test record or authorized resilience exercise result.",
                    "Confirm alternate supplier/provider contract and technical readiness.",
                ],
                "status": "CANDIDATE_NOT_PROVEN",
            })

        if risk.get("correlated_risk_ids"):
            hypotheses.append({
                "hypothesis_id": "H-" + sha([rid, "correlation"]),
                "risk_id": rid,
                "statement": "This risk may be correlated with other risks through shared provider, control, vulnerability, or threat driver.",
                "support": [
                    f"Correlated risks: {risk.get('correlated_risk_ids')}",
                    "Shared driver/provider detected.",
                ],
                "opposition": [
                    "Shared metadata may be coincidental or stale.",
                    "Correlation does not prove common-mode failure.",
                ],
                "falsification_tests": [
                    "Validate independence of failure domains.",
                    "Check whether controls rely on the same underlying provider.",
                ],
                "status": "CANDIDATE_NOT_PROVEN",
            })

    if contradictions:
        hypotheses.append({
            "hypothesis_id": "H-CONTRADICTION",
            "risk_id": None,
            "statement": "Contradictory evidence may indicate stale inventory, scope mismatch, or genuinely different risk conditions.",
            "support": [c.get("description") for c in contradictions[:5]],
            "opposition": ["Contradictions may be real and should not be averaged blindly."],
            "falsification_tests": [
                "Compare as-of dates, scopes, methodologies, and source pedigrees.",
                "Preserve both states until authoritative evidence resolves conflict.",
            ],
            "status": "PRESERVED",
        })

    if fg.get("policy_blocked"):
        hypotheses.append({
            "hypothesis_id": "H-POLICY-BOUNDARY",
            "risk_id": None,
            "statement": "Requested analysis crosses into prohibited offensive/autonomous action territory.",
            "support": ["Policy-block keywords detected in objective/questions."],
            "opposition": ["Defensive resilience analysis may still be lawful and useful."],
            "falsification_tests": ["Reframe objective to evidence-based prioritization and human-governed treatment only."],
            "status": "BLOCKED_POLICY",
        })

    return hypotheses


def falsification_results(hypotheses, fg):
    tests = []

    for h in hypotheses:
        for t in h.get("falsification_tests", []):
            tests.append({
                "hypothesis_id": h.get("hypothesis_id"),
                "risk_id": h.get("risk_id"),
                "test": t,
                "status": "PENDING",
            })

    generic = [
        "Could the asset be less critical than recorded?",
        "Could an undocumented failover or manual workaround exist?",
        "Could the control be stronger than documentation suggests?",
        "Could the dependency inventory be stale?",
        "Could duplicate findings represent the same canonical risk?",
        "Could one source be counted multiple times as independent evidence?",
        "Could worst-case scenario be mistaken for expected case?",
        "Could probability estimate be unsupported by base rate or telemetry?",
    ]

    if fg.get("policy_blocked"):
        generic.append("Remove any offensive, autonomous, sabotage, or consequential-action recommendation.")

    for t in generic:
        tests.append({"hypothesis_id": "GENERIC", "risk_id": None, "test": t, "status": "PENDING"})

    return tests


def dual_ai_review(risks, fg, contradictions, sensitivity, hypotheses):
    primary = {
        "role": "Primary Risk Analyst",
        "summary": f"Assessed {len(risks)} canonical risks with evidence-linked scenarios, controls, dependencies, and priorities.",
    }

    checks = []

    if fg.get("policy_blocked"):
        checks.append("Policy-blocked request detected; only defensive/human-governed analysis allowed.")

    if any(r.get("evidence_confidence") in {"LOW", "UNKNOWN"} for r in risks):
        checks.append("Some risks have low or unknown evidence confidence; verify before consequential action.")

    if any(r.get("likelihood") == "UNKNOWN" or r.get("impact_level") == "UNKNOWN" for r in risks):
        checks.append("Likelihood or impact remains unresolved for at least one risk.")

    if contradictions:
        checks.append("Contradictions are preserved; do not average incompatible evidence silently.")

    if any(r.get("priority_sensitive") for r in risks):
        checks.append("Some priority rankings are assumption-sensitive; human review recommended.")

    if any(r.get("correlated_risk_ids") for r in risks):
        checks.append("Correlated risks exist; do not sum as independent.")

    if any(r.get("single_point_of_failure_candidate") for r in risks):
        checks.append("SPOF candidates require failover verification, not automatic critical designation.")

    if not hypotheses:
        checks.append("No competing hypotheses generated.")

    if checks:
        if any("Policy-blocked" in c or "unresolved" in c.lower() for c in checks):
            agreement = "INSUFFICIENT_EVIDENCE"
        else:
            agreement = "PARTIAL_AGREEMENT"
    else:
        agreement = "AGREE"

    return {
        "primary": primary,
        "skeptic": {
            "role": "Independent Risk Skeptic",
            "checks": checks,
            "adversarial_questions": [
                "Are we double counting the same scenario from multiple modules?",
                "Are controls actually independent defense layers?",
                "Are we confusing threat, vulnerability, exposure, incident, or alert with risk?",
                "Are we using worst case as expected case?",
                "Is probability fabricated?",
                "Is impact exaggerated or unsupported?",
                "Is data stale?",
                "Is one source being counted multiple times?",
                "What would make this risk materially lower?",
            ],
        },
        "agreement": agreement,
        "note": "AI agreement is not independent risk corroboration.",
    }


# ----------------------------------------------------------------------
# Gaps, actions, handoffs, graph
# ----------------------------------------------------------------------

def knowledge_gaps(risks, fg, appetite, tolerance):
    gaps = []

    for u in fg.get("unknowns", []):
        gaps.append({
            "gap": u,
            "importance": "HIGH",
            "recommended_source": "authoritative_control_or_asset_record",
            "expected_information_value": "Resolves material uncertainty before treatment decision.",
        })

    for risk in risks:
        if risk.get("evidence_confidence") in {"LOW", "UNKNOWN"}:
            gaps.append({
                "gap": f"{risk['risk_id']}: evidence confidence low/unknown.",
                "importance": "HIGH",
                "recommended_source": "independent_primary_evidence",
                "expected_information_value": "Improves risk confidence and priority stability.",
            })

        if risk.get("control_gaps"):
            gaps.append({
                "gap": f"{risk['risk_id']}: control effectiveness unverified.",
                "importance": "HIGH",
                "recommended_source": "control_test_or_audit_evidence",
                "expected_information_value": "Determines residual risk more accurately.",
            })

        if risk.get("single_point_of_failure_candidate"):
            gaps.append({
                "gap": f"{risk['risk_id']}: failover/alternative not verified.",
                "importance": "HIGH",
                "recommended_source": "resilience_test_or_contract_record",
                "expected_information_value": "Confirms or removes SPOF candidate.",
            })

        if risk.get("likelihood") == "UNKNOWN":
            gaps.append({
                "gap": f"{risk['risk_id']}: likelihood uncertain.",
                "importance": "MEDIUM",
                "recommended_source": "historical_frequency_or_cti_vulnint",
                "expected_information_value": "Supports calibrated likelihood or plausibility.",
            })

        if risk.get("impact_level") == "UNKNOWN":
            gaps.append({
                "gap": f"{risk['risk_id']}: impact uncertain.",
                "importance": "MEDIUM",
                "recommended_source": "business_impact_analysis",
                "expected_information_value": "Supports impact sizing and priority.",
            })

        if risk.get("risk_owner_candidate") == "UNKNOWN":
            gaps.append({
                "gap": f"{risk['risk_id']}: risk owner unknown.",
                "importance": "MEDIUM",
                "recommended_source": "org_governance_register",
                "expected_information_value": "Enables accountable treatment decisions.",
            })

    if not appetite and not tolerance:
        gaps.append({
            "gap": "Risk appetite/tolerance framework missing.",
            "importance": "HIGH",
            "recommended_source": "enterprise_risk_governance_policy",
            "expected_information_value": "Needed to classify appetite breaches; AI must not invent appetite.",
        })

    return gaps


def next_best_actions(risks, gaps, fg):
    actions = []

    if fg.get("policy_blocked"):
        return [
            "Continue only lawful defensive/resilience risk prioritization.",
            "Route offensive, autonomous, sabotage, or consequential-action requests to human governance/policy review.",
            "Do not recommend attacks, exploits, outages, supplier disruption, account freezes, firings, credit/insurance denials, or regulator notifications.",
        ]

    high_gaps = [g for g in gaps if g.get("importance") == "HIGH"]
    if high_gaps:
        actions.append("Close high-importance evidence gaps before consequential treatment decisions.")

    top = sorted(risks, key=lambda r: r.get("priority_score", 0), reverse=True)[:5]
    for risk in top:
        if risk.get("single_point_of_failure_candidate"):
            actions.append(f"Verify failover/alternative for {risk['risk_id']} through authorized resilience evidence/testing.")
        if risk.get("control_gaps"):
            actions.append(f"Obtain operating-effectiveness evidence for controls linked to {risk['risk_id']}.")
        if risk.get("evidence_confidence") in {"LOW", "UNKNOWN"}:
            actions.append(f"Collect independent primary evidence for {risk['risk_id']} before escalation or acceptance.")
        if risk.get("appetite_status") == "EXCEEDS_TOLERANCE":
            actions.append(f"Escalate {risk['risk_id']} to authorized risk owner/governance forum.")

    if not actions:
        actions.append("Maintain monitoring and refresh evidence at next governance cycle.")

    return unique(actions)


def specialist_handoffs(risks, case):
    handoffs = []
    text = " ".join([case.get("objective", "")] + [str(q) for q in case.get("questions", [])]).lower()

    categories = set()
    for r in risks:
        categories.update(r.get("risk_category", []))

    if "CYBER" in categories or "vulnerab" in text or "exploit" in text:
        handoffs.append({"to": "VULNINT", "reason": "technical vulnerability applicability and exploitability context."})
        handoffs.append({"to": "CYBINT", "reason": "cyber control and technical exposure context."})

    if "THREAT" in categories or "threat" in text:
        handoffs.append({"to": "CTI", "reason": "threat actor, campaign, TTP, and targeting relevance."})

    if any(r.get("dependency_ids") for r in risks) or "supplier" in text or "third_party" in text:
        handoffs.append({"to": "SUPPLYCHAININT", "reason": "entity-level dependency, fourth-party, and substitutability graph."})

    if "FINANCIAL" in categories or "loss" in text:
        handoffs.append({"to": "FININT", "reason": "financial exposure, loss data, and liquidity context."})

    if "FRAUD" in categories or "fraud" in text:
        handoffs.append({"to": "FRAUDINT", "reason": "fraud pattern and account-takeover evidence."})

    if "IDENTITY" in categories or "credential" in text:
        handoffs.append({"to": "CREDINT", "reason": "credential exposure and identity-control evidence."})

    if "REGULATORY" in categories or "LEGAL" in categories or "legal" in text:
        handoffs.append({"to": "LEGALINT", "reason": "legal/regulatory interpretation; RISKINT does not adjudicate."})

    if "PEOPLE" in categories or "owner" in text:
        handoffs.append({"to": "ORGINT", "reason": "business ownership, roles, and governance resolution."})

    if any(r.get("risk_owner_candidate") == "UNKNOWN" for r in risks):
        handoffs.append({"to": "RISKINT_MANAGER", "reason": "assign accountable risk owner before treatment decisions."})

    return handoffs


def build_graph(case, risks, evidences, assets_by_id, functions_by_id, controls_by_id, dependencies_by_id, threats_by_id, hazards_by_id, vulns_by_id, exposures_by_id, contradictions, hypotheses, fg):
    nodes = []
    edges = []
    seen_nodes = set()

    def add_node(node_id, node_type, props):
        if node_id in seen_nodes:
            return
        seen_nodes.add(node_id)
        nodes.append({"id": node_id, "type": node_type, "props": props})

    def add_edge(from_id, rel, to_id, props=None):
        edges.append({
            "from": from_id,
            "rel": rel,
            "to": to_id,
            "props": props or {},
        })

    for e in evidences:
        add_node(e["evidence_id"], "Evidence", {
            "source_id": e.get("source_id"),
            "source_type": e.get("source_type"),
            "reliability": e.get("reliability"),
            "observed_at": e.get("observed_at"),
            "pedigree": e.get("pedigree"),
        })

    for a in assets_by_id.values():
        add_node(a["asset_id"], "Asset", {
            "name": a.get("name"),
            "type": a.get("type"),
            "criticality": a.get("criticality"),
            "provider": a.get("provider"),
            "region": a.get("region"),
        })

    for f in functions_by_id.values():
        add_node(f["function_id"], "BusinessFunction", {
            "name": f.get("name"),
            "criticality": f.get("criticality"),
            "owner_candidate": f.get("owner_candidate"),
        })

    for t in threats_by_id.values():
        add_node(t["threat_id"], "Threat", {"name": t.get("name"), "type": t.get("type"), "targeting_relevance": t.get("targeting_relevance")})

    for h in hazards_by_id.values():
        add_node(h["hazard_id"], "Hazard", {"name": h.get("name"), "type": h.get("type")})

    for v in vulns_by_id.values():
        add_node(v["vulnerability_id"], "Vulnerability", {"name": v.get("name"), "kind": v.get("kind"), "applicability_state": v.get("applicability_state")})

    for e in exposures_by_id.values():
        add_node(e["exposure_id"], "Exposure", {"name": e.get("name"), "type": e.get("type")})

    for c in controls_by_id.values():
        add_node(c["control_id"], "Control", {"name": c.get("name"), "type": c.get("type"), "state": c.get("state"), "credit": c.get("credit")})

    for d in dependencies_by_id.values():
        add_node(d["dependency_id"], "Dependency", {
            "from_asset_id": d.get("from_asset_id"),
            "to_asset_id": d.get("to_asset_id"),
            "to_provider": d.get("to_provider"),
            "critical": d.get("critical"),
            "no_alternative": d.get("no_alternative"),
            "failover_verified": d.get("failover_verified"),
        })
        if d.get("from_asset_id") in assets_by_id and d.get("to_asset_id") in assets_by_id:
            add_edge(d["from_asset_id"], "DEPENDS_ON", d["to_asset_id"], {"dependency_id": d["dependency_id"]})

    for r in risks:
        add_node(r["risk_id"], "Risk", {
            "title": r.get("risk_title"),
            "statement": r.get("risk_statement"),
            "category": r.get("risk_category"),
            "likelihood": r.get("likelihood"),
            "impact": r.get("impact_level"),
            "residual_risk": r.get("residual_risk_band"),
            "priority": r.get("priority_band"),
            "confidence": r.get("evidence_confidence"),
            "status": r.get("status"),
        })

        for aid in r.get("asset_ids", []):
            add_edge(r["risk_id"], "AFFECTS", aid)
        for fid in r.get("business_function_ids", []):
            add_edge(r["risk_id"], "AFFECTS", fid)
        for tid in r.get("threat_ids", []):
            add_edge(r["risk_id"], "THREATENED_BY", tid)
        for hid in r.get("hazard_ids", []):
            add_edge(r["risk_id"], "HAZARD_DRIVEN_BY", hid)
        for vid in r.get("vulnerability_ids", []):
            add_edge(r["risk_id"], "HAS_VULNERABILITY", vid)
        for eid in r.get("exposure_ids", []):
            add_edge(r["risk_id"], "EXPOSES", eid)
        for cid in r.get("control_ids", []):
            add_edge(r["risk_id"], "MITIGATED_BY", cid, {"credit": controls_by_id.get(cid, {}).get("credit")})
        for did in r.get("dependency_ids", []):
            add_edge(r["risk_id"], "DEPENDS_ON", did)
        for evid in r.get("evidence_ids", []):
            add_edge(r["risk_id"], "SUPPORTED_BY", evid)

        for rel in r.get("relationships", []):
            if rel.get("type") == "CORRELATED_WITH":
                add_edge(r["risk_id"], "CORRELATED_WITH", rel.get("with_risk_id"), {"common_cause": rel.get("common_cause")})
            if rel.get("type") == "CASCADE_TO":
                add_edge(r["risk_id"], "CASCADE_TO", rel.get("with_risk_id"), {"dependency_id": rel.get("dependency_id"), "certainty": rel.get("certainty")})

    for c in contradictions:
        add_node(c["contradiction_id"], "Contradiction", c)

    for h in hypotheses:
        add_node(h["hypothesis_id"], "Hypothesis", {
            "risk_id": h.get("risk_id"),
            "statement": h.get("statement"),
            "status": h.get("status"),
        })
        if h.get("risk_id"):
            add_edge(h["hypothesis_id"], "EXPLAINS", h["risk_id"])

    for fact in fg.get("candidate_facts", [])[:100]:
        fid = "FACT-" + sha(fact)
        add_node(fid, "Fact", fact)
        for evid in fact.get("evidence_ids", []):
            add_edge(fid, "SUPPORTED_BY", evid)

    return {"nodes": nodes, "edges": edges}


# ----------------------------------------------------------------------
# Reporting
# ----------------------------------------------------------------------

def fmt(value):
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.2f}"
    return str(value)


def jarvis_brief(result):
    risks = result.get("risks", [])
    fg = result.get("fact_gate", {})

    if fg.get("policy_blocked"):
        return "POLICY_BLOCKED: offensive/autonomous/consequential action request refused. Defensive human-governed risk analysis only."

    if not risks:
        return "No canonical risks resolved from supplied evidence. Status inconclusive."

    top = sorted(risks, key=lambda r: r.get("priority_score", 0), reverse=True)[0]
    return (
        f"Top priority: {top['risk_id']} ({top.get('priority_band')}). "
        f"Residual risk: {top.get('residual_risk_band')}. "
        f"Evidence confidence: {top.get('evidence_confidence')}. "
        "No autonomous enforcement, acceptance, targeting, or offensive action issued."
    )


def render_markdown(result):
    out = []
    fg = result.get("fact_gate", {})
    risks = sorted(result.get("risks", []), key=lambda r: r.get("priority_score", 0), reverse=True)

    out.append(f"# RISKINT Report — {result.get('case_id', 'CASE')}")
    out.append(f"Mode: {result.get('mode')} | As of: {result.get('as_of')} | Engine: {VERSION}")
    out.append("")

    out.append("## JARVIS Brief")
    out.append(result.get("jarvis_brief", ""))
    out.append("")

    out.append("## Policy / Safety Status")
    if fg.get("policy_blocked"):
        out.append("- POLICY_BLOCKED: prohibited offensive/autonomous/consequential action request detected.")
        out.append("- Allowed output limited to defensive, evidence-linked, human-governed risk intelligence.")
    else:
        out.append("- No prohibited offensive/autonomous/consequential action request detected.")
    out.append("")

    out.append("## Objective")
    out.append(str(result.get("objective", "")))
    out.append("")

    out.append("## Questions")
    for q in result.get("questions", []):
        out.append(f"- {q}")
    out.append("")

    out.append("## Risk Portfolio Summary")
    out.append(f"- Canonical risks: `{len(risks)}`")
    out.append(f"- Fact gate pass: `{fg.get('pass')}`")
    out.append(f"- Supported facts: `{len(fg.get('supported_facts', []))}`")
    out.append(f"- Partial facts: `{len(fg.get('partial_facts', []))}`")
    out.append(f"- Disputed facts: `{len(fg.get('disputed_facts', []))}`")
    out.append("")

    out.append("## Top Risks")
    for r in risks[:10]:
        out.append(f"### {r['risk_id']} — {r.get('risk_title')}")
        out.append(f"- Statement: {r.get('risk_statement')}")
        out.append(f"- Category: `{', '.join(r.get('risk_category', []))}`")
        out.append(f"- Assets: `{r.get('asset_ids', [])}`")
        out.append(f"- Functions: `{r.get('business_function_ids', [])}`")
        out.append(f"- Drivers: `{r.get('driver_labels', [])}`")
        out.append(f"- Likelihood: `{r.get('likelihood')}`")
        out.append(f"- Impact: `{r.get('impact_level')}`")
        out.append(f"- Velocity: `{r.get('velocity')}`")
        out.append(f"- Inherent risk: `{r.get('inherent_risk_band')}` score `{fmt(r.get('inherent_risk_score'))}`")
        out.append(f"- Control effect: `{fmt(r.get('control_effect'))}`")
        out.append(f"- Residual risk: `{r.get('residual_risk_band')}` score `{fmt(r.get('residual_risk_score'))}`")
        out.append(f"- Priority: `{r.get('priority_band')}` score `{fmt(r.get('priority_score'))}`")
        out.append(f"- Evidence confidence: `{r.get('evidence_confidence')}`")
        out.append(f"- Data completeness: `{r.get('data_completeness')}` ({fmt(r.get('data_completeness_pct'))}%)")
        out.append(f"- Appetite status: `{r.get('appetite_status')}`")
        out.append(f"- SPOF candidate: `{r.get('single_point_of_failure_candidate')}`")
        out.append(f"- Correlated risks: `{r.get('correlated_risk_ids', [])}`")
        out.append(f"- Cascading risks: `{r.get('cascading_risk_ids', [])}`")
        out.append(f"- Treatment options: `{r.get('treatment_options', [])}`")
        out.append("- Remediation actions:")
        for a in r.get("remediation_actions", []):
            out.append(f"  - {a}")
        out.append("- Monitoring triggers:")
        for m in r.get("monitoring_triggers", []):
            out.append(f"  - {m}")
        out.append("")

    out.append("## Control Effectiveness")
    for r in risks[:10]:
        out.append(f"### {r['risk_id']}")
        for c in r.get("control_effectiveness_summary", []):
            out.append(f"- `{c.get('control_id')}` state=`{c.get('state')}` credit=`{fmt(c.get('credit'))}` verified=`{c.get('verified')}`")
        for g in r.get("control_gaps", []):
            out.append(f"- Gap: {g}")
        out.append("")

    out.append("## Single Points of Failure Candidates")
    if not result.get("single_points_of_failure"):
        out.append("- None detected from supplied dependency evidence.")
    for s in result.get("single_points_of_failure", []):
        out.append(f"- `{s.get('spof_id')}` dependency=`{s.get('dependency_id')}` provider=`{s.get('provider')}` status=`{s.get('status')}`")
        out.append(f"  - Reason: {s.get('reason')}")
    out.append("")

    out.append("## Concentration Candidates")
    if not result.get("concentration_risks"):
        out.append("- None detected from supplied dependency/provider evidence.")
    for c in result.get("concentration_risks", []):
        out.append(f"- `{c.get('concentration_id')}` provider=`{c.get('provider')}` assets=`{c.get('affected_asset_ids')}`")
    out.append("")

    out.append("## Fact Gate")
    out.append(f"Pass: `{fg.get('pass')}`")
    out.append(f"Policy blocked: `{fg.get('policy_blocked')}`")
    for issue in fg.get("issues", []):
        out.append(f"- [{issue.get('severity')}] {issue.get('message')}")
    out.append("")

    out.append("## Candidate Facts")
    for fact in fg.get("candidate_facts", [])[:40]:
        out.append(f"- {fact.get('risk_id')} `{fact.get('status')}` residual=`{fact.get('residual_risk')}` priority=`{fact.get('priority')}` confidence=`{fact.get('evidence_confidence')}`")
    out.append("")

    out.append("## Contradictions")
    if not result.get("contradictions"):
        out.append("- None preserved.")
    for c in result.get("contradictions", []):
        out.append(f"- `{c.get('contradiction_id')}` {c.get('type')}: {c.get('description')}")
    out.append("")

    out.append("## Hypotheses")
    for h in result.get("hypotheses", [])[:20]:
        out.append(f"### {h.get('hypothesis_id')} — {h.get('statement')}")
        out.append(f"- Risk: `{h.get('risk_id')}`")
        out.append(f"- Status: `{h.get('status')}`")
        out.append("- Support:")
        for x in h.get("support", []):
            out.append(f"  - {x}")
        out.append("- Opposition / caveats:")
        for x in h.get("opposition", []):
            out.append(f"  - {x}")
        out.append("- Falsification tests:")
        for x in h.get("falsification_tests", []):
            out.append(f"  - {x}")
        out.append("")

    out.append("## Falsification Queue")
    for t in result.get("falsification_results", [])[:50]:
        out.append(f"- [{t.get('hypothesis_id')}] {t.get('test')}")
    out.append("")

    out.append("## Sensitivity Analysis")
    for s in result.get("sensitivity_results", [])[:10]:
        out.append(f"### {s.get('risk_id')} base=`{s.get('base_priority_band')}` overall=`{s.get('overall')}`")
        for t in s.get("tests", []):
            out.append(f"- {t.get('test')}: `{t.get('base_band')}` -> `{t.get('variant_band')}` status=`{t.get('status')}`")
        out.append("")

    out.append("## Dual-AI Review")
    dual = result.get("dual_ai", {})
    out.append(f"Agreement: `{dual.get('agreement')}`")
    out.append(f"Primary: `{dual.get('primary', {}).get('summary')}`")
    for c in dual.get("skeptic", {}).get("checks", []):
        out.append(f"- Skeptic: {c}")
    out.append("")

    out.append("## Source Independence")
    out.append("```json")
    out.append(json.dumps(result.get("source_independence", {}).get("by_root", {}), indent=2, default=str))
    out.append("```")
    out.append("")

    out.append("## Knowledge Graph Summary")
    graph = result.get("graph", {})
    out.append(f"Nodes: `{len(graph.get('nodes', []))}`, Edges: `{len(graph.get('edges', []))}`")
    out.append("")

    out.append("## Knowledge Gaps")
    for g in result.get("knowledge_gaps", []):
        out.append(f"- [{g.get('importance')}] {g.get('gap')} -> {g.get('recommended_source')}")
    out.append("")

    out.append("## Recommended Next Actions")
    for a in result.get("recommended_next_actions", []):
        out.append(f"- {a}")
    out.append("")

    out.append("## Specialist Handoffs")
    for h in result.get("specialist_handoffs", []):
        out.append(f"- {h.get('to')}: {h.get('reason')}")
    out.append("")

    out.append("## Human Review Requirements")
    for h in result.get("human_review_requirements", []):
        out.append(f"- {h}")
    out.append("")

    out.append("## Limitations")
    for l in result.get("limitations", []):
        out.append(f"- {l}")
    out.append("")

    out.append("## Replay Manifest")
    out.append("```json")
    out.append(json.dumps(result.get("replay_manifest", {}), indent=2, default=str))
    out.append("```")

    return "\n".join(out)


# ----------------------------------------------------------------------
# Agent
# ----------------------------------------------------------------------

class RISKINTAgent:
    def __init__(self, mode="LOCAL_ONLY", authorized_source_types=None):
        if mode not in MODES:
            raise ValueError(f"mode must be one of {sorted(MODES)}")
        self.mode = mode
        self.authorized_source_types = authorized_source_types or [
            "internal_verified_inventory",
            "cmdb",
            "asset_inventory",
            "incident_record",
            "audit_report",
            "control_assessment",
            "penetration_test_summary",
            "authorized_scanner",
            "business_impact_analysis",
            "bcp_dr_record",
            "recovery_exercise",
            "legal_register",
            "regulatory_register",
            "official_advisory",
            "vendor_self_report",
            "policy_document",
            "authorized_commercial_risk_feed",
            "academic_research",
        ]

    def analyze(self, case):
        case = dict(case or {})
        case.setdefault("mode", self.mode)
        as_of = case.get("as_of") or now()

        evidences = [normalize_evidence(e, self.authorized_source_types) for e in case.get("evidences", []) or []]
        evidences_by_id = {e["evidence_id"]: e for e in evidences}

        assets = [normalize_asset(a) for a in case.get("assets", []) or []]
        assets_by_id = {a["asset_id"]: a for a in assets}

        functions = [normalize_business_function(f) for f in case.get("business_functions", []) or []]
        functions_by_id = {f["function_id"]: f for f in functions}

        threats = [normalize_threat(t) for t in case.get("threats", []) or []]
        threats_by_id = {t["threat_id"]: t for t in threats}

        hazards = [normalize_hazard(h) for h in case.get("hazards", []) or []]
        hazards_by_id = {h["hazard_id"]: h for h in hazards}

        vulnerabilities = [normalize_vulnerability(v) for v in case.get("vulnerabilities", []) or []]
        vulns_by_id = {v["vulnerability_id"]: v for v in vulnerabilities}

        exposures = [normalize_exposure(e) for e in case.get("exposures", []) or []]
        exposures_by_id = {e["exposure_id"]: e for e in exposures}

        controls = [normalize_control(c) for c in case.get("controls", []) or []]
        controls_by_id = {c["control_id"]: c for c in controls}

        dependencies = [normalize_dependency(d) for d in case.get("dependencies", []) or []]
        dependencies_by_id = {d["dependency_id"]: d for d in dependencies}

        scenarios = [normalize_scenario(s) for s in case.get("scenarios", []) or []]
        assumptions = [normalize_assumption(a) for a in case.get("assumptions", []) or []]
        contradictions = [normalize_contradiction(c) for c in case.get("contradictions", []) or []]

        registries = {
            "assets": assets_by_id,
            "functions": functions_by_id,
            "threats": threats_by_id,
            "hazards": hazards_by_id,
            "vulnerabilities": vulns_by_id,
            "exposures": exposures_by_id,
            "controls": controls_by_id,
            "dependencies": dependencies_by_id,
            "evidences": evidences_by_id,
        }

        raw_risks = []
        for sc in scenarios:
            risk, _ = build_risk_from_scenario(sc, registries, as_of)
            raw_risks.append(risk)

        risks = deduplicate_risks(raw_risks, contradictions)

        correlate_risks(risks, assets_by_id)
        detect_cascades(risks, dependencies_by_id, assets_by_id)
        spofs = detect_spofs(risks, dependencies_by_id, assets_by_id, functions_by_id)
        concentrations = detect_concentration(risks, dependencies_by_id, assets_by_id)
        detect_systemic(risks)

        appetite = case.get("risk_appetite", {}) or {}
        tolerance = case.get("risk_tolerance", {}) or {}

        for risk in risks:
            risk["appetite_status"] = resolve_appetite_status(risk, appetite, tolerance)
            risk["treatment_options"] = choose_treatment_options(risk)
            risk["remediation_actions"] = generate_remediation_actions(risk, exposures_by_id, dependencies_by_id)
            risk["monitoring_triggers"] = generate_monitoring_triggers(risk)

        data_completeness = {
            "risks_assessed": len(risks),
            "average_completeness_pct": round(
                sum(r.get("data_completeness_pct", 0) for r in risks) / len(risks), 2
            ) if risks else 0,
        }

        fg = fact_gate(
            case=case,
            risks=risks,
            evidences=evidences,
            assets_by_id=assets_by_id,
            functions_by_id=functions_by_id,
            controls_by_id=controls_by_id,
            dependencies_by_id=dependencies_by_id,
            contradictions=contradictions,
            data_completeness=data_completeness,
        )

        hypotheses = generate_hypotheses(risks, contradictions, fg)
        falsification = falsification_results(hypotheses, fg)
        sensitivity = sensitivity_analysis(risks)
        dual = dual_ai_review(risks, fg, contradictions, sensitivity, hypotheses)
        graph = build_graph(
            case=case,
            risks=risks,
            evidences=evidences,
            assets_by_id=assets_by_id,
            functions_by_id=functions_by_id,
            controls_by_id=controls_by_id,
            dependencies_by_id=dependencies_by_id,
            threats_by_id=threats_by_id,
            hazards_by_id=hazards_by_id,
            vulns_by_id=vulns_by_id,
            exposures_by_id=exposures_by_id,
            contradictions=contradictions,
            hypotheses=hypotheses,
            fg=fg,
        )

        gaps = knowledge_gaps(risks, fg, appetite, tolerance)
        actions = next_best_actions(risks, gaps, fg)
        handoffs = specialist_handoffs(risks, case)

        human_review_requirements = []
        if fg.get("policy_blocked"):
            human_review_requirements.append("Policy boundary: human governance required before any action.")
        if any(r.get("priority_band") in {"HIGH", "CRITICAL"} for r in risks):
            human_review_requirements.append("High/critical priority risks require authorized risk-owner review.")
        if any(r.get("appetite_status") == "EXCEEDS_TOLERANCE" for r in risks):
            human_review_requirements.append("Tolerance breaches require formal governance escalation.")
        if any(r.get("priority_sensitive") for r in risks):
            human_review_requirements.append("Assumption-sensitive priorities require human challenge.")
        if contradictions:
            human_review_requirements.append("Contradictory evidence requires human/source reconciliation.")
        if not human_review_requirements:
            human_review_requirements.append("Routine governance review; no autonomous consequential action.")

        status = "PARTIAL"
        if fg.get("policy_blocked"):
            status = "BLOCKED_POLICY"
        elif fg.get("pass") and risks:
            status = "SUCCEEDED"
        elif not risks:
            status = "INCONCLUSIVE"

        result = {
            "case_id": case.get("case_id"),
            "task_id": case.get("task_id"),
            "objective": case.get("objective"),
            "questions": case.get("questions") or [],
            "mode": case.get("mode"),
            "as_of": as_of,
            "model_version": VERSION,
            "evidences": [{k: v for k, v in e.items() if k != "content"} for e in evidences],
            "assets": assets,
            "business_functions": functions,
            "threats": threats,
            "hazards": hazards,
            "vulnerabilities": vulnerabilities,
            "exposures": exposures,
            "controls": controls,
            "dependencies": dependencies,
            "scenarios": scenarios,
            "assumptions": assumptions,
            "risks": risks,
            "single_points_of_failure": spofs,
            "concentration_risks": concentrations,
            "contradictions": contradictions,
            "fact_gate": fg,
            "hypotheses": hypotheses,
            "falsification_results": falsification,
            "sensitivity_results": sensitivity,
            "dual_ai": dual,
            "graph": graph,
            "source_independence": source_independence(evidences),
            "knowledge_gaps": gaps,
            "recommended_next_actions": actions,
            "specialist_handoffs": handoffs,
            "human_review_requirements": human_review_requirements,
            "data_completeness": data_completeness,
            "limitations": LIMITATIONS.copy(),
            "status": status,
            "replay_manifest": {
                "engine_version": VERSION,
                "as_of": as_of,
                "pipeline": [
                    "normalize_entities",
                    "build_risk_from_scenario",
                    "deduplicate",
                    "correlate",
                    "cascade_detect",
                    "spof_detect",
                    "concentration_detect",
                    "systemic_detect",
                    "appetite_status",
                    "treatment_options",
                    "fact_gate",
                    "hypotheses",
                    "falsification",
                    "sensitivity",
                    "dual_ai",
                    "graph",
                    "report",
                ],
                "evidence_hashes": {e["evidence_id"]: e["content_hash"] for e in evidences},
                "risk_canonical_keys": {r["risk_id"]: r["canonical_key"] for r in risks},
                "control_credits": {c["control_id"]: c["credit"] for c in controls},
                "dependency_spof_inputs": {
                    d["dependency_id"]: {
                        "critical": d.get("critical"),
                        "no_alternative": d.get("no_alternative"),
                        "failover_verified": d.get("failover_verified"),
                    }
                    for d in dependencies
                },
                "source_pedigree": {e["evidence_id"]: e.get("pedigree") for e in evidences},
                "policy_blocked": fg.get("policy_blocked"),
                "human_governance_required": True,
            },
        }

        result["jarvis_brief"] = jarvis_brief(result)
        return result


# ----------------------------------------------------------------------
# Demo
# ----------------------------------------------------------------------

if __name__ == "__main__":
    e_cmdb = make_evidence(
        "CMDB-AUTH-001",
        "internal_verified_inventory",
        "Customer authentication application depends on Identity Provider P. Current record shows no independently verified failover IdP.",
        observed_at="2026-10-01",
        pedigree=["INTERNAL_CMDB"],
    )

    e_incident = make_evidence(
        "INC-2025-044",
        "incident_record",
        "Prior outage of Identity Provider P caused customer login disruption for approximately 3 hours.",
        observed_at="2025-11-12",
        pedigree=["INCIDENT_SYSTEM"],
    )

    e_policy = make_evidence(
        "POLICY-FAILOVER-001",
        "policy_document",
        "Design document states secondary IdP may be used, but no failover test record is attached.",
        observed_at="2026-01-15",
        pedigree=["DESIGN_DOC"],
    )

    e_vendor = make_evidence(
        "VENDOR-P-SLA",
        "vendor_self_report",
        "Provider P reports 99.9% uptime SLA. No independent continuity test evidence supplied.",
        observed_at="2026-09-01",
        pedigree=["VENDOR_P"],
    )

    e_audit = make_evidence(
        "AUDIT-CTRL-001",
        "audit_report",
        "Audit found MFA implemented for admin accounts but failover testing evidence missing.",
        observed_at="2026-08-20",
        pedigree=["INTERNAL_AUDIT"],
    )

    assets = [
        {
            "asset_id": "ASSET-AUTH",
            "name": "Customer Authentication Application",
            "type": "application",
            "criticality": "MISSION_CRITICAL",
            "business_function_ids": ["FUNC-AUTH"],
            "provider": "ProviderP",
            "region": "EU",
            "evidence_ids": [e_cmdb["evidence_id"], e_incident["evidence_id"]],
        },
        {
            "asset_id": "ASSET-REPORTING",
            "name": "Internal Reporting Portal",
            "type": "application",
            "criticality": "HIGH",
            "business_function_ids": ["FUNC-REPORTING"],
            "provider": "ProviderP",
            "region": "EU",
            "evidence_ids": [e_cmdb["evidence_id"]],
        },
        {
            "asset_id": "ASSET-IDP-P",
            "name": "Identity Provider P",
            "type": "identity_provider",
            "criticality": "MISSION_CRITICAL",
            "provider": "ProviderP",
            "region": "GLOBAL",
            "evidence_ids": [e_vendor["evidence_id"], e_cmdb["evidence_id"]],
        },
    ]

    functions = [
        {
            "function_id": "FUNC-AUTH",
            "name": "Customer Authentication",
            "criticality": "MISSION_CRITICAL",
            "owner_candidate": "Head of Digital Services",
            "asset_ids": ["ASSET-AUTH"],
            "evidence_ids": [e_cmdb["evidence_id"]],
        },
        {
            "function_id": "FUNC-REPORTING",
            "name": "Internal Management Reporting",
            "criticality": "HIGH",
            "owner_candidate": "Finance Operations Lead",
            "asset_ids": ["ASSET-REPORTING"],
            "evidence_ids": [e_cmdb["evidence_id"]],
        },
    ]

    hazards = [
        {
            "hazard_id": "HAZ-IDP-OUTAGE",
            "name": "Identity Provider P availability outage",
            "type": "provider_outage",
            "source": "historical incident + vendor SLA",
            "severity": "HIGH",
            "evidence_ids": [e_incident["evidence_id"], e_vendor["evidence_id"]],
        }
    ]

    exposures = [
        {
            "exposure_id": "EXP-SINGLE-IDP",
            "name": "Single identity-provider dependency",
            "type": "single_dependency",
            "description": "Critical authentication path depends on one external IdP without verified independent failover.",
            "asset_ids": ["ASSET-AUTH", "ASSET-REPORTING"],
            "evidence_ids": [e_cmdb["evidence_id"], e_policy["evidence_id"]],
        }
    ]

    controls = [
        {
            "control_id": "CTRL-FAILOVER",
            "name": "Secondary IdP failover design",
            "type": "RECOVERY",
            "owner": "Platform Engineering",
            "scope": {
                "asset_ids": ["ASSET-AUTH", "ASSET-REPORTING"],
                "function_ids": ["FUNC-AUTH", "FUNC-REPORTING"],
            },
            "design_state": "DESIGNED",
            "implementation_state": "UNKNOWN",
            "effectiveness_state": "UNKNOWN",
            "last_tested": None,
            "evidence_ids": [e_policy["evidence_id"]],
        },
        {
            "control_id": "CTRL-MFA",
            "name": "Privileged account MFA",
            "type": "PREVENTIVE",
            "owner": "Security Operations",
            "scope": {
                "asset_ids": ["ASSET-AUTH"],
                "function_ids": ["FUNC-AUTH"],
            },
            "design_state": "IMPLEMENTED_REPORTED",
            "implementation_state": "IMPLEMENTED_REPORTED",
            "effectiveness_state": "PARTIALLY_EFFECTIVE",
            "last_tested": "2026-08-20",
            "evidence_ids": [e_audit["evidence_id"]],
        },
    ]

    dependencies = [
        {
            "dependency_id": "DEP-AUTH-IDP",
            "from_asset_id": "ASSET-AUTH",
            "to_asset_id": "ASSET-IDP-P",
            "to_provider": "ProviderP",
            "type": "identity_provider",
            "critical": True,
            "no_alternative": True,
            "failover_verified": False,
            "evidence_ids": [e_cmdb["evidence_id"], e_policy["evidence_id"]],
        },
        {
            "dependency_id": "DEP-REPORT-IDP",
            "from_asset_id": "ASSET-REPORTING",
            "to_asset_id": "ASSET-IDP-P",
            "to_provider": "ProviderP",
            "type": "identity_provider",
            "critical": True,
            "no_alternative": True,
            "failover_verified": False,
            "evidence_ids": [e_cmdb["evidence_id"]],
        },
    ]

    scenarios = [
        {
            "scenario_id": "SC-AUTH-IDP-OUTAGE",
            "title": "Customer authentication disruption due to IdP outage",
            "trigger": "Provider P outage or authentication service degradation",
            "event": "Loss of Identity Provider P availability prevents customer authentication",
            "affected_asset_ids": ["ASSET-AUTH", "ASSET-IDP-P"],
            "affected_function_ids": ["FUNC-AUTH"],
            "hazard_ids": ["HAZ-IDP-OUTAGE"],
            "exposure_ids": ["EXP-SINGLE-IDP"],
            "control_ids": ["CTRL-FAILOVER", "CTRL-MFA"],
            "dependency_ids": ["DEP-AUTH-IDP"],
            "category": ["BUSINESS_CONTINUITY", "OPERATIONAL", "IDENTITY"],
            "plausibility": "HIGHLY_PLAUSIBLE",
            "impact_level": "SEVERE",
            "impact_dimensions": ["customer access outage", "operational disruption", "revenue/service-level risk"],
            "velocity": "FAST",
            "persistence": "BRIEF",
            "horizon": "NEAR_TERM",
            "assumptions": [
                "No independently verified failover IdP is operational.",
                "Manual fallback is not sufficient for customer-facing authentication at scale.",
            ],
            "evidence_ids": [
                e_cmdb["evidence_id"],
                e_incident["evidence_id"],
                e_policy["evidence_id"],
                e_vendor["evidence_id"],
            ],
        },
        {
            "scenario_id": "SC-REPORT-IDP-OUTAGE",
            "title": "Internal reporting disruption due to same IdP outage",
            "trigger": "Provider P outage or authentication service degradation",
            "event": "Loss of Identity Provider P availability prevents internal reporting portal access",
            "affected_asset_ids": ["ASSET-REPORTING", "ASSET-IDP-P"],
            "affected_function_ids": ["FUNC-REPORTING"],
            "hazard_ids": ["HAZ-IDP-OUTAGE"],
            "exposure_ids": ["EXP-SINGLE-IDP"],
            "control_ids": ["CTRL-FAILOVER"],
            "dependency_ids": ["DEP-REPORT-IDP"],
            "category": ["BUSINESS_CONTINUITY", "OPERATIONAL", "IDENTITY"],
            "plausibility": "PLAUSIBLE",
            "impact_level": "HIGH",
            "impact_dimensions": ["internal decision delay", "operational disruption"],
            "velocity": "MEDIUM",
            "persistence": "BRIEF",
            "horizon": "NEAR_TERM",
            "assumptions": [
                "No independently verified failover IdP is operational for reporting portal.",
            ],
            "evidence_ids": [
                e_cmdb["evidence_id"],
                e_policy["evidence_id"],
                e_vendor["evidence_id"],
            ],
        },
    ]

    case = {
        "case_id": "RISKINT-DEMO-001",
        "task_id": "T-001",
        "objective": "Aggregate and prioritize enterprise operational/business-continuity risks from supplied evidence, without taking autonomous action.",
        "questions": [
            "What are the top canonical risks?",
            "Which risks share common causes or providers?",
            "Which SPOF candidates require verification?",
            "What should be prioritized first for human governance?",
        ],
        "mode": "LOCAL_ONLY",
        "as_of": "2026-10-09",
        "risk_appetite": {
            "BUSINESS_CONTINUITY": "MEDIUM",
            "OPERATIONAL": "MEDIUM",
            "IDENTITY": "MEDIUM",
            "DEFAULT": "MEDIUM",
        },
        "risk_tolerance": {
            "BUSINESS_CONTINUITY": "HIGH",
            "OPERATIONAL": "HIGH",
            "IDENTITY": "HIGH",
            "DEFAULT": "HIGH",
        },
        "evidences": [e_cmdb, e_incident, e_policy, e_vendor, e_audit],
        "assets": assets,
        "business_functions": functions,
        "hazards": hazards,
        "exposures": exposures,
        "controls": controls,
        "dependencies": dependencies,
        "scenarios": scenarios,
        "assumptions": [
            {
                "assumption_id": "ASM-FAILOVER",
                "statement": "Secondary IdP failover is designed but not operationally verified.",
                "status": "UNVERIFIED",
                "evidence_ids": [e_policy["evidence_id"]],
                "sensitivity": "HIGH",
            }
        ],
        "contradictions": [],
    }

    agent = RISKINTAgent(mode="LOCAL_ONLY")
    result = agent.analyze(case)

    print(render_markdown(result))

    # Uncomment to inspect full JSON result:
    # print(json.dumps(result, indent=2, default=str))