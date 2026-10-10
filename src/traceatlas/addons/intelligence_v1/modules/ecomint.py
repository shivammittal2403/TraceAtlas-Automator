#!/usr/bin/env python3
"""
ECONINT mini-engine: compact Python skeleton for lawful economic-intelligence workflows.

Boundaries:
- Evidence-first, temporal, revision-aware, policy-aware.
- No market manipulation, insider trading, sanctions evasion, tax/customs evasion,
  capital-flight concealment, economic sabotage, bank-run campaigns, or misinformation.
- Correlation is not causation. Forecasts are not facts.
"""

from __future__ import annotations

import json
import re
import hashlib
from datetime import datetime, timezone

VERSION = "0.1.0"
MODES = {"LOCAL_ONLY", "HYBRID", "CLOUD"}

REVISION_STATES = {
    "PRELIMINARY",
    "PROVISIONAL",
    "REVISED",
    "FINAL",
    "BENCHMARK_REVISED",
    "UNKNOWN",
}

POLICY_STATES = {
    "ANNOUNCED",
    "LEGISLATED",
    "FUNDED",
    "IMPLEMENTED",
    "PARTIALLY_IMPLEMENTED",
    "SUSPENDED",
    "REPEALED",
    "UNKNOWN",
}

POLICY_BLOCK_KEYWORDS = {
    "market manipulation",
    "manipulate market",
    "pump and dump",
    "insider trading",
    "material non-public",
    "sanctions evasion",
    "evade sanctions",
    "circumvent sanctions",
    "tax evasion",
    "customs evasion",
    "capital flight conceal",
    "economic sabotage",
    "bank run",
    "market panic",
    "destabilization campaign",
    "misinformation to affect markets",
    "attack supply infrastructure",
    "disrupt critical civilian supply",
    "chokepoint for destruction",
}

CAUSAL_TRIGGER_WORDS = {
    "cause",
    "caused",
    "causes",
    "causation",
    "why did",
    "drove",
    "driver was",
    "resulted from",
}

LIMITATIONS = [
    "Skeleton engine: no live statistical-office retrieval is performed.",
    "Economic data are measurements, not perfect reality; revisions and methodologies matter.",
    "Correlation and temporal order are not causation.",
    "Policy announcement is not implementation; implementation is not proven effect.",
    "Forecasts and scenarios are hypotheses, not facts.",
    "No market-action, sanctions-evasion, tax-evasion, sabotage, or destabilization guidance is provided.",
]


# ----------------------------------------------------------------------
# Basic helpers
# ----------------------------------------------------------------------

def sha(value) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


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


# ----------------------------------------------------------------------
# Period helpers
# ----------------------------------------------------------------------

PERIOD_RE = re.compile(
    r"^(\d{4})(?:-(\d{2})|-Q([1-4])|-H([1-2]))?$",
    re.IGNORECASE,
)


def parse_period(period):
    if not period:
        return {"raw": period, "freq": "UNKNOWN", "year": None, "month": None, "quarter": None, "half": None}

    p = str(period).strip().upper()
    m = PERIOD_RE.match(p)
    if not m:
        return {"raw": period, "freq": "UNKNOWN", "year": None, "month": None, "quarter": None, "half": None}

    year = int(m.group(1))
    month = int(m.group(2)) if m.group(2) else None
    quarter = int(m.group(3)) if m.group(3) else None
    half = int(m.group(4)) if m.group(4) else None

    if month:
        freq = "MONTH"
    elif quarter:
        freq = "QUARTER"
    elif half:
        freq = "HALF"
    else:
        freq = "YEAR"

    return {"raw": p, "freq": freq, "year": year, "month": month, "quarter": quarter, "half": half}


def period_sort_key(period):
    pr = parse_period(period)
    if pr.get("year") is None:
        return (9999, 9999, 9999)

    if pr.get("month") is not None:
        return (pr["year"], pr["month"], 0)

    if pr.get("quarter") is not None:
        return (pr["year"], pr["quarter"] * 3, 0)

    if pr.get("half") is not None:
        return (pr["year"], pr["half"] * 6, 0)

    return (pr["year"], 12, 0)


def yoy_period(period):
    pr = parse_period(period)
    if pr.get("year") is None:
        return None

    y = pr["year"] - 1

    if pr.get("month") is not None:
        return f"{y}-{pr['month']:02d}"

    if pr.get("quarter") is not None:
        return f"{y}-Q{pr['quarter']}"

    if pr.get("half") is not None:
        return f"{y}-H{pr['half']}"

    return str(y)


def shift_period(period, back=1):
    pr = parse_period(period)
    if pr.get("year") is None:
        return None

    if pr.get("month") is not None:
        idx = pr["year"] * 12 + (pr["month"] - 1) - back
        return f"{idx // 12}-{idx % 12 + 1:02d}"

    if pr.get("quarter") is not None:
        idx = pr["year"] * 4 + (pr["quarter"] - 1) - back
        return f"{idx // 4}-Q{idx % 4 + 1}"

    if pr.get("half") is not None:
        idx = pr["year"] * 2 + (pr["half"] - 1) - back
        return f"{idx // 2}-H{idx % 2 + 1}"

    return str(pr["year"] - back)


# ----------------------------------------------------------------------
# Source reliability / evidence
# ----------------------------------------------------------------------

def source_reliability(evidence):
    st = norm_text(evidence.get("source_type"))

    high_terms = [
        "official",
        "statistical_office",
        "central_bank",
        "ministry",
        "treasury",
        "customs",
        "labor_ministry",
        "multilateral",
        "development_bank",
        "court",
        "budget_office",
    ]
    medium_terms = [
        "commercial",
        "authorized",
        "platform",
        "dataset",
        "survey_provider",
        "academic",
        "industry_association",
    ]
    low_terms = ["media", "blog", "unverified", "unknown"]

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
    ev["evidence_id"] = "EV-" + sha(str(source_id) + str(kwargs.get("period")) + str(content))
    return ev


def normalize_evidence(evidence, authorized_source_types=None):
    ev = dict(evidence)
    ev.setdefault("evidence_id", "EV-" + sha(str(ev.get("source_id")) + str(ev.get("period")) + str(ev.get("content"))))
    ev.setdefault("retrieved_at", now())
    ev.setdefault("content_hash", sha(str(ev.get("content", ""))))
    ev.setdefault("pedigree", [ev.get("source_type", "unknown")])
    ev["reliability"] = source_reliability(ev)

    if authorized_source_types and ev.get("source_type") not in authorized_source_types:
        ev["authorization_warning"] = "SOURCE_NOT_AUTHORIZED_OR_UNCONFIGURED"

    return ev


def source_independence(evidences):
    roots = {}
    for e in evidences:
        root = (e.get("pedigree") or [e.get("source_type", "unknown")])[0]
        roots.setdefault(root, []).append(e["evidence_id"])

    pairs = []
    ids = list({e["evidence_id"] for e in evidences})
    root_by_id = {}
    for e in evidences:
        root_by_id[e["evidence_id"]] = (e.get("pedigree") or [e.get("source_type", "unknown")])[0]

    for i, a in enumerate(ids):
        for b in ids[i + 1:]:
            pairs.append({
                "evidence_a": a,
                "evidence_b": b,
                "state": "INDEPENDENT" if root_by_id.get(a) != root_by_id.get(b) else "DEPENDENT",
                "root_a": root_by_id.get(a),
                "root_b": root_by_id.get(b),
            })

    return {
        "by_root": roots,
        "pairs": pairs,
        "note": "Multiple reports using the same official release are not independent confirmations.",
    }


# ----------------------------------------------------------------------
# Indicator normalization
# ----------------------------------------------------------------------

def infer_measure_type(indicator):
    name = norm_text(indicator.get("name"))
    unit = norm_text(indicator.get("unit"))

    if "%" in unit or any(k in name for k in [
        "growth", "rate", "unemployment", "inflation", "participation",
        "confidence", "utilization", "share", "ratio"
    ]):
        return "RATE"

    if any(k in name for k in ["index", "cpi", "ppi", "rebase"]):
        return "INDEX"

    return "LEVEL"


def normalize_observation(obs, indicator=None):
    o = dict(obs or {})
    ind = indicator or {}

    o["value"] = clean_number(o.get("value"))
    o.setdefault("period", None)

    for field in [
        "unit",
        "currency",
        "price_basis",
        "seasonal_adjustment",
        "revision_status",
        "measure_type",
        "evidence_id",
    ]:
        if o.get(field) is None:
            o[field] = ind.get(field)

    o["price_basis"] = (o.get("price_basis") or "UNKNOWN").upper()
    o["seasonal_adjustment"] = (o.get("seasonal_adjustment") or "UNKNOWN").upper()
    o["revision_status"] = (o.get("revision_status") or "UNKNOWN").upper()

    if o["revision_status"] not in REVISION_STATES:
        o["revision_status"] = "UNKNOWN"

    return o


def normalize_indicator(indicator):
    ind = dict(indicator or {})

    ind.setdefault("indicator_id", "IND-" + sha(str(ind.get("name")) + str(ind.get("geography"))))
    ind.setdefault("name", ind["indicator_id"])
    ind.setdefault("definition", ind.get("name"))
    ind.setdefault("geography", "UNKNOWN")
    ind.setdefault("sector", "TOTAL")
    ind.setdefault("frequency", "UNKNOWN")
    ind.setdefault("unit", "")
    ind.setdefault("currency", None)
    ind.setdefault("price_basis", "UNKNOWN")
    ind.setdefault("seasonal_adjustment", "UNKNOWN")
    ind.setdefault("base_year", None)
    ind.setdefault("measure_type", infer_measure_type(ind))

    obs = [normalize_observation(o, ind) for o in ind.get("observations", [])]
    obs.sort(key=lambda x: period_sort_key(x.get("period")))
    ind["observations"] = obs

    return ind


def find_indicator(indicators, ref):
    ref_n = norm_text(ref)
    for ind in indicators:
        if norm_text(ind.get("indicator_id")) == ref_n or norm_text(ind.get("name")) == ref_n:
            return ind
    return None


def get_obs(indicator, period):
    if not indicator or not period:
        return None
    for o in indicator.get("observations", []):
        if o.get("period") == period:
            return o
    return None


def collect_evidence_ids(indicator, periods):
    ids = []
    for p in periods:
        o = get_obs(indicator, p)
        if o and o.get("evidence_id"):
            ids.append(o["evidence_id"])
    return list(dict.fromkeys(ids))


# ----------------------------------------------------------------------
# Deterministic arithmetic
# ----------------------------------------------------------------------

def change(curr, prev, measure_type="LEVEL"):
    if curr is None or prev is None:
        return None

    if measure_type == "RATE":
        return (round(curr - prev, 4), "pp")

    if prev == 0:
        return None

    return (round((curr / prev - 1.0) * 100.0, 4), "%")


def annualize_qoq(qoq_pct):
    if qoq_pct is None:
        return None
    return round(((1.0 + qoq_pct / 100.0) ** 4 - 1.0) * 100.0, 4)


def cagr(start_value, end_value, years):
    if start_value is None or end_value is None or years is None or years <= 0 or start_value <= 0:
        return None
    return round(((end_value / start_value) ** (1.0 / float(years)) - 1.0) * 100.0, 4)


def contribution_pp(total_prev, total_curr, comp_prev, comp_curr):
    if None in (total_prev, total_curr, comp_prev, comp_curr):
        return None
    if total_prev == 0:
        return None
    return round(((comp_curr - comp_prev) / total_prev) * 100.0, 4)


def deflate_index(nominal_value, price_value, base_price_value):
    if None in (nominal_value, price_value, base_price_value):
        return None
    if price_value == 0:
        return None
    return round((nominal_value / price_value) * base_price_value, 4)


# ----------------------------------------------------------------------
# Summaries and calculations
# ----------------------------------------------------------------------

def summarize_indicator(indicator):
    obs = indicator.get("observations", [])
    if not obs:
        return {
            "indicator_id": indicator.get("indicator_id"),
            "name": indicator.get("name"),
            "latest_period": None,
            "latest_value": None,
            "evidence_ids": [],
        }

    latest = obs[-1]
    prev_yoy = get_obs(indicator, yoy_period(latest.get("period")))
    prev_seq = get_obs(indicator, shift_period(latest.get("period"), 1))

    summary = {
        "indicator_id": indicator.get("indicator_id"),
        "name": indicator.get("name"),
        "definition": indicator.get("definition"),
        "geography": indicator.get("geography"),
        "sector": indicator.get("sector"),
        "frequency": indicator.get("frequency"),
        "unit": latest.get("unit") or indicator.get("unit"),
        "currency": latest.get("currency") or indicator.get("currency"),
        "price_basis": latest.get("price_basis"),
        "seasonal_adjustment": latest.get("seasonal_adjustment"),
        "revision_status": latest.get("revision_status"),
        "measure_type": indicator.get("measure_type"),
        "base_year": indicator.get("base_year"),
        "latest_period": latest.get("period"),
        "latest_value": latest.get("value"),
        "latest_evidence_id": latest.get("evidence_id"),
    }

    evidence_ids = []
    for o in [latest, prev_yoy, prev_seq]:
        if o and o.get("evidence_id"):
            evidence_ids.append(o["evidence_id"])
    summary["evidence_ids"] = list(dict.fromkeys(evidence_ids))

    if prev_yoy:
        if indicator.get("measure_type") == "RATE":
            ch = change(latest.get("value"), prev_yoy.get("value"), "RATE")
            if ch:
                summary["yoy_pp_change"] = ch[0]
                summary["yoy_unit"] = ch[1]
        else:
            ch = change(latest.get("value"), prev_yoy.get("value"), "LEVEL")
            if ch:
                summary["yoy_pct_change"] = ch[0]
                summary["yoy_unit"] = ch[1]

    if prev_seq:
        if indicator.get("measure_type") == "RATE":
            ch = change(latest.get("value"), prev_seq.get("value"), "RATE")
            if ch:
                summary["seq_pp_change"] = ch[0]
                summary["seq_unit"] = ch[1]
        else:
            ch = change(latest.get("value"), prev_seq.get("value"), "LEVEL")
            if ch:
                summary["seq_pct_change"] = ch[0]
                summary["seq_unit"] = ch[1]

        if indicator.get("frequency") == "QUARTER" and summary.get("seq_pct_change") is not None:
            summary["qoq_annualized_pct"] = annualize_qoq(summary["seq_pct_change"])

    return summary


def run_calculations(case, indicators, summaries):
    calcs = []
    summary_by_id = {s["indicator_id"]: s for s in summaries if s.get("indicator_id")}

    for spec in case.get("calculations", []) or []:
        typ = spec.get("type")

        if typ == "yoy":
            ind = find_indicator(indicators, spec.get("indicator"))
            s = summary_by_id.get(ind["indicator_id"]) if ind else None
            value = None
            unit = None
            formula = None
            evidence_ids = []

            if s:
                if s.get("yoy_pct_change") is not None:
                    value = s["yoy_pct_change"]
                    unit = "%"
                    formula = "((current_level_or_index / prior_year_level_or_index) - 1) * 100"
                elif s.get("yoy_pp_change") is not None:
                    value = s["yoy_pp_change"]
                    unit = "pp"
                    formula = "current_rate - prior_year_rate"

                evidence_ids = s.get("evidence_ids", [])

            calcs.append({
                "type": "yoy",
                "name": spec.get("name") or f"YoY {spec.get('indicator')}",
                "indicator_id": ind.get("indicator_id") if ind else spec.get("indicator"),
                "period": spec.get("period"),
                "value": value,
                "unit": unit,
                "formula": formula,
                "evidence_ids": evidence_ids,
            })

        elif typ == "annualized_qoq":
            ind = find_indicator(indicators, spec.get("indicator"))
            period = spec.get("period")
            curr = get_obs(ind, period) if ind else None
            prev = get_obs(ind, shift_period(period, 1)) if ind else None
            ch = change(curr.get("value") if curr else None, prev.get("value") if prev else None, "LEVEL")
            value = annualize_qoq(ch[0]) if ch else None

            calcs.append({
                "type": "annualized_qoq",
                "name": spec.get("name") or f"Annualized QoQ {spec.get('indicator')}",
                "indicator_id": ind.get("indicator_id") if ind else spec.get("indicator"),
                "period": period,
                "value": value,
                "unit": "%" if value is not None else None,
                "formula": "((1 + qoq_pct / 100) ^ 4 - 1) * 100",
                "evidence_ids": collect_evidence_ids(ind, [period, shift_period(period, 1)]) if ind else [],
            })

        elif typ == "contribution":
            total = find_indicator(indicators, spec.get("total_indicator"))
            comp = find_indicator(indicators, spec.get("component_indicator"))
            period = spec.get("period")

            if spec.get("weight") is not None and spec.get("growth") is not None:
                value = round(float(spec["weight"]) * float(spec["growth"]), 4)
                formula = "weight * component_growth"
                evidence_ids = []
            else:
                t_curr = get_obs(total, period) if total else None
                t_prev = get_obs(total, yoy_period(period)) if total else None
                c_curr = get_obs(comp, period) if comp else None
                c_prev = get_obs(comp, yoy_period(period)) if comp else None

                value = contribution_pp(
                    t_prev.get("value") if t_prev else None,
                    t_curr.get("value") if t_curr else None,
                    c_prev.get("value") if c_prev else None,
                    c_curr.get("value") if c_curr else None,
                )
                formula = "((component_current - component_prior_year) / total_prior_year) * 100"
                evidence_ids = collect_evidence_ids(total, [period, yoy_period(period)]) + \
                    collect_evidence_ids(comp, [period, yoy_period(period)])

            calcs.append({
                "type": "contribution",
                "name": spec.get("name") or f"Contribution {spec.get('component_indicator')} to {spec.get('total_indicator')}",
                "indicator_id": comp.get("indicator_id") if comp else spec.get("component_indicator"),
                "total_indicator_id": total.get("indicator_id") if total else spec.get("total_indicator"),
                "period": period,
                "value": value,
                "unit": "pp" if value is not None else None,
                "formula": formula,
                "evidence_ids": list(dict.fromkeys(evidence_ids)),
            })

        elif typ == "cagr":
            start_value = clean_number(spec.get("start_value"))
            end_value = clean_number(spec.get("end_value"))
            years = clean_number(spec.get("years"))
            value = cagr(start_value, end_value, years)

            calcs.append({
                "type": "cagr",
                "name": spec.get("name") or "CAGR",
                "value": value,
                "unit": "%" if value is not None else None,
                "formula": "((end_value / start_value) ^ (1 / years) - 1) * 100",
                "evidence_ids": spec.get("evidence_ids", []),
            })

        elif typ == "deflate":
            nominal_ind = find_indicator(indicators, spec.get("nominal_indicator"))
            price_ind = find_indicator(indicators, spec.get("price_indicator"))
            period = spec.get("period")
            base_period = spec.get("base_period")

            nom = get_obs(nominal_ind, period) if nominal_ind else None
            price = get_obs(price_ind, period) if price_ind else None
            base_price = get_obs(price_ind, base_period) if price_ind else None

            value = deflate_index(
                nom.get("value") if nom else None,
                price.get("value") if price else None,
                base_price.get("value") if base_price else None,
            )

            calcs.append({
                "type": "deflate",
                "name": spec.get("name") or f"Deflated {spec.get('nominal_indicator')}",
                "indicator_id": nominal_ind.get("indicator_id") if nominal_ind else spec.get("nominal_indicator"),
                "period": period,
                "value": value,
                "unit": spec.get("unit", "index"),
                "formula": "(nominal_value / price_index_value) * base_price_index_value",
                "evidence_ids": collect_evidence_ids(nominal_ind, [period]) +
                                 collect_evidence_ids(price_ind, [period, base_period]),
            })

        else:
            calcs.append({
                "type": typ,
                "name": spec.get("name") or "Unsupported calculation",
                "value": None,
                "unit": None,
                "formula": None,
                "evidence_ids": spec.get("evidence_ids", []),
            })

    return calcs


# ----------------------------------------------------------------------
# Cross-indicator validation
# ----------------------------------------------------------------------

def find_summary(summaries, *keywords):
    for s in summaries:
        name = norm_text(s.get("name"))
        if all(norm_text(k) in name for k in keywords):
            return s
    return None


def cross_validate(summaries):
    contradictions = []

    gdp = find_summary(summaries, "gdp") or find_summary(summaries, "gross domestic product")
    ip = find_summary(summaries, "industrial production")

    if gdp and ip:
        g = gdp.get("yoy_pct_change")
        i = ip.get("yoy_pct_change")
        if g is not None and i is not None and g > 1.0 and i < -1.0:
            contradictions.append({
                "type": "GROWTH_VS_PRODUCTION_DIVERGENCE",
                "description": f"Real GDP YoY is {g}% while industrial production YoY is {i}%.",
                "evidence_ids": list(dict.fromkeys((gdp.get("evidence_ids") or []) + (ip.get("evidence_ids") or []))),
                "interpretation": "Divergence may be real: services-led growth, inventory effects, sector mix, or data timing.",
            })

    unemp = find_summary(summaries, "unemployment")
    lfp = find_summary(summaries, "labor force participation") or find_summary(summaries, "participation")

    if unemp and lfp:
        u = unemp.get("yoy_pp_change")
        l = lfp.get("yoy_pp_change")
        if u is not None and l is not None and u < 0 and l < -0.2:
            contradictions.append({
                "type": "UNEMPLOYMENT_FALL_WITH_PARTICIPATION_FALL",
                "description": f"Unemployment fell {u} pp while labor-force participation fell {l} pp.",
                "evidence_ids": list(dict.fromkeys((unemp.get("evidence_ids") or []) + (lfp.get("evidence_ids") or []))),
                "interpretation": "Lower unemployment may partly reflect people leaving the labor force, not only job creation.",
            })

    return contradictions


# ----------------------------------------------------------------------
# Policy / forecast / scenario normalization
# ----------------------------------------------------------------------

def normalize_policies(case):
    policies = []
    for p in case.get("policies", []) or []:
        p = dict(p)
        p.setdefault("policy_id", "POL-" + sha(str(p.get("name")) + str(p.get("effective_date"))))
        status = (p.get("status") or "UNKNOWN").upper()
        if status not in POLICY_STATES:
            status = "UNKNOWN"
        p["status"] = status
        p.setdefault("effect", "UNKNOWN")
        p.setdefault("evidence_id", None)
        policies.append(p)
    return policies


def normalize_forecasts(case):
    forecasts = []
    for f in case.get("forecasts", []) or []:
        f = dict(f)
        f.setdefault("forecast_id", "FC-" + sha(str(f.get("indicator")) + str(f.get("period")) + str(f.get("scenario"))))
        f.setdefault("scenario", "BASE")
        f.setdefault("confidence", "LOW")
        f.setdefault("assumptions", [])
        f.setdefault("range", {})
        f.setdefault("evidence_id", None)
        f["assessment_status"] = "FORECAST_NOT_FACT"
        forecasts.append(f)
    return forecasts


def normalize_scenarios(case):
    scenarios = []
    for s in case.get("scenarios", []) or []:
        s = dict(s)
        s.setdefault("scenario_id", "SC-" + sha(str(s.get("name"))))
        s.setdefault("type", "CUSTOM")
        s.setdefault("assumptions", [])
        s.setdefault("affected_indicators", [])
        s["assessment_status"] = "SCENARIO_NOT_PREDICTION"
        scenarios.append(s)
    return scenarios


# ----------------------------------------------------------------------
# Data quality
# ----------------------------------------------------------------------

def assess_data_quality(indicators, evidences, as_of):
    total_obs = sum(len(i.get("observations", [])) for i in indicators)
    if total_obs == 0:
        return {
            "completeness": 0,
            "evidence_coverage": 0,
            "revision_transparency": 0,
            "comparability": 0,
            "method_transparency": 0,
            "timeliness": 0,
            "source_authority": 0,
            "overall": 0,
            "notes": ["No observations supplied."],
        }

    valued = 0
    evidenced = 0
    revision_known = 0
    basis_known = 0
    sa_known = 0

    for ind in indicators:
        for o in ind.get("observations", []):
            if o.get("value") is not None:
                valued += 1
            if o.get("evidence_id"):
                evidenced += 1
            if o.get("revision_status") != "UNKNOWN":
                revision_known += 1
            if o.get("price_basis") != "UNKNOWN":
                basis_known += 1
            if o.get("seasonal_adjustment") != "UNKNOWN":
                sa_known += 1

    method_known = sum(1 for e in evidences if e.get("methodology_reference"))
    method_transparency = (method_known / max(len(evidences), 1)) * 100.0

    rel_score = {"HIGH": 90, "MEDIUM": 65, "MEDIUM_LOW": 50, "LOW": 30}
    source_authority = sum(rel_score.get(e.get("reliability", "LOW"), 30) for e in evidences) / max(len(evidences), 1)

    release_dates = []
    for e in evidences:
        dt = parse_datetime(e.get("release_date"))
        if dt:
            release_dates.append(dt)

    as_of_dt = parse_datetime(as_of)
    latest_release = max(release_dates) if release_dates else None

    if latest_release and as_of_dt:
        days = (as_of_dt - latest_release).days
        if days <= 90:
            timeliness = 90
        elif days <= 180:
            timeliness = 80
        elif days <= 365:
            timeliness = 60
        else:
            timeliness = 40
    else:
        timeliness = 50

    completeness = (valued / total_obs) * 100.0
    evidence_coverage = (evidenced / total_obs) * 100.0
    revision_transparency = (revision_known / total_obs) * 100.0
    comparability = ((basis_known + sa_known) / (2.0 * total_obs)) * 100.0

    overall = (
        0.20 * completeness +
        0.20 * evidence_coverage +
        0.15 * revision_transparency +
        0.15 * comparability +
        0.10 * timeliness +
        0.10 * method_transparency +
        0.10 * source_authority
    )

    return {
        "completeness": round(completeness, 2),
        "evidence_coverage": round(evidence_coverage, 2),
        "revision_transparency": round(revision_transparency, 2),
        "comparability": round(comparability, 2),
        "method_transparency": round(method_transparency, 2),
        "timeliness": round(timeliness, 2),
        "source_authority": round(source_authority, 2),
        "overall": round(overall, 2),
        "notes": [
            "Scores are heuristic and dimension-specific, not a single opaque country-risk number.",
        ],
    }


# ----------------------------------------------------------------------
# Fact gate
# ----------------------------------------------------------------------

def fact_gate(case, indicators, evidences, summaries, calcs, policies, forecasts, contradictions, data_quality):
    issues = []
    candidate_facts = []
    unknowns = []

    questions = case.get("questions") or []
    objective = case.get("objective") or ""
    text_blob = " ".join([objective] + [str(q) for q in questions])

    policy_blocked = contains_any(text_blob, POLICY_BLOCK_KEYWORDS)
    if policy_blocked:
        issues.append({
            "severity": "BLOCK",
            "message": "Prohibited economic-action request detected. Only defensive/resilience analysis is allowed.",
        })

    ev_ids = {e["evidence_id"] for e in evidences}

    for ind in indicators:
        if not ind.get("definition"):
            issues.append({
                "severity": "MEDIUM",
                "message": f"{ind.get('indicator_id')}: indicator definition missing.",
            })

        for o in ind.get("observations", []):
            ref = f"{ind.get('indicator_id')}@{o.get('period')}"

            if o.get("value") is None:
                issues.append({"severity": "MEDIUM", "message": f"{ref}: value missing."})

            if not o.get("evidence_id"):
                issues.append({"severity": "HIGH", "message": f"{ref}: no evidence linked."})
            elif o["evidence_id"] not in ev_ids:
                issues.append({"severity": "HIGH", "message": f"{ref}: evidence id not found in evidence register."})

            if o.get("price_basis") == "UNKNOWN":
                issues.append({"severity": "MEDIUM", "message": f"{ref}: nominal/real basis unknown."})

            if o.get("seasonal_adjustment") == "UNKNOWN":
                issues.append({"severity": "MEDIUM", "message": f"{ref}: seasonal-adjustment status unknown."})

            if o.get("revision_status") == "UNKNOWN":
                issues.append({"severity": "MEDIUM", "message": f"{ref}: revision status unknown."})

            candidate_facts.append({
                "type": "OBSERVATION",
                "indicator_id": ind.get("indicator_id"),
                "period": o.get("period"),
                "value": o.get("value"),
                "unit": o.get("unit"),
                "price_basis": o.get("price_basis"),
                "seasonal_adjustment": o.get("seasonal_adjustment"),
                "revision_status": o.get("revision_status"),
                "evidence_ids": [o.get("evidence_id")] if o.get("evidence_id") else [],
                "assessment_status": "SOURCE_REPORTED",
            })

    for s in summaries:
        if s.get("latest_value") is not None:
            candidate_facts.append({
                "type": "LATEST_INDICATOR",
                "indicator_id": s.get("indicator_id"),
                "period": s.get("latest_period"),
                "value": s.get("latest_value"),
                "unit": s.get("unit"),
                "price_basis": s.get("price_basis"),
                "seasonal_adjustment": s.get("seasonal_adjustment"),
                "revision_status": s.get("revision_status"),
                "evidence_ids": s.get("evidence_ids", []),
                "assessment_status": "NORMALIZED",
            })

        for key, label in [
            ("yoy_pct_change", "YOY_PERCENT_CHANGE"),
            ("yoy_pp_change", "YOY_PP_CHANGE"),
            ("qoq_annualized_pct", "QOQ_ANNUALIZED_PERCENT"),
        ]:
            if s.get(key) is not None:
                candidate_facts.append({
                    "type": "CALCULATED_SUMMARY",
                    "subtype": label,
                    "indicator_id": s.get("indicator_id"),
                    "period": s.get("latest_period"),
                    "value": s.get(key),
                    "unit": s.get("yoy_unit") if "yoy" in key else ("%" if "annualized" in key else None),
                    "evidence_ids": s.get("evidence_ids", []),
                    "assessment_status": "DETERMINISTIC",
                })

    for c in calcs:
        if c.get("value") is not None:
            candidate_facts.append({
                "type": "CALCULATION",
                "calc_type": c.get("type"),
                "name": c.get("name"),
                "value": c.get("value"),
                "unit": c.get("unit"),
                "formula": c.get("formula"),
                "evidence_ids": c.get("evidence_ids", []),
                "assessment_status": "DETERMINISTIC_TRACEABLE",
            })
        else:
            issues.append({
                "severity": "MEDIUM",
                "message": f"Calculation '{c.get('name')}' produced no value; check inputs.",
            })

    for p in policies:
        if p.get("evidence_id") and p["evidence_id"] not in ev_ids:
            issues.append({
                "severity": "HIGH",
                "message": f"Policy {p.get('policy_id')}: evidence id not found.",
            })

        candidate_facts.append({
            "type": "POLICY_STATUS",
            "policy_id": p.get("policy_id"),
            "name": p.get("name"),
            "status": p.get("status"),
            "announcement_date": p.get("announcement_date"),
            "effective_date": p.get("effective_date"),
            "evidence_ids": [p.get("evidence_id")] if p.get("evidence_id") else [],
            "assessment_status": "ANNOUNCEMENT_IS_NOT_EFFECT",
        })

        if p.get("status") in {"ANNOUNCED", "LEGISLATED", "FUNDED"}:
            unknowns.append(f"{p.get('policy_id')}: implementation/effect not yet established.")

    for f in forecasts:
        if f.get("evidence_id") and f["evidence_id"] not in ev_ids:
            issues.append({
                "severity": "HIGH",
                "message": f"Forecast {f.get('forecast_id')}: evidence id not found.",
            })

        if not f.get("assumptions"):
            issues.append({
                "severity": "MEDIUM",
                "message": f"Forecast {f.get('forecast_id')}: assumptions missing.",
            })

        if not f.get("range"):
            issues.append({
                "severity": "MEDIUM",
                "message": f"Forecast {f.get('forecast_id')}: uncertainty range missing.",
            })

        candidate_facts.append({
            "type": "FORECAST",
            "forecast_id": f.get("forecast_id"),
            "scenario": f.get("scenario"),
            "indicator": f.get("indicator"),
            "period": f.get("period"),
            "value": f.get("value"),
            "range": f.get("range"),
            "assumptions": f.get("assumptions"),
            "evidence_ids": [f.get("evidence_id")] if f.get("evidence_id") else [],
            "assessment_status": "FORECAST_NOT_FACT",
        })

    for con in contradictions:
        issues.append({
            "severity": "MEDIUM",
            "message": f"Cross-indicator contradiction: {con.get('type')} - {con.get('description')}",
        })

    if contains_any(text_blob, CAUSAL_TRIGGER_WORDS):
        issues.append({
            "severity": "INFO",
            "message": "Causal language detected. Use causal-hypothesis testing; do not infer causation from timing alone.",
        })

    if data_quality.get("overall", 0) < 50:
        issues.append({
            "severity": "MEDIUM",
            "message": "Low aggregate data quality. Treat conclusions as provisional.",
        })

    blocking_or_high = any(i.get("severity") in {"BLOCK", "HIGH"} for i in issues)

    return {
        "pass": not blocking_or_high,
        "policy_blocked": policy_blocked,
        "issues": issues,
        "candidate_facts": candidate_facts,
        "unknowns": unknowns,
    }


# ----------------------------------------------------------------------
# Hypothesis / falsification / dual-AI
# ----------------------------------------------------------------------

def generate_hypotheses(case, summaries, calcs, contradictions, fg, policies):
    hypotheses = []

    def add(hid, statement, domain, support, opposition, mechanism, lag, confounders, falsification_tests):
        hypotheses.append({
            "hypothesis_id": hid,
            "statement": statement,
            "domain": domain,
            "support": support,
            "opposition": opposition,
            "mechanism": mechanism,
            "lag": lag,
            "confounders": confounders,
            "falsification_tests": falsification_tests,
            "status": "CANDIDATE_NOT_PROVEN",
        })

    questions_text = " ".join([case.get("objective", "")] + [str(q) for q in (case.get("questions") or [])]).lower()

    gdp = find_summary(summaries, "gdp") or find_summary(summaries, "gross domestic product")
    contributions = [c for c in calcs if c.get("type") == "contribution"]

    if gdp and gdp.get("yoy_pct_change") is not None:
        g = gdp["yoy_pct_change"]
        support = [f"Real GDP YoY change: {g}%"]
        opposition = ["Need expenditure/GVA decomposition, revisions, and base-effect checks."]

        add(
            "H-GDP-DOMESTIC-DEMAND",
            "Domestic demand may be contributing to growth.",
            "growth",
            support,
            opposition,
            "Higher consumption or investment raises aggregate demand and output.",
            "1-4 quarters",
            ["base effects", "import leakage", "inventory cycles", "data revisions"],
            ["Check household consumption and fixed investment contributions.", "Check imports and inventory changes."],
        )

        pos_contrib = [c for c in contributions if c.get("value") is not None and c["value"] > 0.5]
        neg_contrib = [c for c in contributions if c.get("value") is not None and c["value"] < -0.1]

        if pos_contrib:
            add(
                "H-GDP-SPECIFIED-SECTOR-DRIVER",
                "Specified sectoral components contributed positively to growth.",
                "growth",
                [f"{c.get('name')}: {c.get('value')} pp" for c in pos_contrib],
                ["Contribution arithmetic depends on correct constant-price weights and revisions."],
                "Positive value-added growth in a component adds percentage points to total GDP growth.",
                "same quarter",
                ["component definition", "chain-weighting", "revision status"],
                ["Recompute contributions using revised GDP vintage.", "Verify component coverage."],
            )

        if neg_contrib:
            add(
                "H-GDP-SECTOR-DRAG",
                "Some sectors may have subtracted from growth.",
                "growth",
                [f"{c.get('name')}: {c.get('value')} pp" for c in neg_contrib],
                ["Small negative contributions may be noise or timing effects."],
                "Negative value-added growth in a component subtracts percentage points from total GDP growth.",
                "same quarter",
                ["industrial volatility", "inventory adjustment", "measurement error"],
                ["Check industrial production, orders, and capacity utilization.", "Compare with independent proxy data."],
            )

        add(
            "H-GDP-EXTERNAL-DEMAND",
            "External demand may be contributing to growth.",
            "growth",
            ["Requires export volume and global demand data."],
            ["No export decomposition supplied in this minimal run."],
            "Higher foreign demand can raise exports and domestic production.",
            "1-3 quarters",
            ["global slowdown", "terms of trade", "FX", "shipping bottlenecks"],
            ["Retrieve export volume, not just value.", "Check destination-country demand."],
        )

        add(
            "H-GDP-BASE-EFFECT",
            "Base effects may distort the headline YoY growth rate.",
            "growth",
            ["YoY comparisons are sensitive to prior-period weakness or strength."],
            ["No prior-year quarterly path fully supplied."],
            "An unusual denominator can make current growth look stronger or weaker.",
            "immediate",
            ["prior shock", "reopening effects", "statistical discontinuity"],
            ["Inspect two-year compound growth.", "Compare sequential and annualized rates."],
        )

        if gdp.get("revision_status") in {"PRELIMINARY", "PROVISIONAL"}:
            add(
                "H-GDP-REVISION-RISK",
                "Preliminary data may be revised materially.",
                "growth",
                [f"Latest revision status: {gdp.get('revision_status')}"],
                ["Revision size is unknown until next vintage."],
                "Initial estimates use partial source data and can change.",
                "next release",
                ["missing administrative data", "benchmark revision"],
                ["Wait for revised vintage before structural conclusions."],
            )

        if any(p.get("status") == "IMPLEMENTED" for p in policies) and "rate" in questions_text:
            add(
                "H-GDP-POLICY-EASING-CANDIDATE",
                "Implemented monetary easing may support demand, but causality is not established.",
                "growth",
                ["A policy rate change is recorded as implemented."],
                ["Timing alone does not prove causation.", "Transmission can be weak or lagged."],
                "Lower policy rates may reduce borrowing costs if bank and market transmission works.",
                "2-8 quarters",
                ["credit conditions", "bank balance-sheet constraints", "confidence", "fiscal policy", "external demand"],
                ["Check loan growth, credit spreads, mortgage rates, and business investment.", "Compare with unaffected regions/sectors."],
            )

    cpi = find_summary(summaries, "cpi") or find_summary(summaries, "inflation")
    if cpi and cpi.get("yoy_pct_change") is not None:
        inf = cpi["yoy_pct_change"]
        add(
            "H-INFLATION-FOOD-ENERGY",
            "Food and/or energy prices may be driving headline inflation.",
            "inflation",
            [f"Headline CPI YoY: {inf}%"],
            ["Need food/energy/core decomposition."],
            "Volatile components can move headline inflation independently of core demand pressure.",
            "0-2 quarters",
            ["weather", "global commodity prices", "subsidies", "tax changes"],
            ["Compare headline, core, food, and energy inflation.", "Check import price pass-through."],
        )

        add(
            "H-INFLATION-BASE-EFFECT",
            "Base effects may explain part of the inflation change.",
            "inflation",
            ["YoY inflation depends on prior-year price level."],
            ["No full monthly/quarterly price path supplied."],
            "A sharp prior-year price move can make current YoY inflation fall or rise mechanically.",
            "immediate",
            ["energy shock normalization", "temporary tax cuts"],
            ["Inspect monthly CPI contributions and two-year compound inflation."],
        )

        add(
            "H-INFLATION-DEMAND",
            "Demand pressure may be contributing to inflation.",
            "inflation",
            ["Requires core/services inflation, wage growth, capacity utilization."],
            ["Headline CPI alone cannot prove demand pressure."],
            "Strong demand relative to capacity can raise services and goods prices.",
            "1-4 quarters",
            ["supply shocks", "import prices", "profit margins", "expectations"],
            ["Check services inflation, wage growth, vacancies, and capacity utilization."],
        )

        add(
            "H-INFLATION-FX-IMPORTS",
            "Exchange-rate depreciation may raise imported inflation.",
            "inflation",
            ["Requires FX and import-price data."],
            ["Pass-through varies by contracts, hedging, subsidies, and competition."],
            "Weaker currency can raise import prices, which may feed domestic CPI.",
            "1-4 quarters",
            ["global disinflation", "pricing-to-market", "inventories"],
            ["Check import price index and exporter currency invoicing."],
        )

    if contradictions:
        add(
            "H-CONTRADICTION-REAL-DIVERGENCE",
            "Indicator divergence may reflect real sectoral/timing differences rather than error.",
            "validation",
            [c.get("description") for c in contradictions],
            ["Could also reflect measurement, revision, or seasonal-adjustment artifacts."],
            "Different indicators measure different populations, frequencies, and concepts.",
            "variable",
            ["hard data vs survey", "sector mix", "inventory cycle"],
            ["Compare vintage, seasonality, and definitions before forcing reconciliation."],
        )

    return hypotheses


def falsification_results(hypotheses, fg):
    tests = []

    for h in hypotheses:
        for t in h.get("falsification_tests", []):
            tests.append({
                "hypothesis_id": h.get("hypothesis_id"),
                "test": t,
                "status": "PENDING",
            })

    generic = [
        "Could nominal growth be mistaken for real growth?",
        "Could base effects explain the headline change?",
        "Could a preliminary revision change the conclusion?",
        "Could survey sentiment diverge from hard output data?",
        "Could policy timing be too recent for causal effect?",
        "Could sector concentration hide weakness elsewhere?",
        "Could multiple sources share the same official release and therefore not be independent?",
    ]

    if fg.get("policy_blocked"):
        generic.append("Remove any offensive action recommendation; retain only lawful resilience analysis.")

    for t in generic:
        tests.append({"hypothesis_id": "GENERIC", "test": t, "status": "PENDING"})

    return tests


def dual_ai_review(case, summaries, calcs, fg, hypotheses, contradictions):
    primary = {
        "role": "Primary Economic Analyst",
        "summary": (
            f"Reviewed {len(summaries)} indicator summaries, {len(calcs)} deterministic calculations, "
            f"{len(hypotheses)} causal/context hypotheses."
        ),
    }

    checks = []

    if fg.get("policy_blocked"):
        checks.append("Policy-blocked request detected; no offensive market/evasion/sabotage guidance allowed.")

    if any(s.get("price_basis") == "UNKNOWN" for s in summaries):
        checks.append("Some observations lack nominal/real basis.")

    if any(s.get("seasonal_adjustment") == "UNKNOWN" for s in summaries):
        checks.append("Some observations lack seasonal-adjustment status.")

    if any(s.get("revision_status") in {"PRELIMINARY", "PROVISIONAL"} for s in summaries):
        checks.append("Preliminary/provisional data present; revision risk is material.")

    if contradictions:
        checks.append("Cross-indicator contradictions require reconciliation or explicit acceptance as real divergence.")

    if contains_any(" ".join(case.get("questions") or []), CAUSAL_TRIGGER_WORDS):
        checks.append("Causal question detected; timing alone is insufficient.")

    if not calcs:
        checks.append("No deterministic calculations were produced.")

    if any(not f.get("assumptions") for f in (case.get("forecasts") or [])):
        checks.append("Forecast assumptions missing in at least one forecast.")

    if any(h.get("status") == "CANDIDATE_NOT_PROVEN" for h in hypotheses):
        checks.append("Hypotheses remain candidate explanations, not proven causes.")

    if checks:
        if any("Policy-blocked" in c or "missing" in c.lower() for c in checks):
            agreement = "INSUFFICIENT_EVIDENCE"
        else:
            agreement = "PARTIAL_AGREEMENT"
    else:
        agreement = "AGREE"

    return {
        "primary": primary,
        "skeptic": {
            "role": "Independent Economic Skeptic",
            "checks": checks,
        },
        "agreement": agreement,
        "note": "AI agreement is not independent economic corroboration.",
    }


# ----------------------------------------------------------------------
# Graphical memory
# ----------------------------------------------------------------------

def build_graph(case, indicators, evidences, summaries, calcs, policies, forecasts, contradictions, hypotheses, fg):
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

    add_node("Country:" + norm_text(case.get("scope", {}).get("country", "UNKNOWN")), "Country", {
        "name": case.get("scope", {}).get("country", "UNKNOWN")
    })

    for e in evidences:
        add_node(e["evidence_id"], "Evidence", {
            "source_id": e.get("source_id"),
            "source_type": e.get("source_type"),
            "reliability": e.get("reliability"),
            "release_date": e.get("release_date"),
            "vintage_date": e.get("vintage_date"),
            "revision_status": e.get("revision_status"),
            "pedigree": e.get("pedigree"),
        })

    for ind in indicators:
        add_node(ind["indicator_id"], "Indicator", {
            "name": ind.get("name"),
            "definition": ind.get("definition"),
            "geography": ind.get("geography"),
            "sector": ind.get("sector"),
            "frequency": ind.get("frequency"),
            "unit": ind.get("unit"),
            "price_basis": ind.get("price_basis"),
            "seasonal_adjustment": ind.get("seasonal_adjustment"),
            "measure_type": ind.get("measure_type"),
        })

        add_edge("Country:" + norm_text(ind.get("geography", "UNKNOWN")), "MEASURES", ind["indicator_id"], {
            "note": "Geographic measurement relationship."
        })

        for o in ind.get("observations", []):
            oid = "OBS-" + sha(ind["indicator_id"] + str(o.get("period")))
            add_node(oid, "Observation", {
                "indicator_id": ind["indicator_id"],
                "period": o.get("period"),
                "value": o.get("value"),
                "unit": o.get("unit"),
                "price_basis": o.get("price_basis"),
                "seasonal_adjustment": o.get("seasonal_adjustment"),
                "revision_status": o.get("revision_status"),
            })
            add_edge(ind["indicator_id"], "HAS_OBSERVATION", oid)
            if o.get("evidence_id"):
                add_edge(oid, "SUPPORTED_BY", o["evidence_id"])

    for s in summaries:
        sid = "SUM-" + sha(s.get("indicator_id", "") + str(s.get("latest_period")))
        add_node(sid, "IndicatorSummary", s)
        add_edge(s.get("indicator_id"), "SUMMARIZED_AS", sid)

    for c in calcs:
        cid = "CALC-" + sha(str(c.get("name")) + str(c.get("value")) + str(c.get("period")))
        add_node(cid, "Calculation", c)
        for ev in c.get("evidence_ids", []):
            add_edge(cid, "SUPPORTED_BY", ev)

    for p in policies:
        pid = p.get("policy_id")
        add_node(pid, "Policy", {
            "name": p.get("name"),
            "status": p.get("status"),
            "announcement_date": p.get("announcement_date"),
            "effective_date": p.get("effective_date"),
            "effect": p.get("effect"),
        })
        if p.get("evidence_id"):
            add_edge(pid, "SUPPORTED_BY", p["evidence_id"])

    for f in forecasts:
        fid = f.get("forecast_id")
        add_node(fid, "Forecast", {
            "scenario": f.get("scenario"),
            "indicator": f.get("indicator"),
            "period": f.get("period"),
            "value": f.get("value"),
            "range": f.get("range"),
            "assumptions": f.get("assumptions"),
            "assessment_status": f.get("assessment_status"),
        })
        if f.get("evidence_id"):
            add_edge(fid, "SUPPORTED_BY", f["evidence_id"])

    for con in contradictions:
        cid = "CONTRA-" + sha(con.get("type", "") + con.get("description", ""))
        add_node(cid, "Contradiction", con)

    for h in hypotheses:
        hid = h.get("hypothesis_id")
        add_node(hid, "Hypothesis", {
            "statement": h.get("statement"),
            "domain": h.get("domain"),
            "status": h.get("status"),
            "mechanism": h.get("mechanism"),
        })

    for fact in fg.get("candidate_facts", [])[:100]:
        fid = "FACT-" + sha(json.dumps(fact, sort_keys=True, default=str))
        add_node(fid, "Fact", fact)
        for ev in fact.get("evidence_ids", []):
            add_edge(fid, "SUPPORTED_BY", ev)

    return {"nodes": nodes, "edges": edges}


# ----------------------------------------------------------------------
# Gaps, actions, handoffs
# ----------------------------------------------------------------------

def knowledge_gaps(fg, indicators, policies, forecasts, contradictions):
    gaps = []

    for u in fg.get("unknowns", []):
        gaps.append({
            "gap": u,
            "importance": "MEDIUM",
            "recommended_source": "official_release_or_register",
            "expected_information_value": "Clarifies status/effect.",
        })

    for ind in indicators:
        if ind.get("sector") == "UNKNOWN":
            gaps.append({
                "gap": f"{ind.get('indicator_id')}: sector resolution missing.",
                "importance": "MEDIUM",
                "recommended_source": "statistical_classification",
                "expected_information_value": "Improves comparability and decomposition.",
            })

        for o in ind.get("observations", []):
            if o.get("price_basis") == "UNKNOWN":
                gaps.append({
                    "gap": f"{ind.get('indicator_id')}@{o.get('period')}: nominal/real basis unknown.",
                    "importance": "HIGH",
                    "recommended_source": "methodology_note",
                    "expected_information_value": "Prevents nominal/real confusion.",
                })

    for p in policies:
        if p.get("status") in {"ANNOUNCED", "LEGISLATED", "FUNDED"}:
            gaps.append({
                "gap": f"{p.get('policy_id')}: implementation and economic effect unknown.",
                "importance": "HIGH",
                "recommended_source": "official_implementation_record",
                "expected_information_value": "Separates announcement from realized policy.",
            })

    for f in forecasts:
        if not f.get("assumptions"):
            gaps.append({
                "gap": f"{f.get('forecast_id')}: forecast assumptions missing.",
                "importance": "HIGH",
                "recommended_source": "forecast_model_documentation",
                "expected_information_value": "Makes forecast testable.",
            })

    for c in contradictions:
        gaps.append({
            "gap": f"Contradiction {c.get('type')} requires reconciliation or acceptance as real divergence.",
            "importance": "MEDIUM",
            "recommended_source": "independent_hard_data_and_survey",
            "expected_information_value": "Reduces false single-factor narrative.",
        })

    return gaps


def next_best_actions(fg, gaps, indicators, policies, forecasts):
    actions = []

    if fg.get("policy_blocked"):
        return [
            "Continue lawful defensive/resilience analysis only.",
            "Route sanctions/legal boundary questions to SANCTIONSINT and LEGALINT.",
            "Do not provide evasion, manipulation, sabotage, or market-panic recommendations.",
        ]

    if any(g.get("importance") == "HIGH" and "nominal/real" in g.get("gap", "") for g in gaps):
        actions.append("Verify nominal vs real basis and price index base year before comparing growth or purchasing power.")

    if any("revision" in g.get("gap", "").lower() or "preliminary" in g.get("gap", "").lower() for g in gaps):
        actions.append("Monitor the next official revision vintage before promoting preliminary results to structural conclusions.")

    if any("implementation" in g.get("gap", "").lower() for g in gaps):
        actions.append("Verify policy implementation, funding, disbursement, and effective dates.")

    if any("assumptions" in g.get("gap", "").lower() for g in gaps):
        actions.append("Document forecast assumptions, horizons, ranges, and model sources.")

    if any("Contradiction" in g.get("gap", "") for g in gaps):
        actions.append("Reconcile hard data, survey data, sector mix, and timing differences.")

    if not actions:
        actions.append("Refresh latest official releases and cross-check independent sources.")

    return list(dict.fromkeys(actions))


def specialist_handoffs(case, policies, contradictions):
    handoffs = []
    text = " ".join([case.get("objective", "")] + [str(q) for q in (case.get("questions") or [])]).lower()

    if contains_any(text, ["sanction", "restriction", "export control"]):
        handoffs.append({
            "to": "SANCTIONSINT",
            "reason": "Legal listing/restriction status; ECONINT only analyzes lawful economic effects, not evasion.",
        })

    if contains_any(text, ["company", "firm", "corporate", "bank"]):
        handoffs.append({"to": "CORPINT", "reason": "Entity resolution and corporate identity."})
        handoffs.append({"to": "FININT", "reason": "Company financial-flow analysis."})

    if contains_any(text, ["trade", "export", "import", "tariff", "customs"]):
        handoffs.append({"to": "TRADEINT", "reason": "Shipment/import-export relationship evidence."})

    if contains_any(text, ["supply chain", "supplier", "vendor", "logistics"]):
        handoffs.append({"to": "SUPPLYCHAININT", "reason": "Entity-level dependency graph."})

    if contains_any(text, ["law", "legal", "regulation", "policy effect"]):
        handoffs.append({"to": "LEGALINT", "reason": "Legal interpretation and policy-effect boundaries."})

    if contains_any(text, ["paper", "study", "academic", "model estimate"]):
        handoffs.append({"to": "ACADEMICINT", "reason": "Literature and methodology review."})

    if contains_any(text, ["energy", "grid", "infrastructure", "port", "rail"]):
        handoffs.append({"to": "INFRAINT", "reason": "Infrastructure context and physical-system limits."})

    if contradictions:
        handoffs.append({"to": "ECONINT_MANAGER", "reason": "Human review of contradictory indicators before high-stakes use."})

    return handoffs


# ----------------------------------------------------------------------
# Jarvis brief and report rendering
# ----------------------------------------------------------------------

def fmt(value):
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.2f}"
    return str(value)


def jarvis_brief(result):
    summaries = result.get("summaries", [])
    fg = result.get("fact_gate", {})

    gdp = find_summary(summaries, "gdp") or find_summary(summaries, "gross domestic product")
    cpi = find_summary(summaries, "cpi") or find_summary(summaries, "inflation")
    unemp = find_summary(summaries, "unemployment")

    parts = []

    if fg.get("policy_blocked"):
        parts.append("POLICY_BLOCKED: offensive economic-action request refused. Defensive/resilience analysis only.")

    if gdp:
        parts.append(f"GDP YoY: {fmt(gdp.get('yoy_pct_change'))}{gdp.get('yoy_unit', '%')}.")
    if cpi:
        parts.append(f"CPI YoY: {fmt(cpi.get('yoy_pct_change'))}{cpi.get('yoy_unit', '%')}.")
    if unemp:
        parts.append(f"Unemployment: {fmt(unemp.get('latest_value'))}{unemp.get('unit', '%')}.")

    parts.append(f"Fact gate pass: {fg.get('pass')}.")
    parts.append("No causation, market-action, evasion, or sabotage conclusion issued.")

    return " ".join(parts)


def render_markdown(result):
    out = []
    fg = result.get("fact_gate", {})
    dq = result.get("data_quality", {})
    si = result.get("source_independence", {})
    dual = result.get("dual_ai", {})

    out.append(f"# ECONINT Report — {result.get('case_id', 'CASE')}")
    out.append(f"Mode: {result.get('mode')} | As of: {result.get('as_of')} | Engine: {VERSION}")
    out.append("")

    out.append("## JARVIS Brief")
    out.append(result.get("jarvis_brief", ""))
    out.append("")

    out.append("## Policy / Safety Status")
    if fg.get("policy_blocked"):
        out.append("- POLICY_BLOCKED: prohibited economic-action request detected.")
        out.append("- Allowed output limited to lawful defensive/resilience intelligence.")
    else:
        out.append("- No prohibited economic-action request detected.")
    out.append("")

    out.append("## Objective")
    out.append(str(result.get("objective", "")))
    out.append("")

    out.append("## Questions")
    for q in result.get("questions", []):
        out.append(f"- {q}")
    out.append("")

    out.append("## Economic Snapshot")
    for s in result.get("summaries", []):
        out.append(f"### {s.get('name')} ({s.get('indicator_id')})")
        out.append(f"- Latest period: `{s.get('latest_period')}`")
        out.append(f"- Latest value: `{fmt(s.get('latest_value'))} {s.get('unit') or ''}`")
        out.append(f"- Price basis: `{s.get('price_basis')}`")
        out.append(f"- Seasonal adjustment: `{s.get('seasonal_adjustment')}`")
        out.append(f"- Revision status: `{s.get('revision_status')}`")
        if s.get("yoy_pct_change") is not None:
            out.append(f"- YoY percent change: `{fmt(s.get('yoy_pct_change'))}%`")
        if s.get("yoy_pp_change") is not None:
            out.append(f"- YoY pp change: `{fmt(s.get('yoy_pp_change'))} pp`")
        if s.get("qoq_annualized_pct") is not None:
            out.append(f"- QoQ annualized: `{fmt(s.get('qoq_annualized_pct'))}%`")
        out.append(f"- Evidence ids: `{s.get('evidence_ids', [])}`")
        out.append("")

    out.append("## Deterministic Calculations")
    for c in result.get("calculations", []):
        out.append(f"- {c.get('name')}: `{fmt(c.get('value'))} {c.get('unit') or ''}` | formula: `{c.get('formula')}`")
    out.append("")

    out.append("## Policies")
    for p in result.get("policies", []):
        out.append(f"- `{p.get('policy_id')}` {p.get('name')}: status=`{p.get('status')}`, effective=`{p.get('effective_date')}`, effect=`{p.get('effect')}`")
    out.append("")

    out.append("## Forecasts")
    for f in result.get("forecasts", []):
        out.append(f"- `{f.get('forecast_id')}` scenario=`{f.get('scenario')}` indicator=`{f.get('indicator')}` period=`{f.get('period')}` value=`{fmt(f.get('value'))}` range=`{f.get('range')}`")
        out.append(f"  - assumptions: `{f.get('assumptions')}`")
        out.append(f"  - status: `{f.get('assessment_status')}`")
    out.append("")

    out.append("## Scenarios")
    for s in result.get("scenarios", []):
        out.append(f"- `{s.get('scenario_id')}` {s.get('name')} type=`{s.get('type')}` assumptions=`{s.get('assumptions')}`")
    out.append("")

    out.append("## Contradictions")
    if not result.get("contradictions"):
        out.append("- None detected by built-in cross-checks.")
    for c in result.get("contradictions", []):
        out.append(f"- {c.get('type')}: {c.get('description')}")
        out.append(f"  - interpretation: {c.get('interpretation')}")
    out.append("")

    out.append("## Data Quality")
    out.append("```json")
    out.append(json.dumps(dq, indent=2, default=str))
    out.append("```")
    out.append("")

    out.append("## Fact Gate")
    out.append(f"Pass: `{fg.get('pass')}`")
    out.append(f"Policy blocked: `{fg.get('policy_blocked')}`")
    for issue in fg.get("issues", []):
        out.append(f"- [{issue.get('severity')}] {issue.get('message')}")
    out.append("")

    out.append("## Candidate Facts")
    for fact in fg.get("candidate_facts", [])[:40]:
        out.append(f"- {fact.get('type')}/{fact.get('subtype', '')}: `{fact.get('value')} {fact.get('unit') or ''}` status=`{fact.get('assessment_status')}`")
    out.append("")

    out.append("## Hypotheses")
    for h in result.get("hypotheses", []):
        out.append(f"### {h.get('hypothesis_id')} — {h.get('statement')}")
        out.append(f"- Domain: `{h.get('domain')}`")
        out.append(f"- Status: `{h.get('status')}`")
        out.append(f"- Mechanism: `{h.get('mechanism')}`")
        out.append(f"- Lag: `{h.get('lag')}`")
        out.append("- Support:")
        for x in h.get("support", []):
            out.append(f"  - {x}")
        out.append("- Opposition / caveats:")
        for x in h.get("opposition", []):
            out.append(f"  - {x}")
        out.append("- Confounders:")
        for x in h.get("confounders", []):
            out.append(f"  - {x}")
        out.append("- Falsification tests:")
        for x in h.get("falsification_tests", []):
            out.append(f"  - {x}")
        out.append("")

    out.append("## Falsification Queue")
    for t in result.get("falsification_results", [])[:40]:
        out.append(f"- [{t.get('hypothesis_id')}] {t.get('test')}")
    out.append("")

    out.append("## Dual-AI Review")
    out.append(f"Agreement: `{dual.get('agreement')}`")
    out.append(f"Primary: `{dual.get('primary', {}).get('summary')}`")
    for c in dual.get("skeptic", {}).get("checks", []):
        out.append(f"- Skeptic: {c}")
    out.append("")

    out.append("## Source Independence")
    out.append("```json")
    out.append(json.dumps(si.get("by_root", {}), indent=2, default=str))
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

class ECONINTAgent:
    def __init__(self, mode="LOCAL_ONLY", authorized_source_types=None):
        if mode not in MODES:
            raise ValueError(f"mode must be one of {sorted(MODES)}")
        self.mode = mode
        self.authorized_source_types = authorized_source_types or [
            "official_statistical_office",
            "central_bank",
            "finance_ministry",
            "treasury_department",
            "budget_office",
            "customs_authority",
            "labor_ministry",
            "industry_ministry",
            "multilateral_institution",
            "development_bank",
            "official_trade_database",
            "official_energy_statistics",
            "official_agriculture_statistics",
            "official_price_index",
            "company_filing",
            "industry_association",
            "authorized_commercial_economic_dataset",
            "authorized_market_dataset",
            "academic_research",
            "survey_provider",
        ]

    def analyze(self, case):
        case = dict(case or {})
        case.setdefault("mode", self.mode)
        as_of = case.get("as_of") or now()

        evidences = [normalize_evidence(e, self.authorized_source_types) for e in case.get("evidences", []) or []]
        indicators = [normalize_indicator(i) for i in case.get("indicators", []) or []]

        summaries = [summarize_indicator(i) for i in indicators]
        calcs = run_calculations(case, indicators, summaries)
        policies = normalize_policies(case)
        forecasts = normalize_forecasts(case)
        scenarios = normalize_scenarios(case)

        contradictions = cross_validate(summaries)
        dq = assess_data_quality(indicators, evidences, as_of)

        fg = fact_gate(
            case=case,
            indicators=indicators,
            evidences=evidences,
            summaries=summaries,
            calcs=calcs,
            policies=policies,
            forecasts=forecasts,
            contradictions=contradictions,
            data_quality=dq,
        )

        hypotheses = generate_hypotheses(case, summaries, calcs, contradictions, fg, policies)
        falsification = falsification_results(hypotheses, fg)
        dual = dual_ai_review(case, summaries, calcs, fg, hypotheses, contradictions)
        graph = build_graph(case, indicators, evidences, summaries, calcs, policies, forecasts, contradictions, hypotheses, fg)

        gaps = knowledge_gaps(fg, indicators, policies, forecasts, contradictions)
        actions = next_best_actions(fg, gaps, indicators, policies, forecasts)
        handoffs = specialist_handoffs(case, policies, contradictions)

        result = {
            "case_id": case.get("case_id"),
            "task_id": case.get("task_id"),
            "objective": case.get("objective"),
            "questions": case.get("questions") or [],
            "mode": case.get("mode"),
            "as_of": as_of,
            "scope": case.get("scope", {}),
            "evidences": [{k: v for k, v in e.items() if k != "content"} for e in evidences],
            "indicators": indicators,
            "summaries": summaries,
            "calculations": calcs,
            "policies": policies,
            "forecasts": forecasts,
            "scenarios": scenarios,
            "contradictions": contradictions,
            "data_quality": dq,
            "fact_gate": fg,
            "hypotheses": hypotheses,
            "falsification_results": falsification,
            "dual_ai": dual,
            "graph": graph,
            "source_independence": source_independence(evidences),
            "knowledge_gaps": gaps,
            "recommended_next_actions": actions,
            "specialist_handoffs": handoffs,
            "limitations": LIMITATIONS.copy(),
            "replay_manifest": {
                "engine_version": VERSION,
                "as_of": as_of,
                "pipeline": [
                    "normalize_evidence",
                    "normalize_indicator",
                    "summarize_indicator",
                    "deterministic_calculations",
                    "cross_validate",
                    "data_quality",
                    "fact_gate",
                    "hypotheses",
                    "falsification",
                    "dual_ai",
                    "graph",
                    "report",
                ],
                "evidence_hashes": {e["evidence_id"]: e["content_hash"] for e in evidences},
                "indicator_vintages": {
                    ind["indicator_id"]: [
                        {
                            "period": o.get("period"),
                            "value": o.get("value"),
                            "revision_status": o.get("revision_status"),
                            "price_basis": o.get("price_basis"),
                            "seasonal_adjustment": o.get("seasonal_adjustment"),
                            "evidence_id": o.get("evidence_id"),
                        }
                        for o in ind.get("observations", [])
                    ]
                    for ind in indicators
                },
                "calculation_formulas": {
                    c.get("name"): c.get("formula")
                    for c in calcs
                    if c.get("formula")
                },
                "source_pedigree": {
                    e["evidence_id"]: e.get("pedigree")
                    for e in evidences
                },
                "policy_blocked": fg.get("policy_blocked"),
            },
        }

        result["jarvis_brief"] = jarvis_brief(result)
        return result


# ----------------------------------------------------------------------
# Demo
# ----------------------------------------------------------------------

if __name__ == "__main__":
    # Evidence register
    e_gdp_prev = make_evidence(
        "NSO-GDP-2025Q2",
        "official_statistical_office",
        "CountryX real GDP level 2025-Q2 = 100.1, index 2020=100, seasonally adjusted, chain-volume, final.",
        geography="CountryX",
        sector="TOTAL",
        indicator_id="GDP_REAL_LEVEL",
        period="2025-Q2",
        release_date="2025-08-15",
        vintage_date="2025-08-15",
        revision_status="FINAL",
        unit="index 2020=100",
        price_basis="REAL",
        seasonal_adjustment="SA",
        methodology_reference="chain-weighted volume, 2020 base",
        raw_value=100.1,
        normalized_value=100.1,
        pedigree=["NSO"],
    )

    e_gdp_q1 = make_evidence(
        "NSO-GDP-2026Q1",
        "official_statistical_office",
        "CountryX real GDP level 2026-Q1 = 104.5, index 2020=100, seasonally adjusted, revised.",
        geography="CountryX",
        sector="TOTAL",
        indicator_id="GDP_REAL_LEVEL",
        period="2026-Q1",
        release_date="2026-05-15",
        vintage_date="2026-06-01",
        revision_status="REVISED",
        unit="index 2020=100",
        price_basis="REAL",
        seasonal_adjustment="SA",
        methodology_reference="chain-weighted volume, 2020 base",
        raw_value=104.5,
        normalized_value=104.5,
        pedigree=["NSO"],
    )

    e_gdp = make_evidence(
        "NSO-GDP-2026Q2",
        "official_statistical_office",
        "CountryX real GDP level 2026-Q2 = 105.2, index 2020=100, seasonally adjusted, preliminary.",
        geography="CountryX",
        sector="TOTAL",
        indicator_id="GDP_REAL_LEVEL",
        period="2026-Q2",
        release_date="2026-08-15",
        vintage_date="2026-08-15",
        revision_status="PRELIMINARY",
        unit="index 2020=100",
        price_basis="REAL",
        seasonal_adjustment="SA",
        methodology_reference="chain-weighted volume, 2020 base",
        raw_value=105.2,
        normalized_value=105.2,
        pedigree=["NSO"],
    )

    e_ip_prev = make_evidence(
        "NSO-IP-2025Q2",
        "official_statistical_office",
        "CountryX industrial production level 2025-Q2 = 101.0, index 2020=100, SA, final.",
        geography="CountryX",
        sector="INDUSTRY",
        indicator_id="INDUSTRIAL_PRODUCTION_LEVEL",
        period="2025-Q2",
        release_date="2025-07-31",
        vintage_date="2025-07-31",
        revision_status="FINAL",
        unit="index 2020=100",
        price_basis="REAL",
        seasonal_adjustment="SA",
        methodology_reference="volume index",
        raw_value=101.0,
        normalized_value=101.0,
        pedigree=["NSO"],
    )

    e_ip = make_evidence(
        "NSO-IP-2026Q2",
        "official_statistical_office",
        "CountryX industrial production level 2026-Q2 = 99.0, index 2020=100, SA, provisional.",
        geography="CountryX",
        sector="INDUSTRY",
        indicator_id="INDUSTRIAL_PRODUCTION_LEVEL",
        period="2026-Q2",
        release_date="2026-08-01",
        vintage_date="2026-08-01",
        revision_status="PROVISIONAL",
        unit="index 2020=100",
        price_basis="REAL",
        seasonal_adjustment="SA",
        methodology_reference="volume index",
        raw_value=99.0,
        normalized_value=99.0,
        pedigree=["NSO"],
    )

    e_cpi_prev = make_evidence(
        "NSO-CPI-2025Q2",
        "official_statistical_office",
        "CountryX CPI index 2025-Q2 = 110.0, 2020=100, final.",
        geography="CountryX",
        sector="HOUSEHOLD",
        indicator_id="CPI_INDEX",
        period="2025-Q2",
        release_date="2025-07-10",
        vintage_date="2025-07-10",
        revision_status="FINAL",
        unit="index 2020=100",
        price_basis="NOMINAL",
        seasonal_adjustment="NSA",
        methodology_reference="fixed-basket CPI",
        raw_value=110.0,
        normalized_value=110.0,
        pedigree=["NSO"],
    )

    e_cpi = make_evidence(
        "NSO-CPI-2026Q2",
        "official_statistical_office",
        "CountryX CPI index 2026-Q2 = 113.52, 2020=100, revised.",
        geography="CountryX",
        sector="HOUSEHOLD",
        indicator_id="CPI_INDEX",
        period="2026-Q2",
        release_date="2026-07-10",
        vintage_date="2026-07-20",
        revision_status="REVISED",
        unit="index 2020=100",
        price_basis="NOMINAL",
        seasonal_adjustment="NSA",
        methodology_reference="fixed-basket CPI",
        raw_value=113.52,
        normalized_value=113.52,
        pedigree=["NSO"],
    )

    e_unemp_prev = make_evidence(
        "LAB-UNEMP-2025Q2",
        "labor_ministry",
        "CountryX unemployment rate 2025-Q2 = 6.0%, labor force survey, final.",
        geography="CountryX",
        sector="LABOR",
        indicator_id="UNEMPLOYMENT_RATE",
        period="2025-Q2",
        release_date="2025-07-15",
        vintage_date="2025-07-15",
        revision_status="FINAL",
        unit="%",
        price_basis="N/A",
        seasonal_adjustment="SA",
        methodology_reference="household labor survey",
        raw_value=6.0,
        normalized_value=6.0,
        pedigree=["LABOR_MINISTRY"],
    )

    e_unemp = make_evidence(
        "LAB-UNEMP-2026Q2",
        "labor_ministry",
        "CountryX unemployment rate 2026-Q2 = 5.8%, labor force survey, preliminary.",
        geography="CountryX",
        sector="LABOR",
        indicator_id="UNEMPLOYMENT_RATE",
        period="2026-Q2",
        release_date="2026-07-15",
        vintage_date="2026-07-15",
        revision_status="PRELIMINARY",
        unit="%",
        price_basis="N/A",
        seasonal_adjustment="SA",
        methodology_reference="household labor survey",
        raw_value=5.8,
        normalized_value=5.8,
        pedigree=["LABOR_MINISTRY"],
    )

    e_lfp_prev = make_evidence(
        "LAB-LFP-2025Q2",
        "labor_ministry",
        "CountryX labor force participation 2025-Q2 = 62.5%, final.",
        geography="CountryX",
        sector="LABOR",
        indicator_id="LABOR_FORCE_PARTICIPATION_RATE",
        period="2025-Q2",
        release_date="2025-07-15",
        vintage_date="2025-07-15",
        revision_status="FINAL",
        unit="%",
        price_basis="N/A",
        seasonal_adjustment="SA",
        methodology_reference="household labor survey",
        raw_value=62.5,
        normalized_value=62.5,
        pedigree=["LABOR_MINISTRY"],
    )

    e_lfp = make_evidence(
        "LAB-LFP-2026Q2",
        "labor_ministry",
        "CountryX labor force participation 2026-Q2 = 62.1%, preliminary.",
        geography="CountryX",
        sector="LABOR",
        indicator_id="LABOR_FORCE_PARTICIPATION_RATE",
        period="2026-Q2",
        release_date="2026-07-15",
        vintage_date="2026-07-15",
        revision_status="PRELIMINARY",
        unit="%",
        price_basis="N/A",
        seasonal_adjustment="SA",
        methodology_reference="household labor survey",
        raw_value=62.1,
        normalized_value=62.1,
        pedigree=["LABOR_MINISTRY"],
    )

    e_policy_rate_prev = make_evidence(
        "CB-POLICY-2025Q2",
        "central_bank",
        "CountryX policy rate 2025-Q2 = 5.50%, implemented.",
        geography="CountryX",
        sector="MONETARY",
        indicator_id="POLICY_RATE",
        period="2025-Q2",
        release_date="2025-06-01",
        vintage_date="2025-06-01",
        revision_status="FINAL",
        unit="%",
        price_basis="N/A",
        seasonal_adjustment="N/A",
        methodology_reference="official policy rate",
        raw_value=5.50,
        normalized_value=5.50,
        pedigree=["CENTRAL_BANK"],
    )

    e_policy_rate = make_evidence(
        "CB-POLICY-2026Q2",
        "central_bank",
        "CountryX policy rate 2026-Q2 = 5.25%, implemented after 2026-06-01.",
        geography="CountryX",
        sector="MONETARY",
        indicator_id="POLICY_RATE",
        period="2026-Q2",
        release_date="2026-06-01",
        vintage_date="2026-06-01",
        revision_status="FINAL",
        unit="%",
        price_basis="N/A",
        seasonal_adjustment="N/A",
        methodology_reference="official policy rate",
        raw_value=5.25,
        normalized_value=5.25,
        pedigree=["CENTRAL_BANK"],
    )

    e_services_prev = make_evidence(
        "NSO-SVC-2025Q2",
        "official_statistical_office",
        "CountryX services GVA level 2025-Q2 = 60.0, index 2020=100, SA, final.",
        geography="CountryX",
        sector="SERVICES",
        indicator_id="SERVICES_GVA_LEVEL",
        period="2025-Q2",
        release_date="2025-08-15",
        vintage_date="2025-08-15",
        revision_status="FINAL",
        unit="index 2020=100",
        price_basis="REAL",
        seasonal_adjustment="SA",
        methodology_reference="chain-volume GVA",
        raw_value=60.0,
        normalized_value=60.0,
        pedigree=["NSO"],
    )

    e_services = make_evidence(
        "NSO-SVC-2026Q2",
        "official_statistical_office",
        "CountryX services GVA level 2026-Q2 = 63.5, index 2020=100, SA, preliminary.",
        geography="CountryX",
        sector="SERVICES",
        indicator_id="SERVICES_GVA_LEVEL",
        period="2026-Q2",
        release_date="2026-08-15",
        vintage_date="2026-08-15",
        revision_status="PRELIMINARY",
        unit="index 2020=100",
        price_basis="REAL",
        seasonal_adjustment="SA",
        methodology_reference="chain-volume GVA",
        raw_value=63.5,
        normalized_value=63.5,
        pedigree=["NSO"],
    )

    e_manuf_prev = make_evidence(
        "NSO-MAN-2025Q2",
        "official_statistical_office",
        "CountryX manufacturing GVA level 2025-Q2 = 15.0, index 2020=100, SA, final.",
        geography="CountryX",
        sector="MANUFACTURING",
        indicator_id="MANUFACTURING_GVA_LEVEL",
        period="2025-Q2",
        release_date="2025-08-15",
        vintage_date="2025-08-15",
        revision_status="FINAL",
        unit="index 2020=100",
        price_basis="REAL",
        seasonal_adjustment="SA",
        methodology_reference="chain-volume GVA",
        raw_value=15.0,
        normalized_value=15.0,
        pedigree=["NSO"],
    )

    e_manuf = make_evidence(
        "NSO-MAN-2026Q2",
        "official_statistical_office",
        "CountryX manufacturing GVA level 2026-Q2 = 14.7, index 2020=100, SA, preliminary.",
        geography="CountryX",
        sector="MANUFACTURING",
        indicator_id="MANUFACTURING_GVA_LEVEL",
        period="2026-Q2",
        release_date="2026-08-15",
        vintage_date="2026-08-15",
        revision_status="PRELIMINARY",
        unit="index 2020=100",
        price_basis="REAL",
        seasonal_adjustment="SA",
        methodology_reference="chain-volume GVA",
        raw_value=14.7,
        normalized_value=14.7,
        pedigree=["NSO"],
    )

    e_policy = make_evidence(
        "CB-POLICY-ANNOUNCE-2026",
        "central_bank",
        "CentralBankX announced policy rate cut to 5.25% on 2026-05-20, effective 2026-06-01.",
        geography="CountryX",
        sector="MONETARY",
        period="2026-Q2",
        release_date="2026-05-20",
        vintage_date="2026-05-20",
        revision_status="FINAL",
        pedigree=["CENTRAL_BANK"],
    )

    e_forecast = make_evidence(
        "FORECAST-DESK-2026Q4",
        "authorized_commercial_economic_dataset",
        "Internal consensus baseline forecast: GDP level 106.0 in 2026-Q4, range 104.5-107.5.",
        geography="CountryX",
        sector="TOTAL",
        indicator_id="GDP_REAL_LEVEL",
        period="2026-Q4",
        release_date="2026-09-01",
        vintage_date="2026-09-01",
        revision_status="PROVISIONAL",
        pedigree=["CONSENSUS_FEED"],
    )

    indicators = [
        {
            "indicator_id": "GDP_REAL_LEVEL",
            "name": "Real GDP level",
            "definition": "Chain-volume GDP index, 2020=100, seasonally adjusted.",
            "geography": "CountryX",
            "sector": "TOTAL",
            "frequency": "QUARTER",
            "unit": "index 2020=100",
            "price_basis": "REAL",
            "seasonal_adjustment": "SA",
            "base_year": "2020",
            "measure_type": "LEVEL",
            "observations": [
                {"period": "2025-Q2", "value": 100.1, "evidence_id": e_gdp_prev["evidence_id"], "revision_status": "FINAL"},
                {"period": "2026-Q1", "value": 104.5, "evidence_id": e_gdp_q1["evidence_id"], "revision_status": "REVISED"},
                {"period": "2026-Q2", "value": 105.2, "evidence_id": e_gdp["evidence_id"], "revision_status": "PRELIMINARY"},
            ],
        },
        {
            "indicator_id": "INDUSTRIAL_PRODUCTION_LEVEL",
            "name": "Industrial production level",
            "definition": "Industrial production volume index, 2020=100, seasonally adjusted.",
            "geography": "CountryX",
            "sector": "INDUSTRY",
            "frequency": "QUARTER",
            "unit": "index 2020=100",
            "price_basis": "REAL",
            "seasonal_adjustment": "SA",
            "base_year": "2020",
            "measure_type": "LEVEL",
            "observations": [
                {"period": "2025-Q2", "value": 101.0, "evidence_id": e_ip_prev["evidence_id"], "revision_status": "FINAL"},
                {"period": "2026-Q2", "value": 99.0, "evidence_id": e_ip["evidence_id"], "revision_status": "PROVISIONAL"},
            ],
        },
        {
            "indicator_id": "CPI_INDEX",
            "name": "Headline CPI index",
            "definition": "Consumer price index, 2020=100, not seasonally adjusted.",
            "geography": "CountryX",
            "sector": "HOUSEHOLD",
            "frequency": "QUARTER",
            "unit": "index 2020=100",
            "price_basis": "NOMINAL",
            "seasonal_adjustment": "NSA",
            "base_year": "2020",
            "measure_type": "INDEX",
            "observations": [
                {"period": "2025-Q2", "value": 110.0, "evidence_id": e_cpi_prev["evidence_id"], "revision_status": "FINAL"},
                {"period": "2026-Q2", "value": 113.52, "evidence_id": e_cpi["evidence_id"], "revision_status": "REVISED"},
            ],
        },
        {
            "indicator_id": "UNEMPLOYMENT_RATE",
            "name": "Unemployment rate",
            "definition": "Share of labor force unemployed, seasonally adjusted.",
            "geography": "CountryX",
            "sector": "LABOR",
            "frequency": "QUARTER",
            "unit": "%",
            "price_basis": "N/A",
            "seasonal_adjustment": "SA",
            "measure_type": "RATE",
            "observations": [
                {"period": "2025-Q2", "value": 6.0, "evidence_id": e_unemp_prev["evidence_id"], "revision_status": "FINAL"},
                {"period": "2026-Q2", "value": 5.8, "evidence_id": e_unemp["evidence_id"], "revision_status": "PRELIMINARY"},
            ],
        },
        {
            "indicator_id": "LABOR_FORCE_PARTICIPATION_RATE",
            "name": "Labor force participation rate",
            "definition": "Share of working-age population in labor force, seasonally adjusted.",
            "geography": "CountryX",
            "sector": "LABOR",
            "frequency": "QUARTER",
            "unit": "%",
            "price_basis": "N/A",
            "seasonal_adjustment": "SA",
            "measure_type": "RATE",
            "observations": [
                {"period": "2025-Q2", "value": 62.5, "evidence_id": e_lfp_prev["evidence_id"], "revision_status": "FINAL"},
                {"period": "2026-Q2", "value": 62.1, "evidence_id": e_lfp["evidence_id"], "revision_status": "PRELIMINARY"},
            ],
        },
        {
            "indicator_id": "POLICY_RATE",
            "name": "Policy rate",
            "definition": "Central bank policy interest rate.",
            "geography": "CountryX",
            "sector": "MONETARY",
            "frequency": "QUARTER",
            "unit": "%",
            "price_basis": "N/A",
            "seasonal_adjustment": "N/A",
            "measure_type": "RATE",
            "observations": [
                {"period": "2025-Q2", "value": 5.50, "evidence_id": e_policy_rate_prev["evidence_id"], "revision_status": "FINAL"},
                {"period": "2026-Q2", "value": 5.25, "evidence_id": e_policy_rate["evidence_id"], "revision_status": "FINAL"},
            ],
        },
        {
            "indicator_id": "SERVICES_GVA_LEVEL",
            "name": "Services GVA level",
            "definition": "Services gross value added, chain-volume index, 2020=100, SA.",
            "geography": "CountryX",
            "sector": "SERVICES",
            "frequency": "QUARTER",
            "unit": "index 2020=100",
            "price_basis": "REAL",
            "seasonal_adjustment": "SA",
            "base_year": "2020",
            "measure_type": "LEVEL",
            "observations": [
                {"period": "2025-Q2", "value": 60.0, "evidence_id": e_services_prev["evidence_id"], "revision_status": "FINAL"},
                {"period": "2026-Q2", "value": 63.5, "evidence_id": e_services["evidence_id"], "revision_status": "PRELIMINARY"},
            ],
        },
        {
            "indicator_id": "MANUFACTURING_GVA_LEVEL",
            "name": "Manufacturing GVA level",
            "definition": "Manufacturing gross value added, chain-volume index, 2020=100, SA.",
            "geography": "CountryX",
            "sector": "MANUFACTURING",
            "frequency": "QUARTER",
            "unit": "index 2020=100",
            "price_basis": "REAL",
            "seasonal_adjustment": "SA",
            "base_year": "2020",
            "measure_type": "LEVEL",
            "observations": [
                {"period": "2025-Q2", "value": 15.0, "evidence_id": e_manuf_prev["evidence_id"], "revision_status": "FINAL"},
                {"period": "2026-Q2", "value": 14.7, "evidence_id": e_manuf["evidence_id"], "revision_status": "PRELIMINARY"},
            ],
        },
    ]

    case = {
        "case_id": "ECONINT-DEMO-001",
        "task_id": "T-001",
        "objective": "Assess CountryX macroeconomic state, growth drivers, inflation, labor market, policy context, and downside risks.",
        "questions": [
            "What is the current economic state?",
            "Which sectors appear to have contributed to growth?",
            "Did the policy rate cut cause the growth acceleration?",
            "What are the main contradictions and data-quality risks?",
            "What are the downside risks?",
        ],
        "scope": {
            "country": "CountryX",
            "sectors": ["TOTAL", "SERVICES", "MANUFACTURING", "LABOR", "MONETARY"],
            "time_range": "2025-Q2 to 2026-Q2",
        },
        "mode": "LOCAL_ONLY",
        "as_of": "2026-10-09",
        "evidences": [
            e_gdp_prev, e_gdp_q1, e_gdp,
            e_ip_prev, e_ip,
            e_cpi_prev, e_cpi,
            e_unemp_prev, e_unemp,
            e_lfp_prev, e_lfp,
            e_policy_rate_prev, e_policy_rate,
            e_services_prev, e_services,
            e_manuf_prev, e_manuf,
            e_policy, e_forecast,
        ],
        "indicators": indicators,
        "calculations": [
            {"type": "yoy", "indicator": "GDP_REAL_LEVEL", "period": "2026-Q2", "name": "Real GDP YoY growth"},
            {"type": "yoy", "indicator": "INDUSTRIAL_PRODUCTION_LEVEL", "period": "2026-Q2", "name": "Industrial production YoY"},
            {"type": "yoy", "indicator": "CPI_INDEX", "period": "2026-Q2", "name": "Headline CPI YoY inflation"},
            {"type": "annualized_qoq", "indicator": "GDP_REAL_LEVEL", "period": "2026-Q2", "name": "GDP QoQ annualized"},
            {
                "type": "contribution",
                "name": "Services GVA contribution to GDP",
                "total_indicator": "GDP_REAL_LEVEL",
                "component_indicator": "SERVICES_GVA_LEVEL",
                "period": "2026-Q2",
            },
            {
                "type": "contribution",
                "name": "Manufacturing GVA contribution to GDP",
                "total_indicator": "GDP_REAL_LEVEL",
                "component_indicator": "MANUFACTURING_GVA_LEVEL",
                "period": "2026-Q2",
            },
        ],
        "policies": [
            {
                "policy_id": "MON-RATE-2026-06",
                "name": "Policy rate cut to 5.25%",
                "status": "IMPLEMENTED",
                "announcement_date": "2026-05-20",
                "effective_date": "2026-06-01",
                "authority": "CentralBankX",
                "evidence_id": e_policy["evidence_id"],
            }
        ],
        "forecasts": [
            {
                "forecast_id": "FC-BASE-2026Q4",
                "scenario": "BASE",
                "indicator": "GDP_REAL_LEVEL",
                "period": "2026-Q4",
                "value": 106.0,
                "range": {"low": 104.5, "high": 107.5},
                "assumptions": [
                    "energy prices stable",
                    "policy rate unchanged",
                    "external demand moderate",
                ],
                "confidence": "MEDIUM",
                "evidence_id": e_forecast["evidence_id"],
            }
        ],
        "scenarios": [
            {
                "scenario_id": "SC-DOWNSIDE-ENERGY",
                "name": "Energy price spike",
                "type": "DOWNSIDE",
                "assumptions": [
                    "oil +30%",
                    "FX depreciates 5%",
                    "imported inflation rises",
                ],
                "affected_indicators": ["CPI_INDEX", "GDP_REAL_LEVEL"],
            }
        ],
    }

    agent = ECONINTAgent(mode="LOCAL_ONLY")
    result = agent.analyze(case)

    print(render_markdown(result))

    # Uncomment to inspect full JSON result:
    # print(json.dumps(result, indent=2, default=str))