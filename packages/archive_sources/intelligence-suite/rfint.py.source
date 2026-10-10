#!/usr/bin/env python3
"""
TRACEATLAS RFINT main.py
========================

Passive-first, authorized, defensive RF intelligence scaffold.

This module is intentionally NOT an RF scanner, NOT an SDR driver,
NOT a jammer/spoofing/injection tool, and NOT a private-person tracker.

It consumes feature-level RF evidence produced by deterministic tools:
- spectrum analyzer exports
- SDR PSD/waterfall derived events
- authorized WLAN telemetry
- authorized BLE telemetry
- public ADS-B/AIS/beacon metadata
- regulator allocation records
- authorized asset inventory correlations

The goal is to produce an evidence-linked RFINTResult with:
- sensor validation
- calibration awareness
- fact gate
- competing hypotheses
- falsification checks
- dual-AI style skeptic review
- privacy/safety flags
- knowledge gaps
- next best defensive actions
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import statistics
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

VERSION = "0.1.0"

# -----------------------------------------------------------------------------
# Policy guard
# -----------------------------------------------------------------------------

BLOCK_PHRASES = [
    "jam signal",
    "jamming waveform",
    "optimize jamming",
    "spoof gnss",
    "spoof gps",
    "spoof ads-b",
    "spoof ais",
    "spoof radio beacon",
    "spoof wireless identity",
    "deauthenticate wi-fi",
    "deauth client",
    "rogue access point",
    "evil twin",
    "packet injection",
    "rf injection",
    "imsi catcher",
    "rogue bts",
    "rogue base station",
    "capture private voice",
    "decode private message",
    "break encryption",
    "bypass wireless authentication",
    "steal wi-fi credentials",
    "brute force wireless key",
    "crack password",
    "unauthorized bluetooth attack",
    "unauthorized rfid attack",
    "nfc attack",
    "track private person",
    "home/work pattern",
    "weapon-targeting",
    "electronic attack",
    "radar defeat",
    "detection evasion",
    "covert surveillance",
]


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_dt(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def to_float(value: Any) -> Optional[float]:
    try:
        f = float(value)
        if math.isnan(f) or math.isinf(f):
            return None
        return f
    except Exception:
        return None


def public_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if not str(k).startswith("_")}


def increment(counter: Dict[Any, int], key: Any) -> None:
    if key is None:
        return
    counter[key] = counter.get(key, 0) + 1


def top_keys(counter: Dict[Any, int]) -> List[Any]:
    if not counter:
        return []
    return [k for k, _ in sorted(counter.items(), key=lambda x: x[1], reverse=True)]


def numeric_summary(values: List[Any]) -> Dict[str, Any]:
    arr: List[float] = []
    for v in values:
        f = to_float(v)
        if f is not None:
            arr.append(f)
    if not arr:
        return {"count": 0, "min": None, "max": None, "median": None}
    return {
        "count": len(arr),
        "min": min(arr),
        "max": max(arr),
        "median": statistics.median(arr),
    }


def merge_intervals(intervals: List[Tuple[datetime, datetime]]) -> List[Tuple[datetime, datetime]]:
    cleaned: List[Tuple[datetime, datetime]] = []
    for s, e in intervals:
        if s is None or e is None:
            continue
        if e <= s:
            continue
        cleaned.append((s, e))
    cleaned.sort(key=lambda x: x[0])
    merged: List[List[datetime]] = []
    for s, e in cleaned:
        if not merged or s > merged[-1][1]:
            merged.append([s, e])
        else:
            merged[-1][1] = max(merged[-1][1], e)
    return [(s, e) for s, e in merged]


def policy_block_reasons(case: Dict[str, Any]) -> List[str]:
    reasons: List[str] = []
    text = json.dumps(case, ensure_ascii=False, default=str).lower()

    for phrase in BLOCK_PHRASES:
        if phrase in text:
            reasons.append(f"Forbidden RF action/request detected: '{phrase}'")

    scope = case.get("scope") if isinstance(case.get("scope"), dict) else {}
    if scope.get("authorized_only") is not True:
        reasons.append("scope.authorized_only must be true")

    auth = case.get("authorization") if isinstance(case.get("authorization"), dict) else {}
    if not auth.get("lawful_basis"):
        reasons.append("authorization.lawful_basis is missing")
    if not auth.get("purpose"):
        reasons.append("authorization.purpose is missing")

    mode = str(case.get("model_mode", "LOCAL_ONLY")).upper()
    if mode == "CLOUD":
        for ev in case.get("evidence") or []:
            if not isinstance(ev, dict):
                continue
            if ev.get("raw_capture_reference") and not ev.get("sanitized_for_cloud"):
                reasons.append("Cloud mode detected with unsanitized raw capture reference")

    return reasons


# -----------------------------------------------------------------------------
# Validation
# -----------------------------------------------------------------------------

def validate_case(case: Dict[str, Any]) -> Tuple[
    Dict[str, Dict[str, Any]],
    Dict[str, Dict[str, Any]],
    List[Dict[str, Any]],
    List[str],
]:
    issues: List[str] = []
    sensors: Dict[str, Dict[str, Any]] = {}
    evidence: Dict[str, Dict[str, Any]] = {}
    events: List[Dict[str, Any]] = []

    for idx, s in enumerate(case.get("sensors") or []):
        if not isinstance(s, dict):
            issues.append(f"sensors[{idx}] is not an object")
            continue
        sid = s.get("sensor_id")
        if not sid:
            issues.append(f"sensors[{idx}] missing sensor_id")
            continue

        cal = s.get("calibration_state", "CALIBRATION_UNKNOWN")
        s["_calibration_state"] = cal
        s["_usable_for_measurement"] = cal not in (
            "OUT_OF_CALIBRATION",
            "UNSUITABLE_FOR_MEASUREMENT",
        )

        if not s.get("antenna"):
            issues.append(f"sensor {sid} missing antenna context")
        if not s.get("clock_source"):
            issues.append(f"sensor {sid} missing clock_source")

        sensors[sid] = s

    for idx, e in enumerate(case.get("evidence") or []):
        if not isinstance(e, dict):
            issues.append(f"evidence[{idx}] is not an object")
            continue

        eid = e.get("evidence_id") or f"EVD-{idx + 1}"
        e["evidence_id"] = eid

        sid = e.get("sensor_id")
        if sid not in sensors:
            issues.append(f"evidence {eid} references unknown sensor_id={sid}")

        st = parse_dt(e.get("start_time"))
        et = parse_dt(e.get("end_time"))
        if st and et and et < st:
            issues.append(f"evidence {eid} has end_time before start_time")

        evidence[eid] = e

    for idx, ev in enumerate(case.get("signal_events") or []):
        if not isinstance(ev, dict):
            issues.append(f"signal_events[{idx}] is not an object")
            continue

        eid = ev.get("evidence_id")
        if eid and eid not in evidence:
            issues.append(f"signal_event[{idx}] references unknown evidence_id={eid}")

        sid = ev.get("sensor_id")
        if sid and sid not in sensors:
            issues.append(f"signal_event[{idx}] references unknown sensor_id={sid}")

        center = to_float(ev.get("center_frequency_hz"))
        bw = to_float(ev.get("bandwidth_hz"))

        if center is not None and center < 0:
            issues.append(f"signal_event[{idx}] has negative center_frequency_hz")
        if bw is not None and bw <= 0:
            issues.append(f"signal_event[{idx}] has non-positive bandwidth_hz")

        ev["_center_frequency_hz"] = center
        ev["_bandwidth_hz"] = bw
        ev["_start"] = parse_dt(ev.get("start_time"))
        ev["_end"] = parse_dt(ev.get("end_time"))

        events.append(ev)

    if not sensors:
        issues.append("No authorized sensors supplied")

    return sensors, evidence, events, issues


# -----------------------------------------------------------------------------
# Deterministic feature aggregation
# -----------------------------------------------------------------------------

def event_duration(ev: Dict[str, Any]) -> Optional[float]:
    s = ev.get("_start")
    e = ev.get("_end")
    if s and e and e > s:
        return (e - s).total_seconds()
    return None


def compute_occupancy(
    events: List[Dict[str, Any]],
    case: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    tr = case.get("time_range") if isinstance(case.get("time_range"), dict) else {}
    obs_s = parse_dt(tr.get("start_time"))
    obs_e = parse_dt(tr.get("end_time"))

    if not obs_s or not obs_e:
        starts = [ev["_start"] for ev in events if ev.get("_start")]
        ends = [ev["_end"] for ev in events if ev.get("_end")]
        if starts and ends:
            obs_s = min(starts)
            obs_e = max(ends)

    if not obs_s or not obs_e or obs_e <= obs_s:
        return None

    intervals: List[Tuple[datetime, datetime]] = []
    for ev in events:
        s = ev.get("_start")
        e = ev.get("_end")
        if s and e and e > s:
            intervals.append((s, e))

    merged = merge_intervals(intervals)
    active_seconds = sum((e - s).total_seconds() for s, e in merged)
    interval_seconds = (obs_e - obs_s).total_seconds()

    return {
        "observation_start": obs_s.isoformat(),
        "observation_end": obs_e.isoformat(),
        "active_seconds": active_seconds,
        "interval_seconds": interval_seconds,
        "time_occupancy_fraction": active_seconds / interval_seconds if interval_seconds else None,
        "method": "merged_signal_event_intervals",
        "threshold": "provided_signal_events_only",
        "limitation": "Occupancy shows activity, not purpose, identity, or content.",
    }


def cluster_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    clusters: List[Dict[str, Any]] = []

    for ev in events:
        c = ev.get("_center_frequency_hz")
        if c is None:
            continue
        b = ev.get("_bandwidth_hz")

        placed = False
        for cl in clusters:
            tol = max(100_000.0, abs(cl["center_hz"]) * 1e-5)
            if abs(c - cl["center_hz"]) <= tol:
                cb = cl.get("bandwidth_hz")
                if b is not None and cb is not None:
                    bw_tol = max(50_000.0, 0.25 * max(b, cb))
                    if abs(b - cb) > bw_tol:
                        continue

                cl["events"].append(ev)

                centers = [
                    x.get("_center_frequency_hz")
                    for x in cl["events"]
                    if x.get("_center_frequency_hz") is not None
                ]
                if centers:
                    cl["center_hz"] = statistics.median(centers)

                bws = [
                    x.get("_bandwidth_hz")
                    for x in cl["events"]
                    if x.get("_bandwidth_hz") is not None
                ]
                if bws:
                    cl["bandwidth_hz"] = statistics.median(bws)

                placed = True
                break

        if not placed:
            clusters.append(
                {
                    "cluster_id": f"CL-{len(clusters) + 1}",
                    "center_hz": c,
                    "bandwidth_hz": b,
                    "events": [ev],
                }
            )

    return clusters


def independence_between(
    sid_a: Optional[str],
    sid_b: Optional[str],
    sensors: Dict[str, Dict[str, Any]],
) -> str:
    if not sid_a or not sid_b:
        return "UNKNOWN"
    if sid_a == sid_b:
        return "DEPENDENT"

    a = sensors.get(sid_a, {})
    b = sensors.get(sid_b, {})

    up_a = a.get("upstream_receiver_id") or a.get("receiver_id")
    up_b = b.get("upstream_receiver_id") or b.get("receiver_id")

    ant_a = a.get("antenna_reference") or a.get("antenna")
    ant_b = b.get("antenna_reference") or b.get("antenna")

    if up_a and up_b and up_a == up_b:
        return "DEPENDENT"
    if ant_a and ant_b and ant_a == ant_b:
        return "PARTIALLY_DEPENDENT"

    if a.get("sensor_type") == b.get("sensor_type") and a.get("hardware") == b.get("hardware"):
        return "UNKNOWN"

    return "INDEPENDENT"


def cluster_independence(
    cluster: Dict[str, Any],
    sensors: Dict[str, Dict[str, Any]],
) -> str:
    sids = list({ev.get("sensor_id") for ev in cluster.get("events", []) if ev.get("sensor_id")})
    if len(sids) < 2:
        return "SINGLE_SENSOR"

    states: List[str] = []
    for i in range(len(sids)):
        for j in range(i + 1, len(sids)):
            states.append(independence_between(sids[i], sids[j], sensors))

    if "INDEPENDENT" in states:
        return "INDEPENDENT_OR_PARTIAL"
    if "PARTIALLY_DEPENDENT" in states:
        return "PARTIALLY_DEPENDENT"
    return "DEPENDENT_OR_UNKNOWN"


def cluster_calibration(
    cluster: Dict[str, Any],
    sensors: Dict[str, Dict[str, Any]],
) -> str:
    states: List[str] = []
    for ev in cluster.get("events", []):
        sid = ev.get("sensor_id")
        s = sensors.get(sid, {})
        states.append(s.get("_calibration_state", "CALIBRATION_UNKNOWN"))

    if not states:
        return "UNKNOWN"
    if any(st in ("OUT_OF_CALIBRATION", "UNSUITABLE_FOR_MEASUREMENT") for st in states):
        return "DEGRADED"
    if all(st == "CALIBRATED" for st in states):
        return "CALIBRATED"
    if any(st == "CALIBRATED" for st in states):
        return "PARTIALLY_CALIBRATED"
    return "UNKNOWN"


def sensor_reliability_label(s: Dict[str, Any]) -> str:
    cal = s.get("_calibration_state", "CALIBRATION_UNKNOWN")
    stype = str(s.get("sensor_type", "")).upper()

    if cal == "CALIBRATED" and stype in ("SPECTRUM_ANALYZER", "AUTHORIZED_RF_MONITOR"):
        return "HIGH"
    if cal == "CALIBRATED":
        return "MODERATE"
    if cal == "PARTIALLY_CALIBRATED":
        return "LOW"
    return "UNKNOWN"


def build_emitter_candidates(
    clusters: List[Dict[str, Any]],
    sensors: Dict[str, Dict[str, Any]],
    known_emitters: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []

    for cl in clusters:
        events = cl.get("events", [])
        sids = list({ev.get("sensor_id") for ev in events if ev.get("sensor_id")})
        indep = cluster_independence(cl, sensors)
        cal = cluster_calibration(cl, sensors)

        protocol_counter: Dict[str, int] = {}
        modulation_counter: Dict[str, int] = {}
        class_counter: Dict[str, int] = {}

        for ev in events:
            for p in ev.get("protocol_candidates") or []:
                increment(protocol_counter, str(p))
            for m in ev.get("modulation_candidates") or []:
                increment(modulation_counter, str(m))
            increment(class_counter, ev.get("signal_class"))

        top_protocols = top_keys(protocol_counter)
        top_modulations = top_keys(modulation_counter)
        top_classes = top_keys(class_counter)

        state = "POSSIBLE_EMITTER_CLASS"
        if cal == "CALIBRATED" and len(sids) >= 2 and indep.startswith("INDEPENDENT"):
            state = "PROBABLE_EMITTER_CLASS"
        elif cal == "CALIBRATED":
            state = "SUPPORTED_EMITTER_CLASS"

        asset_associations: List[Dict[str, Any]] = []
        for ke in known_emitters or []:
            if not isinstance(ke, dict):
                continue
            kf = to_float(ke.get("center_frequency_hz"))
            if kf is None or cl.get("center_hz") is None:
                continue
            if abs(kf - cl["center_hz"]) <= 100_000.0:
                asset_associations.append(
                    {
                        "known_emitter_id": ke.get("emitter_id"),
                        "authorized_asset_id": ke.get("authorized_asset_id"),
                        "association_state": "POSSIBLE_ASSET_MATCH",
                        "limitation": "Frequency/channel match alone does not prove same emitter or device.",
                    }
                )

        starts = [ev.get("_start") for ev in events if ev.get("_start")]
        ends = [ev.get("_end") for ev in events if ev.get("_end")]

        candidates.append(
            {
                "emitter_candidate_id": f"EMIT-{len(candidates) + 1}",
                "cluster_id": cl["cluster_id"],
                "emitter_state": state,
                "signal_class_candidates": top_classes,
                "modulation_candidates": top_modulations,
                "protocol_candidates": top_protocols,
                "center_frequency_hz": cl.get("center_hz"),
                "bandwidth_hz": cl.get("bandwidth_hz"),
                "sensor_ids": sids,
                "source_independence": indep,
                "calibration_state": cal,
                "first_seen": min(starts).isoformat() if starts else None,
                "last_seen": max(ends).isoformat() if ends else None,
                "authorized_asset_associations": asset_associations,
                "confidence": {
                    "classification_confidence": "MODERATE" if cal == "CALIBRATED" else "LOW",
                    "emitter_confidence": "MODERATE" if state == "PROBABLE_EMITTER_CLASS" else "LOW",
                    "location_confidence": "UNKNOWN",
                },
                "limitations": [
                    "Same frequency does not prove same emitter.",
                    "RF fingerprint does not establish device identity.",
                    "Device identity does not establish owner or person.",
                    "Protocol candidate does not authorize content access.",
                ],
            }
        )

    return candidates


def build_facts(
    events: List[Dict[str, Any]],
    sensors: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    facts: List[Dict[str, Any]] = []
    candidates: List[Dict[str, Any]] = []

    not_facts = [
        "Exact device identity is not established.",
        "Operator/person identity is not established.",
        "Malicious intent is not established.",
        "Protocol candidate does not authorize private content access.",
        "RSSI is not converted to exact distance.",
        "Single bearing is not treated as exact location.",
    ]

    for ev in events:
        sid = ev.get("sensor_id")
        c = ev.get("_center_frequency_hz")
        st = ev.get("_start")
        en = ev.get("_end")
        usable = bool(sensors.get(sid, {}).get("_usable_for_measurement"))
        det = ev.get("detection_state", "INCONCLUSIVE")

        if sid and c is not None:
            conf = "HIGH" if usable and det in ("DETECTED", "LIKELY_DETECTED") else "MODERATE" if usable else "LOW"
            facts.append(
                {
                    "fact_id": f"FCT-{len(facts) + 1}",
                    "statement": (
                        f"{sid} observed energy consistent with a signal near {c:.0f} Hz "
                        f"during {st.isoformat() if st else 'unknown'} to {en.isoformat() if en else 'unknown'}."
                    ),
                    "evidence_id": ev.get("evidence_id"),
                    "sensor_id": sid,
                    "confidence": conf,
                    "basis": "deterministic_signal_event_input",
                }
            )

        protos = ev.get("protocol_candidates") or []
        if protos:
            cal = sensors.get(sid, {}).get("_calibration_state", "CALIBRATION_UNKNOWN")
            candidates.append(
                {
                    "candidate_id": f"CND-{len(candidates) + 1}",
                    "statement": "Features are consistent with protocol family: " + ", ".join(map(str, protos)),
                    "evidence_id": ev.get("evidence_id"),
                    "sensor_id": sid,
                    "confidence": "MODERATE" if cal == "CALIBRATED" and det in ("DETECTED", "LIKELY_DETECTED") else "LOW",
                    "limitation": "Protocol candidate is not private content access and not device identity.",
                }
            )

    return facts, candidates, not_facts


def build_hypotheses(
    emitter_candidates: List[Dict[str, Any]],
    sensors: Dict[str, Dict[str, Any]],
    issues: List[str],
) -> List[Dict[str, Any]]:
    hypotheses: List[Dict[str, Any]] = []

    for ec in emitter_candidates:
        cid = ec["cluster_id"]
        cal = ec["calibration_state"]
        indep = ec["source_independence"]
        assets = ec.get("authorized_asset_associations") or []

        hypotheses.append(
            {
                "hypothesis_id": f"H-{cid}-KNOWN-ASSET",
                "statement": "The cluster may originate from a known authorized asset using the same band/channel.",
                "support": [
                    "Authorized asset/frequency match exists." if assets else "No authorized asset match supplied.",
                ],
                "opposition": [
                    "Same frequency does not prove same emitter.",
                    "Calibration/independence limits interpretation." if cal != "CALIBRATED" or not indep.startswith("INDEPENDENT") else "No major calibration/independence objection recorded.",
                ],
                "falsification_conditions": [
                    "Independent sensor shows different timing/fingerprint.",
                    "Authorized asset inventory shows no transmitter capable in that area/time.",
                    "Observation is reproduced as receiver artifact.",
                ],
            }
        )

        hypotheses.append(
            {
                "hypothesis_id": f"H-{cid}-OTHER-SAME-PROTOCOL",
                "statement": "The cluster may originate from another device using the same protocol/channel.",
                "support": [
                    "Shared spectrum use is common in licensed/unlicensed bands.",
                    "Protocol candidate alone does not uniquely identify device.",
                ],
                "opposition": [
                    "No conflicting evidence supplied yet." if not issues else "Validation issues weaken all hypotheses.",
                ],
                "falsification_conditions": [
                    "Unique authorized metadata correlates only with known asset.",
                    "Multi-sensor fingerprint/timing strongly separates sources.",
                ],
            }
        )

        hypotheses.append(
            {
                "hypothesis_id": f"H-{cid}-SENSOR-ARTIFACT",
                "statement": "The observation may be a receiver/sensor artifact.",
                "support": [
                    "Calibration unknown/degraded." if cal in ("UNKNOWN", "DEGRADED", "PARTIALLY_CALIBRATED") else "Sensor is calibrated, reducing but not eliminating artifact risk.",
                    "Validation issues present." if issues else "No validation issues recorded.",
                ],
                "opposition": [
                    "Independent calibrated sensors agree." if indep.startswith("INDEPENDENT") and cal == "CALIBRATED" else "No strong independent corroboration recorded.",
                ],
                "falsification_conditions": [
                    "Artifact disappears with different antenna/gain/filter configuration.",
                    "Independent calibrated sensor reproduces same spectral/temporal features.",
                ],
            }
        )

        hypotheses.append(
            {
                "hypothesis_id": f"H-{cid}-INTERFERENCE_OR_HARMONIC",
                "statement": "The observation may be interference, harmonic, spurious emission, or intermodulation rather than intended transmission.",
                "support": [
                    "Input includes interference/harmonic flags." if any(
                        ev.get("interference") or ev.get("harmonic_of_hz") or ev.get("spurious")
                        for ev in ec.get("events", [])
                    ) else "No explicit interference/harmonic flag supplied.",
                ],
                "opposition": [
                    "Clean isolated spectral/temporal behavior supplied." if not issues else "Validation issues prevent strong opposition.",
                ],
                "falsification_conditions": [
                    "Frequency arithmetic does not support harmonic/intermodulation relationship.",
                    "Timing/spectral behavior matches known intentional protocol emissions.",
                ],
            }
        )

    return hypotheses


def dual_ai_review(
    events: List[Dict[str, Any]],
    emitter_candidates: List[Dict[str, Any]],
    issues: List[str],
) -> Dict[str, Any]:
    primary = {
        "role": "Primary RF Analyst",
        "assessment": "Signal presence candidates observed." if events else "No deterministic signal events supplied.",
        "classification": "Protocol/modulation candidates remain tentative unless corroborated.",
    }

    if not events:
        skeptic = {
            "role": "Independent RF Skeptic",
            "verdict": "INSUFFICIENT_EVIDENCE",
            "reason": "No signal events were supplied. Measurement cannot be inferred from narrative.",
        }
    elif issues:
        skeptic = {
            "role": "Independent RF Skeptic",
            "verdict": "PARTIAL_AGREEMENT",
            "reason": "Validation issues require downgraded confidence.",
        }
    elif not emitter_candidates:
        skeptic = {
            "role": "Independent RF Skeptic",
            "verdict": "INSUFFICIENT_EVIDENCE",
            "reason": "Events lack sufficient frequency/bandwidth structure for clustering.",
        }
    else:
        calibrated_multi = any(
            ec["calibration_state"] == "CALIBRATED"
            and str(ec["source_independence"]).startswith("INDEPENDENT")
            for ec in emitter_candidates
        )
        verdict = "AGREE_ON_SIGNAL_PRESENCE_ONLY" if calibrated_multi else "PARTIAL_AGREEMENT"
        skeptic = {
            "role": "Independent RF Skeptic",
            "verdict": verdict,
            "reason": "AI agreement is not sensor corroboration. Device/person attribution remains prohibited without authorized evidence.",
        }

    return {
        "primary": primary,
        "skeptic": skeptic,
        "comparison": skeptic.get("verdict", "INSUFFICIENT_EVIDENCE"),
        "note": "Rule-based dual-review scaffold. Human review required for consequential RF conclusions.",
    }


def detect_contradictions(
    clusters: List[Dict[str, Any]],
    case: Dict[str, Any],
) -> List[Dict[str, Any]]:
    contradictions: List[Dict[str, Any]] = list(case.get("existing_contradictions") or [])

    for cl in clusters:
        prot_sets = [
            set(map(str, ev.get("protocol_candidates") or []))
            for ev in cl.get("events", [])
            if ev.get("protocol_candidates")
        ]
        if len(prot_sets) >= 2:
            union = set().union(*prot_sets)
            intersection = set.intersection(*prot_sets)
            if not intersection and all(prot_sets):
                contradictions.append(
                    {
                        "type": "protocol_classification_conflict",
                        "cluster_id": cl["cluster_id"],
                        "values": sorted(union),
                        "note": "Preserve contradiction. Do not average conflicting classifications into fake precision.",
                    }
                )

    return contradictions


def build_graph(
    case: Dict[str, Any],
    sensors: Dict[str, Dict[str, Any]],
    evidence: Dict[str, Dict[str, Any]],
    events: List[Dict[str, Any]],
    clusters: List[Dict[str, Any]],
    emitter_candidates: List[Dict[str, Any]],
    facts: List[Dict[str, Any]],
    hypotheses: List[Dict[str, Any]],
    gaps: List[Dict[str, Any]],
) -> Dict[str, Any]:
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    def add_node(node_id: str, node_type: str, props: Dict[str, Any]) -> None:
        if any(n.get("id") == node_id for n in nodes):
            return
        nodes.append({"id": node_id, "type": node_type, "properties": props})

    def add_edge(src: str, dst: str, rel: str, props: Dict[str, Any]) -> None:
        edges.append({"from": src, "to": dst, "type": rel, "properties": props})

    for sid, s in sensors.items():
        add_node(sid, "RFSensor", public_dict(s))

    for eid, e in evidence.items():
        add_node(eid, "RFCapture", public_dict(e))
        if e.get("sensor_id"):
            add_edge(eid, e["sensor_id"], "OBSERVED_BY", {"evidence_id": eid})

    for i, ev in enumerate(events, 1):
        sig_id = ev.get("event_id") or f"SIG-{i}"
        add_node(sig_id, "Signal", public_dict(ev))
        if ev.get("evidence_id"):
            add_edge(sig_id, ev["evidence_id"], "SUPPORTED_BY", {"event_id": sig_id})
        if ev.get("sensor_id"):
            add_edge(sig_id, ev["sensor_id"], "OBSERVED_BY", {"event_id": sig_id})

    for cl in clusters:
        cid = cl["cluster_id"]
        add_node(
            cid,
            "SignalCluster",
            {
                "center_hz": cl.get("center_hz"),
                "bandwidth_hz": cl.get("bandwidth_hz"),
                "event_count": len(cl.get("events", [])),
            },
        )
        for ev in cl.get("events", []):
            sig_id = ev.get("event_id") or "UNKNOWN"
            add_edge(sig_id, cid, "PART_OF_CLUSTER", {"cluster_id": cid})

    for ec in emitter_candidates:
        eid = ec["emitter_candidate_id"]
        add_node(eid, "EmitterCandidate", {k: v for k, v in ec.items() if k != "events"})
        add_edge(ec["cluster_id"], eid, "EMITTED_BY_CANDIDATE", {"emitter_candidate_id": eid})
        for p in ec.get("protocol_candidates") or []:
            pid = f"PROTO-{p}"
            add_node(pid, "ProtocolCandidate", {"name": p})
            add_edge(eid, pid, "CONSISTENT_WITH_PROTOCOL", {"emitter_candidate_id": eid})

    for f in facts:
        fid = f["fact_id"]
        add_node(fid, "Fact", f)
        if f.get("evidence_id"):
            add_edge(fid, f["evidence_id"], "SUPPORTED_BY", {"fact_id": fid})

    for h in hypotheses:
        hid = h["hypothesis_id"]
        add_node(hid, "Hypothesis", h)

    for g in gaps:
        gid = g.get("gap_id") or f"GAP-{len(gaps)}"
        add_node(gid, "Gap", g)

    return {"nodes": nodes, "edges": edges, "version": VERSION}


def build_knowledge_gaps(
    events: List[Dict[str, Any]],
    clusters: List[Dict[str, Any]],
    emitter_candidates: List[Dict[str, Any]],
    sensors: Dict[str, Dict[str, Any]],
    issues: List[str],
) -> List[Dict[str, Any]]:
    gaps: List[Dict[str, Any]] = []

    if not events:
        gaps.append(
            {
                "gap_id": "GAP-NO-SIGNAL-EVENTS",
                "gap": "No deterministic signal events supplied",
                "importance": "HIGH",
                "recommended_safe_source": "Authorized SDR/spectrum analyzer DSP export",
                "expected_information_value": "Establishes whether any RF activity is measurable",
            }
        )

    if issues:
        gaps.append(
            {
                "gap_id": "GAP-VALIDATION-ISSUES",
                "gap": "Sensor/evidence validation issues present",
                "importance": "HIGH",
                "recommended_safe_source": "Recalibration, clock sync check, antenna/gain audit",
                "expected_information_value": "Improves measurement trust",
            }
        )

    unknown_cal = [sid for sid, s in sensors.items() if s.get("_calibration_state") in ("CALIBRATION_UNKNOWN", "OUT_OF_CALIBRATION", "UNSUITABLE_FOR_MEASUREMENT")]
    if unknown_cal:
        gaps.append(
            {
                "gap_id": "GAP-CALIBRATION",
                "gap": f"Calibration insufficient for sensors: {', '.join(unknown_cal)}",
                "importance": "HIGH",
                "recommended_safe_source": "Authorized calibration record or lab measurement",
                "expected_information_value": "Allows safer power/frequency interpretation",
            }
        )

    if events and not clusters:
        gaps.append(
            {
                "gap_id": "GAP-NO-CLUSTER",
                "gap": "Events lack frequency/bandwidth structure for clustering",
                "importance": "MODERATE",
                "recommended_safe_source": "Re-export PSD/waterfall features with center frequency and bandwidth",
                "expected_information_value": "Supports signal candidate grouping",
            }
        )

    if emitter_candidates and all(ec["emitter_state"] in ("POSSIBLE_EMITTER_CLASS", "UNKNOWN_EMITTER") for ec in emitter_candidates):
        gaps.append(
            {
                "gap_id": "GAP-EMITTER-UNRESOLVED",
                "gap": "Emitter classification remains unresolved",
                "importance": "MODERATE",
                "recommended_safe_source": "Independent authorized sensor, asset inventory correlation, longer passive observation",
                "expected_information_value": "Reduces false attribution risk",
            }
        )

    return gaps


def build_next_actions(
    events: List[Dict[str, Any]],
    issues: List[str],
    emitter_candidates: List[Dict[str, Any]],
    gaps: List[Dict[str, Any]],
) -> List[str]:
    actions: List[str] = []

    if not events:
        actions.append("Run deterministic DSP/SDR tooling and export sanitized signal_events.json")

    if issues:
        actions.append("Resolve sensor/evidence validation issues before classification")

    if any(g["gap_id"] == "GAP-CALIBRATION" for g in gaps):
        actions.append("Obtain calibration record or recalibrate authorized sensor")

    if emitter_candidates:
        actions.append("Collect longer passive observation from an independent authorized sensor")
        actions.append("Correlate emitter candidates against authorized equipment inventory")
        actions.append("Review historical capture baseline for same sensor/location/time-of-day")

    if any(ec["protocol_candidates"] for ec in emitter_candidates):
        actions.append("Hand off device/product-family questions to IOTINT/TECHINT without RF-side exploitation")

    if any(str(ec.get("source_independence", "")).startswith("INDEPENDENT") for ec in emitter_candidates):
        actions.append("Preserve multi-sensor correlation evidence for replay")

    actions.append("Maintain passive-only posture; no transmission, injection, deauthentication, spoofing, or tracking")

    return actions


def build_specialist_handoffs(
    emitter_candidates: List[Dict[str, Any]],
    direction_observations: List[Dict[str, Any]],
    interference_events: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    handoffs: List[Dict[str, Any]] = []

    if emitter_candidates:
        handoffs.append(
            {
                "to": "IOTINT / TECHINT",
                "reason": "Device/product-family identification exceeds RF fingerprint evidence",
                "restrictions": [
                    "No unauthorized pairing",
                    "No exploitation",
                    "No private-person attribution",
                ],
            }
        )
        handoffs.append(
            {
                "to": "SIGINT",
                "reason": "Broader signal relationship analysis may be required",
                "restrictions": ["No private content access without separate lawful workflow"],
            }
        )

    if direction_observations:
        handoffs.append(
            {
                "to": "GEOINT / MAPINT",
                "reason": "Spatial validation requires terrain/map/geometry review",
                "restrictions": [
                    "No precise private-person location",
                    "No weapon targeting",
                    "Propagate uncertainty",
                ],
            }
        )

    if interference_events:
        handoffs.append(
            {
                "to": "INCIDENTINT",
                "reason": "Interference may require operational incident handling",
                "restrictions": [
                    "Intent unresolved unless separately authorized",
                    "No jamming response",
                    "No active RF countermeasure",
                ],
            }
        )

    return handoffs


def analyst_summary(r: Dict[str, Any]) -> str:
    def fmt_list(lst: Any) -> str:
        if not lst:
            return "NONE"
        if isinstance(lst, list):
            return ", ".join(str(x) for x in lst)
        return str(lst)

    def fmt_summary(s: Any, unit: str = "") -> str:
        if not s or s.get("count", 0) == 0:
            return "NONE"
        return (
            f"count={s.get('count')} "
            f"min={s.get('min')} "
            f"max={s.get('max')} "
            f"median={s.get('median')} {unit}".strip()
        )

    lines = [
        "RF ENVIRONMENT STATUS: " + str(r.get("status")) + " | ANOMALY_RISK=" + str(r.get("anomaly_risk")),
        "SENSORS: " + fmt_list(r.get("sensor_ids")),
        "CALIBRATION: " + fmt_list([f"{k}={v}" for k, v in (r.get("calibration_states") or {}).items()]),
        "OBSERVED BANDS: " + fmt_list(r.get("bands")),
        "FREQUENCIES: " + fmt_summary(r.get("frequency_summary"), "Hz"),
        "CHANNELS: " + fmt_list([c.get("channel") or c.get("name") for c in (r.get("channels") or []) if isinstance(c, dict)] or r.get("channels")),
        "BANDWIDTH: " + fmt_summary(r.get("bandwidth_summary"), "Hz"),
        "POWER / RSSI: " + fmt_summary(r.get("power_summary"), "dBm") + " | RSSI=" + fmt_summary(r.get("rssi_summary"), "dB"),
        "SNR: " + fmt_summary(r.get("snr_summary"), "dB"),
        "NOISE FLOOR: " + fmt_summary(r.get("noise_floor_summary"), "dBm"),
        "OCCUPANCY: " + json.dumps(r.get("occupancy") or {}, default=str),
        "SIGNAL TYPES: " + fmt_list([f"{k}:{v}" for k, v in (r.get("signal_class_counts") or {}).items()]),
        "BURST / PERIODICITY: bursts=" + str(len(r.get("bursts") or [])) + " periodicity_records=" + str(len(r.get("periodicity") or [])),
        "MODULATION CANDIDATES: " + fmt_list(r.get("modulation_candidates")),
        "PROTOCOL CANDIDATES: " + fmt_list(r.get("protocol_candidates")),
        "EMITTER CANDIDATES: " + fmt_list([f"{e.get('emitter_candidate_id')}={e.get('emitter_state')}" for e in (r.get("emitter_candidates") or [])]),
        "INTERFERENCE: " + fmt_list([i.get("classification") or i.get("type") or "PROVIDED" for i in (r.get("interference_events") or [])]),
        "HARMONICS / SPURS: harmonics=" + str(len(r.get("harmonic_candidates") or [])) + " spurs=" + str(len(r.get("spurious_emission_candidates") or [])),
        "AUTHORIZED ASSET CORRELATION: " + fmt_list([a.get("authorized_asset_id") or a.get("known_emitter_id") for e in (r.get("emitter_candidates") or []) for a in (e.get("authorized_asset_associations") or [])]),
        "DIRECTION / LOCATION CONFIDENCE: direction_observations=" + str(len(r.get("direction_observations") or [])) + " location_confidence=" + str((r.get("classification_confidence") or {}).get("location_confidence", "UNKNOWN")),
        "TEMPORAL CHANGES: " + str(len(r.get("temporal_changes") or [])),
        "SOURCE / SENSOR RELIABILITY: " + fmt_list([f"{s.get('sensor_id')}={s.get('reliability')}" for s in (r.get("sensor_reliability") or [])]),
        "SOURCE INDEPENDENCE: " + str(r.get("source_independence")),
        "CONTRADICTIONS: " + str(len(r.get("contradictions") or [])),
        "UNKNOWN: " + fmt_list(r.get("unknowns")),
        "NEXT ACTION: " + (r.get("recommended_next_actions") or ["NONE"])[0],
    ]
    return "\n".join(lines)


# -----------------------------------------------------------------------------
# Main analysis
# -----------------------------------------------------------------------------

def blocked_result(case: Dict[str, Any], reasons: List[str], started: str, input_path: Optional[str], input_hash: Optional[str]) -> Dict[str, Any]:
    return {
        "case_id": case.get("case_id"),
        "task_id": case.get("task_id"),
        "objective": case.get("objective"),
        "status": "POLICY_BLOCKED",
        "policy_block_reasons": reasons,
        "mode": case.get("model_mode", "LOCAL_ONLY"),
        "safety_flags": [
            "PASSIVE_ONLY",
            "NO_TRANSMISSION",
            "NO_JAMMING",
            "NO_SPOOFING",
            "NO_RF_INJECTION",
            "NO_PRIVATE_PERSON_TRACKING",
            "NO_WEAPON_TARGETING",
        ],
        "privacy_flags": [
            "METADATA_MINIMIZATION",
            "NO_PRIVATE_CONTENT_ACCESS",
            "ASSET_FIRST_PRINCIPLE",
        ],
        "recommended_next_actions": [
            "Restate objective as authorized passive spectrum monitoring",
            "Supply deterministic DSP-derived signal events",
            "Correlate with authorized asset inventory",
            "Escalate suspected interference to human/regulatory review without active RF response",
        ],
        "limitations": [
            "Requested or detected action crosses RFINT defensive boundary.",
            "No electronic attack, interception, spoofing, injection, or private tracking support is provided.",
        ],
        "replay_manifest": {
            "generated_at": started,
            "finished_at": utcnow_iso(),
            "code_version": VERSION,
            "input_path": input_path,
            "input_sha256": input_hash,
        },
    }


def analyze(case: Dict[str, Any], input_path: Optional[str] = None, input_hash: Optional[str] = None) -> Dict[str, Any]:
    started = utcnow_iso()

    block_reasons = policy_block_reasons(case)
    if block_reasons:
        return blocked_result(case, block_reasons, started, input_path, input_hash)

    sensors, evidence, events, issues = validate_case(case)

    occupancy = compute_occupancy(events, case)
    clusters = cluster_events(events)
    emitter_candidates = build_emitter_candidates(
        clusters,
        sensors,
        case.get("known_emitters") or [],
    )

    facts, candidate_facts, not_facts = build_facts(events, sensors)
    hypotheses = build_hypotheses(emitter_candidates, sensors, issues)
    contradictions = detect_contradictions(clusters, case)
    dual = dual_ai_review(events, emitter_candidates, issues)

    freq_summary = numeric_summary([ev.get("_center_frequency_hz") for ev in events])
    bw_summary = numeric_summary([ev.get("_bandwidth_hz") for ev in events])
    power_summary = numeric_summary([ev.get("power_dbm") for ev in events])
    rssi_summary = numeric_summary([ev.get("rssi_dbm") for ev in events])
    snr_summary = numeric_summary([ev.get("snr_db") for ev in events])
    noise_summary = numeric_summary([ev.get("noise_floor_dbm") for ev in events])

    detection_counts: Dict[str, int] = {}
    class_counts: Dict[str, int] = {}
    for ev in events:
        increment(detection_counts, ev.get("detection_state", "INCONCLUSIVE"))
        increment(class_counts, ev.get("signal_class"))

    modulation_candidates = top_keys(
        {
            k: sum(1 for ev in events if k in map(str, ev.get("modulation_candidates") or []))
            for k in {str(m) for ev in events for m in ev.get("modulation_candidates") or []}
        }
    )

    protocol_candidates = top_keys(
        {
            k: sum(1 for ev in events if k in map(str, ev.get("protocol_candidates") or []))
            for k in {str(p) for ev in events for p in ev.get("protocol_candidates") or []}
        }
    )

    bursts: List[Dict[str, Any]] = []
    periodicity: List[Dict[str, Any]] = []
    duty_cycles: List[Dict[str, Any]] = []
    frequency_drift: List[Dict[str, Any]] = []
    doppler_candidates: List[Dict[str, Any]] = []
    signal_fingerprints: List[Dict[str, Any]] = []

    interval_seconds = (occupancy or {}).get("interval_seconds")

    for ev in events:
        dur = event_duration(ev)
        if ev.get("signal_class") == "BURST" or ev.get("burst") is True:
            bursts.append(
                {
                    "event_id": ev.get("event_id"),
                    "sensor_id": ev.get("sensor_id"),
                    "start_time": ev.get("start_time"),
                    "end_time": ev.get("end_time"),
                    "duration_s": dur,
                    "center_frequency_hz": ev.get("_center_frequency_hz"),
                }
            )

        if ev.get("periodicity"):
            periodicity.append(
                {
                    "event_id": ev.get("event_id"),
                    "sensor_id": ev.get("sensor_id"),
                    "periodicity": ev.get("periodicity"),
                    "note": "Periodicity is not automatically malicious beaconing.",
                }
            )

        if dur is not None and interval_seconds:
            duty_cycles.append(
                {
                    "event_id": ev.get("event_id"),
                    "sensor_id": ev.get("sensor_id"),
                    "duration_s": dur,
                    "observation_interval_s": interval_seconds,
                    "duty_cycle_fraction": dur / interval_seconds if interval_seconds else None,
                }
            )

        if ev.get("frequency_drift"):
            frequency_drift.append({"event_id": ev.get("event_id"), "value": ev.get("frequency_drift")})

        if ev.get("doppler_candidate"):
            doppler_candidates.append({"event_id": ev.get("event_id"), "value": ev.get("doppler_candidate")})

        if ev.get("fingerprint"):
            signal_fingerprints.append({"event_id": ev.get("event_id"), "fingerprint": ev.get("fingerprint")})

    interference_events: List[Dict[str, Any]] = list(case.get("interference_events") or [])
    for ev in events:
        if ev.get("interference"):
            interference_events.append(
                {
                    "source_event_id": ev.get("event_id"),
                    "classification": ev.get("interference_classification", "UNKNOWN"),
                    "intent_state": "INTENT_UNRESOLVED",
                    "note": "Interference observation is not proof of jamming or malicious intent.",
                }
            )

    harmonic_candidates: List[Dict[str, Any]] = list(case.get("harmonic_candidates") or [])
    for ev in events:
        if ev.get("harmonic_of_hz"):
            harmonic_candidates.append(
                {
                    "event_id": ev.get("event_id"),
                    "fundamental_hz": ev.get("harmonic_of_hz"),
                    "relationship": "provided_by_deterministic_input",
                    "limitation": "Harmonic relationship alone does not prove same physical emitter.",
                }
            )

    spurious_emission_candidates: List[Dict[str, Any]] = list(case.get("spurious_emission_candidates") or [])
    for ev in events:
        if ev.get("spurious"):
            spurious_emission_candidates.append(
                {
                    "event_id": ev.get("event_id"),
                    "note": "Spurious emission candidate supplied by deterministic input; not automatically intended transmission.",
                }
            )

    direction_observations: List[Dict[str, Any]] = list(case.get("direction_observations") or [])
    location_candidates: List[Dict[str, Any]] = []
    if direction_observations:
        location_candidates.append(
            {
                "location_candidate_id": "LOC-1",
                "state": "INCONCLUSIVE",
                "reason": "Direction observations alone do not justify exact location. Require authorized multi-static geometry, calibration, multipath review, and human/GEOINT validation.",
                "privacy_boundary": "No private-person location inference.",
            }
        )

    temporal_changes: List[Dict[str, Any]] = list(case.get("temporal_changes") or [])
    for ec in emitter_candidates:
        temporal_changes.append(
            {
                "cluster_id": ec["cluster_id"],
                "first_seen": ec.get("first_seen"),
                "last_seen": ec.get("last_seen"),
                "note": "first_seen is dataset-specific; last_seen does not prove transmitter offline.",
            }
        )

    sensor_reliability = [
        {
            "sensor_id": sid,
            "reliability": sensor_reliability_label(s),
            "calibration_state": s.get("_calibration_state", "CALIBRATION_UNKNOWN"),
            "usable_for_measurement": bool(s.get("_usable_for_measurement")),
        }
        for sid, s in sensors.items()
    ]

    independence_summary = [
        {
            "cluster_id": ec["cluster_id"],
            "source_independence": ec["source_independence"],
        }
        for ec in emitter_candidates
    ]

    if any(str(x["source_independence"]).startswith("INDEPENDENT") for x in independence_summary):
        source_independence = "INDEPENDENT_OBSERVATION_AVAILABLE"
    elif events:
        source_independence = "SINGLE_SENSOR_OR_UNKNOWN"
    else:
        source_independence = "NO_OBSERVATION"

    gaps = build_knowledge_gaps(events, clusters, emitter_candidates, sensors, issues)
    next_actions = build_next_actions(events, issues, emitter_candidates, gaps)
    handoffs = build_specialist_handoffs(emitter_candidates, direction_observations, interference_events)

    unknowns: List[str] = []
    if not events:
        unknowns.append("No measurable RF activity supplied")
    if not protocol_candidates:
        unknowns.append("Protocol family unresolved")
    if not emitter_candidates:
        unknowns.append("Emitter candidate unresolved")
    if any(s.get("_calibration_state") != "CALIBRATED" for s in sensors.values()):
        unknowns.append("Calibration-limited power/frequency interpretation")
    if direction_observations:
        unknowns.append("Exact location not justified")

    if interference_events:
        anomaly_risk = "INTERFERENCE_REVIEW"
    elif case.get("rf_anomalies"):
        anomaly_risk = "UNUSUAL_RF_ACTIVITY"
    elif events:
        anomaly_risk = "EXPECTED_RF_ACTIVITY"
    else:
        anomaly_risk = "INCONCLUSIVE"

    if not sensors:
        status = "BLOCKED_CONFIGURATION"
    elif not events:
        status = "INCONCLUSIVE"
    elif issues:
        status = "PARTIAL"
    else:
        status = "PARTIAL"

    classification_confidence = {
        "measurement_uncertainty": "HIGH" if issues or any(s.get("_calibration_state") != "CALIBRATED" for s in sensors.values()) else "MODERATE",
        "classification_confidence": "MODERATE" if protocol_candidates and not issues else "LOW",
        "emitter_confidence": "LOW" if not emitter_candidates or all(ec["emitter_state"] == "POSSIBLE_EMITTER_CLASS" for ec in emitter_candidates) else "MODERATE",
        "location_confidence": "UNKNOWN" if not direction_observations else "LOW",
        "analyst_confidence": "LOW" if status in ("INCONCLUSIVE", "BLOCKED_CONFIGURATION") else "MODERATE",
    }

    graph = build_graph(case, sensors, evidence, events, clusters, emitter_candidates, facts, hypotheses, gaps)

    result: Dict[str, Any] = {
        "case_id": case.get("case_id"),
        "task_id": case.get("task_id"),
        "objective": case.get("objective"),
        "questions": case.get("questions") or [],
        "mode": case.get("model_mode", "LOCAL_ONLY"),
        "status": status,
        "anomaly_risk": anomaly_risk,
        "source_ids": list({ev.get("source_type") for ev in evidence.values() if ev.get("source_type")}),
        "evidence_ids": list(evidence.keys()),
        "sensor_ids": list(sensors.keys()),
        "sensor_states": {sid: s.get("_calibration_state", "CALIBRATION_UNKNOWN") for sid, s in sensors.items()},
        "calibration_states": {sid: s.get("_calibration_state", "CALIBRATION_UNKNOWN") for sid, s in sensors.items()},
        "captures": [public_dict(e) for e in evidence.values()],
        "frequency_ranges": case.get("frequency_ranges") or [],
        "bands": case.get("bands") or [],
        "channels": case.get("known_channels") or [],
        "spectrum_observations": [public_dict(ev) for ev in events],
        "signal_events": [public_dict(ev) for ev in events],
        "center_frequencies": [ev.get("_center_frequency_hz") for ev in events if ev.get("_center_frequency_hz") is not None],
        "bandwidths": [ev.get("_bandwidth_hz") for ev in events if ev.get("_bandwidth_hz") is not None],
        "power_measurements": [ev.get("power_dbm") for ev in events if ev.get("power_dbm") is not None],
        "rssi": [ev.get("rssi_dbm") for ev in events if ev.get("rssi_dbm") is not None],
        "snr": [ev.get("snr_db") for ev in events if ev.get("snr_db") is not None],
        "noise_floor": [ev.get("noise_floor_dbm") for ev in events if ev.get("noise_floor_dbm") is not None],
        "occupancy": occupancy,
        "bursts": bursts,
        "periodicity": periodicity,
        "duty_cycles": duty_cycles,
        "frequency_drift": frequency_drift,
        "doppler_candidates": doppler_candidates,
        "modulation_candidates": modulation_candidates,
        "protocol_candidates": protocol_candidates,
        "signal_fingerprints": signal_fingerprints,
        "signal_clusters": [
            {
                "cluster_id": cl["cluster_id"],
                "center_hz": cl.get("center_hz"),
                "bandwidth_hz": cl.get("bandwidth_hz"),
                "event_count": len(cl.get("events", [])),
                "sensor_ids": list({ev.get("sensor_id") for ev in cl.get("events", []) if ev.get("sensor_id")}),
            }
            for cl in clusters
        ],
        "emitter_candidates": emitter_candidates,
        "device_candidates": [],
        "authorized_asset_associations": [
            assoc
            for ec in emitter_candidates
            for assoc in ec.get("authorized_asset_associations", [])
        ],
        "wifi_context": case.get("wifi_context") or [],
        "ble_context": case.get("ble_context") or [],
        "cellular_context": case.get("cellular_context") or [],
        "gnss_context": case.get("gnss_context") or [],
        "adsb_context": case.get("adsb_context") or [],
        "ais_context": case.get("ais_context") or [],
        "iot_context": case.get("iot_context") or [],
        "industrial_rf_context": case.get("industrial_rf_context") or [],
        "satellite_rf_context": case.get("satellite_rf_context") or [],
        "interference_events": interference_events,
        "harmonic_candidates": harmonic_candidates,
        "spurious_emission_candidates": spurious_emission_candidates,
        "direction_observations": direction_observations,
        "location_candidates": location_candidates,
        "coverage_context": case.get("coverage_context") or [],
        "regulatory_allocations": case.get("frequency_allocations") or [],
        "license_context": case.get("license_context") or [],
        "temporal_changes": temporal_changes,
        "observations": [public_dict(ev) for ev in events],
        "candidate_facts": candidate_facts,
        "supported_facts": facts,
        "partial_facts": candidate_facts,
        "disputed_facts": contradictions,
        "source_reliability": case.get("source_reliability") or [],
        "sensor_reliability": sensor_reliability,
        "source_bias": case.get("source_bias") or [],
        "source_limitations": case.get("source_limitations") or [],
        "source_pedigree": case.get("source_pedigree") or [],
        "source_independence": source_independence,
        "source_independence_summary": independence_summary,
        "contradictions": contradictions,
        "hypotheses": hypotheses,
        "falsification_results": [
            {
                "hypothesis_id": h["hypothesis_id"],
                "status": "WEAKENED_BY_VALIDATION_ISSUES" if issues else "NOT_FALSIFIED_WITH_CURRENT_EVIDENCE",
                "required_additional_evidence": [
                    "Independent authorized sensor",
                    "Calibration record",
                    "Authorized asset inventory correlation",
                    "Longer passive observation",
                ],
            }
            for h in hypotheses
        ],
        "measurement_uncertainty": classification_confidence["measurement_uncertainty"],
        "classification_confidence": classification_confidence,
        "location_confidence": classification_confidence["location_confidence"],
        "privacy_flags": [
            "METADATA_MINIMIZATION",
            "NO_PRIVATE_CONTENT_ACCESS",
            "NO_PRIVATE_PERSON_TRACKING",
            "ASSET_FIRST_PRINCIPLE",
            "NO_HOME_WORK_PATTERN_INFERENCE",
        ],
        "safety_flags": [
            "PASSIVE_ONLY",
            "NO_TRANSMISSION",
            "NO_JAMMING",
            "NO_SPOOFING",
            "NO_RF_INJECTION",
            "NO_DEAUTHENTICATION",
            "NO_EVIL_TWIN",
            "NO_IMSI_CATCHER",
            "NO_ROGUE_BTS",
            "NO_WEAPON_TARGETING",
            "NO_ELECTRONIC_ATTACK",
        ],
        "unknowns": unknowns,
        "knowledge_gaps": gaps,
        "recommended_next_actions": next_actions,
        "specialist_handoffs": handoffs,
        "limitations": [
            "This scaffold does not perform FFT/PSD/waterfall DSP itself.",
            "It consumes deterministic feature-level inputs only.",
            "It does not access live sensors unless externally configured by authorized tooling.",
            "It does not decode private communications.",
            "It does not attribute signals to devices, owners, or persons without authorized evidence.",
            "Location conclusions remain coarse and uncertainty-propagated.",
        ],
        "frequency_summary": freq_summary,
        "bandwidth_summary": bw_summary,
        "power_summary": power_summary,
        "rssi_summary": rssi_summary,
        "snr_summary": snr_summary,
        "noise_floor_summary": noise_summary,
        "detection_counts": detection_counts,
        "signal_class_counts": class_counts,
        "dual_ai_review": dual,
        "not_facts": not_facts,
        "graphical_memory": graph,
        "validation_issues": issues,
        "replay_manifest": {
            "generated_at": started,
            "finished_at": utcnow_iso(),
            "code_version": VERSION,
            "input_path": input_path,
            "input_sha256": input_hash,
            "dsp_provenance_required": True,
            "note": "Replay requires raw capture hash, sensor config, calibration, clock, FFT/window/threshold parameters, and detector version from the deterministic DSP pipeline.",
        },
    }

    result["required_analyst_summary"] = analyst_summary(result)
    return result


# -----------------------------------------------------------------------------
# Template
# -----------------------------------------------------------------------------

def template_case() -> Dict[str, Any]:
    return {
        "_template_note": "Placeholder values only. Replace with deterministic DSP outputs from authorized sensors. Do not treat this template as real measurement.",
        "case_id": "CASE-EXAMPLE",
        "task_id": "TASK-EXAMPLE",
        "objective": "Authorized passive spectrum occupancy review in a controlled facility.",
        "questions": [
            "What RF activity is observed?",
            "Which frequencies are occupied?",
            "What protocol families are plausible candidates?",
            "What remains uncertain?",
        ],
        "scope": {
            "authorized_only": True,
            "passive_only": True,
            "metadata_minimization": True,
            "no_private_content_access": True,
        },
        "authorization": {
            "lawful_basis": "INTERNAL_AUTHORIZED_SPECTRUM_MONITORING",
            "purpose": "DEFENSIVE_RF_ENVIRONMENT_INTELLIGENCE",
            "approval_reference": "AUTH-RECORD-001",
            "data_retention": "MINIMUM_NECESSARY",
        },
        "model_mode": "LOCAL_ONLY",
        "sensors": [
            {
                "sensor_id": "S1",
                "sensor_type": "AUTHORIZED_SPECTRUM_ANALYZER",
                "hardware": "EXAMPLE_MODEL",
                "firmware": "EXAMPLE_FW",
                "antenna": "EXAMPLE_ANTENNA",
                "gain_db": 0,
                "orientation_deg": None,
                "location": "FACILITY_ZONE_A",
                "location_accuracy_m": 5,
                "frequency_range_hz": [2_400_000_000, 2_483_500_000],
                "sample_rate_limits_sps": [1_000_000, 20_000_000],
                "calibration_state": "CALIBRATED",
                "clock_source": "GPSDO",
                "time_accuracy_us": 1,
                "noise_characteristics": "KNOWN_BASELINE",
                "upstream_receiver_id": "RX-1",
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_to": "2026-12-31T23:59:59Z",
            }
        ],
        "evidence": [
            {
                "evidence_id": "EVD-1",
                "case_id": "CASE-EXAMPLE",
                "sensor_id": "S1",
                "capture_id": "CAP-1",
                "source_type": "PSD_EXPORT",
                "start_time": "2026-10-08T09:00:00Z",
                "end_time": "2026-10-08T09:15:00Z",
                "center_frequency_hz": 2_437_000_000,
                "frequency_span_hz": 50_000_000,
                "sample_rate_sps": 10_000_000,
                "bandwidth_hz": 20_000_000,
                "sensor_location_reference": "FACILITY_ZONE_A",
                "antenna_reference": "EXAMPLE_ANTENNA",
                "calibration_reference": "CAL-REC-001",
                "content_hash": "SHA256_FROM_RAW_CAPTURE",
                "raw_capture_reference": "local:///captures/cap1.iq",
                "processing_pipeline": "deterministic_dsp_v1",
                "parser_version": "1.0.0",
                "analysis_version": VERSION,
                "authorization_context": "AUTHORIZED",
                "sanitized_for_cloud": False,
            }
        ],
        "signal_events": [
            {
                "event_id": "EV-1",
                "sensor_id": "S1",
                "evidence_id": "EVD-1",
                "start_time": "2026-10-08T09:00:05Z",
                "end_time": "2026-10-08T09:00:06Z",
                "center_frequency_hz": 2_437_000_000,
                "frequency_uncertainty_hz": 10_000,
                "bandwidth_hz": 20_000_000,
                "power_dbm": -42.5,
                "rssi_dbm": -67,
                "snr_db": 18.2,
                "noise_floor_dbm": -92,
                "detection_state": "DETECTED",
                "signal_class": "BURST",
                "modulation_candidates": ["OFDM_CANDIDATE"],
                "protocol_candidates": ["Wi-Fi-family candidate"],
                "periodicity": None,
                "fingerprint": {
                    "spectral_shape": "example",
                    "timing_behavior": "example",
                },
                "notes": "Feature-level export from deterministic DSP; not a live measurement by this script.",
            }
        ],
        "known_emitters": [
            {
                "emitter_id": "AP-01",
                "center_frequency_hz": 2_437_000_000,
                "authorized_asset_id": "AUTHORIZED_ASSET_001",
            }
        ],
        "known_channels": [
            {
                "channel": "Wi-Fi Channel 6",
                "center_frequency_hz": 2_437_000_000,
                "bandwidth_hz": 20_000_000,
            }
        ],
        "frequency_allocations": [
            {
                "band": "2.4 GHz ISM",
                "service_context": "UNLICENSED_SHARED",
                "note": "Allocation context does not prove observed emitter identity.",
            }
        ],
        "time_range": {
            "start_time": "2026-10-08T09:00:00Z",
            "end_time": "2026-10-08T09:15:00Z",
        },
        "existing_facts": [],
        "existing_hypotheses": [],
        "existing_contradictions": [],
        "budget": "EXAMPLE",
        "deadline": "EXAMPLE",
    }


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="TRACEATLAS RFINT passive-first analysis scaffold. Consumes deterministic RF feature exports; does not transmit, jam, spoof, inject, or track private persons."
    )
    parser.add_argument("--input", "-i", help="Path to RF input JSON")
    parser.add_argument("--output", "-o", default="rfint_result.json", help="Output RFINTResult JSON path")
    parser.add_argument("--write-template", action="store_true", help="Print a safe input template and exit")
    args = parser.parse_args()

    if args.write_template:
        print(json.dumps(template_case(), indent=2, default=str))
        return

    if not args.input:
        parser.error("--input is required unless --write-template is used")

    path = Path(args.input)
    if not path.exists():
        raise SystemExit(f"Input file not found: {path}")

    raw = path.read_bytes()
    input_hash = sha256_bytes(raw)

    try:
        case = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise SystemExit(f"Failed to parse input JSON: {exc}")

    if not isinstance(case, dict):
        raise SystemExit("Input JSON must be an object")

    result = analyze(case, str(path), input_hash)

    out = Path(args.output)
    out.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")

    print(
        json.dumps(
            {
                "status": result.get("status"),
                "anomaly_risk": result.get("anomaly_risk"),
                "output": str(out),
                "summary": result.get("required_analyst_summary"),
            },
            indent=2,
            default=str,
        )
    )


if __name__ == "__main__":
    main()