# marcybint_short_main.py
# Defensive MARCYBINT skeleton: asset resolution + AIS/GNSS anomaly + fact gate + human review.
# No scanning, exploitation, AIS/GNSS manipulation, navigation commands, or OT changes.

import json
import re
import math
from datetime import datetime, timezone

SAFETY_CRITICAL = {
    "ECDIS", "AIS", "GNSS_RECEIVER", "RADAR", "VDR", "GMDSS",
    "ENGINE_CONTROL", "PROPULSION", "STEERING", "BALLAST",
    "POWER_MANAGEMENT", "DP_SYSTEM"
}


def digits(value):
    return re.sub(r"\D", "", str(value or ""))


def imo_ok(imo):
    d = digits(imo)
    if len(d) != 7:
        return False
    checksum = sum(int(d[i]) * (7 - i) for i in range(6)) % 10
    return checksum == int(d[6])


def parse_ts(value):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        return None


def distance_nm(lat1, lon1, lat2, lon2):
    # Deterministic nautical-mile distance.
    earth_radius_nm = 3440.065
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = phi2 - phi1
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return 2 * earth_radius_nm * math.asin(math.sqrt(a))


def policy_blocked(objective):
    o = (objective or "").lower()

    # Block explicit offensive / unauthorized / control-plane actions.
    if re.search(r"\b(unauthorized\s+access|penetration\s+test|pentest|active\s+scan)\b", o):
        return True
    if re.search(r"\b(exploit|hack|spoof|jam|manipulate|inject|disable|sabotage|defeat)\b", o):
        return True
    if re.search(r"\b(send|transmit)\b.*\b(ais|gnss|distress|navigation|command|order)\b", o):
        return True
    if re.search(r"\b(change|modify|alter)\b.*\b(route|course|chart|charts|ot|plc|engine|ballast|steering|navigation)\b", o):
        return True

    return False


def analyze(case):
    case_id = case.get("case_id", "CASE")
    task_id = case.get("task_id", "TASK")
    objective = case.get("objective", "")

    evidence = [{
        "id": "EV-INPUT",
        "source": "authorized_case_input",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "note": "Input-only defensive analysis; no live sensor access assumed."
    }]

    if policy_blocked(objective):
        return {
            "case_id": case_id,
            "task_id": task_id,
            "status": "POLICY_BLOCKED",
            "safety": "HUMAN_REVIEW_REQUIRED",
            "vessel": {},
            "findings": [{
                "kind": "POLICY_BLOCKED",
                "statement": "Request is outside defensive maritime cyber-intelligence boundaries.",
                "human_review": True
            }],
            "recommendations": [
                "Continue only with defensive, authorized, evidence-first analysis.",
                "Do not scan, exploit, spoof, jam, manipulate, or send maritime control commands."
            ],
            "unknowns": ["Authorization/scope needs clarification before any operational action."],
            "evidence": evidence
        }

    # -------------------------
    # 1) Vessel / asset resolution
    # -------------------------
    vessel = {
        "imo": digits(case.get("imo_number")),
        "mmsi": digits(case.get("mmsi")),
        "call_sign": str(case.get("call_sign") or "").upper(),
        "name": case.get("ship_name") or case.get("name"),
        "owner": case.get("ship_owner") or case.get("owner"),
        "operator": case.get("operator"),
        "technical_manager": case.get("technical_manager"),
        "charterer": case.get("charterer"),
        "flag": case.get("flag_state")
    }

    unknowns = []
    vessel["identity_confidence"] = "IDENTIFIER_CANDIDATE"

    if vessel["imo"] and imo_ok(vessel["imo"]):
        vessel["identity_confidence"] = "IMO_SUPPORTED"
    elif vessel["imo"]:
        unknowns.append("IMO checksum invalid or unverified")

    if vessel["mmsi"] and vessel["imo"]:
        vessel["identity_confidence"] = "MULTI_IDENTIFIER_VERIFIED"
    elif vessel["mmsi"]:
        vessel["identity_confidence"] = "MMSI_SUPPORTED"

    findings = []

    # -------------------------
    # 2) AIS anomaly analysis
    # -------------------------
    ais_points = case.get("ais_data") or []
    if not ais_points:
        findings.append({
            "kind": "AIS_NO_DATA",
            "statement": "No AIS data supplied; cannot assess AIS behavior."
        })

    parsed_ais = []
    for p in ais_points:
        t = parse_ts(p.get("timestamp"))
        lat = p.get("lat")
        lon = p.get("lon")
        if t and isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
            parsed_ais.append((t, lat, lon))
        else:
            findings.append({
                "kind": "AIS_INCOMPLETE",
                "statement": "AIS point missing valid timestamp or coordinates."
            })

    parsed_ais.sort(key=lambda x: x[0])

    for a, b in zip(parsed_ais, parsed_ais[1:]):
        hours = (b[0] - a[0]).total_seconds() / 3600.0
        if hours <= 0:
            continue

        dist = distance_nm(a[1], a[2], b[1], b[2])
        speed_kn = dist / hours

        if speed_kn > 50:
            findings.append({
                "kind": "POSITION_SEQUENCE_INCONSISTENT",
                "statement": (
                    f"AIS-derived speed {speed_kn:.1f} kn exceeds plausible baseline. "
                    "This is an AIS anomaly, not proof of spoofing or cyberattack."
                ),
                "human_review": True
            })

        if hours > 6:
            findings.append({
                "kind": "AIS_GAP",
                "statement": "AIS gap > 6h. Possible coverage, equipment, maintenance, power, or operational causes."
            })

    # -------------------------
    # 3) GNSS anomaly analysis
    # -------------------------
    gnss_records = case.get("gnss_data") or []
    if not gnss_records:
        findings.append({
            "kind": "GNSS_NO_DATA",
            "statement": "No GNSS logs supplied; cannot assess GNSS health."
        })

    for g in gnss_records:
        if g.get("position_integrity_alarm") or g.get("alarm"):
            findings.append({
                "kind": "GNSS_ANOMALY",
                "statement": (
                    "GNSS integrity/alarm observed. Causes may include receiver fault, antenna fault, "
                    "environment, interference, configuration, maintenance, or cyber event. Not automatically attack."
                ),
                "human_review": True
            })

        if g.get("time_anomaly"):
            findings.append({
                "kind": "GNSS_TIME_ANOMALY",
                "statement": "GNSS/time inconsistency observed. Check clock sources and time synchronization.",
                "human_review": True
            })

    # -------------------------
    # 4) Shared sensor dependency
    # -------------------------
    arch = case.get("network_architecture") or {}
    consumers = set(arch.get("consumers") or [])
    if arch.get("gnss_source_id") and {"AIS", "ECDIS"}.issubset(consumers):
        findings.append({
            "kind": "SHARED_SENSOR_DEPENDENCY",
            "statement": "AIS and ECDIS consume the same GNSS source. Agreement is not independent confirmation.",
            "human_review": True
        })

    # -------------------------
    # 5) Cyber-physical correlation candidate
    # -------------------------
    has_ais_anomaly = any(f["kind"] == "POSITION_SEQUENCE_INCONSISTENT" for f in findings)
    has_gnss_anomaly = any(f["kind"] == "GNSS_ANOMALY" for f in findings)

    if has_ais_anomaly and has_gnss_anomaly:
        findings.append({
            "kind": "CYBER_PHYSICAL_CORRELATION_CANDIDATE",
            "statement": (
                "AIS and GNSS anomalies co-occur. Check shared sensor dependency, maintenance, and hardware faults "
                "before assigning cyber causation."
            ),
            "human_review": True
        })

    # -------------------------
    # 6) Fact gate for cyberattack claims
    # -------------------------
    claims = case.get("claims") or {}
    external_evidence = case.get("evidence") or {}

    if claims.get("cyberattack"):
        independent_nav = bool(external_evidence.get("independent_navigation_source"))
        cyber_artifacts = bool(external_evidence.get("cyber_artifacts"))
        physical_impact = bool(external_evidence.get("physical_impact_evidence"))

        if not (independent_nav and cyber_artifacts):
            findings.append({
                "kind": "FACT_GATE_CYBERATTACK_INCONCLUSIVE",
                "statement": (
                    "Cyberattack claim lacks independent cyber evidence plus independent navigation/physical evidence. "
                    "Treat as INCONCLUSIVE."
                ),
                "human_review": True
            })

        if physical_impact and not cyber_artifacts:
            findings.append({
                "kind": "FACT_GATE_PHYSICAL_NOT_CYBER",
                "statement": "Physical/maritime impact observed, but cyber causation is not proven.",
                "human_review": True
            })

    # -------------------------
    # 7) Safety + status + recommendations
    # -------------------------
    systems = set(case.get("systems") or [])
    safety = (
        "HUMAN_REVIEW_REQUIRED"
        if systems & SAFETY_CRITICAL or any(f.get("human_review") for f in findings)
        else "NONE"
    )

    status = "OK"
    if any(
        f["kind"].startswith(("POSITION_SEQUENCE", "GNSS_ANOMALY", "FACT_GATE", "CYBER_PHYSICAL"))
        for f in findings
    ):
        status = "INCONCLUSIVE"

    if unknowns and status == "OK":
        status = "PARTIAL"

    recommendations = [
        "Preserve authorized logs, AIS/GNSS datasets, VDR references, and configuration snapshots.",
        "Verify anomaly against an independent navigation source where authorized: radar, VTS, visual, inertial, or separate receiver.",
        "Check maintenance windows, firmware/software changes, vendor remote sessions, and hardware faults before cyber causation.",
        "Do not alter routes, charts, AIS/GNSS transmissions, OT settings, or safety systems via this analysis.",
        "Engage vessel master / technical superintendent / OEM for any operational or safety-critical action."
    ]

    if safety != "NONE":
        recommendations.append("HUMAN_REVIEW_REQUIRED before any operational action.")

    source_reliability = {
        "input_case": "AUTHORIZED_ONLY_IF_CONFIGURED",
        "ais": "SELF_REPORTED_TRANSMISSION_NOT_GROUND_TRUTH",
        "gnss": "RECEIVER_OUTPUT_REQUIRES_INDEPENDENCE_AND_DIAGNOSTICS"
    }

    limitations = [
        "Skeleton only; no live AIS/GNSS/log connector is assumed.",
        "No scanning, exploitation, spoofing, jamming, or maritime control actions.",
        "Conclusions require authorized evidence, source independence checks, and human maritime safety review."
    ]

    return {
        "case_id": case_id,
        "task_id": task_id,
        "status": status,
        "safety": safety,
        "vessel": vessel,
        "findings": findings,
        "recommendations": recommendations,
        "unknowns": unknowns,
        "source_reliability": source_reliability,
        "limitations": limitations,
        "evidence": evidence
    }


if __name__ == "__main__":
    demo_case = {
        "case_id": "DEMO-001",
        "task_id": "T1",
        "objective": "Defensively assess AIS/GNSS anomaly for vessel TEST",
        "scope": {"authorized_defensive": True},

        "imo_number": "9074729",
        "mmsi": "235095000",
        "call_sign": "5BXX",
        "ship_name": "TEST",
        "ship_owner": "Owner Co",
        "operator": "Operator Co",
        "technical_manager": "Manager Co",
        "charterer": "Charterer Co",
        "flag_state": "MT",

        "systems": ["ECDIS", "AIS", "GNSS_RECEIVER", "RADAR"],

        "network_architecture": {
            "gnss_source_id": "GNSS-1",
            "consumers": ["AIS", "ECDIS", "BRIDGE_DISPLAY"]
        },

        "ais_data": [
            {"timestamp": "2026-10-09T10:00:00Z", "lat": 36.0, "lon": 14.0, "sog": 12.0},
            {"timestamp": "2026-10-09T10:05:00Z", "lat": 37.0, "lon": 14.0, "sog": 12.0}
        ],

        "gnss_data": [
            {"timestamp": "2026-10-09T10:02:00Z", "position_integrity_alarm": True}
        ],

        "claims": {
            "cyberattack": True
        },

        "evidence": {
            "independent_navigation_source": False,
            "cyber_artifacts": False,
            "physical_impact_evidence": False
        }
    }

    result = analyze(demo_case)
    print(json.dumps(result, indent=2))