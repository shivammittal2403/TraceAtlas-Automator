#!/usr/bin/env python3
"""
TRACEATLAS SCADAINT — Compact safe defensive starter.

Mode: DEFENSIVE / PASSIVE-FIRST / AUTHORIZED / SAFETY-FIRST / EVIDENCE-FIRST.

Hard boundaries:
- Does NOT write to PLCs/RTUs/HMIs/SCADA controllers.
- Does NOT change setpoints, process values, ladder logic, firmware, alarms,
  interlocks, safety systems, protective relays, valves, breakers, motors, pumps.
- Does NOT exploit, scan, probe, fuzz, brute-force, spoof, MITM, jam, flood,
  reboot, or otherwise disrupt live OT/ICS/SCADA systems.
- Does NOT use default/stolen/exposed credentials against live assets.
- Does NOT provide sabotage, process manipulation, safety bypass, or physical
  damage optimization.
- Treats engineering files, logs, PCAP-derived metadata, vendor docs, and alarm
  text as untrusted evidence, not instructions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import unicodedata
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

VERSION = "0.1.0-scadaint-safe-compact-starter"

ALLOWED_SCOPES = {
    "public_and_authorized_records",
    "authorized_case_evidence",
    "authorized_ot_records",
    "provided_records_only",
}

PROHIBITED_PATTERNS: List[Tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"(?i)\b(write|send|inject|upload|download|change|modify|alter|set|setpoint|"
            r"logic|program|firmware|value|command|start|stop|open|close|operate)\b"
            r".*\b(plc|rtu|controller|scada|hmi|industrial|process|safety|interlock|"
            r"valve|breaker|motor|pump|setpoint|field\s+device)\b"
        ),
        "PROCESS_OR_CONTROLLER_MANIPULATION",
    ),
    (
        re.compile(
            r"(?i)\b(disable|bypass|defeat|override|alter|modify)\b"
            r".*\b(alarm|interlock|safety|sis|emergency\s+shutdown|protective\s+relay|"
            r"trip|shutdown)\b"
        ),
        "SAFETY_BYPASS_OR_MODIFICATION",
    ),
    (
        re.compile(
            r"(?i)\b(exploit|attack|breach|compromise|pwn|rce|shell|payload)\b"
            r".*\b(plc|rtu|scada|hmi|ics|ot|industrial|controller|engineering\s+workstation|historian)\b"
        ),
        "ICS_EXPLOITATION_REQUEST",
    ),
    (
        re.compile(
            r"(?i)\b(scan|probe|enumerate|fuzz|brute[- ]force|password\s+spray|"
            r"credential\s+stuff|port\s+scan|service\s+enumeration)\b"
            r".*\b(live|ot|ics|scada|plc|rtu|hmi|industrial|controller)\b"
        ),
        "UNAUTHORIZED_ACTIVE_OT_VALIDATION",
    ),
    (
        re.compile(
            r"(?i)\b(use|try|test|validate|leverage)\b"
            r".*\b(default\s+credential|factory\s+default|leaked\s+credential|"
            r"stolen\s+credential|exposed\s+credential|service\s+credential)\b"
            r".*\b(ot|ics|scada|plc|rtu|hmi|live|device)\b"
        ),
        "OT_CREDENTIAL_MISUSE",
    ),
    (
        re.compile(
            r"(?i)\b(spoof|mitm|man[- ]in[- ]the[- ]middle|arp\s+spoof|poison|jam|"
            r"flood|dos|ddos|reboot|communications\s+loss|packet\s+loss)\b"
            r".*\b(ot|ics|scada|plc|rtu|hmi|industrial|controller|fieldbus|telemetry|wireless)\b"
        ),
        "OT_SPOOFING_OR_DISRUPTION",
    ),
    (
        re.compile(
            r"(?i)\b(sabotage|disrupt|damage|destroy|shutdown\s+plant|process\s+manipulation|"
            r"physical\s+damage|failure[- ]inducing|destructive)\b"
            r".*\b(plant|process|industrial|scada|ics|ot|equipment|safety)\b"
        ),
        "SABOTAGE_OR_PROCESS_DISRUPTION",
    ),
]

ASSET_TYPES = {
    "SCADA_SERVER", "HMI", "PLC", "RTU", "DCS_CONTROLLER", "ENGINEERING_WORKSTATION",
    "HISTORIAN", "OPC_SERVER", "OPC_CLIENT", "DATA_CONCENTRATOR", "IED",
    "PROTECTIVE_RELAY", "SIS_COMPONENT", "SAFETY_CONTROLLER", "REMOTE_IO",
    "SENSOR", "ACTUATOR", "VFD", "MOTOR_CONTROLLER", "INDUSTRIAL_GATEWAY",
    "PROTOCOL_CONVERTER", "INDUSTRIAL_SWITCH", "INDUSTRIAL_FIREWALL", "ROUTER",
    "REMOTE_ACCESS_GATEWAY", "JUMP_HOST", "TIME_SERVER", "DATABASE",
    "APPLICATION_SERVER", "UNKNOWN_OT_ASSET", "UNKNOWN",
}

ASSET_ROLES = ASSET_TYPES | {
    "SUPERVISORY_SERVER", "DATA_COLLECTOR", "OPERATOR_INTERFACE", "UNKNOWN",
}

ZONE_TYPES = {
    "CONTROL_ZONE", "SAFETY_ZONE", "SUPERVISORY_ZONE", "HISTORIAN_ZONE",
    "OPERATIONS_ZONE", "IDMZ", "ENTERPRISE_ZONE", "REMOTE_SITE",
    "VENDOR_ACCESS_ZONE", "WIRELESS_OT_ZONE", "UNKNOWN",
}

PURDUE_LEVELS = {
    "LEVEL_0", "LEVEL_1", "LEVEL_2", "LEVEL_3", "LEVEL_3_5",
    "LEVEL_4", "LEVEL_5", "UNKNOWN",
}

PROTOCOLS = {
    "MODBUS_TCP", "DNP3_TCP", "IEC_60870_5_104", "IEC_61850", "OPC_UA",
    "OPC_DA", "ETHERNET_IP", "CIP", "PROFINET", "S7COMM", "BACNET",
    "MQTT", "OTHER", "UNKNOWN",
}

OPERATION_CLASSES = {
    "READ", "WRITE", "CONTROL", "CONFIGURATION", "DIAGNOSTIC", "UNKNOWN",
}

ALARM_PRIORITIES = {
    "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNKNOWN",
}

EVENT_TYPES = {
    "OPERATOR_LOGIN", "ENGINEERING_ACTION", "CONFIGURATION_CHANGE",
    "COMMUNICATION_FAULT", "DEVICE_RESTART", "MODE_CHANGE",
    "MAINTENANCE_EVENT", "ALARM", "OTHER", "UNKNOWN",
}

LIFECYCLE_STATES = {
    "PLANNED", "INSTALLED", "COMMISSIONING", "ACTIVE", "MAINTENANCE",
    "STANDBY", "DECOMMISSIONED", "REPLACED", "UNKNOWN",
}

CRITICALITY_STATES = {
    "MISSION_CRITICAL", "BUSINESS_CRITICAL", "HIGH", "MEDIUM", "LOW",
    "INFORMATIONAL", "UNKNOWN",
}

SAFETY_RELEVANCE_STATES = {
    "SAFETY_CRITICAL", "PROTECTIVE", "SIS_RELEVANT", "MONITORING_ONLY",
    "NON_SAFETY", "UNKNOWN",
}

PHYSICAL_IMPACT_STATES = {
    "NO_OBSERVED_IMPACT", "MONITORING_DEGRADED", "CONTROL_DEGRADED",
    "PROCESS_INTERRUPTION", "SAFETY_RELEVANT_EVENT", "ENVIRONMENTAL_RELEVANCE",
    "PHYSICAL_DAMAGE_REPORTED", "UNKNOWN",
}

INCIDENT_TYPES = {
    "UNEXPECTED_CONFIGURATION_CHANGE", "UNAUTHORIZED_ENGINEERING_ACCESS",
    "NEW_CROSS_ZONE_FLOW", "ABNORMAL_PROCESS_VALUE", "UNEXPECTED_SHUTDOWN",
    "MALWARE_DETECTED", "ACCOUNT_MISUSE", "REMOTE_ACCESS_ANOMALY",
    "OTHER", "UNKNOWN",
}

VULN_APPLICABILITY_STATES = {
    "APPLICABLE_PENDING_VALIDATION", "POSSIBLE_PENDING_FIRMWARE",
    "POSSIBLE", "NOT_APPLICABLE_BASED_ON_MISMATCH", "UNKNOWN",
}

EXPLOIT_AVAILABILITY_STATES = {
    "NO_PUBLIC_EXPLOIT_KNOWN", "PUBLIC_POC_REPORTED", "EXPLOIT_REPORTED",
    "KNOWN_EXPLOITATION_REPORTED", "UNKNOWN",
}

SOURCE_RELIABILITY: Dict[str, float] = {
    "controller_log": 0.86,
    "authorized_ot_sensor": 0.86,
    "scada_server_log": 0.84,
    "security_advisory": 0.84,
    "engineering_project": 0.82,
    "alarm_system": 0.80,
    "historian": 0.78,
    "vendor_documentation": 0.78,
    "incident_report": 0.76,
    "asset_inventory": 0.70,
    "threat_report": 0.60,
    "operator_statement": 0.55,
    "unknown": 0.30,
}

PORT_PROTOCOL_HINTS = {
    502: "MODBUS_TCP",
    20000: "DNP3_TCP",
    102: "S7COMM",
    4840: "OPC_UA",
    44818: "ETHERNET_IP",
    1883: "MQTT",
}

MODBUS_READ_FUNCTIONS = {1, 2, 3, 4}
MODBUS_WRITE_FUNCTIONS = {5, 6, 15, 16, 22, 23}
MODBUS_DIAG_FUNCTIONS = {7, 8, 10, 11, 12, 14, 17, 18, 19, 20, 21, 24, 43, 44}


# --------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def stable_id(prefix: str, *parts: Any) -> str:
    raw = "|".join(str(json_safe(p)) for p in parts)
    return f"{prefix}-{hashlib.sha1(raw.encode('utf-8')).hexdigest()[:16]}"


def json_safe(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {str(k): json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [json_safe(x) for x in obj]
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    return str(obj)


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    s = unicodedata.normalize("NFKC", str(value))
    s = re.sub(r"[\u200b\u200c\u200d\u2060\ufeff]", "", s)
    return s.strip()


def normalize_token(value: Any) -> str:
    s = normalize_text(value).upper()
    s = re.sub(r"[^A-Z0-9]+", "_", s)
    return s.strip("_")


def iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if isinstance(dt, datetime) else None


def parse_time(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    s = normalize_text(value)
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        pass
    for fmt in (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%Y-%m",
        "%Y",
    ):
        try:
            dt = datetime.strptime(s, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except Exception:
            continue
    return None


def parse_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    s = normalize_text(value)
    if not s:
        return None
    try:
        return int(float(s))
    except Exception:
        return None


def parse_float(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    s = normalize_text(value).replace(",", "")
    m = re.search(r"[-+]?\d*\.?\d+(?:[eE][-+]?\d+)?", s)
    if not m:
        return None
    try:
        return float(m.group())
    except Exception:
        return None


def source_list(*items: Any) -> List[str]:
    out: List[str] = []
    for it in items:
        if it is None:
            continue
        if isinstance(it, list):
            out.extend(normalize_text(x) for x in it if normalize_text(x))
        else:
            s = normalize_text(it)
            if s:
                out.append(s)
    return list(dict.fromkeys(out))


def unique_preserve(items: Iterable[Any]) -> List[Any]:
    seen: Set[str] = set()
    out = []
    for item in items:
        key = json.dumps(json_safe(item), sort_keys=True, ensure_ascii=False)
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, value))


def norm_enum(value: Any, allowed: Set[str], default: str = "UNKNOWN") -> str:
    s = normalize_token(value)
    return s if s in allowed else default


def mask_value(value: Any, keep_prefix: int = 2, keep_suffix: int = 2) -> str:
    s = normalize_text(value)
    if not s:
        return ""
    if len(s) <= keep_prefix + keep_suffix:
        return "*" * len(s)
    return s[:keep_prefix] + "*" * (len(s) - keep_prefix - keep_suffix) + s[-keep_suffix:]


def mask_ip(value: Any) -> str:
    s = normalize_text(value)
    if not s:
        return ""
    if ":" in s:
        return mask_value(s, 2, 2)
    parts = s.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.*.*.{parts[3]}"
    return mask_value(s, 2, 2)


def within_time(ts: Optional[datetime], start: Optional[datetime], end: Optional[datetime]) -> bool:
    if ts is None:
        return False
    if start and ts < start:
        return False
    if end and ts > end:
        return False
    return True


# --------------------------------------------------------------------
# Policy / authorization
# --------------------------------------------------------------------

def collect_intent_text(manifest: Dict[str, Any]) -> str:
    parts = [
        normalize_text(manifest.get("objective", "")),
        " ".join(normalize_text(q) for q in manifest.get("questions", []) or []),
        " ".join(normalize_text(x) for x in manifest.get("requested_actions", []) or []),
    ]
    return " ".join(parts)


def policy_screen(manifest: Dict[str, Any]) -> List[str]:
    blob = collect_intent_text(manifest)
    blocked = []
    for pat, label in PROHIBITED_PATTERNS:
        if pat.search(blob):
            blocked.append(label)
    return list(dict.fromkeys(blocked))


def authorization_check(manifest: Dict[str, Any]) -> Tuple[bool, List[str]]:
    auth = manifest.get("authorization") or {}
    reasons: List[str] = []

    if not auth.get("approved"):
        reasons.append("AUTHORIZATION_MISSING_OR_NOT_APPROVED")

    scope = auth.get("scope", "provided_records_only")
    if scope not in ALLOWED_SCOPES:
        reasons.append("UNSUPPORTED_SCOPE")

    mode = auth.get("model_mode", "LOCAL_ONLY")
    if mode not in {"LOCAL_ONLY", "HYBRID", "CLOUD"}:
        reasons.append("UNKNOWN_MODEL_MODE")
    if mode == "CLOUD" and not auth.get("cloud_approved"):
        reasons.append("CLOUD_PROCESSING_NOT_APPROVED")

    if manifest.get("active_validation_requested") and not auth.get("active_validation_approved"):
        reasons.append("ACTIVE_VALIDATION_NOT_APPROVED")

    if (
        manifest.get("pcaps") or manifest.get("flows") or manifest.get("scada_logs")
        or manifest.get("controller_metadata") or manifest.get("config_exports")
    ) and not auth.get("ot_data_approved"):
        reasons.append("OT_DATA_NOT_APPROVED")

    return len(reasons) == 0, reasons


# --------------------------------------------------------------------
# Sources / pedigree / independence
# --------------------------------------------------------------------

def collect_referenced_source_ids(obj: Any) -> Set[str]:
    ids: Set[str] = set()

    def walk(x: Any) -> None:
        if isinstance(x, dict):
            for k, v in x.items():
                if k in ("source_id", "source_ids"):
                    if isinstance(v, list):
                        ids.update(normalize_text(i) for i in v if normalize_text(i))
                    else:
                        s = normalize_text(v)
                        if s:
                            ids.add(s)
                walk(v)
        elif isinstance(x, list):
            for i in x:
                walk(i)

    walk(obj)
    return ids


def ingest_sources(manifest: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    sources: Dict[str, Dict[str, Any]] = {}
    for s in manifest.get("sources", []) or []:
        sid = normalize_text(s.get("source_id"))
        if not sid:
            continue
        stype = normalize_text(s.get("source_type", "unknown")).lower().replace("-", "_").replace(" ", "_")
        rel = s.get("reliability", SOURCE_RELIABILITY.get(stype, SOURCE_RELIABILITY["unknown"]))
        sources[sid] = {
            "source_id": sid,
            "source_type": stype,
            "upstream_source_id": normalize_text(s.get("upstream_source_id")) or None,
            "reliability": clamp(float(rel)),
            "observed_at": normalize_text(s.get("observed_at")) or None,
            "limitations": list(s.get("limitations", []) or []),
        }

    for sid in collect_referenced_source_ids(manifest):
        if sid not in sources:
            sources[sid] = {
                "source_id": sid,
                "source_type": "unknown",
                "upstream_source_id": None,
                "reliability": SOURCE_RELIABILITY["unknown"],
                "observed_at": None,
                "limitations": ["Source referenced but not defined in manifest."],
            }
    return sources


def resolve_source_root(sid: str, sources: Dict[str, Dict[str, Any]], memo: Dict[str, str], visiting: Set[str]) -> str:
    if sid in memo:
        return memo[sid]
    if sid in visiting:
        return sid
    visiting.add(sid)
    src = sources.get(sid)
    if not src or not src.get("upstream_source_id"):
        memo[sid] = sid
    else:
        memo[sid] = resolve_source_root(src["upstream_source_id"], sources, memo, visiting)
    visiting.discard(sid)
    return memo[sid]


def build_source_roots(sources: Dict[str, Dict[str, Any]]) -> Dict[str, str]:
    memo: Dict[str, str] = {}
    for sid in sources:
        resolve_source_root(sid, sources, memo, set())
    return memo


def source_family_ids(source_ids: List[str], roots: Dict[str, str]) -> List[str]:
    return list(dict.fromkeys(roots.get(sid, sid) for sid in source_ids))


def source_quality(source_ids: List[str], sources: Dict[str, Dict[str, Any]]) -> Tuple[float, float]:
    vals = [float(sources.get(sid, {}).get("reliability", SOURCE_RELIABILITY["unknown"])) for sid in source_ids]
    if not vals:
        return SOURCE_RELIABILITY["unknown"], SOURCE_RELIABILITY["unknown"]
    return max(vals), sum(vals) / len(vals)


def independence_state(families: List[str], sources: Dict[str, Dict[str, Any]], source_ids: List[str]) -> str:
    if not source_ids:
        return "UNKNOWN"
    if len(families) <= 1:
        return "DEPENDENT"
    rels = [sources.get(sid, {}).get("reliability", 0.3) for sid in source_ids]
    types = {sources.get(sid, {}).get("source_type", "unknown") for sid in source_ids}
    if len(types) == 1 and max(rels) < 0.70:
        return "PARTIALLY_DEPENDENT"
    if max(rels) >= 0.70:
        return "INDEPENDENT"
    return "PARTIALLY_DEPENDENT"


def source_assessment(sids: List[str], sources: Dict[str, Dict[str, Any]], roots: Dict[str, str]) -> Dict[str, Any]:
    fams = source_family_ids(sids, roots)
    state = independence_state(fams, sources, sids)
    max_rel, avg_rel = source_quality(sids, sources)
    return {
        "source_ids": sids,
        "source_families": fams,
        "state": state,
        "max_reliability": round(max_rel, 4),
        "avg_reliability": round(avg_rel, 4),
    }


# --------------------------------------------------------------------
# Ingestion
# --------------------------------------------------------------------

def ingest_sites(manifest: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for idx, s in enumerate(manifest.get("sites", []) or []):
        sid = normalize_text(s.get("site_id") or s.get("id") or f"SITE-{idx}")
        out[sid] = {
            "site_id": sid,
            "name": normalize_text(s.get("name")) or sid,
            "sector": normalize_text(s.get("sector")) or None,
            "facilities": source_list(s.get("facilities")),
            "plants": source_list(s.get("plants")),
            "process_areas": source_list(s.get("process_areas")),
            "source_ids": source_list(s.get("source_ids"), s.get("source_id")),
            "limitations": list(s.get("limitations", []) or []) + [
                "Site context is defensive architecture inventory only.",
            ],
        }
    return out


def ingest_assets(manifest: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    assets: Dict[str, Dict[str, Any]] = {}
    for idx, a in enumerate(manifest.get("assets", []) or []):
        aid = normalize_text(a.get("asset_id") or a.get("id") or f"ASSET-{idx}")
        atype = norm_enum(a.get("asset_type"), ASSET_TYPES)
        role = norm_enum(a.get("asset_role"), ASSET_ROLES, atype if atype in ASSET_ROLES else "UNKNOWN")
        protocols = [norm_enum(p, PROTOCOLS) for p in source_list(a.get("protocols"))]
        ips = [normalize_text(x).lower() for x in source_list(a.get("ip_addresses"), a.get("ip")) if normalize_text(x)]
        macs = [re.sub(r"[^0-9A-Fa-f]", "", normalize_text(x)).upper() for x in source_list(a.get("mac_addresses"), a.get("mac")) if normalize_text(x)]

        assets[aid] = {
            "asset_id": aid,
            "site_id": normalize_text(a.get("site_id")) or None,
            "asset_type": atype,
            "asset_role": role,
            "vendor": normalize_text(a.get("vendor")) or None,
            "product": normalize_text(a.get("product")) or None,
            "model": normalize_text(a.get("model")) or None,
            "hardware_revision": normalize_text(a.get("hardware_revision")) or None,
            "firmware_version": normalize_text(a.get("firmware_version")) or None,
            "software_version": normalize_text(a.get("software_version")) or None,
            "hostname": normalize_text(a.get("hostname")) or None,
            "ip_addresses": ips,
            "mac_addresses": macs,
            "zone": norm_enum(a.get("zone"), ZONE_TYPES),
            "purdue_level": norm_enum(a.get("purdue_level"), PURDUE_LEVELS),
            "protocols": [p for p in protocols if p != "UNKNOWN"] or ["UNKNOWN"],
            "connected_assets": source_list(a.get("connected_assets")),
            "process_function": normalize_text(a.get("process_function")) or None,
            "criticality": norm_enum(a.get("criticality"), CRITICALITY_STATES),
            "safety_relevance": norm_enum(a.get("safety_relevance"), SAFETY_RELEVANCE_STATES),
            "lifecycle_state": norm_enum(a.get("lifecycle_state"), LIFECYCLE_STATES),
            "first_seen": parse_time(a.get("first_seen")),
            "last_seen": parse_time(a.get("last_seen")),
            "source_ids": source_list(a.get("source_ids"), a.get("source_id")),
            "confidence": clamp(float(a.get("confidence", 0.65))),
            "limitations": list(a.get("limitations", []) or []) + [
                "Inventory is not current reality unless validated by passive evidence.",
                "Protocol use does not alone prove device role.",
                "Banner/version claims are not verified firmware facts.",
            ],
        }
    return assets


def classify_operation(protocol: str, function_code: Any, provided: Any) -> str:
    if provided:
        return norm_enum(provided, OPERATION_CLASSES)
    proto = normalize_token(protocol)
    fc = parse_int(function_code)
    if proto == "MODBUS_TCP" and fc is not None:
        if fc in MODBUS_READ_FUNCTIONS:
            return "READ"
        if fc in MODBUS_WRITE_FUNCTIONS:
            return "WRITE"
        if fc in MODBUS_DIAG_FUNCTIONS:
            return "DIAGNOSTIC"
    return "UNKNOWN"


def port_protocol_consistency(port: Optional[int], protocol: str) -> str:
    proto = normalize_token(protocol)
    hint = PORT_PROTOCOL_HINTS.get(port) if port is not None else None
    if not hint:
        return "UNKNOWN_NO_PORT_HINT"
    if proto == "UNKNOWN":
        return "UNKNOWN_PROTOCOL"
    if hint == proto:
        return "CONSISTENT"
    return "INCONSISTENT_PORT_PROTOCOL"


def ingest_flows(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for idx, f in enumerate(manifest.get("flows", []) or manifest.get("network_flows", []) or []):
        protocol = norm_enum(f.get("protocol"), PROTOCOLS)
        port = parse_int(f.get("port") or f.get("destination_port"))
        op = classify_operation(protocol, f.get("function_code"), f.get("operation_class"))
        out.append({
            "flow_id": normalize_text(f.get("flow_id") or f.get("id") or f"FLOW-{idx}"),
            "source_asset": normalize_text(f.get("source_asset") or f.get("src_asset")),
            "dest_asset": normalize_text(f.get("dest_asset") or f.get("dst_asset")),
            "protocol": protocol,
            "port": port,
            "service": normalize_text(f.get("service")) or None,
            "function_code": parse_int(f.get("function_code")),
            "operation_class": op,
            "message_category": normalize_text(f.get("message_category")) or None,
            "direction": normalize_text(f.get("direction")).upper() or "UNKNOWN",
            "first_seen": parse_time(f.get("first_seen")),
            "last_seen": parse_time(f.get("last_seen")),
            "bytes": parse_float(f.get("bytes")),
            "packets": parse_int(f.get("packets")),
            "new_relative_to_baseline": bool(f.get("new_relative_to_baseline")),
            "unexpected": bool(f.get("unexpected")),
            "source_ids": source_list(f.get("source_ids"), f.get("source_id")),
            "confidence": clamp(float(f.get("confidence", 0.60))),
            "port_protocol_consistency": port_protocol_consistency(port, protocol),
            "limitations": list(f.get("limitations", []) or []) + [
                "Network flow is not control command.",
                "Port is suggestive, not definitive protocol evidence.",
                "Write observation is not malicious activity without context.",
            ],
        })
    return out


def ingest_alarms(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for idx, a in enumerate(manifest.get("alarms", []) or manifest.get("alarm_logs", []) or []):
        out.append({
            "alarm_id": normalize_text(a.get("alarm_id") or a.get("id") or f"ALARM-{idx}"),
            "asset_id": normalize_text(a.get("asset_id")) or None,
            "site_id": normalize_text(a.get("site_id")) or None,
            "priority": norm_enum(a.get("priority"), ALARM_PRIORITIES),
            "first_occurrence": parse_time(a.get("first_occurrence") or a.get("timestamp")),
            "acknowledged": a.get("acknowledged"),
            "duration_seconds": parse_float(a.get("duration_seconds")),
            "recurrence_count": parse_int(a.get("recurrence_count")),
            "related_process_event": normalize_text(a.get("related_process_event")) or None,
            "source_ids": source_list(a.get("source_ids"), a.get("source_id")),
            "confidence": clamp(float(a.get("confidence", 0.60))),
            "limitations": ["Alarm is not incident automatically."],
        })
    return out


def ingest_events(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for idx, e in enumerate(manifest.get("events", []) or manifest.get("event_logs", []) or []):
        out.append({
            "event_id": normalize_text(e.get("event_id") or e.get("id") or f"EVENT-{idx}"),
            "asset_id": normalize_text(e.get("asset_id")) or None,
            "site_id": normalize_text(e.get("site_id")) or None,
            "event_type": norm_enum(e.get("event_type"), EVENT_TYPES),
            "timestamp": parse_time(e.get("timestamp") or e.get("occurred_at")),
            "account": normalize_text(e.get("account")) or None,
            "description": normalize_text(e.get("description")) or None,
            "source_ids": source_list(e.get("source_ids"), e.get("source_id")),
            "confidence": clamp(float(e.get("confidence", 0.60))),
            "limitations": ["Account name is not real-person attribution."],
        })
    return out


def ingest_config_changes(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for idx, c in enumerate(manifest.get("configuration_changes", []) or []):
        out.append({
            "change_id": normalize_text(c.get("change_id") or c.get("id") or f"CFG-{idx}"),
            "asset_id": normalize_text(c.get("asset_id")) or None,
            "site_id": normalize_text(c.get("site_id")) or None,
            "change_type": normalize_text(c.get("change_type")).upper() or "UNKNOWN",
            "old_version": normalize_text(c.get("old_version")) or None,
            "new_version": normalize_text(c.get("new_version")) or None,
            "changed_at": parse_time(c.get("changed_at")),
            "approved": c.get("approved"),
            "ticket": normalize_text(c.get("ticket")) or None,
            "source_ids": source_list(c.get("source_ids"), c.get("source_id")),
            "confidence": clamp(float(c.get("confidence", 0.60))),
            "limitations": ["Configuration change is not malicious change without authorization context."],
        })
    return out


def ingest_maintenance(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for idx, m in enumerate(manifest.get("maintenance_windows", []) or manifest.get("maintenance", []) or []):
        out.append({
            "maintenance_id": normalize_text(m.get("maintenance_id") or m.get("id") or f"MAINT-{idx}"),
            "site_ids": source_list(m.get("site_ids"), m.get("site_id")),
            "asset_ids": source_list(m.get("asset_ids"), m.get("asset_id")),
            "start": parse_time(m.get("start") or m.get("start_date")),
            "end": parse_time(m.get("end") or m.get("end_date")),
            "description": normalize_text(m.get("description")) or None,
            "approved": m.get("approved"),
            "ticket": normalize_text(m.get("ticket")) or None,
            "source_ids": source_list(m.get("source_ids"), m.get("source_id")),
            "confidence": clamp(float(m.get("confidence", 0.60))),
        })
    return out


def ingest_remote_access(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for idx, r in enumerate(manifest.get("remote_access_paths", []) or []):
        out.append({
            "remote_access_id": normalize_text(r.get("remote_access_id") or r.get("id") or f"REM-{idx}"),
            "asset_id": normalize_text(r.get("asset_id")) or None,
            "site_id": normalize_text(r.get("site_id")) or None,
            "service": normalize_text(r.get("service")) or None,
            "authorized": r.get("authorized"),
            "mfa": r.get("mfa"),
            "active_session_evidence": r.get("active_session_evidence"),
            "last_session_at": parse_time(r.get("last_session_at")),
            "source_ids": source_list(r.get("source_ids"), r.get("source_id")),
            "confidence": clamp(float(r.get("confidence", 0.55))),
            "limitations": ["Configured remote access is not active session evidence."],
        })
    return out


def ingest_third_party(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for idx, t in enumerate(manifest.get("third_party_access", []) or []):
        out.append({
            "third_party_id": normalize_text(t.get("third_party_id") or t.get("id") or f"TPA-{idx}"),
            "asset_id": normalize_text(t.get("asset_id")) or None,
            "site_id": normalize_text(t.get("site_id")) or None,
            "vendor": normalize_text(t.get("vendor")) or None,
            "service": normalize_text(t.get("service")) or None,
            "authorized": t.get("authorized"),
            "contract_reference": normalize_text(t.get("contract_reference")) or None,
            "last_access_at": parse_time(t.get("last_access_at")),
            "source_ids": source_list(t.get("source_ids"), t.get("source_id")),
            "confidence": clamp(float(t.get("confidence", 0.55))),
            "limitations": ["Authorized vendor access is not compromise."],
        })
    return out


def ingest_segmentation(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for idx, s in enumerate(manifest.get("segmentation_controls", []) or []):
        out.append({
            "segmentation_id": normalize_text(s.get("segmentation_id") or s.get("id") or f"SEG-{idx}"),
            "site_id": normalize_text(s.get("site_id")) or None,
            "device_type": normalize_text(s.get("device_type")).upper() or "UNKNOWN",
            "zones": source_list(s.get("zones")),
            "rules_summary": normalize_text(s.get("rules_summary")) or None,
            "observed_effectiveness": normalize_text(s.get("observed_effectiveness")).upper() or "UNKNOWN",
            "source_ids": source_list(s.get("source_ids"), s.get("source_id")),
            "confidence": clamp(float(s.get("confidence", 0.55))),
            "limitations": ["Firewall presence is not effective segmentation."],
        })
    return out


def ingest_vulnerabilities(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for idx, v in enumerate(manifest.get("vulnerability_data", []) or manifest.get("vulnerabilities", []) or []):
        out.append({
            "vulnerability_id": normalize_text(v.get("vulnerability_id") or v.get("id") or v.get("cve") or f"VULN-{idx}"),
            "cve": normalize_text(v.get("cve")) or None,
            "asset_id": normalize_text(v.get("asset_id")) or None,
            "vendor": normalize_text(v.get("vendor")) or None,
            "product": normalize_text(v.get("product")) or None,
            "model": normalize_text(v.get("model")) or None,
            "affected_versions": v.get("affected_versions") or v.get("versions") or [],
            "configuration_prerequisites": source_list(v.get("configuration_prerequisites")),
            "mitigations": source_list(v.get("mitigations")),
            "exploit_availability": norm_enum(v.get("exploit_availability"), EXPLOIT_AVAILABILITY_STATES),
            "known_exploitation_reported": bool(v.get("known_exploitation_reported")),
            "advisory": normalize_text(v.get("advisory")) or None,
            "source_ids": source_list(v.get("source_ids"), v.get("source_id")),
            "confidence": clamp(float(v.get("confidence", 0.60))),
            "limitations": [
                "CVE presence is not asset vulnerability.",
                "Vulnerability is not exploitation.",
                "Exploit capability is not observed exploitation.",
            ],
        })
    return out


def ingest_incidents(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for idx, i in enumerate(manifest.get("incidents", []) or []):
        out.append({
            "incident_id": normalize_text(i.get("incident_id") or i.get("id") or f"INC-{idx}"),
            "asset_id": normalize_text(i.get("asset_id")) or None,
            "site_id": normalize_text(i.get("site_id")) or None,
            "incident_type": norm_enum(i.get("incident_type"), INCIDENT_TYPES),
            "occurred_at": parse_time(i.get("occurred_at") or i.get("timestamp")),
            "description": normalize_text(i.get("description")) or None,
            "exploitation_claim": bool(i.get("exploitation_claim")),
            "vulnerability_id": normalize_text(i.get("vulnerability_id")) or None,
            "malware_id": normalize_text(i.get("malware_id")) or None,
            "physical_impact_state": norm_enum(i.get("physical_impact_state"), PHYSICAL_IMPACT_STATES),
            "process_impact_evidence": source_list(i.get("process_impact_evidence")),
            "source_ids": source_list(i.get("source_ids"), i.get("source_id")),
            "confidence": clamp(float(i.get("confidence", 0.55))),
            "limitations": [
                "Cyber event is not process impact.",
                "Process disturbance is not cyberattack.",
                "Physical impact does not prove malicious intent.",
            ],
        })
    return out


def ingest_malware(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for idx, m in enumerate(manifest.get("malware_context", []) or []):
        out.append({
            "malware_id": normalize_text(m.get("malware_id") or m.get("id") or f"MAL-{idx}"),
            "name": normalize_text(m.get("name")) or None,
            "family": normalize_text(m.get("family")) or None,
            "ics_capability_claim": normalize_text(m.get("ics_capability_claim")) or None,
            "observed_action": normalize_text(m.get("observed_action")) or None,
            "asset_id": normalize_text(m.get("asset_id")) or None,
            "source_ids": source_list(m.get("source_ids"), m.get("source_id")),
            "confidence": clamp(float(m.get("confidence", 0.55))),
            "limitations": ["Malware capability is not observed action."],
        })
    return out


def ingest_attack_techniques(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for idx, t in enumerate(manifest.get("attack_techniques", []) or []):
        out.append({
            "technique_mapping_id": normalize_text(t.get("technique_mapping_id") or t.get("id") or f"ATT-{idx}"),
            "technique_id": normalize_text(t.get("technique_id")) or None,
            "framework_version": normalize_text(t.get("framework_version")) or "ATT&CK_ICS_UNKNOWN_VERSION",
            "asset_id": normalize_text(t.get("asset_id")) or None,
            "behavior_evidence": normalize_text(t.get("behavior_evidence")) or None,
            "confidence": clamp(float(t.get("confidence", 0.50))),
            "source_ids": source_list(t.get("source_ids"), t.get("source_id")),
            "limitations": ["Technique mapping is not actor attribution."],
        })
    return out


def ingest_process_relationships(manifest: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    return {
        "control": [
            {
                "relationship_id": normalize_text(r.get("relationship_id") or f"CTRL-{idx}"),
                "controller_asset_id": normalize_text(r.get("controller_asset_id")),
                "process_asset_id": normalize_text(r.get("process_asset_id")) or None,
                "process_function": normalize_text(r.get("process_function")) or None,
                "evidence": normalize_text(r.get("evidence")) or None,
                "source_ids": source_list(r.get("source_ids"), r.get("source_id")),
                "confidence": clamp(float(r.get("confidence", 0.55))),
            }
            for idx, r in enumerate(manifest.get("control_relationships", []) or [])
        ],
        "monitoring": [
            {
                "relationship_id": normalize_text(r.get("relationship_id") or f"MON-{idx}"),
                "sensor_asset_id": normalize_text(r.get("sensor_asset_id")),
                "process_variable": normalize_text(r.get("process_variable")) or None,
                "process_asset_id": normalize_text(r.get("process_asset_id")) or None,
                "source_ids": source_list(r.get("source_ids"), r.get("source_id")),
                "confidence": clamp(float(r.get("confidence", 0.55))),
            }
            for idx, r in enumerate(manifest.get("monitoring_relationships", []) or [])
        ],
        "actuation": [
            {
                "relationship_id": normalize_text(r.get("relationship_id") or f"ACT-{idx}"),
                "actuator_asset_id": normalize_text(r.get("actuator_asset_id")),
                "process_asset_id": normalize_text(r.get("process_asset_id")) or None,
                "source_ids": source_list(r.get("source_ids"), r.get("source_id")),
                "confidence": clamp(float(r.get("confidence", 0.55))),
            }
            for idx, r in enumerate(manifest.get("actuation_relationships", []) or [])
        ],
    }


# --------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------

def maintenance_context_for(
    asset_id: Optional[str],
    site_id: Optional[str],
    ts: Optional[datetime],
    maintenance: List[Dict[str, Any]],
    assets: Dict[str, Dict[str, Any]],
) -> str:
    a = assets.get(asset_id or "", {})
    site = site_id or a.get("site_id")
    ctx = "NONE"
    for m in maintenance:
        asset_match = bool(asset_id and asset_id in m.get("asset_ids", []))
        site_match = bool(site and site in m.get("site_ids", []))
        global_match = not m.get("asset_ids") and not m.get("site_ids")
        if asset_match or site_match or global_match:
            if within_time(ts, m.get("start"), m.get("end")):
                if m.get("approved") is True:
                    return "SUPPORTED"
                ctx = "CANDIDATE"
    return ctx


def assess_assets(
    assets: Dict[str, Dict[str, Any]],
    flows: List[Dict[str, Any]],
    sources: Dict[str, Dict[str, Any]],
    roots: Dict[str, str],
) -> Dict[str, Dict[str, Any]]:
    passive_protocols: Dict[str, Set[str]] = defaultdict(set)
    passive_seen: Dict[str, List[datetime]] = defaultdict(list)

    for f in flows:
        for aid in (f.get("source_asset"), f.get("dest_asset")):
            if aid in assets:
                if f.get("protocol") and f["protocol"] != "UNKNOWN":
                    passive_protocols[aid].add(f["protocol"])
                for ts in (f.get("first_seen"), f.get("last_seen")):
                    if isinstance(ts, datetime):
                        passive_seen[aid].append(ts)

    out = {}
    for aid, a in assets.items():
        sa = source_assessment(a.get("source_ids", []), sources, roots)
        passive = sorted(passive_protocols.get(aid, []))
        observed_ts = sorted(passive_seen.get(aid, []))
        observed = bool(passive or a.get("last_seen") or observed_ts)

        if a.get("asset_role") != "UNKNOWN" and sa["max_reliability"] >= 0.70:
            role_state = "INVENTORY_SUPPORTED"
        elif passive:
            role_state = "PASSIVE_ROLE_CANDIDATE"
        else:
            role_state = "UNKNOWN"

        if a.get("vendor") and a.get("product") and a.get("model") and a.get("firmware_version") and sa["max_reliability"] >= 0.80:
            product_state = "EXACT_MODEL_SUPPORTED"
        elif a.get("vendor") and a.get("product"):
            product_state = "PRODUCT_FAMILY_CANDIDATE"
        elif a.get("vendor"):
            product_state = "VENDOR_CANDIDATE"
        else:
            product_state = "UNKNOWN"

        safety_flag = a.get("safety_relevance") in {"SAFETY_CRITICAL", "PROTECTIVE", "SIS_RELEVANT"}

        out[aid] = {
            "asset_id": aid,
            "role_state": role_state,
            "passive_protocols": passive,
            "observed_in_window": observed,
            "absence_interpretation": "NOT_OBSERVED_IN_WINDOW_NOT_ABSENT",
            "product_state": product_state,
            "source_assessment": sa,
            "safety_flag": safety_flag,
            "criticality": a.get("criticality"),
            "zone": a.get("zone"),
            "purdue_level": a.get("purdue_level"),
            "limitations": [
                "Asset inventory may be stale/incomplete.",
                "Passive non-observation does not prove asset absence.",
                "Protocol participation does not alone establish exact role.",
            ],
        }
    return out


def analyze_network(
    assets: Dict[str, Dict[str, Any]],
    flows: List[Dict[str, Any]],
    maintenance: List[Dict[str, Any]],
    sources: Dict[str, Dict[str, Any]],
    roots: Dict[str, str],
) -> Dict[str, Any]:
    valid = set(assets)
    validated = []
    unknown_asset_flows = []
    high_review = []
    cross_zone = []
    protocol_counts = Counter()
    operation_counts = Counter()
    pair_baseline = Counter()

    for f in flows:
        src = f.get("source_asset")
        dst = f.get("dest_asset")
        unknown = []
        if src not in valid:
            unknown.append(src)
        if dst not in valid:
            unknown.append(dst)
        if unknown:
            unknown_asset_flows.append({"flow_id": f["flow_id"], "unknown_assets": unknown})

        sa = assets.get(src or "", {})
        da = assets.get(dst or "", {})
        sz = sa.get("zone", "UNKNOWN")
        dz = da.get("zone", "UNKNOWN")
        if sz != "UNKNOWN" and dz != "UNKNOWN" and sz != dz:
            xz = True
            cross_zone.append(f["flow_id"])
        elif sz == "UNKNOWN" or dz == "UNKNOWN":
            xz = None
        else:
            xz = False

        ts = f.get("first_seen") or f.get("last_seen")
        mctx = maintenance_context_for(src, sa.get("site_id"), ts, maintenance, assets)
        mctx_dst = maintenance_context_for(dst, da.get("site_id"), ts, maintenance, assets)
        if mctx == "SUPPORTED" or mctx_dst == "SUPPORTED":
            maintenance_state = "SUPPORTED"
        elif mctx == "CANDIDATE" or mctx_dst == "CANDIDATE":
            maintenance_state = "CANDIDATE"
        else:
            maintenance_state = "NONE"

        op = f.get("operation_class", "UNKNOWN")
        protocol_counts[f.get("protocol", "UNKNOWN")] += 1
        operation_counts[op] += 1
        pair_baseline[(src, dst, f.get("protocol"))] += 1

        high = (
            op in {"WRITE", "CONTROL", "CONFIGURATION"}
            or xz is True
            or f.get("unexpected") is True
            or f.get("new_relative_to_baseline") is True
        )
        state = "NEW_OR_UNBASELINED_CANDIDATE" if (f.get("new_relative_to_baseline") or f.get("unexpected")) else "OBSERVED"
        if high and maintenance_state == "NONE":
            review_priority = "HIGH"
        elif high:
            review_priority = "MEDIUM"
        else:
            review_priority = "LOW"

        ff = dict(f)
        ff.update({
            "cross_zone": xz,
            "maintenance_context": maintenance_state,
            "high_review": high,
            "review_priority": review_priority,
            "communication_state": state,
            "source_assessment": source_assessment(f.get("source_ids", []), sources, roots),
        })
        validated.append(ff)
        if high:
            high_review.append(ff)

    inconsistencies = [f["flow_id"] for f in validated if f.get("port_protocol_consistency") == "INCONSISTENT_PORT_PROTOCOL"]

    return {
        "flows": validated,
        "unknown_asset_flows": unknown_asset_flows,
        "high_review_flows": high_review,
        "cross_zone_flows": cross_zone,
        "protocol_counts": dict(protocol_counts),
        "operation_counts": dict(operation_counts),
        "pair_baseline": [{"source": k[0], "dest": k[1], "protocol": k[2], "count": v} for k, v in pair_baseline.items()],
        "port_protocol_inconsistencies": inconsistencies,
        "limitations": [
            "Flow evidence is passive/authorized metadata only; no active probing was performed.",
            "Cross-zone flow is architecture context, not automatic attack.",
            "Write/control observation requires authorization, baseline, and operator/maintenance context.",
        ],
    }


def analyze_protocols(network: Dict[str, Any]) -> Dict[str, Any]:
    counts = network.get("protocol_counts", {})
    legacy = {"MODBUS_TCP", "DNP3_TCP", "IEC_60870_5_104", "S7COMM", "ETHERNET_IP", "BACNET", "OPC_DA"}
    legacy_seen = sorted([p for p in counts if p in legacy])
    return {
        "protocol_counts": counts,
        "operation_counts": network.get("operation_counts", {}),
        "legacy_protocol_context": legacy_seen,
        "port_protocol_inconsistencies": network.get("port_protocol_inconsistencies", []),
        "limitations": [
            "Legacy/plaintext protocol design is a risk characteristic, not evidence of compromise.",
            "Protocol does not prove device identity or role.",
            "Port is suggestive, not definitive.",
        ],
    }


def version_match(asset_version: Optional[str], affected_versions: Any) -> Optional[bool]:
    av = normalize_text(asset_version).lower()
    if not av or affected_versions in (None, "", []):
        return None
    if isinstance(affected_versions, str):
        vals = [affected_versions]
    elif isinstance(affected_versions, list):
        vals = affected_versions
    else:
        vals = [str(affected_versions)]
    norm = [normalize_text(x).lower() for x in vals if normalize_text(x)]
    if not norm:
        return None
    if av in norm:
        return True
    has_range = any(re.search(r"[-~]|through|to|<|>|=", x) for x in norm)
    if has_range:
        return None
    return False


def field_match(vuln_val: Optional[str], asset_val: Optional[str]) -> Optional[bool]:
    if not vuln_val or not asset_val:
        return None
    return normalize_text(vuln_val).lower() == normalize_text(asset_val).lower()


def assess_vulnerabilities(
    assets: Dict[str, Dict[str, Any]],
    vulnerabilities: List[Dict[str, Any]],
    sources: Dict[str, Dict[str, Any]],
    roots: Dict[str, str],
) -> Dict[str, Dict[str, Any]]:
    out = {}
    for v in vulnerabilities:
        aid = v.get("asset_id")
        a = assets.get(aid or "", {})
        matches = [
            field_match(v.get("vendor"), a.get("vendor")),
            field_match(v.get("product"), a.get("product")),
            field_match(v.get("model"), a.get("model")),
        ]
        fw = version_match(a.get("firmware_version"), v.get("affected_versions"))

        if not a:
            state = "UNKNOWN"
            reason = "Asset not resolved."
        elif any(m is False for m in matches) or fw is False:
            state = "NOT_APPLICABLE_BASED_ON_MISMATCH"
            reason = "Vendor/product/model/firmware mismatch based on supplied records."
        elif all(m is True for m in matches if m is not None) and fw is True:
            state = "APPLICABLE_PENDING_VALIDATION"
            reason = "Supplied asset attributes match advisory fields; site configuration/feature still requires validation."
        elif all(m is True for m in matches if m is not None) and fw is None:
            state = "POSSIBLE_PENDING_FIRMWARE"
            reason = "Product/model context matches, but firmware/version evidence is incomplete."
        elif any(m is True for m in matches):
            state = "POSSIBLE"
            reason = "Partial product/vendor match; exact applicability unresolved."
        else:
            state = "UNKNOWN"
            reason = "Insufficient asset product/version evidence."

        out[v["vulnerability_id"]] = {
            "vulnerability_id": v["vulnerability_id"],
            "asset_id": aid,
            "applicability_state": state,
            "reason": reason,
            "exploit_availability": v.get("exploit_availability", "UNKNOWN"),
            "known_exploitation_reported": v.get("known_exploitation_reported", False),
            "mitigations": v.get("mitigations", []),
            "source_assessment": source_assessment(v.get("source_ids", []), sources, roots),
            "limitations": [
                "CVE/advisory is not site applicability until vendor/product/model/version/configuration are validated.",
                "Vulnerability is not exploitation.",
                "No exploit code or active validation is provided.",
            ],
        }
    return out


def analyze_alarms_events(
    alarms: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
    config_changes: List[Dict[str, Any]],
    maintenance: List[Dict[str, Any]],
    assets: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    valid = set(assets)
    alarm_unknown = [a["alarm_id"] for a in alarms if a.get("asset_id") and a["asset_id"] not in valid]
    event_unknown = [e["event_id"] for e in events if e.get("asset_id") and e["asset_id"] not in valid]
    priority_counts = Counter(a.get("priority", "UNKNOWN") for a in alarms)
    event_counts = Counter(e.get("event_type", "UNKNOWN") for e in events)

    correlated = []
    for e in events:
        ts = e.get("timestamp")
        mctx = maintenance_context_for(e.get("asset_id"), e.get("site_id"), ts, maintenance, assets)
        correlated.append({
            "event_id": e["event_id"],
            "event_type": e.get("event_type"),
            "timestamp": ts,
            "maintenance_context": mctx,
            "account_note": "Account name is not real-person attribution.",
        })

    unexpected_changes = []
    for c in config_changes:
        if c.get("approved") is False or (c.get("approved") is None and c.get("ticket") is None):
            unexpected_changes.append(c["change_id"])

    return {
        "alarm_count": len(alarms),
        "alarm_priority_counts": dict(priority_counts),
        "alarm_unknown_assets": alarm_unknown,
        "event_count": len(events),
        "event_type_counts": dict(event_counts),
        "event_unknown_assets": event_unknown,
        "correlated_events": correlated,
        "config_change_count": len(config_changes),
        "unexpected_or_unapproved_changes": unexpected_changes,
        "limitations": [
            "Alarm is not incident.",
            "Alarm flood may be process, sensor, configuration, communications, or attack.",
            "Engineering event account is not person attribution.",
            "Configuration change is not malicious without authorization context.",
        ],
    }


def assess_incidents(
    incidents: List[Dict[str, Any]],
    vuln_assessments: Dict[str, Dict[str, Any]],
    maintenance: List[Dict[str, Any]],
    assets: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    out = []
    for i in incidents:
        ts = i.get("occurred_at")
        mctx = maintenance_context_for(i.get("asset_id"), i.get("site_id"), ts, maintenance, assets)
        vid = i.get("vulnerability_id")
        va = vuln_assessments.get(vid or "", {})
        vuln_state = va.get("applicability_state", "UNKNOWN" if vid else "NOT_REFERENCED")
        impact = i.get("physical_impact_state", "UNKNOWN")
        if impact == "UNKNOWN" and not i.get("process_impact_evidence"):
            impact_note = "NO_INDEPENDENT_PROCESS_IMPACT_EVIDENCE_PROVIDED"
        else:
            impact_note = "IMPACT_STATE_FROM_SUPPLIED_EVIDENCE"

        out.append({
            "incident_id": i["incident_id"],
            "incident_type": i.get("incident_type"),
            "asset_id": i.get("asset_id"),
            "occurred_at": ts,
            "maintenance_context": mctx,
            "vulnerability_id": vid,
            "vulnerability_applicability": vuln_state,
            "exploitation_claim": i.get("exploitation_claim", False),
            "physical_impact_state": impact,
            "impact_note": impact_note,
            "limitations": [
                "Cyber event is not process impact.",
                "Process disturbance is not cyberattack.",
                "Physical impact does not prove malicious intent.",
            ],
        })
    return out


def detect_contradictions(
    assets: Dict[str, Dict[str, Any]],
    asset_assessments: Dict[str, Dict[str, Any]],
    network: Dict[str, Any],
    alarms_events: Dict[str, Any],
    vulnerabilities: List[Dict[str, Any]],
    vuln_assessments: Dict[str, Dict[str, Any]],
    incident_assessments: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    contr: List[Dict[str, Any]] = []

    for uf in network.get("unknown_asset_flows", []):
        contr.append({
            "contradiction_id": stable_id("CTR", "unknown_flow_asset", uf["flow_id"]),
            "type": "FLOW_REFERENCES_UNKNOWN_ASSET",
            "severity": "MATERIAL",
            "flow_id": uf["flow_id"],
            "detail": f"Flow references unknown asset(s): {uf['unknown_assets']}.",
            "possible_causes": ["stale inventory", "new asset", "NAT/gateway", "sensor visibility gap", "data error"],
        })

    for f in network.get("flows", []):
        fs, fe = f.get("first_seen"), f.get("last_seen")
        if isinstance(fs, datetime) and isinstance(fe, datetime) and fe < fs:
            contr.append({
                "contradiction_id": stable_id("CTR", "flow_timestamp", f["flow_id"]),
                "type": "FLOW_TIMESTAMP_ORDER_CONFLICT",
                "severity": "MATERIAL",
                "flow_id": f["flow_id"],
                "detail": "Flow last_seen is earlier than first_seen.",
                "possible_causes": ["clock drift", "timezone error", "data entry error"],
            })
        if f.get("port_protocol_consistency") == "INCONSISTENT_PORT_PROTOCOL":
            contr.append({
                "contradiction_id": stable_id("CTR", "port_protocol", f["flow_id"]),
                "type": "PORT_PROTOCOL_INCONSISTENCY",
                "severity": "MEDIUM",
                "flow_id": f["flow_id"],
                "detail": f"Port {f.get('port')} is commonly associated with another protocol than {f.get('protocol')}.",
                "possible_causes": ["nonstandard port", "gateway/proxy", "protocol misclassification", "data error"],
            })

    ip_map: Dict[str, Set[str]] = defaultdict(set)
    for aid, a in assets.items():
        for ip in a.get("ip_addresses", []):
            ip_map[ip].add(aid)
    for ip, aids in ip_map.items():
        if len(aids) > 1:
            contr.append({
                "contradiction_id": stable_id("CTR", "ip_reuse", ip),
                "type": "IP_REUSE_CANDIDATE",
                "severity": "MEDIUM",
                "ip": ip,
                "asset_ids": sorted(aids),
                "detail": "Same IP appears across multiple asset records.",
                "possible_causes": ["device replacement", "DHCP/reassignment", "NAT", "duplicate inventory", "time-bounded reuse"],
            })

    for aid in alarms_events.get("alarm_unknown_assets", []):
        contr.append({
            "contradiction_id": stable_id("CTR", "alarm_asset", aid),
            "type": "ALARM_REFERENCES_UNKNOWN_ASSET",
            "severity": "MEDIUM",
            "alarm_id": aid,
            "detail": "Alarm references asset not present in inventory.",
            "possible_causes": ["stale inventory", "new asset", "tag/asset mapping error"],
        })

    for inc in incident_assessments:
        if inc.get("exploitation_claim") and inc.get("vulnerability_applicability") in {"UNKNOWN", "NOT_APPLICABLE_BASED_ON_MISMATCH"}:
            contr.append({
                "contradiction_id": stable_id("CTR", "incident_exploit", inc["incident_id"]),
                "type": "EXPLOITATION_CLAIM_WITHOUT_APPLICABLE_VULNERABILITY",
                "severity": "MATERIAL",
                "incident_id": inc["incident_id"],
                "detail": "Incident claims exploitation but referenced vulnerability applicability is unresolved or mismatched.",
                "possible_causes": ["wrong CVE", "wrong asset", "version mismatch", "unsupported claim", "different vulnerability"],
            })

    return unique_preserve(contr)


def build_hypotheses(
    network: Dict[str, Any],
    vuln_assessments: Dict[str, Dict[str, Any]],
    incident_assessments: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    hyp: List[Dict[str, Any]] = []

    def add(subject_type: str, subject_id: str, category: str, statement: str,
            support: List[str], opposition: List[str], unknowns: List[str],
            falsify: List[str]) -> None:
        hyp.append({
            "hypothesis_id": stable_id("HYP", subject_type, subject_id, category),
            "subject_type": subject_type,
            "subject_id": subject_id,
            "category": category,
            "statement": statement,
            "support": support,
            "opposition": opposition,
            "unknowns": unknowns,
            "falsification_conditions": falsify,
            "status": "CANDIDATE",
        })

    for f in network.get("high_review_flows", [])[:200]:
        fid = f["flow_id"]
        add("FLOW", fid, "AUTHORIZED_MAINTENANCE_OR_NORMAL_OPERATION",
            "Unusual/write/control flow may be authorized maintenance or normal SCADA operation.",
            [f"maintenance_context={f.get('maintenance_context')}", f"operation={f.get('operation_class')}"],
            ["No approved ticket or baseline context."],
            ["operator context", "change ticket", "engineering session"],
            ["Authorized maintenance/change records do not explain timing/initiator and baseline shows no prior pattern."])
        add("FLOW", fid, "UNAUTHORIZED_ACCESS_CANDIDATE",
            "Flow may represent unauthorized access or unexpected engineering activity.",
            [f"high_review={f.get('high_review')}", f"cross_zone={f.get('cross_zone')}"],
            ["Maintenance, failover, replacement, or misclassification possible."],
            ["session ownership", "endpoint identity", "gateway/proxy"],
            ["Authorized change record and identity/session evidence explain the flow."])
        add("FLOW", fid, "PROTOCOL_OR_ENDPOINT_MISCLASSIFICATION",
            "Flow may be misclassified due to gateway, proxy, nonstandard port, or parser limitation.",
            [f"port_protocol_consistency={f.get('port_protocol_consistency')}"],
            ["Multiple independent passive observations confirm protocol and endpoints."],
            ["deep packet metadata", "device fingerprints", "engineering configuration"],
            ["Parser/vendor evidence confirms exact protocol and endpoint roles."])
        add("FLOW", fid, "PREVIOUSLY_UNMONITORED_BASELINE",
            "Communication may have existed before but was not visible in prior monitoring.",
            ["sensor visibility can be incomplete"],
            ["historical PCAP/flows show no prior pattern"],
            ["monitoring coverage", "SPAN/TAP placement"],
            ["Historical authorized telemetry shows first-time appearance."])

    for vid, va in list(vuln_assessments.items())[:200]:
        add("VULNERABILITY", vid, "APPLICABLE_WITH_COMPENSATING_CONTROLS",
            "Vulnerability may apply but compensating controls may reduce practical risk.",
            [f"applicability={va.get('applicability_state')}"],
            ["Segmentation/ACL/feature-disabled/patch status unknown."],
            ["configuration", "exposure", "patch status"],
            ["Authorized configuration review confirms feature disabled or traffic blocked."])
        add("VULNERABILITY", vid, "NOT_APPLICABLE_TO_SITE",
            "Advisory may not apply due to product/model/version/configuration mismatch.",
            [f"applicability={va.get('applicability_state')}"],
            ["Exact asset evidence matches advisory."],
            ["firmware", "module", "feature set"],
            ["Authoritative asset inventory/project metadata confirms exact affected version in use."])
        add("VULNERABILITY", vid, "NO_OBSERVED_EXPLOITATION",
            "Vulnerability presence does not prove exploitation.",
            ["CVE/advisory context only"],
            ["incident/telemetry evidence shows exploitation behavior."],
            ["logs", "PCAP", "controller state", "historian"],
            ["Independent OT telemetry/incident evidence demonstrates exploitation."])

    for inc in incident_assessments[:200]:
        iid = inc["incident_id"]
        add("INCIDENT", iid, "CYBER_CAUSED_PROCESS_IMPACT",
            "Cyber activity may have caused process/physical impact.",
            [f"incident_type={inc.get('incident_type')}", f"impact={inc.get('physical_impact_state')}"],
            ["Maintenance, equipment failure, operator error, power/network fault possible."],
            ["controller logs", "historian", "alarms", "operations records"],
            ["Independent engineering/operations evidence excludes cyber pathway."])
        add("INCIDENT", iid, "PROCESS_OR_EQUIPMENT_FAULT",
            "Observed disturbance may be non-cyber process/equipment fault.",
            ["process disturbance can have many causes"],
            ["strong cyber indicators aligned in time"],
            ["maintenance", "sensor health", "power quality"],
            ["Cyber telemetry and controller changes align and non-cyber causes excluded."])
        add("INCIDENT", iid, "MAINTENANCE_OR_TESTING_ARTIFACT",
            "Event may be planned maintenance, commissioning, or test.",
            [f"maintenance_context={inc.get('maintenance_context')}"],
            ["no approved ticket or operator confirmation"],
            ["change management", "work order"],
            ["Change records exclude maintenance and anomaly persists."])

    return hyp[:2000]


def build_gaps(
    assets: Dict[str, Dict[str, Any]],
    asset_assessments: Dict[str, Dict[str, Any]],
    network: Dict[str, Any],
    vulnerabilities: List[Dict[str, Any]],
    vuln_assessments: Dict[str, Dict[str, Any]],
    incident_assessments: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    manifest: Dict[str, Any],
) -> List[Dict[str, Any]]:
    gaps: List[Dict[str, Any]] = []

    if not assets:
        gaps.append({
            "gap_id": stable_id("GAP", "no_assets"),
            "type": "ASSET_INVENTORY_UNRESOLVED",
            "importance": "HIGH",
            "recommended_source": "Authorized OT asset inventory, CMDB, engineering project metadata, passive sensor inventory.",
            "specialist": "SCADAINT",
            "expected_information_value": "Resolve assets before role/topology/process analysis.",
        })

    for aid, ass in asset_assessments.items():
        a = assets.get(aid, {})
        if ass.get("role_state") == "UNKNOWN":
            gaps.append({
                "gap_id": stable_id("GAP", "role", aid),
                "type": "ASSET_ROLE_UNRESOLVED",
                "importance": "HIGH",
                "asset_id": aid,
                "recommended_source": "Engineering documentation, authorized project file, passive protocol context, asset owner confirmation.",
                "specialist": "SCADAINT / TECHINT",
                "expected_information_value": "Distinguish HMI/PLC/RTU/server/workstation roles.",
            })
        if not a.get("firmware_version"):
            gaps.append({
                "gap_id": stable_id("GAP", "firmware", aid),
                "type": "FIRMWARE_UNRESOLVED",
                "importance": "HIGH" if a.get("asset_type") in {"PLC", "RTU", "SCADA_SERVER", "HMI", "SAFETY_CONTROLLER", "PROTECTIVE_RELAY"} else "MEDIUM",
                "asset_id": aid,
                "recommended_source": "Authorized inventory, engineering project, vendor tool record, maintenance log.",
                "specialist": "SCADAINT / TECHINT",
                "expected_information_value": "Resolve vulnerability applicability and lifecycle context.",
            })
        if ass.get("product_state") in {"UNKNOWN", "VENDOR_CANDIDATE"}:
            gaps.append({
                "gap_id": stable_id("GAP", "product", aid),
                "type": "PRODUCT_MODEL_UNRESOLVED",
                "importance": "MEDIUM",
                "asset_id": aid,
                "recommended_source": "Vendor documentation, nameplate/authorized inventory, engineering project.",
                "specialist": "TECHINT / SCADAINT",
                "expected_information_value": "Avoid exact model/version overclaim.",
            })
        if a.get("safety_relevance") == "UNKNOWN":
            gaps.append({
                "gap_id": stable_id("GAP", "safety", aid),
                "type": "SAFETY_RELEVANCE_UNRESOLVED",
                "importance": "HIGH" if a.get("asset_type") in {"SIS_COMPONENT", "SAFETY_CONTROLLER", "PROTECTIVE_RELAY"} else "MEDIUM",
                "asset_id": aid,
                "recommended_source": "Authorized safety engineering documentation.",
                "specialist": "SCADAINT / SISINT / HUMAN_REVIEW",
                "expected_information_value": "Apply safety-first handling correctly.",
            })

    for uf in network.get("unknown_asset_flows", [])[:200]:
        gaps.append({
            "gap_id": stable_id("GAP", "unknown_flow_asset", uf["flow_id"]),
            "type": "TOPOLOGY_ASSET_REFERENCE_UNRESOLVED",
            "importance": "HIGH",
            "flow_id": uf["flow_id"],
            "recommended_source": "Updated asset inventory, DHCP/IPAM, switch port mapping, engineering drawings.",
            "specialist": "SCADAINT / NETINT",
            "expected_information_value": "Resolve endpoint identity before incident interpretation.",
        })

    for f in network.get("high_review_flows", [])[:300]:
        if f.get("maintenance_context") == "NONE":
            gaps.append({
                "gap_id": stable_id("GAP", "maintenance_context", f["flow_id"]),
                "type": "MAINTENANCE_CONTEXT_MISSING",
                "importance": "HIGH",
                "flow_id": f["flow_id"],
                "recommended_source": "Change tickets, maintenance schedule, operator log, engineering session records.",
                "specialist": "SCADAINT / INCIDENTINT",
                "expected_information_value": "Distinguish authorized work from unexpected activity.",
            })

    for vid, va in vuln_assessments.items():
        if va.get("applicability_state") in {"UNKNOWN", "POSSIBLE", "POSSIBLE_PENDING_FIRMWARE"}:
            gaps.append({
                "gap_id": stable_id("GAP", "vuln_applicability", vid),
                "type": "VULNERABILITY_APPLICABILITY_UNRESOLVED",
                "importance": "HIGH",
                "vulnerability_id": vid,
                "recommended_source": "Exact asset vendor/product/model/firmware/configuration evidence.",
                "specialist": "VULNINT / SCADAINT / TECHINT",
                "expected_information_value": "Avoid CVE-to-site-risk overclaim.",
            })

    for inc in incident_assessments:
        if inc.get("physical_impact_state") == "UNKNOWN":
            gaps.append({
                "gap_id": stable_id("GAP", "incident_impact", inc["incident_id"]),
                "type": "PROCESS_OR_PHYSICAL_IMPACT_UNRESOLVED",
                "importance": "HIGH",
                "incident_id": inc["incident_id"],
                "recommended_source": "Historian, alarms, controller logs, operations records, safety system logs where authorized.",
                "specialist": "SCADAINT / INCIDENTINT",
                "expected_information_value": "Separate cyber event from process impact.",
            })

    if manifest.get("clock_offset_unknown") or any(not a.get("last_seen") for a in assets.values()):
        gaps.append({
            "gap_id": stable_id("GAP", "clock"),
            "type": "CLOCK_SYNCHRONIZATION_UNRESOLVED",
            "importance": "MEDIUM",
            "recommended_source": "NTP/PTP/GPS configuration, device clock offsets, timezone normalization records.",
            "specialist": "SCADAINT / LOGINT",
            "expected_information_value": "Prevent false event ordering.",
        })

    for c in contradictions:
        gaps.append({
            "gap_id": stable_id("GAP", "contradiction", c["contradiction_id"]),
            "type": "SCADA_CONTRADICTION_UNRESOLVED",
            "importance": "HIGH" if c.get("severity") == "MATERIAL" else "MEDIUM",
            "contradiction_id": c["contradiction_id"],
            "recommended_source": "Authoritative inventory, passive telemetry, engineering records, vendor advisory, change management.",
            "specialist": "SCADAINT / HUMAN_REVIEW",
            "expected_information_value": "Resolve conflict before defensive action.",
        })

    return gaps[:1000]


def build_next_actions(gaps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    actions = []
    prio = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    for g in gaps:
        t = g.get("type")
        if t == "ASSET_INVENTORY_UNRESOLVED":
            action = "Load authorized OT asset inventory and passive sensor metadata; do not actively scan."
        elif t == "ASSET_ROLE_UNRESOLVED":
            action = "Correlate inventory, engineering documentation, and passive protocol relationships; do not infer role from protocol alone."
        elif t == "FIRMWARE_UNRESOLVED":
            action = "Retrieve firmware/version from authorized inventory, project backup, or vendor record; do not query live controller unless separately authorized."
        elif t == "PRODUCT_MODEL_UNRESOLVED":
            action = "Resolve vendor/product/model through TECHINT/authorized documentation; avoid exact model overclaim."
        elif t == "SAFETY_RELEVANCE_UNRESOLVED":
            action = "Review safety engineering documentation under read-only defensive handling; do not alter safety settings."
        elif t == "TOPOLOGY_ASSET_REFERENCE_UNRESOLVED":
            action = "Update asset/IPAM/switch-port mapping from authorized sources."
        elif t == "MAINTENANCE_CONTEXT_MISSING":
            action = "Review change tickets, maintenance schedule, operator logs, and engineering session records before escalation."
        elif t == "VULNERABILITY_APPLICABILITY_UNRESOLVED":
            action = "Hand exact product/version/configuration to VULNINT; do not test exploitability on live OT."
        elif t == "PROCESS_OR_PHYSICAL_IMPACT_UNRESOLVED":
            action = "Correlate historian, alarms, controller logs, and operations records; do not manipulate process to validate."
        elif t == "CLOCK_SYNCHRONIZATION_UNRESOLVED":
            action = "Normalize timestamps using authorized NTP/PTP/clock-offset metadata."
        elif t == "SCADA_CONTRADICTION_UNRESOLVED":
            action = "Resolve using authoritative primary evidence and human/OT engineer review."
        else:
            action = "Gather additional authorized passive OT evidence."

        actions.append({
            "action": action,
            "gap_id": g.get("gap_id"),
            "priority": g.get("importance", "MEDIUM"),
            "expected_information_value": g.get("expected_information_value"),
            "prohibited_alternatives": [
                "Do not write/send/upload/change PLC/RTU/HMI/controller values.",
                "Do not change setpoints, logic, firmware, alarms, interlocks, safety systems, valves, breakers, motors, or pumps.",
                "Do not exploit, scan, probe, fuzz, brute-force, spoof, MITM, jam, flood, reboot, or disrupt live OT.",
                "Do not use default/stolen/exposed credentials against live assets.",
                "Do not provide sabotage/process manipulation/physical damage guidance.",
            ],
        })
    actions.sort(key=lambda x: prio.get(x.get("priority", "LOW"), 9))
    return actions[:300]


def build_handoffs(
    assets: Dict[str, Dict[str, Any]],
    network: Dict[str, Any],
    vulnerabilities: List[Dict[str, Any]],
    malware: List[Dict[str, Any]],
    incidents: List[Dict[str, Any]],
    remote_access: List[Dict[str, Any]],
    third_party: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    hands = []
    seen = set()

    def add(spec: str, reason: str, payload: Dict[str, Any]) -> None:
        key = (spec, json.dumps(json_safe(payload), sort_keys=True, ensure_ascii=False))
        if key not in seen:
            seen.add(key)
            hands.append({"specialist": spec, "reason": reason, "payload": payload})

    if network.get("flows") or network.get("unknown_asset_flows"):
        add("NETINT / INFRAINT", "Network topology, flow validation, and infrastructure identity require network specialists.", {
            "flow_count": len(network.get("flows", [])),
            "unknown_asset_flow_count": len(network.get("unknown_asset_flows", [])),
        })
    if any(a.get("vendor") or a.get("product") or a.get("model") for a in assets.values()):
        add("TECHINT", "Product/model/revision/technical capability resolution required.", {
            "asset_ids": list(assets.keys())[:100],
        })
    if vulnerabilities:
        add("VULNINT", "Vulnerability applicability and patch/validation workflow required.", {
            "vulnerability_ids": [v["vulnerability_id"] for v in vulnerabilities][:100],
        })
    if malware:
        add("MALINT / CTI", "Industrial malware behavior/family analysis required.", {
            "malware_ids": [m["malware_id"] for m in malware][:100],
        })
    if incidents:
        add("INCIDENTINT / LOGINT", "Incident reconstruction and log correlation required.", {
            "incident_ids": [i["incident_id"] for i in incidents][:100],
        })
    if any(r.get("authorized") is not True or r.get("mfa") is not True for r in remote_access):
        add("CREDINT / SECOPS", "Remote access credential/MFA/least-privilege review required; do not validate credentials actively.", {
            "remote_access_ids": [r["remote_access_id"] for r in remote_access if r.get("authorized") is not True or r.get("mfa") is not True][:100],
        })
    if third_party:
        add("SUPPLYCHAININT", "Vendor/third-party dependency and contract risk review required.", {
            "third_party_ids": [t["third_party_id"] for t in third_party][:100],
        })
    if any(a.get("safety_relevance") in {"SAFETY_CRITICAL", "PROTECTIVE", "SIS_RELEVANT"} for a in assets.values()):
        add("SISINT / OT_SAFETY_HUMAN_REVIEW", "Safety-system context requires qualified safety engineering review; SCADAINT remains read-only.", {
            "asset_ids": [aid for aid, a in assets.items() if a.get("safety_relevance") in {"SAFETY_CRITICAL", "PROTECTIVE", "SIS_RELEVANT"}][:100],
        })
    return hands


class GraphMemory:
    def __init__(self) -> None:
        self.nodes: List[Dict[str, Any]] = []
        self.edges: List[Dict[str, Any]] = []
        self.ids: Set[str] = set()

    def node(self, ntype: str, nid: str, props: Optional[Dict[str, Any]] = None) -> None:
        if nid and nid not in self.ids:
            self.ids.add(nid)
            self.nodes.append({"type": ntype, "id": nid, "properties": props or {}})

    def edge(self, frm: str, to: str, etype: str, props: Optional[Dict[str, Any]] = None) -> None:
        if frm and to:
            self.edges.append({"from": frm, "to": to, "type": etype, "properties": props or {}})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": self.nodes[:3000],
            "edges": self.edges[:6000],
            "note": "SCADA graph preserves passive evidence, uncertainty, safety classification, and source dependence. It does not prove compromise, process impact, or actor attribution.",
        }


def build_graph(
    sites: Dict[str, Dict[str, Any]],
    assets: Dict[str, Dict[str, Any]],
    asset_assessments: Dict[str, Dict[str, Any]],
    network: Dict[str, Any],
    alarms: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
    vulnerabilities: List[Dict[str, Any]],
    vuln_assessments: Dict[str, Dict[str, Any]],
    incidents: List[Dict[str, Any]],
    maintenance: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    hypotheses: List[Dict[str, Any]],
    gaps: List[Dict[str, Any]],
    sources: Dict[str, Dict[str, Any]],
) -> GraphMemory:
    g = GraphMemory()

    for sid, s in sites.items():
        g.node("Site", sid, {"name": s.get("name"), "sector": s.get("sector")})

    for aid, a in assets.items():
        ass = asset_assessments.get(aid, {})
        g.node("Asset", aid, {
            "asset_type": a.get("asset_type"),
            "role_state": ass.get("role_state"),
            "zone": a.get("zone"),
            "purdue_level": a.get("purdue_level"),
            "safety_relevance": a.get("safety_relevance"),
            "criticality": a.get("criticality"),
            "firmware_masked": mask_value(a.get("firmware_version"), 2, 2),
        })
        if a.get("site_id"):
            g.edge(aid, a["site_id"], "LOCATED_IN", {})
        if a.get("zone"):
            g.node("SecurityZone", a["zone"], {})
            g.edge(aid, a["zone"], "PART_OF_ZONE", {})
        for proto in a.get("protocols", []):
            g.node("Protocol", proto, {})
            g.edge(aid, proto, "USES_PROTOCOL_CANDIDATE", {})
        for sid in a.get("source_ids", []):
            g.node("Source", sid, {"source_type": sources.get(sid, {}).get("source_type")})
            g.edge(aid, sid, "SUPPORTED_BY_SOURCE", {})

    for f in network.get("flows", [])[:1000]:
        fid = f["flow_id"]
        g.node("Flow", fid, {
            "protocol": f.get("protocol"),
            "operation_class": f.get("operation_class"),
            "review_priority": f.get("review_priority"),
            "maintenance_context": f.get("maintenance_context"),
        })
        if f.get("source_asset"):
            g.edge(f["source_asset"], fid, "SOURCE_OF_FLOW", {})
        if f.get("dest_asset"):
            g.edge(fid, f["dest_asset"], "DESTINATION_OF_FLOW", {})
        if f.get("protocol"):
            g.edge(fid, f["protocol"], "USES_PROTOCOL", {})

    for a in alarms[:500]:
        g.node("Alarm", a["alarm_id"], {"priority": a.get("priority"), "asset_id": a.get("asset_id")})
        if a.get("asset_id"):
            g.edge(a["asset_id"], a["alarm_id"], "GENERATED_ALARM", {})

    for e in events[:500]:
        g.node("IndustrialEvent", e["event_id"], {"event_type": e.get("event_type"), "asset_id": e.get("asset_id")})
        if e.get("asset_id"):
            g.edge(e["asset_id"], e["event_id"], "REPORTED_EVENT", {})

    for v in vulnerabilities[:500]:
        vid = v["vulnerability_id"]
        va = vuln_assessments.get(vid, {})
        g.node("Vulnerability", vid, {
            "cve": v.get("cve"),
            "applicability_state": va.get("applicability_state"),
            "exploit_availability": v.get("exploit_availability"),
        })
        if v.get("asset_id"):
            g.edge(v["asset_id"], vid, "POSSIBLY_AFFECTED_BY", {"state": va.get("applicability_state")})

    for i in incidents[:500]:
        g.node("Incident", i["incident_id"], {
            "incident_type": i.get("incident_type"),
            "physical_impact_state": i.get("physical_impact_state"),
            "maintenance_context": i.get("maintenance_context"),
        })
        if i.get("asset_id"):
            g.edge(i["asset_id"], i["incident_id"], "OBSERVED_IN_INCIDENT", {})

    for m in maintenance[:500]:
        g.node("MaintenanceWindow", m["maintenance_id"], {
            "start": iso(m.get("start")),
            "end": iso(m.get("end")),
            "approved": m.get("approved"),
        })
        for aid in m.get("asset_ids", [])[:100]:
            g.edge(aid, m["maintenance_id"], "MAINTENANCE_CONTEXT", {})

    for c in contradictions[:500]:
        g.node("Contradiction", c["contradiction_id"], {"type": c.get("type"), "severity": c.get("severity")})
    for h in hypotheses[:500]:
        g.node("Hypothesis", h["hypothesis_id"], {"category": h.get("category"), "subject_id": h.get("subject_id")})
    for gap in gaps[:500]:
        g.node("Gap", gap["gap_id"], {"type": gap.get("type"), "importance": gap.get("importance")})

    return g


def dual_ai_review_stub(
    network: Dict[str, Any],
    vuln_assessments: Dict[str, Dict[str, Any]],
    incident_assessments: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    gaps: List[Dict[str, Any]],
) -> Dict[str, Any]:
    review = {
        "status": "INSUFFICIENT_EVIDENCE",
        "primary_conclusions": [],
        "skeptic_challenges": [],
        "comparison": "NO_SECOND_MODEL_CONFIGURED",
        "notes": [
            "Starter does not call an independent second model.",
            "AI agreement is not OT corroboration.",
            "Human/OT engineer review is mandatory before any active validation, isolation, patching, or incident escalation with operational impact.",
        ],
    }
    if network.get("high_review_flows"):
        review["primary_conclusions"].append(f"{len(network.get('high_review_flows', []))} high-review flow(s) detected from passive/authorized evidence.")
        review["skeptic_challenges"].append("Check maintenance, baseline, gateway/proxy endpoint identity, clock drift, and protocol misclassification.")
    if any(va.get("applicability_state") in {"APPLICABLE_PENDING_VALIDATION", "POSSIBLE_PENDING_FIRMWARE", "POSSIBLE"} for va in vuln_assessments.values()):
        review["primary_conclusions"].append("Some vulnerability applicability remains possible/pending validation.")
        review["skeptic_challenges"].append("Do not treat CVE/advisory as site vulnerability without exact product/version/configuration evidence.")
    if any(inc.get("physical_impact_state") == "UNKNOWN" for inc in incident_assessments):
        review["primary_conclusions"].append("Process/physical impact remains unresolved for some incidents.")
        review["skeptic_challenges"].append("Do not equate cyber event with process impact; correlate historian/alarms/controller logs/operations.")
    if contradictions:
        review["primary_conclusions"].append(f"{len(contradictions)} SCADA contradiction candidate(s) detected.")
        review["skeptic_challenges"].append("Contradictions may be stale inventory, replacement, NAT/gateway, clock drift, failover, or data error.")
    if any(g.get("type") == "SAFETY_RELEVANCE_UNRESOLVED" for g in gaps):
        review["primary_conclusions"].append("Safety relevance unresolved; maintain read-only safety-first handling.")
        review["skeptic_challenges"].append("Do not alter safety settings or perform live safety testing.")
    if review["primary_conclusions"]:
        review["status"] = "PARTIAL_AGREEMENT"
    return review


# --------------------------------------------------------------------
# Result / report
# --------------------------------------------------------------------

def empty_result(manifest: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "case_id": manifest.get("case_id", "CASE-UNKNOWN"),
        "task_id": manifest.get("task_id", "TASK-UNKNOWN"),
        "objective": manifest.get("objective", ""),
        "questions": manifest.get("questions", []) or [],
        "generated_at": utc_now(),
        "version": VERSION,
        "source_ids": [],
        "evidence_ids": [],
        "sites": [],
        "assets": [],
        "asset_roles": [],
        "security_zones": [],
        "conduits": [],
        "protocols": [],
        "network_flows": [],
        "plcs": [],
        "rtus": [],
        "hmis": [],
        "scada_servers": [],
        "engineering_workstations": [],
        "historians": [],
        "safety_components": [],
        "process_relationships": {},
        "alarm_events": [],
        "industrial_events": [],
        "configuration_changes": [],
        "maintenance_context": [],
        "remote_access_paths": [],
        "third_party_access": [],
        "segmentation_context": [],
        "vulnerability_context": [],
        "attack_techniques": [],
        "threat_context": [],
        "malware_context": [],
        "incident_context": [],
        "physical_impact_context": [],
        "process_impact_context": [],
        "timeline_updates": [],
        "observations": [],
        "candidate_facts": [],
        "supported_facts": [],
        "partial_facts": [],
        "disputed_facts": [],
        "source_reliability": [],
        "source_bias": [],
        "source_limitations": [],
        "source_pedigree": [],
        "source_independence": [],
        "contradictions": [],
        "hypotheses": [],
        "falsification_results": [],
        "safety_flags": [
            "Passive-first only; no active OT validation performed.",
            "No controller/process/safety state changes were requested or simulated.",
            "Safety systems require read-only handling and human OT/safety engineer review.",
        ],
        "privacy_flags": [
            "Plant topology and operational metadata treated as sensitive.",
            "Report masks IPs/MACs/firmware values where practical.",
        ],
        "unknowns": [],
        "knowledge_gaps": [],
        "recommended_next_actions": [],
        "specialist_handoffs": [],
        "limitations": [],
        "dual_ai_review": {},
        "graph_memory": {},
        "status": "PARTIAL",
    }


def compute_source_bias(sources: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for sid, src in sources.items():
        st = normalize_text(src.get("source_type", "unknown")).lower()
        bias = []
        if st in {"asset_inventory"}:
            bias.append("inventory staleness/manual maintenance bias")
        if st in {"vendor_documentation", "security_advisory"}:
            bias.append("advisory scope may not match site configuration/version")
        if st in {"operator_statement"}:
            bias.append("recollection/visibility limitations")
        if st in {"threat_report"}:
            bias.append="generic IT/CTI may not fit OT context" if False else bias.append("generic IT/CTI may not fit OT context")
        if st in {"historian", "alarm_system", "scada_server_log", "controller_log"}:
            bias.append("telemetry visibility/clock/source-processing limitations")
        out.append({
            "source_id": sid,
            "source_type": st,
            "potential_bias": bias,
            "limitations": src.get("limitations", []),
        })
    return out


def finalize_status(
    policy_blocked: List[str],
    auth_ok: bool,
    assets: Dict[str, Any],
    contradictions: List[Dict[str, Any]],
    gaps: List[Dict[str, Any]],
) -> str:
    if policy_blocked:
        return "POLICY_BLOCKED"
    if not auth_ok:
        return "BLOCKED_PERMISSION"
    if not assets:
        return "ASSET_UNRESOLVED"
    if contradictions:
        return "PARTIAL"
    if any(g.get("importance") == "HIGH" for g in gaps):
        return "PARTIAL"
    if gaps:
        return "PARTIAL"
    return "SUCCEEDED"


def analyze_scadaint_manifest(manifest: Dict[str, Any]) -> Dict[str, Any]:
    result = empty_result(manifest)

    policy_blocked = policy_screen(manifest)
    if policy_blocked:
        result["status"] = "POLICY_BLOCKED"
        result["violations"] = policy_blocked
        result["limitations"] = [
            "SCADAINT does not write/control/manipulate PLCs, RTUs, HMIs, processes, safety systems, or live OT assets; it does not exploit, scan, probe, fuzz, spoof, disrupt, or provide sabotage guidance."
        ]
        return result

    auth_ok, auth_reasons = authorization_check(manifest)
    if not auth_ok:
        result["status"] = "BLOCKED_PERMISSION"
        result["limitations"] = auth_reasons
        return result

    sources = ingest_sources(manifest)
    roots = build_source_roots(sources)

    sites = ingest_sites(manifest)
    assets = ingest_assets(manifest)
    flows = ingest_flows(manifest)
    alarms = ingest_alarms(manifest)
    events = ingest_events(manifest)
    config_changes = ingest_config_changes(manifest)
    maintenance = ingest_maintenance(manifest)
    remote_access = ingest_remote_access(manifest)
    third_party = ingest_third_party(manifest)
    segmentation = ingest_segmentation(manifest)
    vulnerabilities = ingest_vulnerabilities(manifest)
    incidents = ingest_incidents(manifest)
    malware = ingest_malware(manifest)
    attack_techniques = ingest_attack_techniques(manifest)
    process_relationships = ingest_process_relationships(manifest)

    asset_assessments = assess_assets(assets, flows, sources, roots)
    network = analyze_network(assets, flows, maintenance, sources, roots)
    protocols = analyze_protocols(network)
    vuln_assessments = assess_vulnerabilities(assets, vulnerabilities, sources, roots)
    alarms_events = analyze_alarms_events(alarms, events, config_changes, maintenance, assets)
    incident_assessments = assess_incidents(incidents, vuln_assessments, maintenance, assets)

    contradictions = detect_contradictions(
        assets, asset_assessments, network, alarms_events,
        vulnerabilities, vuln_assessments, incident_assessments
    )
    hypotheses = build_hypotheses(network, vuln_assessments, incident_assessments)
    gaps = build_gaps(
        assets, asset_assessments, network, vulnerabilities,
        vuln_assessments, incident_assessments, contradictions, manifest
    )
    actions = build_next_actions(gaps)
    handoffs = build_handoffs(assets, network, vulnerabilities, malware, incidents, remote_access, third_party)
    graph = build_graph(
        sites, assets, asset_assessments, network, alarms, events,
        vulnerabilities, vuln_assessments, incidents, maintenance,
        contradictions, hypotheses, gaps, sources
    )
    review = dual_ai_review_stub(network, vuln_assessments, incident_assessments, contradictions, gaps)

    observations = [
        f"Sites ingested: {len(sites)}.",
        f"Assets ingested: {len(assets)}.",
        f"Passive/authorized flows ingested: {len(flows)}.",
        f"High-review flows: {len(network.get('high_review_flows', []))}.",
        f"Cross-zone flows: {len(network.get('cross_zone_flows', []))}.",
        f"Alarms: {len(alarms)}; events: {len(events)}; config changes: {len(config_changes)}.",
        f"Maintenance windows: {len(maintenance)}.",
        f"Vulnerability records: {len(vulnerabilities)}.",
        f"Incident records: {len(incidents)}; malware records: {len(malware)}.",
        f"Contradiction candidates: {len(contradictions)}.",
        f"Competing hypotheses: {len(hypotheses)}.",
        "No active OT validation, controller write, process manipulation, safety bypass, exploit, scan, spoof, disruption, or sabotage guidance was performed.",
        "Flow was not equated with control command; write was not equated with malicious activity.",
        "CVE/advisory was not equated with site vulnerability or exploitation.",
        "Cyber event was not equated with process/physical impact.",
        "Safety components were treated as read-only defensive context.",
    ]

    unknowns = []
    for aid, ass in asset_assessments.items():
        if ass.get("role_state") == "UNKNOWN":
            unknowns.append(f"Asset role unresolved for {aid}.")
        if not assets.get(aid, {}).get("firmware_version"):
            unknowns.append(f"Firmware unresolved for {aid}.")
    for vid, va in vuln_assessments.items():
        if va.get("applicability_state") in {"UNKNOWN", "POSSIBLE", "POSSIBLE_PENDING_FIRMWARE"}:
            unknowns.append(f"Vulnerability applicability unresolved for {vid}.")
    for inc in incident_assessments:
        if inc.get("physical_impact_state") == "UNKNOWN":
            unknowns.append(f"Process/physical impact unresolved for {inc['incident_id']}.")
    unknowns.append("Passive non-observation does not prove asset absence.")
    unknowns.append("Protocol/port evidence does not alone prove device role or exact model.")
    result["unknowns"] = list(dict.fromkeys(unknowns))[:500]

    result["sites"] = list(sites.values())
    result["assets"] = [
        {**a, "assessment": asset_assessments.get(aid, {})}
        for aid, a in assets.items()
    ]
    result["asset_roles"] = [
        {"asset_id": aid, "asset_type": a.get("asset_type"), "role_state": asset_assessments.get(aid, {}).get("role_state")}
        for aid, a in assets.items()
    ]
    result["security_zones"] = sorted({a.get("zone") for a in assets.values() if a.get("zone") and a.get("zone") != "UNKNOWN"})
    result["protocols"] = protocols
    result["network_flows"] = network.get("flows", [])
    result["plcs"] = [aid for aid, a in assets.items() if a.get("asset_type") == "PLC"]
    result["rtus"] = [aid for aid, a in assets.items() if a.get("asset_type") == "RTU"]
    result["hmis"] = [aid for aid, a in assets.items() if a.get("asset_type") == "HMI"]
    result["scada_servers"] = [aid for aid, a in assets.items() if a.get("asset_type") == "SCADA_SERVER"]
    result["engineering_workstations"] = [aid for aid, a in assets.items() if a.get("asset_type") == "ENGINEERING_WORKSTATION"]
    result["historians"] = [aid for aid, a in assets.items() if a.get("asset_type") == "HISTORIAN"]
    result["safety_components"] = [aid for aid, a in assets.items() if a.get("asset_type") in {"SIS_COMPONENT", "SAFETY_CONTROLLER", "PROTECTIVE_RELAY"}]
    result["process_relationships"] = process_relationships
    result["alarm_events"] = alarms
    result["industrial_events"] = events
    result["configuration_changes"] = config_changes
    result["maintenance_context"] = maintenance
    result["remote_access_paths"] = remote_access
    result["third_party_access"] = third_party
    result["segmentation_context"] = segmentation
    result["vulnerability_context"] = [
        {**v, "assessment": vuln_assessments.get(v["vulnerability_id"], {})}
        for v in vulnerabilities
    ]
    result["attack_techniques"] = attack_techniques
    result["malware_context"] = malware
    result["incident_context"] = incident_assessments
    result["physical_impact_context"] = [
        {"incident_id": i["incident_id"], "state": i.get("physical_impact_state"), "note": i.get("impact_note")}
        for i in incident_assessments
    ]
    result["process_impact_context"] = result["physical_impact_context"]
    result["timeline_updates"] = [
        {"flow_id": f["flow_id"], "first_seen": iso(f.get("first_seen")), "last_seen": iso(f.get("last_seen"))}
        for f in network.get("flows", [])
    ]
    result["observations"] = observations
    result["contradictions"] = contradictions
    result["hypotheses"] = hypotheses
    result["falsification_results"] = [
        {
            "hypothesis_id": h["hypothesis_id"],
            "category": h.get("category"),
            "opposition": h.get("opposition", []),
            "falsification_conditions": h.get("falsification_conditions", []),
        }
        for h in hypotheses
    ]
    result["knowledge_gaps"] = gaps
    result["recommended_next_actions"] = actions
    result["specialist_handoffs"] = handoffs
    result["dual_ai_review"] = review
    result["graph_memory"] = graph.to_dict()

    for sid, src in sources.items():
        result["source_ids"].append(sid)
        result["source_reliability"].append({
            "source_id": sid,
            "source_type": src.get("source_type"),
            "reliability": src.get("reliability"),
        })
        result["source_limitations"].append({
            "source_id": sid,
            "limitations": src.get("limitations", []),
        })
        result["source_pedigree"].append({
            "source_id": sid,
            "upstream_source_id": src.get("upstream_source_id"),
            "root_source_id": roots.get(sid, sid),
        })
    result["source_bias"] = compute_source_bias(sources)

    for aid, ass in asset_assessments.items():
        result["source_independence"].append({
            "asset_id": aid,
            "state": ass.get("source_assessment", {}).get("state"),
            "max_reliability": ass.get("source_assessment", {}).get("max_reliability"),
        })

    for aid, a in assets.items():
        ass = asset_assessments.get(aid, {})
        if ass.get("role_state") == "INVENTORY_SUPPORTED":
            result["supported_facts"].append({
                "asset_id": aid,
                "statement": f"Authorized inventory/source evidence supports {a.get('asset_type')} role for {aid}.",
            })
        elif ass.get("role_state") == "PASSIVE_ROLE_CANDIDATE":
            result["partial_facts"].append({
                "asset_id": aid,
                "statement": f"Passive protocol context suggests role candidate for {aid}; exact role unresolved.",
            })
        else:
            result["candidate_facts"].append({
                "asset_id": aid,
                "statement": f"Asset {aid} ingested but role/version context incomplete.",
            })

    for f in network.get("high_review_flows", [])[:300]:
        result["candidate_facts"].append({
            "flow_id": f["flow_id"],
            "statement": (
                f"Passive/authorized evidence shows {f.get('source_asset')} -> {f.get('dest_asset')} "
                f"using {f.get('protocol')} with operation class {f.get('operation_class')}; "
                f"maintenance context {f.get('maintenance_context')}; review priority {f.get('review_priority')}."
            ),
        })

    for c in contradictions:
        result["disputed_facts"].append({
            "contradiction_id": c["contradiction_id"],
            "statement": c.get("detail", "SCADA contradiction candidate."),
        })

    base_limits = [
        "SCADAINT starter uses only provided/local authorized records; no live OT access, scanning, probing, writing, exploiting, or disruption was performed.",
        "Passive-first default; active validation requires separate explicit authorization, change control, and safety review.",
        "Inventory is not current reality; passive non-observation is not asset absence.",
        "Port is not protocol; protocol is not device role; flow is not control command.",
        "Write/control observation is not malicious activity without authorization, baseline, and operator context.",
        "CVE/advisory is not site vulnerability; vulnerability is not exploitation; exploitation capability is not observed exploitation.",
        "Cyber event is not process impact; process disturbance is not cyberattack; physical impact is not malicious intent.",
        "Safety systems and protective relays are read-only defensive context only.",
        "No sabotage, process manipulation, safety bypass, physical damage optimization, or operational setpoint recommendation is provided.",
        "Multiple downstream logs/reports may share one upstream telemetry source; source independence assessed separately.",
    ]
    if auth_reasons:
        base_limits.extend(auth_reasons)
    result["limitations"] = list(dict.fromkeys(base_limits))

    result["status"] = finalize_status(policy_blocked, auth_ok, assets, contradictions, gaps)
    return result


def generate_report(result: Dict[str, Any]) -> str:
    lines = ["# SCADAINT Defensive SCADA/ICS Intelligence Report", ""]
    lines += [
        f"- Case ID: `{result.get('case_id')}`",
        f"- Task ID: `{result.get('task_id')}`",
        f"- Generated: `{result.get('generated_at')}`",
        f"- Version: `{result.get('version')}`",
        f"- Status: `{result.get('status')}`",
        "",
    ]

    if result.get("status") == "POLICY_BLOCKED":
        lines += ["## POLICY BLOCKED", "Violations:", *[f"- `{v}`" for v in result.get("violations", [])], ""]
        lines += ["No SCADA/ICS intelligence was performed."]
        return "\n".join(lines)

    lines += ["## Objective", str(result.get("objective", "")), ""]
    lines += ["## Safety / Authorization Boundaries",
              "- Passive-first; no active OT validation performed.",
              "- No PLC/RTU/HMI/controller writes, setpoint changes, logic/firmware changes, alarm disablement, safety bypass, or process manipulation.",
              "- No exploits, scanning, probing, fuzzing, brute force, default credential testing, MITM, spoofing, jamming, flooding, reboot, or disruption.",
              "- No sabotage/physical damage/process disruption guidance.",
              "- Safety systems treated as read-only defensive context; human OT/safety engineer review required for consequential action.",
              ""]

    lines += ["## Sites"]
    for s in result.get("sites", [])[:100]:
        lines.append(f"- Site `{s.get('site_id')}` name=`{s.get('name')}` sector=`{s.get('sector')}` facilities={s.get('facilities', [])[:10]}")
    lines.append("")

    lines += ["## Assets / Roles"]
    for a in result.get("assets", [])[:300]:
        ass = a.get("assessment", {})
        lines.append(f"### `{a.get('asset_id')}`")
        lines.append(f"- Type/role: `{a.get('asset_type')}` / `{ass.get('role_state')}`")
        lines.append(f"- Vendor/product/model: `{a.get('vendor')}` / `{a.get('product')}` / `{a.get('model')}`")
        lines.append(f"- Firmware/software: `{mask_value(a.get('firmware_version'))}` / `{mask_value(a.get('software_version'))}`")
        lines.append(f"- Zone/Purdue: `{a.get('zone')}` / `{a.get('purdue_level')}`")
        lines.append(f"- IPs (masked): {[mask_ip(x) for x in a.get('ip_addresses', [])[:5]]}")
        lines.append(f"- MACs (masked): {[mask_value(x, 2, 2) for x in a.get('mac_addresses', [])[:5]]}")
        lines.append(f"- Protocols: {a.get('protocols', [])}")
        lines.append(f"- Criticality/safety: `{a.get('criticality')}` / `{a.get('safety_relevance')}`")
        lines.append(f"- Observed in window: `{ass.get('observed_in_window')}` absence: `{ass.get('absence_interpretation')}`")
        lines.append(f"- Source independence: `{ass.get('source_assessment', {}).get('state')}` max reliability: `{ass.get('source_assessment', {}).get('max_reliability')}`")
        lines.append("")

    lines += ["## Network / Protocol Analysis"]
    proto = result.get("protocols", {})
    lines.append(f"- Protocol counts: `{json.dumps(proto.get('protocol_counts', {}), ensure_ascii=False, default=str)}`")
    lines.append(f"- Operation counts: `{json.dumps(proto.get('operation_counts', {}), ensure_ascii=False, default=str)}`")
    lines.append(f"- Legacy protocol context: {proto.get('legacy_protocol_context', [])}")
    lines.append(f"- Port/protocol inconsistencies: {proto.get('port_protocol_inconsistencies', [])[:50]}")
    for f in result.get("network_flows", [])[:300]:
        lines.append(
            f"- Flow `{f.get('flow_id')}` `{f.get('source_asset')}` -> `{f.get('dest_asset')}` "
            f"proto=`{f.get('protocol')}` op=`{f.get('operation_class')}` port={f.get('port')} "
            f"cross_zone={f.get('cross_zone')} maintenance={f.get('maintenance_context')} priority={f.get('review_priority')}"
        )
    lines.append("")

    lines += ["## Process Relationships"]
    pr = result.get("process_relationships", {})
    for r in pr.get("control", [])[:200]:
        lines.append(f"- Control `{r.get('relationship_id')}` controller=`{r.get('controller_asset_id')}` process=`{r.get('process_asset_id')}` function=`{r.get('process_function')}`")
    for r in pr.get("monitoring", [])[:200]:
        lines.append(f"- Monitoring `{r.get('relationship_id')}` sensor=`{r.get('sensor_asset_id')}` variable=`{r.get('process_variable')}` process=`{r.get('process_asset_id')}`")
    for r in pr.get("actuation", [])[:200]:
        lines.append(f"- Actuation `{r.get('relationship_id')}` actuator=`{r.get('actuator_asset_id')}` process=`{r.get('process_asset_id')}`")
    lines.append("")

    lines += ["## Alarms / Events / Configuration Changes / Maintenance"]
    for a in result.get("alarm_events", [])[:200]:
        lines.append(f"- Alarm `{a.get('alarm_id')}` asset=`{a.get('asset_id')}` priority=`{a.get('priority')}` first={iso(a.get('first_occurrence'))}")
    for e in result.get("industrial_events", [])[:200]:
        lines.append(f"- Event `{e.get('event_id')}` asset=`{e.get('asset_id')}` type=`{e.get('event_type')}` time={iso(e.get('timestamp'))}")
    for c in result.get("configuration_changes", [])[:200]:
        lines.append(f"- Config change `{c.get('change_id')}` asset=`{c.get('asset_id')}` type=`{c.get('change_type')}` approved={c.get('approved')} old=`{c.get('old_version')}` new=`{c.get('new_version')}`")
    for m in result.get("maintenance_context", [])[:200]:
        lines.append(f"- Maintenance `{m.get('maintenance_id')}` start={iso(m.get('start'))} end={iso(m.get('end'))} approved={m.get('approved')} assets={m.get('asset_ids', [])[:10]}")
    lines.append("")

    lines += ["## Remote Access / Third Party / Segmentation"]
    for r in result.get("remote_access_paths", [])[:200]:
        lines.append(f"- Remote `{r.get('remote_access_id')}` asset=`{r.get('asset_id')}` service=`{r.get('service')}` authorized={r.get('authorized')} mfa={r.get('mfa')} active_evidence={r.get('active_session_evidence')}")
    for t in result.get("third_party_access", [])[:200]:
        lines.append(f"- Third party `{t.get('third_party_id')}` asset=`{t.get('asset_id')}` vendor=`{t.get('vendor')}` authorized={t.get('authorized')}")
    for s in result.get("segmentation_context", [])[:200]:
        lines.append(f"- Segmentation `{s.get('segmentation_id')}` type=`{s.get('device_type')}` zones={s.get('zones', [])} effectiveness=`{s.get('observed_effectiveness')}`")
    lines.append("")

    lines += ["## Vulnerability Context"]
    for v in result.get("vulnerability_context", [])[:300]:
        ass = v.get("assessment", {})
        lines.append(
            f"- Vuln `{v.get('vulnerability_id')}` cve=`{v.get('cve')}` asset=`{v.get('asset_id')}` "
            f"applicability=`{ass.get('applicability_state')}` exploit_avail=`{v.get('exploit_availability')}` "
            f"known_exploitation_reported={v.get('known_exploitation_reported')}"
        )
        lines.append(f"  - reason: {ass.get('reason')}")
        if v.get("mitigations"):
            lines.append(f"  - mitigations: {', '.join(v.get('mitigations', [])[:10])}")
    lines.append("")

    lines += ["## Threat / Malware / ATT&CK for ICS Context"]
    for m in result.get("malware_context", [])[:200]:
        lines.append(f"- Malware `{m.get('malware_id')}` name=`{m.get('name')}` family=`{m.get('family')}` capability_claim=`{m.get('ics_capability_claim')}` observed_action=`{m.get('observed_action')}`")
    for t in result.get("attack_techniques", [])[:200]:
        lines.append(f"- Technique `{t.get('technique_mapping_id')}` id=`{t.get('technique_id')}` version=`{t.get('framework_version')}` asset=`{t.get('asset_id')}` evidence=`{t.get('behavior_evidence')}`")
    lines.append("")

    lines += ["## Incident / Process / Physical Impact Context"]
    for i in result.get("incident_context", [])[:300]:
        lines.append(
            f"- Incident `{i.get('incident_id')}` type=`{i.get('incident_type')}` asset=`{i.get('asset_id')}` "
            f"maintenance=`{i.get('maintenance_context')}` vuln_applicability=`{i.get('vulnerability_applicability')}` "
            f"impact=`{i.get('physical_impact_state')}`"
        )
    lines.append("")

    lines += ["## Source Independence / Reliability"]
    for si in result.get("source_independence", [])[:300]:
        lines.append(f"- Asset `{si.get('asset_id')}` source independence=`{si.get('state')}` max_reliability=`{si.get('max_reliability')}`")
    lines.append("")

    lines += ["## Contradictions"]
    for c in result.get("contradictions", [])[:300]:
        lines.append(f"- `{c.get('contradiction_id')}` [{c.get('severity')}] {c.get('type')}: {c.get('detail')}")
        if c.get("possible_causes"):
            lines.append(f"  - possible causes: {'; '.join(c['possible_causes'][:10])}")
    lines.append("")

    lines += ["## Competing Hypotheses / Falsification"]
    for h in result.get("hypotheses", [])[:500]:
        lines.append(f"- `{h.get('hypothesis_id')}` [{h.get('category')}] {h.get('subject_type')} `{h.get('subject_id')}`: {h.get('statement')}")
        if h.get("falsification_conditions"):
            lines.append(f"  - falsify if: {'; '.join(map(str, h['falsification_conditions'][:5]))}")
    lines.append("")

    lines += ["## Knowledge Gaps"]
    for g in result.get("knowledge_gaps", [])[:500]:
        lines.append(f"- `{g.get('gap_id')}` [{g.get('importance')}] {g.get('type')}: {g.get('recommended_source')}")
    lines.append("")

    lines += ["## Recommended Safe Next Actions"]
    for a in result.get("recommended_next_actions", [])[:500]:
        lines.append(f"- [{a.get('priority')}] {a.get('action')}")
    lines.append("")

    lines += ["## Specialist Handoffs"]
    for h in result.get("specialist_handoffs", []):
        lines.append(f"- {h.get('specialist')}: {h.get('reason')}")
        lines.append(f"  - payload: `{json.dumps(h.get('payload', {}), ensure_ascii=False, default=str)}`"[:1000])
    lines.append("")

    lines += ["## Dual-AI Review Stub"]
    dr = result.get("dual_ai_review", {})
    lines.append(f"- Status: `{dr.get('status')}`")
    lines.append(f"- Comparison: `{dr.get('comparison')}`")
    for n in dr.get("notes", []):
        lines.append(f"- {n}")
    for c in dr.get("primary_conclusions", [])[:50]:
        lines.append(f"- Primary: {c}")
    for c in dr.get("skeptic_challenges", [])[:50]:
        lines.append(f"- Skeptic: {c}")
    lines.append("")

    lines += ["## Limitations"]
    for lim in result.get("limitations", []):
        lines.append(f"- {lim}")
    lines.append("")

    lines += ["## Non-Negotiable Boundary",
              "- Observe first.",
              "- Preserve evidence.",
              "- Resolve asset and role.",
              "- Resolve product/version conservatively.",
              "- Understand process context.",
              "- Check maintenance and clock.",
              "- Verify vulnerability applicability.",
              "- Correlate before attribution.",
              "- Never touch the process just to prove a theory."]

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="TRACEATLAS SCADAINT compact safe starter")
    parser.add_argument("--manifest", required=True, help="Path to SCADAINT manifest JSON")
    parser.add_argument("--output", default="scadaint_result.json", help="Output JSON path")
    parser.add_argument("--report", default="scadaint_report.md", help="Output Markdown report path")
    args = parser.parse_args()

    try:
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"ERROR reading manifest: {exc}", file=sys.stderr)
        return 2

    result = analyze_scadaint_manifest(manifest)

    Path(args.output).write_text(
        json.dumps(json_safe(result), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    Path(args.report).write_text(generate_report(result), encoding="utf-8")

    print(f"Wrote: {args.output}")
    print(f"Wrote: {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())



{
  "case_id": "SCADA-CASE-001",
  "task_id": "SCADA-TASK-001",
  "objective": "Defensively analyze authorized passive SCADA telemetry and asset inventory for a synthetic water-treatment-like control environment. Do not actively probe, write, change setpoints, disable safety, or exploit any asset.",
  "questions": [
    "Which assets and roles are supported by inventory plus passive evidence?",
    "Were any write/control-category industrial protocol operations observed?",
    "Can maintenance context explain unusual flows?",
    "Which vulnerability applicability questions remain unresolved?",
    "What safe next actions and specialist handoffs are appropriate?"
  ],
  "authorization": {
    "approved": True,
    "scope": "authorized_ot_records",
    "model_mode": "LOCAL_ONLY",
    "cloud_approved": False,
    "ot_data_approved": True,
    "active_validation_approved": False
  },
  "active_validation_requested": False,
  "clock_offset_unknown": True,
  "sources": [
    {"source_id": "SINV", "source_type": "asset_inventory", "observed_at": "2026-10-01T00:00:00Z"},
    {"source_id": "SPASSIVE", "source_type": "authorized_ot_sensor", "observed_at": "2026-10-08T00:00:00Z"},
    {"source_id": "SADVISORY", "source_type": "security_advisory", "observed_at": "2026-09-01T00:00:00Z"},
    {"source_id": "SMAINT", "source_type": "incident_report", "observed_at": "2026-10-07T00:00:00Z"},
    {"source_id": "SHIST", "source_type": "historian", "observed_at": "2026-10-08T00:00:00Z"}
  ],
  "sites": [
    {
      "site_id": "SITE-WTP-1",
      "name": "Synthetic Water Treatment Plant 1",
      "sector": "WATER_WASTEWATER",
      "facilities": ["INTAKE", "TREATMENT", "PUMP_STATION"],
      "process_areas": ["RAW_WATER", "TREATED_WATER", "SLUDGE"],
      "source_ids": ["SINV"]
    }
  ],
  "assets": [
    {
      "asset_id": "SCADA-01",
      "site_id": "SITE-WTP-1",
      "asset_type": "SCADA_SERVER",
      "asset_role": "SCADA_SERVER",
      "vendor": "SyntheticAutomation",
      "product": "SyncSCADA",
      "model": "SS-5000",
      "firmware_version": None,
      "software_version": "2024.3",
      "hostname": "scada-01.synthetic.local",
      "ip_addresses": ["10.20.30.10"],
      "zone": "SUPERVISORY_ZONE",
      "purdue_level": "LEVEL_3",
      "protocols": ["MODBUS_TCP", "OPC_UA"],
      "criticality": "MISSION_CRITICAL",
      "safety_relevance": "MONITORING_ONLY",
      "lifecycle_state": "ACTIVE",
      "first_seen": "2026-09-01T00:00:00Z",
      "last_seen": "2026-10-08T00:00:00Z",
      "source_ids": ["SINV", "SPASSIVE"]
    },
    {
      "asset_id": "HMI-01",
      "site_id": "SITE-WTP-1",
      "asset_type": "HMI",
      "asset_role": "HMI",
      "vendor": "SyntheticAutomation",
      "product": "SyncView",
      "model": "HV-220",
      "firmware_version": None,
      "software_version": "2024.3",
      "hostname": "hmi-01.synthetic.local",
      "ip_addresses": ["10.20.30.11"],
      "zone": "SUPERVISORY_ZONE",
      "purdue_level": "LEVEL_2",
      "protocols": ["MODBUS_TCP"],
      "criticality": "BUSINESS_CRITICAL",
      "safety_relevance": "MONITORING_ONLY",
      "lifecycle_state": "ACTIVE",
      "source_ids": ["SINV", "SPASSIVE"]
    },
    {
      "asset_id": "PLC-PUMP-01",
      "site_id": "SITE-WTP-1",
      "asset_type": "PLC",
      "asset_role": "PLC",
      "vendor": "SyntheticControls",
      "product": "EdgePLC",
      "model": "EP-3200",
      "firmware_version": "4.2.1",
      "hostname": "plc-pump-01.synthetic.local",
      "ip_addresses": ["10.20.40.21"],
      "zone": "CONTROL_ZONE",
      "purdue_level": "LEVEL_1",
      "protocols": ["MODBUS_TCP"],
      "process_function": "RAW_WATER_PUMP_CONTROL",
      "criticality": "MISSION_CRITICAL",
      "safety_relevance": "NON_SAFETY",
      "lifecycle_state": "ACTIVE",
      "source_ids": ["SINV", "SPASSIVE"]
    },
    {
      "asset_id": "HIST-01",
      "site_id": "SITE-WTP-1",
      "asset_type": "HISTORIAN",
      "asset_role": "HISTORIAN",
      "vendor": "SyntheticData",
      "product": "ProcessHist",
      "model": "PH-100",
      "software_version": "2025.1",
      "ip_addresses": ["10.20.30.20"],
      "zone": "HISTORIAN_ZONE",
      "purdue_level": "LEVEL_3",
      "protocols": ["OPC_UA"],
      "criticality": "BUSINESS_CRITICAL",
      "safety_relevance": "MONITORING_ONLY",
      "source_ids": ["SINV"]
    },
    {
      "asset_id": "ENG-01",
      "site_id": "SITE-WTP-1",
      "asset_type": "ENGINEERING_WORKSTATION",
      "asset_role": "ENGINEERING_WORKSTATION",
      "vendor": "GenericPC",
      "product": "Workstation",
      "model": "WS-01",
      "software_version": "Windows-like 2025",
      "ip_addresses": ["10.20.30.31"],
      "zone": "SUPERVISORY_ZONE",
      "purdue_level": "LEVEL_2",
      "protocols": ["MODBUS_TCP", "OPC_UA"],
      "criticality": "HIGH",
      "safety_relevance": "NON_SAFETY",
      "source_ids": ["SINV"]
    }
  ],
  "flows": [
    {
      "flow_id": "F1",
      "source_asset": "HMI-01",
      "dest_asset": "PLC-PUMP-01",
      "protocol": "MODBUS_TCP",
      "port": 502,
      "function_code": 3,
      "operation_class": None,
      "first_seen": "2026-10-08T09:00:00Z",
      "last_seen": "2026-10-08T09:05:00Z",
      "packets": 120,
      "source_ids": ["SPASSIVE"],
      "confidence": 0.80
    },
    {
      "flow_id": "F2",
      "source_asset": "HMI-01",
      "dest_asset": "PLC-PUMP-01",
      "protocol": "MODBUS_TCP",
      "port": 502,
      "function_code": 16,
      "operation_class": None,
      "first_seen": "2026-10-08T10:15:00Z",
      "last_seen": "2026-10-08T10:15:30Z",
      "packets": 8,
      "source_ids": ["SPASSIVE"],
      "confidence": 0.78
    },
    {
      "flow_id": "F3",
      "source_asset": "ENG-01",
      "dest_asset": "PLC-PUMP-01",
      "protocol": "MODBUS_TCP",
      "port": 502,
      "function_code": 6,
      "operation_class": None,
      "first_seen": "2026-10-08T14:30:00Z",
      "last_seen": "2026-10-08T14:31:00Z",
      "unexpected": True,
      "source_ids": ["SPASSIVE"],
      "confidence": 0.76
    },
    {
      "flow_id": "F4",
      "source_asset": "SCADA-01",
      "dest_asset": "HIST-01",
      "protocol": "OPC_UA",
      "port": 4840,
      "operation_class": "READ",
      "first_seen": "2026-10-08T00:00:00Z",
      "last_seen": "2026-10-08T23:00:00Z",
      "source_ids": ["SPASSIVE", "SHIST"],
      "confidence": 0.82
    }
  ],
  "alarms": [
    {
      "alarm_id": "AL-01",
      "asset_id": "PLC-PUMP-01",
      "priority": "MEDIUM",
      "first_occurrence": "2026-10-08T10:16:00Z",
      "acknowledged": True,
      "related_process_event": "PUMP_SPEED_DEVIATION",
      "source_ids": ["SPASSIVE"],
      "confidence": 0.75
    }
  ],
  "events": [
    {
      "event_id": "EV-01",
      "asset_id": "PLC-PUMP-01",
      "event_type": "MODE_CHANGE",
      "timestamp": "2026-10-08T10:15:20Z",
      "account": "ops_shared_account",
      "description": "Mode change observed in authorized event log.",
      "source_ids": ["SPASSIVE"],
      "confidence": 0.70
    },
    {
      "event_id": "EV-02",
      "asset_id": "ENG-01",
      "event_type": "ENGINEERING_ACTION",
      "timestamp": "2026-10-08T14:29:00Z",
      "account": "vendor_contractor",
      "description": "Engineering action logged before unexpected PLC write-category flow.",
      "source_ids": ["SPASSIVE"],
      "confidence": 0.72
    }
  ],
  "configuration_changes": [
    {
      "change_id": "CFG-01",
      "asset_id": "PLC-PUMP-01",
      "change_type": "FIRMWARE",
      "old_version": "4.2.0",
      "new_version": "4.2.1",
      "changed_at": "2026-09-20T00:00:00Z",
      "approved": True,
      "ticket": "CHG-9001",
      "source_ids": ["SMAINT"],
      "confidence": 0.80
    }
  ],
  "maintenance_windows": [
    {
      "maintenance_id": "MAINT-01",
      "site_ids": ["SITE-WTP-1"],
      "asset_ids": ["PLC-PUMP-01", "ENG-01"],
      "start": "2026-10-08T14:00:00Z",
      "end": "2026-10-08T15:00:00Z",
      "description": "Authorized vendor tuning window.",
      "approved": True,
      "ticket": "WO-7788",
      "source_ids": ["SMAINT"],
      "confidence": 0.82
    }
  ],
  "remote_access_paths": [
    {
      "remote_access_id": "REM-01",
      "asset_id": "SCADA-01",
      "service": "VendorSupportPortal",
      "authorized": True,
      "mfa": True,
      "active_session_evidence": False,
      "last_session_at": "2026-10-07T18:00:00Z",
      "source_ids": ["SINV"],
      "confidence": 0.70
    }
  ],
  "third_party_access": [
    {
      "third_party_id": "TPA-01",
      "asset_id": "ENG-01",
      "vendor": "SyntheticVendorServices",
      "service": "PLC tuning support",
      "authorized": True,
      "contract_reference": "CONTRACT-44",
      "last_access_at": "2026-10-08T14:25:00Z",
      "source_ids": ["SMAINT"],
      "confidence": 0.75
    }
  ],
  "segmentation_controls": [
    {
      "segmentation_id": "SEG-01",
      "site_id": "SITE-WTP-1",
      "device_type": "INDUSTRIAL_FIREWALL",
      "zones": ["SUPERVISORY_ZONE", "CONTROL_ZONE"],
      "rules_summary": "Authorized supervisory-to-control Modbus traffic expected; engineering access restricted by policy.",
      "observed_effectiveness": "UNKNOWN",
      "source_ids": ["SINV"],
      "confidence": 0.65
    }
  ],
  "vulnerability_data": [
    {
      "vulnerability_id": "CVE-SYN-0001",
      "cve": "CVE-SYN-0001",
      "asset_id": "PLC-PUMP-01",
      "vendor": "SyntheticControls",
      "product": "EdgePLC",
      "model": "EP-3200",
      "affected_versions": ["4.2.1"],
      "configuration_prerequisites": ["Modbus TCP enabled"],
      "mitigations": ["Restrict engineering workstation access", "Review ACLs", "Apply vendor-supported patch during controlled outage"],
      "exploit_availability": "PUBLIC_POC_REPORTED",
      "known_exploitation_reported": False,
      "advisory": "Synthetic vendor advisory",
      "source_ids": ["SADVISORY"],
      "confidence": 0.78
    }
  ],
  "incidents": [
    {
      "incident_id": "INC-01",
      "asset_id": "PLC-PUMP-01",
      "site_id": "SITE-WTP-1",
      "incident_type": "UNEXPECTED_CONFIGURATION_CHANGE",
      "occurred_at": "2026-10-08T14:30:00Z",
      "description": "Unexpected write-category flow from engineering workstation during vendor maintenance window.",
      "exploitation_claim": False,
      "vulnerability_id": "CVE-SYN-0001",
      "physical_impact_state": "UNKNOWN",
      "process_impact_evidence": [],
      "source_ids": ["SPASSIVE", "SMAINT"],
      "confidence": 0.70
    }
  ],
  "malware_context": [],
  "attack_techniques": [
    {
      "technique_mapping_id": "ATT-01",
      "technique_id": "ICS-TTP-SYNTHETIC",
      "framework_version": "ATT&CK_ICS_SYNTHETIC_VERSION",
      "asset_id": "ENG-01",
      "behavior_evidence": "Engineering action followed by write-category PLC flow.",
      "confidence": 0.55,
      "source_ids": ["SPASSIVE"],
      "limitations": ["Technique mapping is not actor attribution."]
    }
  ],
  "control_relationships": [
    {
      "relationship_id": "CR-01",
      "controller_asset_id": "PLC-PUMP-01",
      "process_asset_id": "PUMP-RW-01",
      "process_function": "RAW_WATER_PUMP_CONTROL",
      "evidence": "Authorized engineering documentation",
      "source_ids": ["SINV"],
      "confidence": 0.75
    }
  ],
  "monitoring_relationships": [
    {
      "relationship_id": "MR-01",
      "sensor_asset_id": "SENSOR-PRESSURE-01",
      "process_variable": "pressure",
      "process_asset_id": "PUMP-RW-01",
      "source_ids": ["SINV"],
      "confidence": 0.70
    }
  ],
  "actuation_relationships": [
    {
      "relationship_id": "AR-01",
      "actuator_asset_id": "ACTUATOR-VALVE-01",
      "process_asset_id": "PIPE-RW-01",
      "source_ids": ["SINV"],
      "confidence": 0.68
    }
  ]
}
