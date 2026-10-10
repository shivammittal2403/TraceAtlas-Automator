#!/usr/bin/env python3
"""
TRACEATLAS IOTINT — Safe defensive IoT intelligence starter.

Mode: DEFENSIVE / AUTHORIZED / PASSIVE-FIRST / EVIDENCE-FIRST.

Hard boundaries:
- Does NOT access unauthorized devices.
- Does NOT test default credentials, brute force, password spray, or credential stuff.
- Does NOT bypass authentication, secure boot, encryption, or pairing.
- Does NOT exploit devices, execute remote commands, or deploy payloads.
- Does NOT flash/downgrade/modify firmware without authorized lab workflow.
- Does NOT clone/spoof device identities or use device keys/certificates.
- Does NOT connect to private MQTT brokers, publish control messages, or tamper topics.
- Does NOT perform BLE/Zigbee/Thread/Matter/Z-Wave/Wi-Fi/LoRaWAN/cellular attacks.
- Does NOT activate cameras/microphones, track private individuals, unlock locks,
  control vehicles/medical/industrial/safety devices, create botnets, or deploy malware.
- Treats vendor docs, firmware metadata, telemetry, scans, SBOMs, certificates,
  app metadata, and device banners as untrusted evidence, not instructions.
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

VERSION = "0.1.0-iotint-safe-defensive-starter"

ALLOWED_SCOPES = {
    "public_and_authorized_records",
    "authorized_case_evidence",
    "authorized_iot_records",
    "provided_records_only",
}

PROHIBITED_PATTERNS: List[Tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"(?i)\b(access|connect|login|authenticate|enter)\b.*"
            r"\b(unauthorized|private|unknown|victim)\b.*"
            r"\b(device|iot|camera|lock|vehicle|medical|mqtt|broker|network|fleet)\b"
        ),
        "UNAUTHORIZED_DEVICE_ACCESS",
    ),
    (
        re.compile(
            r"(?i)\b(try|test|use|attempt|validate|check|leverate)\b.*"
            r"\b(default|factory|leaked|stolen|exposed|shared)\b.*"
            r"\b(credential|password|token|key|secret)\b"
        ),
        "CREDENTIAL_TESTING_OR_MISUSE",
    ),
    (
        re.compile(r"(?i)\b(brute[- ]force|password spray|credential stuff)\b"),
        "CREDENTIAL_ATTACK",
    ),
    (
        re.compile(
            r"(?i)\b(bypass|break|defeat|override|disable)\b.*"
            r"\b(authentication|secure boot|encryption|pairing|iam|acl|mfa|lock|safety)\b"
        ),
        "AUTH_OR_SECURITY_BYPASS",
    ),
    (
        re.compile(
            r"(?i)\b(exploit|attack|compromise|pwn|rce|shell|payload)\b.*"
            r"\b(device|iot|camera|lock|vehicle|medical|mqtt|firmware|network|fleet)\b"
        ),
        "IOT_EXPLOITATION",
    ),
    (
        re.compile(
            r"(?i)\b(execute|run|send|issue)\b.*"
            r"\b(remote command|control command|command|payload|actuation)\b.*"
            r"\b(device|iot|camera|lock|vehicle|medical|mqtt|industrial)\b"
        ),
        "REMOTE_COMMAND_EXECUTION",
    ),
    (
        re.compile(
            r"(?i)\b(flash|downgrade|modify|replace|rewrite)\b.*"
            r"\b(firmware|bootloader|image)\b"
        ),
        "UNAUTHORIZED_FIRMWARE_MODIFICATION",
    ),
    (
        re.compile(
            r"(?i)\b(clone|spoof|forge|replay|reuse)\b.*"
            r"\b(device identity|certificate|key|token|mac|serial|matter|zigbee|z-wave|ble|mqtt client)\b"
        ),
        "IDENTITY_CLONING_OR_SPOOFING",
    ),
    (
        re.compile(
            r"(?i)\b(publish|inject|tamper|subscribe|join|commission)\b.*"
            r"\b(mqtt topic|control message|zwave|zigbee|matter|thread|ble|wireless|fabric)\b"
        ),
        "PROTOCOL_MESSAGE_ABUSE",
    ),
    (
        re.compile(
            r"(?i)\b(deauth|deauthenticate|jam|intercept|imsi[- ]catch|rogue base station|capture private)\b"
        ),
        "WIRELESS_ATTACK_OR_INTERCEPTION",
    ),
    (
        re.compile(
            r"(?i)\b(activate|access|view|stream|record)\b.*"
            r"\b(camera|microphone|video|audio|speaker)\b"
        ),
        "PRIVACY_INTRUSION_RISK",
    ),
    (
        re.compile(
            r"(?i)\b(unlock|open|bypass|defeat)\b.*"
            r"\b(lock|door|access control|safe|gate)\b"
        ),
        "PHYSICAL_ACCESS_BYPASS",
    ),
    (
        re.compile(
            r"(?i)\b(control|take over|hijack|disable|manipulate)\b.*"
            r"\b(vehicle|medical device|industrial equipment|safety device|alarm|thermostat|hvac|pacemaker|insulin)\b"
        ),
        "SAFETY_CRITICAL_CONTROL",
    ),
    (
        re.compile(r"(?i)\b(create|build|deploy|operate)\b.*\b(botnet|iot malware)\b"),
        "BOTNET_OR_MALWARE_CREATION",
    ),
    (
        re.compile(
            r"(?i)\b(denial of service|dos|ddos|flood|overwhelm|exhaust)\b.*"
            r"\b(device|iot|network|service|broker|api)\b"
        ),
        "DENIAL_OF_SERVICE",
    ),
    (
        re.compile(
            r"(?i)\b(track|stalk|locate|surveil|follow)\b.*"
            r"\b(person|individual|home|occupant|wearer|private location|victim)\b"
        ),
        "PRIVACY_TRACKING",
    ),
]

DEVICE_CLASSES = {
    "SMART_CAMERA", "SMART_DOORBELL", "SMART_LOCK", "SMART_TV", "SMART_SPEAKER",
    "SMART_LIGHT", "THERMOSTAT", "SENSOR", "ACTUATOR", "WEARABLE", "ROUTER",
    "GATEWAY", "HUB", "APPLIANCE", "METER", "TRACKER", "BUILDING_DEVICE",
    "HEALTH_DEVICE", "VEHICLE_ACCESSORY", "INDUSTRIAL_EDGE_DEVICE",
    "ENVIRONMENTAL_SENSOR", "OTHER", "UNKNOWN",
}

EXPOSURE_STATES = {
    "LOCAL_NETWORK_ONLY", "INTERNET_EXPOSED", "CLOUD_MEDIATED",
    "VPN_PROTECTED", "UNKNOWN",
}

OWNERSHIP_STATES = {
    "OWNERSHIP_VERIFIED", "OWNERSHIP_CANDIDATE", "UNMANAGED_DEVICE",
    "UNREGISTERED_DEVICE", "ROGUE_DEVICE_CANDIDATE", "UNKNOWN",
}

CRITICALITY_STATES = {
    "SAFETY_CRITICAL", "MISSION_CRITICAL", "BUSINESS_CRITICAL",
    "HIGH", "MEDIUM", "LOW", "UNKNOWN",
}

PRIVACY_SENSITIVITY = {
    "VIDEO", "AUDIO", "LOCATION", "HEALTH", "BIOMETRIC",
    "HOME_ACTIVITY", "OCCUPANCY", "ACCOUNT", "CHILD", "OTHER", "UNKNOWN",
}

PHYSICAL_SAFETY = {
    "ACCESS_CONTROL", "VEHICLE", "MEDICAL", "INDUSTRIAL",
    "BUILDING_SAFETY", "FIRE_SECURITY", "HAZARDOUS_EQUIPMENT",
    "OTHER", "UNKNOWN",
}

LIFECYCLE_STATES = {
    "ANNOUNCED", "RELEASED", "SUPPORTED", "MAINTENANCE",
    "SECURITY_ONLY", "END_OF_SALE", "END_OF_SUPPORT", "END_OF_LIFE", "UNKNOWN",
}

SUPPORT_STATUS = {
    "SUPPORTED", "LIMITED_SUPPORT", "SECURITY_ONLY",
    "END_OF_SUPPORT", "END_OF_LIFE", "UNKNOWN",
}

PROTOCOLS = {
    "HTTP", "HTTPS", "MQTT", "COAP", "UPNP", "SSDP", "MDNS", "DNS",
    "NTP", "RTSP", "SSH", "TELNET", "FTP", "WEBSOCKET", "BLE", "ZIGBEE",
    "THREAD", "MATTER", "ZWAVE", "WIFI", "LORAWAN", "NB_IOT", "LTE_M",
    "CELLULAR", "OTHER", "UNKNOWN",
}

INTERFACES = {
    "ETHERNET", "WIFI", "BLE", "ZIGBEE", "THREAD", "MATTER", "ZWAVE",
    "NFC", "LORAWAN", "CELLULAR", "USB", "UART", "JTAG", "SWD", "CAN",
    "GPIO", "SERIAL", "OTHER", "UNKNOWN",
}

CLOUD_RELATIONSHIPS = {
    "TELEMETRY_TO", "RECEIVES_COMMANDS_FROM", "AUTHENTICATES_TO",
    "CHECKS_UPDATE_AT", "UPLOADS_MEDIA_TO", "USES_API", "UNKNOWN",
}

CERT_ROLES = {
    "DEVICE_IDENTITY", "SERVER_TLS", "MUTUAL_TLS", "FLEET_PROVISIONING",
    "OTA_SIGNING", "API_AUTH", "OTHER", "UNKNOWN",
}

VULN_APPLICABILITY_STATES = {
    "APPLICABLE_PENDING_VALIDATION",
    "COMPONENT_APPLICABLE_PENDING_VALIDATION",
    "POSSIBLE_PENDING_FIRMWARE",
    "COMPONENT_CANDIDATE_PENDING_VALIDATION",
    "POSSIBLE",
    "NOT_APPLICABLE_BASED_ON_MISMATCH",
    "NOT_APPLICABLE_BASED_ON_FIXED_VERSION",
    "UNKNOWN",
}

EXPLOIT_AVAILABILITY_STATES = {
    "NO_PUBLIC_EXPLOIT_KNOWN", "PUBLIC_POC_REPORTED", "EXPLOIT_REPORTED",
    "KNOWN_EXPLOITATION_REPORTED", "UNKNOWN",
}

VEX_STATUS = {
    "AFFECTED", "NOT_AFFECTED", "FIXED", "UNDER_INVESTIGATION", "UNKNOWN",
}

SBOM_FORMATS = {
    "CYCLONEDX", "SPDX", "VENDOR_SBOM", "GENERATED_SBOM", "UNKNOWN",
}

TELEMETRY_TYPES = {
    "DNS", "CONNECTION", "SERVICE", "FLOW", "ALERT", "UPDATE_CHECK",
    "TELEMETRY_UPLOAD", "AUTH_EVENT", "OTHER", "UNKNOWN",
}

INCIDENT_TYPES = {
    "UNEXPECTED_OUTBOUND_TRAFFIC", "CONFIGURATION_CHANGE", "REBOOT_ANOMALY",
    "UNKNOWN_DNS", "NEW_CERTIFICATE", "UNEXPECTED_ACCOUNT", "MALWARE_ALERT",
    "VENDOR_INCIDENT", "NETWORK_BEHAVIOR_SHIFT", "BOTNET_REPORT", "OTHER", "UNKNOWN",
}

INCIDENT_STATES = {
    "NO_COMPROMISE_EVIDENCE", "ANOMALY_OBSERVED", "COMPROMISE_CANDIDATE",
    "COMPROMISE_SUPPORTED", "COMPROMISE_VERIFIED_BY_INCIDENT_EVIDENCE", "INCONCLUSIVE",
}

BOTNET_STATES = {
    "NONE_PROVIDED", "BOTNET_ASSOCIATION_REPORTED",
    "BOTNET_PARTICIPATION_CANDIDATE", "BOTNET_PARTICIPATION_SUPPORTED", "UNKNOWN",
}

FLEET_COUNT_STATES = {
    "VERIFIED_COUNT", "INVENTORY_COUNT", "OBSERVED_COUNT", "ESTIMATED_COUNT", "UNKNOWN",
}

AUTH_WEAKNESS_STATES = {
    "SOURCE_REPORTED_AUTH_WEAKNESS", "VULNERABILITY_SUPPORTED",
    "CONFIGURATION_CANDIDATE", "UNKNOWN",
}

SOURCE_RELIABILITY: Dict[str, float] = {
    "official_vendor_documentation": 0.90,
    "authorized_device_inventory": 0.88,
    "authorized_telemetry": 0.86,
    "firmware_image": 0.84,
    "vendor_advisory": 0.84,
    "certificate_transparency": 0.80,
    "authorized_scan_result": 0.78,
    "public_internet_index": 0.62,
    "security_research": 0.60,
    "retailer_listing": 0.45,
    "community_forum": 0.35,
    "unknown": 0.30,
}


# --------------------------------------------------------------------
# Generic helpers
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


def add_unique(lst: List[Any], item: Any) -> None:
    if item is None:
        return
    key = json.dumps(json_safe(item), sort_keys=True, ensure_ascii=False)
    for existing in lst:
        if json.dumps(json_safe(existing), sort_keys=True, ensure_ascii=False) == key:
            return
    lst.append(item)


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


def mask_mac(value: Any) -> str:
    s = re.sub(r"[^0-9A-Fa-f]", "", normalize_text(value)).upper()
    if len(s) != 12:
        return mask_value(value, 2, 2)
    return f"{s[:2]}:{s[2:4]}:**:**:**:{s[10:]}"


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


def hash_string(value: Any) -> str:
    return hashlib.sha256(normalize_text(value).encode("utf-8")).hexdigest()


def within_time(ts: Optional[datetime], start: Optional[datetime], end: Optional[datetime]) -> bool:
    if ts is None:
        return False
    if start and ts < start:
        return False
    if end and ts > end:
        return False
    return True


def days_between(a: Optional[datetime], b: Optional[datetime]) -> Optional[int]:
    if not a or not b:
        return None
    return (b - a).days


def normalize_version(value: Any) -> str:
    return normalize_text(value).lower()


def version_in_list(value: Any, values: Any) -> Optional[bool]:
    v = normalize_version(value)
    if not v or values in (None, "", []):
        return None
    if isinstance(values, str):
        vals = [values]
    elif isinstance(values, list):
        vals = values
    else:
        vals = [str(values)]
    norm = [normalize_text(x).lower() for x in vals if normalize_text(x)]
    if not norm:
        return None
    if v in norm:
        return True
    if any(re.search(r"[-~]|through|to|<|>|=", x) for x in norm):
        return None
    return False


def field_match(left: Any, right: Any) -> Optional[bool]:
    l = normalize_text(left).lower()
    r = normalize_text(right).lower()
    if not l or not r:
        return None
    return l == r


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


def has_iot_sensitive_data(manifest: Dict[str, Any]) -> bool:
    keys = (
        "devices", "device_inventory", "telemetry", "network_logs", "pcaps",
        "scan_results", "firmware_images", "sboms", "certificates",
        "mobile_apps", "cloud_context",
    )
    return any(manifest.get(k) for k in keys)


def has_safety_critical_device(manifest: Dict[str, Any]) -> bool:
    for d in manifest.get("devices", []) or []:
        phys = [normalize_token(x) for x in source_list(d.get("physical_safety_relevance"))]
        crit = normalize_token(d.get("criticality"))
        cls = normalize_token(d.get("device_class"))
        if crit == "SAFETY_CRITICAL":
            return True
        if set(phys) & {"ACCESS_CONTROL", "VEHICLE", "MEDICAL", "INDUSTRIAL", "BUILDING_SAFETY", "FIRE_SECURITY", "HAZARDOUS_EQUIPMENT"}:
            return True
        if cls in {"SMART_LOCK", "HEALTH_DEVICE", "VEHICLE_ACCESSORY", "INDUSTRIAL_EDGE_DEVICE"}:
            return True
    return False


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

    if has_iot_sensitive_data(manifest) and not auth.get("iot_data_approved"):
        reasons.append("IOT_DATA_NOT_APPROVED")

    if manifest.get("active_validation_requested") and not auth.get("active_validation_approved"):
        reasons.append("ACTIVE_VALIDATION_NOT_APPROVED")

    if manifest.get("private_location_requested") and not auth.get("private_location_approved"):
        reasons.append("PRIVATE_LOCATION_NOT_APPROVED")

    if has_safety_critical_device(manifest) and not auth.get("safety_review_approved"):
        reasons.append("SAFETY_CRITICAL_HUMAN_REVIEW_REQUIRED")

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

def normalize_component(comp: Any) -> Dict[str, Any]:
    if isinstance(comp, str):
        return {"name": normalize_text(comp), "version": None, "purl": None, "hash": None}
    if not isinstance(comp, dict):
        return {"name": normalize_text(comp), "version": None, "purl": None, "hash": None}
    return {
        "name": normalize_text(comp.get("name") or comp.get("component") or comp.get("package")),
        "version": normalize_text(comp.get("version")) or None,
        "purl": normalize_text(comp.get("purl")) or None,
        "hash": normalize_text(comp.get("hash") or comp.get("sha256")) or None,
        "source_ids": source_list(comp.get("source_ids"), comp.get("source_id")),
    }


def ingest_devices(manifest: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    devices: Dict[str, Dict[str, Any]] = {}
    raw = manifest.get("devices") or manifest.get("device_inventory") or []
    for idx, d in enumerate(raw):
        did = normalize_text(d.get("device_id") or d.get("id") or d.get("name") or f"DEVICE-{idx}")
        if not did:
            continue
        services = []
        for s in d.get("services", []) or []:
            if isinstance(s, str):
                services.append({"name": s})
            elif isinstance(s, dict):
                services.append(s)
        components = [normalize_component(c) for c in (d.get("software_components", []) or [])]
        protocols = [norm_enum(p, PROTOCOLS) for p in source_list(d.get("protocols"))]
        interfaces = [norm_enum(x, INTERFACES) for x in source_list(d.get("network_interfaces"), d.get("interfaces"))]
        wireless = [norm_enum(x, INTERFACES) for x in source_list(d.get("wireless_interfaces"))]
        privacy = [normalize_token(x) for x in source_list(d.get("privacy_sensitivity"))]
        physical = [normalize_token(x) for x in source_list(d.get("physical_safety_relevance"))]
        devices[did] = {
            "device_id": did,
            "device_class": norm_enum(d.get("device_class"), DEVICE_CLASSES),
            "manufacturer": normalize_text(d.get("manufacturer")) or None,
            "brand": normalize_text(d.get("brand")) or None,
            "oem": normalize_text(d.get("oem")) or None,
            "odm": normalize_text(d.get("odm")) or None,
            "product_family": normalize_text(d.get("product_family") or d.get("product")) or None,
            "model": normalize_text(d.get("model")) or None,
            "variant": normalize_text(d.get("variant")) or None,
            "hardware_revision": normalize_text(d.get("hardware_revision") or d.get("revision")) or None,
            "firmware_version": normalize_text(d.get("firmware_version") or d.get("firmware")) or None,
            "os": normalize_text(d.get("os")) or None,
            "rtos": normalize_text(d.get("rtos")) or None,
            "architecture": normalize_text(d.get("architecture")) or None,
            "chipset_candidate": normalize_text(d.get("chipset_candidate") or d.get("chipset")) or None,
            "serial_reference": [mask_value(x, 2, 2) for x in source_list(d.get("serial_reference"), d.get("serials"))],
            "mac_reference": [mask_mac(x) for x in source_list(d.get("mac_reference"), d.get("mac_addresses"), d.get("mac"))],
            "ip_references": [mask_ip(x) for x in source_list(d.get("ip_references"), d.get("ips"), d.get("ip"))],
            "hostnames": source_list(d.get("hostnames"), d.get("hostname")),
            "device_identities": source_list(d.get("device_identities"), d.get("device_identity")),
            "certificates": d.get("certificates", []) or [],
            "interfaces": [x for x in interfaces if x != "UNKNOWN"],
            "wireless_interfaces": [x for x in wireless if x != "UNKNOWN"],
            "services": services,
            "protocols": [p for p in protocols if p != "UNKNOWN"] or ["UNKNOWN"],
            "cloud_dependencies": d.get("cloud_dependencies", []) or [],
            "api_dependencies": d.get("api_dependencies", []) or [],
            "mobile_app_dependencies": d.get("mobile_app_dependencies", []) or [],
            "software_components": components,
            "lifecycle": norm_enum(d.get("lifecycle"), LIFECYCLE_STATES),
            "support_status": norm_enum(d.get("support_status"), SUPPORT_STATUS),
            "criticality": norm_enum(d.get("criticality"), CRITICALITY_STATES),
            "privacy_sensitivity": privacy,
            "physical_safety_relevance": physical,
            "ownership_state": norm_enum(d.get("ownership_state"), OWNERSHIP_STATES),
            "location_safe": normalize_text(d.get("location_safe") or d.get("site") or d.get("region")) or None,
            "network_segment": normalize_text(d.get("network_segment") or d.get("vlan") or d.get("subnet")) or None,
            "internet_exposure": norm_enum(d.get("internet_exposure"), EXPOSURE_STATES),
            "last_internet_scan_at": parse_time(d.get("last_internet_scan_at")),
            "fingerprint_evidence": source_list(d.get("fingerprint_evidence")),
            "fingerprint_verified": bool(d.get("fingerprint_verified")),
            "first_seen": parse_time(d.get("first_seen")),
            "last_seen": parse_time(d.get("last_seen")),
            "source_ids": source_list(d.get("source_ids"), d.get("source_id")),
            "confidence": clamp(float(d.get("confidence", 0.65))),
            "limitations": list(d.get("limitations", []) or []) + [
                "Device class is not model; brand is not manufacturer; model is not hardware revision.",
                "MAC/OUI may identify NIC/module vendor, not final product manufacturer or owner.",
                "IP is not permanent device identity; public IP is not exact device location.",
                "Open service is exposure context, not vulnerability.",
                "Banner is not verified version unless independently supported.",
            ],
        }
    return devices


def extend_nested_records(devices: Dict[str, Dict[str, Any]], manifest: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    buckets = {
        "certificates": list(manifest.get("certificates", []) or []),
        "ota": list(manifest.get("ota_update_context", []) or []),
        "authentication": list(manifest.get("authentication_context", []) or []),
        "sboms": list(manifest.get("sboms", []) or []),
        "vulnerabilities": list(manifest.get("vulnerabilities", []) or manifest.get("vulnerability_data", []) or []),
        "telemetry": list(manifest.get("telemetry", []) or manifest.get("network_logs", []) or []),
        "incidents": list(manifest.get("incidents", []) or []),
        "malware": list(manifest.get("malware_context", []) or []),
        "supply_chain": list(manifest.get("supply_chain_context", []) or []),
    }
    for did, d in devices.items():
        for key, field in (
            ("certificates", "certificates"),
            ("ota", "ota_update_context"),
            ("authentication", "authentication_context"),
            ("sboms", "sboms"),
            ("vulnerabilities", "vulnerabilities"),
            ("telemetry", "telemetry"),
            ("incidents", "incidents"),
            ("malware", "malware_context"),
            ("supply_chain", "supply_chain_context"),
        ):
            for rec in d.get(field, []) or []:
                if isinstance(rec, dict):
                    rec = dict(rec)
                    rec.setdefault("device_id", did)
                    buckets[key].append(rec)
    return buckets


def index_by_device(records: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in records:
        did = normalize_text(r.get("device_id"))
        if did:
            out[did].append(r)
    return out


def ingest_fleets(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for idx, f in enumerate(manifest.get("fleets", []) or []):
        out.append({
            "fleet_id": normalize_text(f.get("fleet_id") or f.get("id") or f"FLEET-{idx}"),
            "organization": normalize_text(f.get("organization")) or None,
            "device_ids": source_list(f.get("device_ids"), f.get("devices")),
            "product_family": normalize_text(f.get("product_family")) or None,
            "models": source_list(f.get("models")),
            "count_state": norm_enum(f.get("count_state"), FLEET_COUNT_STATES),
            "location_safe": normalize_text(f.get("location_safe") or f.get("region")) or None,
            "criticality": norm_enum(f.get("criticality"), CRITICALITY_STATES),
            "support_state": norm_enum(f.get("support_state"), SUPPORT_STATUS),
            "source_ids": source_list(f.get("source_ids"), f.get("source_id")),
            "confidence": clamp(float(f.get("confidence", 0.60))),
        })
    return out


def ingest_maintenance(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for idx, m in enumerate(manifest.get("maintenance_windows", []) or manifest.get("maintenance", []) or []):
        out.append({
            "maintenance_id": normalize_text(m.get("maintenance_id") or m.get("id") or f"MAINT-{idx}"),
            "device_ids": source_list(m.get("device_ids"), m.get("device_id")),
            "start": parse_time(m.get("start") or m.get("start_date")),
            "end": parse_time(m.get("end") or m.get("end_date")),
            "description": normalize_text(m.get("description")) or None,
            "approved": m.get("approved"),
            "ticket": normalize_text(m.get("ticket")) or None,
            "source_ids": source_list(m.get("source_ids"), m.get("source_id")),
            "confidence": clamp(float(m.get("confidence", 0.60))),
        })
    return out


def determine_as_of(
    manifest: Dict[str, Any],
    devices: Dict[str, Dict[str, Any]],
    telemetry: List[Dict[str, Any]],
    sources: Dict[str, Dict[str, Any]],
) -> Optional[datetime]:
    candidates: List[datetime] = []
    as_of = parse_time((manifest.get("time_range") or {}).get("as_of"))
    if as_of:
        candidates.append(as_of)
    for d in devices.values():
        for k in ("first_seen", "last_seen", "last_internet_scan_at"):
            v = d.get(k)
            if isinstance(v, datetime):
                candidates.append(v)
    for t in telemetry:
        v = parse_time(t.get("timestamp") or t.get("observed_at"))
        if v:
            candidates.append(v)
    for s in sources.values():
        v = parse_time(s.get("observed_at"))
        if v:
            candidates.append(v)
    return max(candidates) if candidates else None


# --------------------------------------------------------------------
# Identity / service / dependency analysis
# --------------------------------------------------------------------

def resolve_device_identity(
    d: Dict[str, Any],
    sources: Dict[str, Dict[str, Any]],
    roots: Dict[str, str],
    has_certificate: bool,
) -> Dict[str, Any]:
    sa = source_assessment(d.get("source_ids", []), sources, roots)
    max_rel = sa["max_reliability"]

    def simple_state(field: str, strong: float = 0.80) -> str:
        if d.get(field):
            return "SUPPORTED" if max_rel >= strong else "CANDIDATE"
        return "UNKNOWN"

    model_state = "MODEL_SUPPORTED" if d.get("model") and max_rel >= 0.80 else ("MODEL_CANDIDATE" if d.get("model") else "UNKNOWN")
    firmware_state = "SUPPORTED" if d.get("firmware_version") and max_rel >= 0.80 else ("CANDIDATE" if d.get("firmware_version") else "UNKNOWN")
    revision_state = "SUPPORTED" if d.get("hardware_revision") and max_rel >= 0.80 else ("CANDIDATE" if d.get("hardware_revision") else "UNKNOWN")

    unique_identity = bool(d.get("device_identities") or d.get("serial_reference") or d.get("mac_reference") or has_certificate)
    if unique_identity and model_state == "MODEL_SUPPORTED" and firmware_state == "SUPPORTED" and max_rel >= 0.85:
        instance_state = "DEVICE_INSTANCE_SUPPORTED"
    elif unique_identity and (model_state != "UNKNOWN" or firmware_state != "UNKNOWN"):
        instance_state = "DEVICE_INSTANCE_CANDIDATE"
    else:
        instance_state = "UNKNOWN"

    fp_count = len(d.get("fingerprint_evidence", []) or [])
    if d.get("fingerprint_verified") and sa["state"] == "INDEPENDENT" and max_rel >= 0.85:
        fingerprint_confidence = "VERIFIED"
    elif fp_count >= 3 and sa["state"] == "INDEPENDENT" and max_rel >= 0.80:
        fingerprint_confidence = "HIGH"
    elif fp_count >= 2:
        fingerprint_confidence = "MEDIUM"
    elif fp_count == 1:
        fingerprint_confidence = "LOW"
    else:
        fingerprint_confidence = "UNKNOWN"

    return {
        "device_class_state": simple_state("device_class"),
        "manufacturer_state": simple_state("manufacturer"),
        "brand_state": simple_state("brand"),
        "oem_state": "CANDIDATE" if d.get("oem") else "UNKNOWN",
        "odm_state": "CANDIDATE" if d.get("odm") else "UNKNOWN",
        "product_family_state": simple_state("product_family"),
        "model_state": model_state,
        "variant_state": simple_state("variant"),
        "hardware_revision_state": revision_state,
        "firmware_state": firmware_state,
        "device_instance_state": instance_state,
        "fingerprint_confidence": fingerprint_confidence,
        "source_assessment": sa,
        "limitations": [
            "Evidence burden increases down the identity ladder.",
            "Brand may be retailer/white-label; manufacturer/OEM/ODM may differ.",
            "MAC OUI may identify NIC/module vendor, not final product manufacturer.",
            "Serial/MAC/IP are not person identity.",
        ],
    }


def analyze_services(d: Dict[str, Any]) -> Dict[str, Any]:
    out = []
    for idx, s in enumerate(d.get("services", []) or []):
        name = normalize_text(s.get("name") or s.get("service") or f"SVC-{idx}")
        port = parse_int(s.get("port"))
        exposure = norm_enum(s.get("exposure"), EXPOSURE_STATES)
        version_claim = normalize_text(s.get("version_claim") or s.get("banner_version")) or None
        version_verified = bool(s.get("version_verified"))
        out.append({
            "service_id": normalize_text(s.get("service_id")) or stable_id("SVC", d["device_id"], name, port, idx),
            "name": name,
            "port": port,
            "exposure": exposure,
            "version_claim": version_claim,
            "version_verified": version_verified,
            "banner_not_verified": bool(version_claim) and not version_verified,
            "observation_not_vulnerability": True,
            "source_ids": source_list(s.get("source_ids"), s.get("source_id")),
        })
    internet_candidate = any(x["exposure"] == "INTERNET_EXPOSED" for x in out) or d.get("internet_exposure") == "INTERNET_EXPOSED"
    return {
        "services": out,
        "internet_exposed_service_candidate": internet_candidate,
        "limitations": [
            "Open port/service is exposure context, not vulnerability.",
            "Service banner is not verified version unless independently supported.",
        ],
    }


def analyze_dependencies(d: Dict[str, Any]) -> Dict[str, Any]:
    cloud = []
    for idx, c in enumerate(d.get("cloud_dependencies", []) or []):
        if isinstance(c, str):
            c = {"endpoint": c}
        cloud.append({
            "dependency_id": normalize_text(c.get("dependency_id")) or stable_id("CLOUD", d["device_id"], idx),
            "provider": normalize_text(c.get("provider") or c.get("cloud_provider")) or None,
            "endpoint": normalize_text(c.get("endpoint") or c.get("domain") or c.get("url")) or None,
            "relationship": norm_enum(c.get("relationship") or c.get("role"), CLOUD_RELATIONSHIPS),
            "evidence": normalize_text(c.get("evidence")) or None,
            "source_ids": source_list(c.get("source_ids"), c.get("source_id")),
        })
    apps = []
    for idx, a in enumerate(d.get("mobile_app_dependencies", []) or []):
        if isinstance(a, str):
            a = {"name": a}
        apps.append({
            "app_dependency_id": normalize_text(a.get("app_dependency_id")) or stable_id("APP", d["device_id"], idx),
            "name": normalize_text(a.get("name") or a.get("app")) or None,
            "platform": normalize_text(a.get("platform")).upper() or None,
            "package_or_bundle": normalize_text(a.get("package_or_bundle") or a.get("package")) or None,
            "function": source_list(a.get("function")),
            "source_ids": source_list(a.get("source_ids"), a.get("source_id")),
        })
    apis = []
    for idx, a in enumerate(d.get("api_dependencies", []) or []):
        if isinstance(a, str):
            a = {"endpoint": a}
        apis.append({
            "api_dependency_id": normalize_text(a.get("api_dependency_id")) or stable_id("API", d["device_id"], idx),
            "endpoint": normalize_text(a.get("endpoint") or a.get("url")) or None,
            "auth_scheme": normalize_text(a.get("auth_scheme") or a.get("authentication")) or None,
            "version": normalize_text(a.get("version")) or None,
            "source_ids": source_list(a.get("source_ids"), a.get("source_id")),
        })
    return {
        "cloud": cloud,
        "mobile_apps": apps,
        "apis": apis,
        "limitations": [
            "Cloud provider is not device vendor/owner.",
            "Cloud endpoint is not automatically control server.",
            "Mobile app vulnerability is not device firmware vulnerability.",
        ],
    }


def analyze_certificates_for_device(
    d: Dict[str, Any],
    certs: List[Dict[str, Any]],
    shared_fp_counts: Counter,
) -> Dict[str, Any]:
    out = []
    for idx, c in enumerate(certs):
        fp = normalize_text(c.get("fingerprint") or c.get("sha256")) or hash_string(c.get("subject") or c.get("san") or idx)
        out.append({
            "certificate_id": normalize_text(c.get("certificate_id") or c.get("id") or stable_id("CERT", d["device_id"], idx)),
            "role": norm_enum(c.get("role"), CERT_ROLES),
            "subject": normalize_text(c.get("subject")) or None,
            "issuer": normalize_text(c.get("issuer")) or None,
            "san": source_list(c.get("san")),
            "valid_from": parse_time(c.get("valid_from")),
            "valid_to": parse_time(c.get("valid_to")),
            "fingerprint_masked": mask_value(fp, 6, 4),
            "shared_across_devices": shared_fp_counts.get(fp, 0) > 1,
            "source_ids": source_list(c.get("source_ids"), c.get("source_id")),
        })
    return {
        "certificates": out,
        "limitations": [
            "Certificate is not device owner.",
            "Shared certificate may indicate fleet provisioning, not vulnerability.",
            "Unique certificate may support identity but still requires provisioning context.",
        ],
    }


def analyze_ota_for_device(otas: List[Dict[str, Any]]) -> Dict[str, Any]:
    out = []
    for idx, o in enumerate(otas):
        out.append({
            "ota_id": normalize_text(o.get("ota_id") or o.get("id") or stable_id("OTA", idx)),
            "update_source": normalize_text(o.get("update_source") or o.get("source")) or None,
            "transport": normalize_text(o.get("transport")).upper() or None,
            "signature_claim": normalize_text(o.get("signature_claim") or o.get("signature")).upper() or None,
            "release_cadence": normalize_text(o.get("release_cadence")) or None,
            "support_state": norm_enum(o.get("support_state"), SUPPORT_STATUS),
            "endpoint": normalize_text(o.get("endpoint") or o.get("url")) or None,
            "last_update_at": parse_time(o.get("last_update_at")),
            "source_ids": source_list(o.get("source_ids"), o.get("source_id")),
        })
    return {
        "ota_records": out,
        "limitations": [
            "OTA endpoint is not necessarily device control endpoint.",
            "IOTINT does not trigger updates on external devices.",
            "Signed firmware indicates signature metadata, not secure implementation.",
        ],
    }


def analyze_authentication_for_device(auths: List[Dict[str, Any]]) -> Dict[str, Any]:
    out = []
    for idx, a in enumerate(auths):
        out.append({
            "authentication_id": normalize_text(a.get("authentication_id") or a.get("id") or stable_id("AUTH", idx)),
            "method": source_list(a.get("method"), a.get("authentication_method")),
            "default_credential_policy_present": bool(a.get("default_credential_policy_present")),
            "weakness_claim": normalize_text(a.get("weakness_claim")) or None,
            "weakness_state": norm_enum(a.get("weakness_state"), AUTH_WEAKNESS_STATES),
            "source_ids": source_list(a.get("source_ids"), a.get("source_id")),
        })
    return {
        "authentication_records": out,
        "limitations": [
            "Default credential documentation is not current credential evidence.",
            "IOTINT does not test credentials against devices.",
        ],
    }


def analyze_sbom_for_device(d: Dict[str, Any], sboms: List[Dict[str, Any]]) -> Dict[str, Any]:
    device_components = d.get("software_components", []) or []
    sbom_records = []
    sbom_components = []
    conflicts = []
    for idx, s in enumerate(sboms):
        comps = [normalize_component(c) for c in (s.get("components", []) or [])]
        sbom_components.extend(comps)
        sbom_records.append({
            "sbom_id": normalize_text(s.get("sbom_id") or s.get("id") or stable_id("SBOM", d["device_id"], idx)),
            "format": norm_enum(s.get("format"), SBOM_FORMATS),
            "generated_at": parse_time(s.get("generated_at")),
            "component_count": len(comps),
            "source_ids": source_list(s.get("source_ids"), s.get("source_id")),
        })
    dev_by_name = {normalize_token(c.get("name")): c for c in device_components if c.get("name")}
    for c in sbom_components:
        key = normalize_token(c.get("name"))
        dc = dev_by_name.get(key)
        if dc and dc.get("version") and c.get("version") and normalize_version(dc["version"]) != normalize_version(c["version"]):
            conflicts.append({
                "component": c.get("name"),
                "device_version": dc.get("version"),
                "sbom_version": c.get("version"),
            })
    return {
        "sbom_records": sbom_records,
        "components": unique_preserve(device_components + sbom_components),
        "conflicts": conflicts,
        "limitations": [
            "SBOM may be incomplete, stale, generic, or wrong build.",
            "Component presence is not reachability or vulnerability.",
        ],
    }


def vulnerability_relevant(v: Dict[str, Any], d: Dict[str, Any]) -> bool:
    if v.get("device_id") and normalize_text(v.get("device_id")) != d.get("device_id"):
        return False
    checks = [
        field_match(v.get("vendor"), d.get("manufacturer")),
        field_match(v.get("brand"), d.get("brand")),
        field_match(v.get("product"), d.get("product_family")),
        field_match(v.get("model"), d.get("model")),
        field_match(v.get("hardware_revision"), d.get("hardware_revision")),
    ]
    if any(c is True for c in checks):
        return True
    comp = normalize_token(v.get("component"))
    purl = normalize_text(v.get("purl"))
    if comp or purl:
        for c in d.get("software_components", []) or []:
            if comp and normalize_token(c.get("name")) == comp:
                return True
            if purl and normalize_text(c.get("purl")) == purl:
                return True
    return False


def assess_vulnerability_for_device(
    v: Dict[str, Any],
    d: Dict[str, Any],
    sbom_components: List[Dict[str, Any]],
) -> Dict[str, Any]:
    checks = [
        field_match(v.get("vendor"), d.get("manufacturer")),
        field_match(v.get("brand"), d.get("brand")),
        field_match(v.get("product"), d.get("product_family")),
        field_match(v.get("model"), d.get("model")),
        field_match(v.get("hardware_revision"), d.get("hardware_revision")),
    ]
    fw_affected = version_in_list(d.get("firmware_version"), v.get("affected_versions"))
    fw_fixed = version_in_list(d.get("firmware_version"), v.get("fixed_versions"))

    comp_matches: List[Optional[bool]] = []
    all_components = unique_preserve((d.get("software_components", []) or []) + sbom_components)
    v_comp = normalize_token(v.get("component"))
    v_purl = normalize_text(v.get("purl"))
    for c in all_components:
        matched = False
        if v_comp and normalize_token(c.get("name")) == v_comp:
            matched = True
        if v_purl and normalize_text(c.get("purl")) == v_purl:
            matched = True
        if matched:
            cv = version_in_list(c.get("version"), v.get("affected_versions"))
            comp_matches.append(cv)

    explicit_false = any(x is False for x in checks)
    any_true = any(x is True for x in checks)
    comp_true = any(x is True for x in comp_matches)

    if fw_fixed is True:
        state = "NOT_APPLICABLE_BASED_ON_FIXED_VERSION"
        reason = "Device firmware matches a fixed version listed in supplied vulnerability record."
    elif comp_true and (explicit_false or fw_affected is False):
        state = "COMPONENT_CANDIDATE_PENDING_VALIDATION"
        reason = "Component/PURL match exists, but product/model/firmware context has mismatch; VULNINT should adjudicate."
    elif comp_true and not explicit_false:
        state = "COMPONENT_APPLICABLE_PENDING_VALIDATION"
        reason = "Component/PURL version match exists; reachability and build configuration still require validation."
    elif explicit_false:
        state = "NOT_APPLICABLE_BASED_ON_MISMATCH"
        reason = "Vendor/brand/product/model/revision mismatch based on supplied records."
    elif fw_affected is False:
        state = "NOT_APPLICABLE_BASED_ON_MISMATCH"
        reason = "Device firmware not listed in affected versions based on supplied exact-match evidence."
    elif any_true and fw_affected is True:
        state = "APPLICABLE_PENDING_VALIDATION"
        reason = "Product/model/firmware fields match advisory fields; configuration/reachability still require validation."
    elif any_true and fw_affected is None:
        state = "POSSIBLE_PENDING_FIRMWARE"
        reason = "Product/model context matches, but firmware/version evidence is incomplete or range-based."
    elif any_true:
        state = "POSSIBLE"
        reason = "Partial product/vendor match; exact applicability unresolved."
    else:
        state = "UNKNOWN"
        reason = "Insufficient device product/version evidence."

    return {
        "vulnerability_id": v.get("vulnerability_id"),
        "cve": v.get("cve"),
        "device_id": d.get("device_id"),
        "applicability_state": state,
        "reason": reason,
        "kev": bool(v.get("kev")),
        "epss": parse_float(v.get("epss")),
        "exploit_availability": norm_enum(v.get("exploit_availability"), EXPLOIT_AVAILABILITY_STATES),
        "known_exploitation_reported": bool(v.get("known_exploitation_reported")),
        "mitigations": source_list(v.get("mitigations")),
        "source_ids": source_list(v.get("source_ids"), v.get("source_id")),
        "limitations": [
            "CVE/advisory is not device vulnerability until product/model/revision/firmware/configuration are validated.",
            "Vulnerability is not exploitation.",
            "Known exploitation elsewhere is not local compromise.",
            "No exploit code or active testing is provided.",
        ],
    }


def assess_device_vulnerabilities(
    d: Dict[str, Any],
    vulnerabilities: List[Dict[str, Any]],
    sbom_components: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    out = []
    for v in vulnerabilities:
        if not vulnerability_relevant(v, d):
            continue
        out.append(assess_vulnerability_for_device(v, d, sbom_components))
    return out


def maintenance_context_for_device(
    device_id: str,
    ts: Optional[datetime],
    maintenance: List[Dict[str, Any]],
) -> str:
    for m in maintenance:
        if device_id in m.get("device_ids", []):
            if within_time(ts, m.get("start"), m.get("end")):
                if m.get("approved") is True:
                    return "SUPPORTED"
                return "CANDIDATE"
    return "NONE"


def analyze_device_telemetry(
    d: Dict[str, Any],
    telemetry: List[Dict[str, Any]],
    maintenance: List[Dict[str, Any]],
) -> Dict[str, Any]:
    anomalies = []
    destinations = Counter()
    protocols = Counter()
    for idx, t in enumerate(telemetry):
        ts = parse_time(t.get("timestamp") or t.get("observed_at"))
        dest = normalize_text(t.get("destination") or t.get("domain") or t.get("ip") or t.get("endpoint")) or None
        proto = norm_enum(t.get("protocol"), PROTOCOLS)
        ttype = norm_enum(t.get("type"), TELEMETRY_TYPES)
        if dest:
            destinations[dest] += 1
        if proto != "UNKNOWN":
            protocols[proto] += 1
        mctx = maintenance_context_for_device(d["device_id"], ts, maintenance)
        is_anomaly = bool(t.get("anomaly")) or t.get("baseline_expected") is False
        if is_anomaly:
            if mctx == "SUPPORTED":
                status = "EXPLAINED_BY_MAINTENANCE"
            elif mctx == "CANDIDATE":
                status = "MAINTENANCE_CANDIDATE"
            else:
                status = "ANOMALY_CANDIDATE"
            anomalies.append({
                "observation_id": normalize_text(t.get("observation_id") or t.get("id") or stable_id("TELEM", d["device_id"], idx)),
                "timestamp": ts,
                "type": ttype,
                "destination": dest,
                "protocol": proto,
                "status": status,
                "maintenance_context": mctx,
                "description": normalize_text(t.get("description")) or None,
                "source_ids": source_list(t.get("source_ids"), t.get("source_id")),
            })
    return {
        "observation_count": len(telemetry),
        "destination_counts": dict(destinations),
        "protocol_counts": dict(protocols),
        "anomalies": anomalies,
        "limitations": [
            "Anomaly is not compromise.",
            "Unexpected traffic may be update, cloud migration, feature change, misconfiguration, or incident.",
        ],
    }


def analyze_device_incidents(
    d: Dict[str, Any],
    incidents: List[Dict[str, Any]],
    malware: List[Dict[str, Any]],
    telemetry: Dict[str, Any],
    vulns: List[Dict[str, Any]],
) -> Dict[str, Any]:
    state = "NO_COMPROMISE_EVIDENCE"
    botnet = "NONE_PROVIDED"
    incident_rows = []
    malware_rows = []

    for idx, i in enumerate(incidents):
        iid = normalize_text(i.get("incident_id") or i.get("id") or stable_id("INC", d["device_id"], idx))
        row = {
            "incident_id": iid,
            "incident_type": norm_enum(i.get("incident_type"), INCIDENT_TYPES),
            "occurred_at": parse_time(i.get("occurred_at") or i.get("timestamp")),
            "description": normalize_text(i.get("description")) or None,
            "compromise_evidence": bool(i.get("compromise_evidence")),
            "verified_by_incident_evidence": bool(i.get("verified_by_incident_evidence")),
            "exploitation_claim": bool(i.get("exploitation_claim")),
            "vulnerability_id": normalize_text(i.get("vulnerability_id")) or None,
            "botnet_report": bool(i.get("botnet_report")),
            "botnet_participation_candidate": bool(i.get("botnet_participation_candidate")),
            "botnet_participation_supported": bool(i.get("botnet_participation_supported")),
            "source_ids": source_list(i.get("source_ids"), i.get("source_id")),
        }
        incident_rows.append(row)
        if row["verified_by_incident_evidence"]:
            state = "COMPROMISE_VERIFIED_BY_INCIDENT_EVIDENCE"
        elif row["compromise_evidence"] and state not in {"COMPROMISE_VERIFIED_BY_INCIDENT_EVIDENCE"}:
            state = "COMPROMISE_CANDIDATE"
        if row["botnet_participation_supported"]:
            botnet = "BOTNET_PARTICIPATION_SUPPORTED"
        elif row["botnet_participation_candidate"] and botnet != "BOTNET_PARTICIPATION_SUPPORTED":
            botnet = "BOTNET_PARTICIPATION_CANDIDATE"
        elif row["botnet_report"] and botnet == "NONE_PROVIDED":
            botnet = "BOTNET_ASSOCIATION_REPORTED"

    for idx, m in enumerate(malware):
        malware_rows.append({
            "malware_id": normalize_text(m.get("malware_id") or m.get("id") or stable_id("MAL", d["device_id"], idx)),
            "name": normalize_text(m.get("name")) or None,
            "family": normalize_text(m.get("family")) or None,
            "capability_claim": normalize_text(m.get("ics_capability_claim") or m.get("capability_claim")) or None,
            "observed_action": normalize_text(m.get("observed_action")) or None,
            "hash": normalize_text(m.get("hash")) or None,
            "source_ids": source_list(m.get("source_ids"), m.get("source_id")),
        })
        if m.get("observed_action") and state == "NO_COMPROMISE_EVIDENCE":
            state = "COMPROMISE_CANDIDATE"

    if telemetry.get("anomalies") and state == "NO_COMPROMISE_EVIDENCE":
        state = "ANOMALY_OBSERVED"

    applicable_states = {v.get("applicability_state") for v in vulns}
    return {
        "incident_state": state,
        "botnet_state": botnet,
        "incidents": incident_rows,
        "malware": malware_rows,
        "has_applicable_vulnerability": bool(
            applicable_states & {
                "APPLICABLE_PENDING_VALIDATION",
                "COMPONENT_APPLICABLE_PENDING_VALIDATION",
                "POSSIBLE_PENDING_FIRMWARE",
                "COMPONENT_CANDIDATE_PENDING_VALIDATION",
                "POSSIBLE",
            }
        ),
        "limitations": [
            "Malware capability is not observed action.",
            "Botnet report is not current infection.",
            "Anomaly is not compromise.",
            "Cyber event is not physical/process impact without correlated evidence.",
        ],
    }


def analyze_privacy_safety(d: Dict[str, Any]) -> Dict[str, Any]:
    privacy_set = set(d.get("privacy_sensitivity", []) or [])
    physical_set = set(d.get("physical_safety_relevance", []) or [])
    high_privacy = privacy_set & {"VIDEO", "AUDIO", "LOCATION", "HEALTH", "BIOMETRIC", "HOME_ACTIVITY", "OCCUPANCY", "CHILD"}
    high_physical = physical_set & {"ACCESS_CONTROL", "VEHICLE", "MEDICAL", "INDUSTRIAL", "BUILDING_SAFETY", "FIRE_SECURITY", "HAZARDOUS_EQUIPMENT"}
    privacy_risk = "HIGH" if high_privacy else ("MEDIUM" if privacy_set & {"ACCOUNT", "OTHER"} else ("UNKNOWN" if not privacy_set else "LOW"))
    physical_risk = "HIGH" if high_physical else ("MEDIUM" if physical_set & {"OTHER"} else ("UNKNOWN" if not physical_set else "LOW"))
    flags = []
    if high_privacy:
        flags.append("Privacy-sensitive telemetry/capture context; minimize data and avoid private-person inference.")
    if high_physical:
        flags.append("Physical-safety-relevant device class/capability; human review required; no control/testing without specialized authorization.")
    if d.get("device_class") in {"SMART_CAMERA", "SMART_DOORBELL", "SMART_SPEAKER"}:
        flags.append("Camera/microphone context: do not activate/access/stream without explicit lawful authorization.")
    if d.get("device_class") == "SMART_LOCK":
        flags.append("Access-control context: do not unlock/bypass/clone credentials or provide entry methods.")
    if d.get("device_class") in {"HEALTH_DEVICE", "WEARABLE"}:
        flags.append("Health-related sensitivity: do not infer conditions or alter therapy/safety functions.")
    return {
        "privacy_risk": privacy_risk,
        "physical_safety_risk": physical_risk,
        "privacy_sensitivity": sorted(privacy_set),
        "physical_safety_relevance": sorted(physical_set),
        "flags": flags,
        "limitations": [
            "Privacy policy claim is not observed behavior.",
            "Device identifier is not person identity.",
            "Physical-safety devices require human governance.",
        ],
    }


def compute_risk_dimensions(
    d: Dict[str, Any],
    identity: Dict[str, Any],
    services: Dict[str, Any],
    deps: Dict[str, Any],
    ota: Dict[str, Any],
    auth: Dict[str, Any],
    sbom: Dict[str, Any],
    vulns: List[Dict[str, Any]],
    telemetry: Dict[str, Any],
    incidents: Dict[str, Any],
    privacy: Dict[str, Any],
) -> Dict[str, Any]:
    vuln_states = {v.get("applicability_state") for v in vulns}
    vulnerable_count = len(vuln_states & {
        "APPLICABLE_PENDING_VALIDATION",
        "COMPONENT_APPLICABLE_PENDING_VALIDATION",
        "POSSIBLE_PENDING_FIRMWARE",
        "COMPONENT_CANDIDATE_PENDING_VALIDATION",
        "POSSIBLE",
    })
    auth_risk = "UNKNOWN"
    if auth.get("authentication_records"):
        if any(r.get("weakness_state") in {"VULNERABILITY_SUPPORTED", "SOURCE_REPORTED_AUTH_WEAKNESS"} for r in auth["authentication_records"]):
            auth_risk = "ELEVATED_PENDING_VALIDATION"
        elif any(r.get("default_credential_policy_present") for r in auth["authentication_records"]):
            auth_risk = "POLICY_CONTEXT_ONLY"
    lifecycle_risk = "UNKNOWN"
    if d.get("lifecycle") in {"END_OF_SUPPORT", "END_OF_LIFE"} or d.get("support_status") in {"END_OF_SUPPORT", "END_OF_LIFE"}:
        lifecycle_risk = "ELEVATED"
    elif d.get("support_status") in {"LIMITED_SUPPORT", "SECURITY_ONLY"}:
        lifecycle_risk = "MODERATE"
    cloud_risk = "UNKNOWN"
    if deps.get("cloud"):
        cloud_risk = "PRESENT_DEPENDENCY"
        if any(c.get("relationship") == "RECEIVES_COMMANDS_FROM" for c in deps["cloud"]):
            cloud_risk = "COMMAND_DEPENDENCY_CONTEXT"
    supply_risk = "UNKNOWN"
    if d.get("oem") or d.get("odm") or identity.get("manufacturer_state") == "CANDIDATE":
        supply_risk = "WHITE_LABEL_OR_OEM_CONTEXT"
    incident_risk = "UNKNOWN"
    if incidents.get("incident_state") in {"COMPROMISE_CANDIDATE", "COMPROMISE_SUPPORTED", "COMPROMISE_VERIFIED_BY_INCIDENT_EVIDENCE"}:
        incident_risk = "ELEVATED"
    elif incidents.get("incident_state") == "ANOMALY_OBSERVED":
        incident_risk = "MODERATE"
    return {
        "device_criticality": d.get("criticality", "UNKNOWN"),
        "internet_exposure": "INTERNET_EXPOSED_CANDIDATE" if services.get("internet_exposed_service_candidate") or d.get("internet_exposure") == "INTERNET_EXPOSED" else d.get("internet_exposure", "UNKNOWN"),
        "authentication_risk": auth_risk,
        "firmware_risk": "UNKNOWN" if identity.get("firmware_state") == "UNKNOWN" else ("ELEVATED_IF_UNSUPPORTED" if lifecycle_risk == "ELEVATED" else "CONTEXT_ONLY"),
        "vulnerability_risk": "PRESENT_PENDING_VALIDATION" if vulnerable_count else "NONE_PROVIDED",
        "lifecycle_risk": lifecycle_risk,
        "cloud_dependency_risk": cloud_risk,
        "supply_chain_risk": supply_risk,
        "privacy_risk": privacy.get("privacy_risk", "UNKNOWN"),
        "physical_safety_risk": privacy.get("physical_safety_risk", "UNKNOWN"),
        "incident_risk": incident_risk,
        "evidence_confidence": identity.get("source_assessment", {}).get("max_reliability", 0.0),
        "limitations": [
            "Risk dimensions are kept separate and not compressed into one magic number.",
            "High risk is not compromise.",
            "Exposure is not vulnerability.",
        ],
    }


def assess_device(
    d: Dict[str, Any],
    sources: Dict[str, Dict[str, Any]],
    roots: Dict[str, str],
    cert_index: Dict[str, List[Dict[str, Any]]],
    ota_index: Dict[str, List[Dict[str, Any]]],
    auth_index: Dict[str, List[Dict[str, Any]]],
    sbom_index: Dict[str, List[Dict[str, Any]]],
    vulnerabilities: List[Dict[str, Any]],
    telemetry_index: Dict[str, List[Dict[str, Any]]],
    incident_index: Dict[str, List[Dict[str, Any]]],
    malware_index: Dict[str, List[Dict[str, Any]]],
    maintenance: List[Dict[str, Any]],
    shared_cert_fps: Counter,
) -> Dict[str, Any]:
    did = d["device_id"]
    identity = resolve_device_identity(d, sources, roots, bool(cert_index.get(did)))
    services = analyze_services(d)
    deps = analyze_dependencies(d)
    certs = analyze_certificates_for_device(d, cert_index.get(did, []), shared_cert_fps)
    ota = analyze_ota_for_device(ota_index.get(did, []))
    auth = analyze_authentication_for_device(auth_index.get(did, []))
    sbom = analyze_sbom_for_device(d, sbom_index.get(did, []))
    vulns = assess_device_vulnerabilities(d, vulnerabilities, sbom.get("components", []))
    telemetry = analyze_device_telemetry(d, telemetry_index.get(did, []), maintenance)
    incidents = analyze_device_incidents(d, incident_index.get(did, []), malware_index.get(did, []), telemetry, vulns)
    privacy = analyze_privacy_safety(d)
    risk = compute_risk_dimensions(d, identity, services, deps, ota, auth, sbom, vulns, telemetry, incidents, privacy)
    return {
        "device_id": did,
        "identity_resolution": identity,
        "services": services,
        "dependencies": deps,
        "certificates": certs,
        "ota": ota,
        "authentication": auth,
        "sbom": sbom,
        "vulnerability_context": vulns,
        "telemetry": telemetry,
        "incident_context": incidents,
        "privacy_safety": privacy,
        "risk_dimensions": risk,
        "limitations": [
            "Passive-first defensive analysis only; no active device interaction was performed.",
            "Device identity, model, revision, firmware, exposure, vulnerability, and compromise are separate claims.",
        ],
    }


# --------------------------------------------------------------------
# Fleet / contradictions / hypotheses / gaps / actions / handoffs
# --------------------------------------------------------------------

def analyze_fleets(fleets: List[Dict[str, Any]], devices: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for f in fleets:
        known = [did for did in f.get("device_ids", []) if did in devices]
        unknown = [did for did in f.get("device_ids", []) if did not in devices]
        fw_counts = Counter(devices[did].get("firmware_version") for did in known if devices[did].get("firmware_version"))
        total = sum(fw_counts.values())
        distribution = [
            {
                "firmware_version": fw,
                "device_count": cnt,
                "percentage": round((cnt / total) * 100.0, 2) if total else None,
            }
            for fw, cnt in fw_counts.items()
        ]
        out.append({
            **f,
            "known_device_count": len(known),
            "unknown_device_ids": unknown,
            "firmware_distribution": distribution,
            "limitations": [
                "Observed network count is not total fleet size.",
                "Fleet location is stored at safe granularity only.",
            ],
        })
    return out


def detect_contradictions(
    devices: Dict[str, Dict[str, Any]],
    assessments: Dict[str, Dict[str, Any]],
    fleets: List[Dict[str, Any]],
    telemetry: List[Dict[str, Any]],
    incidents: List[Dict[str, Any]],
    vuln_lookup: Dict[Tuple[str, str], str],
    as_of: Optional[datetime],
) -> List[Dict[str, Any]]:
    contr: List[Dict[str, Any]] = []

    for f in fleets:
        for did in f.get("unknown_device_ids", []):
            contr.append({
                "contradiction_id": stable_id("CTR", "fleet_unknown", f["fleet_id"], did),
                "type": "FLEET_REFERENCES_UNKNOWN_DEVICE",
                "severity": "MATERIAL",
                "fleet_id": f["fleet_id"],
                "device_id": did,
                "detail": f"Fleet {f['fleet_id']} references unknown device {did}.",
                "possible_causes": ["stale fleet record", "missing inventory", "device renamed/replaced", "data error"],
            })

    for t in telemetry:
        did = normalize_text(t.get("device_id"))
        if did and did not in devices:
            contr.append({
                "contradiction_id": stable_id("CTR", "telemetry_unknown", t.get("observation_id") or hash_string(json_safe(t)), did),
                "type": "TELEMETRY_REFERENCES_UNKNOWN_DEVICE",
                "severity": "MATERIAL",
                "device_id": did,
                "detail": f"Telemetry references unknown device {did}.",
                "possible_causes": ["inventory gap", "new device", "gateway/NAT identity confusion", "data error"],
            })

    for i in incidents:
        did = normalize_text(i.get("device_id"))
        if did and did not in devices:
            contr.append({
                "contradiction_id": stable_id("CTR", "incident_unknown", i.get("incident_id") or hash_string(json_safe(i)), did),
                "type": "INCIDENT_REFERENCES_UNKNOWN_DEVICE",
                "severity": "MATERIAL",
                "device_id": did,
                "detail": f"Incident references unknown device {did}.",
                "possible_causes": ["inventory gap", "device replaced", "misattributed alert", "data error"],
            })
        if i.get("exploitation_claim") and did:
            vid = normalize_text(i.get("vulnerability_id"))
            state = vuln_lookup.get((vid, did), "UNKNOWN")
            if state in {"UNKNOWN", "NOT_APPLICABLE_BASED_ON_MISMATCH", "NOT_APPLICABLE_BASED_ON_FIXED_VERSION"}:
                contr.append({
                    "contradiction_id": stable_id("CTR", "exploit_claim", i.get("incident_id"), did, vid),
                    "type": "EXPLOITATION_CLAIM_WITHOUT_APPLICABLE_VULNERABILITY",
                    "severity": "MATERIAL",
                    "device_id": did,
                    "vulnerability_id": vid,
                    "detail": f"Incident claims exploitation but vulnerability applicability is {state}.",
                    "possible_causes": ["wrong CVE", "wrong device", "version mismatch", "unsupported claim", "different vulnerability"],
                })

    for did, ass in assessments.items():
        d = devices.get(did, {})
        if ass["services"].get("internet_exposed_service_candidate") or d.get("internet_exposure") == "INTERNET_EXPOSED":
            scan = d.get("last_internet_scan_at")
            age = days_between(scan, as_of)
            if scan and age is not None and age > 365:
                contr.append({
                    "contradiction_id": stable_id("CTR", "stale_exposure", did),
                    "type": "STALE_INTERNET_EXPOSURE_OBSERVATION",
                    "severity": "MEDIUM",
                    "device_id": did,
                    "detail": f"Internet exposure claim relies on scan observation {age} days old.",
                    "possible_causes": ["device changed state", "IP reuse", "NAT/cloud change", "scan stale"],
                })
        if d.get("lifecycle") in {"END_OF_SUPPORT", "END_OF_LIFE"} or d.get("support_status") in {"END_OF_SUPPORT", "END_OF_LIFE"}:
            for o in ass["ota"].get("ota_records", []):
                if o.get("support_state") in {"SUPPORTED", "SECURITY_ONLY"}:
                    contr.append({
                        "contradiction_id": stable_id("CTR", "lifecycle_ota", did, o.get("ota_id")),
                        "type": "LIFECYCLE_VS_OTA_SUPPORT_CONFLICT",
                        "severity": "MEDIUM",
                        "device_id": did,
                        "detail": "Device lifecycle indicates end-of-support while OTA record indicates active support.",
                        "possible_causes": ["stale lifecycle record", "security-only branch", "regional support difference", "data error"],
                    })
        for c in ass["sbom"].get("conflicts", []):
            contr.append({
                "contradiction_id": stable_id("CTR", "sbom_component", did, c.get("component")),
                "type": "SBOM_COMPONENT_VERSION_CONFLICT",
                "severity": "MEDIUM",
                "device_id": did,
                "detail": f"Component {c.get('component')} version conflict: device={c.get('device_version')} sbom={c.get('sbom_version')}.",
                "possible_causes": ["stale SBOM", "wrong build", "partial update", "component renaming"],
            })
        if ass["identity_resolution"].get("device_instance_state") == "DEVICE_INSTANCE_SUPPORTED":
            for c in ass["certificates"].get("certificates", []):
                if c.get("shared_across_devices"):
                    contr.append({
                        "contradiction_id": stable_id("CTR", "shared_cert_instance", did, c.get("certificate_id")),
                        "type": "SHARED_CERT_WITH_UNIQUE_INSTANCE_CLAIM",
                        "severity": "LOW",
                        "device_id": did,
                        "detail": "Device instance is claimed supported while certificate is shared across devices.",
                        "possible_causes": ["fleet provisioning certificate", "unique identity from other source", "data ambiguity"],
                    })

    return unique_preserve(contr)


def build_hypotheses(
    devices: Dict[str, Dict[str, Any]],
    assessments: Dict[str, Dict[str, Any]],
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

    for did, ass in assessments.items():
        d = devices.get(did, {})
        ident = ass["identity_resolution"]
        add("DEVICE", did, "EXACT_MODEL_SUPPORTED",
            "Device may be exact model/revision/firmware as inventoried.",
            [f"model_state={ident.get('model_state')}", f"firmware_state={ident.get('firmware_state')}", f"source_independence={ident.get('source_assessment', {}).get('state')}"],
            ["White-label/OEM/ODM or stale inventory possible."],
            ["hardware revision", "firmware currentness", "OEM relationship"],
            ["Authoritative datasheet/firmware mapping/authorized inventory confirms different model/revision."])
        add("DEVICE", did, "WHITE_LABEL_OR_OEM_VARIANT",
            "Device may be white-label or OEM/ODM variant with different underlying manufacturer.",
            [f"brand={d.get('brand')}", f"manufacturer={d.get('manufacturer')}", f"oem={d.get('oem')}", f"odm={d.get('odm')}"],
            ["Brand and manufacturer records align and are independently sourced."],
            ["OEM/ODM contract", "hardware revision", "firmware branch"],
            ["Manufacturer/OEM documentation confirms single brand-manufacturer relationship."])
        add("DEVICE", did, "STALE_INVENTORY",
            "Inventory record may be stale relative to current device state.",
            ["inventory can lag firmware upgrades/replacements"],
            ["recent authorized telemetry/passive observations corroborate current state"],
            ["last_seen", "firmware history", "device replacement"],
            ["Fresh authorized inventory/telemetry confirms current model/firmware."])
        add("DEVICE", did, "BANNER_OR_GATEWAY_MISATTRIBUTION",
            "Service banner or network observation may belong to gateway/proxy rather than endpoint device.",
            ["IoT ecosystems often use hubs/gateways/cloud proxies"],
            ["direct device telemetry and certificate/identity evidence align"],
            ["NAT", "hub/proxy", "cloud mediator"],
            ["Endpoint identity evidence confirms direct device service."])

        for a in ass["telemetry"].get("anomalies", [])[:50]:
            oid = a["observation_id"]
            add("TELEMETRY", oid, "FIRMWARE_UPDATE_OR_VENDOR_BACKEND_CHANGE",
                "Unexpected traffic may be firmware update or vendor backend migration.",
                [f"destination={a.get('destination')}", f"maintenance_context={a.get('maintenance_context')}"],
                ["No vendor update endpoint or release metadata correlation."],
                ["update cadence", "DNS history", "cloud endpoint changes"],
                ["Vendor release metadata and DNS/telemetry history do not explain destination."])
            add("TELEMETRY", oid, "DEVICE_CONFIG_CHANGE",
                "Unexpected traffic may reflect configuration or feature change.",
                ["configuration can alter outbound destinations"],
                ["no config change evidence"],
                ["management platform logs", "device config export"],
                ["Authorized config logs show no change and behavior persists."])
            add("TELEMETRY", oid, "COMPROMISE_CANDIDATE",
                "Unexpected traffic may indicate compromise or unauthorized control channel.",
                [f"status={a.get('status')}"],
                ["Maintenance/update/cloud migration/config change possible."],
                ["process chain", "certificate", "credential exposure", "malware"],
                ["Independent incident evidence excludes benign vendor/config causes and identifies malicious pathway."])

        for v in ass["vulnerability_context"][:50]:
            vid = v["vulnerability_id"]
            state = v.get("applicability_state")
            if state in {"UNKNOWN", "POSSIBLE", "POSSIBLE_PENDING_FIRMWARE", "COMPONENT_CANDIDATE_PENDING_VALIDATION"}:
                add("VULNERABILITY", f"{did}:{vid}", "APPLICABLE_WITH_COMPENSATING_CONTROLS",
                    "Vulnerability may apply but segmentation/ACL/feature-disabled/patch status may reduce practical risk.",
                    [f"applicability={state}"],
                    ["Exact configuration/reachability unknown."],
                    ["firewall rules", "service exposure", "feature state"],
                    ["Authorized configuration review confirms not reachable/not enabled."])
                add("VULNERABILITY", f"{did}:{vid}", "NOT_APPLICABLE_TO_SITE",
                    "Advisory may not apply due to product/model/revision/firmware/configuration mismatch.",
                    [f"applicability={state}"],
                    ["Exact asset evidence matches advisory."],
                    ["firmware", "module", "feature set"],
                    ["Authoritative inventory/project metadata confirms exact affected version in use."])
                add("VULNERABILITY", f"{did}:{vid}", "NO_OBSERVED_EXPLOITATION",
                    "Vulnerability presence does not prove exploitation.",
                    ["CVE/advisory context only"],
                    ["incident/telemetry evidence shows exploitation behavior."],
                    ["logs", "PCAP", "device state", "malware"],
                    ["Independent telemetry/incident evidence demonstrates exploitation."])

        inc = ass["incident_context"]
        if inc.get("incident_state") in {"ANOMALY_OBSERVED", "COMPROMISE_CANDIDATE"}:
            add("INCIDENT", did, "CYBER_COMPROMISE_CANDIDATE",
                "Device may be compromised or under unauthorized control.",
                [f"incident_state={inc.get('incident_state')}", f"botnet_state={inc.get('botnet_state')}"],
                ["Maintenance, update, cloud migration, config change, sensor/telemetry gap possible."],
                ["process chain", "credentials", "malware", "controller/command evidence"],
                ["Independent incident evidence excludes benign causes and confirms malicious pathway."])
            add("INCIDENT", did, "BENIGN_OPERATIONAL_CAUSE",
                "Observed anomaly may be benign operational/vendor behavior.",
                ["IoT devices commonly update/connect to cloud"],
                ["strong malware/credential/command evidence"],
                ["vendor release notes", "maintenance", "config change"],
                ["Benign explanations excluded by authorized telemetry/incident evidence."])

    return hyp[:2000]


def build_gaps(
    devices: Dict[str, Dict[str, Any]],
    assessments: Dict[str, Dict[str, Any]],
    fleets: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    manifest: Dict[str, Any],
) -> List[Dict[str, Any]]:
    gaps: List[Dict[str, Any]] = []

    if not devices:
        gaps.append({
            "gap_id": stable_id("GAP", "no_devices"),
            "type": "DEVICE_INVENTORY_UNRESOLVED",
            "importance": "HIGH",
            "recommended_source": "Authorized device inventory, management platform, DHCP/DNS/telemetry, vendor documentation.",
            "specialist": "IOTINT",
            "expected_information_value": "Resolve devices before identity/risk analysis.",
        })

    for did, ass in assessments.items():
        d = devices.get(did, {})
        ident = ass["identity_resolution"]
        if ident.get("model_state") in {"UNKNOWN", "MODEL_CANDIDATE"}:
            gaps.append({
                "gap_id": stable_id("GAP", "model", did),
                "type": "DEVICE_MODEL_UNRESOLVED",
                "importance": "HIGH",
                "device_id": did,
                "recommended_source": "Vendor datasheet, label/photo, authorized inventory, SSDP/mDNS/UPnP metadata where authorized, firmware mapping.",
                "specialist": "IOTINT / TECHINT",
                "expected_information_value": "Avoid product-family-level findings being treated as device-specific.",
            })
        if ident.get("hardware_revision_state") in {"UNKNOWN", "CANDIDATE"}:
            gaps.append({
                "gap_id": stable_id("GAP", "revision", did),
                "type": "HARDWARE_REVISION_UNRESOLVED",
                "importance": "HIGH",
                "device_id": did,
                "recommended_source": "Authorized inventory, teardown/FCC filing where public, firmware release mapping, device management platform.",
                "specialist": "TECHINT / IOTINT",
                "expected_information_value": "Revision can change vulnerability applicability and radio/security behavior.",
            })
        if ident.get("firmware_state") in {"UNKNOWN", "CANDIDATE"}:
            gaps.append({
                "gap_id": stable_id("GAP", "firmware", did),
                "type": "FIRMWARE_UNRESOLVED",
                "importance": "HIGH",
                "device_id": did,
                "recommended_source": "Authorized device management export, firmware hash/metadata, vendor release notes, passive update telemetry.",
                "specialist": "IOTINT / TECHINT",
                "expected_information_value": "Resolve current firmware before vulnerability/lifecycle conclusions.",
            })
        if ident.get("manufacturer_state") in {"UNKNOWN", "CANDIDATE"} or d.get("oem") or d.get("odm"):
            gaps.append({
                "gap_id": stable_id("GAP", "manufacturer_oem", did),
                "type": "MANUFACTURER_OEM_ODM_UNRESOLVED",
                "importance": "MEDIUM",
                "device_id": did,
                "recommended_source": "Vendor documentation, certification filings, PCB/module markings where authorized, supply-chain records.",
                "specialist": "SUPPLYCHAININT / TECHINT",
                "expected_information_value": "Separate brand, manufacturer, OEM, ODM, and component supplier.",
            })
        if not ass["dependencies"].get("cloud"):
            gaps.append({
                "gap_id": stable_id("GAP", "cloud", did),
                "type": "CLOUD_DEPENDENCY_UNRESOLVED",
                "importance": "MEDIUM",
                "device_id": did,
                "recommended_source": "Authorized DNS/telemetry, app config, firmware metadata, vendor documentation.",
                "specialist": "CLOUDINT / NETINT / IOTINT",
                "expected_information_value": "Map device-to-cloud relationship without assuming control.",
            })
        if not ass["dependencies"].get("mobile_apps"):
            gaps.append({
                "gap_id": stable_id("GAP", "mobile_app", did),
                "type": "MOBILE_APP_DEPENDENCY_UNRESOLVED",
                "importance": "LOW",
                "device_id": did,
                "recommended_source": "Official app store metadata, vendor documentation, authorized mobile telemetry.",
                "specialist": "MOBILEINT / APPINT",
                "expected_information_value": "Track commissioning/configuration/monitoring dependencies.",
            })
        if not ass["certificates"].get("certificates"):
            gaps.append({
                "gap_id": stable_id("GAP", "certificate", did),
                "type": "CERTIFICATE_CONTEXT_UNRESOLVED",
                "importance": "MEDIUM",
                "device_id": did,
                "recommended_source": "Certificate transparency, authorized TLS observations, device management export.",
                "specialist": "CERTINT / IOTINT",
                "expected_information_value": "Understand device identity/TLS/fleet provisioning context.",
            })
        if not ass["sbom"].get("sbom_records"):
            gaps.append({
                "gap_id": stable_id("GAP", "sbom", did),
                "type": "SBOM_MISSING",
                "importance": "MEDIUM",
                "device_id": did,
                "recommended_source": "Vendor SBOM, authorized firmware extraction, build metadata.",
                "specialist": "IOTINT / SUPPLYCHAININT",
                "expected_information_value": "Improve component vulnerability matching.",
            })
        for v in ass["vulnerability_context"]:
            if v.get("applicability_state") in {"UNKNOWN", "POSSIBLE", "POSSIBLE_PENDING_FIRMWARE", "COMPONENT_CANDIDATE_PENDING_VALIDATION"}:
                gaps.append({
                    "gap_id": stable_id("GAP", "vuln_applicability", did, v.get("vulnerability_id")),
                    "type": "VULNERABILITY_APPLICABILITY_UNRESOLVED",
                    "importance": "HIGH",
                    "device_id": did,
                    "vulnerability_id": v.get("vulnerability_id"),
                    "recommended_source": "Exact model/revision/firmware/configuration evidence; VULNINT adjudication.",
                    "specialist": "VULNINT / IOTINT / TECHINT",
                    "expected_information_value": "Avoid CVE-to-device overclaim.",
                })
        if d.get("lifecycle") == "UNKNOWN" or d.get("support_status") == "UNKNOWN":
            gaps.append({
                "gap_id": stable_id("GAP", "lifecycle", did),
                "type": "LIFECYCLE_SUPPORT_UNRESOLVED",
                "importance": "MEDIUM",
                "device_id": did,
                "recommended_source": "Vendor lifecycle page, release notes, support policy, EOL notice.",
                "specialist": "IOTINT",
                "expected_information_value": "Distinguish end-of-sale, end-of-support, and end-of-life.",
            })
        if d.get("ownership_state") == "UNKNOWN":
            gaps.append({
                "gap_id": stable_id("GAP", "ownership", did),
                "type": "DEVICE_OWNERSHIP_UNRESOLVED",
                "importance": "MEDIUM",
                "device_id": did,
                "recommended_source": "Authorized asset register, procurement record, network access control, site inventory.",
                "specialist": "IOTINT / ORGINT",
                "expected_information_value": "Distinguish corporate/BYOD/guest/vendor/rogue device without person attribution.",
            })
        if ass["incident_context"].get("incident_state") in {"ANOMALY_OBSERVED", "COMPROMISE_CANDIDATE", "INCONCLUSIVE"}:
            gaps.append({
                "gap_id": stable_id("GAP", "incident", did),
                "type": "INCIDENT_STATUS_UNRESOLVED",
                "importance": "HIGH",
                "device_id": did,
                "recommended_source": "Authorized telemetry, EDR/MDM/device logs, malware sandbox handoff, vendor incident notice.",
                "specialist": "INCIDENTINT / MALINT / IOTINT",
                "expected_information_value": "Separate anomaly from compromise without active interaction.",
            })
        if ass["privacy_safety"].get("privacy_risk") == "HIGH":
            gaps.append({
                "gap_id": stable_id("GAP", "privacy", did),
                "type": "PRIVACY_RISK_REVIEW_REQUIRED",
                "importance": "HIGH",
                "device_id": did,
                "recommended_source": "Privacy policy, authorized telemetry, data-flow mapping, DPIA where applicable.",
                "specialist": "PRIVACY_REVIEW / IOTINT",
                "expected_information_value": "Minimize sensitive video/audio/location/health data exposure.",
            })
        if ass["privacy_safety"].get("physical_safety_risk") == "HIGH":
            gaps.append({
                "gap_id": stable_id("GAP", "physical_safety", did),
                "type": "PHYSICAL_SAFETY_HUMAN_REVIEW_REQUIRED",
                "importance": "HIGH",
                "device_id": did,
                "recommended_source": "Qualified safety/human review; authorized specialist workflow for lock/vehicle/medical/industrial/building safety devices.",
                "specialist": "OTINT / SAFETY_HUMAN_REVIEW / LEGALINT",
                "expected_information_value": "Prevent unsafe control/testing recommendations.",
            })

    for f in fleets:
        if f.get("unknown_device_ids"):
            gaps.append({
                "gap_id": stable_id("GAP", "fleet_unknown", f["fleet_id"]),
                "type": "FLEET_SCOPE_UNRESOLVED",
                "importance": "MEDIUM",
                "fleet_id": f["fleet_id"],
                "recommended_source": "Updated authorized inventory/management platform.",
                "specialist": "IOTINT",
                "expected_information_value": "Resolve fleet membership before count/risk conclusions.",
            })

    if manifest.get("clock_offset_unknown"):
        gaps.append({
            "gap_id": stable_id("GAP", "clock"),
            "type": "TIMESTAMP_UNCERTAINTY",
            "importance": "MEDIUM",
            "recommended_source": "Device NTP/RTC status, collector/server time normalization, timezone metadata.",
            "specialist": "IOTINT / LOGINT",
            "expected_information_value": "Prevent false event ordering.",
        })

    for c in contradictions:
        gaps.append({
            "gap_id": stable_id("GAP", "contradiction", c["contradiction_id"]),
            "type": "IOT_CONTRADICTION_UNRESOLVED",
            "importance": "HIGH" if c.get("severity") == "MATERIAL" else "MEDIUM",
            "contradiction_id": c["contradiction_id"],
            "recommended_source": "Authoritative inventory, vendor documentation, fresh authorized telemetry, firmware/SBOM evidence.",
            "specialist": "IOTINT / HUMAN_REVIEW",
            "expected_information_value": "Resolve conflict before consequential defensive action.",
        })

    return gaps[:1000]


def build_next_actions(gaps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    actions = []
    prio = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    for g in gaps:
        t = g.get("type")
        if t == "DEVICE_INVENTORY_UNRESOLVED":
            action = "Load authorized device inventory/management platform; do not actively discover unauthorized devices."
        elif t == "DEVICE_MODEL_UNRESOLVED":
            action = "Retrieve vendor datasheet/model mapping and authorized inventory evidence; do not infer exact model from class alone."
        elif t == "HARDWARE_REVISION_UNRESOLVED":
            action = "Verify hardware revision from authorized inventory, firmware mapping, or public certification records where lawful."
        elif t == "FIRMWARE_UNRESOLVED":
            action = "Retrieve current firmware from authorized management export or passive update telemetry; do not query live device without authorization."
        elif t == "MANUFACTURER_OEM_ODM_UNRESOLVED":
            action = "Resolve brand/manufacturer/OEM/ODM through supply-chain and technical documentation; do not treat brand as manufacturer."
        elif t == "CLOUD_DEPENDENCY_UNRESOLVED":
            action = "Review authorized DNS/telemetry and vendor documentation for cloud endpoints; do not access cloud backend without authorization."
        elif t == "MOBILE_APP_DEPENDENCY_UNRESOLVED":
            action = "Review official app-store metadata and vendor documentation; hand deep app analysis to MOBILEINT/APPINT."
        elif t == "CERTIFICATE_CONTEXT_UNRESOLVED":
            action = "Review certificate transparency/authorized TLS metadata; do not use device keys/certificates."
        elif t == "SBOM_MISSING":
            action = "Obtain vendor SBOM or authorized firmware metadata; do not execute unknown firmware outside isolated lab approval."
        elif t == "VULNERABILITY_APPLICABILITY_UNRESOLVED":
            action = "Hand exact product/model/revision/firmware/configuration to VULNINT; do not test exploitability on live devices."
        elif t == "LIFECYCLE_SUPPORT_UNRESOLVED":
            action = "Retrieve vendor lifecycle/EOL/support policy; distinguish end-of-sale from end-of-support."
        elif t == "DEVICE_OWNERSHIP_UNRESOLVED":
            action = "Use authorized asset register/NAC/procurement records; do not map device identity to private person unnecessarily."
        elif t == "INCIDENT_STATUS_UNRESOLVED":
            action = "Correlate authorized telemetry/device logs and hand malware/incident reconstruction to MALINT/INCIDENTINT; do not interact with suspected C2."
        elif t == "PRIVACY_RISK_REVIEW_REQUIRED":
            action = "Apply data minimization and privacy review; do not access camera/microphone/location/health data without explicit lawful authorization."
        elif t == "PHYSICAL_SAFETY_HUMAN_REVIEW_REQUIRED":
            action = "Escalate to qualified safety/human review; do not control/test lock/vehicle/medical/industrial/building-safety devices."
        elif t == "FLEET_SCOPE_UNRESOLVED":
            action = "Update fleet membership from authorized inventory before count/firmware-distribution conclusions."
        elif t == "TIMESTAMP_UNCERTAINTY":
            action = "Normalize timestamps using authorized NTP/RTC/timezone metadata."
        elif t == "IOT_CONTRADICTION_UNRESOLVED":
            action = "Resolve using authoritative primary evidence and human review before defensive action."
        else:
            action = "Gather additional authorized passive IoT evidence."

        actions.append({
            "action": action,
            "gap_id": g.get("gap_id"),
            "priority": g.get("importance", "MEDIUM"),
            "expected_information_value": g.get("expected_information_value"),
            "prohibited_alternatives": [
                "Do not access unauthorized devices or test credentials.",
                "Do not exploit, execute remote commands, flash firmware, bypass secure boot, or clone identities.",
                "Do not publish/subscribe unauthorized MQTT topics or attack BLE/Zigbee/Thread/Matter/Z-Wave/Wi-Fi/LoRaWAN/cellular.",
                "Do not activate cameras/microphones, unlock locks, control vehicles/medical/industrial/safety devices.",
                "Do not create botnets, deploy malware, perform DoS, or track private individuals.",
            ],
        })
    actions.sort(key=lambda x: prio.get(x.get("priority", "LOW"), 9))
    return actions[:300]


def build_handoffs(
    devices: Dict[str, Dict[str, Any]],
    assessments: Dict[str, Dict[str, Any]],
    vulnerabilities: List[Dict[str, Any]],
    malware: List[Dict[str, Any]],
    incidents: List[Dict[str, Any]],
    telemetry: List[Dict[str, Any]],
    certificates: List[Dict[str, Any]],
    fleets: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    hands = []
    seen = set()

    def add(spec: str, reason: str, payload: Dict[str, Any]) -> None:
        key = (spec, json.dumps(json_safe(payload), sort_keys=True, ensure_ascii=False))
        if key not in seen:
            seen.add(key)
            hands.append({"specialist": spec, "reason": reason, "payload": payload})

    if devices:
        add("TECHINT", "Hardware/model/revision/chipset/architecture technical resolution may be required.", {
            "device_ids": list(devices.keys())[:100],
        })
    if telemetry or any(ass["services"].get("services") for ass in assessments.values()):
        add("NETINT / IPINT / DNSINT / INFRAINT", "Network service, IP/domain, DNS, and infrastructure relationship analysis required.", {
            "telemetry_count": len(telemetry),
            "device_ids": list(devices.keys())[:100],
        })
    if any(ass["dependencies"].get("cloud") for ass in assessments.values()):
        add("CLOUDINT", "Cloud backend dependency and configuration analysis requires cloud specialist under authorization.", {
            "device_ids": [did for did, ass in assessments.items() if ass["dependencies"].get("cloud")][:100],
        })
    if any(ass["dependencies"].get("mobile_apps") for ass in assessments.values()):
        add("MOBILEINT / APPINT", "Companion app deep analysis requires mobile/app specialist.", {
            "device_ids": [did for did, ass in assessments.items() if ass["dependencies"].get("mobile_apps")][:100],
        })
    if vulnerabilities:
        add("VULNINT", "Vulnerability applicability, fixed versions, KEV/EPSS, and exploitation context required.", {
            "vulnerability_ids": [v.get("vulnerability_id") for v in vulnerabilities][:100],
        })
    if malware:
        add("MALINT", "IoT malware behavior/family analysis required; do not execute artifacts.", {
            "malware_ids": [m.get("malware_id") for m in malware][:100],
        })
    if incidents:
        add("INCIDENTINT / LOGINT", "Incident reconstruction and log correlation required.", {
            "incident_ids": [i.get("incident_id") for i in incidents][:100],
        })
    if certificates:
        add("CERTINT", "Certificate chain, issuance, reuse, and TLS identity analysis required.", {
            "certificate_count": len(certificates),
        })
    if any(d.get("oem") or d.get("odm") or d.get("manufacturer") for d in devices.values()):
        add("SUPPLYCHAININT", "Manufacturer/OEM/ODM/component/cloud/app supply-chain dependency analysis required.", {
            "device_ids": list(devices.keys())[:100],
        })
    if any(ass["privacy_safety"].get("physical_safety_risk") == "HIGH" for ass in assessments.values()):
        add("OTINT / SAFETY_HUMAN_REVIEW / LEGALINT", "Physical-safety-relevant IoT devices require qualified human/safety/legal review.", {
            "device_ids": [did for did, ass in assessments.items() if ass["privacy_safety"].get("physical_safety_risk") == "HIGH"][:100],
        })
    if any(ass["privacy_safety"].get("privacy_risk") == "HIGH" for ass in assessments.values()):
        add("PRIVACY_REVIEW / LEGALINT", "Privacy-sensitive camera/mic/location/health wearable context requires privacy/legal review.", {
            "device_ids": [did for did, ass in assessments.items() if ass["privacy_safety"].get("privacy_risk") == "HIGH"][:100],
        })
    if any(ass["authentication"].get("authentication_records") for ass in assessments.values()):
        add("CREDINT / SECOPS", "Authentication architecture/default-credential policy/MFA/least-privilege review required; no credential testing.", {
            "device_ids": [did for did, ass in assessments.items() if ass["authentication"].get("authentication_records")][:100],
        })
    if fleets:
        add("ORGINT / CORPINT", "Fleet organizational ownership/business-unit mapping may require entity specialists.", {
            "fleet_ids": [f["fleet_id"] for f in fleets][:100],
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
            "note": "IoT graph preserves identity uncertainty, dependencies, exposure, vulnerability applicability, privacy/safety flags, and source dependence. It does not prove compromise or authorize device interaction.",
        }


def build_graph(
    devices: Dict[str, Dict[str, Any]],
    assessments: Dict[str, Dict[str, Any]],
    fleets: List[Dict[str, Any]],
    vulnerabilities: List[Dict[str, Any]],
    incidents: List[Dict[str, Any]],
    malware: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    hypotheses: List[Dict[str, Any]],
    gaps: List[Dict[str, Any]],
    sources: Dict[str, Dict[str, Any]],
) -> GraphMemory:
    g = GraphMemory()
    for did, d in devices.items():
        ass = assessments.get(did, {})
        g.node("IoTDevice", did, {
            "device_class": d.get("device_class"),
            "model_state": ass.get("identity_resolution", {}).get("model_state"),
            "firmware_state": ass.get("identity_resolution", {}).get("firmware_state"),
            "ownership_state": d.get("ownership_state"),
            "privacy_risk": ass.get("privacy_safety", {}).get("privacy_risk"),
            "physical_safety_risk": ass.get("privacy_safety", {}).get("physical_safety_risk"),
        })
        for typ, val in (
            ("DeviceClass", d.get("device_class")),
            ("Manufacturer", d.get("manufacturer")),
            ("Brand", d.get("brand")),
            ("OEM", d.get("oem")),
            ("ODM", d.get("odm")),
            ("ProductFamily", d.get("product_family")),
            ("Model", d.get("model")),
            ("Variant", d.get("variant")),
            ("HardwareRevision", d.get("hardware_revision")),
            ("Firmware", d.get("firmware_version")),
            ("OperatingSystem", d.get("os")),
            ("RTOS", d.get("rtos")),
            ("ChipsetCandidate", d.get("chipset_candidate")),
        ):
            if val:
                nid = stable_id(typ, val)
                g.node(typ, nid, {"value": mask_value(val, 3, 2) if typ in {"Firmware", "ChipsetCandidate"} else val})
                g.edge(did, nid, f"HAS_{typ.upper()}_CANDIDATE", {})
        for mac in d.get("mac_reference", []):
            g.node("MAC", stable_id("MAC", mac), {"masked": mac})
            g.edge(did, stable_id("MAC", mac), "ASSIGNED_MAC_OBSERVATION", {})
        for ip in d.get("ip_references", []):
            g.node("IP", stable_id("IP", ip), {"masked": ip})
            g.edge(did, stable_id("IP", ip), "OBSERVED_AT_IP", {})
        for host in d.get("hostnames", []):
            g.node("Hostname", stable_id("HOST", host), {"value": host})
            g.edge(did, stable_id("HOST", host), "HAS_HOSTNAME", {})
        for svc in ass.get("services", {}).get("services", []):
            sid = svc["service_id"]
            g.node("Service", sid, {"name": svc.get("name"), "exposure": svc.get("exposure")})
            g.edge(did, sid, "EXPOSES_SERVICE", {})
        for proto in d.get("protocols", []):
            g.node("Protocol", proto, {})
            g.edge(did, proto, "USES_PROTOCOL", {})
        for c in ass.get("dependencies", {}).get("cloud", []):
            cid = c["dependency_id"]
            g.node("CloudService", cid, {"provider": c.get("provider"), "endpoint_masked": mask_value(c.get("endpoint"), 4, 2), "relationship": c.get("relationship")})
            g.edge(did, cid, c.get("relationship") or "DEPENDS_ON", {})
        for a in ass.get("dependencies", {}).get("mobile_apps", []):
            aid = a["app_dependency_id"]
            g.node("MobileApplication", aid, {"name": a.get("name"), "platform": a.get("platform")})
            g.edge(did, aid, "MANAGED_BY_APP_CANDIDATE", {})
        for cert in ass.get("certificates", {}).get("certificates", []):
            cid = cert["certificate_id"]
            g.node("Certificate", cid, {"role": cert.get("role"), "shared": cert.get("shared_across_devices")})
            g.edge(did, cid, "USES_CERTIFICATE", {})
        for o in ass.get("ota", {}).get("ota_records", []):
            oid = o["ota_id"]
            g.node("OTAService", oid, {"support_state": o.get("support_state"), "endpoint_masked": mask_value(o.get("endpoint"), 4, 2)})
            g.edge(did, oid, "CHECKS_UPDATE_AT_CANDIDATE", {})
        for comp in ass.get("sbom", {}).get("components", [])[:100]:
            comp_id = stable_id("COMPONENT", comp.get("name"), comp.get("version"))
            g.node("SoftwareComponent", comp_id, {"name": comp.get("name"), "version": comp.get("version"), "purl": comp.get("purl")})
            g.edge(did, comp_id, "CONTAINS_COMPONENT_CANDIDATE", {})
        for v in ass.get("vulnerability_context", [])[:100]:
            vid = v.get("vulnerability_id")
            if vid:
                g.node("Vulnerability", vid, {"cve": v.get("cve")})
                g.edge(did, vid, "POSSIBLY_AFFECTED_BY", {"state": v.get("applicability_state")})
        for sid in d.get("source_ids", []):
            g.node("Source", sid, {"source_type": sources.get(sid, {}).get("source_type")})
            g.edge(did, sid, "SUPPORTED_BY_SOURCE", {})

    for f in fleets:
        g.node("Fleet", f["fleet_id"], {"organization": f.get("organization"), "count_state": f.get("count_state")})
        for did in f.get("device_ids", [])[:200]:
            g.edge(did, f["fleet_id"], "MEMBER_OF_FLEET", {})

    for i in incidents[:500]:
        iid = i.get("incident_id")
        if iid:
            g.node("Incident", iid, {"type": i.get("incident_type"), "device_id": i.get("device_id")})
            if i.get("device_id"):
                g.edge(i["device_id"], iid, "OBSERVED_IN_INCIDENT", {})

    for m in malware[:500]:
        mid = m.get("malware_id")
        if mid:
            g.node("Malware", mid, {"name": m.get("name"), "family": m.get("family"), "device_id": m.get("device_id")})
            if m.get("device_id"):
                g.edge(m["device_id"], mid, "MALWARE_CONTEXT", {})

    for c in contradictions[:500]:
        g.node("Contradiction", c["contradiction_id"], {"type": c.get("type"), "severity": c.get("severity")})
    for h in hypotheses[:500]:
        g.node("Hypothesis", h["hypothesis_id"], {"category": h.get("category"), "subject_id": h.get("subject_id")})
    for gap in gaps[:500]:
        g.node("Gap", gap["gap_id"], {"type": gap.get("type"), "importance": gap.get("importance")})

    return g


def dual_ai_review_stub(
    assessments: Dict[str, Dict[str, Any]],
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
            "AI agreement is not technical corroboration.",
            "Human review required for safety-critical devices, privacy-sensitive cameras/mics/health data, firmware modification, fleet isolation, public compromise attribution, or active validation requests.",
        ],
    }
    if any(ass["identity_resolution"].get("model_state") in {"MODEL_SUPPORTED", "MODEL_CANDIDATE"} for ass in assessments.values()):
        review["primary_conclusions"].append("Some device model states are resolved/candidate from provided records.")
        review["skeptic_challenges"].append("Check white-label/OEM/ODM, hardware revision, stale inventory, banner/gateway misattribution.")
    if any(ass["incident_context"].get("incident_state") in {"ANOMALY_OBSERVED", "COMPROMISE_CANDIDATE"} for ass in assessments.values()):
        review["primary_conclusions"].append("Some devices have anomaly/compromise candidate states.")
        review["skeptic_challenges"].append("Do not equate anomaly with compromise; correlate maintenance, updates, cloud migration, config change, malware, and independent telemetry.")
    if contradictions:
        review["primary_conclusions"].append(f"{len(contradictions)} IoT contradiction candidate(s) detected.")
        review["skeptic_challenges"].append("Contradictions may be stale inventory, replacement, shared infrastructure, SBOM mismatch, or dependent sources.")
    if any(g.get("type") == "PHYSICAL_SAFETY_HUMAN_REVIEW_REQUIRED" for g in gaps):
        review["primary_conclusions"].append("Physical-safety human review required for some devices.")
        review["skeptic_challenges"].append("Do not provide control/testing procedures for lock/vehicle/medical/industrial/building-safety devices.")
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
        "devices": [],
        "device_classes": [],
        "manufacturers": [],
        "brands": [],
        "oems": [],
        "odms": [],
        "product_families": [],
        "models": [],
        "variants": [],
        "hardware_revisions": [],
        "firmware_versions": [],
        "operating_systems": [],
        "rtos": [],
        "architectures": [],
        "chipset_candidates": [],
        "device_identifiers": [],
        "mac_context": [],
        "ip_context": [],
        "hostnames": [],
        "network_interfaces": [],
        "wireless_interfaces": [],
        "services": [],
        "protocols": [],
        "mqtt_context": [],
        "coap_context": [],
        "upnp_context": [],
        "mdns_context": [],
        "ble_context": [],
        "zigbee_context": [],
        "thread_context": [],
        "matter_context": [],
        "zwave_context": [],
        "wifi_context": [],
        "lorawan_context": [],
        "cellular_iot_context": [],
        "cloud_dependencies": [],
        "api_dependencies": [],
        "mobile_app_dependencies": [],
        "certificates": [],
        "device_identity_context": [],
        "ota_update_context": [],
        "secure_boot_context": [],
        "hardware_root_of_trust_context": [],
        "authentication_context": [],
        "default_configuration_context": [],
        "internet_exposure": [],
        "sboms": [],
        "vex_records": [],
        "software_components": [],
        "vulnerability_context": [],
        "supply_chain_context": [],
        "lifecycle_context": [],
        "support_status": [],
        "fleet_context": [],
        "telemetry_context": [],
        "behavior_baselines": [],
        "anomalies": [],
        "incident_context": [],
        "malware_context": [],
        "privacy_risk": [],
        "physical_safety_risk": [],
        "risk_dimensions": [],
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
        "privacy_flags": [
            "Device identifiers, serials, MACs, IPs, hostnames, topics, and locations minimized/masked where sensitive.",
            "No private-person tracking or exact private-location inference performed.",
        ],
        "safety_flags": [
            "No device control, firmware modification, credential testing, exploitation, wireless attack, camera/mic activation, lock bypass, vehicle/medical/industrial control, botnet, malware, or DoS performed.",
            "Safety-critical devices require human/qualified review.",
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
        if st in {"official_vendor_documentation", "vendor_advisory"}:
            bias.append("vendor marketing/scope limitations; may not match site configuration/revision")
        if st in {"authorized_device_inventory", "authorized_scan_result"}:
            bias.append("inventory lag, scanner misfingerprint, coverage gaps")
        if st in {"public_internet_index",}:
            bias.append("historical observation, visibility bias, may not be current")
        if st in {"security_research", "community_forum", "retailer_listing"}:
            bias.append("sample bias, model naming differences, unverified claims")
        if st in {"firmware_image", "certificate_transparency"}:
            bias.append("metadata may not reflect deployed configuration or current device state")
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
    devices: Dict[str, Any],
    contradictions: List[Dict[str, Any]],
    gaps: List[Dict[str, Any]],
) -> str:
    if policy_blocked:
        return "POLICY_BLOCKED"
    if not auth_ok:
        return "BLOCKED_PERMISSION"
    if not devices:
        return "DEVICE_UNRESOLVED"
    if contradictions:
        return "PARTIAL"
    if any(g.get("importance") == "HIGH" for g in gaps):
        return "PARTIAL"
    if gaps:
        return "PARTIAL"
    return "SUCCEEDED"


def analyze_iotint_manifest(manifest: Dict[str, Any]) -> Dict[str, Any]:
    result = empty_result(manifest)

    policy_blocked = policy_screen(manifest)
    if policy_blocked:
        result["status"] = "POLICY_BLOCKED"
        result["violations"] = policy_blocked
        result["limitations"] = [
            "IOTINT does not access unauthorized devices, test credentials, exploit, modify firmware, bypass security, attack wireless/MQTT/IoT protocols, activate cameras/microphones, control safety-critical devices, create botnets, deploy malware, perform DoS, or track private individuals."
        ]
        return result

    auth_ok, auth_reasons = authorization_check(manifest)
    if not auth_ok:
        result["status"] = "BLOCKED_PERMISSION"
        result["limitations"] = auth_reasons
        return result

    sources = ingest_sources(manifest)
    roots = build_source_roots(sources)
    devices = ingest_devices(manifest)
    nested = extend_nested_records(devices, manifest)

    cert_index = index_by_device(nested["certificates"])
    ota_index = index_by_device(nested["ota"])
    auth_index = index_by_device(nested["authentication"])
    sbom_index = index_by_device(nested["sboms"])
    telemetry_index = index_by_device(nested["telemetry"])
    incident_index = index_by_device(nested["incidents"])
    malware_index = index_by_device(nested["malware"])

    shared_fp_counts: Counter = Counter()
    for certs in cert_index.values():
        for c in certs:
            fp = normalize_text(c.get("fingerprint") or c.get("sha256")) or hash_string(c.get("subject") or c.get("san") or "")
            if fp:
                shared_fp_counts[fp] += 1

    vulnerabilities = nested["vulnerabilities"]
    maintenance = ingest_maintenance(manifest)
    fleets_raw = ingest_fleets(manifest)
    as_of = determine_as_of(manifest, devices, nested["telemetry"], sources)

    assessments = {
        did: assess_device(
            d, sources, roots, cert_index, ota_index, auth_index, sbom_index,
            vulnerabilities, telemetry_index, incident_index, malware_index,
            maintenance, shared_fp_counts
        )
        for did, d in devices.items()
    }

    vuln_lookup: Dict[Tuple[str, str], str] = {}
    for did, ass in assessments.items():
        for v in ass.get("vulnerability_context", []):
            vid = normalize_text(v.get("vulnerability_id"))
            if vid:
                vuln_lookup[(vid, did)] = v.get("applicability_state", "UNKNOWN")

    fleet_context = analyze_fleets(fleets_raw, devices)
    contradictions = detect_contradictions(devices, assessments, fleet_context, nested["telemetry"], nested["incidents"], vuln_lookup, as_of)
    hypotheses = build_hypotheses(devices, assessments)
    gaps = build_gaps(devices, assessments, fleet_context, contradictions, manifest)
    actions = build_next_actions(gaps)
    handoffs = build_handoffs(devices, assessments, vulnerabilities, nested["malware"], nested["incidents"], nested["telemetry"], nested["certificates"], fleet_context)
    graph = build_graph(devices, assessments, fleet_context, vulnerabilities, nested["incidents"], nested["malware"], contradictions, hypotheses, gaps, sources)
    review = dual_ai_review_stub(assessments, contradictions, gaps)

    observations = [
        f"Devices ingested: {len(devices)}.",
        f"Certificates ingested: {len(nested['certificates'])}.",
        f"OTA records ingested: {len(nested['ota'])}.",
        f"Authentication records ingested: {len(nested['authentication'])}.",
        f"SBOMs ingested: {len(nested['sboms'])}.",
        f"Vulnerability records ingested: {len(vulnerabilities)}.",
        f"Telemetry observations ingested: {len(nested['telemetry'])}.",
        f"Incidents ingested: {len(nested['incidents'])}; malware context records: {len(nested['malware'])}.",
        f"Fleets ingested: {len(fleet_context)}.",
        f"As-of date used for temporal validation: {iso(as_of)}.",
        f"Contradiction candidates: {len(contradictions)}.",
        f"Competing hypotheses: {len(hypotheses)}.",
        "No unauthorized device access, credential testing, exploitation, firmware modification, protocol attack, camera/microphone activation, lock bypass, vehicle/medical/industrial control, botnet creation, malware deployment, DoS, or private tracking was performed.",
        "Device class was not equated with model; brand was not equated with manufacturer; model was not equated with hardware revision.",
        "Open service was not equated with vulnerability; banner was not equated with verified version; internet scan observation was not equated with current reachability.",
        "CVE/advisory was not equated with device vulnerability; vulnerability was not equated with exploitation; known exploitation was not equated with local compromise.",
        "Privacy-sensitive and physical-safety-relevant devices were flagged for human/qualified review.",
    ]

    unknowns = []
    for did, ass in assessments.items():
        ident = ass["identity_resolution"]
        if ident.get("model_state") in {"UNKNOWN", "MODEL_CANDIDATE"}:
            unknowns.append(f"Device model unresolved for {did}.")
        if ident.get("hardware_revision_state") in {"UNKNOWN", "CANDIDATE"}:
            unknowns.append(f"Hardware revision unresolved for {did}.")
        if ident.get("firmware_state") in {"UNKNOWN", "CANDIDATE"}:
            unknowns.append(f"Firmware unresolved for {did}.")
        if ass["incident_context"].get("incident_state") in {"ANOMALY_OBSERVED", "COMPROMISE_CANDIDATE", "INCONCLUSIVE"}:
            unknowns.append(f"Incident/compromise state unresolved for {did}.")
    unknowns.append("Device identifier is not person identity.")
    unknowns.append("Cloud provider is not device vendor/owner.")
    unknowns.append("SBOM component presence is not reachability or vulnerability.")
    result["unknowns"] = list(dict.fromkeys(unknowns))[:500]

    for did, d in devices.items():
        ass = assessments.get(did, {})
        d_out = dict(d)
        d_out["assessment"] = ass
        result["devices"].append(d_out)
        result["device_classes"].append({"device_id": did, "device_class": d.get("device_class")})
        if d.get("manufacturer"):
            result["manufacturers"].append({"device_id": did, "manufacturer": d.get("manufacturer")})
        if d.get("brand"):
            result["brands"].append({"device_id": did, "brand": d.get("brand")})
        if d.get("oem"):
            result["oems"].append({"device_id": did, "oem": d.get("oem")})
        if d.get("odm"):
            result["odms"].append({"device_id": did, "odm": d.get("odm")})
        if d.get("product_family"):
            result["product_families"].append({"device_id": did, "product_family": d.get("product_family")})
        if d.get("model"):
            result["models"].append({"device_id": did, "model": d.get("model"), "state": ass.get("identity_resolution", {}).get("model_state")})
        if d.get("variant"):
            result["variants"].append({"device_id": did, "variant": d.get("variant")})
        if d.get("hardware_revision"):
            result["hardware_revisions"].append({"device_id": did, "hardware_revision": d.get("hardware_revision")})
        if d.get("firmware_version"):
            result["firmware_versions"].append({"device_id": did, "firmware_version": d.get("firmware_version")})
        if d.get("os"):
            result["operating_systems"].append({"device_id": did, "os": d.get("os")})
        if d.get("rtos"):
            result["rtos"].append({"device_id": did, "rtos": d.get("rtos")})
        if d.get("architecture"):
            result["architectures"].append({"device_id": did, "architecture": d.get("architecture")})
        if d.get("chipset_candidate"):
            result["chipset_candidates"].append({"device_id": did, "chipset_candidate": mask_value(d.get("chipset_candidate"), 3, 2)})
        result["device_identifiers"].append({
            "device_id": did,
            "serials_masked": d.get("serial_reference", []),
            "macs_masked": d.get("mac_reference", []),
            "ips_masked": d.get("ip_references", []),
            "hostnames": d.get("hostnames", []),
            "device_identities": [mask_value(x, 3, 2) for x in d.get("device_identities", [])],
        })
        result["mac_context"].extend([{"device_id": did, "mac_masked": x} for x in d.get("mac_reference", [])])
        result["ip_context"].extend([{"device_id": did, "ip_masked": x} for x in d.get("ip_references", [])])
        result["hostnames"].extend([{"device_id": did, "hostname": x} for x in d.get("hostnames", [])])
        result["network_interfaces"].extend([{"device_id": did, "interface": x} for x in d.get("interfaces", [])])
        result["wireless_interfaces"].extend([{"device_id": did, "interface": x} for x in d.get("wireless_interfaces", [])])
        result["services"].extend([{"device_id": did, **s} for s in ass.get("services", {}).get("services", [])])
        result["protocols"].extend([{"device_id": did, "protocol": p} for p in d.get("protocols", [])])
        for proto in d.get("protocols", []):
            bucket = {
                "MQTT": result["mqtt_context"],
                "COAP": result["coap_context"],
                "UPNP": result["upnp_context"],
                "MDNS": result["mdns_context"],
                "BLE": result["ble_context"],
                "ZIGBEE": result["zigbee_context"],
                "THREAD": result["thread_context"],
                "MATTER": result["matter_context"],
                "ZWAVE": result["zwave_context"],
                "WIFI": result["wifi_context"],
                "LORAWAN": result["lorawan_context"],
                "NB_IOT": result["cellular_iot_context"],
                "LTE_M": result["cellular_iot_context"],
                "CELLULAR": result["cellular_iot_context"],
            }.get(proto)
            if bucket is not None:
                bucket.append({"device_id": did, "protocol": proto, "context": "OBSERVATIONAL_METADATA_ONLY"})
        result["cloud_dependencies"].extend([{"device_id": did, **c} for c in ass.get("dependencies", {}).get("cloud", [])])
        result["api_dependencies"].extend([{"device_id": did, **a} for a in ass.get("dependencies", {}).get("apis", [])])
        result["mobile_app_dependencies"].extend([{"device_id": did, **a} for a in ass.get("dependencies", {}).get("mobile_apps", [])])
        result["certificates"].extend([{"device_id": did, **c} for c in ass.get("certificates", {}).get("certificates", [])])
        result["device_identity_context"].append({"device_id": did, "state": ass.get("identity_resolution", {}).get("device_instance_state")})
        result["ota_update_context"].extend([{"device_id": did, **o} for o in ass.get("ota", {}).get("ota_records", [])])
        result["authentication_context"].extend([{"device_id": did, **a} for a in ass.get("authentication", {}).get("authentication_records", [])])
        result["default_configuration_context"].extend([{"device_id": did, "default_credential_policy_present": a.get("default_credential_policy_present")} for a in ass.get("authentication", {}).get("authentication_records", [])])
        result["internet_exposure"].append({
            "device_id": did,
            "state": ass.get("risk_dimensions", {}).get("internet_exposure"),
            "last_internet_scan_at": iso(d.get("last_internet_scan_at")),
        })
        result["sboms"].extend([{"device_id": did, **s} for s in ass.get("sbom", {}).get("sbom_records", [])])
        result["software_components"].extend([{"device_id": did, **c} for c in ass.get("sbom", {}).get("components", [])[:200]])
        result["vulnerability_context"].extend([{"device_id": did, **v} for v in ass.get("vulnerability_context", [])])
        result["supply_chain_context"].extend([{"device_id": did, **s} for s in nested["supply_chain"] if s.get("device_id") == did])
        result["lifecycle_context"].append({"device_id": did, "lifecycle": d.get("lifecycle")})
        result["support_status"].append({"device_id": did, "support_status": d.get("support_status")})
        result["telemetry_context"].extend(nested["telemetry"] if False else []) # placeholder; filled below globally
        result["anomalies"].extend([{"device_id": did, **a} for a in ass.get("telemetry", {}).get("anomalies", [])])
        result["incident_context"].extend([{"device_id": did, **i} for i in ass.get("incident_context", {}).get("incidents", [])])
        result["malware_context"].extend([{"device_id": did, **m} for m in ass.get("incident_context", {}).get("malware", [])])
        result["privacy_risk"].append({"device_id": did, "risk": ass.get("privacy_safety", {}).get("privacy_risk"), "sensitivity": ass.get("privacy_safety", {}).get("privacy_sensitivity")})
        result["physical_safety_risk"].append({"device_id": did, "risk": ass.get("privacy_safety", {}).get("physical_safety_risk"), "relevance": ass.get("privacy_safety", {}).get("physical_safety_relevance")})
        result["risk_dimensions"].append({"device_id": did, **ass.get("risk_dimensions", {})})
        result["timeline_updates"].append({
            "device_id": did,
            "first_seen": iso(d.get("first_seen")),
            "last_seen": iso(d.get("last_seen")),
            "as_of": iso(as_of),
        })

    result["telemetry_context"] = nested["telemetry"]
    result["behavior_baselines"] = [
        {"device_id": did, "destination_counts": ass.get("telemetry", {}).get("destination_counts", {}), "protocol_counts": ass.get("telemetry", {}).get("protocol_counts", {})}
        for did, ass in assessments.items()
    ]
    result["vex_records"] = manifest.get("vex_records", []) or []
    result["secure_boot_context"] = manifest.get("secure_boot_context", []) or []
    result["hardware_root_of_trust_context"] = manifest.get("hardware_root_of_trust_context", []) or []
    result["fleet_context"] = fleet_context

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

    for did, ass in assessments.items():
        result["source_independence"].append({
            "device_id": did,
            "state": ass.get("identity_resolution", {}).get("source_assessment", {}).get("state"),
            "max_reliability": ass.get("identity_resolution", {}).get("source_assessment", {}).get("max_reliability"),
        })

    for did, ass in assessments.items():
        ident = ass["identity_resolution"]
        if ident.get("model_state") == "MODEL_SUPPORTED":
            result["supported_facts"].append({
                "device_id": did,
                "statement": f"Provided authorized records support model state for {did}.",
            })
        elif ident.get("model_state") == "MODEL_CANDIDATE":
            result["partial_facts"].append({
                "device_id": did,
                "statement": f"Model candidate for {did}; exact model requires stronger evidence.",
            })
        else:
            result["candidate_facts"].append({
                "device_id": did,
                "statement": f"Device {did} ingested but model/identity context incomplete.",
            })
        for a in ass["telemetry"].get("anomalies", []):
            result["candidate_facts"].append({
                "device_id": did,
                "observation_id": a.get("observation_id"),
                "statement": f"Telemetry anomaly candidate: destination={a.get('destination')} status={a.get('status')} maintenance={a.get('maintenance_context')}.",
            })

    for c in contradictions:
        result["disputed_facts"].append({
            "contradiction_id": c["contradiction_id"],
            "statement": c.get("detail", "IoT contradiction candidate."),
        })

    base_limits = [
        "IOTINT starter uses only provided/local authorized records; no live device access, credential testing, exploitation, firmware modification, protocol attack, camera/microphone activation, device control, botnet creation, malware deployment, DoS, or private tracking was performed.",
        "Passive-first default; active validation requires separate explicit authorization, scope, rate limits, safety review, and audit.",
        "Device class is not model; brand is not manufacturer; OEM is not ODM; model is not hardware revision; firmware is not model.",
        "MAC/OUI may identify NIC/module vendor, not final product manufacturer or device owner.",
        "IP is not permanent device identity; public IP geolocation is approximate and not exact device location.",
        "Open port/service is exposure context, not vulnerability; banner is not verified version.",
        "Internet scan observation is historical and not current reachability.",
        "Default credential documentation is not current credential evidence.",
        "Certificate is not device owner; shared certificate may be fleet provisioning.",
        "Signed firmware is not secure firmware; unsigned firmware is not malicious firmware.",
        "SBOM component presence is not reachability or vulnerability.",
        "CVE/advisory is not device vulnerability; vulnerability is not exploitation; known exploitation is not local compromise.",
        "Network anomaly is not compromise; botnet report is not current infection.",
        "Cloud provider is not device vendor; cloud endpoint is not automatically control server.",
        "Mobile app vulnerability is not device firmware vulnerability.",
        "Privacy policy claim is not observed behavior.",
        "Safety-critical devices require human/qualified review; no control/testing procedures provided.",
    ]
    if auth_reasons:
        base_limits.extend(auth_reasons)
    result["limitations"] = list(dict.fromkeys(base_limits))

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
    result["status"] = finalize_status(policy_blocked, auth_ok, devices, contradictions, gaps)
    return result


def generate_report(result: Dict[str, Any]) -> str:
    lines = ["# IOTINT Defensive IoT Intelligence Report", ""]
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
        lines += ["No IoT intelligence was performed."]
        return "\n".join(lines)

    lines += ["## Objective", str(result.get("objective", "")), ""]
    lines += ["## Safety / Privacy / Authorization Boundaries",
              "- Passive-first defensive analysis only.",
              "- No unauthorized device access, credential testing, exploitation, firmware modification, protocol attack, camera/microphone activation, lock bypass, vehicle/medical/industrial control, botnet, malware, DoS, or private tracking.",
              "- Device class ≠ model; brand ≠ manufacturer; model ≠ revision; firmware ≠ model.",
              "- Open service ≠ vulnerability; banner ≠ verified version; scan observation ≠ current reachability.",
              "- CVE ≠ device vulnerable; vulnerable ≠ exploited; exploited ≠ local compromise.",
              "- Anomaly ≠ compromise; botnet report ≠ current infection.",
              "- Privacy-sensitive and physical-safety-relevant devices flagged for human/qualified review.",
              ""]

    lines += ["## Devices / Identity Resolution"]
    for d in result.get("devices", [])[:300]:
        ass = d.get("assessment", {})
        ident = ass.get("identity_resolution", {})
        lines.append(f"### `{d.get('device_id')}`")
        lines.append(f"- Class: `{d.get('device_class')}`")
        lines.append(f"- Manufacturer/Brand/OEM/ODM: `{d.get('manufacturer')}` / `{d.get('brand')}` / `{d.get('oem')}` / `{d.get('odm')}`")
        lines.append(f"- Product family/model/variant/revision: `{d.get('product_family')}` / `{d.get('model')}` / `{d.get('variant')}` / `{d.get('hardware_revision')}`")
        lines.append(f"- Firmware/OS/RTOS/arch/chipset: `{d.get('firmware_version')}` / `{d.get('os')}` / `{d.get('rtos')}` / `{d.get('architecture')}` / `{mask_value(d.get('chipset_candidate'),2,2)}`")
        lines.append(f"- Identity states: model=`{ident.get('model_state')}` revision=`{ident.get('hardware_revision_state')}` firmware=`{ident.get('firmware_state')}` instance=`{ident.get('device_instance_state')}` fingerprint=`{ident.get('fingerprint_confidence')}`")
        lines.append(f"- MACs/IPs/hosts (masked): {d.get('mac_reference', [])[:5]} / {d.get('ip_references', [])[:5]} / {d.get('hostnames', [])[:5]}")
        lines.append(f"- Interfaces: wired={d.get('interfaces', [])} wireless={d.get('wireless_interfaces', [])}")
        lines.append(f"- Protocols: {d.get('protocols', [])}")
        lines.append(f"- Ownership/location/segment: `{d.get('ownership_state')}` / `{d.get('location_safe')}` / `{d.get('network_segment')}`")
        lines.append(f"- Lifecycle/support: `{d.get('lifecycle')}` / `{d.get('support_status')}`")
        lines.append(f"- Source independence: `{ident.get('source_assessment', {}).get('state')}` max reliability: `{ident.get('source_assessment', {}).get('max_reliability')}`")
        lines.append("")

    lines += ["## Services / Exposure"]
    for s in result.get("services", [])[:500]:
        lines.append(f"- Device `{s.get('device_id')}` service `{s.get('name')}` port={s.get('port')} exposure=`{s.get('exposure')}` version_claim={s.get('version_claim')} verified={s.get('version_verified')}")
    for e in result.get("internet_exposure", [])[:300]:
        lines.append(f"- Internet exposure `{e.get('device_id')}` state=`{e.get('state')}` last_scan=`{e.get('last_internet_scan_at')}`")
    lines.append("")

    lines += ["## Cloud / API / Mobile App Dependencies"]
    for c in result.get("cloud_dependencies", [])[:300]:
        lines.append(f"- Cloud `{c.get('device_id')}` provider=`{c.get('provider')}` endpoint=`{mask_value(c.get('endpoint'),4,2)}` relationship=`{c.get('relationship')}`")
    for a in result.get("api_dependencies", [])[:300]:
        lines.append(f"- API `{a.get('device_id')}` endpoint=`{mask_value(a.get('endpoint'),4,2)}` auth=`{a.get('auth_scheme')}` version=`{a.get('version')}`")
    for m in result.get("mobile_app_dependencies", [])[:300]:
        lines.append(f"- Mobile app `{m.get('device_id')}` name=`{m.get('name')}` platform=`{m.get('platform')}` package=`{m.get('package_or_bundle')}` function={m.get('function', [])}")
    lines.append("")

    lines += ["## Certificates / OTA / Authentication / Secure Context"]
    for c in result.get("certificates", [])[:300]:
        lines.append(f"- Cert `{c.get('device_id')}` role=`{c.get('role')}` subject=`{c.get('subject')}` issuer=`{c.get('issuer')}` shared={c.get('shared_across_devices')} fp=`{c.get('fingerprint_masked')}`")
    for o in result.get("ota_update_context", [])[:300]:
        lines.append(f"- OTA `{o.get('device_id')}` source=`{o.get('update_source')}` transport=`{o.get('transport')}` signature_claim=`{o.get('signature_claim')}` support=`{o.get('support_state')}` endpoint=`{mask_value(o.get('endpoint'),4,2)}`")
    for a in result.get("authentication_context", [])[:300]:
        lines.append(f"- Auth `{a.get('device_id')}` methods={a.get('method')} default_policy={a.get('default_credential_policy_present')} weakness_state=`{a.get('weakness_state')}`")
    lines.append("")

    lines += ["## SBOM / Software Components / VEX"]
    for s in result.get("sboms", [])[:300]:
        lines.append(f"- SBOM `{s.get('device_id')}` format=`{s.get('format')}` generated=`{s.get('generated_at')}` components={s.get('component_count')}")
    for c in result.get("software_components", [])[:500]:
        lines.append(f"- Component `{c.get('device_id')}` name=`{c.get('name')}` version=`{c.get('version')}` purl=`{c.get('purl')}`")
    {
  "case_id": "IOT-CASE-001",
  "task_id": "IOT-TASK-001",
  "objective": "Defensively analyze an authorized IoT smart-camera ecosystem for device identity, cloud dependencies, vulnerability applicability, telemetry anomalies, privacy risk, and safe next actions. No active device access, credential testing, exploitation, firmware modification, protocol attack, camera/microphone activation, or private tracking is requested.",
  "questions": [
    "Is the device identity resolved to model, revision, and firmware?",
    "Are brand, manufacturer, OEM/ODM, and component supplier kept separate?",
    "Which cloud, API, and mobile-app dependencies are evidenced?",
    "Does the vulnerability record apply to this device, or is applicability unresolved?",
    "Can the telemetry anomaly be explained by maintenance or vendor update behavior?",
    "What privacy and physical-safety considerations require human review?",
    "What safe defensive next actions and specialist handoffs are appropriate?"
  ],
  "requested_actions": [],
  "authorization": {
    "approved": True,
    "scope": "authorized_iot_records",
    "model_mode": "LOCAL_ONLY",
    "cloud_approved": False,
    "iot_data_approved": True,
    "active_validation_approved": False,
    "private_location_approved": False,
    "safety_review_approved": False
  },
  "active_validation_requested": False,
  "private_location_requested": False,
  "clock_offset_unknown": True,
  "time_range": {
    "as_of": "2026-10-09"
  },
  "sources": [
    {
      "source_id": "SVENDOR",
      "source_type": "official_vendor_documentation",
      "observed_at": "2026-09-01T00:00:00Z"
    },
    {
      "source_id": "SINV",
      "source_type": "authorized_device_inventory",
      "observed_at": "2026-10-08T00:00:00Z"
    },
    {
      "source_id": "STELEM",
      "source_type": "authorized_telemetry",
      "observed_at": "2026-10-08T00:00:00Z"
    },
    {
      "source_id": "SADV",
      "source_type": "vendor_advisory",
      "observed_at": "2026-09-15T00:00:00Z"
    },
    {
      "source_id": "SSCAN",
      "source_type": "public_internet_index",
      "observed_at": "2026-10-01T00:00:00Z"
    }
  ],
  "devices": [
    {
      "device_id": "CAM-01",
      "device_class": "SMART_CAMERA",
      "manufacturer": "SyntheticOptics",
      "brand": "HomeGuard",
      "oem": None,
      "odm": None,
      "product_family": "HG-Cam",
      "model": "HG-Cam-200",
      "variant": "indoor",
      "hardware_revision": "Rev B",
      "firmware_version": "3.4.1",
      "os": "Embedded Linux",
      "rtos": None,
      "architecture": "ARM",
      "chipset_candidate": "SyntheticSoC-72",
      "serial_reference": [
        "SN123456789"
      ],
      "mac_reference": [
        "AA:BB:CC:DD:EE:FF"
      ],
      "ip_references": [
        "10.0.10.20"
      ],
      "hostnames": [
        "cam01.home.local"
      ],
      "device_identities": [
        "cloud-device-id-abc123"
      ],
      "certificates": [
        {
          "certificate_id": "CERT-01",
          "role": "DEVICE_IDENTITY",
          "subject": "CN=cam01.synthetic.example",
          "issuer": "Synthetic IoT CA",
          "san": [
            "cam01.synthetic.example"
          ],
          "valid_from": "2026-01-01",
          "valid_to": "2027-01-01",
          "fingerprint": "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
          "source_ids": [
            "SINV"
          ]
        }
      ],
      "network_interfaces": [
        "ETHERNET",
        "WIFI"
      ],
      "wireless_interfaces": [
        "WIFI"
      ],
      "services": [
        {
          "service_id": "SVC-HTTPS",
          "name": "HTTPS",
          "port": 443,
          "exposure": "CLOUD_MEDIATED",
          "version_claim": "nginx/1.18.0",
          "version_verified": False,
          "source_ids": [
            "SINV",
            "STELEM"
          ]
        }
      ],
      "protocols": [
        "HTTPS",
        "MQTT"
      ],
      "cloud_dependencies": [
        {
          "dependency_id": "CLOUD-01",
          "provider": "SyntheticCloud",
          "endpoint": "mqtt.synthetic.example",
          "relationship": "TELEMETRY_TO",
          "evidence": "Vendor documentation and authorized telemetry",
          "source_ids": [
            "SVENDOR",
            "STELEM"
          ]
        }
      ],
      "api_dependencies": [
        {
          "api_dependency_id": "API-01",
          "endpoint": "https://api.synthetic.example/v1/devices",
          "auth_scheme": "OAuth2-like",
          "version": "v1",
          "source_ids": [
            "SVENDOR"
          ]
        }
      ],
      "mobile_app_dependencies": [
        {
          "app_dependency_id": "APP-01",
          "name": "HomeGuard Cam",
          "platform": "IOS",
          "package_or_bundle": "com.synthetic.homeguard",
          "function": [
            "commissioning",
            "monitoring",
            "firmware_update"
          ],
          "source_ids": [
            "SVENDOR"
          ]
        }
      ],
      "software_components": [
        {
          "name": "BusyBox",
          "version": "1.35.0",
          "purl": "pkg:generic/busybox@1.35.0"
        }
      ],
      "lifecycle": "SUPPORTED",
      "support_status": "SUPPORTED",
      "criticality": "MEDIUM",
      "privacy_sensitivity": [
        "VIDEO",
        "LOCATION"
      ],
      "physical_safety_relevance": [],
      "ownership_state": "OWNERSHIP_VERIFIED",
      "location_safe": "Home network / Region X",
      "network_segment": "IOT_VLAN",
      "internet_exposure": "CLOUD_MEDIATED",
      "last_internet_scan_at": "2026-10-01",
      "fingerprint_evidence": [
        "SSDP model string",
        "mDNS service name",
        "TLS SNI pattern"
      ],
      "fingerprint_verified": False,
      "first_seen": "2026-09-01",
      "last_seen": "2026-10-08",
      "source_ids": [
        "SINV",
        "STELEM",
        "SVENDOR"
      ],
      "confidence": 0.82,
      "ota_update_context": [
        {
          "ota_id": "OTA-01",
          "update_source": "SyntheticCloud",
          "transport": "HTTPS",
          "signature_claim": "SIGNED",
          "release_cadence": "quarterly",
          "support_state": "SUPPORTED",
          "endpoint": "https://ota.synthetic.example",
          "last_update_at": "2026-09-15",
          "source_ids": [
            "SVENDOR"
          ]
        }
      ],
      "authentication_context": [
        {
          "authentication_id": "AUTH-01",
          "method": [
            "certificate",
            "token"
          ],
          "default_credential_policy_present": True,
          "weakness_claim": None,
          "weakness_state": "CONFIGURATION_CANDIDATE",
          "source_ids": [
            "SVENDOR"
          ]
        }
      ],
      "sboms": [
        {
          "sbom_id": "SBOM-01",
          "format": "VENDOR_SBOM",
          "generated_at": "2026-09-01",
          "components": [
            {
              "name": "BusyBox",
              "version": "1.35.0",
              "purl": "pkg:generic/busybox@1.35.0"
            },
            {
              "name": "OpenSSL",
              "version": "3.0.8",
              "purl": "pkg:generic/openssl@3.0.8"
            }
          ],
          "source_ids": [
            "SVENDOR"
          ]
        }
      ]
    }
  ],
  "vulnerabilities": [
    {
      "vulnerability_id": "CVE-SYN-2026-0001",
      "cve": "CVE-SYN-2026-0001",
      "device_id": "CAM-01",
      "vendor": "SyntheticOptics",
      "brand": "HomeGuard",
      "product": "HG-Cam",
      "model": "HG-Cam-200",
      "hardware_revision": "Rev B",
      "affected_versions": [
        "3.4.1"
      ],
      "fixed_versions": [
        "3.4.2"
      ],
      "component": "BusyBox",
      "purl": "pkg:generic/busybox@1.35.0",
      "kev": False,
      "epss": 0.04,
      "exploit_availability": "PUBLIC_POC_REPORTED",
      "known_exploitation_reported": False,
      "mitigations": [
        "Apply vendor firmware 3.4.2 during authorized maintenance",
        "Restrict unnecessary local network exposure",
        "Review segmentation and outbound allowlists"
      ],
      "source_ids": [
        "SADV"
      ],
      "confidence": 0.75
    }
  ],
  "telemetry": [
    {
      "observation_id": "TEL-01",
      "device_id": "CAM-01",
      "timestamp": "2026-10-08T09:00:00Z",
      "type": "CONNECTION",
      "destination": "mqtt.synthetic.example",
      "protocol": "MQTT",
      "anomaly": False,
      "baseline_expected": True,
      "source_ids": [
        "STELEM"
      ]
    },
    {
      "observation_id": "TEL-02",
      "device_id": "CAM-01",
      "timestamp": "2026-10-08T10:30:00Z",
      "type": "DNS",
      "destination": "ota-update.example.net",
      "protocol": "DNS",
      "anomaly": True,
      "baseline_expected": False,
      "description": "Unexpected DNS to non-vendor update domain.",
      "source_ids": [
        "STELEM"
      ]
    }
  ],
  "incidents": [
    {
      "incident_id": "INC-01",
      "device_id": "CAM-01",
      "incident_type": "UNKNOWN_DNS",
      "occurred_at": "2026-10-08T10:30:00Z",
      "description": "Unknown DNS destination observed during authorized maintenance window.",
      "compromise_evidence": False,
      "verified_by_incident_evidence": False,
      "exploitation_claim": False,
      "vulnerability_id": "CVE-SYN-2026-0001",
      "botnet_report": False,
      "source_ids": [
        "STELEM"
      ]
    }
  ],
  "malware_context": [],
  "maintenance_windows": [
    {
      "maintenance_id": "MAINT-01",
      "device_ids": [
        "CAM-01"
      ],
      "start": "2026-10-08T10:00:00Z",
      "end": "2026-10-08T11:00:00Z",
      "description": "Authorized firmware staging test.",
      "approved": True,
      "ticket": "CHG-123",
      "source_ids": [
        "SINV"
      ]
    }
  ],
  "fleets": [
    {
      "fleet_id": "FLEET-HOME-01",
      "organization": "Synthetic Home Lab",
      "device_ids": [
        "CAM-01"
      ],
      "product_family": "HG-Cam",
      "models": [
        "HG-Cam-200"
      ],
      "count_state": "INVENTORY_COUNT",
      "location_safe": "Region X",
      "criticality": "MEDIUM",
      "support_state": "SUPPORTED",
      "source_ids": [
        "SINV"
      ]
    }
  ],
  "vex_records": [
    {
      "vex_id": "VEX-01",
      "device_id": "CAM-01",
      "vulnerability_id": "CVE-SYN-2026-0001",
      "status": "AFFECTED",
      "justification": "Vendor advisory indicates firmware 3.4.1 is affected.",
      "source_ids": [
        "SADV"
      ]
    }
  ],
  "secure_boot_context": [
    {
      "device_id": "CAM-01",
      "claim": "SECURE_BOOT_CLAIMED",
      "evidence": "Vendor datasheet",
      "source_ids": [
        "SVENDOR"
      ]
    }
  ],
  "hardware_root_of_trust_context": [
    {
      "device_id": "CAM-01",
      "component": "secure_element",
      "status": "CLAIMED",
      "source_ids": [
        "SVENDOR"
      ]
    }
  ]
}


    {
  "case_id": "IOT-CASE-001",
  "task_id": "IOT-TASK-001",
  "objective": "Defensively analyze an authorized IoT smart-camera ecosystem for device identity, cloud dependencies, vulnerability applicability, telemetry anomalies, privacy risk, and safe next actions. No active device access, credential testing, exploitation, firmware modification, protocol attack, camera/microphone activation, or private tracking is requested.",
  "questions": [
    "Is the device identity resolved to model, revision, and firmware?",
    "Are brand, manufacturer, OEM/ODM, and component supplier kept separate?",
    "Which cloud, API, and mobile-app dependencies are evidenced?",
    "Does the vulnerability record apply to this device, or is applicability unresolved?",
    "Can the telemetry anomaly be explained by maintenance or vendor update behavior?",
    "What privacy and physical-safety considerations require human review?",
    "What safe defensive next actions and specialist handoffs are appropriate?"
  ],
  "requested_actions": [],
  "authorization": {
    "approved": True,
    "scope": "authorized_iot_records",
    "model_mode": "LOCAL_ONLY",
    "cloud_approved": False,
    "iot_data_approved": True,
    "active_validation_approved": False,
    "private_location_approved": False,
    "safety_review_approved": False
  },
  "active_validation_requested": False,
  "private_location_requested": False,
  "clock_offset_unknown": True,
  "time_range": {
    "as_of": "2026-10-09"
  },
  "sources": [
    {
      "source_id": "SVENDOR",
      "source_type": "official_vendor_documentation",
      "observed_at": "2026-09-01T00:00:00Z"
    },
    {
      "source_id": "SINV",
      "source_type": "authorized_device_inventory",
      "observed_at": "2026-10-08T00:00:00Z"
    },
    {
      "source_id": "STELEM",
      "source_type": "authorized_telemetry",
      "observed_at": "2026-10-08T00:00:00Z"
    },
    {
      "source_id": "SADV",
      "source_type": "vendor_advisory",
      "observed_at": "2026-09-15T00:00:00Z"
    },
    {
      "source_id": "SSCAN",
      "source_type": "public_internet_index",
      "observed_at": "2026-10-01T00:00:00Z"
    }
  ],
  "devices": [
    {
      "device_id": "CAM-01",
      "device_class": "SMART_CAMERA",
      "manufacturer": "SyntheticOptics",
      "brand": "HomeGuard",
      "oem": None,
      "odm": None,
      "product_family": "HG-Cam",
      "model": "HG-Cam-200",
      "variant": "indoor",
      "hardware_revision": "Rev B",
      "firmware_version": "3.4.1",
      "os": "Embedded Linux",
      "rtos": None,
      "architecture": "ARM",
      "chipset_candidate": "SyntheticSoC-72",
      "serial_reference": [
        "SN123456789"
      ],
      "mac_reference": [
        "AA:BB:CC:DD:EE:FF"
      ],
      "ip_references": [
        "10.0.10.20"
      ],
      "hostnames": [
        "cam01.home.local"
      ],
      "device_identities": [
        "cloud-device-id-abc123"
      ],
      "certificates": [
        {
          "certificate_id": "CERT-01",
          "role": "DEVICE_IDENTITY",
          "subject": "CN=cam01.synthetic.example",
          "issuer": "Synthetic IoT CA",
          "san": [
            "cam01.synthetic.example"
          ],
          "valid_from": "2026-01-01",
          "valid_to": "2027-01-01",
          "fingerprint": "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
          "source_ids": [
            "SINV"
          ]
        }
      ],
      "network_interfaces": [
        "ETHERNET",
        "WIFI"
      ],
      "wireless_interfaces": [
        "WIFI"
      ],
      "services": [
        {
          "service_id": "SVC-HTTPS",
          "name": "HTTPS",
          "port": 443,
          "exposure": "CLOUD_MEDIATED",
          "version_claim": "nginx/1.18.0",
          "version_verified": False,
          "source_ids": [
            "SINV",
            "STELEM"
          ]
        }
      ],
      "protocols": [
        "HTTPS",
        "MQTT"
      ],
      "cloud_dependencies": [
        {
          "dependency_id": "CLOUD-01",
          "provider": "SyntheticCloud",
          "endpoint": "mqtt.synthetic.example",
          "relationship": "TELEMETRY_TO",
          "evidence": "Vendor documentation and authorized telemetry",
          "source_ids": [
            "SVENDOR",
            "STELEM"
          ]
        }
      ],
      "api_dependencies": [
        {
          "api_dependency_id": "API-01",
          "endpoint": "https://api.synthetic.example/v1/devices",
          "auth_scheme": "OAuth2-like",
          "version": "v1",
          "source_ids": [
            "SVENDOR"
          ]
        }
      ],
      "mobile_app_dependencies": [
        {
          "app_dependency_id": "APP-01",
          "name": "HomeGuard Cam",
          "platform": "IOS",
          "package_or_bundle": "com.synthetic.homeguard",
          "function": [
            "commissioning",
            "monitoring",
            "firmware_update"
          ],
          "source_ids": [
            "SVENDOR"
          ]
        }
      ],
      "software_components": [
        {
          "name": "BusyBox",
          "version": "1.35.0",
          "purl": "pkg:generic/busybox@1.35.0"
        }
      ],
      "lifecycle": "SUPPORTED",
      "support_status": "SUPPORTED",
      "criticality": "MEDIUM",
      "privacy_sensitivity": [
        "VIDEO",
        "LOCATION"
      ],
      "physical_safety_relevance": [],
      "ownership_state": "OWNERSHIP_VERIFIED",
      "location_safe": "Home network / Region X",
      "network_segment": "IOT_VLAN",
      "internet_exposure": "CLOUD_MEDIATED",
      "last_internet_scan_at": "2026-10-01",
      "fingerprint_evidence": [
        "SSDP model string",
        "mDNS service name",
        "TLS SNI pattern"
      ],
      "fingerprint_verified": False,
      "first_seen": "2026-09-01",
      "last_seen": "2026-10-08",
      "source_ids": [
        "SINV",
        "STELEM",
        "SVENDOR"
      ],
      "confidence": 0.82,
      "ota_update_context": [
        {
          "ota_id": "OTA-01",
          "update_source": "SyntheticCloud",
          "transport": "HTTPS",
          "signature_claim": "SIGNED",
          "release_cadence": "quarterly",
          "support_state": "SUPPORTED",
          "endpoint": "https://ota.synthetic.example",
          "last_update_at": "2026-09-15",
          "source_ids": [
            "SVENDOR"
          ]
        }
      ],
      "authentication_context": [
        {
          "authentication_id": "AUTH-01",
          "method": [
            "certificate",
            "token"
          ],
          "default_credential_policy_present": True,
          "weakness_claim": None,
          "weakness_state": "CONFIGURATION_CANDIDATE",
          "source_ids": [
            "SVENDOR"
          ]
        }
      ],
      "sboms": [
        {
          "sbom_id": "SBOM-01",
          "format": "VENDOR_SBOM",
          "generated_at": "2026-09-01",
          "components": [
            {
              "name": "BusyBox",
              "version": "1.35.0",
              "purl": "pkg:generic/busybox@1.35.0"
            },
            {
              "name": "OpenSSL",
              "version": "3.0.8",
              "purl": "pkg:generic/openssl@3.0.8"
            }
          ],
          "source_ids": [
            "SVENDOR"
          ]
        }
      ]
    }
  ],
  "vulnerabilities": [
    {
      "vulnerability_id": "CVE-SYN-2026-0001",
      "cve": "CVE-SYN-2026-0001",
      "device_id": "CAM-01",
      "vendor": "SyntheticOptics",
      "brand": "HomeGuard",
      "product": "HG-Cam",
      "model": "HG-Cam-200",
      "hardware_revision": "Rev B",
      "affected_versions": [
        "3.4.1"
      ],
      "fixed_versions": [
        "3.4.2"
      ],
      "component": "BusyBox",
      "purl": "pkg:generic/busybox@1.35.0",
      "kev": False,
      "epss": 0.04,
      "exploit_availability": "PUBLIC_POC_REPORTED",
      "known_exploitation_reported": False,
      "mitigations": [
        "Apply vendor firmware 3.4.2 during authorized maintenance",
        "Restrict unnecessary local network exposure",
        "Review segmentation and outbound allowlists"
      ],
      "source_ids": [
        "SADV"
      ],
      "confidence": 0.75
    }
  ],
  "telemetry": [
    {
      "observation_id": "TEL-01",
      "device_id": "CAM-01",
      "timestamp": "2026-10-08T09:00:00Z",
      "type": "CONNECTION",
      "destination": "mqtt.synthetic.example",
      "protocol": "MQTT",
      "anomaly": False,
      "baseline_expected": True,
      "source_ids": [
        "STELEM"
      ]
    },
    {
      "observation_id": "TEL-02",
      "device_id": "CAM-01",
      "timestamp": "2026-10-08T10:30:00Z",
      "type": "DNS",
      "destination": "ota-update.example.net",
      "protocol": "DNS",
      "anomaly": True,
      "baseline_expected": False,
      "description": "Unexpected DNS to non-vendor update domain.",
      "source_ids": [
        "STELEM"
      ]
    }
  ],
  "incidents": [
    {
      "incident_id": "INC-01",
      "device_id": "CAM-01",
      "incident_type": "UNKNOWN_DNS",
      "occurred_at": "2026-10-08T10:30:00Z",
      "description": "Unknown DNS destination observed during authorized maintenance window.",
      "compromise_evidence": False,
      "verified_by_incident_evidence": False,
      "exploitation_claim": False,
      "vulnerability_id": "CVE-SYN-2026-0001",
      "botnet_report": False,
      "source_ids": [
        "STELEM"
      ]
    }
  ],
  "malware_context": [],
  "maintenance_windows": [
    {
      "maintenance_id": "MAINT-01",
      "device_ids": [
        "CAM-01"
      ],
      "start": "2026-10-08T10:00:00Z",
      "end": "2026-10-08T11:00:00Z",
      "description": "Authorized firmware staging test.",
      "approved": True,
      "ticket": "CHG-123",
      "source_ids": [
        "SINV"
      ]
    }
  ],
  "fleets": [
    {
      "fleet_id": "FLEET-HOME-01",
      "organization": "Synthetic Home Lab",
      "device_ids": [
        "CAM-01"
      ],
      "product_family": "HG-Cam",
      "models": [
        "HG-Cam-200"
      ],
      "count_state": "INVENTORY_COUNT",
      "location_safe": "Region X",
      "criticality": "MEDIUM",
      "support_state": "SUPPORTED",
      "source_ids": [
        "SINV"
      ]
    }
  ],
  "vex_records": [
    {
      "vex_id": "VEX-01",
      "device_id": "CAM-01",
      "vulnerability_id": "CVE-SYN-2026-0001",
      "status": "AFFECTED",
      "justification": "Vendor advisory indicates firmware 3.4.1 is affected.",
      "source_ids": [
        "SADV"
      ]
    }
  ],
  "secure_boot_context": [
    {
      "device_id": "CAM-01",
      "claim": "SECURE_BOOT_CLAIMED",
      "evidence": "Vendor datasheet",
      "source_ids": [
        "SVENDOR"
      ]
    }
  ],
  "hardware_root_of_trust_context": [
    {
      "device_id": "CAM-01",
      "component": "secure_element",
      "status": "CLAIMED",
      "source_ids": [
        "SVENDOR"
      ]
    }
  ]
}
