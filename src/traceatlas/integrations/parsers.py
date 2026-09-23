from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from typing import Any
from urllib.parse import urlparse
from xml.etree import ElementTree

from .registry import ToolSpec


DOMAIN_RE = re.compile(r"(?<![@\w.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![\w.-])")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}")
URL_RE = re.compile(r"https?://[^\s\]\[<>\"']+")
IP_RE = re.compile(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])")


def _sensitive_key(key: str) -> bool:
    lowered = key.lower().replace("-", "_")
    return any(part in lowered for part in ("secret", "password", "passwd", "token", "private_key", "raw"))


def redact_sensitive(value: Any, key: str = "") -> Any:
    if _sensitive_key(key) and value not in (None, "", [], {}):
        canonical = json.dumps(value, sort_keys=True, default=str)
        return {"redacted": True, "sha256": hashlib.sha256(canonical.encode()).hexdigest()}
    if isinstance(value, dict):
        return {str(k): redact_sensitive(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]
    return value


def _json_records(raw: str, jsonl: bool) -> list[Any]:
    records: list[Any] = []
    if jsonl:
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                records.append(line)
        return records
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return [line for line in raw.splitlines() if line.strip()]
    return data if isinstance(data, list) else [data]


def _pick(record: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value: Any = record
        for part in key.split("."):
            if not isinstance(value, dict) or part not in value:
                value = None
                break
            value = value[part]
        if value not in (None, "", []):
            return value
    return None


def _event_for_record(spec: ToolSpec, record: Any) -> list[dict[str, Any]]:
    base = {"confidence": 75, "risk": "info", "tags": ["external-tool", spec.name]}
    if spec.emitted_type == "DOMAIN":
        value = _pick(record, "host", "domain", "input") if isinstance(record, dict) else record
        if value:
            return [{**base, "event_type": "DOMAIN", "data": str(value).lower().rstrip(".")}]
    if spec.emitted_type == "URL":
        value = _pick(record, "url", "endpoint", "request.endpoint", "input") if isinstance(record, dict) else record
        if value and str(value).startswith(("http://", "https://")):
            return [{**base, "event_type": "URL", "data": str(value)}]
    if spec.emitted_type == "OPEN_PORT":
        if isinstance(record, dict):
            port = _pick(record, "port")
            host = _pick(record, "ip", "host")
            if port:
                return [{**base, "event_type": "OPEN_PORT", "data": {
                    "host": host, "port": int(port), "protocol": record.get("protocol", "tcp")
                }, "confidence": 90}]
    if spec.emitted_type in {"SECRET_CANDIDATE", "NUCLEI_FINDING", "WEB_FINDING"}:
        risk = "medium"
        if isinstance(record, dict):
            severity = str(_pick(record, "info.severity", "severity", "level") or "").lower()
            if severity in {"info", "low", "medium", "high", "critical"}:
                risk = severity
        return [{**base, "event_type": spec.emitted_type,
                 "data": redact_sensitive(record), "risk": risk, "confidence": 70}]
    if spec.emitted_type != "OSINT_INDICATOR":
        return [{**base, "event_type": spec.emitted_type, "data": redact_sensitive(record)}]
    return _infer_indicators(record, spec.name)


def _infer_indicators(record: Any, tool: str) -> list[dict[str, Any]]:
    text = json.dumps(record, default=str) if not isinstance(record, str) else record
    base = {"confidence": 55, "risk": "info", "tags": ["external-tool", tool]}
    output: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for kind, regex in (("URL", URL_RE), ("EMAIL_ADDRESS", EMAIL_RE), ("DOMAIN", DOMAIN_RE), ("IP_ADDRESS", IP_RE)):
        for match in regex.findall(text):
            value = match.rstrip(".,;)")
            if kind == "IP_ADDRESS":
                try:
                    ipaddress.ip_address(value)
                except ValueError:
                    continue
            key = (kind, value.lower())
            if key in seen:
                continue
            seen.add(key)
            output.append({**base, "event_type": kind, "data": value})
    if not output and record not in (None, "", {}, []):
        output.append({**base, "event_type": "RAW_OBSERVATION", "data": redact_sensitive(record),
                       "confidence": 35})
    return output


def _parse_nmap(raw: str, spec: ToolSpec) -> list[dict[str, Any]]:
    try:
        root = ElementTree.fromstring(raw)
    except ElementTree.ParseError:
        return []
    output = []
    for host in root.findall("host"):
        addr_node = host.find("address")
        address = addr_node.get("addr") if addr_node is not None else None
        ports = host.find("ports")
        if ports is None:
            continue
        for port in ports.findall("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            output.append({
                "event_type": "OPEN_PORT",
                "data": {"host": address, "port": int(port.get("portid", "0")),
                         "protocol": port.get("protocol", "tcp"),
                         "service": service.get("name") if service is not None else None},
                "confidence": 95, "risk": "info", "tags": ["external-tool", spec.name],
            })
    return output


def parse_output(spec: ToolSpec, raw: str) -> list[dict[str, Any]]:
    if not raw.strip():
        return []
    if spec.output_format == "nmap_xml":
        return _parse_nmap(raw, spec)
    if spec.output_format in {"json", "jsonl"}:
        records = _json_records(raw, spec.output_format == "jsonl")
    elif spec.output_format == "lines":
        records = [line.strip() for line in raw.splitlines() if line.strip()]
    else:
        records = [raw]
    events: list[dict[str, Any]] = []
    for record in records[:5000]:
        events.extend(_event_for_record(spec, record))
    deduped: list[dict[str, Any]] = []
    fingerprints: set[str] = set()
    for event in events:
        canonical = json.dumps([event["event_type"], event["data"]], sort_keys=True, default=str)
        fingerprint = hashlib.sha256(canonical.encode()).hexdigest()
        if fingerprint not in fingerprints:
            fingerprints.add(fingerprint)
            deduped.append(event)
    return deduped[:5000]


def in_scope(event: dict[str, Any], target_type: str, target: str) -> bool:
    event_type, data = event["event_type"], event["data"]
    root_domain = None
    if target_type == "domain":
        root_domain = target.lower().rstrip(".")
    elif target_type == "url":
        root_domain = (urlparse(target).hostname or "").lower()
    if event_type == "DOMAIN" and root_domain:
        value = str(data).lower().rstrip(".")
        return value == root_domain or value.endswith("." + root_domain)
    if event_type == "URL" and root_domain:
        host = (urlparse(str(data)).hostname or "").lower()
        return host == root_domain or host.endswith("." + root_domain)
    if event_type == "EMAIL_ADDRESS" and root_domain:
        return str(data).lower().endswith("@" + root_domain)
    if event_type == "IP_ADDRESS" and target_type == "ip":
        return str(data) == target
    return True

