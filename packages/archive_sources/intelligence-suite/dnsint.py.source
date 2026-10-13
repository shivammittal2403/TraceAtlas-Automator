import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import json, re, csv, hashlib, uuid, ipaddress
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

APP_TITLE = "TraceAtlas DNSINT AI Employee — Passive / Authorized DNS Intelligence"
APP_VERSION = "TraceAtlas DNSINT Panel v0.1"

FIELDS = [
    ("case_id", "Case ID", "entry"),
    ("task_id", "Task ID", "entry"),
    ("objective", "Objective", "text"),
    ("target_domain", "Target Domain(s)", "entry"),
    ("target_type", "Target Type", "combo"),
    ("questions", "DNSINT Questions", "text"),
    ("evidence_paths", "Local Authorized DNS Evidence Paths (JSON/CSV/TXT)", "text"),
    ("known_domains", "Known Domains / Subdomains", "text"),
    ("known_ips", "Known IPs", "text"),
    ("known_nameservers", "Known Nameservers", "text"),
    ("known_mail_servers", "Known Mail Servers (MX)", "text"),
    ("time_range", "Time Range", "text"),
    ("jurisdiction", "Jurisdiction", "entry"),
    ("scope", "Scope / Allowed Sources", "text"),
    ("authorization", "Authorization Basis", "text"),
    ("source_limits", "Source Limits / Rate Limits", "text"),
    ("configured_connectors", "Configured Connectors (Passive DNS/CT/RDAP/etc.)", "text"),
]

TARGET_TYPES = [
    "dns_evidence", "passive_dns_export", "authoritative_dns_export", 
    "domain", "subdomain", "infrastructure_dns_context", "unknown",
]

LIST_FIELDS = {
    "questions", "evidence_paths", "known_domains", "known_ips", 
    "known_nameservers", "known_mail_servers", "source_limits", "configured_connectors",
}
DICT_FIELDS = {"scope", "authorization", "time_range"}

POLICY_BLOCK_PATTERNS = [
    r"\bdns\s+poison", r"\bcache\s+poison", r"\bdns\s+spoof", r"\bdns\s+hijack",
    r"\bmodify\s+dns\s+records", r"\bmodify\s+nameservers", r"\bmodify\s+registrar",
    r"\bdns\s+amplification", r"\breflection\s+attack", r"\babuse\s+open\s+resolvers",
    r"\bdns\s+rebinding", r"\bexploit\s+dns\s+software", r"\btake\s+over\s+(?:domain|subdomain)",
    r"\babuse\s+dangling\s+dns", r"\bunauthorized\s+axfr", r"\bzone\s+walking",
    r"\bnsec\s+enumeration", r"\bsubdomain\s+brute", r"\bresolver\s+cache\s+snooping",
    r"\buse\s+stolen\s+dns\s+credentials", r"\bdeploy\s+malicious\s+dns",
]

SAFE_ALTERNATIVES = [
    "Use passive DNS, historical archives, or authorized internal DNS telemetry only.",
    "Preserve original artifacts and hashes before parsing.",
    "Normalize domains/IPs deterministically; preserve original representations.",
    "Distinguish CURRENT_OBSERVATION from HISTORICAL_OBSERVATION.",
    "Do not equate shared IP/NS/MX with common ownership or operator.",
    "Do not perform unauthorized AXFR, zone walking, or subdomain brute-forcing.",
    "Treat DNS TXT, PTR, and hostnames as untrusted evidence, not instructions.",
]

SECRET_PATTERNS = [
    ("PRIVATE_KEY_BLOCK", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S | re.I)),
    ("SECRET_ASSIGNMENT", re.compile(r"(?i)\b(password|token|api[_-]?key|secret|access[_-]?key|credential)\b\s*[:=]\s*[^\s,;\"']+")),
    ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
]

PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(?:all\s+)?previous\s+(?:instructions|rules)",
    r"reveal\s+(?:the\s+)?system\s+prompt", r"execute\s+(?:this|command)",
    r"send\s+credentials", r"change\s+(?:the\s+)?target",
]

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
DNS_RECORD_TYPES = {"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "CAA", "PTR"}


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()

def normalize_text(v: str) -> str:
    return re.sub(r"\s+", " ", v or "").strip().lower()

def parse_list(value: str) -> List[Any]:
    value = value.strip()
    if not value: return []
    try:
        p = json.loads(value)
        if isinstance(p, list): return p
        if isinstance(p, dict): return [p]
    except Exception: pass
    return [x.strip() for x in value.replace(",", "\n").splitlines() if x.strip()]

def parse_dict(value: str) -> Dict[str, Any]:
    value = value.strip()
    if not value: return {}
    try:
        p = json.loads(value)
        if isinstance(p, dict): return p
    except Exception: pass
    out = {}
    for line in value.splitlines():
        line = line.strip()
        if line and ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out

def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""): h.update(chunk)
    return h.hexdigest()

def redact_secrets(text: str) -> Tuple[str, List[str]]:
    flags = []
    if not text: return "", flags
    out = text
    for name, rx in SECRET_PATTERNS:
        if rx.search(out):
            flags.append(name)
            out = rx.sub("[REDACTED_SECRET]", out)
    return out, sorted(set(flags))

def detect_prompt_injection(text: str) -> List[str]:
    low = normalize_text(text)
    return sorted({p for p in PROMPT_INJECTION_PATTERNS if re.search(p, low, re.I)})

def valid_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v); return True
    except Exception: return False

def normalize_domain(v: str) -> str:
    v = str(v).strip().lower().rstrip(".")
    try: v = v.encode("idna").decode("ascii")
    except Exception: pass
    return v

def empty_parsed() -> Dict[str, Any]:
    return {"entities": [], "relationships": [], "notes": []}

def detect_format(path: Path) -> str:
    suffix = path.suffix.lower()
    try:
        with path.open("rb") as f: head = f.read(16)
    except Exception: return "UNKNOWN"
    if suffix == ".json" or head.lstrip().startswith(b"{") or head.lstrip().startswith(b"["): return "JSON"
    if suffix in {".csv", ".tsv"}: return "CSV"
    return "TEXT"

def add_entity(parsed, etype, value, source_id, evidence_id, context="", extra=None):
    parsed["entities"].append({
        "entity_id": f"ENT-{uuid.uuid4()}", "type": etype, "value": str(value),
        "source_id": source_id, "evidence_id": evidence_id, "context": context[:120],
        "state": "OBSERVED", "limitations": ["DNS record observed; ownership/operator not established."],
        **(extra or {})
    })

def add_relationship(parsed, src, rel, tgt, source_id, evidence_id, note="", temporal=None):
    if not src or not tgt: return
    parsed["relationships"].append({
        "relationship_id": f"REL-{uuid.uuid4()}", "source_ref": str(src)[:160],
        "relationship": str(rel).upper(), "target_ref": str(tgt)[:160],
        "source_id": source_id, "evidence_id": evidence_id, "state": "OBSERVED",
        "note": note[:200], "temporal": temporal,
        "limitations": ["DNS relationship observed; does not prove common ownership or operator."],
    })

def extract_dns_entities(text: str, source_id: str, evidence_id: str, context: str = "") -> Tuple[List[Dict[str, Any]], List[str]]:
    redacted, secret_flags = redact_secrets(text or "")
    parsed = empty_parsed()
    
    # Simple regex extraction for text
    for match in DOMAIN_RE.finditer(redacted):
        dom = normalize_domain(match.group(0))
        add_entity(parsed, "DOMAIN", dom, source_id, evidence_id, context)
        
    for match in IPV4_RE.finditer(redacted):
        if valid_ip(match.group(0)):
            add_entity(parsed, "IPV4", match.group(0), source_id, evidence_id, context)
            
    for match in IPV6_RE.finditer(redacted):
        if valid_ip(match.group(0)):
            add_entity(parsed, "IPV6", match.group(0), source_id, evidence_id, context)

    return parsed["entities"], secret_flags

def process_json_dns(data: Any, source_id: str, evidence_id: str, parsed: Dict[str, Any]):
    items = []
    if isinstance(data, list): items = data
    elif isinstance(data, dict):
        for k in ["records", "passive_dns", "results", "data"]:
            if isinstance(data.get(k), list):
                items = data[k]; break
        if not items: items = [data]

    for item in items[:50000]:
        if not isinstance(item, dict): continue
        
        qname = item.get("query_name") or item.get("domain") or item.get("fqdn") or item.get("name")
        rtype = str(item.get("record_type") or item.get("type") or "").upper()
        rvalue = item.get("record_value") or item.get("value") or item.get("answer") or item.get("ip")
        first_seen = item.get("first_seen") or item.get("first_observed")
        last_seen = item.get("last_seen") or item.get("last_observed")
        
        if qname:
            qname = normalize_domain(str(qname))
            add_entity(parsed, "DOMAIN", qname, source_id, evidence_id, "json_record", {"first_seen": first_seen, "last_seen": last_seen})
            
        if rvalue and rtype in DNS_RECORD_TYPES:
            rvalue_str = str(rvalue).strip()
            if rtype in {"A", "AAAA"}:
                if valid_ip(rvalue_str):
                    add_entity(parsed, f"IP{rtype[-1] if rtype=='AAAA' else 'V4'}", rvalue_str, source_id, evidence_id, "json_record")
                    add_relationship(parsed, qname, "RESOLVES_TO", rvalue_str, source_id, evidence_id, 
                                     f"{rtype} record", {"first_seen": first_seen, "last_seen": last_seen})
            elif rtype == "CNAME":
                target = normalize_domain(rvalue_str)
                add_entity(parsed, "DOMAIN", target, source_id, evidence_id, "json_record")
                add_relationship(parsed, qname, "CNAME_TO", target, source_id, evidence_id, 
                                 "CNAME record", {"first_seen": first_seen, "last_seen": last_seen})
            elif rtype == "NS":
                ns = normalize_domain(rvalue_str)
                add_entity(parsed, "NAMESERVER", ns, source_id, evidence_id, "json_record")
                add_relationship(parsed, qname, "USES_NAMESERVER", ns, source_id, evidence_id, 
                                 "NS record", {"first_seen": first_seen, "last_seen": last_seen})
            elif rtype == "MX":
                # MX usually has priority and host, try to extract host
                mx_host = rvalue_str.split()[-1] if " " in rvalue_str else rvalue_str
                mx_host = normalize_domain(mx_host)
                add_entity(parsed, "MAIL_SERVER", mx_host, source_id, evidence_id, "json_record")
                add_relationship(parsed, qname, "USES_MAIL_SERVER", mx_host, source_id, evidence_id, 
                                 "MX record", {"first_seen": first_seen, "last_seen": last_seen})
            elif rtype == "TXT":
                add_entity(parsed, "TXT_RECORD", rvalue_str[:200], source_id, evidence_id, "json_record")
                add_relationship(parsed, qname, "HAS_TXT", rvalue_str[:200], source_id, evidence_id, "TXT record")

def process_csv_dns(path: Path, source_id: str, evidence_id: str, parsed: Dict[str, Any]):
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        sample = f.read(1_000_000); f.seek(0)
        try: dialect = csv.Sniffer().sniff(sample, delimiters=",;\t| ")
        except csv.Error: dialect = csv.excel
        reader = csv.DictReader(f, dialect=dialect)
        
        for idx, row in enumerate(reader):
            if idx >= 50000: break
            qname = row.get("query_name") or row.get("domain") or row.get("fqdn") or row.get("name")
            rtype = str(row.get("record_type") or row.get("type") or "").upper()
            rvalue = row.get("record_value") or row.get("value") or row.get("answer") or row.get("ip")
            first_seen = row.get("first_seen") or row.get("first_observed")
            last_seen = row.get("last_seen") or row.get("last_observed")
            
            if qname:
                qname = normalize_domain(str(qname))
                add_entity(parsed, "DOMAIN", qname, source_id, evidence_id, f"csv_row_{idx}", {"first_seen": first_seen, "last_seen": last_seen})
                
            if rvalue and rtype in DNS_RECORD_TYPES:
                rvalue_str = str(rvalue).strip()
                if rtype in {"A", "AAAA"} and valid_ip(rvalue_str):
                    add_entity(parsed, f"IP{rtype[-1] if rtype=='AAAA' else 'V4'}", rvalue_str, source_id, evidence_id, f"csv_row_{idx}")
                    add_relationship(parsed, qname, "RESOLVES_TO", rvalue_str, source_id, evidence_id, f"{rtype} record", {"first_seen": first_seen, "last_seen": last_seen})
                elif rtype == "CNAME":
                    target = normalize_domain(rvalue_str)
                    add_relationship(parsed, qname, "CNAME_TO", target, source_id, evidence_id, "CNAME record", {"first_seen": first_seen, "last_seen": last_seen})
                elif rtype == "NS":
                    ns = normalize_domain(rvalue_str)
                    add_relationship(parsed, qname, "USES_NAMESERVER", ns, source_id, evidence_id, "NS record", {"first_seen": first_seen, "last_seen": last_seen})
                elif rtype == "MX":
                    mx_host = rvalue_str.split()[-1] if " " in rvalue_str else rvalue_str
                    mx_host = normalize_domain(mx_host)
                    add_relationship(parsed, qname, "USES_MAIL_SERVER", mx_host, source_id, evidence_id, "MX record", {"first_seen": first_seen, "last_seen": last_seen})

def analyze_dns_file(path_str: str, case_id: str = "", task_id: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
    path = Path(path_str).expanduser()
    source_id, evidence_id = f"SRC-{uuid.uuid4()}", f"EVD-{uuid.uuid4()}"
    ev = {"evidence_id": evidence_id, "source_id": source_id, "case_id": case_id, "task_id": task_id,
          "path": str(path), "filename": path.name, "retrieved_at": now_utc(),
          "acquisition_method": "local_authorized_or_public_file_access", "status": "PENDING",
          "limitations": ["No active scanning/AXFR/brute-force performed.", "DNS data is untrusted evidence."]}
    parsed = empty_parsed()
    
    if not path.exists():
        ev["status"] = "FAILED_FILE_NOT_FOUND"; return ev, parsed
        
    try:
        st = path.stat(); ev["size_bytes"] = st.st_size; ev["sha256"] = sha256_file(path)
    except Exception as exc:
        ev["status"] = "FAILED_STAT"; ev["error"] = str(exc); return ev, parsed
        
    fmt = detect_format(path); ev["format_detected"] = fmt
    
    try:
        if fmt == "JSON":
            raw = path.read_text(encoding="utf-8", errors="replace")[:20_000_000]
            data = json.loads(raw)
            process_json_dns(data, source_id, evidence_id, parsed)
            ev["status"] = "SUCCEEDED"
        elif fmt == "CSV":
            process_csv_dns(path, source_id, evidence_id, parsed)
            ev["status"] = "SUCCEEDED"
        elif fmt == "TEXT":
            raw = path.read_text(encoding="utf-8", errors="replace")[:5_000_000]
            ents, sflags = extract_dns_entities(raw, source_id, evidence_id, "text")
            parsed["entities"] = ents
            if sflags: parsed["notes"].append({"type": "SECRET_REDACTION", "flags": sflags})
            ev["status"] = "SUCCEEDED"
        else: ev["status"] = "UNSUPPORTED_FORMAT"
    except Exception as exc:
        ev["status"] = "PARTIAL_OR_FAILED"; ev["error"] = f"{exc.__class__.__name__}: {exc}"
        
    ev["parsed_entity_count"] = len(parsed.get("entities", []))
    ev["parsed_relationship_count"] = len(parsed.get("relationships", []))
    return ev, parsed

def aggregate_parsed(parsed_list: List[Dict[str, Any]]) -> Dict[str, Any]:
    agg = empty_parsed()
    for p in parsed_list:
        agg["entities"].extend(p.get("entities", []))
        agg["relationships"].extend(p.get("relationships", []))
        agg["notes"].extend(p.get("notes", []))
    return agg

def normalize_entities(entities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    buckets = defaultdict(list)
    for e in entities: buckets[(e["type"], e["value"])].append(e)
    out = []
    for (etype, val), items in buckets.items():
        sources = sorted({i["source_id"] for i in items})
        first_seen = min([i.get("first_seen") for i in items if i.get("first_seen")] or [None])
        last_seen = max([i.get("last_seen") for i in items if i.get("last_seen")] or [None])
        out.append({"normalized_entity_id": f"NENT-{uuid.uuid4()}", "type": etype, "value": val,
                    "occurrence_count": len(items), "source_count": len(sources),
                    "source_ids": sources[:50], "evidence_ids": sorted({i["evidence_id"] for i in items})[:50],
                    "first_seen": first_seen, "last_seen": last_seen,
                    "confidence": "MODERATE_PENDING_INDEPENDENCE" if len(sources) > 1 else "LOW", "state": "OBSERVED"})
    out.sort(key=lambda x: (x["type"], -x["occurrence_count"]))
    return out[:10000]

def build_contradictions(entities: List[Dict[str, Any]], relationships: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    dom_targets = defaultdict(set)
    for r in relationships:
        if r["relationship"] in {"RESOLVES_TO", "CNAME_TO"}:
            dom_targets[r["source_ref"]].add(r["target_ref"])
    cons = []
    for dom, targets in dom_targets.items():
        if len(targets) > 1:
            cons.append({"contradiction_id": f"CON-{uuid.uuid4()}", "type": "DNS_CONFLICT", "subject": dom,
                         "values": sorted(targets)[:20],
                         "possible_explanations": ["migration", "TTL/cache", "load balancing", "GeoDNS", "different time windows", "stale data"],
                         "resolution_status": "UNRESOLVED", "caution": "Preserve temporal history; do not silently merge."})
    return cons[:200]

def build_hypotheses(entities, relationships) -> List[Dict[str, Any]]:
    hyps = []
    types = {e["type"] for e in entities}
    if {"DOMAIN", "IPV4"} <= types or {"DOMAIN", "IPV6"} <= types:
        hyps += [
            {"hypothesis_id": f"HYP-{uuid.uuid4()}", "statement": "Observed domain and IP may share infrastructure.",
             "supporting_facts": ["Domain/IP co-occurrence in parsed DNS evidence."],
             "falsification_conditions": ["Shared IP is CDN/reverse-proxy/multi-tenant.", "Historical DNS shows different mapping."],
             "next_test": "Check historical DNS and certificate records.", "status": "OPEN"},
        ]
    if not hyps:
        hyps.append({"hypothesis_id": f"HYP-{uuid.uuid4()}", "statement": "Current local evidence is insufficient to establish DNS relationships.",
                     "next_test": "Attach authorized passive DNS or authoritative DNS exports.", "status": "OPEN"})
    return hyps[:100]

def build_knowledge_gaps(payload, files, entities, relationships) -> List[Dict[str, Any]]:
    gaps = []
    types = {e["type"] for e in entities}
    if not files:
        gaps.append({"gap_id": f"GAP-{uuid.uuid4()}", "question": "What authorized DNS evidence exists?",
                     "missing_evidence": "No local evidence file supplied.", "specialist_owner": "DNSINT AI Employee", "priority": "HIGH"})
    if "DOMAIN" in types and "IPV4" not in types and "IPV6" not in types:
        gaps.append({"gap_id": f"GAP-{uuid.uuid4()}", "question": "What do the domains resolve to over time?",
                     "missing_evidence": "No timestamped A/AAAA DNS observations.", "specialist_owner": "DNSINT", "priority": "HIGH"})
    return gaps[:100]

def build_specialist_handoffs(payload, entities) -> List[Dict[str, Any]]:
    types = {e["type"] for e in entities}
    handoffs = []
    if "DOMAIN" in types: handoffs.append({"specialist": "DOMAININT", "reason": "Domain registration/lifecycle context needed.", "expected_output": "RDAP/WHOIS context."})
    if "IPV4" in types or "IPV6" in types: handoffs.append({"specialist": "IPINT / INFRAINT", "reason": "IP context present.", "expected_output": "Allocation/ASN/hosting/cloud context."})
    if "NAMESERVER" in types: handoffs.append({"specialist": "INFRAINT", "reason": "Nameserver provider context needed.", "expected_output": "DNS provider identification."})
    if not handoffs: handoffs.append({"specialist": "DNSINT Manager", "reason": "No specialist handoff triggered.", "expected_output": "Review scope."})
    return handoffs

def build_next_best_action(payload, policy, files, entities, relationships):
    if policy["status"] == "HUMAN_REVIEW_REQUIRED":
        return {"action": "Route to human DNSINT reviewer before consequential ownership attribution.", "owner": "DNSINT Manager"}
    if not files: return {"action": "Attach authorized/passive DNS evidence.", "owner": "DNSINT AI Employee"}
    types = {e["type"] for e in entities}
    if "DOMAIN" in types: return {"action": "Query historical passive DNS to establish timestamped domain→IP mappings.", "owner": "DNSINT"}
    return {"action": "Proceed with passive correlation and source-independence review.", "owner": "DNSINT AI Employee"}

def build_collection_plan(payload, questions, files, entities):
    plan = []
    priority = 1
    has_files = bool(files)
    has_entities = bool(entities)
    connectors = payload.get("configured_connectors") or []
    has_connectors = bool(connectors) and not any("None configured" in str(x) for x in connectors)
    
    def add(op, tool, purpose, status, expected, note="Passive/authorized only."):
        nonlocal priority
        plan.append({"operation": op, "tool_or_provider": tool, "purpose": purpose, "status": status,
                     "expected_output": expected, "priority": priority, "policy_note": note, "execution_status": "NOT_EXECUTED_PLANNING_ONLY"})
        priority += 1
        
    add("preserve_dns_evidence", "local evidence store", "Hash and preserve original DNS artifacts.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE", "DNSEvidenceObject with SHA256.")
    add("safe_parse_dns_artifacts", "local deterministic parser", "Extract domains/IPs/records with first_seen/last_seen.",
        "COMPLETED_LOCAL" if has_entities else "PLANNED_REQUIRES_EVIDENCE", "Normalized DNS entities and temporal relationships.")
    add("passive_dns_historical_context", "Passive DNS connector", "Establish historical domain→IP/NS/MX mappings.",
        "BLOCKED_CONFIGURATION" if not has_connectors else "PLANNED_REQUIRES_CONNECTOR", "Historical RESOLVES_TO with valid_from/valid_to.")
    add("authoritative_dns_check", "Current DNS resolver", "Verify current DNS state against historical.",
        "PLANNED_REQUIRES_AUTHORIZATION", "Current vs Historical DNS comparison.")
    add("certificate_transparency_correlation", "CERTINT / CT connector", "Correlate CT hostnames with DNS records.",
        "BLOCKED_CONFIGURATION" if not has_connectors else "PLANNED_REQUIRES_CONNECTOR", "CT hostname validation.")
    add("source_reliability_independence", "DNSINT analyst", "Assess source reliability and cluster dependent passive DNS feeds.",
        "PLANNED_ANALYTIC", "INDEPENDENT/PARTIALLY_DEPENDENT/DEPENDENT/UNKNOWN.")
    return plan

def policy_screen(payload: Dict[str, Any]) -> Dict[str, Any]:
    scanned = " ".join([str(payload.get("objective", "")), " ".join(str(q) for q in payload.get("questions", [])),
                        str(payload.get("target_domain", ""))]).lower()
    blocked = [p for p in POLICY_BLOCK_PATTERNS if re.search(p, scanned, re.I)]
    if blocked:
        return {"status": "POLICY_BLOCKED", "reasons": sorted(set(blocked)), "human_review_required": True,
                "explanation": "Requested task appears to require DNS poisoning, unauthorized AXFR, subdomain takeover, or brute-forcing.",
                "safe_alternatives": SAFE_ALTERNATIVES}
    return {"status": "ALLOWED_PASSIVE_AUTHORIZED", "reasons": [], "human_review_required": False,
            "explanation": "No obvious violation. Planning-only unless authorized connectors configured.", "safe_alternatives": []}

def validate_payload(payload: Dict[str, Any]) -> List[str]:
    warnings = []
    for f in ["case_id", "task_id", "objective", "target_domain", "target_type"]:
        if not payload.get(f): warnings.append(f"Missing required field: {f}")
    if not payload.get("questions"): warnings.append("No DNSINT questions provided. Defaults inferred.")
    if not payload.get("evidence_paths") and not payload.get("known_domains"):
        warnings.append("No evidence paths or domains provided. Output remains planning-only.")
    return warnings

def default_questions(payload: Dict[str, Any]) -> List[str]:
    return ["What DNS records currently exist and what existed historically?",
            "What domains resolved to which IPs over time?",
            "Which nameservers and mail infrastructure are involved?",
            "Which records changed and when?",
            "Which relationships are historical vs current?",
            "Are there wildcard or CDN effects contaminating the data?"]


class TraceAtlasDNSINTPanel(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1320x900")
        self.minsize(1050, 720)
        self.entries, self.last_result = {}, {}
        self.analyzed_files, self.parsed, self.normalized = [], empty_parsed(), []
        self._configure_style()
        self._build_ui()
        self._set_defaults()

    def _configure_style(self):
        style = ttk.Style(self)
        try: style.theme_use("clam")
        except tk.TclError: pass
        self.configure(bg="#0b0f19")
        style.configure("TFrame", background="#0b0f19")
        style.configure("TLabel", background="#0b0f19", foreground="#e5e7eb", font=("Segoe UI", 10))
        style.configure("Header.TLabel", background="#0b0f19", foreground="#34d399", font=("Segoe UI", 17, "bold"))
        style.configure("Subheader.TLabel", background="#0b0f19", foreground="#94a3b8", font=("Segoe UI", 9))
        style.configure("TNotebook", background="#0b0f19", borderwidth=0)
        style.configure("TNotebook.Tab", padding=[14, 7], font=("Segoe UI", 10, "bold"))
        style.configure("TEntry", fieldbackground="#111827", foreground="#e5e7eb", insertcolor="#fff", bordercolor="#334155")
        style.configure("TCombobox", fieldbackground="#111827", foreground="#e5e7eb", bordercolor="#334155")
        style.configure("TButton", padding=7, font=("Segoe UI", 10, "bold"), background="#1f2937", foreground="#e5e7eb", bordercolor="#475569")
        style.map("TButton", background=[("active", "#334155")], foreground=[("active", "#fff")])

    def _build_ui(self):
        header = ttk.Frame(self)
        header.pack(fill="x", padx=16, pady=(14, 8))
        ttk.Label(header, text="TraceAtlas DNSINT AI Employee", style="Header.TLabel").pack(anchor="w")
        ttk.Label(header, text=(
            "Passive-first / authorized / evidence-first DNS intelligence • No poisoning/AXFR/takeover/brute-force • "
            "Historical ≠ Current • Shared IP/NS ≠ Shared Operator • deterministic parsing only"
        ), style="Subheader.TLabel", wraplength=1240, justify="left").pack(anchor="w", pady=(2, 0))
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(8, 16))
        self.input_tab, self.output_tab = ttk.Frame(self.notebook), ttk.Frame(self.notebook)
        self.notebook.add(self.input_tab, text="DNSINT Task Input")
        self.notebook.add(self.output_tab, text="Output / DNSINT Plan / Evidence")
        self._build_input_tab()
        self._build_output_tab()

    def _build_input_tab(self):
        container = ttk.Frame(self.input_tab)
        container.pack(fill="both", expand=True)
        self.canvas = tk.Canvas(container, bg="#0b0f19", highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=self.canvas.yview)
        self.form = ttk.Frame(self.canvas)
        self.form.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.create_window((0, 0), window=self.form, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        row = 0
        for key, label, kind in FIELDS:
            ttk.Label(self.form, text=label).grid(row=row, column=0, sticky="nw", padx=10, pady=6)
            if kind == "entry": w = ttk.Entry(self.form, width=100)
            elif kind == "combo": w = ttk.Combobox(self.form, values=TARGET_TYPES if key == "target_type" else [], width=98, state="readonly")
            else: w = tk.Text(self.form, height=3, width=100, bg="#111827", fg="#e5e7eb", insertbackground="white", relief="flat", highlightthickness=1, highlightbackground="#334155", font=("Segoe UI", 10), wrap="word")
            w.grid(row=row, column=1, sticky="ew", padx=10, pady=6)
            self.entries[key] = w
            row += 1
        self.form.columnconfigure(1, weight=1)
        buttons = ttk.Frame(self.input_tab)
        buttons.pack(fill="x", padx=10, pady=12)
        ttk.Button(buttons, text="Add Evidence Files", command=self.add_evidence_files).pack(side="left", padx=4)
        ttk.Button(buttons, text="Analyze Local DNS Evidence", command=self.analyze_local_dnsint).pack(side="left", padx=4)
        ttk.Button(buttons, text="Run Policy Screen", command=self.run_policy_screen).pack(side="left", padx=4)
        ttk.Button(buttons, text="Generate DNSINT Plan", command=self.generate_plan).pack(side="left", padx=4)
        ttk.Button(buttons, text="Export JSON", command=self.export_json).pack(side="left", padx=4)
        ttk.Button(buttons, text="Copy Output", command=self.copy_output).pack(side="left", padx=4)
        ttk.Button(buttons, text="Clear Form", command=self.clear_form).pack(side="left", padx=4)

    def _build_output_tab(self):
        container = ttk.Frame(self.output_tab)
        container.pack(fill="both", expand=True)
        self.output = tk.Text(container, wrap="word", bg="#020617", fg="#a7f3d0", insertbackground="white", relief="flat", highlightthickness=1, highlightbackground="#334155", font=("Consolas", 11))
        scroll = ttk.Scrollbar(container, orient="vertical", command=self.output.yview)
        self.output.configure(yscrollcommand=scroll.set)
        self.output.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def _set_defaults(self):
        self.set_widget_value("case_id", "DNSINT-CASE-001")
        self.set_widget_value("task_id", "DNSINT-TASK-001")
        self.set_widget_value("objective", "Build authorized, passive-first DNS intelligence: identify historical and current DNS relationships without active scanning or takeover.")
        self.set_widget_value("target_domain", "example.com")
        self.set_widget_value("target_type", "dns_evidence")
        self.set_widget_value("questions", "\n".join(default_questions({})))
        for k in ["evidence_paths", "known_domains", "known_ips", "known_nameservers", "known_mail_servers"]:
            self.set_widget_value(k, "")
        self.set_widget_value("time_range", json.dumps({"from": "", "to": "", "timezone": "UTC"}, indent=2))
        self.set_widget_value("jurisdiction", "")
        self.set_widget_value("scope", json.dumps({"allowed_source_types": ["passive DNS", "authoritative DNS", "historical archives", "CT"], "prohibited_actions": ["DNS poisoning", "AXFR", "subdomain takeover", "brute-force"]}, indent=2))
        self.set_widget_value("authorization", json.dumps({"authorized_by": "DNSINT Manager", "permitted_actions": ["passive/public collection", "authorized telemetry parsing"], "prohibited_actions": ["active exploitation", "takeover", "poisoning"]}, indent=2))
        self.set_widget_value("source_limits", "")
        self.set_widget_value("configured_connectors", "None configured. Planning-only for external enrichment.")

    def get_widget_value(self, key):
        w = self.entries.get(key)
        if w is None: return ""
        if isinstance(w, tk.Text): return w.get("1.0", "end-1c").strip()
        return w.get().strip()

    def set_widget_value(self, key, value):
        w = self.entries.get(key)
        if w is None: return
        if isinstance(w, tk.Text): w.delete("1.0", "end"); w.insert("1.0", value)
        elif isinstance(w, ttk.Combobox): w.set(value)
        else: w.delete(0, "end"); w.insert(0, value)

    def collect_payload(self):
        payload = {}
        for key, _, _ in FIELDS:
            raw = self.get_widget_value(key)
            if key in LIST_FIELDS: payload[key] = parse_list(raw)
            elif key in DICT_FIELDS: payload[key] = parse_dict(raw)
            else: payload[key] = raw
        payload["generated_at"], payload["panel_version"], payload["operating_mode"] = now_utc(), APP_VERSION, "PLANNING_ONLY_PASSIVE_FIRST"
        return payload

    def add_evidence_files(self):
        paths = filedialog.askopenfilenames(title="Select authorized DNS evidence files", filetypes=[("DNS evidence", "*.json *.csv *.tsv *.txt *.log"), ("All files", "*.*")])
        if not paths: return
        current = self.get_widget_value("evidence_paths")
        self.set_widget_value("evidence_paths", current + ("\n" if current else "") + "\n".join(paths))
        messagebox.showinfo("Evidence Files Added", f"{len(paths)} path(s) added.")

    def run_policy_screen(self):
        payload = self.collect_payload()
        policy = policy_screen(payload)
        self.last_result = {"mode": "POLICY_SCREEN_ONLY", "policy_screen": policy}
        self._write_output(self.last_result)
        self.notebook.select(self.output_tab)
        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning("Policy Blocked", "DNSINT request policy-blocked:\n\n" + "\n".join(policy["reasons"]))
        else:
            messagebox.showinfo("Policy Screen", "No obvious violation. Planning-only active.")

    def analyze_local_dnsint(self):
        payload = self.collect_payload()
        policy = policy_screen(payload)
        if policy["status"] == "POLICY_BLOCKED":
            self.last_result = {"mode": "POLICY_BLOCKED", "policy_screen": policy}
            self._write_output(self.last_result); return
        paths = [str(p).strip() for p in payload.get("evidence_paths", []) if str(p).strip()]
        if not paths:
            messagebox.showwarning("No Evidence", "Add local DNS evidence files first."); return
        files, parsed_list = [], []
        for p in paths[:20]:
            f, pr = analyze_dns_file(p, payload.get("case_id", ""), payload.get("task_id", ""))
            files.append(f); parsed_list.append(pr)
        aggregated = aggregate_parsed(parsed_list)
        normalized = normalize_entities(aggregated.get("entities", []))
        self.analyzed_files, self.parsed, self.normalized = files, aggregated, normalized
        report = self._build_local_analysis_report(files, aggregated, normalized, payload, policy)
        self.last_result = report
        self._write_output(report)
        self.notebook.select(self.output_tab)
        messagebox.showinfo("Local DNSINT Analysis Complete", f"Files: {len(files)}\nEntities: {len(normalized)}\nRelationships: {len(aggregated.get('relationships', []))}")

    def generate_plan(self):
        payload = self.collect_payload()
        warnings = validate_payload(payload)
        policy = policy_screen(payload)
        if policy["status"] == "POLICY_BLOCKED":
            self.last_result = {"mode": "POLICY_BLOCKED", "policy_screen": policy, "warnings": warnings}
            self._write_output(self.last_result); return
        questions = payload.get("questions") or default_questions(payload)
        files, parsed = self.analyzed_files, self.parsed
        entities = self.normalized or normalize_entities(parsed.get("entities", []))
        relationships = parsed.get("relationships", [])
        contradictions = build_contradictions(parsed.get("entities", []), relationships)
        hypotheses = build_hypotheses(entities, relationships)
        gaps = build_knowledge_gaps(payload, files, entities, relationships)
        handoffs = build_specialist_handoffs(payload, entities)
        next_action = build_next_best_action(payload, policy, files, entities, relationships)
        status = "PLANNING_PLUS_LOCAL_DETERMINISTIC_EVIDENCE" if (files or entities) else "PLANNING_ONLY"
        result = {
            "mode": status, "panel_version": APP_VERSION,
            "policy": "Passive-first. No DNS poisoning/AXFR/takeover/brute-force. Deterministic parsing only. Historical != Current.",
            "policy_screen": policy, "warnings": warnings, "payload": payload, "intelligence_questions": questions,
            "evidence_inventory": files, "entity_preview": entities[:300], "entity_count": len(entities),
            "relationship_preview": relationships[:300], "relationship_count": len(relationships),
            "contradictions": contradictions, "hypotheses": hypotheses,
            "knowledge_gaps": gaps, "specialist_handoffs": handoffs, "next_best_action": next_action,
            "dnsint_collection_plan": build_collection_plan(payload, questions, files, entities),
            **self._policy_sections(), **self._schemas(),
        }
        self.last_result = result
        self._write_output(result)
        self.notebook.select(self.output_tab)

    def _build_local_analysis_report(self, files, parsed, entities, payload, policy):
        relationships = parsed.get("relationships", [])
        contradictions = build_contradictions(parsed.get("entities", []), relationships)
        hypotheses = build_hypotheses(entities, relationships)
        gaps = build_knowledge_gaps(payload, files, entities, relationships)
        handoffs = build_specialist_handoffs(payload, entities)
        next_action = build_next_best_action(payload, policy, files, entities, relationships)
        return {
            "mode": "LOCAL_DETERMINISTIC_DNSINT_ANALYSIS", "panel_version": APP_VERSION, "policy_screen": policy,
            "active_scanning_performed": False, "axfr_performed": False, "takeover_performed": False,
            "evidence_inventory": files, "entity_preview": entities[:300], "entity_count": len(entities),
            "relationship_preview": relationships[:300], "relationship_count": len(relationships),
            "contradictions": contradictions, "hypotheses": hypotheses,
            "knowledge_gaps": gaps, "specialist_handoffs": handoffs, "recommended_next_actions": next_action,
            "limitations": ["Local deterministic parsing only.", "Ownership/operator not established.", "Temporal validity requires first_seen/last_seen."],
        }

    def _write_output(self, result):
        self.output.delete("1.0", "end")
        self.output.insert("1.0", json.dumps(result, ensure_ascii=False, indent=2, default=str))

    def _policy_sections(self):
        return {
            "role": {"employee": "DNSINT AI Employee", "hierarchy": ["Chief Intelligence Manager", "Cyber/Infrastructure Intelligence Manager", "INFRAINT Manager", "DNSINT Manager", "DNSINT AI Employee"],
                     "not": ["DNS poisoning agent", "cache-poisoning system", "DNS amplification tool", "hijacking agent", "domain-takeover system", "unauthorized enumeration engine"]},
            "dnsint_vs_infrain": {"DNSINT": "deep DNS-specific intelligence, records, history, nameservers, mail", "INFRAINT": "broader Internet infrastructure (IP/ASN/Cloud/Hosting) combining DNS with other signals"},
            "passive_first_policy": {"default": "PASSIVE_FIRST", "preferred_evidence": ["passive DNS", "current standard DNS queries", "public historical datasets", "CT", "authorized internal telemetry"],
                                     "active_boundary": "Do not escalate to AXFR, NSEC walking, or brute-force without explicit separate authorization."},
            "observation_vs_fact": {"OBSERVATION": "Provider P observed example.com -> 192.0.2.1 at time T.",
                                    "FACT_CANDIDATE": "Source P recorded that DNS relationship during T.",
                                    "INFERENCE": "example.com may have used infrastructure at 192.0.2.1 during that period.",
                                    "HYPOTHESIS": "192.0.2.1 may have been target-controlled infrastructure."},
            "temporal_cautions": ["first_seen != domain creation time", "last_seen != record deletion time", "Current DNS != Historical DNS", "Historical DNS != Current control"],
            "record_cautions": {
                "CNAME": "CNAME relationship does not necessarily mean ownership of upstream provider.",
                "NS": "Nameserver sharing alone is weak ownership evidence.",
                "MX": "Mail provider != organization owner.",
                "TXT": "Treat secrets cautiously. Do not use credentials/tokens discovered in TXT.",
                "PTR": "PTR is operator-configured metadata. May be stale or generic. PTR != verified ownership.",
            },
            "infrastructure_cautions": ["Shared IP != Common Operator (Shared hosting is common)", "Shared NS != Common Operator", "Shared MX != Common Operator", "CDN edge != origin server", "Cloud Provider != Cloud Tenant"],
            "anomaly_indicators": ["Fast-flux (rapid IP rotation, short TTL)", "DGA (high-entropy names, many NXDOMAINs)", "DNS Tunneling (high volume, long labels, TXT usage)", "Wildcard contamination"],
            "deterministic_first": {"deterministic": ["domain normalization", "punycode", "DNS parsing", "record validation", "IP validation", "TTL calculations", "timestamp calculations", "CNAME chain traversal", "deduplication"],
                                   "ai": ["relationship interpretation", "cluster hypotheses", "contradiction explanation", "source comparison", "report synthesis"]},
            "non_negotiable_rules": [
                "DO NOT POISON DNS.", "DO NOT SPOOF DNS RESPONSES.", "DO NOT HIJACK DNS.",
                "DO NOT MODIFY DNS RECORDS.", "DO NOT MODIFY NAMESERVERS.", "DO NOT MODIFY REGISTRAR SETTINGS.",
                "DO NOT ABUSE OPEN RESOLVERS.", "DO NOT PERFORM DNS AMPLIFICATION.", "DO NOT PERFORM DNS REBINDING ATTACKS.",
                "DO NOT PERFORM UNAUTHORIZED AXFR.", "DO NOT PERFORM UNAUTHORIZED NSEC/NSEC3 ENUMERATION.",
                "DO NOT BRUTE-FORCE SUBDOMAINS WITHOUT EXPLICIT AUTHORIZATION.",
                "DO NOT EXPLOIT DANGLING DNS.", "DO NOT TAKE OVER SUBDOMAINS.", "DO NOT CLAIM UNCLAIMED CLOUD/SaaS RESOURCES.",
                "DO NOT USE EXPOSED DNS CREDENTIALS.", "DO NOT EQUATE DNS RECORD WITH OWNERSHIP.",
                "DO NOT EQUATE IP WITH ORGANIZATION.", "DO NOT EQUATE IP WITH PERSON.",
                "DO NOT EQUATE NAMESERVER WITH DOMAIN OWNER.", "DO NOT EQUATE MX PROVIDER WITH ORGANIZATION OWNER.",
                "DO NOT EQUATE SHARED IP WITH COMMON OPERATOR.", "DO NOT EQUATE SHARED NS WITH COMMON OPERATOR.",
                "DO NOT EQUATE SHARED MX WITH COMMON OPERATOR.", "DO NOT EQUATE SHORT TTL WITH MALICIOUSNESS.",
                "DO NOT EQUATE MANY IPS WITH FAST FLUX WITHOUT FALSIFICATION.", "DO NOT EQUATE DYNAMIC DNS WITH MALICIOUSNESS.",
                "DO NOT EQUATE PASSIVE-DNS FIRST_SEEN WITH DOMAIN CREATION.", "DO NOT EQUATE LAST_SEEN WITH RECORD DELETION.",
                "DO NOT EQUATE CT HOSTNAME WITH CURRENT DNS.",
                "DO NOT EQUATE CURRENT SINKHOLE INFRASTRUCTURE WITH HISTORICAL ATTACKER CONTROL.",
                "DO NOT EQUATE CURRENT DNS WITH HISTORICAL DNS.", "DO NOT EQUATE HISTORICAL DNS WITH CURRENT CONTROL.",
                "DO NOT EQUATE MULTIPLE COPIED PASSIVE-DNS SERVICES WITH INDEPENDENT SOURCES.",
                "DO NOT EQUATE AI AGREEMENT WITH DNS CORROBORATION.",
                "DO NOT HIDE WILDCARD CONTAMINATION.", "DO NOT HIDE GEO-DNS / CDN EFFECTS.", "DO NOT HIDE SOURCE COVERAGE LIMITATIONS.",
                "DO NOT INVENT DNS RECORDS.", "DO NOT INVENT FIRST/LAST SEEN.", "DO NOT INVENT HOSTING OWNERSHIP.",
                "DO NOT LOSE TEMPORAL DNS HISTORY.",
            ],
        }

    def _schemas(self):
        return {
            "dns_evidence_schema": {"evidence_id": "Unique identifier", "source_id": "Source identifier", "query_name": "Domain queried", "record_type": "A/AAAA/CNAME/etc.", "record_value": "Resolved value", "ttl": "Time to live", "first_seen": "First observation", "last_seen": "Last observation", "content_hash": "SHA256"},
            "dns_entity_schema": {"entity_id": "Unique identifier", "type": "DOMAIN/IPV4/IPV6/NAMESERVER/MAIL_SERVER/TXT_RECORD", "value": "Normalized value", "first_seen": "Earliest observation", "last_seen": "Latest observation", "state": "OBSERVED"},
            "dns_relationship_schema": {"relationship_id": "Unique identifier", "source_ref": "Source domain", "relationship": "RESOLVES_TO/CNAME_TO/USES_NAMESERVER/USES_MAIL_SERVER", "target_ref": "Target IP/Domain/NS/MX", "state": "OBSERVED", "temporal": {"first_seen": "T1", "last_seen": "T2"}},
            "dnsint_result_schema": ["case_id", "task_id", "objective", "domains", "a_records", "aaaa_records", "cname_records", "mx_records", "ns_records", "txt_records", "current_dns", "historical_dns", "passive_dns", "first_seen", "last_seen", "wildcard_status", "dns_providers", "mail_providers", "ip_relationships", "infrastructure_clusters", "entities", "relationships", "contradictions", "hypotheses", "knowledge_gaps", "recommended_next_actions", "specialist_handoffs"],
        }

    def export_json(self):
        if not self.last_result: self.generate_plan()
        data = self.last_result or self.collect_payload()
        pf = data.get("payload", data)
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")], initialfile=f"{pf.get('case_id', 'dnsint')}_{pf.get('task_id', 'task')}.json")
        if not path: return
        try:
            with open(path, "w", encoding="utf-8") as f: json.dump(data, f, ensure_ascii=False, indent=2, default=str)
            messagebox.showinfo("Export Complete", f"DNSINT JSON saved to:\n{path}")
        except Exception as exc: messagebox.showerror("Export Failed", str(exc))

    def copy_output(self):
        text = self.output.get("1.0", "end-1c").strip()
        if not text: messagebox.showinfo("Copy Output", "No output to copy."); return
        self.clipboard_clear(); self.clipboard_append(text)
        messagebox.showinfo("Copy Output", "Output copied to clipboard.")

    def clear_form(self):
        if not messagebox.askyesno("Clear Form", "Clear all fields, analyzed evidence, and reset defaults?"): return
        self._set_defaults()
        self.output.delete("1.0", "end")
        self.last_result, self.analyzed_files, self.parsed, self.normalized = {}, [], empty_parsed(), []

if __name__ == "__main__":
    app = TraceAtlasDNSINTPanel()
    app.mainloop()