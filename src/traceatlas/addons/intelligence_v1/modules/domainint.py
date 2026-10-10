import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import json, re, csv, hashlib, uuid, ipaddress
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

APP_TITLE = "TraceAtlas DOMAININT AI Employee — Passive / Authorized Domain Intelligence"
APP_VERSION = "TraceAtlas DOMAININT Panel v0.1"

FIELDS = [
    ("case_id", "Case ID", "entry"),
    ("task_id", "Task ID", "entry"),
    ("objective", "Objective", "text"),
    ("target_domain", "Target Domain(s)", "entry"),
    ("target_type", "Target Type", "combo"),
    ("questions", "DOMAININT Questions", "text"),
    ("evidence_paths", "Local Authorized Domain Evidence Paths (RDAP/WHOIS/JSON/CSV/TXT)", "text"),
    ("known_domains", "Known Domains / Subdomains", "text"),
    ("known_organizations", "Known Organizations / Brands", "text"),
    ("known_registrars", "Known Registrars", "text"),
    ("time_range", "Time Range", "text"),
    ("jurisdiction", "Jurisdiction", "entry"),
    ("scope", "Scope / Allowed Sources", "text"),
    ("authorization", "Authorization Basis", "text"),
    ("source_limits", "Source Limits / Rate Limits", "text"),
    ("configured_connectors", "Configured Connectors (RDAP/WHOIS/CT/Archive/etc.)", "text"),
]

TARGET_TYPES = [
    "domain_evidence", "rdap_export", "whois_export", "domain_inventory",
    "brand_domain_analysis", "typosquat_analysis", "unknown",
]

LIST_FIELDS = {
    "questions", "evidence_paths", "known_domains", "known_organizations",
    "known_registrars", "source_limits", "configured_connectors",
}
DICT_FIELDS = {"scope", "authorization", "time_range"}

POLICY_BLOCK_PATTERNS = [
    r"\btake\s+over\s+(?:domain|subdomain)", r"\bmodify\s+dns", r"\bmodify\s+nameservers",
    r"\bmodify\s+registrar\s+settings", r"\battempt\s+account\s+recovery",
    r"\buse\s+stolen\s+registrar\s+credentials", r"\buse\s+leaked\s+tokens",
    r"\bclaim\s+dangling\s+(?:cloud|saas)", r"\bunauthorized\s+axfr",
    r"\bunauthorized\s+high[-\s]volume\s+domain\s+enumeration",
    r"\bregister\s+deceptive\s+domains", r"\bdeploy\s+phishing\s+domains",
    r"\bcontact\s+registrants\s+autonomously",
]

SAFE_ALTERNATIVES = [
    "Use passive RDAP, WHOIS, historical archives, or authorized internal domain inventories only.",
    "Preserve original artifacts and hashes before parsing.",
    "Normalize domains deterministically; preserve original representations.",
    "Distinguish REGISTRAR from REGISTRANT, and HOSTING from OWNERSHIP.",
    "Model domain control as temporal ERAS; do not assign one timeless owner.",
    "Do not perform domain takeover, account recovery, or unauthorized enumeration.",
    "Treat WHOIS text, RDAP remarks, and web archives as untrusted evidence.",
]

SECRET_PATTERNS = [
    ("PRIVATE_KEY_BLOCK", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S | re.I)),
    ("SECRET_ASSIGNMENT", re.compile(r"(?i)\b(password|token|api[_-]?key|secret|access[_-]?key|credential|auth[_-]?code)\b\s*[:=]\s*[^\s,;\"']+")),
    ("EMAIL_LIKE", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
]

PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(?:all\s+)?previous\s+(?:instructions|rules)",
    r"reveal\s+(?:the\s+)?system\s+prompt", r"execute\s+(?:this|command)",
    r"send\s+credentials", r"change\s+(?:the\s+)?target",
]

DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DATE_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}Z?)?\b")


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
            # Redact emails partially to preserve domain context but hide user
            if name == "EMAIL_LIKE":
                out = re.sub(r"([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", r"[REDACTED_USER]@\2", out)
            else:
                out = rx.sub("[REDACTED_SECRET]", out)
    return out, sorted(set(flags))

def detect_prompt_injection(text: str) -> List[str]:
    low = normalize_text(text)
    return sorted({p for p in PROMPT_INJECTION_PATTERNS if re.search(p, low, re.I)})

def normalize_domain(v: str) -> str:
    v = str(v).strip().lower().rstrip(".")
    try: v = v.encode("idna").decode("ascii")
    except Exception: pass
    return v

def extract_registrable_domain(domain: str) -> str:
    parts = domain.split('.')
    if len(parts) <= 2: return domain
    if len(parts) >= 3 and parts[-2] in {'co', 'com', 'org', 'net', 'gov', 'edu', 'ac'} and len(parts[-1]) == 2:
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])

def empty_parsed() -> Dict[str, Any]:
    return {"entities": [], "relationships": [], "events": [], "notes": []}

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
        "state": "OBSERVED", "limitations": ["Registration/Infrastructure data observed; legal ownership not established."],
        **(extra or {})
    })

def add_relationship(parsed, src, rel, tgt, source_id, evidence_id, note="", temporal=None):
    if not src or not tgt: return
    parsed["relationships"].append({
        "relationship_id": f"REL-{uuid.uuid4()}", "source_ref": str(src)[:160],
        "relationship": str(rel).upper(), "target_ref": str(tgt)[:160],
        "source_id": source_id, "evidence_id": evidence_id, "state": "OBSERVED",
        "note": note[:200], "temporal": temporal,
        "limitations": ["Relationship observed; does not prove legal ownership or current control."],
    })

def add_event(parsed, domain, event_type, date, source_id, evidence_id):
    if not domain or not date: return
    parsed["events"].append({
        "event_id": f"EVT-{uuid.uuid4()}", "domain": str(domain), "event_type": str(event_type).upper(),
        "date": str(date), "source_id": source_id, "evidence_id": evidence_id,
        "limitations": ["Date reflects registry record, not necessarily first use or current state."],
    })

def process_rdap_json(data: Any, source_id: str, evidence_id: str, parsed: Dict[str, Any]):
    items = []
    if isinstance(data, list): items = data
    elif isinstance(data, dict):
        if "ldhName" in data or "handle" in data: items = [data]
        else:
            for k in ["domains", "results", "data"]:
                if isinstance(data.get(k), list): items = data[k]; break

    for item in items[:10000]:
        if not isinstance(item, dict): continue
        
        domain = item.get("ldhName") or item.get("domain") or item.get("name")
        if domain:
            domain = normalize_domain(str(domain))
            reg_domain = extract_registrable_domain(domain)
            add_entity(parsed, "DOMAIN", domain, source_id, evidence_id, "rdap_record", {"registrable_domain": reg_domain})
            
            # Events (Dates)
            for evt in item.get("events", []):
                action = evt.get("eventAction", "unknown")
                date = evt.get("eventDate")
                if date:
                    add_event(parsed, domain, action, date, source_id, evidence_id)
                    
            # Status
            statuses = item.get("status", [])
            if isinstance(statuses, list):
                for st in statuses:
                    add_entity(parsed, "DOMAIN_STATUS", f"{domain}:{st}", source_id, evidence_id, "rdap_status")
                    
            # Nameservers
            for ns in item.get("nameservers", []):
                ns_name = ns.get("ldhName") or ns.get("name")
                if ns_name:
                    ns_name = normalize_domain(str(ns_name))
                    add_entity(parsed, "NAMESERVER", ns_name, source_id, evidence_id, "rdap_ns")
                    add_relationship(parsed, domain, "USES_NAMESERVER", ns_name, source_id, evidence_id, "RDAP NS record")
                    
            # Entities (Registrar, Registrant)
            for ent in item.get("entities", []):
                roles = ent.get("roles", [])
                handle = ent.get("handle") or ent.get("name") or "unknown"
                
                if "registrar" in roles:
                    add_entity(parsed, "REGISTRAR", str(handle), source_id, evidence_id, "rdap_registrar")
                    add_relationship(parsed, domain, "REGISTERED_VIA", str(handle), source_id, evidence_id, "RDAP Registrar")
                elif "registrant" in roles:
                    # Check for privacy/proxy
                    vcard = ent.get("vcardArray", [])
                    is_privacy = False
                    if isinstance(vcard, list) and len(vcard) > 1:
                        for v in vcard[1]:
                            if isinstance(v, list) and len(v) >= 4:
                                if "privacy" in str(v).lower() or "proxy" in str(v).lower() or "redacted" in str(v).lower():
                                    is_privacy = True
                                    
                    if is_privacy:
                        add_entity(parsed, "PRIVACY_PROVIDER", str(handle), source_id, evidence_id, "rdap_privacy")
                        add_relationship(parsed, domain, "USES_PRIVACY_PROVIDER", str(handle), source_id, evidence_id, "RDAP Privacy/Proxy")
                    else:
                        add_entity(parsed, "REGISTRANT_CLAIM", str(handle), source_id, evidence_id, "rdap_registrant")
                        add_relationship(parsed, domain, "REGISTRANT_CLAIM", str(handle), source_id, evidence_id, "RDAP Registrant")

def process_csv_domain(path: Path, source_id: str, evidence_id: str, parsed: Dict[str, Any]):
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        sample = f.read(1_000_000); f.seek(0)
        try: dialect = csv.Sniffer().sniff(sample, delimiters=",;\t| ")
        except csv.Error: dialect = csv.excel
        reader = csv.DictReader(f, dialect=dialect)
        
        for idx, row in enumerate(reader):
            if idx >= 50000: break
            domain = row.get("domain") or row.get("name") or row.get("fqdn")
            if domain:
                domain = normalize_domain(str(domain))
                add_entity(parsed, "DOMAIN", domain, source_id, evidence_id, f"csv_row_{idx}")
                
                registrar = row.get("registrar")
                if registrar:
                    add_entity(parsed, "REGISTRAR", registrar, source_id, evidence_id, f"csv_row_{idx}")
                    add_relationship(parsed, domain, "REGISTERED_VIA", registrar, source_id, evidence_id, "CSV Registrar")
                    
                registrant = row.get("registrant") or row.get("owner") or row.get("organization")
                if registrant:
                    if any(x in str(registrant).lower() for x in ["privacy", "proxy", "redacted", "whoisguard"]):
                        add_entity(parsed, "PRIVACY_PROVIDER", registrant, source_id, evidence_id, f"csv_row_{idx}")
                        add_relationship(parsed, domain, "USES_PRIVACY_PROVIDER", registrant, source_id, evidence_id, "CSV Privacy")
                    else:
                        add_entity(parsed, "REGISTRANT_CLAIM", registrant, source_id, evidence_id, f"csv_row_{idx}")
                        add_relationship(parsed, domain, "REGISTRANT_CLAIM", registrant, source_id, evidence_id, "CSV Registrant")
                        
                created = row.get("created") or row.get("creation_date") or row.get("registered")
                if created: add_event(parsed, domain, "registration", created, source_id, evidence_id)
                
                expires = row.get("expires") or row.get("expiration_date") or row.get("expiry")
                if expires: add_event(parsed, domain, "expiration", expires, source_id, evidence_id)
                
                status = row.get("status")
                if status: add_entity(parsed, "DOMAIN_STATUS", f"{domain}:{status}", source_id, evidence_id, f"csv_row_{idx}")

def extract_text_entities(text: str, source_id: str, evidence_id: str, parsed: Dict[str, Any]):
    redacted, sflags = redact_secrets(text)
    if sflags: parsed["notes"].append({"type": "SECRET_REDACTION", "flags": sflags})
    
    for match in DOMAIN_RE.finditer(redacted):
        dom = normalize_domain(match.group(0))
        add_entity(parsed, "DOMAIN", dom, source_id, evidence_id, "text_regex")
        
    for match in DATE_RE.finditer(redacted):
        add_entity(parsed, "DATE", match.group(0), source_id, evidence_id, "text_regex")

def analyze_domain_file(path_str: str, case_id: str = "", task_id: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
    path = Path(path_str).expanduser()
    source_id, evidence_id = f"SRC-{uuid.uuid4()}", f"EVD-{uuid.uuid4()}"
    ev = {"evidence_id": evidence_id, "source_id": source_id, "case_id": case_id, "task_id": task_id,
          "path": str(path), "filename": path.name, "retrieved_at": now_utc(),
          "acquisition_method": "local_authorized_or_public_file_access", "status": "PENDING",
          "limitations": ["No active takeover/account recovery performed.", "WHOIS/RDAP data is untrusted evidence."]}
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
            process_rdap_json(data, source_id, evidence_id, parsed)
            ev["status"] = "SUCCEEDED"
        elif fmt == "CSV":
            process_csv_domain(path, source_id, evidence_id, parsed)
            ev["status"] = "SUCCEEDED"
        elif fmt == "TEXT":
            raw = path.read_text(encoding="utf-8", errors="replace")[:5_000_000]
            extract_text_entities(raw, source_id, evidence_id, parsed)
            ev["status"] = "SUCCEEDED"
        else: ev["status"] = "UNSUPPORTED_FORMAT"
    except Exception as exc:
        ev["status"] = "PARTIAL_OR_FAILED"; ev["error"] = f"{exc.__class__.__name__}: {exc}"
        
    ev["parsed_entity_count"] = len(parsed.get("entities", []))
    ev["parsed_relationship_count"] = len(parsed.get("relationships", []))
    ev["parsed_event_count"] = len(parsed.get("events", []))
    return ev, parsed

def aggregate_parsed(parsed_list: List[Dict[str, Any]]) -> Dict[str, Any]:
    agg = empty_parsed()
    for p in parsed_list:
        agg["entities"].extend(p.get("entities", []))
        agg["relationships"].extend(p.get("relationships", []))
        agg["events"].extend(p.get("events", []))
        agg["notes"].extend(p.get("notes", []))
    return agg

def normalize_entities(entities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    buckets = defaultdict(list)
    for e in entities: buckets[(e["type"], e["value"])].append(e)
    out = []
    for (etype, val), items in buckets.items():
        sources = sorted({i["source_id"] for i in items})
        out.append({"normalized_entity_id": f"NENT-{uuid.uuid4()}", "type": etype, "value": val,
                    "occurrence_count": len(items), "source_count": len(sources),
                    "source_ids": sources[:50], "evidence_ids": sorted({i["evidence_id"] for i in items})[:50],
                    "confidence": "MODERATE_PENDING_INDEPENDENCE" if len(sources) > 1 else "LOW", "state": "OBSERVED"})
    out.sort(key=lambda x: (x["type"], -x["occurrence_count"]))
    return out[:10000]

def build_control_eras(entities: List[Dict[str, Any]], relationships: List[Dict[str, Any]], events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # Group registrant/registrar claims by domain to form temporal eras
    domain_claims = defaultdict(list)
    for r in relationships:
        if r["relationship"] in {"REGISTRANT_CLAIM", "REGISTERED_VIA", "USES_PRIVACY_PROVIDER"}:
            domain_claims[r["source_ref"]].append({
                "type": r["relationship"], "target": r["target_ref"], "source_id": r["source_id"]
            })
            
    eras = []
    for dom, claims in domain_claims.items():
        reg_claims = [c for c in claims if c["type"] == "REGISTRANT_CLAIM"]
        priv_claims = [c for c in claims if c["type"] == "USES_PRIVACY_PROVIDER"]
        registrar_claims = [c for c in claims if c["type"] == "REGISTERED_VIA"]
        
        if reg_claims:
            unique_regs = sorted({c["target"] for c in reg_claims})
            eras.append({"era_id": f"ERA-{uuid.uuid4()}", "domain": dom, "era_type": "REGISTRANT_ERA",
                         "candidates": unique_regs[:10], "privacy_protected": False,
                         "caution": "Registrant claim != verified legal owner. May be privacy/proxy or stale."})
        elif priv_claims:
            unique_privs = sorted({c["target"] for c in priv_claims})
            eras.append({"era_id": f"ERA-{uuid.uuid4()}", "domain": dom, "era_type": "PRIVACY_ERA",
                         "candidates": unique_privs[:10], "privacy_protected": True,
                         "caution": "Privacy provider obscures actual registrant. Do not equate provider with owner."})
                         
        if reg_claims and len(set(c["target"] for c in reg_claims)) > 1:
            eras.append({"era_id": f"ERA-{uuid.uuid4()}", "domain": dom, "era_type": "REGISTRANT_CHANGE_DETECTED",
                         "candidates": sorted({c["target"] for c in reg_claims})[:10], "privacy_protected": False,
                         "caution": "Multiple registrant claims detected. Domain reassignment or transfer likely."})
                         
    return eras[:500]

def build_contradictions(entities: List[Dict[str, Any]], relationships: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    dom_regs = defaultdict(set)
    dom_privs = defaultdict(set)
    for r in relationships:
        if r["relationship"] == "REGISTRANT_CLAIM": dom_regs[r["source_ref"]].add(r["target_ref"])
        if r["relationship"] == "USES_PRIVACY_PROVIDER": dom_privs[r["source_ref"]].add(r["target_ref"])
        
    cons = []
    for dom, regs in dom_regs.items():
        if len(regs) > 1:
            cons.append({"contradiction_id": f"CON-{uuid.uuid4()}", "type": "REGISTRANT_CONFLICT", "subject": dom,
                         "values": sorted(regs)[:20],
                         "possible_explanations": ["domain transfer", "re-registration", "data lag", "WHOIS inconsistency", "privacy proxy change"],
                         "resolution_status": "UNRESOLVED", "caution": "Preserve temporal history; do not silently merge ownership claims."})
                         
    for dom, regs in dom_regs.items():
        if dom in dom_privs and dom_privs[dom]:
            cons.append({"contradiction_id": f"CON-{uuid.uuid4()}", "type": "PRIVACY_VS_REGISTRANT_CONFLICT", "subject": dom,
                         "values": sorted(regs | dom_privs[dom])[:20],
                         "possible_explanations": ["partial redaction", "different WHOIS/RDAP sources", "registrar change"],
                         "resolution_status": "UNRESOLVED"})
                         
    return cons[:200]

def build_hypotheses(entities, relationships, eras) -> List[Dict[str, Any]]:
    hyps = []
    types = {e["type"] for e in entities}
    
    if "REGISTRANT_CLAIM" in types:
        hyps.append({"hypothesis_id": f"HYP-{uuid.uuid4()}", "statement": "Registrant claim represents actual legal owner.",
                     "supporting_facts": ["RDAP/WHOIS lists entity as registrant."],
                     "falsification_conditions": ["Entity is a privacy/proxy service.", "Domain was recently re-registered.", "Data is stale."],
                     "next_test": "Cross-reference with official organization documentation or COMPANYINT.", "status": "OPEN"})
                     
    if any(e["era_type"] == "REGISTRANT_CHANGE_DETECTED" for e in eras):
        hyps.append({"hypothesis_id": f"HYP-{uuid.uuid4()}", "statement": "Domain underwent reassignment or ownership transfer.",
                     "supporting_facts": ["Multiple distinct registrant claims observed."],
                     "falsification_conditions": ["Different claims are actually aliases of same entity.", "One claim is a privacy provider misclassified."],
                     "next_test": "Analyze registration dates and infrastructure changes to define control eras.", "status": "OPEN"})
                     
    if not hyps:
        hyps.append({"hypothesis_id": f"HYP-{uuid.uuid4()}", "statement": "Current local evidence is insufficient to establish domain ownership or lifecycle.",
                     "next_test": "Attach authorized RDAP/WHOIS exports or historical archives.", "status": "OPEN"})
    return hyps[:100]

def build_knowledge_gaps(payload, files, entities, relationships, eras) -> List[Dict[str, Any]]:
    gaps = []
    types = {e["type"] for e in entities}
    if not files:
        gaps.append({"gap_id": f"GAP-{uuid.uuid4()}", "question": "What authorized domain registration evidence exists?",
                     "missing_evidence": "No local RDAP/WHOIS evidence file supplied.", "specialist_owner": "DOMAININT AI Employee", "priority": "HIGH"})
    if "DOMAIN" in types and "REGISTRANT_CLAIM" not in types and "PRIVACY_PROVIDER" not in types:
        gaps.append({"gap_id": f"GAP-{uuid.uuid4()}", "question": "Who is the registrant or privacy provider?",
                     "missing_evidence": "No registrant/privacy claims parsed.", "specialist_owner": "DOMAININT", "priority": "HIGH"})
    if "PRIVACY_PROVIDER" in types and "REGISTRANT_CLAIM" not in types:
        gaps.append({"gap_id": f"GAP-{uuid.uuid4()}", "question": "Who is the actual owner behind the privacy proxy?",
                     "missing_evidence": "Privacy provider obscures registrant. Legal/authorized records needed.", "specialist_owner": "COMPANYINT / Legal", "priority": "MEDIUM"})
    return gaps[:100]

def build_specialist_handoffs(payload, entities) -> List[Dict[str, Any]]:
    types = {e["type"] for e in entities}
    handoffs = []
    if "NAMESERVER" in types: handoffs.append({"specialist": "DNSINT", "reason": "Nameserver context present.", "expected_output": "DNS provider identification and historical NS changes."})
    if "REGISTRANT_CLAIM" in types: handoffs.append({"specialist": "COMPANYINT", "reason": "Registrant claim present.", "expected_output": "Legal entity verification and corporate ownership."})
    if "DOMAIN" in types: handoffs.append({"specialist": "INFRAINT / CERTINT", "reason": "Domain context present.", "expected_output": "Hosting, cloud, CDN, and certificate relationships."})
    if not handoffs: handoffs.append({"specialist": "DOMAININT Manager", "reason": "No specialist handoff triggered.", "expected_output": "Review scope."})
    return handoffs

def build_next_best_action(payload, policy, files, entities, relationships):
    if policy["status"] == "HUMAN_REVIEW_REQUIRED":
        return {"action": "Route to human DOMAININT reviewer before consequential ownership attribution.", "owner": "DOMAININT Manager"}
    if not files: return {"action": "Attach authorized RDAP/WHOIS/domain inventory evidence.", "owner": "DOMAININT AI Employee"}
    types = {e["type"] for e in entities}
    if "PRIVACY_PROVIDER" in types and "REGISTRANT_CLAIM" not in types:
        return {"action": "Cross-reference privacy-protected domain with authorized internal inventory or official org records.", "owner": "COMPANYINT / DOMAININT"}
    return {"action": "Proceed with temporal control-era modeling and source-independence review.", "owner": "DOMAININT AI Employee"}

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
        
    add("preserve_domain_evidence", "local evidence store", "Hash and preserve original RDAP/WHOIS artifacts.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE", "DomainEvidenceObject with SHA256.")
    add("safe_parse_domain_artifacts", "local deterministic parser", "Extract domains, registrars, registrants, dates, statuses.",
        "COMPLETED_LOCAL" if has_entities else "PLANNED_REQUIRES_EVIDENCE", "Normalized domain entities and temporal events.")
    add("rdap_whois_historical_context", "RDAP/WHOIS connector", "Establish historical registration and control eras.",
        "BLOCKED_CONFIGURATION" if not has_connectors else "PLANNED_REQUIRES_CONNECTOR", "Temporal REGISTRANT_CLAIM and REGISTRAR changes.")
    add("certificate_transparency_correlation", "CERTINT / CT connector", "Correlate CT hostnames with domain registration timeline.",
        "BLOCKED_CONFIGURATION" if not has_connectors else "PLANNED_REQUIRES_CONNECTOR", "CT issuance timeline vs registration dates.")
    add("source_reliability_independence", "DOMAININT analyst", "Assess source reliability and cluster dependent WHOIS mirrors.",
        "PLANNED_ANALYTIC", "INDEPENDENT/PARTIALLY_DEPENDENT/DEPENDENT/UNKNOWN.")
    return plan

def policy_screen(payload: Dict[str, Any]) -> Dict[str, Any]:
    scanned = " ".join([str(payload.get("objective", "")), " ".join(str(q) for q in payload.get("questions", [])),
                        str(payload.get("target_domain", ""))]).lower()
    blocked = [p for p in POLICY_BLOCK_PATTERNS if re.search(p, scanned, re.I)]
    if blocked:
        return {"status": "POLICY_BLOCKED", "reasons": sorted(set(blocked)), "human_review_required": True,
                "explanation": "Requested task appears to require domain takeover, account recovery, credential use, or unauthorized enumeration.",
                "safe_alternatives": SAFE_ALTERNATIVES}
    return {"status": "ALLOWED_PASSIVE_AUTHORIZED", "reasons": [], "human_review_required": False,
            "explanation": "No obvious violation. Planning-only unless authorized connectors configured.", "safe_alternatives": []}

def validate_payload(payload: Dict[str, Any]) -> List[str]:
    warnings = []
    for f in ["case_id", "task_id", "objective", "target_domain", "target_type"]:
        if not payload.get(f): warnings.append(f"Missing required field: {f}")
    if not payload.get("questions"): warnings.append("No DOMAININT questions provided. Defaults inferred.")
    if not payload.get("evidence_paths") and not payload.get("known_domains"):
        warnings.append("No evidence paths or domains provided. Output remains planning-only.")
    return warnings

def default_questions(payload: Dict[str, Any]) -> List[str]:
    return ["What is the domain identity, registrar, and registry?",
            "What is the registration timeline (creation, update, expiration)?",
            "Who are the registrant claims, and are they obscured by privacy/proxy services?",
            "What domain control eras exist based on historical registration data?",
            "Which nameservers, mail servers, and DNS providers are associated?",
            "Are there related domains, brand similarities, or typosquat candidates?",
            "Is the domain parked, sinkholed, seized, or re-registered?"]


class TraceAtlasDOMAININTPanel(tk.Tk):
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
        style.configure("Header.TLabel", background="#0b0f19", foreground="#f472b6", font=("Segoe UI", 17, "bold"))
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
        ttk.Label(header, text="TraceAtlas DOMAININT AI Employee", style="Header.TLabel").pack(anchor="w")
        ttk.Label(header, text=(
            "Passive-first / authorized / evidence-first domain intelligence • No takeover/account recovery/credential use • "
            "Registrar ≠ Registrant • Hosting ≠ Ownership • Historical ≠ Current • deterministic parsing only"
        ), style="Subheader.TLabel", wraplength=1240, justify="left").pack(anchor="w", pady=(2, 0))
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(8, 16))
        self.input_tab, self.output_tab = ttk.Frame(self.notebook), ttk.Frame(self.notebook)
        self.notebook.add(self.input_tab, text="DOMAININT Task Input")
        self.notebook.add(self.output_tab, text="Output / DOMAININT Plan / Evidence")
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
        ttk.Button(buttons, text="Analyze Local Domain Evidence", command=self.analyze_local_domainint).pack(side="left", padx=4)
        ttk.Button(buttons, text="Run Policy Screen", command=self.run_policy_screen).pack(side="left", padx=4)
        ttk.Button(buttons, text="Generate DOMAININT Plan", command=self.generate_plan).pack(side="left", padx=4)
        ttk.Button(buttons, text="Export JSON", command=self.export_json).pack(side="left", padx=4)
        ttk.Button(buttons, text="Copy Output", command=self.copy_output).pack(side="left", padx=4)
        ttk.Button(buttons, text="Clear Form", command=self.clear_form).pack(side="left", padx=4)

    def _build_output_tab(self):
        container = ttk.Frame(self.output_tab)
        container.pack(fill="both", expand=True)
        self.output = tk.Text(container, wrap="word", bg="#020617", fg="#fbcfe8", insertbackground="white", relief="flat", highlightthickness=1, highlightbackground="#334155", font=("Consolas", 11))
        scroll = ttk.Scrollbar(container, orient="vertical", command=self.output.yview)
        self.output.configure(yscrollcommand=scroll.set)
        self.output.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def _set_defaults(self):
        self.set_widget_value("case_id", "DOMAININT-CASE-001")
        self.set_widget_value("task_id", "DOMAININT-TASK-001")
        self.set_widget_value("objective", "Build authorized, passive-first domain intelligence: identify registration, lifecycle, and control eras without takeover or credential use.")
        self.set_widget_value("target_domain", "example.com")
        self.set_widget_value("target_type", "domain_evidence")
        self.set_widget_value("questions", "\n".join(default_questions({})))
        for k in ["evidence_paths", "known_domains", "known_organizations", "known_registrars"]:
            self.set_widget_value(k, "")
        self.set_widget_value("time_range", json.dumps({"from": "", "to": "", "timezone": "UTC"}, indent=2))
        self.set_widget_value("jurisdiction", "")
        self.set_widget_value("scope", json.dumps({"allowed_source_types": ["RDAP", "WHOIS", "CT", "Archives", "Authorized Inventory"], "prohibited_actions": ["domain takeover", "account recovery", "credential use", "unauthorized enumeration"]}, indent=2))
        self.set_widget_value("authorization", json.dumps({"authorized_by": "DOMAININT Manager", "permitted_actions": ["passive/public collection", "authorized telemetry parsing"], "prohibited_actions": ["active exploitation", "takeover", "registrar abuse"]}, indent=2))
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
        paths = filedialog.askopenfilenames(title="Select authorized domain evidence files", filetypes=[("Domain evidence", "*.json *.csv *.tsv *.txt *.log"), ("All files", "*.*")])
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
            messagebox.showwarning("Policy Blocked", "DOMAININT request policy-blocked:\n\n" + "\n".join(policy["reasons"]))
        else:
            messagebox.showinfo("Policy Screen", "No obvious violation. Planning-only active.")

    def analyze_local_domainint(self):
        payload = self.collect_payload()
        policy = policy_screen(payload)
        if policy["status"] == "POLICY_BLOCKED":
            self.last_result = {"mode": "POLICY_BLOCKED", "policy_screen": policy}
            self._write_output(self.last_result); return
        paths = [str(p).strip() for p in payload.get("evidence_paths", []) if str(p).strip()]
        if not paths:
            messagebox.showwarning("No Evidence", "Add local domain evidence files first."); return
        files, parsed_list = [], []
        for p in paths[:20]:
            f, pr = analyze_domain_file(p, payload.get("case_id", ""), payload.get("task_id", ""))
            files.append(f); parsed_list.append(pr)
        aggregated = aggregate_parsed(parsed_list)
        normalized = normalize_entities(aggregated.get("entities", []))
        self.analyzed_files, self.parsed, self.normalized = files, aggregated, normalized
        report = self._build_local_analysis_report(files, aggregated, normalized, payload, policy)
        self.last_result = report
        self._write_output(report)
        self.notebook.select(self.output_tab)
        messagebox.showinfo("Local DOMAININT Analysis Complete", f"Files: {len(files)}\nEntities: {len(normalized)}\nRelationships: {len(aggregated.get('relationships', []))}\nEvents: {len(aggregated.get('events', []))}")

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
        events = parsed.get("events", [])
        eras = build_control_eras(entities, relationships, events)
        contradictions = build_contradictions(parsed.get("entities", []), relationships)
        hypotheses = build_hypotheses(entities, relationships, eras)
        gaps = build_knowledge_gaps(payload, files, entities, relationships, eras)
        handoffs = build_specialist_handoffs(payload, entities)
        next_action = build_next_best_action(payload, policy, files, entities, relationships)
        status = "PLANNING_PLUS_LOCAL_DETERMINISTIC_EVIDENCE" if (files or entities) else "PLANNING_ONLY"
        result = {
            "mode": status, "panel_version": APP_VERSION,
            "policy": "Passive-first. No domain takeover/account recovery/credential use. Deterministic parsing only. Registrar != Registrant.",
            "policy_screen": policy, "warnings": warnings, "payload": payload, "intelligence_questions": questions,
            "evidence_inventory": files, "entity_preview": entities[:300], "entity_count": len(entities),
            "relationship_preview": relationships[:300], "relationship_count": len(relationships),
            "event_preview": events[:300], "event_count": len(events),
            "control_eras": eras, "contradictions": contradictions, "hypotheses": hypotheses,
            "knowledge_gaps": gaps, "specialist_handoffs": handoffs, "next_best_action": next_action,
            "domainint_collection_plan": build_collection_plan(payload, questions, files, entities),
            **self._policy_sections(), **self._schemas(),
        }
        self.last_result = result
        self._write_output(result)
        self.notebook.select(self.output_tab)

    def _build_local_analysis_report(self, files, parsed, entities, payload, policy):
        relationships = parsed.get("relationships", [])
        events = parsed.get("events", [])
        eras = build_control_eras(entities, relationships, events)
        contradictions = build_contradictions(parsed.get("entities", []), relationships)
        hypotheses = build_hypotheses(entities, relationships, eras)
        gaps = build_knowledge_gaps(payload, files, entities, relationships, eras)
        handoffs = build_specialist_handoffs(payload, entities)
        next_action = build_next_best_action(payload, policy, files, entities, relationships)
        return {
            "mode": "LOCAL_DETERMINISTIC_DOMAININT_ANALYSIS", "panel_version": APP_VERSION, "policy_screen": policy,
            "active_takeover_performed": False, "credential_use_performed": False, "unauthorized_enumeration_performed": False,
            "evidence_inventory": files, "entity_preview": entities[:300], "entity_count": len(entities),
            "relationship_preview": relationships[:300], "relationship_count": len(relationships),
            "event_preview": events[:300], "event_count": len(events),
            "control_eras": eras, "contradictions": contradictions, "hypotheses": hypotheses,
            "knowledge_gaps": gaps, "specialist_handoffs": handoffs, "recommended_next_actions": next_action,
            "limitations": ["Local deterministic parsing only.", "Legal ownership not established.", "Privacy/proxy services obscure actual registrants."],
        }

    def _write_output(self, result):
        self.output.delete("1.0", "end")
        self.output.insert("1.0", json.dumps(result, ensure_ascii=False, indent=2, default=str))

    def _policy_sections(self):
        return {
            "role": {"employee": "DOMAININT AI Employee", "hierarchy": ["Chief Intelligence Manager", "Cyber/Infrastructure Intelligence Manager", "INFRAINT Manager", "DOMAININT Manager", "DOMAININT AI Employee"],
                     "not": ["domain hijacking agent", "subdomain-takeover agent", "registrar abuse system", "credential-use system", "phishing-domain deployment agent"]},
            "domainint_vs_dnsint": {"DOMAININT": "domain identity, registration, lifecycle, ownership candidates, control eras", "DNSINT": "DNS records, resolution history, nameservers, mail infrastructure"},
            "passive_first_rule": {"default": "PASSIVE_FIRST", "preferred_evidence": ["RDAP", "WHOIS", "DNS", "passive DNS", "CT", "public web", "archives", "authorized internal inventory"],
                                   "active_boundary": "Do not escalate to takeover testing, account recovery, or registrar interaction."},
            "observation_vs_claim": {"OBSERVATION": "RDAP source lists Organization X in registrant field.",
                                     "SOURCE_CLAIM": "Registration data claims Organization X as registrant.",
                                     "FACT_CANDIDATE": "At retrieval time T, source S contained that registrant value.",
                                     "ASSESSMENT": "Organization X likely controls the domain (requires additional evidence)."},
            "ownership_cautions": ["Registrar != Registrant", "Registry != Owner", "Privacy Provider != Owner", "RDAP field != verified real-world identity", "Domain name != organization ownership", "Shared IP/NS/Registrar != same owner"],
            "lifecycle_cautions": ["Creation date != first-ever existence or first use", "Updated date != specific cause without evidence", "Expiration date may change due to renewal/transfer", "Privacy protection is normal, not malicious intent"],
            "control_eras": "Represent domain control as temporal ERAS. Do not assign one timeless owner to entire domain history.",
            "deterministic_first": {"deterministic": ["domain normalization", "public suffix parsing", "punycode", "WHOIS/RDAP parsing", "EPP status parsing", "date normalization", "Levenshtein distance", "Unicode confusable checks", "certificate parsing", "DNS parsing", "hashing", "deduplication"],
                                   "ai": ["organization association hypotheses", "domain-family interpretation", "contradiction analysis", "source comparison", "narrative synthesis"]},
            "non_negotiable_rules": [
                "DO NOT TAKE OVER DOMAINS.", "DO NOT TAKE OVER SUBDOMAINS.", "DO NOT MODIFY DNS.",
                "DO NOT MODIFY NAMESERVERS.", "DO NOT MODIFY REGISTRAR SETTINGS.", "DO NOT ATTEMPT ACCOUNT RECOVERY.",
                "DO NOT USE STOLEN REGISTRAR CREDENTIALS.", "DO NOT USE LEAKED TOKENS OR COOKIES.",
                "DO NOT CLAIM DANGLING CLOUD/SaaS RESOURCES.", "DO NOT PERFORM UNAUTHORIZED AXFR.",
                "DO NOT PERFORM UNAUTHORIZED HIGH-VOLUME DOMAIN ENUMERATION.", "DO NOT REGISTER DECEPTIVE DOMAINS.",
                "DO NOT DEPLOY PHISHING DOMAINS.", "DO NOT CONTACT REGISTRANTS AUTONOMOUSLY.",
                "DO NOT EQUATE REGISTRAR WITH OWNER.", "DO NOT EQUATE REGISTRY WITH OWNER.",
                "DO NOT EQUATE PRIVACY PROVIDER WITH OWNER.", "DO NOT EQUATE RDAP FIELD WITH VERIFIED REAL-WORLD IDENTITY.",
                "DO NOT EQUATE DOMAIN NAME WITH ORGANIZATION OWNERSHIP.", "DO NOT EQUATE SHARED IP WITH SAME OWNER.",
                "DO NOT EQUATE SHARED ASN WITH SAME OWNER.", "DO NOT EQUATE SHARED NAMESERVER WITH SAME OWNER.",
                "DO NOT EQUATE SHARED CERTIFICATE WITH SAME OWNER.", "DO NOT EQUATE SHARED REGISTRAR WITH SAME ACTOR.",
                "DO NOT EQUATE SAME TLD WITH RELATEDNESS.", "DO NOT EQUATE NEW DOMAIN WITH MALICIOUSNESS.",
                "DO NOT EQUATE OLD DOMAIN WITH TRUSTWORTHINESS.", "DO NOT EQUATE PRIVACY PROTECTION WITH MALICIOUS INTENT.",
                "DO NOT EQUATE REGISTRATION COUNTRY WITH OPERATOR NATIONALITY.",
                "DO NOT EQUATE HISTORICAL OWNER WITH CURRENT OWNER.", "DO NOT EQUATE ARCHIVED CONTENT WITH CURRENT CONTROL.",
                "DO NOT EQUATE CT ENTRY WITH LIVE DEPLOYMENT.", "DO NOT EQUATE DOMAIN SIMILARITY WITH MALICIOUS IMPERSONATION.",
                "DO NOT EQUATE MULTIPLE WHOIS MIRRORS WITH INDEPENDENT SOURCES.",
                "DO NOT EQUATE AI AGREEMENT WITH DOMAIN CORROBORATION.",
                "DO NOT HIDE REGISTRATION REDACTION.", "DO NOT HIDE DOMAIN REASSIGNMENT POSSIBILITY.",
                "DO NOT HIDE PROVIDER/THIRD-PARTY RELATIONSHIPS.", "DO NOT INVENT REGISTRANT DATA.",
                "DO NOT INVENT OWNERSHIP.", "DO NOT INVENT HISTORICAL CONTROL.", "DO NOT LOSE DOMAIN LIFECYCLE HISTORY.",
            ],
        }

    def _schemas(self):
        return {
            "domain_evidence_schema": {"evidence_id": "Unique identifier", "source_id": "Source identifier", "domain": "Normalized domain", "observation_type": "RDAP/WHOIS/CT/etc.", "raw_value": "Original data", "observed_at": "UTC time", "valid_from": "Temporal start", "valid_to": "Temporal end", "content_hash": "SHA256"},
            "domain_entity_schema": {"entity_id": "Unique identifier", "type": "DOMAIN/REGISTRAR/REGISTRANT_CLAIM/PRIVACY_PROVIDER/NAMESERVER/DOMAIN_STATUS", "value": "Normalized value", "state": "OBSERVED", "limitations": "Registration data observed; legal ownership not established."},
            "domain_relationship_schema": {"relationship_id": "Unique identifier", "source_ref": "Source domain", "relationship": "REGISTERED_VIA/REGISTRANT_CLAIM/USES_PRIVACY_PROVIDER/USES_NAMESERVER", "target_ref": "Target entity", "state": "OBSERVED", "temporal": {"event_date": "T1"}},
            "domain_event_schema": {"event_id": "Unique identifier", "domain": "Domain", "event_type": "REGISTRATION/EXPIRATION/UPDATE/TRANSFER", "date": "Event date", "limitations": "Date reflects registry record, not necessarily first use or current state."},
            "control_era_schema": {"era_id": "Unique identifier", "domain": "Domain", "era_type": "REGISTRANT_ERA/PRIVACY_ERA/REGISTRANT_CHANGE_DETECTED", "candidates": "List of registrant/privacy claims", "privacy_protected": "Boolean", "caution": "Registrant claim != verified legal owner."},
            "domainint_result_schema": ["case_id", "task_id", "objective", "domain", "normalized_domain", "registrable_domain", "tld", "registry", "registrar", "registrar_history", "registrant_claims", "privacy_providers", "creation_dates", "updated_dates", "expiration_dates", "domain_statuses", "lifecycle_state", "control_eras", "nameservers", "certificates", "hosting_relationships", "related_domains", "organization_associations", "entities", "relationships", "events", "contradictions", "hypotheses", "knowledge_gaps", "recommended_next_actions", "specialist_handoffs"],
        }

    def export_json(self):
        if not self.last_result: self.generate_plan()
        data = self.last_result or self.collect_payload()
        pf = data.get("payload", data)
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")], initialfile=f"{pf.get('case_id', 'domainint')}_{pf.get('task_id', 'task')}.json")
        if not path: return
        try:
            with open(path, "w", encoding="utf-8") as f: json.dump(data, f, ensure_ascii=False, indent=2, default=str)
            messagebox.showinfo("Export Complete", f"DOMAININT JSON saved to:\n{path}")
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
    app = TraceAtlasDOMAININTPanel()
    app.mainloop()