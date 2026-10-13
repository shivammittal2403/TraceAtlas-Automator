import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import json
import re
import csv
import hashlib
import uuid

from collections import defaultdict, Counter
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


APP_TITLE = "TraceAtlas TRADEINT AI Employee — Lawful / Authorized / Compliance-Aware Trade Intelligence Panel"
APP_VERSION = "TraceAtlas TRADEINT Panel v0.1"


FIELDS = [
    ("case_id", "Case ID", "entry"),
    ("task_id", "Task ID", "entry"),
    ("objective", "Objective", "text"),
    ("target", "Target / Company / Shipment Context", "entry"),
    ("target_type", "Target Type", "combo"),
    ("questions", "TRADEINT Questions", "text"),

    ("companies", "Companies / Organizations", "text"),
    ("suppliers", "Suppliers", "text"),
    ("buyers", "Buyers", "text"),
    ("shippers", "Shippers", "text"),
    ("consignees", "Consignees", "text"),
    ("manufacturers", "Manufacturers", "text"),
    ("carriers", "Carriers", "text"),
    ("freight_forwarders", "Freight Forwarders", "text"),
    ("ports", "Ports / Terminals", "text"),
    ("countries", "Countries (Origin/Dest)", "text"),
    ("products", "Products / Commodities", "text"),
    ("hs_codes", "HS Codes / Tariff Lines", "text"),
    
    ("customs_records", "Customs Record Metadata", "text"),
    ("bills_of_lading", "Bill of Lading Metadata", "text"),
    ("invoices", "Commercial Invoices", "text"),
    ("packing_lists", "Packing Lists", "text"),
    ("certificates_of_origin", "Certificates of Origin", "text"),
    ("trade_finance_docs", "Trade Finance Documents", "text"),
    ("procurement_records", "Procurement Records", "text"),

    ("customs_paths", "Customs Record Export Paths", "text"),
    ("bol_paths", "Bill of Lading Export Paths", "text"),
    ("invoice_paths", "Invoice Export Paths", "text"),
    ("packing_paths", "Packing List Export Paths", "text"),
    ("coo_paths", "Certificate of Origin Export Paths", "text"),
    ("manifest_paths", "Shipping Manifest Export Paths", "text"),
    ("stix_misp_paths", "STIX / MISP Export Paths", "text"),

    ("time_range", "Time Range", "text"),
    ("jurisdiction", "Jurisdiction", "entry"),
    ("scope", "Scope / Allowed Sources", "text"),
    ("authorization", "Authorization Basis", "text"),
    ("source_limits", "Source Limits / Safety Limits", "text"),
    ("budget", "Budget", "entry"),
    ("deadline", "Deadline", "entry"),
    ("configured_connectors", "Configured Connectors (Customs DB/Licensed Provider/etc.)", "text"),
]


TARGET_TYPES = [
    "shipment_analysis",
    "company_trade_profile",
    "commodity_flow",
    "customs_compliance_check",
    "sanctions_context",
    "export_control_context",
    "supply_chain_risk",
    "unknown",
]


LIST_FIELDS = {
    "questions",
    "companies",
    "suppliers",
    "buyers",
    "shippers",
    "consignees",
    "manufacturers",
    "carriers",
    "freight_forwarders",
    "ports",
    "countries",
    "products",
    "hs_codes",
    "customs_records",
    "bills_of_lading",
    "invoices",
    "packing_lists",
    "certificates_of_origin",
    "trade_finance_docs",
    "procurement_records",
    "customs_paths",
    "bol_paths",
    "invoice_paths",
    "packing_paths",
    "coo_paths",
    "manifest_paths",
    "stix_misp_paths",
    "source_limits",
    "configured_connectors",
}


DICT_FIELDS = {
    "scope",
    "authorization",
    "time_range",
}


SENSITIVE_TARGET_TYPES = {
    "shipment_analysis",
    "company_trade_profile",
    "commodity_flow",
    "customs_compliance_check",
    "sanctions_context",
    "export_control_context",
    "supply_chain_risk",
}


POLICY_BLOCK_PATTERNS = [
    r"\b(?:design|plan|suggest|recommend)\b[^\n]{0,140}\b(?:smuggling route|concealment technique|false declaration|misclassification|tariff avoidance|origin laundering|invoice falsification|under-invoicing|over-invoicing|transshipment for evasion|shell company routing|cargo concealment|container tampering|AIS manipulation|manifest falsification|customs bypass|inspection avoidance|export control evasion|sanctions evasion|dual-use diversion)\b",
    r"\b(?:facilitate|enable|assist with)\b[^\n]{0,140}\b(?:illegal weapons trade|wildlife trafficking|controlled substance trade|human trafficking|illicit procurement)\b",
    r"\b(?:how to|ways to|methods to)\b[^\n]{0,140}\b(?:avoid customs|reduce detection|hide origin|bypass controls|evade sanctions)\b",
]


SAFE_ALTERNATIVES = [
    "Provide lawful/authorized/evidence-first trade intelligence: entity resolution, commodity analysis, HS-code context, shipment verification, value/quantity consistency checks, route/transshipment analysis, document correlation, and defensive risk assessment.",
    "Do not design smuggling routes, recommend concealment/false declarations/misclassification, advise on tariff evasion via deception, suggest origin laundering, invoice falsification, under/over-invoicing, transshipment for evasion, shell-company routing, cargo concealment, container tampering, AIS/manifest manipulation, customs bypass, inspection avoidance, export-control evasion, sanctions evasion, or dual-use diversion.",
    "Separate roles: Shipper != Manufacturer, Consignee != End User, Buyer != Consignee, Forwarder != Owner, Carrier != Cargo Owner.",
    "Separate concepts: Shipping Country != Origin, Transit != Final Destination, HS Code != Exact Product, Invoice != Shipment, Shipment != Payment.",
    "Escalate legal/compliance questions to humans. Never turn trade intelligence into evasion advice.",
]


SECRET_PATTERNS = [
    (
        "PRIVATE_KEY_BLOCK",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.S | re.I,
        ),
    ),
    (
        "PASSWORD_OR_TOKEN_ASSIGNMENT",
        re.compile(
            r"(?i)\b(password|passwd|pwd|token|api[_-]?key|apikey|secret|"
            r"access[_-]?key|auth[_-]?key|client[_-]?secret|authorization|cookie|session|credential)\b"
            r"\s*[:=]\s*[^\s,;\"']+"
        ),
    ),
]


PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(?:all\s+)?previous\s+(?:instructions|rules)",
    r"change\s+consignee",
    r"use\s+this\s+route",
    r"send\s+document\s+elsewhere",
    r"falsify\s+declaration",
    r"hide\s+origin",
]


# Regex for extracting financial/trade amounts
AMOUNT_RE = re.compile(r"([€$£¥₹]|USD|EUR|GBP|JPY|INR|CAD|AUD|CHF)\s*(-?\d[\d,]*(?:\.\d+)?)|(-?\d[\d,]*(?:\.\d+)?)\s*(USD|EUR|GBP|JPY|INR|CAD|AUD|CHF)")
CURRENCY_SYMBOL_MAP = {
    "$": "USD",
    "€": "EUR",
    "£": "GBP",
    "¥": "JPY",
    "₹": "INR",
}

# Simple HS Code pattern (6-10 digits)
HS_CODE_RE = re.compile(r"\b\d{6}(?:\.\d{2})?(?:-\d{2})?\b")

INCOTERMS = [
    "EXW", "FCA", "FOB", "CFR", "CIF", "CPT", "CIP", "DAP", "DPU", "DDP"
]

COMMODITY_KEYWORDS = {
    "MACHINERY": ["machine", "equipment", "controller", "engine", "motor"],
    "CHEMICALS": ["chemical", "compound", "acid", "solvent", "polymer"],
    "TEXTILES": ["fabric", "cloth", "garment", "yarn", "fiber"],
    "FOOD_AGRI": ["food", "agricultural", "grain", "fruit", "vegetable", "meat"],
    "METALS_MINERALS": ["metal", "steel", "iron", "copper", "ore", "mineral"],
    "ELECTRONICS": ["electronic", "chip", "semiconductor", "component", "device"],
    "VEHICLES": ["vehicle", "car", "truck", "auto", "part"],
    "OTHER": [],
}


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_text(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip().lower()


def normalize_key(value: Any) -> str:
    s = str(value or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "_", s)
    return s.strip("_")


def parse_list(value: str) -> List[Any]:
    value = str(value or "").strip()
    if not value:
        return []

    try:
        parsed = json.loads(value)
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict):
            return [parsed]
    except Exception:
        pass

    normalized = value.replace(",", "\n")
    parts = [p.strip() for p in normalized.splitlines()]
    return [p for p in parts if p]


def parse_dict(value: str) -> Dict[str, Any]:
    value = str(value or "").strip()
    if not value:
        return {}

    try:
        parsed = json.loads(value)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    result: Dict[str, Any] = {}
    for line in value.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, val = line.split(":", 1)
        result[key.strip()] = val.strip()
    return result


def listify(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return [value]


def unique_preserve_order(items: List[Any]) -> List[Any]:
    seen = set()
    out = []
    for item in items:
        key = json.dumps(item, ensure_ascii=False, sort_keys=True, default=str) if isinstance(item, (dict, list)) else str(item)
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def truncate_list(items: List[Any], limit: int) -> Tuple[List[Any], bool]:
    if len(items) <= limit:
        return items, False
    return items[:limit], True


def sha256_text(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="replace")).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def content_fingerprint(text: str) -> str:
    """Heuristic token fingerprint, never proof of independent source origin."""
    redacted, _ = redact_secrets(str(text or ""))
    tokens = re.findall(r"[a-z0-9]+", str(redacted).casefold())
    return sha256_text(" ".join(sorted(set(tokens))))[:32] if tokens else ""


def redact_secrets(text: str) -> Tuple[str, List[str]]:
    flags: List[str] = []
    if not text:
        return "", flags

    out = text
    for name, rx in SECRET_PATTERNS:
        if rx.search(out):
            flags.append(name)
            out = rx.sub("[REDACTED_SECRET]", out)

    return out, sorted(set(flags))


def detect_prompt_injection(text: str) -> List[str]:
    flags: List[str] = []
    low = normalize_text(text)
    for pattern in PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, low, re.I):
            flags.append(pattern)
    return sorted(set(flags))


def safe_str(value: Any, limit: int = 300) -> str:
    return redact_secrets(str(value or ""))[0].strip()[:limit]


def parse_decimal(amount: Any) -> Optional[Decimal]:
    if amount is None:
        return None
    try:
        s = str(amount).replace(",", "").strip()
        if not s:
            return None
        return Decimal(s)
    except (InvalidOperation, ValueError):
        return None


def extract_hs_codes(text: str) -> List[str]:
    codes = []
    for m in HS_CODE_RE.finditer(text or ""):
        c = m.group(0)
        if c not in codes:
            codes.append(c)
    return codes


def classify_commodity(description: str) -> str:
    low = normalize_text(description)
    scores = {}
    for cat, keywords in COMMODITY_KEYWORDS.items():
        score = sum(1 for k in keywords if k in low)
        if score > 0:
            scores[cat] = score
    
    if not scores:
        return "UNKNOWN"
    
    max_cat = max(scores, key=scores.get)
    return max_cat


def calculate_unit_value(total_val: Optional[Decimal], qty: Optional[Decimal]) -> Optional[Decimal]:
    if total_val is None or qty is None or qty == 0:
        return None
    try:
        # Use quantize for standard currency precision (2 decimals) unless high precision needed
        return (total_val / qty).quantize(Decimal('0.0001'), rounding='ROUND_HALF_UP')
    except Exception:
        return None


def empty_parsed() -> Dict[str, Any]:
    return {
        "sources": [],
        "entities": [],
        "shipments": [],
        "documents": [], # BOL, Invoice, Packing List, COO
        "observations": [],
        "notes": [],
        "contradictions": [],
        "hypotheses": [],
        "knowledge_gaps": [],
        "specialist_handoffs": [],
    }


def add_note(parsed: Dict[str, Any], note_type: str, **kwargs: Any) -> None:
    if len(parsed.get("notes", [])) >= 200000:
        return
    note = {"type": note_type}
    note.update(kwargs)
    parsed["notes"].append(note)


def add_observation(parsed: Dict[str, Any], statement: str, source_id: str, evidence_id: str, context: str = "") -> None:
    if len(parsed.get("observations", [])) >= 200000:
        return

    redacted, secret_flags = redact_secrets(str(statement or "")[:1000])
    injection_flags = detect_prompt_injection(str(statement or ""))

    parsed["observations"].append({
        "observation_id": f"OBS-{uuid.uuid4()}",
        "statement": redacted,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": context[:200],
        "state": "SOURCE_OBSERVED",
        "secret_flags": secret_flags,
        "prompt_injection_flags": injection_flags,
        "content_hash": sha256_text(str(statement or "")),
        "limitations": [
            "Trade record observation is metadata existence, not verified legality or intent.",
        ],
    })

    if secret_flags:
        add_note(parsed, "SECRET_REDACTION", flags=secret_flags, source_id=source_id, evidence_id=evidence_id, context=context)
    if injection_flags:
        add_note(parsed, "PROMPT_INJECTION_FLAG", flags=injection_flags, source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Embedded instructions in trade docs are ignored.")


def add_source(
    parsed: Dict[str, Any],
    source_id: str,
    evidence_id: str,
    filename: str = "",
    file_hash: str = "",
    publisher: str = "",
    title: str = "",
    source_type: str = "",
    markings: str = "",
    content_fp: str = "",
) -> None:
    for s in parsed["sources"]:
        if s.get("source_id") == source_id:
            if file_hash and not s.get("file_hash"):
                s["file_hash"] = file_hash
            if publisher and not s.get("publisher"):
                s["publisher"] = publisher
            if title and not s.get("title"):
                s["title"] = title
            if content_fp and not s.get("content_fingerprint"):
                s["content_fingerprint"] = content_fp
            return

    parsed["sources"].append({
        "source_id": source_id,
        "evidence_id": evidence_id,
        "filename": filename,
        "file_hash": file_hash,
        "publisher": publisher,
        "title": title,
        "source_type": source_type or "UNKNOWN",
        "markings": markings,
        "content_fingerprint": content_fp,
        "retrieved_at": now_utc(),
        "state": "SOURCE_REGISTERED",
        "source_independence_state": "UNKNOWN",
        "limitations": [
            "Source registration is local provenance metadata.",
            "Aggregators/copies are not independent sources.",
        ],
    })


def add_entity(parsed: Dict[str, Any], name: Any, role: str, source_id: str, evidence_id: str, context: str = "") -> Optional[str]:
    n = safe_str(name, 200)
    if not n:
        return None
    
    norm_n = normalize_text(n)
    
    for e in parsed["entities"]:
        if e.get("normalized_name") == norm_n and e.get("role_candidate") == role:
            return e.get("entity_id")
            
    eid = f"ENT-{uuid.uuid4()}"
    parsed["entities"].append({
        "entity_id": eid,
        "name": n,
        "normalized_name": norm_n,
        "role_candidate": role, # SHIPPER, CONSIGNEE, BUYER, SELLER, CARRIER, etc.
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "ENTITY_CANDIDATE",
        "limitations": [
            "Entity role separation required. Shipper != Manufacturer. Consignee != End User.",
            "Name similarity alone does not prove identity.",
        ],
    })
    return eid


def add_shipment(
    parsed: Dict[str, Any],
    shipper: Optional[str],
    consignee: Optional[str],
    buyer: Optional[str],
    seller: Optional[str],
    commodity_desc: str,
    hs_code: Optional[str],
    quantity: Optional[Decimal],
    unit: str,
    weight: Optional[Decimal],
    declared_value: Optional[Decimal],
    currency: str,
    origin_country: Optional[str],
    dest_country: Optional[str],
    port_load: Optional[str],
    port_discharge: Optional[str],
    carrier: Optional[str],
    forwarder: Optional[str],
    incoterm: Optional[str],
    departure_date: Optional[str],
    arrival_date: Optional[str],
    bol_ref: Optional[str],
    invoice_ref: Optional[str],
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    
    sid = f"SHP-{uuid.uuid4()}"
    
    # Calculate Unit Value Deterministically
    unit_val = calculate_unit_value(declared_value, quantity)
    
    parsed["shipments"].append({
        "shipment_id": sid,
        "shipper_entity_id": shipper,
        "consignee_entity_id": consignee,
        "buyer_entity_id": buyer,
        "seller_entity_id": seller,
        "commodity_description": safe_str(commodity_desc, 300),
        "commodity_class": classify_commodity(commodity_desc),
        "hs_code_declared": hs_code,
        "quantity": str(quantity) if quantity else None,
        "unit": unit,
        "weight_kg": str(weight) if weight else None,
        "declared_value": str(declared_value) if declared_value else None,
        "currency": currency,
        "unit_value_calculated": str(unit_val) if unit_val else None,
        "origin_country": origin_country,
        "destination_country": dest_country,
        "port_of_loading": port_load,
        "port_of_discharge": port_discharge,
        "carrier": carrier,
        "freight_forwarder": forwarder,
        "incoterm": incoterm,
        "departure_date": departure_date,
        "arrival_date": arrival_date,
        "bill_of_lading_ref": bol_ref,
        "invoice_ref": invoice_ref,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "SHIPMENT_OBSERVED",
        "limitations": [
            "Record exists. Legality/Intent not determined.",
            "Shipper may not be Manufacturer.",
            "Consignee may not be End User.",
            "Declared Value != Market Value necessarily.",
        ],
    })
    return sid


def process_json_record(
    rec: Dict[str, Any],
    source_id: str,
    evidence_id: str,
    parsed: Dict[str, Any],
    context: str = "",
) -> None:
    if not isinstance(rec, dict):
        return

    rec_context = context or "json_record"
    
    # Identify Role Fields
    shipper_raw = get_field(rec, ["shipper", "sender", "exporter"])
    consignee_raw = get_field(rec, ["consignee", "receiver", "importer"])
    buyer_raw = get_field(rec, ["buyer", "purchaser"])
    seller_raw = get_field(rec, ["seller", "vendor", "supplier"])
    carrier_raw = get_field(rec, ["carrier", "vessel", "aircraft"])
    fwd_raw = get_field(rec, ["forwarder", "agent"])
    
    # Resolve Entities
    ent_shipper = add_entity(parsed, shipper_raw, "SHIPPER", source_id, evidence_id, rec_context) if shipper_raw else None
    ent_consignee = add_entity(parsed, consignee_raw, "CONSIGNEE", source_id, evidence_id, rec_context) if consignee_raw else None
    ent_buyer = add_entity(parsed, buyer_raw, "BUYER", source_id, evidence_id, rec_context) if buyer_raw else None
    ent_seller = add_entity(parsed, seller_raw, "SELLER", source_id, evidence_id, rec_context) if seller_raw else None
    
    # Commodity Info
    desc = get_field(rec, ["description", "goods", "product", "item"]) or ""
    hs_raw = get_field(rec, ["hs_code", "tariff", "code"])
    hs_list = extract_hs_codes(str(desc) + " " + str(hs_raw or ""))
    primary_hs = hs_list[0] if hs_list else None
    
    # Quantities/Values
    qty_raw = get_field(rec, ["quantity", "qty", "units_count"])
    unit_raw = get_field(rec, ["unit", "uom"]) or "UNSPECIFIED"
    wt_raw = get_field(rec, ["weight", "gross_weight", "net_weight"])
    val_raw = get_field(rec, ["value", "amount", "total_price", "declared_value"])
    curr_raw = get_field(rec, ["currency", "ccy"]) or "USD"
    
    qty_dec = parse_decimal(qty_raw)
    wt_dec = parse_decimal(wt_raw)
    val_dec = parse_decimal(val_raw)
    
    # Locations/Dates
    orig = get_field(rec, ["origin", "country_of_origin"])
    dest = get_field(rec, ["destination", "final_destination"])
    p_load = get_field(rec, ["port_of_loading", "loading_port"])
    p_disc = get_field(rec, ["port_of_discharge", "discharge_port"])
    dep_date = get_field(rec, ["departure_date", "export_date", "loaded_on"])
    arr_date = get_field(rec, ["arrival_date", "import_date", "discharged_on"])
    
    # Docs
    incoterm = get_field(rec, ["incoterm", "terms"])
    bol_ref = get_field(rec, ["bol_number", "bill_of_lading"])
    inv_ref = get_field(rec, ["invoice_number", "invoice_id"])
    
    # Add Shipment if core elements present
    if any([ent_shipper, ent_consignee, desc, primary_hs]):
        add_shipment(
            parsed,
            ent_shipper,
            ent_consignee,
            ent_buyer,
            ent_seller,
            desc,
            primary_hs,
            qty_dec,
            unit_raw,
            wt_dec,
            val_dec,
            curr_raw,
            orig,
            dest,
            p_load,
            p_disc,
            carrier_raw,
            fwd_raw,
            incoterm,
            dep_date,
            arr_date,
            bol_ref,
            inv_ref,
            source_id,
            evidence_id,
            rec_context
        )
        
    # Also process text blob for hidden patterns
    text_blob = json.dumps(rec, ensure_ascii=False, default=str)[:5000]
    process_text_block(text_blob, source_id, evidence_id, parsed, context=rec_context)


def process_text_block(
    text: str,
    source_id: str,
    evidence_id: str,
    parsed: Dict[str, Any],
    context: str = "",
) -> None:
    raw = str(text or "")
    if not raw.strip():
        return

    redacted, secret_flags = redact_secrets(raw)
    injection_flags = detect_prompt_injection(raw)

    if secret_flags:
        add_note(parsed, "SECRET_REDACTION", flags=secret_flags, source_id=source_id, evidence_id=evidence_id, context=context)
    if injection_flags:
        add_note(parsed, "PROMPT_INJECTION_FLAG", flags=injection_flags, source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Trade documents are untrusted data.")

    add_observation(parsed, redacted[:1000], source_id, evidence_id, context=context)

    # Extract HS Codes from free text
    hs_found = extract_hs_codes(redacted)
    if hs_found:
        add_note(parsed, "HS_CODE_DETECTED", codes=hs_found, source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="HS code presence indicates classification candidate, not verified product identity.")

    # Detect Anomalies Heuristically (Defensive Only)
    low = normalize_text(redacted)
    indicators = []
    
    # Very basic keyword spotting for review signals
    if "transshipment" in low or "via" in low:
        indicators.append("TRANSSHIPMENT_MENTIONED")
    if "urgent" in low or "expedited" in low:
        indicators.append("EXPEDITED_REQUEST_NOTED")
        
    if indicators:
        add_note(parsed, "TRADE_REVIEW_SIGNAL", signals=indicators, source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Signal indicates need for document verification, NOT proof of violation.")


def get_field(rec: Dict[str, Any], keys: List[str]) -> Any:
    if not isinstance(rec, dict):
        return None

    lower = {normalize_key(k): v for k, v in rec.items()}
    for key in keys:
        nk = normalize_key(key)
        if nk in lower and lower[nk] not in (None, ""):
            val = lower[nk]
            if isinstance(val, list):
                return val[0] if val else None
            return val
    return None


def classify_json_payload(data: Any, filename: str = "") -> str:
    if isinstance(data, list):
        return "JSON_ARRAY"
    if not isinstance(data, dict):
        return "GENERIC_JSON"

    keys = {normalize_key(k) for k in data.keys()}
    low = json.dumps(data, ensure_ascii=False, default=str)[:20000].lower()
    fname = normalize_text(filename)

    if "bol" in fname or "bill_of_lading" in keys or "master_bol" in low:
        return "BILL_OF_LADING_RECORD"
    if "invoice" in fname or "inv_" in fname or "commercial_invoice" in low:
        return "COMMERCIAL_INVOICE"
    if "packing" in fname or "pack_list" in keys:
        return "PACKING_LIST"
    if "origin" in fname or "certificate_of_origin" in keys:
        return "CERTIFICATE_OF_ORIGIN"
    if "customs" in fname or "declaration" in keys:
        return "CUSTOMS_DECLARATION"
    if "manifest" in fname:
        return "SHIPPING_MANIFEST"
        
    return "GENERIC_TRADE_DATA"


def walk_json(
    data: Any,
    source_id: str,
    evidence_id: str,
    parsed: Dict[str, Any],
    depth: int = 0,
    path: str = "",
) -> None:
    if depth > 14 or len(parsed.get("observations", [])) > 200000:
        return

    if isinstance(data, dict):
        process_json_record(data, source_id, evidence_id, parsed, context=path or "json")
        for k, v in data.items():
            new_path = f"{path}.{k}" if path else str(k)
            walk_json(v, source_id, evidence_id, parsed, depth + 1, new_path)
    elif isinstance(data, list):
        for item in data[:100000]:
            walk_json(item, source_id, evidence_id, parsed, depth + 1, path)
    elif isinstance(data, str):
        process_text_block(data, source_id, evidence_id, parsed, context=path or "json_string")


def process_json_file(path: Path, source_id: str, evidence_id: str) -> Tuple[str, Dict[str, Any]]:
    parsed = empty_parsed()
    raw = path.read_text(encoding="utf-8", errors="replace")[:30_000_000]
    redacted_raw, _ = redact_secrets(raw)
    fp = content_fingerprint(redacted_raw)
    data = json.loads(raw)
    kind = classify_json_payload(data, path.name)

    add_source(
        parsed,
        source_id,
        evidence_id,
        filename=path.name,
        file_hash=sha256_file(path),
        source_type=kind,
        content_fp=fp,
    )

    walk_json(data, source_id, evidence_id, parsed)
    return kind, parsed


def process_csv_file(path: Path, source_id: str, evidence_id: str) -> Tuple[str, Dict[str, Any]]:
    parsed = empty_parsed()
    raw = path.read_text(encoding="utf-8", errors="replace")[:30_000_000]
    redacted_raw, _ = redact_secrets(raw)
    fp = content_fingerprint(redacted_raw)
    kind = "CSV_TRADE_DATA"

    add_source(
        parsed,
        source_id,
        evidence_id,
        filename=path.name,
        file_hash=sha256_file(path),
        source_type=kind,
        content_fp=fp,
    )

    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        sample = f.read(1_000_000)
        f.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t| ")
        except csv.Error:
            dialect = csv.excel

        reader = csv.DictReader(f, dialect=dialect)
        for idx, row in enumerate(reader):
            if idx >= 200000:
                break
            process_json_record(row, source_id, evidence_id, parsed, context=f"csv_row_{idx}")

    return kind, parsed


def process_text_file(path: Path, source_id: str, evidence_id: str) -> Tuple[str, Dict[str, Any]]:
    parsed = empty_parsed()
    raw = path.read_text(encoding="utf-8", errors="replace")[:10_000_000]
    redacted_raw, _ = redact_secrets(raw)
    fp = content_fingerprint(redacted_raw)
    
    low = redacted_raw.lower()[:20000]
    if "bill of lading" in low:
        kind = "TEXT_BOL"
    elif "invoice" in low:
        kind = "TEXT_INVOICE"
    elif "customs" in low:
        kind = "TEXT_CUSTOMS_DECL"
    else:
        kind = "TEXT_TRADE_NOTE"

    add_source(
        parsed,
        source_id,
        evidence_id,
        filename=path.name,
        file_hash=sha256_file(path),
        source_type=kind,
        content_fp=fp,
    )

    for line_no, line in enumerate(raw.splitlines()[:200000]):
        if line.strip():
            process_text_block(line, source_id, evidence_id, parsed, context=f"text_line_{line_no}")

    return kind, parsed


def detect_format(path: Path) -> Dict[str, str]:
    suffix = path.suffix.lower()

    try:
        with path.open("rb") as f:
            head = f.read(256)
    except Exception as exc:
        return {"format_detected": "UNKNOWN", "mime_type": "application/octet-stream", "format_error": str(exc)}

    binary_suffixes = {
        ".exe", ".dll", ".sys", ".elf", ".so", ".dylib", ".bin", ".fw", ".img",
        ".iso", ".apk", ".jar", ".class", ".zip", ".gz", ".tar", ".7z", ".rar",
        ".pcap", ".pcapng", ".cap", ".msi", ".cab", ".pdf", ".docx", ".xlsx",
    }

    if suffix in binary_suffixes:
        return {"format_detected": "BINARY_ARTIFACT", "mime_type": "application/octet-stream"}

    stripped = head.lstrip()

    if suffix == ".json" or stripped.startswith(b"{") or stripped.startswith(b"["):
        return {"format_detected": "JSON", "mime_type": "application/json"}

    if suffix in {".csv", ".tsv"}:
        return {"format_detected": "CSV", "mime_type": "text/csv"}

    if b"," in head and b"\n" in head and all(b in b"\x09\x0a\x0d\x20" or 32 <= b <= 126 for b in head[:64]):
        return {"format_detected": "CSV", "mime_type": "text/csv"}

    if suffix in {".txt", ".log", ".md", ".yaml", ".yml", ".report", ".stix", ".taxii", ".misp", ".snapshot"}:
        return {"format_detected": "TEXT", "mime_type": "text/plain"}

    try:
        probe = head.decode("utf-8", errors="strict")
        if probe.strip():
            return {"format_detected": "TEXT", "mime_type": "text/plain"}
    except Exception:
        pass

    return {"format_detected": "UNKNOWN", "mime_type": "application/octet-stream"}


def analyze_trade_file(path_str: str, case_id: str = "", task_id: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
    path = Path(path_str).expanduser()
    source_id = f"SRC-{uuid.uuid4()}"
    evidence_id = f"EVD-{uuid.uuid4()}"

    file_evidence: Dict[str, Any] = {
        "evidence_id": evidence_id,
        "source_id": source_id,
        "case_id": case_id,
        "task_id": task_id,
        "path": str(path),
        "filename": path.name,
        "retrieved_at": now_utc(),
        "acquisition_method": "local_authorized_or_public_file_access",
        "status": "PENDING",
        "limitations": [
            "No smuggling route design, customs evasion advice, sanctions evasion planning, or export-control bypass methods performed.",
            "Binary artifacts (PDF/XLSX) are hash/metadata preserved only; no deep parsing executed in this stdlib-only panel.",
            "Trade records are untrusted evidence, not instruction.",
            "Secrets are redacted.",
            "Record existence != Illegal Intent.",
        ],
    }

    parsed = empty_parsed()

    if not path.exists():
        file_evidence["status"] = "FAILED_FILE_NOT_FOUND"
        return file_evidence, parsed

    try:
        st = path.stat()
        file_evidence["size_bytes"] = st.st_size
        file_evidence["filesystem_modified_at"] = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat()
    except Exception as exc:
        file_evidence["status"] = "FAILED_STAT"
        file_evidence["error"] = str(exc)
        return file_evidence, parsed

    try:
        file_evidence["sha256"] = sha256_file(path)
    except Exception as exc:
        file_evidence["sha256_error"] = str(exc)

    fmt = detect_format(path)
    file_evidence.update(fmt)
    format_detected = file_evidence.get("format_detected", "UNKNOWN")

    try:
        if format_detected == "JSON":
            kind, parsed = process_json_file(path, source_id, evidence_id)
            file_evidence["content_kind"] = kind
            file_evidence["status"] = "SUCCEEDED"
        elif format_detected == "CSV":
            kind, parsed = process_csv_file(path, source_id, evidence_id)
            file_evidence["content_kind"] = kind
            file_evidence["status"] = "SUCCEEDED"
        elif format_detected == "TEXT":
            kind, parsed = process_text_file(path, source_id, evidence_id)
            file_evidence["content_kind"] = kind
            file_evidence["status"] = "SUCCEEDED"
        elif format_detected == "BINARY_ARTIFACT":
            file_evidence["content_kind"] = "BINARY_TRADE_DOC_METADATA_ONLY"
            file_evidence["status"] = "PARTIAL_BINARY_METADATA_ONLY"
            file_evidence["reason"] = (
                "Binary trade document detected. This planning panel preserves hash/metadata only. "
                "It does not execute macros, parse PDF/XLSX deeply, or extract hidden layers."
            )
        else:
            file_evidence["content_kind"] = "UNKNOWN_OR_UNSUPPORTED"
            file_evidence["status"] = "UNSUPPORTED_FORMAT"
    except Exception as exc:
        file_evidence["status"] = "PARTIAL_OR_FAILED"
        file_evidence["error"] = f"{exc.__class__.__name__}: {exc}"

    file_evidence["parsed_shipment_count"] = len(parsed.get("shipments", []))
    file_evidence["parsed_entity_count"] = len(parsed.get("entities", []))

    return file_evidence, parsed


def aggregate_parsed(parsed_list: List[Dict[str, Any]]) -> Dict[str, Any]:
    agg = empty_parsed()
    for p in parsed_list:
        for key in agg.keys():
            if isinstance(agg[key], list) and isinstance(p.get(key), list):
                agg[key].extend(p[key])
        for key in agg.keys():
            if isinstance(agg[key], list):
                agg[key] = unique_preserve_order(agg[key])[:200000]
    return agg


def build_trade_network(parsed: Dict[str, Any]) -> None:
    """
    Construct simple relationship edges from shipments.
    """
    relations = []
    ships = parsed.get("shipments", [])
    
    for s in ships:
        shipper = s.get("shipper_entity_id")
        consignee = s.get("consignee_entity_id")
        seller = s.get("seller_entity_id")
        buyer = s.get("buyer_entity_id")
        
        # Seller -> Buyer
        if seller and buyer:
            relations.append({
                "relation_id": f"REL-{uuid.uuid4()}",
                "from_entity": seller,
                "to_entity": buyer,
                "type": "SOLD_TO",
                "shipment_id": s.get("shipment_id"),
                "state": "TRADE_RELATIONSHIP_OBSERVED",
                "limitations": ["Single shipment observed. Recurrence unknown."],
            })
            
        # Shipper -> Consignee
        if shipper and consignee:
            relations.append({
                "relation_id": f"REL-{uuid.uuid4()}",
                "from_entity": shipper,
                "to_entity": consignee,
                "type": "SHIPPED_TO",
                "shipment_id": s.get("shipment_id"),
                "state": "LOGISTICS_LINK_OBSERVED",
                "limitations": ["Logistics link only. Economic ownership unresolved."],
            })
            
    parsed["trade_relations"] = relations


def build_contradictions(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    contradictions = []
    
    # Check for Duplicate Shipments (Same BOL/Invoice Ref)
    ref_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for s in parsed.get("shipments", []):
        bol = s.get("bill_of_lading_ref")
        inv = s.get("invoice_ref")
        if bol:
            ref_map[f"BOL:{bol}"].append(s)
        if inv:
            ref_map[f"INV:{inv}"].append(s)
            
    for sig, group in ref_map.items():
        if len(group) > 1:
            ids = [g['shipment_id'] for g in group]
            contradictions.append({
                "contradiction_id": f"CON-{uuid.uuid4()}",
                "type": "POTENTIAL_DUPLICATE_SHIPMENT",
                "subject": sig,
                "values": ids[:10],
                "possible_explanations": [
                    "Master/House BOL difference",
                    "Amended record",
                    "Partial shipment split",
                    "Data entry duplication",
                ],
                "resolution_status": "UNRESOLVED",
                "caution": "Do not double-count trade volume.",
            })
            
    # Check Value/Quantity Consistency within same shipment (if multiple records exist)
    # Simplified: Just flag if Unit Value seems extreme compared to others (placeholder logic)
    
    contradictions, _ = truncate_list(contradictions, 5000)
    return contradictions


def build_hypotheses(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    hyps = []
    ships = parsed.get("shipments", [])
    rels = parsed.get("trade_relations", [])
    
    if not ships:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Insufficient shipment data to form trade network hypotheses.",
            "supporting_facts": [],
            "opposing_facts": [],
            "unknowns": ["counterparties", "commodities", "routes"],
            "falsification_conditions": ["New customs/BOL records provided."],
            "next_test": "Ingest bill of lading or invoice exports.",
            "status": "OPEN",
        })
        return hyps[:1000]

    # Example Hypothesis: Normal Trade vs New Relationship
    new_pairs = set()
    known_pairs = set() # Placeholder for historical DB lookup
    
    for r in rels:
        pair = (r['from_entity'], r['to_entity'])
        if pair not in known_pairs:
            new_pairs.add(pair)
            
    if new_pairs:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Observed trades represent new commercial relationships rather than established recurring supply chains.",
            "supporting_facts": [f"{len(new_pairs)} unique entity pairs identified."],
            "opposing_facts": ["Historical data missing; recurrence cannot be ruled out."],
            "assumptions": ["Dataset covers relevant timeframe."],
            "unknowns": ["Contractual basis", "Payment status"],
            "falsification_conditions": ["Historical records show prior transactions between these entities."],
            "next_test": "Query historical trade database for counterparty overlap.",
            "status": "OPEN",
        })

    hyps, _ = truncate_list(hyps, 1000)
    return hyps


def build_knowledge_gaps(payload: Dict[str, Any], files: List[Dict[str, Any]], parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    gaps = []
    ships = parsed.get("shipments", [])
    
    if not files:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What authorized trade records exist?",
            "missing_evidence": "No local TRADEINT artifact supplied.",
            "likely_source": "Customs declaration export, Bill of Lading scan, Commercial Invoice.",
            "specialist_owner": "TRADEINT AI Employee",
            "priority": "HIGH",
            "expected_information_value": "Enables baseline trade mapping.",
            "safety_boundary": "No evasion advice or illegal facilitation.",
        })

    if ships and not any(s.get("hs_code_declared") for s in ships):
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What is the precise commodity classification?",
            "missing_evidence": "HS codes missing from records.",
            "likely_source": "Product specification sheet, Technical datasheet, Customs ruling.",
            "specialist_owner": "TRADEINT / TECHINT",
            "priority": "MEDIUM_HIGH",
            "expected_information_value": "Determines duty rate and control status.",
            "safety_boundary": "Do not misclassify to evade duties.",
        })
        
    if any(not s.get("origin_country") for s in ships):
         gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What is the true country of origin?",
            "missing_evidence": "Origin field empty or ambiguous.",
            "likely_source": "Certificate of Origin, Manufacturing location records.",
            "specialist_owner": "TRADEINT / OWNERSHIPINT",
            "priority": "HIGH_IF_SANCTIONS_RELEVANT",
            "expected_information_value": "Critical for sanctions/export-control compliance.",
            "safety_boundary": "Do not assume shipping point equals origin.",
        })

    gaps, _ = truncate_list(gaps, 500)
    return gaps


def build_specialist_handoffs(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    handoffs = []
    ships = parsed.get("shipments", [])
    
    # Sanctions Handoff
    if any(s.get("origin_country") or s.get("destination_country") for s in ships):
        handoffs.append({
            "specialist": "SANCTIONSINT",
            "reason": "Cross-border trade detected involving specific jurisdictions.",
            "expected_output": "Entity/Country sanctions screening results.",
            "question": "Do any parties or locations fall under active sanctions regimes?",
        })
        
    # FININT Handoff
    if any(s.get("invoice_ref") for s in ships):
        handoffs.append({
            "specialist": "FININT",
            "reason": "Commercial invoices linked to shipments.",
            "expected_output": "Payment settlement verification.",
            "question": "Were payments made consistent with invoice values and terms?",
        })

    if not handoffs:
        handoffs.append({
            "specialist": "TRADEINT Manager",
            "reason": "Standard trade review.",
            "expected_output": "Supply chain visibility report.",
            "question": "Are supplier dependencies concentrated?",
        })

    return handoffs


def finalize_parsed(parsed: Dict[str, Any], payload: Optional[Dict[str, Any]] = None, files: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    build_trade_network(parsed)
    parsed["contradictions"] = build_contradictions(parsed)
    parsed["hypotheses"] = build_hypotheses(parsed)
    parsed["knowledge_gaps"] = build_knowledge_gaps(payload or {}, files or [], parsed)
    parsed["specialist_handoffs"] = build_specialist_handoffs(parsed)
    return parsed


def build_next_best_action(
    payload: Dict[str, Any],
    policy: Dict[str, Any],
    files: List[Dict[str, Any]],
    parsed: Dict[str, Any],
) -> Dict[str, str]:
    ships = parsed.get("shipments", [])
    
    if policy.get("status") == "POLICY_BLOCKED":
        return {
            "action": "Revise task to remove prohibited evasion, falsification, or illicit facilitation behavior.",
            "reason": "TRADEINT is analytical/lawful, not operational/evasive.",
            "owner": "TRADEINT Manager",
            "expected_output": "Policy-compliant defensive scope.",
        }

    if not files:
        return {
            "action": "Attach authorized customs records, Bills of Lading, or Invoices.",
            "reason": "No trade evidence available.",
            "owner": "TRADEINT AI Employee",
            "expected_output": "Evidence inventory.",
        }

    if ships and not any(s.get("hs_code_declared") for s in ships):
        return {
            "action": "Retrieve technical specifications or certificates to resolve HS classification ambiguity.",
            "reason": "Commodity classification is incomplete.",
            "owner": "TRADEINT / TECHINT",
            "expected_output": "Verified HS Code candidates.",
        }

    return {
        "action": "Proceed with Document Correlation (Invoice vs BOL vs Packing List) and Benign Explanation Testing.",
        "reason": "Basic shipments mapped; consistency check required.",
        "owner": "TRADEINT / DOCINT",
        "expected_output": "Consistent Trade Narrative or Flagged Discrepancies.",
    }


def build_collection_plan(
    payload: Dict[str, Any],
    questions: List[Any],
    files: List[Dict[str, Any]],
    parsed: Dict[str, Any],
) -> List[Dict[str, Any]]:
    plan = []
    priority = 1
    questions_limited, _ = truncate_list([str(q) for q in questions], 8)

    has_files = bool(files)
    has_ships = bool(parsed.get("shipments"))
    has_rels = bool(parsed.get("trade_relations"))

    def add(operation: str, tool: str, purpose: str, status: str, expected_output: str, safety_risk: str = "LOW", policy_note: str = "Lawful / Analytical / Non-Evasive.") -> None:
        nonlocal priority
        plan.append({
            "question": questions_limited[0] if questions_limited else "General TRADEINT planning",
            "operation": operation,
            "tool_or_provider": tool,
            "purpose": purpose,
            "status": status,
            "expected_output": expected_output,
            "priority": priority,
            "safety_risk": safety_risk,
            "policy_note": policy_note,
            "authorization_status": "ALLOWED_LAWFUL_AUTHORIZED",
            "execution_status": "NOT_EXECUTED_PLANNING_ONLY",
        })
        priority += 1

    add(
        "verify_authorization_and_scope",
        "Legal / Compliance",
        "Ensure access to trade data is legally authorized and scoped.",
        "COMPLETED_LOCAL" if payload.get("authorization") else "REQUIRED_BEFORE_COLLECTION",
        "Signed authorization mandate.",
        safety_risk="CRITICAL_IF_UNAUTHORIZED",
        policy_note="No snooping.",
    )

    add(
        "ingest_primary_records",
        "Local Parser",
        "Hash and ingest Customs Declarations, BOLs, Invoices.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "Normalized Shipment Objects.",
    )

    add(
        "resolve_entities_and_roles",
        "TRADEINT Engine",
        "Map Shipper/Consignee/Buyer/Seller separately.",
        "COMPLETED_LOCAL" if has_ships else "PLANNED_ANALYTIC",
        "Entity-Role Links.",
        safety_risk="HIGH_IF_ROLE_COLLAPSE",
        policy_note="Shipper != Manufacturer. Consignee != End User.",
    )

    add(
        "construct_trade_network",
        "Graph Builder",
        "Create Directed Edges for Sales/Shippings.",
        "COMPLETED_LOCAL" if has_rels else "PLANNED_ANALYTIC",
        "Trade Network Graph.",
        safety_risk="MEDIUM_IF_MISSING_HOPS",
        policy_note="Forwarder != Owner.",
    )

    add(
        "correlate_documents",
        "Reconciliation Logic",
        "Match Invoice <-> BOL <-> Packing List.",
        "PLANNED_ANALYTIC",
        "Document Consistency Report.",
        safety_risk="HIGH_IF_ASSUMED_CONSISTENT",
        policy_note="Mismatch != Fraud automatically.",
    )

    add(
        "test_benign_explanations",
        "Analyst",
        "Propose normal logistics reasons for anomalies.",
        "PLANNED_ANALYTIC",
        "Alternative Hypotheses List.",
        safety_risk="HIGH_IF_TUNNEL_VISION",
        policy_note="Anomaly != Smuggling.",
    )

    return plan


def policy_screen(payload: Dict[str, Any]) -> Dict[str, Any]:
    scanned_text = " ".join(
        [
            str(payload.get("objective", "")),
            " ".join(str(q) for q in payload.get("questions", [])),
            str(payload.get("target", "")),
            " ".join(str(s) for s in payload.get("companies", [])),
            " ".join(str(s) for s in payload.get("products", [])),
        ]
    ).lower()

    blocked_reasons = [p for p in POLICY_BLOCK_PATTERNS if re.search(p, scanned_text, re.IGNORECASE)]

    human_review_required = False
    safety_notes: List[str] = []

    if payload.get("target_type") in SENSITIVE_TARGET_TYPES:
        human_review_required = True
        safety_notes.append(
            "Sensitive trade context detected. Analysis must remain lawful, authorized, and analytical. "
            "No evasion advice, falsification, or illicit facilitation."
        )

    if payload.get("countries") or payload.get("hs_codes"):
        human_review_required = True
        safety_notes.append(
            "Sanctions/Export-Control context possible. Ensure final legal determination is handled by SANCTIONSINT/LEGALINT."
        )

    if blocked_reasons:
        return {
            "status": "POLICY_BLOCKED",
            "reasons": sorted(set(blocked_reasons)),
            "human_review_required": True,
            "safety_notes": safety_notes,
            "explanation": (
                "The requested task appears to involve designing smuggling routes, recommending customs/sanctions evasion, "
                "or facilitating illegal trade activities."
            ),
            "safe_alternatives": SAFE_ALTERNATIVES,
        }

    if human_review_required:
        return {
            "status": "HUMAN_REVIEW_REQUIRED",
            "reasons": [],
            "human_review_required": True,
            "safety_notes": safety_notes,
            "explanation": (
                "No obvious hard policy violation detected, but sensitive cross-border/sanctions/export-control context applies. "
                "Conclusions must be reviewed by authorized compliance/legal humans before action."
            ),
            "safe_alternatives": SAFE_ALTERNATIVES,
        }

    return {
        "status": "ALLOWED_LAWFUL_AUTHORIZED",
        "reasons": [],
        "human_review_required": False,
        "safety_notes": [],
        "explanation": "No obvious policy violation detected. Planning-only mode remains active.",
        "safe_alternatives": [],
    }


def validate_payload(payload: Dict[str, Any]) -> List[str]:
    warnings: List[str] = []

    required = ["case_id", "task_id", "objective", "target", "target_type"]
    for field in required:
        if not payload.get(field):
            warnings.append(f"Missing required field: {field}")

    if not payload.get("questions"):
        warnings.append("No TRADEINT questions provided. Default questions will be inferred.")

    evidence_keys = [
        "companies",
        "suppliers",
        "buyers",
        "shippers",
        "consignees",
        "products",
        "hs_codes",
        "customs_records",
        "bills_of_lading",
        "invoices",
        "customs_paths",
        "bol_paths",
        "invoice_paths",
    ]

    if not any(payload.get(k) for k in evidence_keys):
        warnings.append("No trade evidence provided. Output remains planning-only.")

    if not payload.get("time_range"):
        warnings.append("No time range provided. Trade trends and seasonality require temporal context.")

    return warnings


def default_questions(payload: Dict[str, Any]) -> List[str]:
    return [
        "Which entities were involved in the reported shipments?",
        "What commodities/products were traded, and what HS codes apply?",
        "Who shipped, who received, and who bought/sold?",
        "Are declared values and quantities internally consistent across documents?",
        "Did goods undergo transshipment, and is it ordinary logistics?",
        "Are there sanctions or export-control risks associated with parties/locations?",
        "Do document mismatches indicate clerical error or potential fraud?",
        "What benign explanations exist for observed trade anomalies?",
    ]


class TraceAtlasTRADEINTPanel(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1380x940")
        self.minsize(1100, 760)

        self.entries: Dict[str, Any] = {}
        self.last_result: Dict[str, Any] = {}

        self.analyzed_files: List[Dict[str, Any]] = []
        self.parsed: Dict[str, Any] = empty_parsed()

        self._configure_style()
        self._build_ui()
        self._set_defaults()

    def _configure_style(self) -> None:
        style = ttk.Style(self)

        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        self.configure(bg="#0b0f19")

        style.configure("TFrame", background="#0b0f19")
        style.configure("TLabel", background="#0b0f19", foreground="#e5e7eb", font=("Segoe UI", 10))
        style.configure(
            "Header.TLabel",
            background="#0b0f19",
            foreground="#fbbf24", # Amber/Yellow for Trade
            font=("Segoe UI", 17, "bold"),
        )
        style.configure(
            "Subheader.TLabel",
            background="#0b0f19",
            foreground="#94a3b8",
            font=("Segoe UI", 9),
        )
        style.configure("TNotebook", background="#0b0f19", borderwidth=0)
        style.configure("TNotebook.Tab", padding=[14, 7], font=("Segoe UI", 10, "bold"))

        style.configure(
            "TEntry",
            fieldbackground="#111827",
            foreground="#e5e7eb",
            insertcolor="#ffffff",
            bordercolor="#334155",
            lightcolor="#334155",
            darkcolor="#334155",
        )

        style.configure(
            "TCombobox",
            fieldbackground="#111827",
            foreground="#e5e7eb",
            arrowcolor="#e5e7eb",
            bordercolor="#334155",
            lightcolor="#334155",
            darkcolor="#334155",
        )

        style.configure(
            "TButton",
            padding=7,
            font=("Segoe UI", 10, "bold"),
            background="#1f2937",
            foreground="#e5e7eb",
            bordercolor="#475569",
            lightcolor="#475569",
            darkcolor="#475569",
        )

        style.map(
            "TButton",
            background=[("active", "#334155")],
            foreground=[("active", "#ffffff")],
        )

        style.configure(
            "Vertical.TScrollbar",
            background="#1f2937",
            troughcolor="#0b0f19",
            arrowcolor="#e5e7eb",
        )

    def _build_ui(self) -> None:
        header = ttk.Frame(self)
        header.pack(fill="x", padx=16, pady=(14, 8))

        ttk.Label(header, text="TraceAtlas TRADEINT AI Employee", style="Header.TLabel").pack(anchor="w")

        ttk.Label(
            header,
            text=(
                "Lawful / Authorized / Evidence-first / Compliance-aware trade intelligence • Planning-only by default • "
                "Local deterministic JSON/CSV/TXT shipment/customs/invoice parsing only • "
                "No smuggling design / no evasion advice / no falsification / no illicit facilitation • "
                "Shipper != Manufacturer • Consignee != End User • Invoice != Shipment • Anomaly != Crime"
            ),
            style="Subheader.TLabel",
            wraplength=1280,
            justify="left",
        ).pack(anchor="w", pady=(2, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(8, 16))

        self.input_tab = ttk.Frame(self.notebook)
        self.output_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.input_tab, text="TRADEINT Task Input")
        self.notebook.add(self.output_tab, text="Output / TRADEINT Plan / Evidence")

        self._build_input_tab()
        self._build_output_tab()

    def _build_input_tab(self) -> None:
        container = ttk.Frame(self.input_tab)
        container.pack(fill="both", expand=True)

        self.canvas = tk.Canvas(container, bg="#0b0f19", highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=self.canvas.yview)
        self.form = ttk.Frame(self.canvas)

        self.form.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas_window = self.canvas.create_window((0, 0), window=self.form, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        row = 0

        for key, label, kind in FIELDS:
            ttk.Label(self.form, text=label).grid(row=row, column=0, sticky="nw", padx=10, pady=6)

            if kind == "entry":
                widget = ttk.Entry(self.form, width=102)

            elif kind == "combo":
                widget = ttk.Combobox(
                    self.form,
                    values=TARGET_TYPES if key == "target_type" else [],
                    width=100,
                    state="readonly",
                )

            else:
                widget = tk.Text(
                    self.form,
                    height=3,
                    width=102,
                    bg="#111827",
                    fg="#e5e7eb",
                    insertbackground="white",
                    relief="flat",
                    highlightthickness=1,
                    highlightbackground="#334155",
                    font=("Segoe UI", 10),
                    wrap="word",
                )

            widget.grid(row=row, column=1, sticky="ew", padx=10, pady=6)
            self.entries[key] = widget
            row += 1

        self.form.columnconfigure(1, weight=1)

        buttons1 = ttk.Frame(self.input_tab)
        buttons1.pack(fill="x", padx=10, pady=(12, 4))

        buttons2 = ttk.Frame(self.input_tab)
        buttons2.pack(fill="x", padx=10, pady=(0, 12))

        ttk.Button(buttons1, text="Add Customs Records", command=self.add_customs).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Bills of Lading", command=self.add_bols).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Invoices", command=self.add_invoices_btn).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Packing Lists", command=self.add_packing).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Certificates of Origin", command=self.add_coo).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add STIX / MISP", command=self.add_stix_misp).pack(side="left", padx=4)

        ttk.Button(buttons2, text="Analyze Local TRADEINT Evidence", command=self.analyze_local_tradeint).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Run Policy Screen", command=self.run_policy_screen).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Generate TRADEINT Plan", command=self.generate_plan).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Export JSON", command=self.export_json).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Copy Output", command=self.copy_output).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Clear Form", command=self.clear_form).pack(side="left", padx=4)

    def _build_output_tab(self) -> None:
        container = ttk.Frame(self.output_tab)
        container.pack(fill="both", expand=True)

        self.output = tk.Text(
            container,
            wrap="word",
            bg="#020617",
            fg="#fef3c7", # Light amber text
            insertbackground="white",
            relief="flat",
            highlightthickness=1,
            highlightbackground="#334155",
            font=("Consolas", 11),
        )

        output_scroll = ttk.Scrollbar(container, orient="vertical", command=self.output.yview)
        self.output.configure(yscrollcommand=output_scroll.set)

        self.output.pack(side="left", fill="both", expand=True)
        output_scroll.pack(side="right", fill="y")

    def _set_defaults(self) -> None:
        self.set_widget_value("case_id", "TRADEINT-CASE-001")
        self.set_widget_value("task_id", "TRADEINT-TASK-001")
        self.set_widget_value(
            "objective",
            "Analyze lawful/authorized trade intelligence using evidence-first TRADEINT methods. "
            "Preserve originals, parse safe shipment/customs/invoice metadata deterministically, resolve entities/roles cautiously, "
            "verify HS-code context, check value/quantity consistency, analyze routes/transshipment, correlate documents, test benign explanations, "
            "and produce defensive risk assessments without designing evasion, falsifying records, or facilitating illegal trade.",
        )
        self.set_widget_value("target", "Illustrative example.com / authorized trade context")
        self.set_widget_value("target_type", "shipment_analysis")
        self.set_widget_value(
            "questions",
            "\n".join(default_questions({"target": "Illustrative example.com / authorized trade context"})),
        )

        for field in [
            "companies",
            "suppliers",
            "buyers",
            "shippers",
            "consignees",
            "manufacturers",
            "carriers",
            "freight_forwarders",
            "ports",
            "countries",
            "products",
            "hs_codes",
            "customs_records",
            "bills_of_lading",
            "invoices",
            "packing_lists",
            "certificates_of_origin",
            "trade_finance_docs",
            "procurement_records",
            "customs_paths",
            "bol_paths",
            "invoice_paths",
            "packing_paths",
            "coo_paths",
            "manifest_paths",
            "stix_misp_paths",
        ]:
            self.set_widget_value(field, "")

        self.set_widget_value(
            "time_range",
            json.dumps({"from": "", "to": "", "timezone": "UTC"}, indent=2),
        )
        self.set_widget_value("jurisdiction", "")
        self.set_widget_value(
            "scope",
            json.dumps(
                {
                    "allowed_source_types": [
                        "official customs data",
                        "government import/export databases",
                        "licensed shipment databases",
                        "authorized bills of lading",
                        "commercial invoices",
                        "public corporate records",
                    ],
                    "prohibited_sources_and_actions": [
                        "designing smuggling routes",
                        "recommending concealment techniques",
                        "recommending false declarations",
                        "recommending HS-code misclassification",
                        "recommending tariff avoidance through deception",
                        "recommending origin laundering",
                        "recommending invoice falsification",
                        "recommending under-invoicing or over-invoicing",
                        "recommending transshipment for sanctions evasion",
                        "recommending shell-company routing",
                        "recommending cargo concealment",
                        "recommending container tampering",
                        "recommending AIS manipulation",
                        "recommending manifest falsification",
                        "recommending customs-control bypass",
                        "recommending inspection avoidance",
                        "recommending export-control evasion",
                        "recommending sanctions evasion",
                        "recommending dual-use diversion",
                        "facilitating trafficking",
                        "facilitating illegal weapons trade",
                        "facilitating illegal wildlife trade",
                        "facilitating controlled-substance trade",
                        "facilitating human trafficking",
                    ],
                    "data_minimization_rules": [
                        "preserve original record names",
                        "do not infer manufacturer from shipper",
                        "do not infer end-user from consignee",
                    ],
                    "authorized_use": "internal defensive/authorized trade analysis only",
                },
                indent=2,
            ),
        )
        self.set_widget_value(
            "authorization",
            json.dumps(
                {
                    "authorized_by": "TRADEINT Manager / Chief Intelligence Manager",
                    "authorization_basis": "customer-authorized lawful/public engagement",
                    "permitted_actions": [
                        "local record hashing",
                        "shipment normalization",
                        "entity resolution",
                        "document correlation",
                        "risk assessment",
                    ],
                    "prohibited_actions": [
                        "evasion advice",
                        "falsification",
                        "illicit facilitation",
                    ],
                },
                indent=2,
            ),
        )
        self.set_widget_value("source_limits", "")
        self.set_widget_value("budget", "")
        self.set_widget_value("deadline", "")
        self.set_widget_value(
            "configured_connectors",
            "None configured. No live Customs DB/Licensed Provider connector invoked. Planning-only.",
        )

    def get_widget_value(self, key: str) -> str:
        widget = self.entries.get(key)
        if widget is None:
            return ""

        if isinstance(widget, tk.Text):
            return widget.get("1.0", "end-1c").strip()

        if isinstance(widget, ttk.Combobox):
            return widget.get().strip()

        if isinstance(widget, ttk.Entry):
            return widget.get().strip()

        return ""

    def set_widget_value(self, key: str, value: str) -> None:
        widget = self.entries.get(key)
        if widget is None:
            return

        if isinstance(widget, tk.Text):
            widget.delete("1.0", "end")
            widget.insert("1.0", value)
        elif isinstance(widget, ttk.Combobox):
            widget.set(value)
        elif isinstance(widget, ttk.Entry):
            widget.delete(0, "end")
            widget.insert(0, value)

    def collect_payload(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {}

        for key, _, _ in FIELDS:
            raw = self.get_widget_value(key)

            if key in LIST_FIELDS:
                payload[key] = parse_list(raw)
            elif key in DICT_FIELDS:
                payload[key] = parse_dict(raw)
            else:
                payload[key] = raw

        payload["generated_at"] = now_utc()
        payload["panel_version"] = APP_VERSION
        payload["operating_mode"] = "PLANNING_ONLY_LAWFUL_AUTHORIZED_ANALYTICAL"
        payload["source_boundary"] = "LAWFUL_AUTHORIZED_EVIDENCE_FIRST_COMPLIANCE_AWARE_TRADEINT_ONLY"
        return payload

    def _append_paths(self, field: str, paths: Tuple[str, ...], title: str) -> None:
        if not paths:
            return

        current = self.get_widget_value(field)
        added = "\n".join(paths)
        new_value = current + ("\n" if current else "") + added
        self.set_widget_value(field, new_value)
        messagebox.showinfo(title, f"{len(paths)} path(s) added to {field}.")

    def add_customs(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select customs record export files",
            filetypes=[
                ("Customs Records", "*.json *.csv *.tsv *.txt"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("customs_paths", paths, "Customs Files Added")

    def add_bols(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select Bill of Lading export files",
            filetypes=[
                ("Bills of Lading", "*.json *.csv *.tsv *.txt"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("bol_paths", paths, "BOL Files Added")

    def add_invoices_btn(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select invoice export files",
            filetypes=[
                ("Invoices", "*.json *.csv *.tsv *.txt"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("invoice_paths", paths, "Invoice Files Added")

    def add_packing(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select packing list export files",
            filetypes=[
                ("Packing Lists", "*.json *.csv *.tsv *.txt"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("packing_paths", paths, "Packing List Files Added")

    def add_coo(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select certificate of origin export files",
            filetypes=[
                ("Certificates of Origin", "*.json *.csv *.tsv *.txt"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("coo_paths", paths, "COO Files Added")

    def add_stix_misp(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select STIX / MISP export files",
            filetypes=[
                ("STIX / MISP", "*.json *.xml *.csv *.txt"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("stix_misp_paths", paths, "STIX / MISP Files Added")

    def run_policy_screen(self) -> None:
        payload = self.collect_payload()
        policy = policy_screen(payload)

        result = {
            "mode": "POLICY_SCREEN_ONLY",
            "panel_version": APP_VERSION,
            "policy_screen": policy,
            "payload_preview": {
                "case_id": payload.get("case_id"),
                "task_id": payload.get("task_id"),
                "objective": payload.get("objective"),
                "target": payload.get("target"),
                "target_type": payload.get("target_type"),
                "has_companies": bool(payload.get("companies")),
                "has_products": bool(payload.get("products")),
                "has_hs_codes": bool(payload.get("hs_codes")),
                "has_customs": bool(payload.get("customs_records") or payload.get("customs_paths")),
                "has_bols": bool(payload.get("bills_of_lading") or payload.get("bol_paths")),
            },
        }

        self.last_result = result
        self._write_output(result)
        self.notebook.select(self.output_tab)

        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning(
                "Policy Blocked",
                "This TRADEINT request is policy-blocked.\n\n"
                + "\n".join(policy["reasons"])
                + "\n\nUse only lawful/analytical alternatives.",
            )
        elif policy["status"] == "HUMAN_REVIEW_REQUIRED":
            messagebox.showwarning(
                "Human Review Required",
                "No hard policy block detected, but sensitive cross-border/sanctions context applies.",
            )
        else:
            messagebox.showinfo(
                "Policy Screen",
                "No obvious policy violation detected. Planning-only mode remains active.",
            )

    def analyze_local_tradeint(self) -> None:
        payload = self.collect_payload()
        policy = policy_screen(payload)

        if policy["status"] == "POLICY_BLOCKED":
            result = {
                "mode": "POLICY_BLOCKED",
                "panel_version": APP_VERSION,
                "policy_screen": policy,
                "evidence_inventory": [],
                "shipments_preview": [],
                "relations_preview": [],
                "observations": [],
                "candidate_facts": [],
            }
            self.last_result = result
            self._write_output(result)
            messagebox.showwarning("Policy Blocked", "Local TRADEINT evidence analysis blocked by policy screen.")
            return

        path_fields = [
            "customs_paths",
            "bol_paths",
            "invoice_paths",
            "packing_paths",
            "coo_paths",
            "manifest_paths",
            "stix_misp_paths",
        ]

        all_paths: List[str] = []
        seen = set()

        for field in path_fields:
            for p in payload.get(field, []):
                sp = str(p).strip()
                if sp and sp not in seen:
                    seen.add(sp)
                    all_paths.append(sp)

        if not all_paths:
            messagebox.showwarning("No TRADEINT Evidence", "Add local authorized/lawful trade evidence files first.")
            return

        self.output.delete("1.0", "end")
        self.output.insert("1.0", "Analyzing local lawful/authorized TRADEINT evidence. Hashing and parsing may take time...\n")
        self.notebook.select(self.output_tab)

        files: List[Dict[str, Any]] = []
        parsed_list: List[Dict[str, Any]] = []

        for p in all_paths[:30]:
            f, parsed = analyze_trade_file(p, payload.get("case_id", ""), payload.get("task_id", ""))
            files.append(f)
            parsed_list.append(parsed)

        aggregated = finalize_parsed(aggregate_parsed(parsed_list), payload, files)

        self.analyzed_files = files
        self.parsed = aggregated

        report = self._build_local_analysis_report(
            files=files,
            parsed=aggregated,
            payload=payload,
            policy=policy,
        )

        self.last_result = report
        self._write_output(report)

        succeeded = sum(1 for f in files if str(f.get("status", "")).startswith("SUCCEEDED"))
        messagebox.showinfo(
            "Local TRADEINT Evidence Analysis Complete",
            f"Processed {len(files)} evidence file(s).\n"
            f"Succeeded/partial: {succeeded}\n"
            f"Shipments: {len(aggregated.get('shipments', []))}\n"
            f"Entities: {len(aggregated.get('entities', []))}\n"
            f"Relations: {len(aggregated.get('trade_relations', []))}\n"
            "Review output for limitations and next actions.",
        )

    def generate_plan(self) -> None:
        payload = self.collect_payload()
        warnings = validate_payload(payload)
        policy = policy_screen(payload)

        if policy["status"] == "POLICY_BLOCKED":
            result = {
                "mode": "POLICY_BLOCKED",
                "panel_version": APP_VERSION,
                "policy_screen": policy,
                "warnings": warnings,
                "payload": payload,
                "tradeint_collection_plan": [],
                "next_best_action": {
                    "action": "Revise task to remove prohibited evasion, falsification, or illicit facilitation behavior.",
                    "owner": "TRADEINT Manager",
                    "expected_output": "Policy-compliant defensive scope.",
                },
            }
            self.last_result = result
            self._write_output(result)
            messagebox.showwarning(
                "Policy Blocked",
                "TRADEINT plan not generated because the request is policy-blocked.",
            )
            return

        questions = payload.get("questions") or default_questions(payload)

        if not self.parsed.get("shipments") and not self.parsed.get("trade_relations"):
            self.parsed = finalize_parsed(empty_parsed(), payload, self.analyzed_files)

        files = self.analyzed_files
        parsed = self.parsed

        next_action = build_next_best_action(payload, policy, files, parsed)
        collection_plan = build_collection_plan(payload, questions, files, parsed)

        overall_status = "PLANNING_ONLY"
        if policy["status"] == "HUMAN_REVIEW_REQUIRED":
            overall_status = "HUMAN_REVIEW_REQUIRED"
        if files or parsed.get("shipments") or parsed.get("trade_relations"):
            overall_status = "PLANNING_PLUS_LOCAL_DETERMINISTIC_EVIDENCE"

        result = {
            "mode": overall_status,
            "panel_version": APP_VERSION,
            "policy": (
                "This output does not design smuggling routes, recommend concealment/false declarations/misclassification, advise on tariff evasion via deception, "
                "suggest origin laundering, invoice falsification, under/over-invoicing, transshipment for evasion, shell-company routing, cargo concealment, "
                "container tampering, AIS/manifest manipulation, customs bypass, inspection avoidance, export-control evasion, sanctions evasion, or dual-use diversion. "
                "Local deterministic analysis is limited to hashing, safe JSON/CSV/TXT trade record parsing, entity/role resolution, commodity/HS context, "
                "shipment verification, value/quantity consistency checks, route/transshipment analysis, document correlation, sanctions/export-control context checking, "
                "trade anomaly flagging (defensive only), benign explanation testing, contradiction detection, competing hypotheses, falsification, secret redaction, "
                "prompt-injection flagging, and defensive specialist handoff planning. Live Customs DB/Licensed Provider enrichment, regulatory reporting, and consequential "
                "legal actions remain planning-only unless configured/authorized/human-reviewed."
            ),
            "policy_screen": policy,
            "warnings": warnings,
            "payload": payload,
            "intelligence_questions": questions,
            "evidence_inventory": files,
            "shipments_preview": parsed.get("shipments", [])[:300],
            "entities_preview": parsed.get("entities", [])[:300],
            "trade_relations_preview": parsed.get("trade_relations", [])[:300],
            "contradictions": parsed.get("contradictions", [])[:1000],
            "hypotheses": parsed.get("hypotheses", [])[:1000],
            "knowledge_gaps": parsed.get("knowledge_gaps", [])[:500],
            "specialist_handoffs": parsed.get("specialist_handoffs", [])[:500],
            "next_best_action": next_action,
            "tradeint_collection_plan": collection_plan,
            **self._policy_sections(),
            **self._schemas(),
        }

        self.last_result = result
        self._write_output(result)
        self.notebook.select(self.output_tab)

        if warnings:
            messagebox.showwarning(
                "Validation Warnings",
                "TRADEINT plan generated with warnings:\n\n" + "\n".join(warnings),
            )

    def _build_local_analysis_report(
        self,
        files: List[Dict[str, Any]],
        parsed: Dict[str, Any],
        payload: Dict[str, Any],
        policy: Dict[str, Any],
    ) -> Dict[str, Any]:
        next_action = build_next_best_action(payload, policy, files, parsed)
        collection_plan = build_collection_plan(payload, default_questions(payload), files, parsed)

        observations: List[Dict[str, Any]] = []

        for f in files:
            observations.append({
                "observation_id": f"OBS-{uuid.uuid4()}",
                "statement": f"A local lawful/authorized TRADEINT evidence file was accessed and hashed: {f.get('filename')}.",
                "evidence_id": f.get("evidence_id"),
                "source_id": f.get("source_id"),
                "observed_at": now_utc(),
                "extraction_method": "local_deterministic_file_hash",
                "limitations": "File hash does not prove legality or intent.",
            })

        observations.extend([
            {
                "observation_id": f"OBS-{uuid.uuid4()}",
                "statement": f"{len(files)} TRADEINT evidence file(s) were parsed locally.",
                "evidence_id": "AGGREGATE",
                "source_id": "LOCAL_PARSER",
                "observed_at": now_utc(),
                "extraction_method": "safe_json_csv_text_trade_parser",
                "limitations": "Parser output is normalized evidence, not verified external reality.",
            },
            {
                "observation_id": f"OBS-{uuid.uuid4()}",
                "statement": f"{len(parsed.get('shipments', []))} shipment record(s) and {len(parsed.get('trade_relations', []))} relationship(s) were extracted.",
                "evidence_id": "AGGREGATE",
                "source_id": "LOCAL_SHIPMENT_PARSER",
                "observed_at": now_utc(),
                "extraction_method": "shipment_relation_extraction",
                "limitations": "Record existence != Illegal Intent.",
            },
            {
                "observation_id": f"OBS-{uuid.uuid4()}",
                "statement": "No smuggling route design, customs evasion advice, sanctions evasion planning, or export-control bypass methods were performed.",
                "evidence_id": "LOCAL_PANEL_POLICY",
                "source_id": "LOCAL_POLICY_GUARD",
                "observed_at": now_utc(),
                "extraction_method": "lawful_analytical_policy",
                "limitations": "Planning/local deterministic panel only.",
            },
        ])

        observations, _ = truncate_list(observations, 500)

        candidate_facts: List[Dict[str, Any]] = []

        for f in files:
            if f.get("sha256"):
                candidate_facts.append({
                    "candidate_fact": f"The preserved local TRADEINT evidence artifact {f.get('filename')} has SHA256 {f.get('sha256')}.",
                    "status": "SUPPORTED",
                    "evidence_ids": [f.get("evidence_id")],
                    "notes": "Supported by deterministic local hashing. Does not prove legality.",
                })

        candidate_facts.extend([
            {
                "candidate_fact": f"{len(parsed.get('shipments', []))} shipment candidate(s) were extracted.",
                "status": "SUPPORTED_AS_CANDIDATE_ONLY",
                "evidence_ids": ["AGGREGATE"],
                "not_supported": [
                    "verified legality",
                    "verified intent",
                    "verified ultimate beneficiary",
                    "verified end user",
                ],
            },
            {
                "candidate_fact": "No smuggling route design, customs evasion advice, sanctions evasion planning, or export-control bypass methods were performed.",
                "status": "SUPPORTED",
                "evidence_ids": ["LOCAL_PANEL_POLICY"],
                "notes": "Lawful/analytical planning boundary.",
            },
        ])

        candidate_facts, _ = truncate_list(candidate_facts, 200)

        fact_gate = {
            "status": "LOCAL_DETERMINISTIC_ONLY" if files or parsed.get("shipments") else "NO_LOCAL_TRADEINT_EVIDENCE",
            "supported": [
                "file/source existence and SHA256 hash",
                "parsed shipment records",
                "parsed entity candidates",
                "parsed trade relationships",
                "parsed HS code candidates",
                "parsed value/quantity metadata",
                "contradiction candidates",
                "competing hypotheses",
                "secret redaction flags",
                "prompt-injection flags",
            ],
            "not_supported": [
                "verified legality",
                "verified intent",
                "verified ultimate beneficiary",
                "verified end user",
                "verified manufacturer",
                "final legal determination",
                "autonomous customs complaint",
                "autonomous shipment freeze",
            ],
            "safety_status": "No smuggling route design, customs evasion advice, sanctions evasion planning, or export-control bypass methods performed.",
        }

        return {
            "mode": "LOCAL_DETERMINISTIC_TRADEINT_ANALYSIS",
            "panel_version": APP_VERSION,
            "policy_screen": policy,
            "smuggling_design_performed": False,
            "evasion_advice_performed": False,
            "falsification_performed": False,
            "illicit_facilitation_performed": False,
            "evidence_inventory": files,
            "shipments_preview": parsed.get("shipments", [])[:300],
            "entities_preview": parsed.get("entities", [])[:300],
            "trade_relations_preview": parsed.get("trade_relations", [])[:300],
            "contradictions": parsed.get("contradictions", [])[:1000],
            "hypotheses": parsed.get("hypotheses", [])[:1000],
            "knowledge_gaps": parsed.get("knowledge_gaps", [])[:500],
            "specialist_handoffs": parsed.get("specialist_handoffs", [])[:500],
            "observations": observations,
            "candidate_facts": candidate_facts,
            "fact_gate": fact_gate,
            "recommended_next_actions": next_action,
            "tradeint_collection_plan_preview": collection_plan[:20],
            "limitations": [
                "Only local deterministic checks were performed.",
                "No network access was performed.",
                "No smuggling route design, customs evasion advice, sanctions evasion planning, or export-control bypass methods were performed.",
                "Shipper is not Manufacturer.",
                "Consignee is not End User.",
                "Buyer is not Consignee.",
                "Forwarder is not Economic Owner.",
                "Carrier is not Cargo Owner.",
                "Shipping Country is not Country of Origin.",
                "Transit Country is not Final Destination.",
                "HS Code is not Exact Product Identity.",
                "Invoice is not Shipment.",
                "Shipment is not Payment.",
                "Contract is not Delivery.",
                "Scheduled Arrival is not Actual Arrival.",
                "Unusual Route is not Evasion.",
                "Trade Anomaly is not Illegal Trade.",
                "Dual-Use Item is not Prohibited Trade.",
                "Exposed secrets were redacted heuristically and not used.",
                "Trade documents were treated as untrusted evidence.",
            ],
        }

    def _write_output(self, result: Dict[str, Any]) -> None:
        self.output.delete("1.0", "end")
        self.output.insert("1.0", json.dumps(result, ensure_ascii=False, indent=2, default=str))

    def _policy_sections(self) -> Dict[str, Any]:
        return {
            "role": {
                "employee": "TRADEINT AI Employee",
                "hierarchy": [
                    "Chief Intelligence Manager",
                    "Economic / Commercial Intelligence Manager",
                    "Trade Intelligence Manager",
                    "TRADEINT AI Employee",
                ],
                "not": [
                    "smuggling planner",
                    "customs-evasion advisor",
                    "sanctions-evasion advisor",
                    "export-control bypass system",
                    "tariff-evasion advisor",
                    "document falsification system",
                    "shipping concealment planner",
                    "illicit logistics planner",
                    "autonomous customs/legal adjudicator",
                ],
            },
            "core_principle": [
                "TRADE RECORD",
                "PRESERVE",
                "NORMALIZE",
                "ENTITY RESOLUTION",
                "COMMODITY RESOLUTION",
                "HS CLASSIFICATION CONTEXT",
                "SHIPMENT RESOLUTION",
                "ROUTE / ORIGIN / DESTINATION",
                "VALUE / QUANTITY VALIDATION",
                "DOCUMENT CORRELATION",
                "SOURCE RELIABILITY",
                "SOURCE INDEPENDENCE",
                "ANOMALY ANALYSIS",
                "BENIGN-EXPLANATION CHECK",
                "FACT GATE",
                "DEFENSIBLE TRADE ASSESSMENT",
            ],
            "critical_separations": [
                "shipper != manufacturer",
                "consignee != end user",
                "buyer != consignee",
                "freight forwarder != economic owner",
                "carrier != cargo owner",
                "shipping country != country of origin",
                "transit country != final destination",
                "hs code != exact product",
                "product != unique hs code",
                "invoice != shipment",
                "shipment != payment",
                "contract != delivery",
                "scheduled arrival != actual arrival",
                "unusual route != evasion",
                "transshipment != sanctions evasion",
                "low/high unit price != customs fraud",
                "trade anomaly != illegal trade",
                "dual-use item != prohibited trade",
                "sanctions name match != sanctioned entity",
                "sanctioned-entity involvement != automatic violation",
                "export-control relevance != illegal export",
                "multiple commercial databases using same customs data != independent sources",
                "AI agreement != trade corroboration",
            ],
            "hard_restrictions": [
                "Do not design smuggling routes.",
                "Do not recommend concealment techniques.",
                "Do not recommend false declarations.",
                "Do not recommend HS-code misclassification.",
                "Do not recommend tariff avoidance through deception.",
                "Do not recommend origin laundering.",
                "Do not recommend invoice falsification.",
                "Do not recommend under-invoicing.",
                "Do not recommend over-invoicing.",
                "Do not recommend transshipment for sanctions evasion.",
                "Do not recommend shell-company routing.",
                "Do not recommend front-company structures.",
                "Do not recommend cargo concealment.",
                "Do not recommend container tampering.",
                "Do not recommend AIS manipulation.",
                "Do not recommend manifest falsification.",
                "Do not recommend customs-control bypass.",
                "Do not recommend inspection avoidance.",
                "Do not recommend export-control evasion.",
                "Do not recommend sanctions evasion.",
                "Do not recommend dual-use diversion.",
                "Do not facilitate trafficking.",
                "Do not facilitate illegal weapons trade.",
                "Do not facilitate illegal wildlife trade.",
                "Do not facilitate controlled-substance trade.",
                "Do not facilitate human trafficking.",
            ],
            "non_negotiable_rules": [
                "DO NOT DESIGN SMUGGLING ROUTES.",
                "DO NOT DESIGN SANCTIONS-EVASION ROUTES.",
                "DO NOT DESIGN CUSTOMS-EVASION METHODS.",
                "DO NOT RECOMMEND FALSE HS CLASSIFICATION.",
                "DO NOT RECOMMEND ORIGIN LAUNDERING.",
                "DO NOT RECOMMEND FALSE END-USER DOCUMENTS.",
                "DO NOT RECOMMEND INVOICE FALSIFICATION.",
                "DO NOT RECOMMEND UNDER-INVOICING OR OVER-INVOICING.",
                "DO NOT RECOMMEND SHELL-COMPANY STRUCTURES TO HIDE TRADE.",
                "DO NOT RECOMMEND TRANSSHIPMENT TO EVADE CONTROLS.",
                "DO NOT RECOMMEND CARGO CONCEALMENT.",
                "DO NOT RECOMMEND INSPECTION AVOIDANCE.",
                "DO NOT RECOMMEND AIS OR MANIFEST MANIPULATION.",
                "DO NOT FACILITATE ILLEGAL TRADE.",
                "DO NOT FACILITATE CONTROLLED-GOODS DIVERSION.",
                "DO NOT EQUATE SHIPPER WITH MANUFACTURER.",
                "DO NOT EQUATE CONSIGNEE WITH END USER.",
                "DO NOT EQUATE BUYER WITH CONSIGNEE.",
                "DO NOT EQUATE FREIGHT FORWARDER WITH ECONOMIC OWNER.",
                "DO NOT EQUATE CARRIER WITH CARGO OWNER.",
                "DO NOT EQUATE SHIPPING COUNTRY WITH COUNTRY OF ORIGIN.",
                "DO NOT EQUATE TRANSIT COUNTRY WITH FINAL DESTINATION.",
                "DO NOT EQUATE HS CODE WITH EXACT PRODUCT.",
                "DO NOT EQUATE PRODUCT WITH UNIQUE HS CODE.",
                "DO NOT EQUATE INVOICE WITH SHIPMENT.",
                "DO NOT EQUATE SHIPMENT WITH PAYMENT.",
                "DO NOT EQUATE CONTRACT WITH DELIVERY.",
                "DO NOT EQUATE SCHEDULED ARRIVAL WITH ACTUAL ARRIVAL.",
                "DO NOT EQUATE UNUSUAL ROUTE WITH EVASION.",
                "DO NOT EQUATE TRANSSHIPMENT WITH SANCTIONS EVASION.",
                "DO NOT EQUATE LOW/HIGH UNIT PRICE WITH CUSTOMS FRAUD.",
                "DO NOT EQUATE TRADE ANOMALY WITH ILLEGAL TRADE.",
                "DO NOT EQUATE DUAL-USE ITEM WITH PROHIBITED TRADE.",
                "DO NOT EQUATE SANCTIONS NAME MATCH WITH SANCTIONED ENTITY.",
                "DO NOT EQUATE SANCTIONED-ENTITY INVOLVEMENT WITH AUTOMATIC VIOLATION.",
                "DO NOT EQUATE EXPORT-CONTROL RELEVANCE WITH ILLEGAL EXPORT.",
                "DO NOT EQUATE MULTIPLE COMMERCIAL DATABASES USING SAME CUSTOMS DATA WITH INDEPENDENT SOURCES.",
                "DO NOT EQUATE AI AGREEMENT WITH TRADE CORROBORATION.",
                "DO NOT HIDE DATASET COVERAGE LIMITATIONS.",
                "DO NOT HIDE HOUSE/MASTER BOL DIFFERENCES.",
                "DO NOT HIDE INCOTERM DIFFERENCES.",
                "DO NOT HIDE HS VERSION DIFFERENCES.",
                "DO NOT HIDE ENTITY-ROLE UNCERTAINTY.",
                "DO NOT HIDE BENIGN EXPLANATIONS.",
                "DO NOT INVENT SHIPMENTS.",
                "DO NOT INVENT MANUFACTURERS.",
                "DO NOT INVENT END USERS.",
                "DO NOT INVENT ORIGINS.",
                "DO NOT INVENT ROUTES.",
                "DO NOT INVENT VALUES.",
                "DO NOT INVENT SANCTIONS VIOLATIONS.",
                "DO NOT INVENT CUSTOMS FRAUD.",
                "DO NOT LOSE HISTORICAL TRADE RELATIONSHIPS.",
            ],
        }

    def _schemas(self) -> Dict[str, Any]:
        return {
            "trade_evidence_schema": {
                "evidence_id": "Unique TRADEINT evidence identifier",
                "case_id": "Case identifier",
                "source_id": "Source identifier",
                "source_type": "Customs / BOL / Invoice / etc.",
                "document_id": "Document reference",
                "shipment_reference": "Shipment ID",
                "record_reference": "Record ID",
                "bill_of_lading_reference": "BOL Number",
                "invoice_reference": "Invoice Number",
                "observed_at": "Observation time",
                "shipment_date": "Shipment Date",
                "declaration_date": "Declaration Date",
                "arrival_date": "Arrival Date",
                "departure_date": "Departure Date",
                "retrieved_at": "Retrieval time",
                "content_hash": "SHA256",
                "raw_artifact_reference": "Secure path",
                "parser_version": "Version",
                "normalizer_version": "Version",
                "authorization_context": "Auth Basis",
            },
            "shipment_schema": {
                "shipment_id": "Unique Shipment ID",
                "shipper_entity_id": "Shipper",
                "consignee_entity_id": "Consignee",
                "buyer_entity_id": "Buyer",
                "seller_entity_id": "Seller",
                "commodity_description": "Text Desc",
                "commodity_class": "Category",
                "hs_code_declared": "Code",
                "quantity": "Qty",
                "unit": "UOM",
                "weight_kg": "Weight",
                "declared_value": "Value",
                "currency": "CCY",
                "unit_value_calculated": "Calc Val",
                "origin_country": "Origin",
                "destination_country": "Dest",
                "port_of_loading": "Port Load",
                "port_of_discharge": "Port Disc",
                "carrier": "Carrier",
                "freight_forwarder": "FF",
                "incoterm": "Terms",
                "departure_date": "Dep Date",
                "arrival_date": "Arr Date",
                "bill_of_lading_ref": "BOL Ref",
                "invoice_ref": "Inv Ref",
                "source_id": "Src ID",
                "evidence_id": "Evd ID",
                "context": "Ctx",
                "state": "SHIPMENT_OBSERVED",
                "limitations": [
                    "Record exists. Legality/Intent not determined.",
                    "Shipper may not be Manufacturer.",
                    "Consignee may not be End User.",
                ],
            },
            "tradeint_result_schema": [
                "case_id",
                "task_id",
                "objective",
                "questions",
                "source_ids",
                "evidence_ids",
                "companies",
                "manufacturers",
                "suppliers",
                "buyers",
                "sellers",
                "shippers",
                "consignees",
                "notify_parties",
                "freight_forwarders",
                "carriers",
                "customs_brokers",
                "ports",
                "countries",
                "products",
                "commodities",
                "hs_codes",
                "hs_mapping_states",
                "shipments",
                "containers",
                "bills_of_lading",
                "invoices",
                "packing_lists",
                "certificates_of_origin",
                "customs_declarations",
                "quantities",
                "units",
                "weights",
                "declared_values",
                "currencies",
                "unit_values",
                "incoterms",
                "origins",
                "export_countries",
                "destinations",
                "routes",
                "transshipment_context",
                "shipment_status",
                "shipment_frequency",
                "supplier_dependency",
                "buyer_concentration",
                "trade_trends",
                "seasonality",
                "invoice_shipment_matches",
                "procurement_context",
                "trade_finance_context",
                "ownership_context",
                "sanctions_context",
                "export_control_context",
                "dual_use_context",
                "customs_risk_signals",
                "trade_anomalies",
                "document_mismatches",
                "fraud_indicators",
                "timeline_updates",
                "observations",
                "candidate_facts",
                "supported_facts",
                "partial_facts",
                "disputed_facts",
                "source_reliability",
                "source_bias",
                "source_limitations",
                "source_pedigree",
                "source_independence",
                "contradictions",
                "hypotheses",
                "falsification_results",
                "privacy_flags",
                "legal_flags",
                "unknowns",
                "knowledge_gaps",
                "recommended_next_actions",
                "specialist_handoffs",
                "limitations",
                "status",
            ],
        }

    def export_json(self) -> None:
        if not self.last_result:
            self.generate_plan()

        data = self.last_result or self.collect_payload()

        payload_for_name = data.get("payload") or data.get("payload_preview") or data
        case_id = payload_for_name.get("case_id", "tradeint")
        task_id = payload_for_name.get("task_id", "task")

        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=f"{case_id}_{task_id}.json",
        )

        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
            messagebox.showinfo("Export Complete", f"TRADEINT JSON saved to:\n{path}")
        except Exception as exc:
            messagebox.showerror("Export Failed", str(exc))

    def copy_output(self) -> None:
        text = self.output.get("1.0", "end-1c").strip()
        if not text:
            messagebox.showinfo("Copy Output", "No output to copy.")
            return

        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Copy Output", "Output copied to clipboard.")

    def clear_form(self) -> None:
        confirm = messagebox.askyesno(
            "Clear Form",
            "Are you sure you want to clear all fields, analyzed TRADEINT evidence, and reset defaults?",
        )
        if not confirm:
            return

        self._set_defaults()
        self.output.delete("1.0", "end")
        self.last_result = {}
        self.analyzed_files = []
        self.parsed = empty_parsed()


if __name__ == "__main__":
    app = TraceAtlasTRADEINTPanel()
    app.mainloop()
