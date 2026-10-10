import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import json
import re
import csv
import hashlib
import uuid
import unicodedata

from collections import defaultdict, Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


APP_TITLE = "TraceAtlas SANCTIONSINT AI Employee — Evidence-First / Authorized / Public-List Screening Panel"
APP_VERSION = "TraceAtlas SANCTIONSINT Panel v0.1"


FIELDS = [
    ("case_id", "Case ID", "entry"),
    ("task_id", "Task ID", "entry"),
    ("objective", "Objective", "text"),
    ("subject_name", "Subject Name (Person/Org/Vessel/Aircraft)", "entry"),
    ("subject_type", "Subject Type", "combo"),
    ("subject_aliases", "Subject Aliases / AKAs / Trade Names", "text"),
    ("subject_dob", "Subject Date of Birth (YYYY-MM-DD or YYYY)", "entry"),
    ("subject_nationality", "Subject Nationality / Citizenship", "entry"),
    ("subject_registration_no", "Subject Registration Number / LEI / IMO / Tail No", "entry"),
    ("subject_address", "Subject Address / Location", "text"),
    ("subject_organization_affiliation", "Subject Organization Affiliations", "text"),
    ("subject_identifiers", "Other Identifiers (Passport/Tax/Crypto Addr etc.)", "text"),
    
    ("lists_to_check", "Lists to Check (IDs or 'ALL_CONFIGURED')", "text"),
    ("jurisdiction_scope", "Jurisdiction Scope for Legal Interpretation", "entry"),
    
    ("sanctions_list_paths", "Sanctions List Data Paths (JSON/CSV)", "text"),
    ("watch_list_paths", "Watch/Denied Party List Paths", "text"),
    ("export_control_paths", "Export Control / Denied Party Paths", "text"),
    ("debarment_paths", "Debarment / Regulatory List Paths", "text"),
    
    ("time_range", "Time Range for Historical Checks", "text"),
    ("scope", "Scope / Allowed Sources", "text"),
    ("authorization", "Authorization Basis", "text"),
    ("configured_connectors", "Configured Connectors (Official APIs/Licenses)", "text"),
]


SUBJECT_TYPES = [
    "person",
    "organization",
    "vessel",
    "aircraft",
    "crypto_wallet",
    "domain",
    "other",
    "unknown",
]


LIST_FIELDS = {
    "subject_aliases",
    "subject_identifiers",
    "lists_to_check",
    "sanctions_list_paths",
    "watch_list_paths",
    "export_control_paths",
    "debarment_paths",
    "configured_connectors",
}


DICT_FIELDS = {
    "scope",
    "authorization",
    "time_range",
}


NEGATION_RE = re.compile(
    r"\b(?:do not|don't|dont|must not|shall not|should not|avoid|without|never|not to|prohibit|policy blocked|safe alternative|defensive only)\b",
    re.I,
)


POLICY_BLOCK_PATTERNS = [
    r"\b(?:freeze|block|reject|terminate|close|deny)\b[^\n]{0,140}\b(?:account|transaction|customer|employment|service|business)\b",
    r"\b(?:file|submit|report)\b[^\n]{0,140}\b(?:legal|regulatory|police|court|authority)\b[^\n]{0,80}\b(?:autonomously|automatically|without review)\b",
    r"\b(?:contact|message|notify)\b[^\n]{0,140}\b(?:subject|target|individual|company)\b[^\n]{0,80}\b(?:directly|secretly|without authorization)\b",
    r"\b(?:evade|circumvent|bypass)\b[^\n]{0,140}\b(?:sanctions|embargo|restriction|control|compliance)\b",
    r"\b(?:conceal|hide|mask)\b[^\n]{0,140}\b(?:beneficial ownership|identity|asset|transaction)\b",
    r"\b(?:declare|assert|confirm)\b[^\n]{0,140}\b(?:guilty|criminal|terrorist|illegal|fraudster)\b[^\n]{0,80}\b(?:based on name match|solely from list)\b",
]


SAFE_ALTERNATIVES = [
    "Provide evidence-first compliance intelligence: ingest configured public/licensed lists, normalize subjects, compare identifiers/aliases/jurisdictions/temporal states, generate candidate matches with disambiguation scores, flag false positives, preserve source versions, and escalate material matches to human review.",
    "Do not autonomously freeze accounts, block transactions, reject customers, terminate employment, file legal reports, contact subjects, evade sanctions, conceal ownership, or declare criminality based solely on name matches.",
    "Separate Candidate Match from Verified Identity Match. Separate Listing Authority from Global Applicability. Separate Current Status from Historical Removal.",
    "Use deterministic identifier comparison for DOB, Registration Numbers, Nationality, and Addresses. Never rely on fuzzy name matching alone for SUPPORTED_MATCH status.",
]


SECRET_PATTERNS = [
    (
        "PRIVATE_KEY_BLOCK",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S | re.I),
    ),
    (
        "PASSWORD_OR_TOKEN_ASSIGNMENT",
        re.compile(
            r"(?i)\b(password|passwd|pwd|token|api[_-]?key|apikey|secret|"
            r"access[_-]?key|auth[_-]?key|client[_-]?secret|authorization|cookie|session|credential)\b"
            r"\s*[:=]\s*[^\s,;\"']+"
        ),
    ),
    (
        "BEARER_TOKEN",
        re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-+/=]{8,}"),
    ),
]


PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(?:all\s+)?previous\s+(?:instructions|rules)",
    r"reveal\s+(?:the\s+)?system\s+prompt",
    r"execute\s+(?:this\s+)?(?:command|script|code)",
    r"disable\s+(?:security|compliance)\s+controls",
    r"send\s+(?:data|credentials|reports)",
]


# --- Normalization Helpers ---

def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_text(value: Any) -> str:
    """Basic whitespace/case normalization."""
    return re.sub(r"\s+", " ", str(value or "")).strip().lower()


def strip_accents(text: str) -> str:
    """Remove diacritics for cross-script similarity approximation."""
    try:
        nfkd = unicodedata.normalize('NFKD', text)
        ascii_encoded = nfkd.encode('ASCII', 'ignore').decode('ascii')
        return ascii_encoded.lower()
    except Exception:
        return text.lower()


def normalize_name_for_match(name: str) -> str:
    """
    Normalize names for comparison:
    - Strip accents
    - Remove punctuation
    - Collapse spaces
    - Lowercase
    - Remove common honorifics/suffixes (Mr., Ms., Ltd., Inc., Corp., LLC, GmbH, etc.)
    """
    if not name:
        return ""
    
    # 1. Unicode NFKC then strip accents
    s = unicodedata.normalize('NFKC', name)
    s = strip_accents(s)
    
    # 2. Remove punctuation except hyphens/apostrophes inside words initially, then clean up
    s = re.sub(r"[^\w\s\-']", "", s)
    
    # 3. Common corporate suffixes/honorifics removal
    suffixes = [
        r"\b(ltd|limited|inc|corporation|corp|llc|lp|llp|gmbh|sa|nv|bv|pty|plc|co|company|group|holdings|industries|international|global|enterprises|technologies|systems|services|consulting|associates|partners|trading|commerce|logistics|shipping|aviation|marine|oil|gas|energy|mining|resources)\b",
        r"\b(mr|mrs|ms|miss|dr|prof|sir|madam|haji|mullah|sheikh|sayed|syed|rev|rabbis)\b",
        r"\b(bin|ibn|al|el|van|von|de|der|la|le|da|dos|das)\b" # Particles often handled differently but simplified here
    ]
    for suf in suffixes:
        s = re.sub(suf, "", s, flags=re.IGNORECASE)
        
    # 4. Clean up remaining extra spaces
    s = re.sub(r"\s+", " ", s).strip()
    
    return s


def parse_date_flexible(date_str: str) -> Optional[str]:
    """Attempt to parse various date formats to ISO YYYY-MM-DD or just Year."""
    if not date_str:
        return None
    s = str(date_str).strip()
    
    # Try standard ISO
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d")
    except ValueError:
        pass
        
    # Try DD/MM/YYYY or MM/DD/YYYY heuristics (ambiguous, prefer strict input in production)
    # For this demo, we'll just try simple splits if it looks like a date
    parts = re.split(r"[/\-.]", s)
    if len(parts) == 3:
        try:
            y, m, d = int(parts[-1]), int(parts[1]), int(parts[0])
            if 1 <= m <= 12 and 1 <= d <= 31:
                return f"{y:04d}-{m:02d}-{d:02d}"
        except ValueError:
            pass
            
    # If only year provided
    if len(parts) == 1 and len(s) == 4 and s.isdigit():
        return s
        
    return None


def sha256_text(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="replace")).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


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


def get_field(rec: Dict[str, Any], keys: List[str], default: Any = None) -> Any:
    if not isinstance(rec, dict):
        return default
    lower = {normalize_key(k): v for k, v in rec.items()}
    for key in keys:
        nk = normalize_key(key)
        if nk in lower and lower[nk] not in (None, ""):
            return lower[nk]
    return default


def normalize_key(value: Any) -> str:
    s = str(value or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "_", s)
    return s.strip("_")


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


# --- Core Logic Structures ---

class SanctionsRecord:
    def __init__(self, raw_data: Dict[str, Any], source_meta: Dict[str, Any]):
        self.raw = raw_data
        self.source_meta = source_meta
        self.record_id = f"SAN-{uuid.uuid4()}"
        
        # Extract fields based on common schemas (OFAC/UN/EU style)
        self.names = self._extract_names()
        self.normalized_names = [normalize_name_for_match(n) for n in self.names if n]
        self.aliases = self._extract_aliases()
        self.identifiers = self._extract_identifiers()
        self.dob = self._extract_dob()
        self.nationality = self._extract_nationality()
        self.addresses = self._extract_addresses()
        self.listing_authority = source_meta.get("authority", "UNKNOWN")
        self.jurisdiction = source_meta.get("jurisdiction", "GLOBAL")
        self.program = source_meta.get("program", "GENERAL")
        self.list_name = source_meta.get("list_name", "UNKNOWN")
        self.status = source_meta.get("status", "ACTIVE") # ACTIVE, REMOVED, AMENDED
        self.effective_from = source_meta.get("effective_from", "")
        self.retrieved_at = source_meta.get("retrieved_at", now_utc())
        
    def _extract_names(self) -> List[str]:
        # Look for primary name fields
        vals = []
        for k in ["name", "entity_name", "legal_name", "full_name", "first_name_last_name"]:
            v = get_field(self.raw, [k])
            if v:
                if isinstance(v, list):
                    vals.extend([str(x) for x in v])
                else:
                    vals.append(str(v))
        return unique_preserve_order(vals)

    def _extract_aliases(self) -> List[str]:
        vals = []
        for k in ["aka", "also_known_as", "alias", "trade_name", "former_name", "secondary_name"]:
            v = get_field(self.raw, [k])
            if v:
                if isinstance(v, list):
                    vals.extend([str(x) for x in v])
                elif isinstance(v, dict):
                     # Some schemas have {'name': '...', 'type': '...'}
                     if 'name' in v: vals.append(str(v['name']))
                else:
                    vals.append(str(v))
        return unique_preserve_order(vals)

    def _extract_identifiers(self) -> Dict[str, str]:
        ids = {}
        mapping = {
            "passport": ["passport_number", "id_passport", "travel_doc"],
            "registration": ["registration_number", "company_reg", "lei", "imo", "tail_number", "tax_id"],
            "dob_alt": ["date_of_birth", "birth_date", "dob"],
            "nationality_alt": ["citizenship", "nationality_country"]
        }
        for id_type, keys in mapping.items():
            val = get_field(self.raw, keys)
            if val:
                ids[id_type] = str(val).strip()
        return ids

    def _extract_dob(self) -> Optional[str]:
        dob_raw = get_field(self.raw, ["date_of_birth", "birth_date", "dob"])
        if dob_raw:
            return parse_date_flexible(str(dob_raw))
        # Check identifiers
        if "dob_alt" in self.identifiers:
             return parse_date_flexible(self.identifiers["dob_alt"])
        return None

    def _extract_nationality(self) -> Optional[str]:
        nat = get_field(self.raw, ["nationality", "citizenship", "country"])
        if nat:
            return normalize_text(nat)
        if "nationality_alt" in self.identifiers:
            return normalize_text(self.identifiers["nationality_alt"])
        return None

    def _extract_addresses(self) -> List[str]:
        vals = []
        for k in ["address", "location", "city", "country", "registered_office"]:
            v = get_field(self.raw, [k])
            if v:
                vals.append(str(v))
        return unique_preserve_order(vals)


class SubjectProfile:
    def __init__(self, payload: Dict[str, Any]):
        self.payload = payload
        self.name = payload.get("subject_name", "")
        self.type = payload.get("subject_type", "unknown")
        self.aliases = payload.get("subject_aliases", [])
        self.dob = payload.get("subject_dob", "")
        self.nationality = payload.get("subject_nationality", "")
        self.registration_no = payload.get("subject_registration_no", "")
        self.address = payload.get("subject_address", "")
        self.other_ids = payload.get("subject_identifiers", [])
        
        self.norm_name = normalize_name_for_match(self.name)
        self.norm_aliases = [normalize_name_for_match(a) for a in self.aliases if a]
        self.parsed_dob = parse_date_flexible(self.dob)
        self.norm_nat = normalize_text(self.nationality)
        self.norm_reg = normalize_text(self.registration_no)
        self.norm_addr = normalize_text(self.address)


# --- Matching Engine ---

def calculate_similarity_score(subject: SubjectProfile, record: SanctionsRecord) -> Dict[str, Any]:
    """
    Returns detailed dimension scores and overall assessment.
    Dimensions: NAME, ALIAS, DOB, NAT, REG, ADDR, CONFLICTS
    """
    dims = {
        "NAME_MATCH": 0.0,
        "ALIAS_MATCH": 0.0,
        "DOB_MATCH": 0.0,
        "NATIONALITY_MATCH": 0.0,
        "REGISTRATION_MATCH": 0.0,
        "ADDRESS_SIMILARITY": 0.0,
        "CONFLICT_SCORE": 0.0, # Higher is worse/conflicting
        "TOTAL_EVIDENCE_WEIGHT": 0.0
    }
    
    reasons = []
    conflicts = []
    
    # 1. Name Matching
    subj_norms = [subject.norm_name] + subject.norm_aliases
    rec_norms = record.normalized_names
    
    exact_name_hit = False
    partial_name_hit = False
    
    for sn in subj_norms:
        if not sn: continue
        for rn in rec_norms:
            if not rn: continue
            if sn == rn:
                exact_name_hit = True
                break
            elif sn in rn or rn in sn:
                partial_name_hit = True
                
    if exact_name_hit:
        dims["NAME_MATCH"] = 1.0
        reasons.append("Exact normalized name match.")
    elif partial_name_hit:
        dims["NAME_MATCH"] = 0.6
        reasons.append("Partial/Substring name match.")
    else:
        # Simple Levenshtein-like check for near misses (optional, keeping simple for stdlib speed)
        # For now, if no hit, score 0
        pass

    # 2. Alias Matching (already covered in subj_norms loop above effectively, 
    # but let's separate if record has specific alias field hits)
    if not exact_name_hit:
        for sa in subject.norm_aliases:
            for ra in record.aliases:
                if normalize_name_for_match(ra) == sa:
                    dims["ALIAS_MATCH"] = 0.8
                    reasons.append(f"Alias match: {ra}")
                    break

    # 3. DOB Matching
    if subject.parsed_dob and record.dob:
        if subject.parsed_dob == record.dob:
            dims["DOB_MATCH"] = 1.0
            reasons.append("Date of Birth matches exactly.")
        else:
            # Conflict
            dims["CONFLICT_SCORE"] += 0.5
            conflicts.append(f"DOB Mismatch: Subj={subject.parsed_dob}, Rec={record.dob}")
    elif subject.parsed_dob or record.dob:
        # One missing, neutral but lowers confidence
        pass 

    # 4. Nationality Matching
    if subject.norm_nat and record.nationality:
        if subject.norm_nat == record.nationality:
            dims["NATIONALITY_MATCH"] = 0.8
            reasons.append("Nationality matches.")
        else:
            dims["CONFLICT_SCORE"] += 0.4
            conflicts.append(f"Nationality Mismatch: Subj={subject.norm_nat}, Rec={record.nationality}")

    # 5. Registration Number Matching
    if subject.norm_reg:
        # Check against record identifiers
        reg_found = False
        for id_val in record.identifiers.values():
            if normalize_text(id_val) == subject.norm_reg:
                reg_found = True
                break
        
        if reg_found:
            dims["REGISTRATION_MATCH"] = 1.0
            reasons.append("Unique Registration Identifier matches.")
        else:
            # Potential conflict if record has a different reg number format/type
            if record.identifiers.get("registration"):
                 dims["CONFLICT_SCORE"] += 0.6
                 conflicts.append("Registration Number does not match record.")

    # 6. Address Similarity (Simple keyword overlap)
    if subject.norm_addr and record.addresses:
        subj_words = set(re.findall(r'\w+', subject.norm_addr))
        best_overlap = 0
        for addr in record.addresses:
            rec_words = set(re.findall(r'\w+', normalize_text(addr)))
            intersection = subj_words & rec_words
            union = subj_words | rec_words
            if union:
                jaccard = len(intersection) / len(union)
                if jaccard > best_overlap:
                    best_overlap = jaccard
        
        if best_overlap > 0.5:
            dims["ADDRESS_SIMILARITY"] = best_overlap
            reasons.append(f"Address similarity ({best_overlap:.2f}).")
        elif best_overlap < 0.1 and subj_words:
             dims["CONFLICT_SCORE"] += 0.2
             conflicts.append("Address significantly different.")

    # Calculate Total Weight
    # Weights: Reg(1.0), DOB(0.8), Nat(0.6), Name(0.5), Alias(0.4), Addr(0.2)
    weights = {
        "REGISTRATION_MATCH": 1.0,
        "DOB_MATCH": 0.8,
        "NATIONALITY_MATCH": 0.6,
        "NAME_MATCH": 0.5,
        "ALIAS_MATCH": 0.4,
        "ADDRESS_SIMILARITY": 0.2
    }
    
    total_weight = sum(dims[k] * w for k, w in weights.items())
    
    # Penalty for conflicts
    penalty = dims["CONFLICT_SCORE"]
    
    final_score = max(0.0, total_weight - penalty)
    dims["TOTAL_EVIDENCE_WEIGHT"] = round(final_score, 2)
    
    return {
        "dimensions": dims,
        "reasons": reasons,
        "conflicts": conflicts,
        "final_score": final_score
    }


def determine_screening_status(score_result: Dict[str, Any], subject: SubjectProfile, record: SanctionsRecord) -> str:
    """
    Maps score and context to SANCTIONSINT statuses.
    """
    dims = score_result["dimensions"]
    conflicts = score_result["conflicts"]
    
    # Rule 1: Unique Identifier Match (Reg/IMO/LEI) + Name/Alias Support -> SUPPORTED_MATCH
    if dims["REGISTRATION_MATCH"] >= 0.9:
        if dims["NAME_MATCH"] > 0 or dims["ALIAS_MATCH"] > 0:
            return "SUPPORTED_MATCH"
            
    # Rule 2: Strong Multi-Factor Match (Name + DOB + Nat) -> PROBABLE_MATCH
    if dims["NAME_MATCH"] >= 0.8 and dims["DOB_MATCH"] >= 0.9 and dims["NATIONALITY_MATCH"] >= 0.7:
        if not conflicts:
            return "PROBABLE_MATCH"
            
    # Rule 3: Name Match Only -> CANDIDATE_MATCH (Never Supported)
    if dims["NAME_MATCH"] >= 0.8:
        if conflicts:
            return "LIKELY_FALSE_POSITIVE"
        return "CANDIDATE_MATCH"
        
    # Rule 4: Partial Matches / Low Confidence
    if score_result["final_score"] > 0.4:
        if conflicts:
            return "UNRESOLVED" # Needs manual look
        return "POSSIBLE_MATCH"
        
    # Rule 5: No significant match
    if score_result["final_score"] < 0.1:
        return "NO_MATCH_FOUND"
        
    return "UNRESOLVED"


# --- Source Ingestion ---

def load_sanctions_lists(paths: List[str]) -> Tuple[List[SanctionsRecord], List[Dict[str, Any]], List[str]]:
    """
    Loads JSON/CSV files into SanctionsRecords.
    Returns: records, source_metadata_list, warnings
    """
    records = []
    sources_meta = []
    warnings = []
    
    for p_str in paths:
        path = Path(p_str).expanduser()
        if not path.exists():
            warnings.append(f"File not found: {path}")
            continue
            
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            data = None
            
            # Detect Format
            stripped = content.lstrip()
            if stripped.startswith("{") or stripped.startswith("["):
                data = json.loads(content)
                fmt = "JSON"
            else:
                # Assume CSV
                lines = content.splitlines()
                if not lines: continue
                reader = csv.DictReader(lines)
                data = list(reader)
                fmt = "CSV"
                
            if not isinstance(data, list):
                if isinstance(data, dict):
                    # Might be a wrapper object {"results": [...]}
                    if "results" in data: data = data["results"]
                    elif "records" in data: data = data["records"]
                    else: data = [data]
                else:
                    warnings.append(f"Unsupported structure in {path}")
                    continue
                    
            # Infer Metadata from Filename or Content Heuristics
            fname_lower = path.name.lower()
            authority = "UNKNOWN_AUTHORITY"
            jurisdiction = "UNKNOWN_JURISDICTION"
            list_type = "GENERAL_SANCTIONS"
            
            if "ofac" in fname_lower:
                authority = "US_TREASURY_OFAC"
                jurisdiction = "USA"
                list_type = "SDN_LIST"
            elif "un_" in fname_lower or "consolidated" in fname_lower:
                authority = "UNITED_NATIONS"
                jurisdiction = "GLOBAL"
                list_type = "UN_CONSOLIDATED"
            elif "eu_" in fname_lower or "eurlex" in fname_lower:
                authority = "EU_COUNCIL"
                jurisdiction = "EUROPEAN_UNION"
                list_type = "EU_SANCTIONS"
            elif "uk_" in fname_lower or "hmt" in fname_lower or "ofsi" in fname_lower:
                authority = "UK_OFSI_HMT"
                jurisdiction = "UNITED_KINGDOM"
                list_type = "UK_SANCTIONS"
            elif "denied" in fname_lower or "bis" in fname_lower:
                authority = "US_BIS_DENIED_PARTIES"
                jurisdiction = "USA_EXPORT_CONTROL"
                list_type = "DENIED_PARTY_LIST"
                
            # Create Source Meta
            src_id = f"SRC-{uuid.uuid4()}"
            meta = {
                "source_id": src_id,
                "filename": path.name,
                "authority": authority,
                "jurisdiction": jurisdiction,
                "list_name": list_type,
                "list_type": "SANCTIONS_WATCHLIST",
                "version": "LOCAL_SNAPSHOT", # Placeholder for real versioning
                "published_at": "",
                "updated_at": datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat(),
                "retrieved_at": now_utc(),
                "hash": sha256_file(path),
                "limitations": ["Local snapshot only. Verify against live official source for critical decisions."]
            }
            sources_meta.append(meta)
            
            # Parse Records
            count = 0
            for item in data:
                if not isinstance(item, dict):
                    continue
                rec = SanctionsRecord(item, meta)
                if rec.names or rec.aliases: # Must have some identity info
                    records.append(rec)
                    count += 1
            
            if count == 0:
                warnings.append(f"No valid sanction records parsed from {path}")
                
        except Exception as e:
            warnings.append(f"Error loading {path}: {str(e)}")
            
    return records, sources_meta, warnings


# --- Policy & Validation ---

def policy_screen(payload: Dict[str, Any]) -> Dict[str, Any]:
    scanned_fields = ["objective", "subject_name", "subject_aliases", "jurisdiction_scope"]
    parts = []
    for key in scanned_fields:
        val = payload.get(key)
        if isinstance(val, list):
            parts.extend(str(x) for x in val)
        else:
            parts.append(str(val or ""))
            
    scanned = " \n ".join(parts).lower()
    
    blocked_reasons = []
    for pat in POLICY_BLOCK_PATTERNS:
        rx = re.compile(pat, re.I)
        for m in rx.finditer(scanned):
            start = max(0, m.start() - 180)
            prefix = scanned[start:m.start()]
            if NEGATION_RE.search(prefix):
                continue
            blocked_reasons.append(pat)
            break
            
    if blocked_reasons:
        return {
            "status": "POLICY_BLOCKED",
            "reasons": sorted(set(blocked_reasons)),
            "explanation": "Request implies autonomous enforcement action, evasion, or unauthorized legal determination.",
            "safe_alternatives": SAFE_ALTERNATIVES
        }
        
    return {
        "status": "ALLOWED_DEFENSIVE_AUTHORIZED",
        "reasons": [],
        "explanation": "Screening request accepted for analysis. Human review required for any consequential action."
    }


def validate_payload(payload: Dict[str, Any]) -> List[str]:
    warnings = []
    if not payload.get("subject_name"):
        warnings.append("Missing Subject Name.")
    if not payload.get("sanctions_list_paths") and not payload.get("watch_list_paths"):
        warnings.append("No sanctions list data paths provided. Cannot perform meaningful screening.")
    return warnings


# --- Main Application Class ---

class TraceAtlasSANCTIONSINTPanel(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1380x940")
        self.minsize(1100, 760)

        self.entries: Dict[str, Any] = {}
        self.last_result: Dict[str, Any] = {}
        self.loaded_records: List[SanctionsRecord] = []
        self.sources_meta: List[Dict[str, Any]] = []

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
        style.configure("Header.TLabel", background="#0b0f19", foreground="#ef4444", font=("Segoe UI", 17, "bold")) # Red accent for compliance
        style.configure("Subheader.TLabel", background="#0b0f19", foreground="#94a3b8", font=("Segoe UI", 9))
        style.configure("TNotebook", background="#0b0f19", borderwidth=0)
        style.configure("TNotebook.Tab", padding=[14, 7], font=("Segoe UI", 10, "bold"))
        style.configure("TEntry", fieldbackground="#111827", foreground="#e5e7eb", insertcolor="#ffffff", bordercolor="#334155")
        style.configure("TCombobox", fieldbackground="#111827", foreground="#e5e7eb", arrowcolor="#e5e7eb", bordercolor="#334155")
        style.configure("TButton", padding=7, font=("Segoe UI", 10, "bold"), background="#1f2937", foreground="#e5e7eb", bordercolor="#475569")
        style.map("TButton", background=[("active", "#334155")], foreground=[("active", "#ffffff")])
        style.configure("Vertical.TScrollbar", background="#1f2937", troughcolor="#0b0f19", arrowcolor="#e5e7eb")

    def _build_ui(self) -> None:
        header = ttk.Frame(self)
        header.pack(fill="x", padx=16, pady=(14, 8))
        ttk.Label(header, text="TraceAtlas SANCTIONSINT AI Employee", style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text=(
                "Evidence-First / Authorized / Public-List Screening • Planning & Analysis Only • "
                "Name Match != Identity Match • Candidate != Verified • Jurisdiction Preserved • "
                "No Autonomous Blocking/Freezing/Filing • Human Review Required for Material Matches"
            ),
            style="Subheader.TLabel",
            wraplength=1280,
            justify="left",
        ).pack(anchor="w", pady=(2, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(8, 16))

        self.input_tab = ttk.Frame(self.notebook)
        self.output_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.input_tab, text="SANCTIONSINT Input & Lists")
        self.notebook.add(self.output_tab, text="Output / Screening Report")

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
                widget = ttk.Combobox(self.form, values=SUBJECT_TYPES if key == "subject_type" else [], width=100, state="readonly")
            else:
                widget = tk.Text(self.form, height=3, width=102, bg="#111827", fg="#e5e7eb", insertbackground="white", relief="flat", highlightthickness=1, highlightbackground="#334155", font=("Segoe UI", 10), wrap="word")
            widget.grid(row=row, column=1, sticky="ew", padx=10, pady=6)
            self.entries[key] = widget
            row += 1

        self.form.columnconfigure(1, weight=1)

        buttons1 = ttk.Frame(self.input_tab)
        buttons1.pack(fill="x", padx=10, pady=(12, 4))
        buttons2 = ttk.Frame(self.input_tab)
        buttons2.pack(fill="x", padx=10, pady=(0, 12))

        ttk.Button(buttons1, text="Load Sanctions Lists", command=self.load_lists).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Watch/Export/Debarment Files", command=self.add_other_lists).pack(side="left", padx=4)

        ttk.Button(buttons2, text="Run Screening Analysis", command=self.run_screening).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Run Policy Screen", command=self.run_policy_screen).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Export JSON Report", command=self.export_json).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Copy Output", command=self.copy_output).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Clear Form", command=self.clear_form).pack(side="left", padx=4)

    def _build_output_tab(self) -> None:
        container = ttk.Frame(self.output_tab)
        container.pack(fill="both", expand=True)
        self.output = tk.Text(container, wrap="word", bg="#020617", fg="#fecaca", insertbackground="white", relief="flat", highlightthickness=1, highlightbackground="#334155", font=("Consolas", 11))
        output_scroll = ttk.Scrollbar(container, orient="vertical", command=self.output.yview)
        self.output.configure(yscrollcommand=output_scroll.set)
        self.output.pack(side="left", fill="both", expand=True)
        output_scroll.pack(side="right", fill="y")

    def _set_defaults(self) -> None:
        self.set_widget_value("case_id", "SANCTIONS-CASE-001")
        self.set_widget_value("task_id", "SCREEN-TASK-001")
        self.set_widget_value("objective", "Perform evidence-first sanctions screening against configured local/public lists.")
        self.set_widget_value("subject_name", "John Doe Example")
        self.set_widget_value("subject_type", "person")
        self.set_widget_value("jurisdiction_scope", "USA")
        self.set_widget_value("lists_to_check", "ALL_CONFIGURED")
        self.set_widget_value("time_range", json.dumps({"from": "", "to": "", "timezone": "UTC"}, indent=2))
        self.set_widget_value("scope", json.dumps({"allowed_sources": ["public_gov", "licensed_feed"], "prohibited_actions": ["auto_block"]}, indent=2))
        self.set_widget_value("authorization", json.dumps({"basis": "internal_compliance_review"}, indent=2))
        self.set_widget_value("configured_connectors", "None configured. Using local file uploads.")

    def get_widget_value(self, key: str) -> str:
        widget = self.entries.get(key)
        if widget is None: return ""
        if isinstance(widget, tk.Text): return widget.get("1.0", "end-1c").strip()
        if isinstance(widget, ttk.Combobox): return widget.get().strip()
        if isinstance(widget, ttk.Entry): return widget.get().strip()
        return ""

    def set_widget_value(self, key: str, value: str) -> None:
        widget = self.entries.get(key)
        if widget is None: return
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
                # Split by comma or newline
                items = [i.strip() for i in re.split(r'[,\n]', raw) if i.strip()]
                payload[key] = items
            elif key in DICT_FIELDS:
                try:
                    payload[key] = json.loads(raw) if raw else {}
                except:
                    payload[key] = {}
            else:
                payload[key] = raw
        payload["generated_at"] = now_utc()
        payload["panel_version"] = APP_VERSION
        return payload

    def add_other_lists(self) -> None:
        paths = filedialog.askopenfilenames(title="Select Additional List Files", filetypes=[("Data", "*.json *.csv"), ("All", "*.*")])
        if paths:
            current = self.get_widget_value("watch_list_paths")
            new_val = "\n".join(filter(None, [current, "\n".join(paths)]))
            self.set_widget_value("watch_list_paths", new_val)
            messagebox.showinfo("Added", f"{len(paths)} files added to Watch/Export/Debarment paths.")

    def load_lists(self) -> None:
        payload = self.collect_payload()
        all_paths = []
        all_paths.extend(payload.get("sanctions_list_paths", []))
        all_paths.extend(payload.get("watch_list_paths", []))
        all_paths.extend(payload.get("export_control_paths", []))
        all_paths.extend(payload.get("debarment_paths", []))
        
        # Deduplicate
        seen = set()
        unique_paths = []
        for p in all_paths:
            if p not in seen:
                seen.add(p)
                unique_paths.append(p)
                
        if not unique_paths:
            messagebox.showwarning("No Files", "Please select at least one sanctions list file.")
            return

        self.output.delete("1.0", "end")
        self.output.insert("1.0", "Loading sanctions lists...\n")
        self.notebook.select(self.output_tab)
        self.update()

        records, metas, warns = load_sanctions_lists(unique_paths)
        
        self.loaded_records = records
        self.sources_meta = metas
        
        msg = f"Loaded {len(records)} records from {len(metas)} source files.\n"
        if warns:
            msg += f"Warnings:\n" + "\n".join(warns)
        messagebox.showinfo("Load Complete", msg)
        self.output.insert("end", msg + "\nReady for screening.\n")

    def run_policy_screen(self) -> None:
        payload = self.collect_payload()
        policy = policy_screen(payload)
        result = {"mode": "POLICY_SCREEN_ONLY", "policy_screen": policy}
        self.last_result = result
        self._write_output(result)
        self.notebook.select(self.output_tab)
        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning("Blocked", "Policy Blocked.")
        else:
            messagebox.showinfo("OK", "Allowed.")

    def run_screening(self) -> None:
        payload = self.collect_payload()
        warnings = validate_payload(payload)
        policy = policy_screen(payload)
        
        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning("Blocked", "Screening blocked by policy.")
            return
            
        if not self.loaded_records:
            messagebox.showwarning("No Data", "Load sanctions lists first.")
            return

        subject = SubjectProfile(payload)
        
        self.output.delete("1.0", "end")
        self.output.insert("1.0", f"Screening Subject: {subject.name}...\n")
        self.notebook.select(self.output_tab)
        self.update()

        matches = []
        
        for rec in self.loaded_records:
            score_res = calculate_similarity_score(subject, rec)
            status = determine_screening_status(score_res, subject, rec)
            
            # Filter noise
            if status == "NO_MATCH_FOUND" and score_res["final_score"] < 0.1:
                continue
                
            matches.append({
                "record_id": rec.record_id,
                "matched_name_primary": rec.names[0] if rec.names else "N/A",
                "authority": rec.listing_authority,
                "jurisdiction": rec.jurisdiction,
                "list_name": rec.list_name,
                "status_code": status,
                "score_details": score_res,
                "raw_record_sample": {
                    "names": rec.names[:3],
                    "aliases": rec.aliases[:3],
                    "identifiers": rec.identifiers,
                    "dob": rec.dob,
                    "nationality": rec.nationality
                }
            })
            
        # Sort by score descending
        matches.sort(key=lambda x: x["score_details"]["final_score"], reverse=True)
        
        report = {
            "mode": "SANCTIONS_SCREENING_RESULT",
            "panel_version": APP_VERSION,
            "timestamp": now_utc(),
            "policy_screen": policy,
            "validation_warnings": warnings,
            "subject_profile": {
                "name": subject.name,
                "type": subject.type,
                "normalized_name": subject.norm_name,
                "dob": subject.parsed_dob,
                "nationality": subject.norm_nat,
                "registration": subject.norm_reg
            },
            "sources_loaded": self.sources_meta,
            "total_records_scanned": len(self.loaded_records),
            "matches_found": len(matches),
            "screening_results": matches[:50], # Limit output size
            "summary_assessment": self._generate_summary(matches),
            "disclaimer": [
                "This tool provides analytical candidates based on local data snapshots.",
                "It does NOT constitute a legal determination of sanctions status.",
                "SUPPORTED_MATCH requires independent verification of unique identifiers.",
                "Human compliance officer review is mandatory before any operational action.",
                "Source data may be stale; always verify against live official government portals."
            ]
        }
        
        self.last_result = report
        self._write_output(report)
        
        top_status = matches[0]["status_code"] if matches else "NO_MATCH_FOUND"
        messagebox.showinfo("Screening Complete", f"Top Result: {top_status}\nMatches Found: {len(matches)}")

    def _generate_summary(self, matches: List[Dict[str, Any]]) -> str:
        if not matches:
            return "No significant matches found against loaded datasets."
        
        high_conf = [m for m in matches if m["status_code"] in ["SUPPORTED_MATCH", "PROBABLE_MATCH"]]
        cand = [m for m in matches if m["status_code"] in ["CANDIDATE_MATCH", "POSSIBLE_MATCH"]]
        fp = [m for m in matches if m["status_code"] == "LIKELY_FALSE_POSITIVE"]
        
        summary = f"Found {len(high_conf)} High/Possible Match(es), {len(cand)} Candidate(s), {len(fp)} Likely FP(s).\n"
        if high_conf:
            summary += "ACTION REQUIRED: Immediate human review of high-confidence matches.\n"
        elif cand:
            summary += "ACTION REQUIRED: Manual disambiguation of candidate matches.\n"
        else:
            summary += "Low risk detected, but retain evidence for audit trail.\n"
            
        return summary

    def _write_output(self, result: Dict[str, Any]) -> None:
        self.output.delete("1.0", "end")
        self.output.insert("1.0", json.dumps(result, ensure_ascii=False, indent=2, default=str))

    def export_json(self) -> None:
        if not self.last_result: 
            messagebox.showinfo("Info", "Run screening first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.last_result, f, ensure_ascii=False, indent=2, default=str)
            messagebox.showinfo("Saved", path)

    def copy_output(self) -> None:
        text = self.output.get("1.0", "end-1c").strip()
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            messagebox.showinfo("Copied", "Output copied.")

    def clear_form(self) -> None:
        if messagebox.askyesno("Confirm", "Clear all inputs and results?"):
            self._set_defaults()
            self.output.delete("1.0", "end")
            self.last_result = {}
            self.loaded_records = []
            self.sources_meta = []


if __name__ == "__main__":
    try:
        app = TraceAtlasSANCTIONSINTPanel()
        app.mainloop()
    except tk.TclError as exc:
        print(f"GUI Error: {exc}")
        print("Logic usable as library.")