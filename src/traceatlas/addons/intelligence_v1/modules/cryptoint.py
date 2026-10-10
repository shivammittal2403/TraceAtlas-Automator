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


APP_TITLE = "TraceAtlas CRYPTOINT AI Employee — Defensive / Lawful / Authorized / Evidence-First Blockchain Intelligence Panel"
APP_VERSION = "TraceAtlas CRYPTOINT Panel v0.1"


FIELDS = [
    ("case_id", "Case ID", "entry"),
    ("task_id", "Task ID", "entry"),
    ("objective", "Objective", "text"),
    ("target", "Target / Address / Transaction / Token / Service Context", "entry"),
    ("target_type", "Target Type", "combo"),
    ("questions", "CRYPTOINT Questions", "text"),

    ("chains", "Chains / Networks", "text"),
    ("addresses", "Addresses", "text"),
    ("transaction_hashes", "Transaction Hashes", "text"),
    ("blocks", "Blocks", "text"),
    ("tokens", "Tokens / Contracts", "text"),
    ("contracts", "Smart Contracts", "text"),
    ("wallet_labels", "Wallet Labels / Tags", "text"),
    ("exchanges", "Exchanges / Services", "text"),
    ("bridges", "Bridges", "text"),
    ("entities", "Entities / Organizations", "text"),

    ("payment_records", "Payment Records (Context)", "text"),
    ("fraud_context", "Fraud / Scam Context", "text"),
    ("incident_context", "Incident / Breach Context", "text"),
    ("ransomware_context", "Ransomware Context", "text"),
    ("sanctions_data", "Sanctions Data", "text"),

    ("chain_data_paths", "Chain Data / Node Export Paths", "text"),
    ("tx_export_paths", "Transaction Export Paths", "text"),
    ("address_label_paths", "Address Label / Tag Paths", "text"),
    ("token_metadata_paths", "Token Metadata / Registry Paths", "text"),
    ("contract_event_paths", "Contract Event / Log Paths", "text"),
    ("bridge_log_paths", "Bridge Deposit / Withdrawal Logs", "text"),
    ("stix_misp_paths", "STIX / MISP Export Paths", "text"),

    ("time_range", "Time Range", "text"),
    ("jurisdiction", "Jurisdiction", "entry"),
    ("scope", "Scope / Allowed Sources", "text"),
    ("authorization", "Authorization Basis", "text"),
    ("source_limits", "Source Limits / Safety Limits", "text"),
    ("budget", "Budget", "entry"),
    ("deadline", "Deadline", "entry"),
    ("configured_connectors", "Configured Connectors (RPC/Indexer/Analytics/etc.)", "text"),
]


TARGET_TYPES = [
    "transaction_tracing",
    "address_clustering",
    "fund_flow_reconstruction",
    "token_contract_analysis",
    "bridge_cross_chain_correlation",
    "exchange_deposit_withdrawal_context",
    "sanctions_context_check",
    "fraud_ransomware_context",
    "unknown",
]


LIST_FIELDS = {
    "questions",
    "chains",
    "addresses",
    "transaction_hashes",
    "blocks",
    "tokens",
    "contracts",
    "wallet_labels",
    "exchanges",
    "bridges",
    "entities",
    "payment_records",
    "fraud_context",
    "incident_context",
    "ransomware_context",
    "sanctions_data",
    "chain_data_paths",
    "tx_export_paths",
    "address_label_paths",
    "token_metadata_paths",
    "contract_event_paths",
    "bridge_log_paths",
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
    "transaction_tracing",
    "address_clustering",
    "fund_flow_reconstruction",
    "token_contract_analysis",
    "bridge_cross_chain_correlation",
    "exchange_deposit_withdrawal_context",
    "sanctions_context_check",
    "fraud_ransomware_context",
}


NEGATION_RE = re.compile(
    r"\b(?:do not|don't|dont|must not|shall not|should not|avoid|without|never|not to|prohibit|policy blocked|safe alternative|defensive only)\b",
    re.I,
)


POLICY_BLOCK_PATTERNS = [
    r"\b(?:use|apply|utilize|sign|broadcast)\b[^\n]{0,140}\b(?:private key|seed phrase|mnemonic|recovery phrase|wallet credential)\b",
    r"\b(?:transfer|send|move|withdraw|deposit|sweep|drain)\b[^\n]{0,140}\b(?:crypto|bitcoin|ethereum|solana|token|asset|funds|balance)\b",
    r"\b(?:exploit|hack|attack|manipulate)\b[^\n]{0,140}\b(?:smart contract|bridge|defi protocol|oracle|liquidity pool|dapp)\b",
    r"\b(?:front-run|sandwich|flash loan attack|rug pull|pump and dump|wash trading)\b",
    r"\b(?:launder|clean|mix|tumble|peel|chain hop|evade tracing)\b[^\n]{0,140}\b(?:crypto|bitcoin|ethereum|token|funds|assets)\b",
    r"\b(?:design|create|plan|recommend)\b[^\n]{0,140}\b(?:mixer strategy|evasion route|privacy tool for concealment|sanctions evasion|aml bypass)\b",
    r"\b(?:brute force|crack|recover without authorization)\b[^\n]{0,140}\b(?:wallet|key|seed|mnemonic)\b",
]


SAFE_ALTERNATIVES = [
    "Provide defensive/lawful/authorized/evidence-first blockchain intelligence: parse local chain data, resolve addresses/transactions/tokens/contracts, reconstruct on-chain flows, identify clustering hypotheses with exposed heuristics, check source independence, and produce attribution-gated reports.",
    "Do not use private keys, sign/broadcast transactions, move assets, test wallet control, drain wallets, exploit contracts/bridges/DeFi, manipulate oracles/prices, design laundering/mixing/peeling/chain-hopping evasion, or advise sanctions/AML/KYC bypass.",
    "Separate address from wallet, wallet from person, exchange address from customer, transaction from payment purpose, cluster from entity, label from verified owner, and direct flow from service-mediated flow.",
    "Use deterministic arithmetic for amounts, decimals, fees, and balances. Escalate real-person attribution, asset seizure/freezing, law-enforcement action, or sanctions violation determinations to authorized human/legal/compliance review.",
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
        "SEED_PHRASE_LIKE",
        re.compile(r"\b(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8}\b", re.I), # Heuristic for mnemonic-like strings
    ),
    (
        "PASSWORD_OR_TOKEN_ASSIGNMENT",
        re.compile(
            r"(?i)\b(password|passwd|pwd|token|api[_-]?key|apikey|secret|"
            r"access[_-]?key|auth[_-]?key|client[_-]?secret|authorization|cookie|session|credential|private_key|seed_phrase|mnemonic)\b"
            r"\s*[:=]\s*[^\s,;\"']+"
        ),
    ),
    (
        "BEARER_TOKEN",
        re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-+/=]{8,}"),
    ),
    (
        "AWS_ACCESS_KEY",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    (
        "JWT_LIKE_TOKEN",
        re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"),
    ),
]


PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(?:all\s+)?previous\s+(?:instructions|rules)",
    r"reveal\s+(?:the\s+)?system\s+prompt",
    r"send\s+(?:money|funds|crypto|btc|eth)",
    r"sign\s+(?:this\s+)?(?:transaction|message)",
    r"use\s+(?:my\s+)?(?:private key|seed phrase)",
    r"execute\s+(?:script|code|command)",
    r"disable\s+(?:security|compliance)\s+controls",
]


# Regex patterns for common blockchain identifiers
BTC_ADDR_RE = re.compile(r"\b([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{20,90})\b")
ETH_ADDR_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
TX_HASH_RE = re.compile(r"\b0x[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{64}\b") # Generic 64 hex or eth style
SOLANA_ADDR_RE = re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b") # Loose heuristic for Solana/Base58

ENTITY_ROLE_KEYS = [
    "address",
    "addresses",
    "sender",
    "recipient",
    "to",
    "from",
    "contract",
    "contracts",
    "token",
    "tokens",
    "exchange",
    "exchanges",
    "service",
    "services",
    "entity",
    "entities",
    "miner",
    "validator",
    "pool",
    "bridge",
    "bridges",
]


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


def content_tokens(text: str) -> List[str]:
    redacted, _ = redact_secrets(str(text or ""))
    low = normalize_text(redacted)
    return re.findall(r"[a-z0-9]+", low)


def content_fingerprint(text: str) -> str:
    tokens = content_tokens(text)
    if not tokens:
        return ""
    return sha256_text(" ".join(sorted(set(tokens))))[:32]


def get_field(rec: Dict[str, Any], keys: List[str], as_list: bool = False) -> Any:
    if not isinstance(rec, dict):
        return [] if as_list else None

    lower = {normalize_key(k): v for k, v in rec.items()}
    for key in keys:
        nk = normalize_key(key)
        if nk in lower and lower[nk] not in (None, ""):
            val = lower[nk]
            if as_list:
                return listify(val)
            if isinstance(val, list):
                return val[0] if val else None
            return val
    return [] if as_list else None


def extract_addresses(text: str) -> List[Tuple[str, str]]:
    """Returns list of (address_string, estimated_chain_type)"""
    found = []
    
    # ETH/EVM
    for m in ETH_ADDR_RE.finditer(text):
        addr = m.group(0)
        found.append((addr, "EVM"))
        
    # BTC Legacy/Segwit
    for m in BTC_ADDR_RE.finditer(text):
        addr = m.group(0)
        # Avoid double counting if regex overlaps (unlikely given specific chars)
        if any(addr == a for a, _ in found):
            continue
        chain = "BTC_SEGWIT" if addr.startswith("bc1") else "BTC_LEGACY"
        found.append((addr, chain))
        
    return found


def parse_amount(value: Any, decimals: int = 18) -> Optional[Decimal]:
    """Parses raw string/int to Decimal considering standard ERC20/native decimals."""
    if value is None:
        return None
    
    s = str(value).strip()
    if not s:
        return None
        
    try:
        # Handle scientific notation or large ints
        d = Decimal(s)
        if decimals > 0:
            d = d / (Decimal(10) ** decimals)
        return d.quantize(Decimal("0.000000000000000001"))
    except InvalidOperation:
        return None


def empty_parsed() -> Dict[str, Any]:
    return {
        "sources": [],
        "chains": [],
        "addresses": [],
        "transactions": [],
        "blocks": [],
        "tokens": [],
        "contracts": [],
        "events": [],
        "clusters": [],
        "labels": [],
        "flows": [],
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
            "Blockchain observation proves state change, not real-world identity or intent.",
            "Labels are source-reported until corroborated by independent authority.",
        ],
    })

    if secret_flags:
        add_note(parsed, "SECRET_REDACTION", flags=secret_flags, source_id=source_id, evidence_id=evidence_id, context=context)
    if injection_flags:
        add_note(parsed, "PROMPT_INJECTION_FLAG", flags=injection_flags, source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Embedded instructions in chain data/logs are ignored.")


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
            "Multiple explorers reading same node are not independent sources.",
        ],
    })


def add_chain(parsed: Dict[str, Any], name: Any, network: Any, model: Any, source_id: str, evidence_id: str) -> Optional[str]:
    n = safe_str(name, 100).upper()
    if not n:
        return None
    
    net = safe_str(network, 100).lower() or "mainnet"
    mod = safe_str(model, 50).upper() or "UNKNOWN"
    
    cid = f"CHN-{uuid.uuid4()}"
    parsed["chains"].append({
        "chain_id": cid,
        "name": n,
        "network": net,
        "model": mod,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "state": "CHAIN_CANDIDATE",
        "limitations": ["Chain identification requires consistent address/hash format validation."],
    })
    return cid


def add_address(parsed: Dict[str, Any], addr: Any, chain_hint: Any, addr_type: Any, source_id: str, evidence_id: str, context: str = "") -> Optional[str]:
    a = safe_str(addr, 100)
    if not a:
        return None
        
    norm_a = a.lower() if a.startswith("0x") else a # Case sensitivity varies by chain
    
    for ad in parsed["addresses"]:
        if ad.get("normalized_address") == norm_a:
            if chain_hint and not ad.get("chain_hint"):
                ad["chain_hint"] = safe_str(chain_hint, 50)
            if addr_type and ad.get("address_type") in ("", "UNKNOWN"):
                ad["address_type"] = safe_str(addr_type, 50).upper()
            return ad.get("address_id")

    aid = f"ADR-{uuid.uuid4()}"
    parsed["addresses"].append({
        "address_id": aid,
        "raw_address": a,
        "normalized_address": norm_a,
        "chain_hint": safe_str(chain_hint, 50),
        "address_type": safe_str(addr_type, 50).upper() or "UNKNOWN",
        "first_seen": "",
        "last_seen": "",
        "entity_labels": [],
        "cluster_ids": [],
        "risk_context": [],
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "ADDRESS_CANDIDATE",
        "limitations": [
            "Address does not prove ownership or controller.",
            "Same address string may exist on different networks/chains.",
        ],
    })
    return aid


def add_transaction(parsed: Dict[str, Any], tx_hash: Any, block_num: Any, timestamp: Any, sender: Any, recipients: Any, value: Any, fee: Any, chain_id: Any, source_id: str, evidence_id: str, context: str = "") -> Optional[str]:
    th = safe_str(tx_hash, 100)
    if not th:
        return None
        
    tid = f"TXN-{uuid.uuid4()}"
    
    # Resolve Sender
    sndr_ref = None
    if sender:
        sndr_addr = sender if isinstance(sender, str) else sender.get("address")
        sndr_ref = add_address(parsed, sndr_addr, None, "EOA_OR_USER_ADDRESS", source_id, evidence_id, f"{context}/sender")

    rcpt_refs = []
    if recipients:
        rec_list = listify(recipients)
        for r in rec_list:
            r_addr = r if isinstance(r, str) else r.get("address")
            ref = add_address(parsed, r_addr, None, "UNKNOWN", source_id, evidence_id, f"{context}/recipient")
            if ref:
                rcpt_refs.append(ref)

    parsed["transactions"].append({
        "transaction_id": tid,
        "hash": th,
        "block_number": safe_str(block_num, 50),
        "timestamp": safe_str(timestamp, 100),
        "sender_ref": sndr_ref,
        "recipient_refs": rcpt_refs,
        "native_value_raw": safe_str(value, 50),
        "fee_raw": safe_str(fee, 50),
        "chain_id": chain_id,
        "status": "CONFIRMED", # Default assumption for parsed blocks
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "TRANSACTION_PARSED",
        "limitations": [
            "Transaction proves state change, not intent or identity.",
            "Value/Fee units depend on chain-specific decimals.",
        ],
    })
    return tid


def add_token(parsed: Dict[str, Any], symbol: Any, name: Any, contract: Any, decimals: Any, chain_id: Any, source_id: str, evidence_id: str) -> Optional[str]:
    sym = safe_str(symbol, 50).upper()
    cnt = safe_str(contract, 100)
    
    if not sym and not cnt:
        return None
        
    tid = f"TKN-{uuid.uuid4()}"
    
    # Link contract address
    ctr_ref = None
    if cnt:
        ctr_ref = add_address(parsed, cnt, None, "TOKEN_CONTRACT", source_id, evidence_id, f"token_contract/{sym}")

    parsed["tokens"].append({
        "token_id": tid,
        "symbol": sym,
        "name": safe_str(name, 100),
        "contract_ref": ctr_ref,
        "decimals": safe_str(decimals, 10),
        "chain_id": chain_id,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "state": "TOKEN_METADATA_OBSERVED",
        "limitations": [
            "Symbol/Name can be spoofed. Contract address + Chain is primary identity.",
            "Decimals must be used for accurate amount calculation.",
        ],
    })
    return tid


def add_cluster(parsed: Dict[str, Any], addresses: List[str], method: Any, confidence: Any, source_id: str, evidence_id: str) -> Optional[str]:
    if not addresses:
        return None
        
    cid = f"CLU-{uuid.uuid4()}"
    
    # Update addresses with cluster ID
    for ad in parsed["addresses"]:
        if ad.get("normalized_address") in [a.lower() if a.startswith('0x') else a for a in addresses]:
            if cid not in ad["cluster_ids"]:
                ad["cluster_ids"].append(cid)

    parsed["clusters"].append({
        "cluster_id": cid,
        "member_addresses": addresses[:100],
        "clustering_method": safe_str(method, 100).upper(),
        "confidence": safe_str(confidence, 50).upper() or "PROBABLE",
        "source_id": source_id,
        "evidence_id": evidence_id,
        "state": "CLUSTER_HYPOTHESIS",
        "limitations": [
            "Clustering is analytical inference, not proof of ownership.",
            "Exceptions: CoinJoin, Custodial Services, Multisig, Exchange Pooling.",
        ],
    })
    return cid


def process_json_record(
    rec: Dict[str, Any],
    source_id: str,
    evidence_id: str,
    parsed: Dict[str, Any],
    context: str = "",
) -> None:
    if not isinstance(rec, dict):
        return

    rec_ctx = context or "json_record"

    text_blob = json.dumps(rec, ensure_ascii=False, default=str)[:12000]
    process_text_block(text_blob, source_id, evidence_id, parsed, context=rec_ctx)

    # Extract explicit addresses
    for key in ENTITY_ROLE_KEYS:
        vals = get_field(rec, [key], as_list=True)
        for val in vals:
            if isinstance(val, dict):
                addr = val.get("address") or val.get("id") or val.get("hex")
                ctype = val.get("type") or val.get("tag")
            else:
                addr = str(val)
                ctype = ""
            
            if addr:
                add_address(parsed, addr, rec.get("chain"), ctype, source_id, evidence_id, f"{rec_ctx}/{key}")

    # Explicit Transaction Structure
    tx_hash = get_field(rec, ["hash", "tx_hash", "transaction_hash", "id"])
    if tx_hash:
        sender = get_field(rec, ["from", "sender", "input_address"])
        recipients = get_field(rec, ["to", "receiver", "output_address"], as_list=True)
        value = get_field(rec, ["value", "amount", "satoshis"])
        fee = get_field(rec, ["fee", "gas_used", "gas_price"])
        block = get_field(rec, ["block_number", "block_height", "block"])
        ts = get_field(rec, ["timestamp", "time", "date"])
        chain_name = get_field(rec, ["chain", "network"])
        
        # Create Chain Object if new
        chain_id = None
        if chain_name:
            chain_id = add_chain(parsed, chain_name, rec.get("network", "mainnet"), rec.get("consensus_model", "UNKNOWN"), source_id, evidence_id)
            
        add_transaction(
            parsed,
            tx_hash,
            block,
            ts,
            sender,
            recipients,
            value,
            fee,
            chain_id,
            source_id,
            evidence_id,
            rec_ctx,
        )

    # Token Metadata
    token_sym = get_field(rec, ["symbol", "ticker"])
    token_ctr = get_field(rec, ["contract_address", "token_contract"])
    if token_sym or token_ctr:
        add_token(
            parsed,
            token_sym,
            get_field(rec, ["name"]),
            token_ctr,
            get_field(rec, ["decimals"]),
            None, # Chain link implicit via context or separate record
            source_id,
            evidence_id,
        )

    # Clustering Hints (if provided in input data structure)
    cluster_members = get_field(rec, ["cluster_members", "associated_addresses"], as_list=True)
    if cluster_members:
        member_addrs = []
        for cm in cluster_members:
            if isinstance(cm, dict):
                member_addrs.append(cm.get("address"))
            else:
                member_addrs.append(str(cm))
        
        valid_members = [m for m in member_addrs if m]
        if valid_members:
             add_cluster(
                parsed,
                valid_members,
                get_field(rec, ["clustering_method", "heuristic"]) or "INPUT_PROVIDED",
                get_field(rec, ["confidence"]) or "SOURCE_REPORTED",
                source_id,
                evidence_id,
            )


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
                 caution="Chain logs/RPC responses are untrusted data.")

    add_observation(parsed, redacted[:1000], source_id, evidence_id, context=context)

    # Auto-extract addresses from free text
    extracted = extract_addresses(redacted)
    for addr, chain_guess in extracted:
        add_address(parsed, addr, chain_guess, "AUTO_EXTRACTED", source_id, evidence_id, context)


def classify_json_payload(data: Any, filename: str = "") -> str:
    if isinstance(data, list):
        return "JSON_ARRAY_CHAIN_DATA"
    if not isinstance(data, dict):
        return "GENERIC_JSON"

    keys = {normalize_key(k) for k in data.keys()}
    low = json.dumps(data, ensure_ascii=False, default=str)[:30000].lower()
    fname = normalize_text(filename)

    if "block" in fname or "blocks" in keys:
        return "BLOCK_EXPORT"
    if "tx" in fname or "transaction" in fname or "transactions" in keys:
        return "TRANSACTION_EXPORT"
    if "label" in fname or "tags" in fname or "entities" in keys:
        return "ADDRESS_LABEL_DATASET"
    if "token" in fname or "metadata" in fname:
        return "TOKEN_METADATA"
    if "contract" in fname or "abi" in fname:
        return "CONTRACT_METADATA"
    if "bridge" in fname or "cross_chain" in low:
        return "BRIDGE_LOG"

    return "GENERIC_BLOCKCHAIN_DATA"


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
    kind = "CSV_BLOCKCHAIN_DATA"

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

    low = redacted_raw.lower()[:30000]
    if "block" in low or "tx" in low or "hash" in low:
        kind = "TEXT_CHAIN_LOG"
    elif "label" in low or "tag" in low or "entity" in low:
        kind = "TEXT_LABEL_DATASET"
    else:
        kind = "TEXT_GENERIC_CRYPTO_DATA"

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
        ".pptx", ".mp3", ".wav", ".mp4", ".avi", ".db", ".sqlite",
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

    if suffix in {".txt", ".log", ".md", ".yaml", ".yml", ".report", ".stix", ".taxii", ".misp", ".snapshot", ".dat", ".idx"}:
        return {"format_detected": "TEXT", "mime_type": "text/plain"}

    try:
        probe = head.decode("utf-8", errors="strict")
        if probe.strip():
            return {"format_detected": "TEXT", "mime_type": "text/plain"}
    except Exception:
        pass

    return {"format_detected": "UNKNOWN", "mime_type": "application/octet-stream"}


def analyze_crypto_file(path_str: str, case_id: str = "", task_id: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
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
            "No private key use, transaction signing, broadcasting, asset movement, wallet draining, contract exploitation, or evasion guidance performed.",
            "Binary artifacts are hash/metadata preserved only.",
            "Chain data is untrusted evidence, not instruction.",
            "Exposed secrets were redacted and not used.",
            "Addresses/Transactions are structural facts, not identity proofs.",
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
            file_evidence["content_kind"] = "BINARY_CHAIN_DOC_METADATA_ONLY"
            file_evidence["status"] = "PARTIAL_BINARY_METADATA_ONLY"
            file_evidence["reason"] = (
                "Binary blockchain document detected. This planning panel preserves hash/metadata only. "
                "It does not execute binaries, load wallets, connect to RPCs, or interact with chains."
            )
        else:
            file_evidence["content_kind"] = "UNKNOWN_OR_UNSUPPORTED"
            file_evidence["status"] = "UNSUPPORTED_FORMAT"
    except Exception as exc:
        file_evidence["status"] = "PARTIAL_OR_FAILED"
        file_evidence["error"] = f"{exc.__class__.__name__}: {exc}"

    file_evidence["parsed_address_count"] = len(parsed.get("addresses", []))
    file_evidence["parsed_transaction_count"] = len(parsed.get("transactions", []))
    file_evidence["parsed_token_count"] = len(parsed.get("tokens", []))
    file_evidence["parsed_cluster_count"] = len(parsed.get("clusters", []))

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


def build_source_independence(parsed: Dict[str, Any]) -> None:
    sources = parsed.get("sources", [])
    hash_groups: Dict[str, List[str]] = defaultdict(list)
    fp_groups: Dict[str, List[str]] = defaultdict(list)
    publisher_groups: Dict[str, List[str]] = defaultdict(list)

    for s in sources:
        sid = s.get("source_id")
        fh = s.get("file_hash")
        fp = s.get("content_fingerprint")
        pub = normalize_text(s.get("publisher") or "")
        if fh:
            hash_groups[fh].append(sid)
        if fp:
            fp_groups[fp].append(sid)
        if pub:
            publisher_groups[pub].append(sid)

    for s in sources:
        fh = s.get("file_hash")
        fp = s.get("content_fingerprint")
        pub = normalize_text(s.get("publisher") or "")

        if fh and len(hash_groups.get(fh, [])) > 1:
            s["source_independence_state"] = "DEPENDENT_COPIES"
            s["source_family_count"] = 1
        elif fp and len(fp_groups.get(fp, [])) > 1:
            s["source_independence_state"] = "DEPENDENT_CONTENT_FAMILY"
            s["source_family_count"] = 1
        elif pub and len(publisher_groups.get(pub, [])) > 1:
            s["source_independence_state"] = "PARTIALLY_DEPENDENT_PENDING_REVIEW"
            s["source_family_count"] = 1
        elif len(sources) > 1:
            s["source_independence_state"] = "UNKNOWN_POTENTIALLY_INDEPENDENT"
            s["source_family_count"] = len(sources)
        else:
            s["source_independence_state"] = "SINGLE_SOURCE"
            s["source_family_count"] = 1


def infer_flows(parsed: Dict[str, Any]) -> None:
    """Constructs simple directed edges between addresses based on transactions."""
    flows = []
    txns = parsed.get("transactions", [])
    
    for t in txns:
        sender = t.get("sender_ref")
        recipients = t.get("recipient_refs", [])
        
        if not sender:
            continue
            
        for r in recipients:
            flows.append({
                "flow_id": f"FLW-{uuid.uuid4()}",
                "from_address_ref": sender,
                "to_address_ref": r,
                "transaction_ref": t.get("transaction_id"),
                "value_raw": t.get("native_value_raw"),
                "timestamp": t.get("timestamp"),
                "state": "ON_CHAIN_FLOW_OBSERVED",
                "limitations": [
                    "Flow represents technical transfer, not economic relationship.",
                    "Self-transfers and change outputs may appear as distinct flows.",
                ],
            })
            
    parsed["flows"] = unique_preserve_order(flows)[:50000]


def analyze_clustering_exceptions(parsed: Dict[str, Any]) -> None:
    """Flags potential false positives in clustering based on known patterns."""
    notes = []
    clusters = parsed.get("clusters", [])
    
    for c in clusters:
        members = c.get("member_addresses", [])
        if len(members) > 50:
            notes.append({
                "note_id": f"NOTE-{uuid.uuid4()}",
                "type": "LARGE_CLUSTER_WARNING",
                "cluster_id": c.get("cluster_id"),
                "message": "Large cluster size may indicate exchange pooling or custodial service rather than single-user wallet.",
                "caution": "Verify against known exchange deposit address patterns before attributing to individual.",
            })
            
    if notes:
        parsed["notes"].extend(notes)


def build_contradictions(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    contradictions = []
    
    # Check for duplicate Tx Hashes with different data
    tx_by_hash: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for t in parsed.get("transactions", []):
        h = t.get("hash")
        if h:
            tx_by_hash[h].append(t)
            
    for h, group in tx_by_hash.items():
        if len(group) > 1:
            senders = {g.get("sender_ref") for g in group if g.get("sender_ref")}
            values = {g.get("native_value_raw") for g in group if g.get("native_value_raw")}
            
            if len(senders) > 1 or len(values) > 1:
                contradictions.append({
                    "contradiction_id": f"CON-{uuid.uuid4()}",
                    "type": "TRANSACTION_DATA_CONFLICT",
                    "subject": h,
                    "values": {"senders": list(senders)[:10], "values": list(values)[:10]},
                    "possible_explanations": [
                        "Reorg history",
                        "Different chain forks",
                        "Parser error",
                        "Spoofed/Malformed input data",
                    ],
                    "resolution_status": "UNRESOLVED",
                    "caution": "Do not assume canonical state without finality confirmation.",
                })
                
    contradictions, _ = truncate_list(contradictions, 5000)
    return contradictions


def build_hypotheses(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    hyps = []
    addresses = parsed.get("addresses", [])
    clusters = parsed.get("clusters", [])
    flows = parsed.get("flows", [])
    
    if not addresses and not flows:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Insufficient on-chain data to form tracing or clustering hypotheses.",
            "supporting_facts": ["No addresses or flows parsed."],
            "opposing_facts": [],
            "unknowns": ["chain activity", "address relationships"],
            "next_test": "Import valid block explorer exports or RPC logs.",
            "status": "OPEN",
        })
        return hyps[:1000]

    if clusters:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Parsed data suggests multiple addresses share common control (Cluster Hypothesis).",
            "supporting_facts": [f"{len(clusters)} cluster(s) identified."],
            "opposing_facts": ["Clusters may be exchange pools, multisigs, or CoinJoin artifacts."],
            "unknowns": ["real-world controller", "custody model"],
            "falsification_conditions": ["Independent exchange disclosure shows pooled custody.", "CoinJoin structure confirmed."],
            "next_test": "Cross-reference cluster members against known service labels and check for common-input-spending anomalies.",
            "status": "OPEN",
        })

    if flows:
        rapid_flows = [f for f in flows if f.get("timestamp")] # Simplified check
        if rapid_flows:
             hyps.append({
                "hypothesis_id": f"HYP-{uuid.uuid4()}",
                "statement": "Fund movement patterns suggest potential peeling or mixing behavior.",
                "supporting_facts": [f"{len(rapid_flows)} sequential flow(s) detected."],
                "opposing_facts": ["Normal treasury management, arbitrage, or DEX routing."],
                "unknowns": ["intent", "counterparty identity"],
                "falsification_conditions": ["Flows map to known merchant/payment processors.", "Volumes match typical user activity."],
                "next_test": "Analyze flow depth and entropy. Do not conclude laundering without off-chain context.",
                "status": "OPEN",
            })

    hyps, _ = truncate_list(hyps, 1000)
    return hyps


def build_knowledge_gaps(payload: Dict[str, Any], files: List[Dict[str, Any]], parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    gaps = []
    addresses = parsed.get("addresses", [])
    labels = parsed.get("labels", []) # Note: Labels aren't fully populated in this simplified parser, usually come from external tag DBs
    
    if not files:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What lawful/authorized blockchain evidence exists?",
            "missing_evidence": "No local CRYPTOINT artifact supplied.",
            "likely_source": "Block explorer CSV/JSON, RPC node dump, analytics provider export.",
            "specialist_owner": "CRYPTOINT AI Employee",
            "priority": "HIGH",
            "expected_information_value": "Enables baseline chain analysis.",
            "safety_boundary": "No key usage, no transaction sending.",
        })

    if addresses and not any(a.get("entity_labels") for a in addresses):
         gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "Which addresses correspond to known services/entities?",
            "missing_evidence": "Address labels/tags missing.",
            "likely_source": "Commercial blockchain intelligence feed, public OFAC lists, exchange disclosures.",
            "specialist_owner": "CRYPTOINT / SANCTIONSINT",
            "priority": "MEDIUM_HIGH",
            "expected_information_value": "Converts anonymous addresses to contextual entities.",
            "safety_boundary": "Labels are probabilistic, not absolute proof of control.",
        })

    gaps, _ = truncate_list(gaps, 500)
    return gaps


def build_specialist_handoffs(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    handoffs = []
    addresses = parsed.get("addresses", [])
    flows = parsed.get("flows", [])
    
    if any(a.get("address_type") == "SMART_CONTRACT" for a in addresses):
        handoffs.append({
            "specialist": "DOCINT / CODEAUDIT",
            "reason": "Smart contract interaction detected.",
            "expected_output": "Code verification, ABI decoding, vulnerability assessment.",
            "question": "Is the contract malicious, buggy, or legitimate?",
        })
        
    if flows:
        handoffs.append({
            "specialist": "FININT / PAYMENTINT",
            "reason": "Asset flow detected.",
            "expected_output": "Economic interpretation, fiat valuation, payment reconciliation.",
            "question": "Does this on-chain movement represent a commercial payment, investment, or other financial event?",
        })

    if not handoffs:
        handoffs.append({
            "specialist": "CRYPTOINT Manager",
            "reason": "Standard chain analysis completed.",
            "expected_output": "Review findings, approve further deep-dive or closure.",
            "question": "Are current hypotheses sufficient for decision making?",
        })

    return handoffs


def finalize_parsed(parsed: Dict[str, Any], payload: Optional[Dict[str, Any]] = None, files: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    build_source_independence(parsed)
    infer_flows(parsed)
    analyze_clustering_exceptions(parsed)
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
    addresses = parsed.get("addresses", [])
    clusters = parsed.get("clusters", [])
    flows = parsed.get("flows", [])

    if policy.get("status") == "POLICY_BLOCKED":
        return {
            "action": "Revise task to remove prohibited key usage, transaction signing, asset movement, exploitation, or evasion guidance.",
            "reason": "CRYPTOINT is defensive blockchain intelligence, not an operational wallet or attack tool.",
            "owner": "CRYPTOINT Manager",
            "expected_output": "Policy-compliant defensive scope.",
        }

    if not files:
        return {
            "action": "Attach lawful/authorized block explorer exports, RPC logs, or analytics datasets.",
            "reason": "No on-chain evidence available for local parsing.",
            "owner": "CRYPTOINT AI Employee",
            "expected_output": "Blockchain evidence inventory.",
        }

    if not addresses:
        return {
            "action": "Validate input format. Ensure addresses/hashes are present in JSON/CSV.",
            "reason": "Parser did not identify valid blockchain addresses.",
            "owner": "CRYPTOINT Engineer",
            "expected_output": "Debugged ingestion pipeline.",
        }

    if clusters:
        return {
            "action": "Correlate clustered addresses with external label databases to distinguish exchange/custodial infrastructure from user wallets.",
            "reason": "Clustering alone does not prove individual ownership.",
            "owner": "CRYPTOINT Analyst",
            "expected_output": "Refined cluster attribution.",
        }

    return {
        "action": "Proceed with flow visualization and temporal analysis. Identify entry/exit points.",
        "reason": "Basic structural analysis complete.",
        "owner": "CRYPTOINT / FININT",
        "expected_output": "Visual fund-flow graph.",
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

    def add(operation: str, tool: str, purpose: str, status: str, expected_output: str, safety_risk: str = "LOW") -> None:
        nonlocal priority
        plan.append({
            "question": questions_limited[0] if questions_limited else "General CRYPTOINT planning",
            "operation": operation,
            "tool_or_provider": tool,
            "purpose": purpose,
            "status": status,
            "expected_output": expected_output,
            "priority": priority,
            "safety_risk": safety_risk,
            "policy_note": "Defensive / lawful / authorized / evidence-first blockchain intelligence only.",
            "authorization_status": "ALLOWED_DEFENSIVE_AUTHORIZED",
            "execution_status": "NOT_EXECUTED_PLANNING_ONLY",
        })
        priority += 1

    add(
        "define_crypto_questions_scope",
        "CRYPTOINT Manager",
        "Define tracing/clustering goals and allowed data sources.",
        "COMPLETED_LOCAL" if payload.get("questions") else "REQUIRED_BEFORE_COLLECTION",
        "Requirement-driven collection plan.",
    )

    add(
        "preserve_original_chain_data",
        "local evidence store",
        "Hash and store raw JSON/CSV exports without modification.",
        "COMPLETED_LOCAL" if files else "PLANNED_REQUIRES_EVIDENCE",
        "Immutable chain data archive.",
    )

    add(
        "parse_transactions_and_addresses",
        "local deterministic parser",
        "Extract hashes, addresses, values, and timestamps from structured data.",
        "COMPLETED_LOCAL" if files else "PLANNED_REQUIRES_EVIDENCE",
        "Normalized transaction/address objects.",
    )

    add(
        "apply_clustering_heuristics",
        "local analyzer",
        "Group addresses using common-input-selection or provided hints.",
        "PLANNED_ANALYTIC",
        "Cluster candidates with heuristic transparency.",
        safety_risk="MEDIUM_IF_HEURISTIC_OVERUSED",
    )

    add(
        "correlate_external_labels",
        "CRYPTOINT Analyst / External API",
        "Match addresses against known exchange/service/sanction lists.",
        "PLANNED_EXTERNAL_CORRELATION",
        "Entity-attributed address set.",
        safety_risk="HIGH_IF_STALE_LABELS_USED",
    )

    return plan


def policy_screen(payload: Dict[str, Any]) -> Dict[str, Any]:
    scanned_fields = [
        "objective",
        "target",
        "questions",
        "chains",
        "addresses",
        "transaction_hashes",
        "tokens",
        "contracts",
        "wallet_labels",
        "exchanges",
        "bridges",
        "entities",
        "payment_records",
        "fraud_context",
        "incident_context",
        "ransomware_context",
        "sanctions_data",
    ]

    parts: List[str] = []
    for key in scanned_fields:
        val = payload.get(key)
        if isinstance(val, list):
            parts.extend(str(x) for x in val)
        elif isinstance(val, dict):
            parts.append(json.dumps(val, ensure_ascii=False, default=str))
        else:
            parts.append(str(val or ""))

    scanned = " \n ".join(parts).lower()

    blocked_reasons: List[str] = []
    for pat in POLICY_BLOCK_PATTERNS:
        rx = re.compile(pat, re.I)
        for m in rx.finditer(scanned):
            start = max(0, m.start() - 180)
            prefix = scanned[start:m.start()]
            if NEGATION_RE.search(prefix):
                continue
            blocked_reasons.append(pat)
            break

    human_review_required = False
    safety_notes: List[str] = []

    if payload.get("target_type") in SENSITIVE_TARGET_TYPES:
        human_review_required = True
        safety_notes.append(
            "Sensitive blockchain/tracing context detected. Analysis must remain defensive and observational. "
            "No key usage, no transaction sending, no exploitation."
        )

    if payload.get("sanctions_data"):
        human_review_required = True
        safety_notes.append(
            "Sanctions context detected. Final legal determination requires SANCTIONSINT/Human Review."
        )

    if blocked_reasons:
        return {
            "status": "POLICY_BLOCKED",
            "reasons": sorted(set(blocked_reasons)),
            "human_review_required": True,
            "safety_notes": safety_notes,
            "explanation": "Request involves prohibited cryptographic operations or evasion techniques.",
            "safe_alternatives": SAFE_ALTERNATIVES,
        }

    if human_review_required:
        return {
            "status": "HUMAN_REVIEW_REQUIRED",
            "reasons": [],
            "human_review_required": True,
            "safety_notes": safety_notes,
            "explanation": "No hard block, but sensitive attribution/sanctions context applies.",
            "safe_alternatives": SAFE_ALTERNATIVES,
        }

    return {
        "status": "ALLOWED_DEFENSIVE_AUTHORIZED",
        "reasons": [],
        "human_review_required": False,
        "safety_notes": [],
        "explanation": "Planning-only mode active.",
        "safe_alternatives": [],
    }


def validate_payload(payload: Dict[str, Any]) -> List[str]:
    warnings: List[str] = []
    required = ["case_id", "task_id", "objective", "target", "target_type"]
    for field in required:
        if not payload.get(field):
            warnings.append(f"Missing required field: {field}")
    if not payload.get("questions"):
        warnings.append("No CRYPTOINT questions provided.")
    if not any(payload.get(k) for k in ["chain_data_paths", "tx_export_paths", "address_label_paths"]):
        warnings.append("No blockchain evidence paths provided.")
    return warnings


def default_questions(payload: Dict[str, Any]) -> List[str]:
    return [
        "Which chains and networks are involved?",
        "What transactions occurred and what was their status?",
        "Which addresses participated and what are their types?",
        "Can we hypothesize wallet clusters based on available heuristics?",
        "What tokens/assets moved and what are their contract identities?",
        "Did funds pass through exchanges, bridges, or mixers?",
        "Are there any sanctions/fraud/ransomware labels associated?",
        "What remains unknown regarding real-world attribution?",
    ]


class TraceAtlasCRYPTOINTPanel(tk.Tk):
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
        style.configure("Header.TLabel", background="#0b0f19", foreground="#a78bfa", font=("Segoe UI", 17, "bold"))
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
        ttk.Label(header, text="TraceAtlas CRYPTOINT AI Employee", style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text=(
                "Defensive / lawful / authorized / evidence-first blockchain intelligence • Planning-only by default • "
                "Local deterministic JSON/CSV/TXT chain data parsing only • "
                "No private key use / no signing / no broadcasting / no moving assets / no exploitation / no evasion guidance • "
                "Address != Wallet • Wallet != Person • Cluster != Entity • Label != Proof"
            ),
            style="Subheader.TLabel",
            wraplength=1280,
            justify="left",
        ).pack(anchor="w", pady=(2, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(8, 16))

        self.input_tab = ttk.Frame(self.notebook)
        self.output_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.input_tab, text="CRYPTOINT Task Input")
        self.notebook.add(self.output_tab, text="Output / Crypto Plan / Evidence")

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
                widget = ttk.Combobox(self.form, values=TARGET_TYPES if key == "target_type" else [], width=100, state="readonly")
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

        ttk.Button(buttons1, text="Add Chain Data", command=self.add_chain_data).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Tx Exports", command=self.add_tx_exports).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Address Labels", command=self.add_address_labels).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Token Metadata", command=self.add_token_metadata).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Bridge Logs", command=self.add_bridge_logs).pack(side="left", padx=4)

        ttk.Button(buttons2, text="Analyze Local CRYPTOINT Evidence", command=self.analyze_local_crypto).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Run Policy Screen", command=self.run_policy_screen).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Generate Crypto Plan", command=self.generate_plan).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Export JSON", command=self.export_json).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Copy Output", command=self.copy_output).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Clear Form", command=self.clear_form).pack(side="left", padx=4)

    def _build_output_tab(self) -> None:
        container = ttk.Frame(self.output_tab)
        container.pack(fill="both", expand=True)
        self.output = tk.Text(container, wrap="word", bg="#020617", fg="#ddd6fe", insertbackground="white", relief="flat", highlightthickness=1, highlightbackground="#334155", font=("Consolas", 11))
        output_scroll = ttk.Scrollbar(container, orient="vertical", command=self.output.yview)
        self.output.configure(yscrollcommand=output_scroll.set)
        self.output.pack(side="left", fill="both", expand=True)
        output_scroll.pack(side="right", fill="y")

    def _set_defaults(self) -> None:
        self.set_widget_value("case_id", "CRYPTOINT-CASE-001")
        self.set_widget_value("task_id", "CRYPTOINT-TASK-001")
        self.set_widget_value("objective", "Analyze lawful/authorized/defensive blockchain intelligence using evidence-first methods.")
        self.set_widget_value("target", "Illustrative example.com / authorized blockchain context")
        self.set_widget_value("target_type", "transaction_tracing")
        self.set_widget_value("questions", "\n".join(default_questions({"target": "Illustrative example.com"})))
        
        for field in LIST_FIELDS.union(DICT_FIELDS):
            if field not in ["questions", "scope", "authorization", "time_range"]:
                 self.set_widget_value(field, "")
                 
        self.set_widget_value("time_range", json.dumps({"from": "", "to": "", "timezone": "UTC"}, indent=2))
        self.set_widget_value("scope", json.dumps({"allowed_sources": ["public explorers", "authorized RPCs"], "prohibited_actions": ["sign tx", "use keys"]}, indent=2))
        self.set_widget_value("authorization", json.dumps({"basis": "lawful defensive investigation"}, indent=2))
        self.set_widget_value("configured_connectors", "None configured.")

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
            if key in LIST_FIELDS: payload[key] = parse_list(raw)
            elif key in DICT_FIELDS: payload[key] = parse_dict(raw)
            else: payload[key] = raw
        payload["generated_at"] = now_utc()
        payload["panel_version"] = APP_VERSION
        payload["operating_mode"] = "PLANNING_ONLY_DEFENSIVE_LAWFUL_AUTHORIZED"
        return payload

    def _append_paths(self, field: str, paths: Tuple[str, ...], title: str) -> None:
        if not paths: return
        current = self.get_widget_value(field)
        added = "\n".join(paths)
        new_value = current + ("\n" if current else "") + added
        self.set_widget_value(field, new_value)
        messagebox.showinfo(title, f"{len(paths)} path(s) added.")

    def add_chain_data(self): self._append_paths("chain_data_paths", filedialog.askopenfilenames(title="Select Chain Data", filetypes=[("Data", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_tx_exports(self): self._append_paths("tx_export_paths", filedialog.askopenfilenames(title="Select Tx Exports", filetypes=[("Exports", "*.json *.csv"), ("All", "*.*")]), "Added")
    def add_address_labels(self): self._append_paths("address_label_paths", filedialog.askopenfilenames(title="Select Labels", filetypes=[("Labels", "*.json *.csv"), ("All", "*.*")]), "Added")
    def add_token_metadata(self): self._append_paths("token_metadata_paths", filedialog.askopenfilenames(title="Select Tokens", filetypes=[("Metadata", "*.json"), ("All", "*.*")]), "Added")
    def add_bridge_logs(self): self._append_paths("bridge_log_paths", filedialog.askopenfilenames(title="Select Bridges", filetypes=[("Logs", "*.json *.csv"), ("All", "*.*")]), "Added")

    def run_policy_screen(self) -> None:
        payload = self.collect_payload()
        policy = policy_screen(payload)
        result = {"mode": "POLICY_SCREEN_ONLY", "policy_screen": policy}
        self.last_result = result
        self._write_output(result)
        self.notebook.select(self.output_tab)
        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning("Blocked", "Policy Blocked.")
        elif policy["status"] == "HUMAN_REVIEW_REQUIRED":
            messagebox.showwarning("Review", "Human Review Required.")
        else:
            messagebox.showinfo("OK", "Allowed.")

    def analyze_local_crypto(self) -> None:
        payload = self.collect_payload()
        policy = policy_screen(payload)
        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning("Blocked", "Analysis blocked.")
            return

        path_fields = ["chain_data_paths", "tx_export_paths", "address_label_paths", "token_metadata_paths", "bridge_log_paths"]
        all_paths = []
        seen = set()
        for field in path_fields:
            for p in payload.get(field, []):
                sp = str(p).strip()
                if sp and sp not in seen:
                    seen.add(sp)
                    all_paths.append(sp)

        if not all_paths:
            messagebox.showwarning("No Evidence", "Add files first.")
            return

        self.output.delete("1.0", "end")
        self.output.insert("1.0", "Analyzing...\n")
        self.notebook.select(self.output_tab)

        files = []
        parsed_list = []
        for p in all_paths[:30]:
            f, parsed = analyze_crypto_file(p, payload.get("case_id", ""), payload.get("task_id", ""))
            files.append(f)
            parsed_list.append(parsed)

        aggregated = finalize_parsed(aggregate_parsed(parsed_list), payload, files)
        self.analyzed_files = files
        self.parsed = aggregated

        report = self._build_local_analysis_report(files, aggregated, payload, policy)
        self.last_result = report
        self._write_output(report)
        
        messagebox.showinfo("Done", f"Parsed {len(files)} files.\nAddresses: {len(aggregated['addresses'])}\nTxns: {len(aggregated['transactions'])}")

    def generate_plan(self) -> None:
        payload = self.collect_payload()
        warnings = validate_payload(payload)
        policy = policy_screen(payload)
        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning("Blocked", "Plan blocked.")
            return

        questions = payload.get("questions") or default_questions(payload)
        if not self.parsed.get("addresses") and not self.parsed.get("transactions"):
            self.parsed = finalize_parsed(empty_parsed(), payload, self.analyzed_files)

        next_action = build_next_best_action(payload, policy, self.analyzed_files, self.parsed)
        collection_plan = build_collection_plan(payload, questions, self.analyzed_files, self.parsed)

        result = {
            "mode": "PLANNING_PLUS_LOCAL_DETERMINISTIC_EVIDENCE" if self.analyzed_files else "PLANNING_ONLY",
            "policy_screen": policy,
            "warnings": warnings,
            "payload": payload,
            "evidence_inventory": self.analyzed_files,
            "addresses_preview": self.parsed.get("addresses", [])[:100],
            "transactions_preview": self.parsed.get("transactions", [])[:100],
            "clusters_preview": self.parsed.get("clusters", [])[:50],
            "flows_preview": self.parsed.get("flows", [])[:100],
            "hypotheses": self.parsed.get("hypotheses", []),
            "knowledge_gaps": self.parsed.get("knowledge_gaps", []),
            "next_best_action": next_action,
            "collection_plan": collection_plan,
        }
        self.last_result = result
        self._write_output(result)
        self.notebook.select(self.output_tab)

    def _build_local_analysis_report(self, files, parsed, payload, policy) -> Dict[str, Any]:
        return {
            "mode": "LOCAL_DETERMINISTIC_CRYPTOINT_ANALYSIS",
            "policy_screen": policy,
            "evidence_inventory": files,
            "addresses": parsed.get("addresses", [])[:300],
            "transactions": parsed.get("transactions", [])[:300],
            "clusters": parsed.get("clusters", [])[:100],
            "flows": parsed.get("flows", [])[:300],
            "hypotheses": parsed.get("hypotheses", []),
            "contradictions": parsed.get("contradictions", []),
            "limitations": [
                "No private keys used.",
                "No transactions signed.",
                "Addresses are not persons.",
                "Clusters are hypotheses.",
            ],
        }

    def _write_output(self, result: Dict[str, Any]) -> None:
        self.output.delete("1.0", "end")
        self.output.insert("1.0", json.dumps(result, ensure_ascii=False, indent=2, default=str))

    def export_json(self) -> None:
        if not self.last_result: self.generate_plan()
        data = self.last_result
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
            messagebox.showinfo("Saved", path)

    def copy_output(self) -> None:
        text = self.output.get("1.0", "end-1c").strip()
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            messagebox.showinfo("Copied", "Output copied.")

    def clear_form(self) -> None:
        if messagebox.askyesno("Confirm", "Clear all?"):
            self._set_defaults()
            self.output.delete("1.0", "end")
            self.last_result = {}
            self.analyzed_files = []
            self.parsed = empty_parsed()


if __name__ == "__main__":
    try:
        app = TraceAtlasCRYPTOINTPanel()
        app.mainloop()
    except tk.TclError as exc:
        print(f"GUI Error: {exc}")
        print("Logic usable as library.")