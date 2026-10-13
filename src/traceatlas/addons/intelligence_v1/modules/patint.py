#!/usr/bin/env python3
"""PATINT mini-engine: compact Python skeleton for lawful patent-intelligence workflows."""
from __future__ import annotations
import re, json, hashlib
from datetime import datetime, timezone

VERSION = "0.1.0"
MODES = {"LOCAL_ONLY", "HYBRID", "CLOUD"}
HARMFUL_KEYWORDS = {"weapon", "weapons", "explosive", "cbrn", "chemical weapon", "biological weapon", "radiological", "nuclear", "targeting", "delivery system", "missile"}
LEGAL_TRIGGER_WORDS = {"infringe", "infringement", "invalid", "invalidity", "fto", "freedom to operate", "license", "licensing", "royalty", "litigation", "enforceability", "estoppel", "claim construction"}
LIMITATIONS = [
    "Skeleton engine: no live patent-office retrieval is performed.",
    "Legal status is temporal and source-bound; check official registers as of report date.",
    "No infringement, validity, enforceability, or licensing conclusions are issued.",
    "PCT publications are not worldwide patents; national/regional phase must be resolved.",
    "Specification disclosure is not claimed scope; claims define legal scope subject to law.",
]

def sha(value: str) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]

def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def norm_id(raw: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", (raw or "").upper())

def infer_kind(raw: str) -> str:
    n = norm_id(raw)
    if n.startswith("WO"):
        return "PCT_PUB"
    if re.search(r"A\d{1,2}$", n):
        return "APP_PUB"
    if re.search(r"(B|C)\d{1,2}$", n):
        return "GRANT"
    return "UNKNOWN"

def infer_jurisdiction(raw: str) -> str | None:
    m = re.match(r"^([A-Z]{2})", norm_id(raw))
    return m.group(1) if m else None

def make_evidence(source_id: str, source_type: str, jurisdiction: str | None, patent_ref: str | None,
                  content: str, published_at: str | None = None, pedigree: list[str] | None = None) -> dict:
    return {
        "evidence_id": "EV-" + sha(source_id + content),
        "source_id": source_id,
        "source_type": source_type,
        "jurisdiction": jurisdiction,
        "patent_ref": patent_ref,
        "published_at": published_at,
        "retrieved_at": now(),
        "content": content,
        "content_hash": sha(content),
        "pedigree": pedigree or [source_type],
    }

def normalize_document(d: dict) -> dict:
    d = dict(d)
    d.setdefault("patent_document_id", "DOC-" + sha(d.get("document_number", "")))
    d.setdefault("document_number", "")
    d.setdefault("jurisdiction", infer_jurisdiction(d.get("document_number", "")))
    d.setdefault("document_kind", infer_kind(d.get("document_number", "")))
    d.setdefault("title", None)
    d.setdefault("abstract", None)
    d.setdefault("filing_date", None)
    d.setdefault("publication_date", None)
    d.setdefault("grant_date", None)
    d.setdefault("priority_dates", [])
    d.setdefault("inventors", [])
    d.setdefault("applicants", [])
    d.setdefault("assignees", [])
    d.setdefault("classifications", [])
    d.setdefault("evidence_ids", [])
    d.setdefault("legal_status", "UNKNOWN")
    d.setdefault("confidence", {})
    if not d.get("claims") and d.get("claims_text"):
        d["claims"] = parse_claims(d["claims_text"], d.get("claim_version", "AS_FILED"))
    d.setdefault("claims", [])
    return d

def make_document(document_number: str, **kwargs) -> dict:
    return normalize_document({"document_number": document_number, **kwargs})

def parse_claims(text: str, version: str = "AS_FILED") -> list[dict]:
    claims = []
    if not text:
        return claims
    chunks = re.split(r"(?m)^\s*(\d+)\.\s+", text)
    for i in range(1, len(chunks), 2):
        try:
            num = int(chunks[i])
        except Exception:
            continue
        body = (chunks[i + 1] if i + 1 < len(chunks) else "").strip()
        parents = []
        pm = re.search(r"claims?\s+((?:\d+\s*(?:and|or)?\s*)+)", body, flags=re.I)
        if pm:
            parents = sorted({int(x) for x in re.findall(r"\d+", pm.group(1))})
        ctype = "dependent" if parents else "independent"
        elements = [p.strip() for p in re.split(r";|\.\s+(?=A |An |The |Said |Wherein )", body) if p.strip()]
        claims.append({
            "claim_number": num,
            "type": ctype,
            "text": body,
            "parents": parents,
            "version": version,
            "status": "parsed",
            "elements": elements,
        })
    return claims

def claim_tree(claims: list[dict]) -> dict:
    edges = {c["claim_number"]: c.get("parents", []) for c in claims}
    independent = [c["claim_number"] for c in claims if c["type"] == "independent"]
    dependent = [c["claim_number"] for c in claims if c["type"] == "dependent"]
    return {"roots": independent, "edges": edges, "independent_count": len(independent), "dependent_count": len(dependent)}

def priority_chain(doc: dict) -> dict:
    dates = sorted({x for x in doc.get("priority_dates", []) if x})
    filing = doc.get("filing_date")
    earliest = dates[0] if dates else filing
    return {"earliest_claimed_priority": earliest, "priority_dates": dates, "filing_date": filing,
            "note": "Priority claim recorded; validity not adjudicated."}

def build_families(docs: list[dict]) -> list[dict]:
    fam = {}
    for d in docs:
        pc = priority_chain(d)
        key = tuple(pc["priority_dates"] or ([pc["filing_date"]] if pc["filing_date"] else []))
        if not key:
            key = ("UNRESOLVED", d["patent_document_id"])
        fid = "FAM-" + sha("|".join(key))
        fam.setdefault(fid, {"family_id": fid, "family_type": "SIMPLE", "method": "same_earliest_priority_set",
                             "priority_set": list(key), "members": []})
        fam[fid]["members"].append(d["patent_document_id"])
    return list(fam.values())

def ownership_timeline(doc: dict) -> list[dict]:
    events = []
    for app in doc.get("applicants", []):
        events.append({"date": doc.get("filing_date"), "actor": app, "relationship": "APPLICANT",
                       "source_evidence_ids": doc.get("evidence_ids", [])})
    for a in doc.get("assignees", []):
        events.append({"date": a.get("effective_date") or a.get("record_date"), "actor": a.get("name"),
                       "relationship": a.get("type", "ASSIGNMENT"), "details": a,
                       "source_evidence_ids": doc.get("evidence_ids", [])})
    events.sort(key=lambda x: x.get("date") or "")
    return events

def assess_legal_status(doc: dict, as_of: str | None = None) -> dict:
    as_of = as_of or now()
    status = doc.get("legal_status", "UNKNOWN")
    notes = []
    if status == "UNKNOWN":
        if doc.get("grant_date"):
            status = "GRANTED"
            notes.append("Grant date observed; active/enforceability not confirmed.")
        elif doc.get("publication_date"):
            status = "PENDING"
            notes.append("Publication observed; prosecution status not confirmed.")
    return {"status": status, "as_of": as_of, "notes": notes, "temporal": True,
            "source_bound": bool(doc.get("evidence_ids"))}

def source_reliability(ev: dict) -> str:
    st = (ev.get("source_type") or "").lower()
    if any(k in st for k in ["official", "wipo", "patent_office", "register", "court"]):
        return "HIGH"
    if any(k in st for k in ["commercial", "database", "platform"]):
        return "MEDIUM"
    if any(k in st for k in ["company", "announcement", "filing"]):
        return "MEDIUM_LOW"
    return "LOW"

def source_independence(evidences: list[dict]) -> dict:
    root_of, by_root = {}, {}
    for e in evidences:
        root = (e.get("pedigree") or [e.get("source_type", "unknown")])[0]
        root_of[e["evidence_id"]] = root
        by_root.setdefault(root, []).append(e["evidence_id"])
    pairs = []
    ids = list(root_of.keys())
    for i, a in enumerate(ids):
        for b in ids[i + 1:]:
            pairs.append({"evidence_a": a, "evidence_b": b,
                          "state": "INDEPENDENT" if root_of[a] != root_of[b] else "DEPENDENT",
                          "root_a": root_of[a], "root_b": root_of[b]})
    return {"by_root": by_root, "pairs": pairs, "note": "Multiple copies of same office record are not independent."}

def fact_gate(docs: list[dict], evidences: list[dict], questions: list[str]) -> dict:
    ev_ids = {e["evidence_id"] for e in evidences}
    issues, candidate_facts, unknowns = [], [], []
    for d in docs:
        num = d.get("document_number") or d["patent_document_id"]
        if not d.get("evidence_ids"):
            issues.append({"severity": "HIGH", "message": f"{num}: no evidence linked"})
        else:
            missing = [e for e in d["evidence_ids"] if e not in ev_ids]
            if missing:
                issues.append({"severity": "HIGH", "message": f"{num}: missing evidence ids {missing}"})
        if d.get("document_kind") == "UNKNOWN":
            issues.append({"severity": "MEDIUM", "message": f"{num}: document kind unresolved"})
        if not d.get("jurisdiction"):
            issues.append({"severity": "HIGH", "message": f"{num}: jurisdiction unresolved"})
        pc = d.get("priority_chain") or priority_chain(d)
        if not pc.get("earliest_claimed_priority"):
            issues.append({"severity": "MEDIUM", "message": f"{num}: earliest priority unresolved"})
        else:
            candidate_facts.append({"type": "EARLIEST_CLAIMED_PRIORITY", "value": pc["earliest_claimed_priority"],
                                    "document": num, "evidence_ids": d.get("evidence_ids", []),
                                    "status": "RECORDED_NOT_ADJUDICATED"})
        if not d.get("claims"):
            issues.append({"severity": "MEDIUM", "message": f"{num}: claims not available"})
        else:
            ct = d.get("claim_tree") or claim_tree(d["claims"])
            candidate_facts.append({"type": "CLAIM_STRUCTURE", "value": f"{ct['independent_count']} independent / {ct['dependent_count']} dependent",
                                    "document": num, "evidence_ids": d.get("evidence_ids", []), "status": "PARSED"})
        status = d.get("legal_status_assessment", {}).get("status") or d.get("legal_status", "UNKNOWN")
        if status == "UNKNOWN":
            unknowns.append(f"{num}: legal status unknown as of source")
        else:
            candidate_facts.append({"type": "LEGAL_STATUS", "value": status, "document": num,
                                    "evidence_ids": d.get("evidence_ids", []), "status": "SOURCE_REPORTED_TEMPORAL"})
        latest = None
        for a in d.get("assignees", []):
            if not latest or (a.get("effective_date") or "") >= (latest.get("effective_date") or ""):
                latest = a
        if latest:
            candidate_facts.append({"type": "LATEST_ASSIGNEE_CANDIDATE", "value": latest.get("name"),
                                    "document": num, "effective_date": latest.get("effective_date"),
                                    "evidence_ids": d.get("evidence_ids", []),
                                    "status": "CANDIDATE_NOT_CURRENT_OWNER_UNLESS_OFFICIAL"})
    qtxt = " ".join(questions).lower()
    if any(w in qtxt for w in LEGAL_TRIGGER_WORDS):
        issues.append({"severity": "INFO", "message": "Legal conclusion requested; route to LEGALINT/human counsel."})
    return {"pass": not any(i["severity"] == "HIGH" for i in issues), "issues": issues,
            "candidate_facts": candidate_facts, "unknowns": unknowns}

def dual_ai_review(analysis: dict, fg: dict) -> dict:
    docs = analysis.get("documents", [])
    primary = {"summary": f"Primary analyst resolved {len(docs)} documents and {len(analysis.get('families', []))} families.",
               "risk": "MEDIUM" if fg.get("issues") else "LOW"}
    checks = []
    if any(i.get("severity") == "HIGH" for i in fg.get("issues", [])):
        checks.append("High-severity fact-gate issues remain.")
    if not docs:
        checks.append("No documents supplied.")
    for d in docs:
        num = d.get("document_number")
        status = d.get("legal_status_assessment", {}).get("status")
        if d.get("document_kind") == "APP_PUB" and status == "GRANTED":
            checks.append(f"{num}: application publication treated as granted without grant document.")
        if status == "UNKNOWN":
            checks.append(f"{num}: legal status unresolved.")
        if not d.get("claims"):
            checks.append(f"{num}: claim scope unavailable.")
        if not d.get("evidence_ids"):
            checks.append(f"{num}: no source evidence.")
    if not checks:
        agreement = "AGREE"
    elif any("High-severity" in c or "unresolved" in c or "no source" in c for c in checks):
        agreement = "INSUFFICIENT_EVIDENCE"
    else:
        agreement = "PARTIAL_AGREEMENT"
    return {"primary": primary, "skeptic": {"checks": checks}, "agreement": agreement,
            "note": "AI agreement is not independent patent corroboration."}

def safety_flags(docs: list[dict]) -> list[dict]:
    flags = []
    for d in docs:
        blob = " ".join(str(x) for x in [d.get("title"), d.get("abstract"), " ".join(map(str, d.get("classifications", [])))]).lower()
        if any(k in blob for k in HARMFUL_KEYWORDS):
            flags.append({"document": d.get("document_number"), "flag": "HARMFUL_TECHNOLOGY_BOUNDARY",
                          "action": "high_level_bibliographic_only"})
    return flags

def legal_review_flags(questions: list[str], analysis: dict) -> list[str]:
    q = " ".join(questions).lower()
    flags = []
    if any(w in q for w in LEGAL_TRIGGER_WORDS):
        flags.append("LEGAL_REVIEW_REQUIRED")
    if any(d.get("legal_status_assessment", {}).get("status") in {"GRANTED", "ACTIVE"} for d in analysis.get("documents", [])):
        flags.append("ACTIVE_RIGHTS_NEED_LEGAL_CONTEXT")
    if any(d.get("document_kind") == "PCT_PUB" for d in analysis.get("documents", [])):
        flags.append("PCT_NOT_WORLDWIDE_PATENT")
    return flags

def build_graph(docs: list[dict], families: list[dict], evidences: list[dict]) -> dict:
    nodes, edges = {}, []
    def add_node(nid, ntype, props):
        nodes[nid] = {"id": nid, "type": ntype, "props": props}
    for e in evidences:
        add_node(e["evidence_id"], "Evidence", {k: v for k, v in e.items() if k != "content"})
    for d in docs:
        did = d["patent_document_id"]
        add_node(did, "PatentDocument", {"number": d.get("document_number"), "kind": d.get("document_kind"),
                                         "jurisdiction": d.get("jurisdiction"),
                                         "status": d.get("legal_status_assessment", {}).get("status")})
        for ev in d.get("evidence_ids", []):
            edges.append({"from": did, "rel": "SUPPORTED_BY", "to": ev})
        for inv in d.get("inventors", []):
            iid = "INV-" + sha(inv)
            add_node(iid, "Inventor", {"name": inv})
            edges.append({"from": did, "rel": "INVENTED_BY", "to": iid})
        for app in d.get("applicants", []):
            aid = "APP-" + sha(app)
            add_node(aid, "Applicant", {"name": app})
            edges.append({"from": did, "rel": "FILED_BY", "to": aid})
        for a in d.get("assignees", []):
            name = a.get("name") or "UNKNOWN"
            sid = "ASSIGNEE-" + sha(name)
            add_node(sid, "Assignee", {"name": name})
            edges.append({"from": did, "rel": "ASSIGNED_TO", "to": sid,
                          "props": {"effective_date": a.get("effective_date"), "type": a.get("type")}})
        for cls in d.get("classifications", []):
            cid = "CLASS-" + sha(str(cls))
            add_node(cid, "Classification", {"code": cls})
            edges.append({"from": did, "rel": "CLASSIFIED_AS", "to": cid})
        for c in d.get("claims", []):
            cid = did + "-C" + str(c["claim_number"])
            add_node(cid, "Claim", {"number": c["claim_number"], "type": c["type"], "version": c.get("version")})
            edges.append({"from": did, "rel": "HAS_CLAIM", "to": cid})
            for p in c.get("parents", []):
                edges.append({"from": cid, "rel": "DEPENDS_ON_CLAIM", "to": did + "-C" + str(p)})
        pc = d.get("priority_chain") or priority_chain(d)
        ep = pc.get("earliest_claimed_priority")
        if ep:
            pid = "PRIO-" + sha(ep)
            add_node(pid, "PriorityApplication", {"date": ep})
            edges.append({"from": did, "rel": "CLAIMS_PRIORITY_TO", "to": pid})
    for f in families:
        add_node(f["family_id"], "PatentFamily", {"method": f["method"], "priority_set": f["priority_set"]})
        for m in f["members"]:
            edges.append({"from": m, "rel": "MEMBER_OF_FAMILY", "to": f["family_id"]})
    return {"nodes": list(nodes.values()), "edges": edges}

def portfolio_counts(docs: list[dict], families: list[dict]) -> dict:
    kinds = [d.get("document_kind") for d in docs]
    statuses = [d.get("legal_status_assessment", {}).get("status") for d in docs]
    return {"DOCUMENT_COUNT": len(docs), "FAMILY_COUNT": len(families),
            "APPLICATION_COUNT": sum(1 for k in kinds if k in {"APP_PUB", "PCT_PUB"}),
            "GRANT_COUNT": sum(1 for k in kinds if k == "GRANT"),
            "UNKNOWN_STATUS_COUNT": sum(1 for s in statuses if s == "UNKNOWN")}

def next_best_actions(fg: dict, docs: list[dict]) -> list[str]:
    actions = []
    if any(i["severity"] == "HIGH" for i in fg.get("issues", [])):
        actions.append("Retrieve official legal-status and assignment records for unresolved identifiers.")
    for d in docs:
        if d.get("document_kind") == "PCT_PUB":
            actions.append(f"Resolve national-phase entries for {d['document_number']}; PCT is not a worldwide patent.")
        if not d.get("claims"):
            actions.append(f"Obtain claim text for {d['document_number']} before scope analysis.")
        if d.get("legal_status_assessment", {}).get("status") == "UNKNOWN":
            actions.append(f"Check current register status for {d['document_number']} as of report date.")
    if not actions:
        actions.append("Perform evidence-linked claim-element review if FTO/infringement questions arise.")
    return list(dict.fromkeys(actions))

def knowledge_gaps(fg: dict, docs: list[dict]) -> list[dict]:
    gaps = []
    for u in fg.get("unknowns", []):
        gaps.append({"gap": u, "importance": "HIGH", "recommended_source": "official_legal_status_register"})
    for d in docs:
        if d.get("document_kind") == "PCT_PUB":
            gaps.append({"gap": f"{d['document_number']} national phases unknown", "importance": "MEDIUM",
                         "recommended_source": "WIPO/national office"})
        if not d.get("assignees"):
            gaps.append({"gap": f"{d['document_number']} assignment history unknown", "importance": "MEDIUM",
                         "recommended_source": "official_assignment_register"})
    return gaps

def specialist_handoffs(legal_flags: list[str], docs: list[dict]) -> list[dict]:
    h = []
    if "LEGAL_REVIEW_REQUIRED" in legal_flags:
        h.append({"to": "LEGALINT", "reason": "infringement/validity/FTO legal interpretation"})
    if any(d.get("assignees") for d in docs):
        h.append({"to": "CORPINT", "reason": "verify corporate identity of assignees"})
    h.append({"to": "TECHINT", "reason": "validate product implementation if product mapping needed"})
    return h

def jarvis_brief(r: dict) -> str:
    docs = r.get("documents", [])
    fams = r.get("families", [])
    fg = r.get("fact_gate", {})
    unknowns = fg.get("unknowns", [])[:2]
    return (f"Resolved {len(docs)} documents into {len(fams)} simple families. "
            f"Fact gate pass={fg.get('pass')}. "
            "No infringement or invalidity determination was made. "
            + (f"Top unknowns: {'; '.join(unknowns)}." if unknowns else ""))

def render_markdown(r: dict) -> str:
    out = []
    out.append(f"# PATINT Report — {r.get('case_id', 'CASE')}")
    out.append(f"Mode: {r.get('mode')} | As of: {r.get('as_of')} | Engine: {VERSION}\n")
    out.append("## JARVIS Brief")
    out.append(r.get("jarvis_brief", "") + "\n")
    out.append("## Documents")
    for d in r.get("documents", []):
        status = d.get("legal_status_assessment", {}).get("status")
        out.append(f"- `{d.get('document_number')}` kind=`{d.get('document_kind')}` jurisdiction=`{d.get('jurisdiction')}` status=`{status}`")
        out.append(f"  - Title: {d.get('title')}")
        out.append(f"  - Earliest claimed priority: {d.get('priority_chain', {}).get('earliest_claimed_priority')}")
        ct = d.get("claim_tree", {})
        out.append(f"  - Claims: {ct.get('independent_count', 0)} independent, {ct.get('dependent_count', 0)} dependent")
        if d.get("current_owner_candidate"):
            out.append(f"  - Current owner candidate: {d['current_owner_candidate']} ({d.get('current_owner_state')})")
    out.append("\n## Families")
    for f in r.get("families", []):
        out.append(f"- `{f['family_id']}` method={f['method']} priority={f['priority_set']} members={f['members']}")
    out.append("\n## Portfolio Counts")
    out.append("```json\n" + json.dumps(r.get("portfolio_counts", {}), indent=2) + "\n```")
    out.append("\n## Fact Gate")
    out.append(f"Pass: {r.get('fact_gate', {}).get('pass')}")
    for i in r.get("fact_gate", {}).get("issues", []):
        out.append(f"- [{i.get('severity')}] {i.get('message')}")
    out.append("\n## Candidate Facts")
    for cf in r.get("fact_gate", {}).get("candidate_facts", [])[:20]:
        out.append(f"- {cf.get('type')}: {cf.get('value')} ({cf.get('status')})")
    out.append("\n## Dual-AI Review")
    out.append(f"Agreement: {r.get('dual_ai', {}).get('agreement')}")
    for c in r.get("dual_ai", {}).get("skeptic", {}).get("checks", []):
        out.append(f"- Skeptic: {c}")
    out.append("\n## Safety / Legal Flags")
    for sf in r.get("safety_flags", []):
        out.append(f"- Safety: {sf.get('flag')} on {sf.get('document')} -> {sf.get('action')}")
    for lf in r.get("legal_review_flags", []):
        out.append(f"- Legal: {lf}")
    out.append("\n## Recommended Next Actions")
    for a in r.get("recommended_next_actions", []):
        out.append(f"- {a}")
    out.append("\n## Knowledge Gaps")
    for g in r.get("knowledge_gaps", []):
        out.append(f"- [{g.get('importance')}] {g.get('gap')} -> {g.get('recommended_source')}")
    out.append("\n## Specialist Handoffs")
    for h in r.get("specialist_handoffs", []):
        out.append(f"- {h.get('to')}: {h.get('reason')}")
    out.append("\n## Source Independence")
    out.append("```json\n" + json.dumps(r.get("source_independence", {}).get("by_root", {}), indent=2) + "\n```")
    out.append("\n## Knowledge Graph Summary")
    g = r.get("graph", {})
    out.append(f"Nodes: {len(g.get('nodes', []))}, Edges: {len(g.get('edges', []))}")
    out.append("\n## Limitations")
    for l in r.get("limitations", []):
        out.append(f"- {l}")
    out.append("\n## Replay Manifest")
    out.append("```json\n" + json.dumps(r.get("replay_manifest", {}), indent=2, default=str) + "\n```")
    return "\n".join(out)

class PATINTAgent:
    def __init__(self, mode: str = "LOCAL_ONLY", authorized_source_types: list[str] | None = None):
        if mode not in MODES:
            raise ValueError(f"mode must be one of {sorted(MODES)}")
        self.mode = mode
        self.authorized_source_types = authorized_source_types or [
            "official_patent_office", "official_wipo_record", "official_assignment_register",
            "official_legal_status_register", "public_court_decision", "public_standards_database",
            "authorized_commercial_patent_platform"
        ]

    def analyze(self, case: dict) -> dict:
        case = dict(case)
        case.setdefault("mode", self.mode)
        as_of = case.get("as_of") or now()

        evidences = [dict(e) for e in case.get("evidences", [])]
        for e in evidences:
            e.setdefault("evidence_id", "EV-" + sha(e.get("source_id", "") + e.get("content", "")))
            e.setdefault("retrieved_at", now())
            e.setdefault("content_hash", sha(e.get("content", "")))
            e["reliability"] = source_reliability(e)
            if e.get("source_type") not in self.authorized_source_types:
                e["authorization_warning"] = "SOURCE_NOT_AUTHORIZED_OR_UNCONFIGURED"

        docs = [normalize_document(d) for d in case.get("documents", [])]
        for d in docs:
            d["priority_chain"] = priority_chain(d)
            d["claim_tree"] = claim_tree(d.get("claims", []))
            d["ownership_timeline"] = ownership_timeline(d)
            d["legal_status_assessment"] = assess_legal_status(d, as_of)
            owner_events = [ev for ev in d["ownership_timeline"] if ev.get("relationship") != "APPLICANT"]
            d["current_owner_candidate"] = owner_events[-1]["actor"] if owner_events else (d["applicants"][0] if d["applicants"] else None)
            d["current_owner_state"] = "OFFICIAL_RECORD_SUPPORTED" if d["evidence_ids"] and owner_events else ("PROBABLE" if d["applicants"] else "UNKNOWN")

        families = build_families(docs)
        questions = case.get("questions", [])
        fg = fact_gate(docs, evidences, questions)
        analysis = {"documents": docs, "families": families, "as_of": as_of}
        dar = dual_ai_review(analysis, fg)
        graph = build_graph(docs, families, evidences)
        legal_flags = legal_review_flags(questions, analysis)

        result = {
            "case_id": case.get("case_id"),
            "task_id": case.get("task_id"),
            "objective": case.get("objective"),
            "questions": questions,
            "mode": case.get("mode"),
            "as_of": as_of,
            "documents": docs,
            "families": families,
            "evidences": [{k: v for k, v in e.items() if k != "content"} for e in evidences],
            "fact_gate": fg,
            "dual_ai": dar,
            "graph": graph,
            "safety_flags": safety_flags(docs),
            "legal_review_flags": legal_flags,
            "recommended_next_actions": next_best_actions(fg, docs),
            "knowledge_gaps": knowledge_gaps(fg, docs),
            "specialist_handoffs": specialist_handoffs(legal_flags, docs),
            "source_independence": source_independence(evidences),
            "portfolio_counts": portfolio_counts(docs, families),
            "limitations": LIMITATIONS.copy(),
            "replay_manifest": {
                "engine_version": VERSION,
                "pipeline": ["normalize_document", "priority_chain", "claim_tree", "ownership_timeline",
                             "legal_status", "family", "fact_gate", "dual_ai", "graph", "report"],
                "evidence_hashes": {e["evidence_id"]: e["content_hash"] for e in evidences},
                "document_hashes": {
                    d["patent_document_id"]: sha(json.dumps(
                        {k: v for k, v in d.items() if k not in {"priority_chain", "claim_tree", "ownership_timeline", "legal_status_assessment"}},
                        sort_keys=True, default=str)) for d in docs
                },
                "claim_versions": {d["patent_document_id"]: [c.get("version") for c in d.get("claims", [])] for d in docs},
                "family_method": "simple_family_same_priority_set",
            },
        }
        result["jarvis_brief"] = jarvis_brief(result)
        return result

if __name__ == "__main__":
    e1 = make_evidence("USPTO-PALM", "official_patent_office", "US", "US20240000001A1",
                       "USPTO record: application publication, applicant Acme, priority 2022-06-01.",
                       published_at="2024-01-01", pedigree=["USPTO"])
    e2 = make_evidence("WIPO-PCT", "official_wipo_record", "WO", "WO2023111111A1",
                       "WIPO PCT publication, priority 2022-06-01.",
                       published_at="2023-06-08", pedigree=["WIPO"])
    e3 = make_evidence("USPTO-PALM", "official_patent_office", "US", "US11999999B2",
                       "USPTO record: grant, assignee Acme, status payable.",
                       published_at="2024-05-01", pedigree=["USPTO"])

    d1 = make_document("US20240000001A1", title="Widget controller", abstract="Controls widgets.",
                       claims_text="1. A method comprising determining a widget state and adjusting power.\n2. The method of claim 1, wherein the adjusting uses a fuzzy rule.",
                       filing_date="2023-06-01", publication_date="2024-01-01", priority_dates=["2022-06-01"],
                       inventors=["Alice Example"], applicants=["Acme Inc."],
                       assignees=[{"name": "Acme Inc.", "effective_date": "2023-01-01", "type": "initial"}],
                       legal_status="PENDING", evidence_ids=[e1["evidence_id"]], classifications=["G05B19/042"])

    d2 = make_document("WO2023111111A1", title="Widget controller", abstract="PCT widget control.",
                       claims_text="1. A system comprising a controller configured to adjust power based on widget state.",
                       filing_date="2023-06-01", publication_date="2023-06-08", priority_dates=["2022-06-01"],
                       inventors=["Alice Example"], applicants=["Acme Inc."], legal_status="PENDING",
                       evidence_ids=[e2["evidence_id"]], classifications=["G05B19/042"])

    d3 = make_document("US11999999B2", title="Widget controller", abstract="Granted widget control.",
                       claims_text="1. A method comprising determining a widget state, adjusting power, and logging the adjustment.\n2. The method of claim 1, wherein logging occurs in a secure enclave.",
                       filing_date="2023-06-01", grant_date="2024-05-01", priority_dates=["2022-06-01"],
                       inventors=["Alice Example"], applicants=["Acme Inc."],
                       assignees=[{"name": "Acme Inc.", "effective_date": "2023-01-01", "type": "initial"},
                                  {"name": "Beta Holdings LLC", "effective_date": "2025-02-01", "type": "assignment"}],
                       legal_status="GRANTED", evidence_ids=[e3["evidence_id"]], classifications=["G05B19/042"])

    case = {
        "case_id": "CASE-001",
        "task_id": "T-001",
        "objective": "Resolve family, ownership, claims, status",
        "questions": ["What is earliest priority?", "Does family include PCT?", "Who is latest assignee?", "Is there FTO concern?"],
        "mode": "LOCAL_ONLY",
        "as_of": "2026-10-09",
        "evidences": [e1, e2, e3],
        "documents": [d1, d2, d3],
    }

    agent = PATINTAgent(mode="LOCAL_ONLY")
    result = agent.analyze(case)
    print(render_markdown(result))