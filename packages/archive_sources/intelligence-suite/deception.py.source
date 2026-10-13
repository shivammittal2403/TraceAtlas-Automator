# deceptionint_short_main.py
# Defensive DECEPTIONINT skeleton:
# Analyze deception/manipulation INDICATORS only.
# DO NOT create deception, disinformation, propaganda, fake personas, pretexting,
# astroturfing, microtargeting, forged evidence, or manipulative persuasion.
# Contradiction/falsehood != deception. Intent requires separate evidence.

import json
import re
import hashlib
import itertools
from datetime import datetime, timezone
from collections import defaultdict
from difflib import SequenceMatcher

# -----------------------------
# Constants / boundaries
# -----------------------------

NOW = lambda: datetime.now(timezone.utc).isoformat()

HARMFUL_ACTION_RE = re.compile(
    r"\b(create|make|design|generate|produce|optimize|run|execute|operate|teach|coach|train|help me)\b",
    re.IGNORECASE,
)

HARMFUL_TARGET_RE = re.compile(
    r"\b(deception|disinformation|propaganda|fake persona|fake account|astroturf|"
    r"influence campaign|microtargeting|phishing|scam pretext|forgery|fake evidence|"
    r"fake expert|fake grassroots|counter-disinformation|lie better|evade deception detection|"
    r"manipulate people|psychological manipulation)\b",
    re.IGNORECASE,
)

CLAIM_TYPES = {
    "FACTUAL", "IDENTITY", "AUTHORITY", "AFFILIATION", "TEMPORAL", "GEOGRAPHIC",
    "CAUSAL", "STATISTICAL", "QUANTITATIVE", "EXPERTISE", "OWNERSHIP",
    "PROVENANCE", "INTENT", "FORECAST", "OPINION", "VALUE_JUDGMENT",
    "SATIRE", "UNKNOWN",
}

NON_FACTUAL_TYPES = {"OPINION", "VALUE_JUDGMENT", "SATIRE"}

DIRECTLY_VERIFIABLE_TYPES = {
    "FACTUAL", "IDENTITY", "AUTHORITY", "AFFILIATION", "TEMPORAL",
    "GEOGRAPHIC", "STATISTICAL", "QUANTITATIVE", "OWNERSHIP", "PROVENANCE",
}

INDICATOR_TYPES = {
    "IDENTITY_DECEPTION",
    "AUTHORITY_DECEPTION",
    "SOURCE_DECEPTION",
    "PROVENANCE_DECEPTION",
    "CONTEXT_DECEPTION",
    "TEMPORAL_DECEPTION",
    "GEOGRAPHIC_DECEPTION",
    "STATISTICAL_MISREPRESENTATION",
    "EVIDENCE_FABRICATION",
    "EVIDENCE_ALTERATION",
    "CITATION_LAUNDERING",
    "SOURCE_LAUNDERING",
    "FALSE_CONSENSUS",
    "COORDINATED_INAUTHENTICITY",
    "SPONSORSHIP_CONCEALMENT",
    "IMPERSONATION",
    "PRETEXTING",
    "SELECTIVE_OMISSION",
    "QUOTE_CONTEXT_DISTORTION",
    "RECYCLED_CONTENT",
    "SYNTHETIC_MEDIA_CONTEXT",
    "CONTENT_REUSE",
    "CIRCULAR_CITATION_CANDIDATE",
    "COORDINATION_OBSERVED_NOT_DECEPTIVE",
    "OTHER",
    "UNKNOWN",
}

BENIGN_EXPLANATIONS = [
    "Honest error",
    "Outdated information",
    "Bad memory or incomplete knowledge",
    "Translation or localization issue",
    "Editorial summarization / accidental omission",
    "Satire or parody misunderstood as factual",
    "Fiction/roleplay presented out of context",
    "Platform-generated timestamp mistaken for event time",
    "Legitimate coordination (marketing, advocacy, emergency comms)",
    "Legitimate syndication or quoting",
    "Compromised or misconfigured account",
    "Upstream source mistake copied downstream",
    "Different definition, denominator, population, or time period",
    "Technical parsing/metadata error",
    "Confidentiality or privacy constraint, not deception",
]

SKEPTIC_QUESTIONS = [
    "Are we confusing false/unverified claim with intentional deception?",
    "Are the sources actually independent, or one upstream family?",
    "Could this be outdated information reposted without context?",
    "Could the media be authentic but miscaptioned?",
    "Could the statistic use a different denominator/population/time period?",
    "Could identity/affiliation conflict be role change, rebrand, or stale registry?",
    "Could coordination be legitimate advocacy/marketing/emergency communication?",
    "Could omission be accidental editorial summarization?",
    "Could satire/fiction be misunderstood as factual?",
    "Do we have direct intent evidence, or only misleading presentation indicators?",
]

CURRENT_WORDS = [
    "today", "now", "current", "currently", "just happened", "breaking",
    "latest", "this morning", "tonight", "2026",
]


# -----------------------------
# Helpers
# -----------------------------

def norm(value):
    value = str(value or "").strip().lower()
    value = re.sub(r"[^a-z0-9]+", "_", value)
    return value.strip("_")


def to_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def parse_dt(value):
    if not value:
        return None
    try:
        s = str(value)
        if len(s) == 10:
            s += "T00:00:00+00:00"
        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        return None


def stable_id(prefix, *parts):
    raw = "|".join(str(p or "") for p in parts)
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}-{digest}"


def text_hash(text):
    return hashlib.sha1(norm(text).encode("utf-8")).hexdigest()[:16]


def similarity(a, b):
    return SequenceMatcher(None, str(a or "").lower(), str(b or "").lower()).ratio()


def policy_blocked(objective):
    o = str(objective or "")
    # Block explicit requests to create/design/optimize/execute deception or manipulation.
    if HARMFUL_ACTION_RE.search(o) and HARMFUL_TARGET_RE.search(o):
        return True
    return False


# -----------------------------
# Source pedigree / independence
# -----------------------------

def upstream_chain(sid, sources, seen=None):
    seen = seen or set()
    if not sid or sid in seen or sid not in sources:
        return []
    seen.add(sid)
    chain = [sid]
    src = sources.get(sid, {})
    up = src.get("upstream_id") or src.get("upstream_source")
    if up:
        chain += upstream_chain(up, sources, seen)
    return chain


def source_family(sid, sources):
    src = sources.get(sid, {})
    return norm(src.get("family") or src.get("publisher") or src.get("organization") or sid)


def source_independence(a, b, sources):
    if not a or not b:
        return "UNKNOWN"
    if a == b:
        return "DEPENDENT"

    ua = set(upstream_chain(a, sources))
    ub = set(upstream_chain(b, sources))

    if ua & ub:
        return "DEPENDENT"

    fa = source_family(a, sources)
    fb = source_family(b, sources)

    if fa and fb and fa == fb:
        return "PARTIALLY_DEPENDENT"

    cites_a = {norm(x) for x in to_list(sources.get(a, {}).get("cites"))}
    cites_b = {norm(x) for x in to_list(sources.get(b, {}).get("cites"))}

    if cites_a & cites_b:
        return "PARTIALLY_DEPENDENT"

    if fa and fb and fa != fb:
        return "INDEPENDENT"

    return "UNKNOWN"


# -----------------------------
# Claim classification
# -----------------------------

def classify_claim_type(claim):
    explicit = claim.get("claim_type")
    if explicit:
        return str(explicit).upper()

    text = claim.get("text") or " ".join(
        str(claim.get(k) or "") for k in ("subject", "predicate", "object")
    )
    tl = text.lower()

    if any(w in tl for w in ["opinion", "believe", "should", "best", "worst", "value judgment"]):
        return "OPINION"
    if any(w in tl for w in ["will", "expect", "forecast", "predict", "projected"]):
        return "FORECAST"
    if "%" in text or re.search(r"\b\d[\d,\.]*\s*(percent|increase|decrease|risk|rate|probability)\b", tl):
        return "STATISTICAL"
    if any(w in tl for w in ["doctor", "professor", "expert", "official", "agency", "represent", "spokesperson", "ceo", "authority"]):
        return "AUTHORITY"
    if any(w in tl for w in ["image", "photo", "picture", "video", "audio", "document", "file", "screenshot", "provenance"]):
        return "PROVENANCE"
    if any(w in tl for w in ["today", "now", "current", "currently", "just happened", "breaking", "latest"]):
        return "TEMPORAL"
    if any(w in tl for w in ["located", "city", "country", "place", "site", "coordinates", "geographic"]):
        return "GEOGRAPHIC"
    if any(w in tl for w in ["caused", "because", "led to", "resulted", "due to"]):
        return "CAUSAL"
    if any(w in tl for w in ["works at", "employed by", "affiliated with", "member of", "founder", "owner", "director"]):
        return "IDENTITY"

    return "FACTUAL"


def verifiability_for_type(ctype):
    if ctype in NON_FACTUAL_TYPES:
        return "NON_FACTUAL"
    if ctype == "FORECAST":
        return "INDIRECTLY_VERIFIABLE"
    if ctype in DIRECTLY_VERIFIABLE_TYPES:
        return "DIRECTLY_VERIFIABLE"
    if ctype in {"CAUSAL", "INTENT"}:
        return "PARTIALLY_VERIFIABLE"
    return "UNKNOWN"


# -----------------------------
# Core analyzer
# -----------------------------

def analyze(case):
    case_id = case.get("case_id", "DECEPTION-CASE")
    objective = case.get("objective", "")
    sources = case.get("sources") or {}
    claims_raw = case.get("claims") or []
    evidence_raw = case.get("evidence") or []

    input_evidence = [{
        "evidence_id": "EV-INPUT",
        "source_id": "authorized_case_input",
        "observed_at": NOW(),
        "note": "Input-only defensive deception-indicator analysis. No live web/social/media access assumed.",
    }]

    if policy_blocked(objective):
        return {
            "case_id": case_id,
            "status": "POLICY_BLOCKED",
            "objective": objective,
            "findings": [{
                "kind": "POLICY_BLOCKED",
                "statement": "DECEPTIONINT does not design, optimize, generate, or execute deception/manipulation.",
                "human_review": True,
            }],
            "recommendations": [
                "Continue only with defensive detection, verification, provenance analysis, and resilience recommendations.",
                "Do not create fake personas, disinformation, propaganda, astroturfing, pretexting, or manipulative persuasion.",
                "Do not infer deception/intent merely from false or conflicting claims.",
            ],
            "limitations": ["Policy boundary enforced; no deception-indicator synthesis performed."],
            "evidence": input_evidence,
        }

    if not claims_raw:
        return {
            "case_id": case_id,
            "status": "PARTIAL",
            "objective": objective,
            "claims": [],
            "indicators": [],
            "knowledge_gaps": [{"kind": "NO_CLAIMS_PROVIDED", "statement": "No claims supplied."}],
            "recommendations": ["Provide claims, sources, evidence, provenance/context checks, and authorization scope."],
            "evidence": input_evidence,
        }

    # -------------------------
    # Normalize claims
    # -------------------------
    claims = []
    claims_by_id = {}

    for idx, c in enumerate(claims_raw):
        cid = c.get("claim_id") or stable_id("CLAIM", c.get("text"), c.get("source_id"), idx)
        text = c.get("text") or " ".join(
            str(c.get(k) or "") for k in ("subject", "predicate", "object")
        )
        ctype = classify_claim_type(c)
        verif = c.get("verifiability") or verifiability_for_type(ctype)

        claim = {
            "claim_id": cid,
            "text": text,
            "subject": c.get("subject"),
            "predicate": c.get("predicate"),
            "object": c.get("object"),
            "claim_type": ctype,
            "verifiability": verif,
            "source_id": c.get("source_id"),
            "speaker_or_publisher": c.get("speaker_or_publisher"),
            "published_at": parse_dt(c.get("published_at")),
            "event_time": parse_dt(c.get("event_time")),
            "location": c.get("location"),
            "certainty": c.get("certainty", "ASSERTED"),
            "evidence_ids": to_list(c.get("evidence_ids")),
            "claim_status": "UNASSESSED",
            "deception_status": "UNASSESSED",
            "deception_indicator_ids": [],
            "limitations": to_list(c.get("limitations")),
        }
        claims.append(claim)
        claims_by_id[cid] = claim

    evidence_by_claim = defaultdict(list)
    for e in evidence_raw:
        evidence_by_claim[e.get("claim_id")].append(e)

    indicators = []
    gaps = []
    unknowns = []
    fact_gate = []
    source_pair_independence = {}

    def add_gap(kind, statement, claim_ids=None, source_ids=None, recommended_source=None, specialist=None, importance="MEDIUM"):
        gaps.append({
            "gap_id": stable_id("GAP", kind, *(claim_ids or []), statement),
            "kind": kind,
            "statement": statement,
            "claim_ids": to_list(claim_ids),
            "source_ids": to_list(source_ids),
            "recommended_source": recommended_source,
            "specialist": specialist,
            "importance": importance,
        })

    def add_indicator(
        indicator_type,
        claim_id,
        status,
        severity,
        confidence,
        intent_relevance,
        evidence_ids,
        observed_behavior,
        alternatives=None,
    ):
        indicator_type = str(indicator_type).upper()
        if indicator_type not in INDICATOR_TYPES:
            indicator_type = "UNKNOWN"

        iid = f"IND-{len(indicators)+1}"
        ind = {
            "indicator_id": iid,
            "indicator_type": indicator_type,
            "claim_id": claim_id,
            "status": status,              # OBSERVED / WEAK / MODERATE / STRONG / DISPUTED / INCONCLUSIVE
            "severity": severity,          # INFORMATIONAL / LOW / MEDIUM / HIGH / CRITICAL
            "confidence": confidence,      # LOW / MEDIUM / HIGH
            "intent_relevance": intent_relevance,
            "evidence_ids": [x for x in to_list(evidence_ids) if x],
            "observed_behavior": observed_behavior,
            "alternative_explanations": list(dict.fromkeys(alternatives or BENIGN_EXPLANATIONS)),
            "created_at": NOW(),
        }
        indicators.append(ind)

        if claim_id in claims_by_id:
            claims_by_id[claim_id]["deception_indicator_ids"].append(iid)

        return ind

    # -------------------------
    # Missing source / pedigree gaps
    # -------------------------
    for claim in claims:
        sid = claim.get("source_id")
        if sid and sid not in sources:
            add_gap(
                "SOURCE_UNRESOLVED",
                f"Claim {claim['claim_id']} references source {sid}, but source metadata was not provided.",
                claim_ids=[claim["claim_id"]],
                source_ids=[sid],
                recommended_source="Original publisher/profile/registry",
                specialist="WEBINT / SOCMINT / CORPINT",
                importance="HIGH",
            )

    # -------------------------
    # Claim fact-gate status
    # -------------------------
    for claim in claims:
        cid = claim["claim_id"]
        evs = evidence_by_claim.get(cid, [])

        supporting = [e for e in evs if norm(e.get("stance")) == "support"]
        contradicting = [e for e in evs if norm(e.get("stance")) == "contradict"]

        def has_independent(evs):
            for e in evs:
                ind = source_independence(e.get("source_id"), claim.get("source_id"), sources)
                key = tuple(sorted([e.get("source_id") or "NA", claim.get("source_id") or "NA"]))
                source_pair_independence[f"{key[0]}->{key[1]}"] = ind
                if ind == "INDEPENDENT":
                    return True
            return False

        if claim["verifiability"] == "NON_FACTUAL":
            status = "NOT_FACT_CHECKABLE"
            reason = "Opinion/value/satire/fiction claim is not evaluated as empirical fact unless presented as factual."
        elif has_independent(contradicting):
            status = "DISPUTED"
            reason = "Independent contradicting evidence exists."
        elif has_independent(supporting):
            status = "SUPPORTED"
            reason = "Independent supporting evidence exists."
        elif supporting:
            status = "PARTIALLY_SUPPORTED"
            reason = "Supporting evidence exists but independence/quality is limited."
        elif contradicting:
            status = "DISPUTED"
            reason = "Contradicting evidence exists but independence is not fully established."
        else:
            status = "INCONCLUSIVE"
            reason = "No sufficient evidence supplied to support or dispute the claim."

        claim["claim_status"] = status

        fact_gate.append({
            "claim_id": cid,
            "claim_status": status,
            "passed": status == "SUPPORTED",
            "reason": reason,
            "evidence_ids": [e.get("evidence_id") for e in evs if e.get("evidence_id")],
            "source_id": claim.get("source_id"),
            "source_pedigree": upstream_chain(claim.get("source_id"), sources),
        })

        if status == "INCONCLUSIVE":
            add_gap(
                "EVIDENCE_MISSING",
                f"Claim {cid} lacks sufficient evidence for fact-gate resolution.",
                claim_ids=[cid],
                recommended_source="Primary/original evidence",
                specialist="FACT GATE / relevant domain specialist",
                importance="MEDIUM",
            )

    # -------------------------
    # Temporal context checks
    # -------------------------
    for tc in to_list(case.get("temporal_checks")):
        cid = tc.get("claim_id")
        claim = claims_by_id.get(cid)
        if not claim:
            continue

        text = (claim.get("text") or "").lower()
        has_current = any(w in text for w in CURRENT_WORDS) or bool(tc.get("claims_current"))
        first_seen = parse_dt(tc.get("archive_first_seen") or tc.get("first_seen"))
        published = parse_dt(tc.get("published_at") or claim.get("published_at"))

        mismatch = bool(tc.get("temporal_mismatch"))
        if has_current and first_seen and published and (published - first_seen).days > 30:
            mismatch = True

        if mismatch:
            add_indicator(
                "TEMPORAL_DECEPTION",
                cid,
                "MODERATE" if tc.get("strong") else "WEAK",
                "MEDIUM",
                "MEDIUM",
                "CONTEXT_ONLY",
                [tc.get("evidence_id")],
                "Content or caption presents older material as current/new.",
                alternatives=[
                    "Outdated repost",
                    "Platform timestamp confusion",
                    "Honest editorial error",
                    "Archive date incorrect",
                    "Legitimate retrospective post misread as current",
                ],
            )

    # -------------------------
    # Geographic context checks
    # -------------------------
    for gc in to_list(case.get("geographic_checks")):
        cid = gc.get("claim_id")
        claimed = gc.get("claimed_location")
        verified = gc.get("verified_location")

        if claimed and verified and norm(claimed) != norm(verified):
            add_indicator(
                "GEOGRAPHIC_DECEPTION",
                cid,
                "MODERATE" if gc.get("strong") else "WEAK",
                "MEDIUM",
                "MEDIUM",
                "CONTEXT_ONLY",
                [gc.get("evidence_id")],
                f"Claimed location '{claimed}' conflicts with verified/contextual location '{verified}'.",
                alternatives=[
                    "Similar-looking location",
                    "Administrative boundary ambiguity",
                    "Translation/place-name variant",
                    "Geolocation error",
                    "Map labeling mistake",
                ],
            )

    # -------------------------
    # Media / provenance context
    # -------------------------
    for mc in to_list(case.get("media_checks")):
        cid = mc.get("claim_id")
        prov = norm(mc.get("provenance_status")).upper()

        if prov == "AUTHENTIC" and (mc.get("temporal_mismatch") or mc.get("geographic_mismatch")):
            add_indicator(
                "CONTEXT_DECEPTION",
                cid,
                "MODERATE",
                "MEDIUM",
                "MEDIUM",
                "CONTEXT_ONLY",
                [mc.get("evidence_id")],
                "Media appears authentic, but accompanying temporal/geographic context is inconsistent.",
                alternatives=[
                    "Real media miscaptioned by upstream source",
                    "Editorial error",
                    "Archive metadata wrong",
                    "Legitimate reuse with unclear labeling",
                ],
            )

        if mc.get("synthetic_indicators"):
            add_indicator(
                "SYNTHETIC_MEDIA_CONTEXT",
                cid,
                "WEAK",
                "MEDIUM",
                "LOW",
                "PROVENANCE_ONLY",
                [mc.get("evidence_id")],
                "Synthetic-media indicators are present. This does not confirm generation or deception.",
                alternatives=[
                    "Detector false positive",
                    "Compression artifact",
                    "Stylized/edited authentic media",
                    "AI-assisted but disclosed/legitimate content",
                ],
            )

        if prov == "MANIPULATED":
            add_indicator(
                "EVIDENCE_ALTERATION",
                cid,
                "MODERATE",
                "HIGH",
                "MEDIUM",
                "EVIDENCE_INTEGRITY",
                [mc.get("evidence_id")],
                "Evidence/media manipulation indicator recorded. Requires forensic/human review.",
                alternatives=[
                    "Forensic false positive",
                    "Legitimate editing/cropping/annotation",
                    "Metadata parsing artifact",
                ],
            )

        if mc.get("reused_from_older_event"):
            add_indicator(
                "RECYCLED_CONTENT",
                cid,
                "MODERATE" if mc.get("strong") else "WEAK",
                "MEDIUM",
                "MEDIUM",
                "CONTEXT_ONLY",
                [mc.get("evidence_id")],
                "Content appears reused from an older event/context.",
                alternatives=[
                    "Legitimate archival reference",
                    "Educational example",
                    "Outdated repost without malicious intent",
                ],
            )

        if mc.get("c2pa_present") is False:
            add_gap(
                "PROVENANCE_UNAVAILABLE",
                f"Media/check for claim {cid} lacks C2PA/provenance metadata. Absence does not imply fake.",
                claim_ids=[cid],
                recommended_source="Native file, camera metadata, publisher provenance",
                specialist="METADATAINT / IMINT / VIDINT / AUDINT",
                importance="MEDIUM",
            )

    # -------------------------
    # Statistical / denominator checks
    # -------------------------
    for sc in to_list(case.get("statistical_checks")):
        cid = sc.get("claim_id")
        claimed_pct = sc.get("claimed_percent")
        denominator = sc.get("denominator")
        baseline = sc.get("baseline")
        current = sc.get("current")

        if claimed_pct is not None and (denominator in (None, "") or sc.get("missing_denominator")):
            add_indicator(
                "SELECTIVE_OMISSION",
                cid,
                "WEAK",
                "MEDIUM",
                "MEDIUM",
                "CONTEXT_ONLY",
                [sc.get("evidence_id")],
                "Statistical/percentage claim lacks denominator, baseline, population, or time period.",
                alternatives=[
                    "Accidental summarization",
                    "Source did not have denominator",
                    "Different metric definition",
                    "Editorial space limit",
                ],
            )

        if baseline not in (None, 0) and current is not None and claimed_pct is not None:
            try:
                actual_pct = ((float(current) - float(baseline)) / float(baseline)) * 100.0
                tol = max(1.0, 0.05 * abs(float(claimed_pct)))
                if abs(actual_pct - float(claimed_pct)) > tol:
                    add_indicator(
                        "STATISTICAL_MISREPRESENTATION",
                        cid,
                        "MODERATE",
                        "MEDIUM",
                        "HIGH",
                        "CONTEXT_ONLY",
                        [sc.get("evidence_id")],
                        f"Computed change {actual_pct:.1f}% differs materially from claimed {claimed_pct}%.",
                        alternatives=[
                            "Different baseline/current definitions",
                            "Different time period",
                            "Rounding/method difference",
                            "Data entry error",
                        ],
                    )
            except Exception:
                add_gap(
                    "STATISTICAL_METHOD_UNKNOWN",
                    f"Statistical check for claim {cid} could not be computed deterministically.",
                    claim_ids=[cid],
                    recommended_source="Raw dataset/methodology",
                    specialist="DATAINT / ACADEMICINT / FININT",
                    importance="MEDIUM",
                )

    # -------------------------
    # Quote/context checks
    # -------------------------
    for qc in to_list(case.get("quote_checks")):
        cid = qc.get("claim_id")
        original = qc.get("original_text")
        quoted = qc.get("quoted_text")

        if original and quoted:
            sim = similarity(original, quoted)
            if sim < 0.60 or qc.get("missing_context") or qc.get("speaker_mismatch"):
                add_indicator(
                    "QUOTE_CONTEXT_DISTORTION",
                    cid,
                    "MODERATE" if qc.get("strong") else "WEAK",
                    "MEDIUM",
                    "MEDIUM",
                    "CONTEXT_ONLY",
                    [qc.get("evidence_id")],
                    "Quoted material appears truncated, mismatched, or missing material context.",
                    alternatives=[
                        "Legitimate short quotation",
                        "Translation difference",
                        "Transcription error",
                        "Editorial excerpting",
                    ],
                )

    # -------------------------
    # Identity / authority / credential checks
    # -------------------------
    for ic in to_list(case.get("identity_checks")):
        cid = ic.get("claim_id")
        verified_identity = ic.get("verified_identity")
        affiliation_verified = ic.get("affiliation_verified")
        authority_verified = ic.get("authority_verified")
        signals = to_list(ic.get("impersonation_signals"))

        if verified_identity is False or affiliation_verified is False or authority_verified is False:
            itype = "IDENTITY_DECEPTION" if verified_identity is False else "AUTHORITY_DECEPTION"
            status = "MODERATE" if signals else "WEAK"
            severity = "HIGH" if signals else "MEDIUM"

            add_indicator(
                itype,
                cid,
                status,
                severity,
                "MEDIUM",
                "IDENTITY_OR_AUTHORITY",
                [ic.get("evidence_id")],
                "Claimed identity/affiliation/authority is not supported by supplied verification evidence.",
                alternatives=[
                    "Role change",
                    "Rebrand/organization name change",
                    "Stale registry/database",
                    "Self-description outdated",
                    "Translation/title mismatch",
                    "Pseudonymous but legitimate account",
                ],
            )

    # -------------------------
    # Sponsorship disclosure checks
    # -------------------------
    for sp in to_list(case.get("sponsorship_checks")):
        cid = sp.get("claim_id")
        funder = sp.get("funder")
        disclosed = sp.get("disclosed")

        if funder and disclosed is False:
            add_indicator(
                "SPONSORSHIP_CONCEALMENT",
                cid or sp.get("source_id"),
                "MODERATE",
                "MEDIUM",
                "MEDIUM",
                "CONTEXT_ONLY",
                [sp.get("evidence_id")],
                "Funding/sponsorship relationship appears undisclosed in the analyzed item.",
                alternatives=[
                    "Disclosure exists elsewhere",
                    "Funding relationship ambiguous",
                    "Sponsorship does not imply editorial control",
                    "Administrative omission",
                ],
            )

    # -------------------------
    # Source/citation laundering checks
    # -------------------------
    for lc in to_list(case.get("laundering_checks")):
        cid = lc.get("claim_id")
        ltype = norm(lc.get("type")).upper()

        if ltype in ("SOURCE_LAUNDERING", "CITATION_LAUNDERING") and lc.get("evidence"):
            add_indicator(
                ltype,
                cid,
                "MODERATE",
                "MEDIUM",
                "MEDIUM",
                "SOURCE_INTEGRITY",
                [lc.get("evidence_id")],
                lc.get("note") or "Claim appears to gain apparent authority through citation/source chain.",
                alternatives=[
                    "Legitimate secondary reporting",
                    "Independent confirmation exists but not supplied",
                    "Citation graph incomplete",
                ],
            )

    # -------------------------
    # Coordination / false consensus checks
    # -------------------------
    for cc in to_list(case.get("coordination_checks")):
        cid = cc.get("claim_id") or cc.get("narrative_id")
        synchronized = bool(cc.get("synchronized"))
        identical = bool(cc.get("identical_content"))
        inauth = bool(cc.get("inauthentic_identity_evidence"))
        conceal = bool(cc.get("concealed_sponsorship"))
        purchased = bool(cc.get("purchased_engagement"))

        if synchronized and identical and (inauth or conceal or purchased):
            add_indicator(
                "COORDINATED_INAUTHENTICITY",
                cid,
                "MODERATE",
                "HIGH",
                "MEDIUM",
                "MANUFACTURED_CONSENSUS",
                [cc.get("evidence_id")],
                "Coordination indicators combine with identity/authenticity or sponsorship concerns.",
                alternatives=[
                    "Legitimate coordinated campaign",
                    "Shared press release",
                    "Community organizing",
                    "Emergency communication",
                    "Automation without deceptive intent",
                ],
            )
        elif synchronized and identical:
            add_indicator(
                "COORDINATION_OBSERVED_NOT_DECEPTIVE",
                cid,
                "WEAK",
                "INFORMATIONAL",
                "LOW",
                "NONE",
                [cc.get("evidence_id")],
                "Synchronized/similar content observed, but no inauthenticity evidence supplied.",
                alternatives=[
                    "Legitimate coordination",
                    "Shared source material",
                    "Common news event",
                    "Platform amplification",
                ],
            )

    # -------------------------
    # Content reuse / duplicate artifact families
    # -------------------------
    if case.get("analyze_content_reuse"):
        groups = defaultdict(list)
        for p in to_list(case.get("posts")):
            txt = p.get("text") or ""
            if not txt:
                continue
            h = p.get("content_hash") or text_hash(txt)
            groups[h].append(p)

        for h, group in groups.items():
            if len(group) <= 1:
                continue

            source_ids = {p.get("source_id") for p in group if p.get("source_id")}
            account_ids = {p.get("account_id") for p in group if p.get("account_id")}
            first_cid = group[0].get("claim_id")

            add_indicator(
                "CONTENT_REUSE",
                first_cid,
                "WEAK",
                "LOW",
                "MEDIUM",
                "SOURCE_DEPENDENCY",
                [group[0].get("evidence_id")],
                f"{len(group)} posts/items share the same content fingerprint.",
                alternatives=[
                    "Quoting",
                    "Syndication",
                    "Press release",
                    "Legitimate republication",
                    "Common source language",
                ],
            )

            if len(source_ids) > 1:
                independent_pairs = []
                for a, b in itertools.combinations(sorted(source_ids), 2):
                    ind = source_independence(a, b, sources)
                    independent_pairs.append(ind)
                    source_pair_independence[f"{a}->{b}"] = ind

                if not all(x == "INDEPENDENT" for x in independent_pairs):
                    add_gap(
                        "SOURCE_INDEPENDENCE_UNRESOLVED",
                        "Repeated content appears across sources that are not confirmed independent.",
                        claim_ids=[first_cid] if first_cid else [],
                        source_ids=list(source_ids),
                        recommended_source="Original upstream publication/archive",
                        specialist="WEBINT / SOCMINT / DISINFOINT",
                        importance="MEDIUM",
                    )

            if len(account_ids) > 1:
                unknowns.append("Multiple accounts share identical content; common operator is NOT inferred without stronger evidence.")

    # -------------------------
    # Circular citation detection (simple)
    # -------------------------
    edges = to_list(case.get("citation_edges"))
    if edges:
        adj = defaultdict(set)
        for e in edges:
            frm = e.get("from") or e.get("source_id")
            to = e.get("to") or e.get("target_id")
            if frm and to:
                adj[frm].add(to)

        visited = set()
        stack = set()
        cycle_found = False

        def dfs(node):
            nonlocal cycle_found
            visited.add(node)
            stack.add(node)
            for nxt in adj.get(node, []):
                if nxt not in visited:
                    dfs(nxt)
                elif nxt in stack:
                    cycle_found = True
            stack.remove(node)

        for n in list(adj.keys()):
            if n not in visited:
                dfs(n)
            if cycle_found:
                break

        if cycle_found:
            add_indicator(
                "CIRCULAR_CITATION_CANDIDATE",
                "GRAPH",
                "MODERATE",
                "MEDIUM",
                "MEDIUM",
                "SOURCE_INTEGRITY",
                [],
                "Citation graph contains a cycle; repeated citation is not independent corroboration.",
                alternatives=[
                    "Citation graph incomplete",
                    "Mutual scholarly dialogue misparsed",
                    "Data ingestion artifact",
                ],
            )

    # -------------------------
    # Update claim-level deception status
    # -------------------------
    for claim in claims:
        cid = claim["claim_id"]
        claim_inds = [i for i in indicators if i.get("claim_id") == cid]

        if not claim_inds:
            claim["deception_status"] = "NO_DECEPTION_EVIDENCE"
        elif any(i["status"] in ("MODERATE", "STRONG") for i in claim_inds):
            claim["deception_status"] = "DECEPTION_INDICATORS_PRESENT"
        else:
            claim["deception_status"] = "MISLEADING_PRESENTATION_CANDIDATE"

    # -------------------------
    # Intent evidence analysis
    # -------------------------
    intent_evidence = to_list(case.get("intent_evidence"))
    strong_intent_types = {
        "ADMISSION",
        "COURT_FINDING",
        "INTERNAL_INSTRUCTION",
        "FABRICATED_MATERIAL",
        "KNOWN_FALSE_IDENTITY",
        "DELIBERATE_CONCEALMENT",
    }
    moderate_intent_types = {
        "REPEATED_AFTER_CORRECTION",
        "CONTRADICTORY_PRIVATE_PUBLIC_KNOWLEDGE",
        "DOCUMENTED_COORDINATION_WITH_DECEPTIVE_MECHANISM",
    }

    strong_ie = [
        ie for ie in intent_evidence
        if norm(ie.get("type")).upper() in strong_intent_types
        and norm(ie.get("strength")).upper() in ("STRONG", "MODERATE")
    ]
    moderate_ie = [
        ie for ie in intent_evidence
        if norm(ie.get("type")).upper() in moderate_intent_types
        and norm(ie.get("strength")).upper() in ("STRONG", "MODERATE")
    ]

    if strong_ie:
        intent_state = "INTENT_SUPPORTED"
    elif moderate_ie and any(i["status"] in ("MODERATE", "STRONG") for i in indicators):
        intent_state = "INTENT_PROBABLE"
    elif indicators:
        intent_state = "INTENT_UNRESOLVED"
    else:
        intent_state = "NO_INTENT_EVIDENCE"

    # -------------------------
    # Overall deception status
    # -------------------------
    if not indicators:
        deception_status = "NO_DECEPTION_EVIDENCE"
    elif intent_state == "INTENT_SUPPORTED" and any(i["status"] == "STRONG" for i in indicators):
        deception_status = "DECEPTION_HYPOTHESIS_SUPPORTED"
    elif any(i["status"] in ("MODERATE", "STRONG") for i in indicators):
        deception_status = "DECEPTION_INDICATORS_PRESENT"
    else:
        deception_status = "MISLEADING_PRESENTATION_CANDIDATE"

    if any(i["status"] == "DISPUTED" for i in indicators):
        deception_status = "DISPUTED"

    # -------------------------
    # Hypotheses
    # -------------------------
    hypotheses = []
    if indicators:
        hypotheses.append({
            "hypothesis_id": "H1",
            "statement": "Observed indicators are consistent with misleading presentation or deceptive mechanism.",
            "support": [i["indicator_id"] for i in indicators if i["status"] in ("WEAK", "MODERATE", "STRONG")],
            "opposition": [
                "Direct intent evidence is absent or unresolved in supplied input",
                "Benign explanations have not been fully excluded",
            ],
            "status": "CANDIDATE",
        })
        hypotheses.append({
            "hypothesis_id": "H2",
            "statement": "Observations may be explained by honest error, outdated information, satire, translation, legitimate coordination, or upstream mistake.",
            "support": ["No decisive intent evidence supplied in this offline case"],
            "opposition": [
                "Multiple independent contradictions/context mismatches may reduce simple-error probability, but do not prove intent"
            ],
            "status": "VIABLE",
        })

    # -------------------------
    # Unknowns / gaps
    # -------------------------
    if intent_state == "INTENT_UNRESOLVED":
        unknowns.append("Deceptive intent remains unresolved.")
    if intent_state == "NO_INTENT_EVIDENCE" and indicators:
        unknowns.append("Deception indicators exist, but intent evidence was not supplied.")
    if any(v in ("UNKNOWN", "PARTIALLY_DEPENDENT") for v in source_pair_independence.values()):
        unknowns.append("Some source independence relationships remain unresolved.")

    add_gap(
        "ORIGINAL_SOURCE_RECOVERY",
        "Locate earliest/original publication and native artifacts to reduce citation/source laundering uncertainty.",
        recommended_source="Archive, original publisher, native media, registry",
        specialist="WEBINT / METADATAINT / IMINT / VIDINT / AUDINT",
        importance="HIGH",
    )

    # -------------------------
    # Human review
    # -------------------------
    high_severity_types = {
        "IDENTITY_DECEPTION",
        "AUTHORITY_DECEPTION",
        "IMPERSONATION",
        "EVIDENCE_FABRICATION",
        "EVIDENCE_ALTERATION",
        "COORDINATED_INAUTHENTICITY",
        "SPONSORSHIP_CONCEALMENT",
        "SOURCE_LAUNDERING",
        "CITATION_LAUNDERING",
    }

    human_review_required = (
        bool(case.get("high_consequence"))
        or intent_state in ("INTENT_SUPPORTED", "INTENT_PROBABLE")
        or any(i["severity"] in ("HIGH", "CRITICAL") for i in indicators)
        or any(
            i["indicator_type"] in high_severity_types and i["status"] in ("MODERATE", "STRONG")
            for i in indicators
        )
    )

    # -------------------------
    # Specialist handoffs
    # -------------------------
    handoffs = set()
    for ind in indicators:
        t = ind["indicator_type"]
        if t in ("IDENTITY_DECEPTION", "AUTHORITY_DECEPTION", "IMPERSONATION"):
            handoffs.update(["CORPINT", "ORGINT", "ACADEMICINT", "LEGALINT"])
        if t in ("STATISTICAL_MISREPRESENTATION", "SELECTIVE_OMISSION"):
            handoffs.update(["DATAINT", "ACADEMICINT", "FININT"])
        if t in ("SYNTHETIC_MEDIA_CONTEXT", "EVIDENCE_ALTERATION", "RECYCLED_CONTENT", "CONTEXT_DECEPTION"):
            handoffs.update(["IMINT", "VIDINT", "AUDINT", "METADATAINT", "DOCINT"])
        if t in ("SOURCE_LAUNDERING", "CITATION_LAUNDERING", "CIRCULAR_CITATION_CANDIDATE"):
            handoffs.update(["WEBINT", "SOCMINT", "ACADEMICINT"])
        if t in ("COORDINATED_INAUTHENTICITY", "FALSE_CONSENSUS", "CONTENT_REUSE"):
            handoffs.update(["SOCMINT", "DISINFOINT", "CAMPAIGNINT"])
        if t in ("SPONSORSHIP_CONCEALMENT",):
            handoffs.update(["FININT", "CORPINT", "ADINT"])

    if not handoffs:
        handoffs.add("DECEPTIONINT")

    # -------------------------
    # Recommendations
    # -------------------------
    recommendations = [
        "Retrieve the original/primary source and earliest known publication.",
        "Use web/media archives to compare captions, dates, disclosures, edits, and deletions.",
        "Obtain native media/provenance where available: hashes, metadata, C2PA, publisher records.",
        "Verify identity/authority through official registries/channels, not logos, badges, handles, or screenshots alone.",
        "For statistical claims, recover denominator, baseline, population, time period, and method.",
        "Count independent evidence families, not URLs/posts/reposts.",
        "Preserve original and corrected versions; do not silently rewrite history.",
        "Label synthetic/AI-assisted content when provenance supports it and policy requires disclosure.",
        "Publish transparent, source-linked corrections if TraceAtlas/organization controls the content.",
        "Do not create counter-deception, fake personas, pretexting, astroturfing, or retaliatory manipulation.",
        "Route high-consequence intent/attribution conclusions to qualified human review.",
    ]

    if human_review_required:
        recommendations.append("HUMAN_REVIEW_REQUIRED before public accusation, legal/regulatory action, or real-person/organization attribution.")

    # -------------------------
    # Limitations / status
    # -------------------------
    limitations = [
        "Offline skeleton; no live web, social, media, registry, or archive access is assumed.",
        "Deception indicators are not proof of intent.",
        "False/unverified claim != deception.",
        "Authentic media can still have false context.",
        "Synthetic-media indicators do not confirm generation or deception.",
        "Coordination/automation alone does not establish inauthenticity.",
        "Intent unresolved is a valid defensive outcome.",
    ]

    if case.get("demo_data_is_synthetic"):
        limitations.append("Demo claims/sources/evidence are synthetic placeholders, not real publications or allegations.")

    if not claims:
        status = "PARTIAL"
    elif human_review_required:
        status = "HUMAN_REVIEW_REQUIRED"
    elif deception_status == "NO_DECEPTION_EVIDENCE":
        status = "SUCCEEDED"
    else:
        status = "INCONCLUSIVE"

    return {
        "case_id": case_id,
        "task_id": case.get("task_id"),
        "status": status,
        "objective": objective,
        "demo_data_is_synthetic": bool(case.get("demo_data_is_synthetic")),
        "human_review_required": human_review_required,

        "claims": claims,
        "fact_gate": fact_gate,

        "sources": sources,
        "source_pedigree": {
            c["claim_id"]: upstream_chain(c.get("source_id"), sources)
            for c in claims
        },
        "source_pair_independence": source_pair_independence,

        "evidence": evidence_raw,
        "indicators": indicators,

        "benign_explanations": BENIGN_EXPLANATIONS,
        "skeptic_questions": SKEPTIC_QUESTIONS,
        "hypotheses": hypotheses,

        "intent_state": intent_state,
        "deception_status": deception_status,

        "knowledge_gaps": gaps,
        "unknowns": unknowns,
        "recommended_next_actions": recommendations,
        "specialist_handoffs": sorted(handoffs),
        "limitations": limitations,
        "generated_at": NOW(),
        "input_evidence": input_evidence,
    }


# -----------------------------
# Synthetic demo
# -----------------------------

if __name__ == "__main__":
    demo_case = {
        "case_id": "DECEPTIONINT-DEMO-001",
        "task_id": "T1",
        "objective": "Defensively analyze synthetic misleading claims and preserve intent uncertainty.",
        "demo_data_is_synthetic": True,
        "high_consequence": True,
        "analyze_content_reuse": True,

        "sources": {
            "S1": {
                "source_id": "S1",
                "family": "synthetic_blog",
                "publisher": "Synthetic Blog",
                "reliability": "LOW",
            },
            "S2": {
                "source_id": "S2",
                "family": "synthetic_aggregator",
                "upstream_id": "S1",
            },
            "S3": {
                "source_id": "S3",
                "family": "synthetic_news",
                "upstream_id": "S2",
            },
            "S4": {
                "source_id": "S4",
                "family": "synthetic_factcheck",
                "publisher": "Synthetic Fact Check",
            },
        },

        "claims": [
            {
                "claim_id": "C1",
                "text": "Image I shows an explosion in City L today.",
                "claim_type": "PROVENANCE",
                "source_id": "S3",
                "published_at": "2026-10-09T00:00:00Z",
                "location": "City L",
            },
            {
                "claim_id": "C2",
                "text": "Experts confirmed risk increased 200%.",
                "claim_type": "STATISTICAL",
                "source_id": "S2",
                "published_at": "2026-10-08T00:00:00Z",
            },
            {
                "claim_id": "C3",
                "text": "Dr. X from Agency Y warned that Policy Z is unsafe.",
                "claim_type": "AUTHORITY",
                "source_id": "S1",
                "published_at": "2026-10-07T00:00:00Z",
            },
        ],

        "evidence": [
            {
                "evidence_id": "E1",
                "claim_id": "C1",
                "stance": "CONTRADICT",
                "source_id": "S4",
                "note": "Archive shows same image in 2023 and geolocation supports City M.",
            },
            {
                "evidence_id": "E2",
                "claim_id": "C2",
                "stance": "CONTRADICT",
                "source_id": "S4",
                "note": "Underlying dataset shows baseline 1, current 2, i.e. 100%, and denominator omitted.",
            },
            {
                "evidence_id": "E3",
                "claim_id": "C3",
                "stance": "CONTRADICT",
                "source_id": "S4",
                "note": "Official registry does not verify Dr. X affiliation with Agency Y; quote omits hypothetical context.",
            },
        ],

        "temporal_checks": [
            {
                "claim_id": "C1",
                "archive_first_seen": "2023-05-01T00:00:00Z",
                "published_at": "2026-10-09T00:00:00Z",
                "claims_current": True,
                "evidence_id": "E1",
            }
        ],

        "geographic_checks": [
            {
                "claim_id": "C1",
                "claimed_location": "City L",
                "verified_location": "City M",
                "evidence_id": "E1",
            }
        ],

        "media_checks": [
            {
                "claim_id": "C1",
                "media_id": "IMG-I",
                "provenance_status": "AUTHENTIC",
                "temporal_mismatch": True,
                "geographic_mismatch": True,
                "synthetic_indicators": False,
                "c2pa_present": False,
                "evidence_id": "E1",
            }
        ],

        "statistical_checks": [
            {
                "claim_id": "C2",
                "claimed_percent": 200,
                "baseline": 1,
                "current": 2,
                "denominator": None,
                "missing_denominator": True,
                "evidence_id": "E2",
            }
        ],

        "identity_checks": [
            {
                "claim_id": "C3",
                "claimed_identity": "Dr. X",
                "claimed_affiliation": "Agency Y",
                "verified_identity": None,
                "affiliation_verified": False,
                "authority_verified": False,
                "impersonation_signals": ["logo only", "lookalike domain"],
                "evidence_id": "E3",
            }
        ],

        "quote_checks": [
            {
                "claim_id": "C3",
                "original_text": "In a hypothetical scenario, if Policy Z were implemented without safeguards, it could be unsafe.",
                "quoted_text": "Policy Z is unsafe.",
                "missing_context": True,
                "speaker_mismatch": False,
                "evidence_id": "E3",
            }
        ],

        "sponsorship_checks": [
            {
                "claim_id": "C2",
                "source_id": "S2",
                "funder": "Synthetic Corp",
                "disclosed": False,
                "evidence_id": "E2",
            }
        ],

        "laundering_checks": [
            {
                "claim_id": "C2",
                "type": "SOURCE_LAUNDERING",
                "evidence": True,
                "note": "Weak blog claim appears via aggregator/news as if independently validated.",
                "evidence_id": "E2",
            }
        ],

        "coordination_checks": [
            {
                "claim_id": "C1",
                "synchronized": False,
                "identical_content": False,
                "inauthentic_identity_evidence": False,
                "concealed_sponsorship": False,
                "purchased_engagement": False,
            }
        ],

        "posts": [
            {
                "post_id": "P1",
                "claim_id": "C1",
                "source_id": "S3",
                "account_id": "A3",
                "text": "Image I shows an explosion in City L today.",
            },
            {
                "post_id": "P2",
                "claim_id": "C1",
                "source_id": "S2",
                "account_id": "A2",
                "text": "Image I shows an explosion in City L today.",
            },
        ],

        "intent_evidence": [],
    }

    result = analyze(demo_case)
    print(json.dumps(result, indent=2, ensure_ascii=False))