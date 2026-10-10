#!/usr/bin/env python3
"""
TRACEATLAS LINGINT main.py
==========================

Defensive, authorized, evidence-first, privacy-aware linguistic intelligence
scaffold.

This module:
- Does NOT fetch live text, documents, transcripts, or corpora.
- Does NOT invent language, script, dialect, translation, author, speaker,
  intent, nationality, identity, quote source, or source pedigree.
- Does NOT infer race, ethnicity, religion, sexual orientation, health status,
  mental-health status, criminality, or nationality from language or style.
- Does NOT claim definitive authorship from stylometry alone.
- Does NOT use language as a lie detector.
- Does NOT generate propaganda, manipulation, persuasion optimization,
  phishing/social-engineering language, harassment messaging, extremist
  propaganda, or deceptive influence operations.
- Does NOT deanonymize private persons from writing style alone.

It consumes deterministic text records supplied by authorized/public sources:
- original text artifacts
- normalized / stylometry / search / translation layers
- supplied translations and translation metadata
- supplied claims and claim alignments
- supplied author-sample corpora for closed-set comparison only
- source metadata, pedigree, independence metadata
- glossaries / term mappings where supplied
- time, language, script, genre, and privacy metadata

It produces an evidence-linked LINGINTResult with:
- script identification without language/identity overclaim
- conservative language identification with short-text uncertainty
- code-switching / multilingual span analysis
- terminology, acronym, entity-mention extraction
- claim, negation, modality, certainty, hedging analysis
- quotation / reported-speech separation
- register, rhetorical, framing, and defensive propaganda-signal description
- translation drift detection: negation drop, modality drop, certainty
  strengthening, attribution drift candidates
- exact / near duplicate and template reuse analysis
- phrase reuse and document clustering
- stylometric feature extraction
- closed-set authorship-candidate consistency comparison only
- AI-generated-text and machine-translation context from supplied indicators
- source pedigree and source independence
- contradiction preservation
- competing hypotheses and falsification
- dual-AI style skeptic review
- privacy / sensitive-trait firewall flags
- graphical memory scaffold
- analyst summary and report-ready result object
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import statistics
import unicodedata
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

VERSION = "0.1.0"

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

SCRIPT_RANGES: List[Tuple[str, List[Tuple[int, int]]]] = [
    ("LATIN", [(0x0041, 0x005A), (0x0061, 0x007A), (0x00C0, 0x024F)]),
    ("GREEK", [(0x0370, 0x03FF)]),
    ("CYRILLIC", [(0x0400, 0x04FF), (0x0500, 0x052F)]),
    ("ARMENIAN", [(0x0530, 0x058F)]),
    ("HEBREW", [(0x0590, 0x05FF)]),
    ("ARABIC", [
        (0x0600, 0x06FF), (0x0750, 0x077F), (0x08A0, 0x08FF),
        (0xFB50, 0xFDFF), (0xFE70, 0xFEFF)
    ]),
    ("DEVANAGARI", [(0x0900, 0x097F), (0xA8E0, 0xA8FF)]),
    ("BENGALI", [(0x0980, 0x09FF)]),
    ("TAMIL", [(0x0B80, 0x0BFF)]),
    ("TELUGU", [(0x0C00, 0x0C7F)]),
    ("KANNADA", [(0x0C80, 0x0CFF)]),
    ("MALAYALAM", [(0x0D00, 0x0D7F)]),
    ("GUJARATI", [(0x0A80, 0x0AFF)]),
    ("GURMUKHI", [(0x0A00, 0x0A7F)]),
    ("THAI", [(0x0E00, 0x0E7F)]),
    ("GEORGIAN", [(0x10A0, 0x10FF)]),
    ("ARMENIAN_EXT", [(0x0530, 0x058F)]),
    ("HANGUL", [
        (0x1100, 0x11FF), (0x3130, 0x318F), (0xA960, 0xA97F),
        (0xAC00, 0xD7AF), (0xD7B0, 0xD7FF)
    ]),
    ("HAN", [
        (0x3400, 0x4DBF), (0x4E00, 0x9FFF), (0xF900, 0xFAFF),
        (0x20000, 0x2A6DF), (0x2A700, 0x2B73F)
    ]),
    ("HIRAGANA", [(0x3040, 0x309F)]),
    ("KATAKANA", [(0x30A0, 0x30FF), (0xFF66, 0xFF9F)]),
]

STOPWORDS: Dict[str, Set[str]] = {
    "EN": {
        "the", "a", "an", "and", "or", "but", "if", "then", "than", "that",
        "this", "these", "those", "of", "in", "on", "at", "by", "for", "with",
        "about", "against", "between", "into", "through", "during", "before",
        "after", "above", "below", "to", "from", "up", "down", "out", "off",
        "over", "under", "again", "further", "once", "here", "there", "when",
        "where", "why", "how", "all", "any", "both", "each", "few", "more",
        "most", "other", "some", "such", "no", "nor", "not", "only", "own",
        "same", "so", "too", "very", "can", "will", "just", "should", "now",
        "is", "are", "was", "were", "be", "been", "being", "have", "has",
        "had", "having", "do", "does", "did", "doing", "would", "could",
        "should", "may", "might", "must", "shall", "i", "you", "he", "she",
        "it", "we", "they", "me", "him", "her", "us", "them", "my", "your",
        "his", "its", "our", "their"
    },
    "ES": {
        "el", "la", "los", "las", "un", "una", "unos", "unas", "y", "o", "pero",
        "si", "que", "de", "del", "en", "con", "por", "para", "sin", "sobre",
        "entre", "hasta", "desde", "este", "esta", "estos", "estas", "ese",
        "esa", "esos", "esas", "a", "ante", "bajo", "cabe", "tras", "es", "son",
        "fue", "eran", "ser", "estar", "haber", "hay", "tener", "tiene", "hacer"
    },
    "FR": {
        "le", "la", "les", "un", "une", "des", "du", "de", "des", "et", "ou",
        "mais", "si", "que", "qui", "quoi", "dont", "au", "aux", "à", "a",
        "avec", "pour", "sans", "sous", "sur", "dans", "en", "chez", "vers",
        "est", "sont", "était", "étaient", "être", "avoir", "a", "ont", "fait"
    },
    "DE": {
        "der", "die", "das", "ein", "eine", "und", "oder", "aber", "wenn",
        "dass", "wer", "was", "wie", "wo", "von", "zu", "mit", "für", "ohne",
        "gegen", "zwischen", "durch", "über", "unter", "vor", "nach", "bei",
        "ist", "sind", "war", "waren", "sein", "haben", "hat", "haben", "machen"
    },
    "PT": {
        "o", "a", "os", "as", "um", "uma", "uns", "umas", "e", "ou", "mas",
        "se", "que", "de", "do", "da", "dos", "das", "em", "com", "por",
        "para", "sem", "sobre", "entre", "até", "desde", "este", "esta",
        "estes", "estas", "esse", "essa", "esses", "essas", "é", "são", "foi",
        "eram", "ser", "estar", "ter", "tem", "fazer"
    },
    "IT": {
        "il", "lo", "la", "i", "gli", "le", "un", "uno", "una", "e", "o", "ma",
        "se", "che", "chi", "cosa", "di", "del", "della", "in", "con", "per",
        "senza", "su", "tra", "fra", "è", "sono", "era", "erano", "essere",
        "avere", "ha", "hanno", "fare"
    },
    "NL": {
        "de", "het", "een", "en", "of", "maar", "als", "dat", "wie", "wat",
        "van", "in", "op", "aan", "bij", "met", "voor", "zonder", "over",
        "tussen", "door", "is", "zijn", "was", "waren", "zijn", "hebben",
        "heeft", "maken"
    },
    "TR": {
        "ve", "veya", "ama", "fakat", "eğer", "ki", "bu", "şu", "o", "bir",
        "bazı", "he", "hiç", "çok", "daha", "en", "için", "ile", "gibi",
        "kadar", "sonra", "önce", "dir", "dır", "dur", "değil", "var", "yok"
    },
    "ID": {
        "dan", "atau", "tetapi", "jika", "bahwa", "yang", "ini", "itu", "sebuah",
        "beberapa", "sangat", "lebih", "paling", "untuk", "dengan", "seperti",
        "sebagai", "adalah", "bukan", "ada", "tidak", "akan", "sudah", "belum"
    },
    "HI": {
        "का", "की", "के", "कि", "कर", "करने", "किया", "है", "हैं", "था", "थी",
        "थे", "और", "या", "लेकिन", "पर", "पे", "से", "में", "को", "तक", "बाट",
        "द्वारा", "लिए", "साथ", "बिना", "जब", "जहाँ", "कौन", "क्या", "कैसे",
        "यह", "वह", "इस", "उस", "ये", "वे", "एक", "कुछ", "सब", "बहुत", "नहीं"
    },
    "UR": {
        "کا", "کی", "کے", "کہ", "کر", "کرنا", "کیا", "ہے", "ہیں", "تھا", "تھی",
        "تھے", "اور", "یا", "لیکن", "پر", "سے", "میں", "کو", "تک", "بغیر",
        "دWARA", "لیے", "ساتھ", "جب", "جہاں", "کون", "کیا", "کیسے", "یہ", "وہ",
        "اس", "ایک", "کچھ", "سب", "بہت", "نہیں"
    },
    "AR": {
        "ال", "و", "أو", "لكن", "إذا", "أن", "من", "إلى", "في", "مع", "عن",
        "على", " تحت", "بين", "خلال", "قبل", "بعد", "هذا", "هذه", "ذلك",
        "تلك", "هو", "هي", "هم", "كان", "كانت", "يكون", "هناك", "لا", "ليس",
        "ما", "ماذا", "كيف", "أين", "متى", "كل", "بعض", "جدا"
    },
    "RU": {
        "и", "или", "но", "если", "что", "кто", "как", "где", "когда", "от",
        "до", "с", "без", "над", "под", "между", "через", "перед", "после",
        "этот", "эта", "это", "те", "тот", "та", "то", "он", "она", "оно",
        "они", "был", "была", "были", "есть", "нет", "можно", "нужно", "очень",
        "более", "самый", "все", "всё", "каждый"
    },
    "ZH": {
        "的", "了", "和", "是", "在", "有", "我", "你", "他", "她", "它", "我们",
        "你们", "他们", "这", "那", "一个", "一些", "很", "更", "最", "不", "没",
        "可以", "可能", "应该", "必须", "因为", "所以", "如果", "但是", "或者"
    },
    "KO": {
        "이", "가", "을", "를", "은", "는", "와", "과", "도", "만", "부터", "까지",
        "에서", "으로", "로", "에게", "한테", "께", "보다", "처럼", "같이", "만큼",
        " 그리고", "또", "하지만", "그러나", "왜", "언제", "어디", "누가", "무엇",
        "이것", "저것", "그것", "아니", "않", "매우", "더", "가장"
    },
    "HE": {
        "של", "ל", "ב", "כ", "ה", "ו", "אם", "או", "אבל", "ש", "מי", "מה",
        "איך", "איפה", "מתי", "מן", "עד", "עם", "בלי", "על", "תחת", "בין",
        "דרך", "לפני", "אחרי", "זה", "זאת", "אלה", "הוא", "היא", "הם", "הן",
        "היה", "היו", "יש", "אין", "מאוד", "יותר", "הכי", "לא"
    },
    "EL": {
        "ο", "η", "το", "οι", "τα", "και", "ή", "αλλά", "αν", "ότι", "που",
        "ποιος", "τι", "πως", "που", "πότε", "από", "σε", "με", "χωρίς",
        "πάνω", "κάτω", "ανάμεσα", "μέσα", "πριν", "μετά", "αυτός", "αυτή",
        "αυτό", "αυτοί", "αυτές", "είναι", "ήταν", "υπάρχει", "δεν", "πολύ",
        "περισσότερο", "πιο"
    },
}

FUNCTION_WORDS: Set[str] = set().union(*STOPWORDS.values())

NEGATION_WORDS: Set[str] = {
    "not", "no", "nor", "never", "nothing", "nowhere", "neither", "nobody",
    "non", "nicht", "kein", "keine", "ne", "pas", "jamais", "aucun", "ningún",
    "nadie", "nunca", "no", "not", "nahi", "नहीं", "na", "لا", "ليس", "لم",
    "не", "нет", "ни", "不", "没", "没有", "아니", "안", "못", "לא", "אינו",
    "μη", "όχι", "bukan", "tidak", "hayır", "değil"
}

NEGATION_PHRASES: List[str] = [
    "n't", "not ", " no ", " never", " nothing", " neither", " nicht", " kein",
    " ne ", " pas ", " jamais", " ningún", " nadie", " nunca", " नहीं", " لا ",
    " ليس", " не ", " нет", " 不", "没", "没有", "안", "못", "לא", " não",
    " değil", " bukan", " tidak"
]

MODAL_WORDS: Set[str] = {
    "may", "might", "could", "can", "cannot", "cant", "should", "would",
    "will", "shall", "must", "allegedly", "reportedly", "apparently",
    "possibly", "probably", "likely", "puede", "podría", "quizás", "peut",
    "peut-être", "kann", "könnte", "muss", "sollte", "ho", "sakta",
    "हो", "सकता", "सकती", "يمكن", "قد", "ربما", "может", "возможно",
    "должен", "可能", "可以", "会", "应该", "수", "있", "יכול", "אולי",
    "μπορεί", "ίσως", "dapat", "maaari", "bisa", "olabilir"
}

MODAL_PHRASES: List[str] = [
    " may ", " might ", " could ", " can ", " cannot ", " should ", " would ",
    " will ", " shall ", " must ", " allegedly ", " reportedly ", " apparently ",
    " possibly ", " probably ", " likely ", " puede ", " podría ", " quizás ",
    " peut ", " peut-être ", " kann ", " könnte ", " muss ", " sollte ",
    " हो सकता ", " يمكن ", " قد ", " ربما ", " может ", " возможно ",
    " 可能 ", " 可以 ", " 수 있다 ", " יכול ", " אולי ", " μπορεί ", " ίσως "
]

HEDGE_WORDS: Set[str] = {
    "possibly", "apparently", "likely", "seems", "seem", "appeared",
    "suggests", "suggest", "may", "might", "could", "somewhat", "arguably",
    "reportedly", "allegedly", "parece", "semble", "scheint", "похоже",
    "يبدو", "似乎", "好像", " seeming", " seeming"
}

HEDGE_PHRASES: List[str] = [
    " possibly ", " apparently ", " likely ", " seems ", " seem ", " suggests ",
    " may ", " might ", " could ", " somewhat ", " arguably ", " reportedly ",
    " allegedly ", " parece ", " semble ", " scheint ", " похоже ", " يبدو ",
    " 似乎 ", " 好像 "
]

CERTAINTY_WORDS: Set[str] = {
    "confirmed", "confirms", "confirming", "proven", "proved", "certain",
    "certainly", "definitely", "certainly", "verified", "verified",
    "confirmado", "confirmó", "certeza", "confirmé", "certitude", "bestätigt",
    "sicher", "подтверждено", "уверенно", "确认", "确定", "مؤكد", "확실",
    "מאושר", "επιβεβαιώθηκε"
}

CERTAINTY_PHRASES: List[str] = [
    " confirmed ", " proven ", " certain ", " definitely ", " certainly ",
    " verified ", " confirmado ", " certitude ", " bestätigt ", " sicher ",
    " подтверждено ", " 确认 ", " 确定 ", " مؤكد ", " 확실 ", " מאושר ",
    " επιβεβαιώθηκε "
]

REPORTING_VERBS: Set[str] = {
    "said", "says", "stated", "announced", "reported", "claims", "claimed",
    "alleges", "alleged", "admitted", "denied", "confirmed", "according",
    "notes", "wrote", "writes", "dijo", "dice", "señala", "afirmó", "según",
    "déclaré", "selon", "a", "sagte", "laut", "заявил", "по", "قال", "وفقا",
    "根据", "말했다", "לפי", "σύμφωνα"
}

REPORTING_PHRASES: List[str] = [
    " said ", " says ", " stated ", " announced ", " reported ", " claims ",
    " alleged ", " admitted ", " denied ", " confirmed ", " according to ",
    " notes ", " wrote ", " dijo ", " señala ", " afirmó ", " según ",
    " a déclaré ", " selon ", " sagte ", " laut ", " заявил ", " по словам ",
    " قال ", " وفقا ", " 根据 ", " 말했다 ", " לפי ", " σύμφωνα "
]

REGISTER_HINTS: Dict[str, List[str]] = {
    "FORMAL": ["hereby", "pursuant", "whereas", "dear", "sincerely", "respectfully", "official", "statement", "communiqué", "memorandum"],
    "INFORMAL": ["hey", "lol", "omg", "btw", "gonna", "kinda", "dude", "bro", "yeah", "nah"],
    "TECHNICAL": ["system", "network", "server", "protocol", "exploit", "malware", "api", "database", "encryption", "authentication", "payload", "repository"],
    "LEGAL": ["court", "lawsuit", "indictment", "statute", "regulation", "liability", "injunction", "plaintiff", "defendant", "jurisdiction", "contract", "breach"],
    "ACADEMIC": ["study", "research", "hypothesis", "methodology", "sample", "peer-reviewed", "abstract", "literature", "variable", "significant"],
    "JOURNALISTIC": ["sources said", "according to", "reported", "exclusive", "investigation", "statement", "spokesperson", "officials said"],
    "PROMOTIONAL": ["buy", "limited", "offer", "discount", "sign up", "subscribe", "amazing", "best", "act now", "free trial"],
    "CONVERSATIONAL": ["i think", "you know", "like", "just", "anyway", "so", "well", "kind of"]
}

PROPAGANDA_HINTS: Dict[str, List[str]] = {
    "BINARY_FRAMING": ["us vs them", "enemy", "traitor", "patriot", "evil", "righteous", "pure", "corrupt", "liberator", "occupier", "they hate us"],
    "FEAR_APPEAL": ["threat", "danger", "invasion", "attack", "chaos", "existential", "destroy", "eliminate", "wipe out", "catastrophe"],
    "AUTHORITY_APPEAL": ["leaders say", "official", "historical inevitability", "experts agree", "science says", "the people know"],
    "MORAL_ABSOLUTISM": ["good vs evil", "sacred", "duty", "honor", "betrayal", "justice", "sin", "virtue"],
    "URGENCY": ["now", "immediately", "act before", "last chance", "before it is too late", "urgent"],
    "DELEGITIMIZATION": ["illegitimate", "fraud", "fake", "puppet", "regime", "terrorists", "criminals", "enemies of the people"]
}

MACHINE_TRANSLATION_HINTS: List[str] = [
    # These are weak indicators only. They do not prove machine translation.
    "literal translation", "word-for-word", "awkward phrasing", "unnatural grammar"
]

AI_TEXT_HINTS: List[str] = [
    # Weak indicators only. Detector output or provenance is required for stronger claims.
    "moreover", "furthermore", "in conclusion", "it is important to note",
    "delve", "tapestry", "navigate the complexities", "in today's world"
]

PRIVATE_TAGS: Set[str] = {
    "private_text",
    "private_message",
    "private_person",
    "personal_contact",
    "home_location",
    "private_location",
    "stalking_target",
    "private_journalist_source",
    "confidential_source_deanonymization"
}

SENSITIVE_TRAIT_TAGS: Set[str] = {
    "race",
    "ethnicity",
    "religion",
    "sexual_orientation",
    "health_condition",
    "mental_health",
    "criminality",
    "political_affiliation",
    "nationality_inference"
}

BLOCK_PHRASES: List[str] = [
    # sensitive trait inference
    "infer race",
    "infer ethnicity",
    "infer religion",
    "infer sexual orientation",
    "infer health condition",
    "infer mental health",
    "infer criminality",
    "infer nationality as fact",
    "nationality from language",
    "ethnicity from language",
    "religion from language",
    "political belief from language",
    "private political beliefs",
    "psychological diagnosis",
    "lie detector",
    "detect deception from language",
    "deception from language",
    "intent from linguistic style",
    "intent from writing style",

    # authorship overclaim
    "definitive author identification",
    "definitive authorship",
    "identify real persons from writing style",
    "prove author from stylometry",
    "certain author",
    "author confirmed from style",

    # manipulation / harmful generation
    "generate targeted manipulation",
    "targeted manipulation campaign",
    "optimize propaganda",
    "propaganda generation",
    "optimize coercive persuasion",
    "coercive persuasion",
    "optimize phishing",
    "phishing language",
    "social-engineering language",
    "social engineering language",
    "create harassment messaging",
    "harassment messaging",
    "create extremist propaganda",
    "extremist propaganda",
    "deceptive influence operations",
    "influence operation",
    "covert private-person tracking",
    "private-person tracking through language",
    "deanonymize private person from writing style",
    "deanonymise private person from writing style",
]

SOURCE_TYPE_RELIABILITY: Dict[str, str] = {
    "AUTHORIZED_INTERNAL": "HIGH",
    "OFFICIAL_RECORD": "HIGH",
    "AUTHENTICATED_TRANSCRIPT": "HIGH",
    "LICENSED_CORPUS": "HIGH",
    "PUBLIC_SPEECH": "MODERATE",
    "PUBLISHED_ARTICLE": "MODERATE",
    "PRESS_RELEASE": "MODERATE",
    "PUBLIC_POST": "LOW",
    "FORUM_POST": "LOW",
    "CHAT_EXPORT": "MODERATE",
    "UNKNOWN": "UNKNOWN",
}

CLAIM_TYPES: Set[str] = {
    "FACTUAL_CLAIM",
    "OPINION",
    "VALUE_JUDGMENT",
    "PREDICTION",
    "SATIRE",
    "RHETORICAL_STATEMENT",
    "UNKNOWN",
}

MODALITY_LEVELS: Set[str] = {
    "CERTAIN",
    "HIGH_CONFIDENCE",
    "MODERATE",
    "TENTATIVE",
    "SPECULATIVE",
    "UNKNOWN",
}

CERTAINTY_LEVELS: Set[str] = {
    "CERTAIN",
    "HIGH_CONFIDENCE",
    "MODERATE",
    "TENTATIVE",
    "SPECULATIVE",
    "UNKNOWN",
}

AUTHORSHIP_LABELS: Set[str] = {
    "CONSISTENT_WITH",
    "MORE_CONSISTENT_WITH",
    "LESS_CONSISTENT_WITH",
    "INCONSISTENT_WITH",
    "INSUFFICIENT_TEXT",
    "UNKNOWN_AUTHOR",
    "INCONCLUSIVE",
    "PRIVACY_BOUNDARY",
}

SEVERE_QUALITY_FLAGS: Set[str] = {
    "missing_original_text",
    "source_unknown",
    "privacy_private_text_boundary",
    "language_uncertain",
    "translation_missing",
    "translation_ambiguous",
    "negation_drop_candidate",
    "modality_drop_candidate",
    "certainty_strengthening_candidate",
    "attribution_drift_candidate",
    "insufficient_authorship_corpus",
    "genre_mismatch",
    "authorship_overclaim_blocked",
    "sensitive_trait_inference_blocked",
    "prompt_injection_like_instruction_detected",
}

# -----------------------------------------------------------------------------
# Small helpers
# -----------------------------------------------------------------------------

def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_dt(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except Exception:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def to_float(value: Any) -> Optional[float]:
    if value is None or isinstance(value, bool):
        return None
    try:
        f = float(value)
        if math.isnan(f) or math.isinf(f):
            return None
        return f
    except Exception:
        return None


def public_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if not str(k).startswith("_")}


def ensure_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def iso_or_none(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if isinstance(dt, datetime) else None


def dt_sort_key(dt: Optional[datetime]) -> float:
    return dt.timestamp() if isinstance(dt, datetime) else 0.0


def add_flag(obj: Dict[str, Any], flag: str) -> None:
    flags = obj.setdefault("_quality_flags", [])
    f = str(flag).strip().lower()
    if f and f not in flags:
        flags.append(f)


def safe_std(values: List[float]) -> Optional[float]:
    vals = [v for v in values if v is not None]
    if len(vals) < 2:
        return None
    try:
        return statistics.stdev(vals)
    except Exception:
        return None


def numeric_summary(values: List[Any]) -> Dict[str, Any]:
    arr: List[float] = []
    for v in values:
        f = to_float(v)
        if f is not None:
            arr.append(f)
    if not arr:
        return {"count": 0, "min": None, "max": None, "median": None, "mean": None, "std": None}
    return {
        "count": len(arr),
        "min": min(arr),
        "max": max(arr),
        "median": statistics.median(arr),
        "mean": statistics.fmean(arr),
        "std": safe_std(arr),
    }


def normalize_choice(value: Any, allowed: Iterable[str], default: str = "UNKNOWN") -> str:
    s = str(value or "").strip().upper().replace("-", "_").replace(" ", "_")
    allowed_set = set(allowed)
    return s if s in allowed_set else default


def normalize_name(value: Any) -> Optional[str]:
    s = unicodedata.normalize("NFKC", str(value or "")).lower().strip()
    s = re.sub(r"\s+", " ", s)
    return s or None


def short_text(value: Any, limit: int = 220) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    if len(s) <= limit:
        return s
    return s[:limit].rstrip() + "..."


def get_tags(obj: Dict[str, Any]) -> Set[str]:
    return {str(x).strip().lower() for x in ensure_list(obj.get("tags") or obj.get("sensitive_tags")) if x}


def get_records(case: Dict[str, Any], *keys: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for k in keys:
        v = case.get(k)
        if isinstance(v, list):
            out.extend([x for x in v if isinstance(x, dict)])
        elif isinstance(v, dict):
            out.append(v)
    return out


def sha256_text(text: Any) -> Optional[str]:
    if text is None:
        return None
    s = str(text)
    if not s.strip():
        return None
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def normalize_text(text: Any) -> str:
    if text is None:
        return ""
    s = unicodedata.normalize("NFKC", str(text)).lower()
    s = re.sub(r"\s+", " ", s)
    s = re.sub(r"[^\w\s]", "", s, flags=re.UNICODE)
    return s.strip()


def normalized_hash(text: Any) -> Optional[str]:
    nt = normalize_text(text)
    if not nt:
        return None
    return hashlib.sha256(nt.encode("utf-8")).hexdigest()


def token_shingles(text: Any, n: int = 3) -> Set[str]:
    toks = normalize_text(text).split()
    if not toks:
        return set()
    if len(toks) < n:
        return {" ".join(toks)}
    return {" ".join(toks[i:i + n]) for i in range(len(toks) - n + 1)}


def word_ngrams(tokens: List[str], n: int) -> List[str]:
    if len(tokens) < n:
        return [" ".join(tokens)] if tokens else []
    return [" ".join(tokens[i:i + n]) for i in range(len(tokens) - n + 1)]


def jaccard(a: Set[str], b: Set[str]) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def split_sentences(text: Any) -> List[str]:
    if text is None:
        return []
    s = str(text)
    parts = re.split(r"(?<=[.!?।؛؟])\s+|\n+", s)
    return [p.strip() for p in parts if p.strip()]


def char_script(ch: str) -> str:
    o = ord(ch)
    for name, ranges in SCRIPT_RANGES:
        for lo, hi in ranges:
            if lo <= o <= hi:
                return name
    return "OTHER"


def cosine_dicts(a: Dict[str, float], b: Dict[str, float]) -> float:
    if not a or not b:
        return 0.0
    keys = set(a) & set(b)
    if not keys:
        return 0.0
    dot = sum(a[k] * b[k] for k in keys)
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


class DSU:
    def __init__(self) -> None:
        self.parent: Dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


# -----------------------------------------------------------------------------
# Policy gate
# -----------------------------------------------------------------------------

def policy_block_reasons(case: Dict[str, Any]) -> List[str]:
    reasons: List[str] = []

    scanned_parts: List[str] = []
    for key in ("objective", "questions", "scope", "authorization", "requested_outputs", "tags", "next_action_requests"):
        val = case.get(key)
        if val is not None:
            scanned_parts.append(json.dumps(val, ensure_ascii=False, default=str))

    text = " ".join(scanned_parts).lower()

    for phrase in BLOCK_PHRASES:
        if phrase in text:
            reasons.append(f"Forbidden LINGINT action/request detected: '{phrase}'")

    scope = case.get("scope") if isinstance(case.get("scope"), dict) else {}
    auth = case.get("authorization") if isinstance(case.get("authorization"), dict) else {}
    requested = case.get("requested_outputs") if isinstance(case.get("requested_outputs"), dict) else {}

    if scope.get("authorized_only") is not True:
        reasons.append("scope.authorized_only must be true")

    if scope.get("privacy_aware") is False:
        reasons.append("scope.privacy_aware must not be false")

    if scope.get("no_sensitive_trait_profiling") is False:
        reasons.append("scope.no_sensitive_trait_profiling must not be false")

    prohibited_scope_flags = [
        "infer_race",
        "infer_ethnicity",
        "infer_religion",
        "infer_sexual_orientation",
        "infer_health_condition",
        "infer_mental_health_diagnosis",
        "infer_criminality",
        "infer_nationality_as_fact_from_language",
        "definitive_author_identification",
        "deception_from_language",
        "intent_from_linguistic_style",
        "generate_targeted_manipulation",
        "optimize_propaganda",
        "optimize_coercive_persuasion",
        "optimize_phishing_social_engineering",
        "create_harassment_messaging",
        "create_extremist_propaganda",
        "create_deceptive_influence_operations",
        "profile_private_political_beliefs",
        "covert_private_person_tracking",
        "private_person_tracking",
        "source_deanonymization",
    ]

    for flag in prohibited_scope_flags:
        if scope.get(flag) is True:
            reasons.append(f"scope.{flag} is prohibited")

    prohibited_requested = [
        "race_inference",
        "ethnicity_inference",
        "religion_inference",
        "sexual_orientation_inference",
        "health_inference",
        "mental_health_inference",
        "criminality_inference",
        "nationality_fact_from_language",
        "definitive_authorship",
        "lie_detection",
        "deception_detection",
        "intent_from_style",
        "propaganda",
        "manipulation_campaign",
        "phishing_text",
        "social_engineering_text",
        "harassment_text",
        "extremist_propaganda",
        "influence_operation",
        "deanonymize_private_person",
        "private_person_tracking",
    ]

    for flag in prohibited_requested:
        if requested.get(flag) is True:
            reasons.append(f"requested_outputs.{flag} is prohibited")

    if not auth.get("lawful_basis"):
        reasons.append("authorization.lawful_basis is missing")

    if not auth.get("purpose"):
        reasons.append("authorization.purpose is missing")

    return reasons


def blocked_result(
    case: Dict[str, Any],
    reasons: List[str],
    started: str,
    input_path: Optional[str],
    input_hash: Optional[str],
) -> Dict[str, Any]:
    return {
        "case_id": case.get("case_id"),
        "task_id": case.get("task_id"),
        "objective": case.get("objective"),
        "status": "POLICY_BLOCKED",
        "policy_block_reasons": reasons,
        "mode": case.get("model_mode", "LOCAL_ONLY"),
        "safety_flags": [
            "NO_SENSITIVE_TRAIT_PROFILING",
            "NO_NATIONALITY_INFERENCE_FROM_LANGUAGE",
            "NO_DEFINITIVE_AUTHORSHIP_FROM_STYLOMETRY",
            "NO_LIE_DETECTION",
            "NO_INTENT_INFERENCE_FROM_STYLE",
            "NO_PROPAGANDA_GENERATION",
            "NO_MANIPULATION_OPTIMIZATION",
            "NO_PHISHING_OR_SOCIAL_ENGINEERING_LANGUAGE",
            "NO_HARASSMENT_MESSAGING",
            "NO_EXTREMIST_PROPAGANDA",
            "NO_DECEPTIVE_INFLUENCE_OPERATIONS",
            "NO_PRIVATE_PERSON_DEANONYMIZATION",
            "NO_COVERT_TRACKING_THROUGH_LANGUAGE",
        ],
        "privacy_flags": [
            "NO_PRIVATE_PERSON_TARGETING",
            "NO_CONFIDENTIAL_SOURCE_IDENTIFICATION",
            "MINIMUM_NECESSARY_PERSONAL_DATA",
            "AUTHORSHIP_ANALYSIS_CASE_SCOPED_ONLY",
        ],
        "recommended_next_actions": [
            "Restate objective as descriptive language, translation, discourse, terminology, or authorized authorship-candidate comparison",
            "Do not request race, ethnicity, religion, sexuality, health, mental-health, criminality, or nationality inference",
            "Do not request definitive author identification or deception detection from language alone",
            "Do not request propaganda, manipulation, phishing, harassment, or influence-operation content",
            "Use authorized/public text records and preserve original text layers",
        ],
        "limitations": [
            "Requested or detected use crosses LINGINT lawful/ethical boundary.",
            "No sensitive-trait profiling, nationality inference, definitive authorship, lie detection, manipulation, propaganda, phishing, harassment, or private-person deanonymization support is provided.",
        ],
        "replay_manifest": {
            "generated_at": started,
            "finished_at": utcnow_iso(),
            "code_version": VERSION,
            "input_path": input_path,
            "input_sha256": input_hash,
        },
    }


# -----------------------------------------------------------------------------
# Source / text / sample validation
# -----------------------------------------------------------------------------

def source_reliability_label(source: Dict[str, Any]) -> str:
    rel = str(source.get("reliability") or source.get("_reliability") or "").strip().upper()
    if rel in {"HIGH", "MEDIUM", "LOW", "UNKNOWN"}:
        return rel
    stype = str(source.get("source_type") or source.get("_source_type") or "UNKNOWN").strip().upper()
    return SOURCE_TYPE_RELIABILITY.get(stype, "UNKNOWN")


def validate_sources(case: Dict[str, Any]) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    issues: List[str] = []
    sources: Dict[str, Dict[str, Any]] = {}

    for idx, s in enumerate(get_records(case, "sources", "source_metadata")):
        sid = str(s.get("source_id") or s.get("id") or f"SRC-{idx + 1}").strip()
        s["source_id"] = sid

        stype = str(s.get("source_type") or "UNKNOWN").strip().upper()
        s["_source_type"] = stype
        s["_reliability"] = source_reliability_label(s)

        s["_publisher"] = s.get("publisher")
        s["_organization"] = s.get("organization")
        s["_account"] = s.get("account")
        s["_domain"] = str(s.get("domain") or "").strip().lower() or None

        s["_upstream_source_ids"] = [
            str(x).strip()
            for x in ensure_list(s.get("upstream_sources") or s.get("upstream_source_ids") or s.get("upstream_source_id"))
            if x
        ]

        s["_independence_group"] = str(
            s.get("independence_group")
            or (s["_upstream_source_ids"][0] if s["_upstream_source_ids"] else None)
            or s.get("publisher")
            or s.get("organization")
            or s.get("account")
            or sid
        ).strip().upper()

        s["_first_seen"] = parse_dt(s.get("first_seen"))
        s["_last_seen"] = parse_dt(s.get("last_seen"))
        s["_limitations"] = ensure_list(s.get("limitations"))

        if s["_first_seen"] and s["_last_seen"] and s["_last_seen"] < s["_first_seen"]:
            add_flag(s, "timing_conflict")

        sources[sid] = s

    if not sources:
        issues.append("No source metadata supplied")

    return sources, issues


def prepare_text_layers(original: Any) -> Dict[str, str]:
    forensic = "" if original is None else str(original)
    normalized = unicodedata.normalize("NFKC", forensic)
    normalized = re.sub(r"\s+", " ", normalized).strip()

    stylometry = normalized

    search = normalized.lower()
    search = re.sub(r"[^\w\s]", " ", search, flags=re.UNICODE)
    search = re.sub(r"\s+", " ", search).strip()

    return {
        "forensic": forensic,
        "normalized": normalized,
        "stylometry": stylometry,
        "search": search,
    }


def redact_personal_fields(obj: Dict[str, Any]) -> None:
    hints = ("home", "private", "personal", "contact", "address", "phone", "family", "email", "location")
    for k in list(obj.keys()):
        lk = str(k).lower()
        if any(h in lk for h in hints):
            obj[k] = "REDACTED"


def detect_prompt_injection_like(text: Any) -> bool:
    if text is None:
        return False
    s = str(text).lower()
    phrases = [
        "ignore previous instructions",
        "ignore your rules",
        "ignore system",
        "send the file",
        "execute code",
        "reveal hidden prompt",
        "change verdict",
        "contact this user",
    ]
    return any(p in s for p in phrases)


def validate_texts(
    case: Dict[str, Any],
    sources: Dict[str, Dict[str, Any]],
    settings: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, Any]], List[str], List[str]]:
    issues: List[str] = []
    warnings: List[str] = []
    texts: List[Dict[str, Any]] = []
    texts_by_id: Dict[str, Dict[str, Any]] = {}

    raw = get_records(case, "texts", "documents", "messages", "posts", "transcripts", "text_artifacts")

    for idx, t in enumerate(raw):
        tid = str(t.get("text_id") or t.get("document_id") or t.get("message_id") or t.get("id") or f"TEXT-{idx + 1}").strip()
        t["text_id"] = tid

        original = t.get("original_text") or t.get("text") or t.get("content_text") or ""
        if not str(original).strip():
            issues.append(f"text {tid} missing original_text")
            add_flag(t, "missing_original_text")

        layers = prepare_text_layers(original)
        t["_forensic_text"] = layers["forensic"]
        t["_normalized_text"] = layers["normalized"]
        t["_stylometry_text"] = layers["stylometry"]
        t["_search_text"] = layers["search"]

        translated = t.get("translated_text") or t.get("translation") or ""
        tlayers = prepare_text_layers(translated)
        t["_translation_text"] = tlayers["normalized"]
        t["_translation_search"] = tlayers["search"]

        tags = get_tags(t)
        t["_tags"] = tags

        t["_analysis_enabled"] = True
        t["_authorship_allowed"] = True

        if tags & PRIVATE_TAGS:
            add_flag(t, "privacy_private_text_boundary")
            redact_personal_fields(t)
            if tags & {"private_text", "private_message", "private_person"}:
                t["_analysis_enabled"] = False
                t["_authorship_allowed"] = False
                t["_forensic_text"] = "[REDACTED_PRIVATE_TEXT]"
                t["_normalized_text"] = "[REDACTED_PRIVATE_TEXT]"
                t["_stylometry_text"] = ""
                t["_search_text"] = ""
                t["_translation_text"] = ""
                t["_translation_search"] = ""

        if tags & SENSITIVE_TRAIT_TAGS:
            add_flag(t, "sensitive_trait_inference_blocked")
            warnings.append(f"text {tid} contained sensitive-trait tag; inference disabled")

        if detect_prompt_injection_like(t["_forensic_text"]) or detect_prompt_injection_like(t.get("translated_text")):
            add_flag(t, "prompt_injection_like_instruction_detected")
            warnings.append(f"text {tid} contained instruction-like untrusted content; ignored as data")

        t["_content_hash"] = t.get("content_hash") or sha256_text(t["_forensic_text"])
        t["_normalized_hash"] = t.get("normalized_hash") or normalized_hash(t["_normalized_text"])
        t["_shingles"] = token_shingles(t["_stylometry_text"], int(settings.get("shingle_size", 3))) if t["_analysis_enabled"] else set()

        t["_source_id"] = str(t.get("source_id") or "").strip() or None
        if t["_source_id"] and t["_source_id"] not in sources:
            add_flag(t, "source_unknown")
            warnings.append(f"text {tid} references unknown source_id={t['_source_id']}")

        t["_translation_of"] = str(t.get("translation_of") or t.get("original_text_id") or "").strip() or None
        if t["_translation_of"] and t["_translation_of"] not in texts_by_id:
            # May be forward reference; validate later.
            pass

        t["_language_hint"] = normalize_name(t.get("language_hint") or t.get("language"))
        t["_script_hint"] = str(t.get("script_hint") or "").strip().upper() or None
        t["_genre"] = str(t.get("genre") or "UNKNOWN").strip().upper()
        t["_published_at"] = parse_dt(t.get("published_at") or t.get("timestamp"))
        t["_observed_at"] = parse_dt(t.get("observed_at") or t.get("retrieved_at"))

        t["_author_candidate_ids"] = [
            str(x).strip()
            for x in ensure_list(t.get("author_candidate_ids") or t.get("author_candidates"))
            if x
        ]

        t["_quote_speakers"] = t.get("quote_speakers") or {}
        t["_glossary"] = t.get("glossary") or {}
        t["_ai_text_indicator"] = t.get("ai_text_indicator")
        t["_machine_translation_indicator"] = t.get("machine_translation_indicator")

        t["_source_ids"] = [str(x).strip() for x in ensure_list(t.get("source_ids") or t.get("source_id")) if x]
        t["_evidence_ids"] = [str(x).strip() for x in ensure_list(t.get("evidence_ids") or t.get("evidence_id")) if x]

        texts.append(t)
        texts_by_id[tid] = t

    # Resolve translation_of references.
    for t in texts:
        tr = t.get("_translation_of")
        if tr and tr not in texts_by_id:
            issues.append(f"text {t.get('text_id')} references unknown translation_of={tr}")
            add_flag(t, "source_text_missing")

    if not texts:
        issues.append("No text artifacts supplied")

    return texts, texts_by_id, issues, warnings


def validate_author_samples(
    case: Dict[str, Any],
    settings: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], List[str], List[str]]:
    issues: List[str] = []
    warnings: List[str] = []
    samples: List[Dict[str, Any]] = []

    raw = get_records(case, "known_author_samples", "author_samples", "comparison_corpus")

    for idx, s in enumerate(raw):
        sid = str(s.get("sample_id") or s.get("id") or f"SAMP-{idx + 1}").strip()
        s["sample_id"] = sid

        author = str(s.get("author_candidate_id") or s.get("author_id") or s.get("candidate_id") or "").strip()
        if not author:
            issues.append(f"author sample {sid} missing author_candidate_id")
        s["_author_candidate_id"] = author or None

        original = s.get("text") or s.get("original_text") or ""
        layers = prepare_text_layers(original)
        s["_forensic_text"] = layers["forensic"]
        s["_normalized_text"] = layers["normalized"]
        s["_stylometry_text"] = layers["stylometry"]
        s["_search_text"] = layers["search"]

        tags = get_tags(s)
        s["_tags"] = tags
        if tags & PRIVATE_TAGS:
            add_flag(s, "privacy_private_text_boundary")
            redact_personal_fields(s)
            s["_analysis_enabled"] = False
        else:
            s["_analysis_enabled"] = True

        s["_language_hint"] = normalize_name(s.get("language_hint") or s.get("language"))
        s["_genre"] = str(s.get("genre") or "UNKNOWN").strip().upper()
        s["_published_at"] = parse_dt(s.get("published_at"))
        s["_content_hash"] = s.get("content_hash") or sha256_text(s["_forensic_text"])
        s["_normalized_hash"] = s.get("normalized_hash") or normalized_hash(s["_normalized_text"])

        samples.append(s)

    return samples, issues, warnings


def validate_claims(
    case: Dict[str, Any],
    texts_by_id: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    issues: List[str] = []
    claims: List[Dict[str, Any]] = []

    for idx, c in enumerate(get_records(case, "claims")):
        cid = str(c.get("claim_id") or c.get("id") or f"CLAIM-{idx + 1}").strip()
        c["claim_id"] = cid

        text_id = str(c.get("text_id") or c.get("document_id") or "").strip()
        c["_text_id"] = text_id
        if text_id and text_id not in texts_by_id:
            issues.append(f"claim {cid} references unknown text_id={text_id}")

        c["_claim_type"] = normalize_choice(c.get("claim_type") or c.get("type"), CLAIM_TYPES, "UNKNOWN")
        c["_subject"] = normalize_name(c.get("subject"))
        c["_predicate"] = normalize_name(c.get("predicate"))
        c["_object"] = normalize_name(c.get("object"))
        c["_time_reference"] = str(c.get("time_reference") or c.get("time") or "").strip() or None
        c["_location_reference"] = str(c.get("location_reference") or c.get("location") or "").strip().upper() or None
        c["_negation"] = bool(c.get("negation"))
        c["_modality"] = normalize_choice(c.get("modality"), MODALITY_LEVELS, "UNKNOWN")
        c["_certainty"] = normalize_choice(c.get("certainty"), CERTAINTY_LEVELS, "UNKNOWN")
        c["_numeric_value"] = to_float(c.get("numeric_value") or c.get("value"))
        c["_numeric_unit"] = str(c.get("numeric_unit") or c.get("unit") or "").strip() or None
        c["_claim_summary"] = short_text(c.get("claim_text_summary") or c.get("claim_text") or c.get("text"), 260)
        c["_source_ids"] = [str(x).strip() for x in ensure_list(c.get("source_ids") or c.get("source_id")) if x]
        c["_evidence_ids"] = [str(x).strip() for x in ensure_list(c.get("evidence_ids") or c.get("evidence_id")) if x]

        subj = c["_subject"] or ""
        pred = c["_predicate"] or ""
        obj = c["_object"] or ""
        c["_semantic_key"] = f"{subj}|{pred}|{obj}|{c['_time_reference'] or ''}|{c['_location_reference'] or ''}|{c['_numeric_unit'] or ''}"

        claims.append(c)

    return claims, issues


def validate_claim_alignments(
    case: Dict[str, Any],
    claims_by_id: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    issues: List[str] = []
    alignments: List[Dict[str, Any]] = []

    for idx, a in enumerate(get_records(case, "claim_alignments", "cross_language_claims")):
        aid = str(a.get("alignment_id") or a.get("id") or f"ALIGN-{idx + 1}").strip()
        a["alignment_id"] = aid

        left = str(a.get("left_claim_id") or a.get("claim_a") or "").strip()
        right = str(a.get("right_claim_id") or a.get("claim_b") or "").strip()
        a["_left_claim_id"] = left
        a["_right_claim_id"] = right

        if left and left not in claims_by_id:
            issues.append(f"alignment {aid} references unknown left_claim_id={left}")
        if right and right not in claims_by_id:
            issues.append(f"alignment {aid} references unknown right_claim_id={right}")

        a["_relation"] = normalize_choice(
            a.get("relation") or a.get("type"),
            {"SAME_CLAIM", "PARTIAL_MATCH", "CONTRADICTORY_CLAIM", "RELATED_CLAIM", "UNKNOWN"},
            "UNKNOWN"
        )
        a["_confidence"] = str(a.get("confidence") or "UNKNOWN").upper()
        alignments.append(a)

    return alignments, issues


# -----------------------------------------------------------------------------
# Linguistic analysis
# -----------------------------------------------------------------------------

def detect_script(text: Any) -> Dict[str, Any]:
    if text is None:
        return {"script": "UNKNOWN", "confidence": "LOW", "counts": {}, "dominant_ratio": 0.0, "note": "Script is not language."}

    letters = [ch for ch in str(text) if ch.isalpha()]
    if not letters:
        return {"script": "UNKNOWN", "confidence": "LOW", "counts": {}, "dominant_ratio": 0.0, "note": "No alphabetic characters detected."}

    counts = Counter(char_script(ch) for ch in letters)
    total = sum(counts.values())
    ranked = counts.most_common()
    dominant, dom_count = ranked[0]
    ratio = dom_count / total if total else 0.0

    confidence = "HIGH" if ratio >= 0.80 else "MEDIUM" if ratio >= 0.60 else "LOW"
    script = dominant

    if len(ranked) > 1:
        second_ratio = ranked[1][1] / total if total else 0.0
        if second_ratio >= 0.15 and ratio < 0.70:
            script = "MIXED"
            confidence = "LOW"

    return {
        "script": script,
        "confidence": confidence,
        "counts": dict(counts),
        "dominant_ratio": ratio,
        "note": "Script identification does not establish language, nationality, ethnicity, or identity.",
    }


def language_id(text: Any, script_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    script_info = script_info or {}
    s = str(text or "")
    tokens = re.findall(r"\w+", s.lower(), flags=re.UNICODE)

    if len(s.strip()) < 20 or len(tokens) < 5:
        return {
            "language": "UNKNOWN",
            "confidence": "LOW",
            "candidates": [],
            "note": "Short text insufficient for confident language identification.",
            "quality_flags": ["language_uncertain"],
        }

    scores: Dict[str, float] = {}
    for lang, words in STOPWORDS.items():
        match = sum(1 for t in tokens if t in words)
        scores[lang] = match / max(1, len(tokens))

    script = str(script_info.get("script") or "UNKNOWN").upper()

    # Script priors, deliberately weak.
    if script == "DEVANAGARI":
        scores["HI"] = scores.get("HI", 0.0) + 0.10
    elif script == "ARABIC":
        scores["AR"] = scores.get("AR", 0.0) + 0.07
        scores["UR"] = scores.get("UR", 0.0) + 0.07
    elif script == "CYRILLIC":
        scores["RU"] = scores.get("RU", 0.0) + 0.10
    elif script == "HEBREW":
        scores["HE"] = scores.get("HE", 0.0) + 0.10
    elif script == "GREEK":
        scores["EL"] = scores.get("EL", 0.0) + 0.10
    elif script == "HANGUL":
        scores["KO"] = scores.get("KO", 0.0) + 0.10
    elif script == "HAN":
        han_chars = re.findall(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]", s)
        if len(han_chars) >= 5:
            scores["ZH"] = max(scores.get("ZH", 0.0), 0.16 + min(0.10, len(han_chars) / 100.0))

    candidates = sorted(((lang, sc) for lang, sc in scores.items() if sc > 0), key=lambda x: x[1], reverse=True)[:5]

    if not candidates:
        return {
            "language": "UNKNOWN",
            "confidence": "LOW",
            "candidates": [],
            "note": "No sufficient language signal detected.",
            "quality_flags": ["language_uncertain"],
        }

    best_lang, best_score = candidates[0]
    margin = best_score - (candidates[1][1] if len(candidates) > 1 else 0.0)

    if best_score >= 0.18 and margin >= 0.06:
        confidence = "HIGH"
    elif best_score >= 0.12 and margin >= 0.03:
        confidence = "MEDIUM"
    elif best_score >= 0.06:
        confidence = "LOW"
    else:
        return {
            "language": "UNKNOWN",
            "confidence": "LOW",
            "candidates": [{"language": l, "score": round(sc, 4)} for l, sc in candidates],
            "note": "Language signal too weak for confident identification.",
            "quality_flags": ["language_uncertain"],
        }

    return {
        "language": best_lang,
        "confidence": confidence,
        "candidates": [{"language": l, "score": round(sc, 4)} for l, sc in candidates],
        "best_score": round(best_score, 4),
        "margin": round(margin, 4),
        "note": "Language identification does not establish nationality, ethnicity, religion, political belief, or identity.",
    }


def analyze_code_switching(text: Any) -> Dict[str, Any]:
    s = str(text or "")
    chunks = split_sentences(s)
    spans: List[Dict[str, Any]] = []

    for i, ch in enumerate(chunks):
        if len(ch.strip()) < 3:
            continue
        sc = detect_script(ch)
        li = language_id(ch, sc)
        spans.append({
            "span_index": i,
            "text_excerpt": short_text(ch, 120),
            "script": sc.get("script"),
            "language": li.get("language"),
            "language_confidence": li.get("confidence"),
        })

    langs = {x.get("language") for x in spans if x.get("language") not in {"UNKNOWN", "OTHER", None}}

    if len(langs) <= 1:
        state = "MONOLINGUAL_OR_UNDETERMINED"
    else:
        state = "CODE_SWITCHED_OR_MULTILINGUAL_CANDIDATE"

    return {
        "state": state,
        "distinct_language_candidates": sorted(langs),
        "spans": spans[:100],
        "note": "Code-switching or multilingual writing does not establish identity, nationality, ethnicity, or community membership.",
    }


def analyze_text_features(text: Any) -> Dict[str, Any]:
    s = str(text or "")
    sentences = split_sentences(s)
    negation_count = 0
    modality_count = 0
    hedging_count = 0
    certainty_count = 0
    quote_count = 0
    reported_speech_count = 0

    neg_examples: List[str] = []
    mod_examples: List[str] = []
    hedge_examples: List[str] = []
    cert_examples: List[str] = []
    quote_examples: List[str] = []
    rep_examples: List[str] = []

    for sent in sentences:
        raw_lower = sent.lower()
        tokens = re.findall(r"\w+", raw_lower, flags=re.UNICODE)

        neg = any(t in NEGATION_WORDS for t in tokens) or any(p in raw_lower for p in NEGATION_PHRASES)
        mod = any(t in MODAL_WORDS for t in tokens) or any(p in raw_lower for p in MODAL_PHRASES)
        hedge = any(t in HEDGE_WORDS for t in tokens) or any(p in raw_lower for p in HEDGE_PHRASES)
        cert = any(t in CERTAINTY_WORDS for t in tokens) or any(p in raw_lower for p in CERTAINTY_PHRASES)
        quote = bool(re.search(r"[“\"‘\']", sent))
        rep = any(t in REPORTING_VERBS for t in tokens) or any(p in raw_lower for p in REPORTING_PHRASES)

        if neg:
            negation_count += 1
            if len(neg_examples) < 5:
                neg_examples.append(short_text(sent, 140) or "")
        if mod:
            modality_count += 1
            if len(mod_examples) < 5:
                mod_examples.append(short_text(sent, 140) or "")
        if hedge:
            hedging_count += 1
            if len(hedge_examples) < 5:
                hedge_examples.append(short_text(sent, 140) or "")
        if cert:
            certainty_count += 1
            if len(cert_examples) < 5:
                cert_examples.append(short_text(sent, 140) or "")
        if quote:
            quote_count += 1
            if len(quote_examples) < 5:
                quote_examples.append(short_text(sent, 140) or "")
        if rep:
            reported_speech_count += 1
            if len(rep_examples) < 5:
                rep_examples.append(short_text(sent, 140) or "")

    return {
        "sentence_count": len(sentences),
        "negation_count": negation_count,
        "modality_count": modality_count,
        "hedging_count": hedging_count,
        "certainty_count": certainty_count,
        "quote_count": quote_count,
        "reported_speech_count": reported_speech_count,
        "negation_examples": [x for x in neg_examples if x],
        "modality_examples": [x for x in mod_examples if x],
        "hedging_examples": [x for x in hedge_examples if x],
        "certainty_examples": [x for x in cert_examples if x],
        "quote_examples": [x for x in quote_examples if x],
        "reported_speech_examples": [x for x in rep_examples if x],
    }


def extract_terms(text: Any, limit: int = 80) -> List[Dict[str, Any]]:
    tokens = re.findall(r"\w+", normalize_text(text), flags=re.UNICODE)
    filtered = [t for t in tokens if len(t) >= 3 and t not in FUNCTION_WORDS]
    counts = Counter(filtered)
    return [
        {"term": term, "count": count}
        for term, count in counts.most_common(limit)
    ]


def extract_acronyms(text: Any) -> List[str]:
    s = str(text or "")
    found = re.findall(r"\b[A-Z][A-Z0-9]{1,9}\b", s)
    return sorted(set(found))


def extract_entity_mentions(text: Any) -> List[Dict[str, Any]]:
    s = str(text or "")
    pattern = re.compile(r"\b[A-Z][a-zA-Z\u00C0-\u024F]+(?:\s+[A-Z][a-zA-Z\u00C0-\u024F]+){0,3}\b")
    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for m in pattern.finditer(s):
        ment = m.group(0).strip()
        key = ment.lower()
        if key in FUNCTION_WORDS or len(ment) < 2:
            continue
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "mention": ment,
            "type": "UNRESOLVED_ENTITY_MENTION",
            "note": "Mention is not resolved entity identity.",
        })
        if len(out) >= 100:
            break
    return out


def extract_quotes(text: Any) -> List[Dict[str, Any]]:
    s = str(text or "")
    pattern = re.compile(r"[“\"]([^“”\"]{2,500})[”\"]|‘([^‘’]{2,500})’")
    out: List[Dict[str, Any]] = []
    for i, m in enumerate(pattern.finditer(s), 1):
        q = m.group(1) or m.group(2)
        if not q:
            continue
        out.append({
            "quote_id": f"Q-{i}",
            "quote_text": short_text(q, 240),
            "speaker": "UNKNOWN",
            "mode": "DIRECT_QUOTE",
            "verification_state": "UNVERIFIED",
            "note": "Detected quotation marks do not prove speaker identity or verbatim accuracy.",
        })
    return out


def analyze_register(text: Any, features: Dict[str, Any]) -> Dict[str, Any]:
    s = str(text or "").lower()
    scores: Dict[str, int] = defaultdict(int)

    for reg, hints in REGISTER_HINTS.items():
        for h in hints:
            if h in s:
                scores[reg] += 1

    avg_sentence_len = features.get("sentence_count", 0)
    token_count = len(re.findall(r"\w+", normalize_text(text), flags=re.UNICODE))
    if avg_sentence_len and token_count:
        avg = token_count / max(1, avg_sentence_len)
        if avg > 25:
            scores["FORMAL"] += 1
        if avg < 10:
            scores["CONVERSATIONAL"] += 1

    ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    primary = ranked[0][0] if ranked and ranked[0][1] > 0 else "UNKNOWN"

    return {
        "primary_register": primary,
        "candidates": [{"register": r, "score": sc} for r, sc in ranked[:5]],
        "note": "Register is a textual style category, not author identity, authority, or truth.",
    }


def analyze_rhetoric(text: Any) -> Dict[str, Any]:
    s = str(text or "")
    lower = s.lower()
    tokens = re.findall(r"\w+", normalize_text(s), flags=re.UNICODE)

    repeated_phrases: List[Dict[str, Any]] = []
    for n in (3, 4):
        grams = Counter(word_ngrams(tokens, n))
        for gram, count in grams.most_common(20):
            if count >= 3:
                repeated_phrases.append({"ngram_size": n, "phrase": gram, "count": count})
        if repeated_phrases:
            break

    signals: List[Dict[str, Any]] = []
    for cat, phrases in PROPAGANDA_HINTS.items():
        count = 0
        examples: List[str] = []
        for p in phrases:
            c = lower.count(p)
            if c:
                count += c
                if len(examples) < 5:
                    examples.append(p)
        if count:
            signals.append({
                "signal_type": cat,
                "count": count,
                "examples": examples,
            })

    return {
        "repeated_phrases": repeated_phrases[:20],
        "influence_signals": signals,
        "note": "These are descriptive linguistic signals only. They do not prove propaganda, intent, coordination, falsehood, or identity.",
    }


def analyze_text_artifact(t: Dict[str, Any]) -> None:
    if not t.get("_analysis_enabled", True):
        t["_script"] = {"script": "REDACTED", "confidence": "LOW", "counts": {}, "dominant_ratio": 0.0, "note": "Private text redacted."}
        t["_language"] = {"language": "REDACTED", "confidence": "LOW", "candidates": [], "note": "Private text redacted."}
        t["_code_switching"] = {"state": "REDACTED", "distinct_language_candidates": [], "spans": [], "note": "Private text redacted."}
        t["_features"] = analyze_text_features("")
        t["_terms"] = []
        t["_acronyms"] = []
        t["_entity_mentions"] = []
        t["_quotes"] = []
        t["_register"] = {"primary_register": "REDACTED", "candidates": [], "note": "Private text redacted."}
        t["_rhetoric"] = {"repeated_phrases": [], "influence_signals": [], "note": "Private text redacted."}
        t["_translation_drift"] = {}
        t["_terminology_consistency"] = []
        t["_style_features"] = stylometric_features("")
        return

    t["_script"] = detect_script(t["_forensic_text"])
    t["_language"] = language_id(t["_normalized_text"], t["_script"])
    t["_code_switching"] = analyze_code_switching(t["_forensic_text"])
    t["_features"] = analyze_text_features(t["_forensic_text"])
    t["_terms"] = extract_terms(t["_search_text"])
    t["_acronyms"] = extract_acronyms(t["_forensic_text"])
    t["_entity_mentions"] = extract_entity_mentions(t["_forensic_text"])
    t["_quotes"] = extract_quotes(t["_forensic_text"])
    t["_register"] = analyze_register(t["_forensic_text"], t["_features"])
    t["_rhetoric"] = analyze_rhetoric(t["_forensic_text"])
    t["_style_features"] = stylometric_features(t["_stylometry_text"])

    if t.get("_translation_text"):
        t["_translation_drift"] = translation_drift(t["_forensic_text"], t["_translation_text"])
        t["_terminology_consistency"] = terminology_consistency(t)
    else:
        t["_translation_drift"] = {}
        t["_terminology_consistency"] = []
        if t.get("_translation_of"):
            add_flag(t, "translation_missing")


def translation_drift(original: Any, translation: Any) -> Dict[str, Any]:
    orig_feat = analyze_text_features(original)
    trans_feat = analyze_text_features(translation)

    drift: List[Dict[str, Any]] = []

    if orig_feat["negation_count"] > 0 and trans_feat["negation_count"] == 0:
        drift.append({
            "type": "NEGATION_DROP_CANDIDATE",
            "original_negation_count": orig_feat["negation_count"],
            "translation_negation_count": trans_feat["negation_count"],
            "examples": orig_feat.get("negation_examples", [])[:3],
        })

    if orig_feat["modality_count"] > 0 and trans_feat["modality_count"] == 0:
        drift.append({
            "type": "MODALITY_DROP_CANDIDATE",
            "original_modality_count": orig_feat["modality_count"],
            "translation_modality_count": trans_feat["modality_count"],
            "examples": orig_feat.get("modality_examples", [])[:3],
        })

    if orig_feat["hedging_count"] > 0 and trans_feat["hedging_count"] == 0:
        drift.append({
            "type": "HEDGING_DROP_CANDIDATE",
            "original_hedging_count": orig_feat["hedging_count"],
            "translation_hedging_count": trans_feat["hedging_count"],
            "examples": orig_feat.get("hedging_examples", [])[:3],
        })

    if trans_feat["certainty_count"] > orig_feat["certainty_count"] + 1:
        drift.append({
            "type": "CERTAINTY_STRENGTHENING_CANDIDATE",
            "original_certainty_count": orig_feat["certainty_count"],
            "translation_certainty_count": trans_feat["certainty_count"],
            "examples": trans_feat.get("certainty_examples", [])[:3],
        })

    if orig_feat["reported_speech_count"] > 0 and trans_feat["reported_speech_count"] == 0:
        drift.append({
            "type": "ATTRIBUTION_DRIFT_CANDIDATE",
            "original_reported_speech_count": orig_feat["reported_speech_count"],
            "translation_reported_speech_count": trans_feat["reported_speech_count"],
            "examples": orig_feat.get("reported_speech_examples", [])[:3],
        })

    state = "NO_MATERIAL_DRIFT_DETECTED" if not drift else "DRIFT_CANDIDATE"

    return {
        "state": state,
        "drift_events": drift,
        "original_features": orig_feat,
        "translation_features": trans_feat,
        "note": "Lexical drift detection is heuristic. Consequential translation meaning changes require human linguist review.",
    }


def terminology_consistency(t: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    glossary = t.get("_glossary") or {}
    original = str(t.get("_forensic_text") or "").lower()
    translation = str(t.get("_translation_text") or "").lower()

    for term, preferred in glossary.items():
        if not term or not preferred:
            continue
        term_l = str(term).lower()
        pref_l = str(preferred).lower()
        if term_l in original and pref_l not in translation:
            out.append({
                "type": "TERMINOLOGY_INCONSISTENCY_CANDIDATE",
                "source_term": term,
                "preferred_translation": preferred,
                "note": "Preferred glossary term not detected in supplied translation.",
            })

    return out


# -----------------------------------------------------------------------------
# Stylometry / authorship candidate comparison
# -----------------------------------------------------------------------------

def stylometric_features(text: Any) -> Dict[str, Any]:
    s = str(text or "")
    if not s.strip():
        return {"trigrams": {}, "numeric": {}}

    lower = normalize_text(s)
    tokens = re.findall(r"\w+", lower, flags=re.UNICODE)
    sentences = split_sentences(s)

    avg_sentence_len = len(tokens) / max(1, len(sentences))
    punct_counts = Counter(ch for ch in s if ch in ".,;:!?-–—'\"()[]{}")
    total_chars = max(1, len(s))

    numeric = {
        "token_count": float(len(tokens)),
        "avg_sentence_len": float(avg_sentence_len),
        "comma_rate": punct_counts[","] / total_chars,
        "period_rate": punct_counts["."] / total_chars,
        "semicolon_rate": punct_counts[";"] / total_chars,
        "dash_rate": sum(punct_counts[c] for c in "-–—") / total_chars,
        "quote_rate": sum(punct_counts[c] for c in "'\"“”‘’") / total_chars,
        "paren_rate": sum(punct_counts[c] for c in "()[]{}") / total_chars,
        "lexical_diversity": len(set(tokens)) / max(1, len(tokens)),
        "function_word_ratio": sum(1 for t in tokens if t in FUNCTION_WORDS) / max(1, len(tokens)),
    }

    clean = re.sub(r"\s+", " ", lower)
    tri = Counter()
    for i in range(max(0, len(clean) - 2)):
        tri[clean[i:i + 3]] += 1

    norm = math.sqrt(sum(v * v for v in tri.values())) or 1.0
    vec = {k: v / norm for k, v in tri.items()}

    return {"trigrams": vec, "numeric": numeric}


def compare_style(f1: Dict[str, Any], f2: Dict[str, Any]) -> float:
    lex = cosine_dicts(f1.get("trigrams", {}), f2.get("trigrams", {}))

    n1 = f1.get("numeric", {})
    n2 = f2.get("numeric", {})
    diff = 0.0
    keys = set(n1) | set(n2)
    for k in keys:
        a = float(n1.get(k, 0.0))
        b = float(n2.get(k, 0.0))
        scale = max(abs(a), abs(b), 1e-6)
        diff += abs(a - b) / scale

    num_sim = 1.0 / (1.0 + diff) if diff >= 0 else 0.0
    return 0.75 * lex + 0.25 * num_sim


def authorship_analysis(
    texts: List[Dict[str, Any]],
    samples: List[Dict[str, Any]],
    settings: Dict[str, Any],
) -> List[Dict[str, Any]]:
    min_chars = int(settings.get("min_authorship_chars", 200))
    sample_feats: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    sample_genres: Dict[str, Set[str]] = defaultdict(set)

    for s in samples:
        if not s.get("_analysis_enabled", True):
            continue
        author = s.get("_author_candidate_id")
        if not author:
            continue
        feat = stylometric_features(s.get("_stylometry_text", ""))
        sample_feats[author].append(feat)
        sample_genres[author].add(str(s.get("_genre") or "UNKNOWN").upper())

    out: List[Dict[str, Any]] = []

    for t in texts:
        tid = t.get("text_id")
        if not t.get("_analysis_enabled", True):
            out.append({
                "text_id": tid,
                "status": "PRIVACY_BOUNDARY",
                "candidates": [],
                "unknown_author_possible": True,
                "limitations": ["Private text redacted; authorship comparison disabled."],
            })
            continue

        if not t.get("_authorship_allowed", True):
            out.append({
                "text_id": tid,
                "status": "PRIVACY_BOUNDARY",
                "candidates": [],
                "unknown_author_possible": True,
                "limitations": ["Authorship analysis disabled by privacy boundary."],
            })
            continue

        text_len = len(str(t.get("_stylometry_text") or ""))
        if text_len < min_chars:
            out.append({
                "text_id": tid,
                "status": "INSUFFICIENT_TEXT",
                "text_length": text_len,
                "minimum_required": min_chars,
                "candidates": [],
                "unknown_author_possible": True,
                "limitations": ["Insufficient text length for reliable stylometric comparison."],
            })
            continue

        tf = t.get("_style_features") or stylometric_features(t.get("_stylometry_text", ""))
        candidates: List[Dict[str, Any]] = []

        for author, feats in sample_feats.items():
            sims = [compare_style(tf, sf) for sf in feats]
            if not sims:
                continue
            avg = sum(sims) / len(sims)
            mx = max(sims)
            mn = min(sims)

            genre_mismatch = False
            text_genre = str(t.get("_genre") or "UNKNOWN").upper()
            if text_genre != "UNKNOWN" and sample_genres.get(author):
                if text_genre not in sample_genres[author]:
                    genre_mismatch = True

            if avg >= 0.72:
                label = "CONSISTENT_WITH"
            elif avg >= 0.58:
                label = "MORE_CONSISTENT_WITH"
            elif avg <= 0.30:
                label = "INCONSISTENT_WITH"
            else:
                label = "LESS_CONSISTENT_WITH"

            candidates.append({
                "author_candidate_id": author,
                "label": label,
                "average_similarity": round(avg, 4),
                "max_similarity": round(mx, 4),
                "min_similarity": round(mn, 4),
                "sample_count": len(feats),
                "genre_mismatch": genre_mismatch,
                "limitations": [
                    "Stylometric consistency is not identity proof.",
                    "Genre, topic, editing, translation, collaboration, AI assistance, and small corpus size can distort comparison.",
                    "Authorship does not establish account control or real-world identity.",
                ],
            })

        candidates.sort(key=lambda x: x.get("average_similarity", 0.0), reverse=True)

        if not candidates:
            status = "UNKNOWN_AUTHOR"
        elif candidates[0].get("average_similarity", 0.0) < 0.35:
            status = "UNKNOWN_AUTHOR"
        elif candidates[0].get("average_similarity", 0.0) < 0.58:
            status = "INCONCLUSIVE"
        else:
            status = candidates[0].get("label", "INCONCLUSIVE")

        out.append({
            "text_id": tid,
            "status": status,
            "text_length": text_len,
            "candidates": candidates[:10],
            "unknown_author_possible": True,
            "closed_set_only": True,
            "limitations": [
                "This is closed-set candidate comparison only, not open-world identification.",
                "Do not infer nationality, ethnicity, religion, race, political belief, health, or criminality.",
                "Do not treat stylistic consistency as definitive authorship.",
            ],
        })

    return out


# -----------------------------------------------------------------------------
# Duplicate / template / clustering / source independence
# -----------------------------------------------------------------------------

def make_skeleton(text: Any) -> str:
    s = normalize_text(text)
    s = re.sub(r"\d+", "#", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def duplicate_analysis(texts: List[Dict[str, Any]], settings: Dict[str, Any]) -> Dict[str, Any]:
    relationships: List[Dict[str, Any]] = []
    exact_groups: Dict[str, List[str]] = defaultdict(list)
    skeleton_groups: Dict[str, List[str]] = defaultdict(list)

    for t in texts:
        t["_duplicate_state"] = "UNKNOWN"
        t["_duplicate_similarity"] = None
        t["_skeleton_hash"] = normalized_hash(make_skeleton(t.get("_search_text", ""))) if t.get("_analysis_enabled", True) else None

        nh = t.get("_normalized_hash")
        if nh:
            exact_groups[nh].append(t["text_id"])

        sk = t.get("_skeleton_hash")
        if sk and len(str(t.get("_search_text") or "")) > 50:
            skeleton_groups[sk].append(t["text_id"])

    for h, ids in exact_groups.items():
        if len(ids) > 1:
            for tid in ids:
                next(x for x in texts if x["text_id"] == tid)["_duplicate_state"] = "EXACT_DUPLICATE"
            relationships.append({
                "type": "exact_duplicate",
                "normalized_hash": h,
                "text_ids": sorted(ids),
            })

    max_pairs = int(settings.get("max_near_duplicate_pairs", 5000))
    light = float(settings.get("near_duplicate_light_threshold", 0.75))
    partial = float(settings.get("near_duplicate_partial_threshold", 0.45))

    comparable = [t for t in texts if t.get("_shingles") and t.get("_analysis_enabled", True)]
    pairs = 0
    for i in range(len(comparable)):
        if pairs >= max_pairs:
            break
        a = comparable[i]
        for j in range(i + 1, len(comparable)):
            if pairs >= max_pairs:
                break
            b = comparable[j]
            if a.get("_duplicate_state") == "EXACT_DUPLICATE" or b.get("_duplicate_state") == "EXACT_DUPLICATE":
                continue
            if a.get("_language", {}).get("language") and b.get("_language", {}).get("language"):
                if a["_language"]["language"] != b["_language"]["language"]:
                    continue
            sim = jaccard(a["_shingles"], b["_shingles"])
            pairs += 1
            if sim >= light:
                state = "LIGHT_REWRITE"
            elif sim >= partial:
                state = "PARTIAL_OVERLAP"
            else:
                state = "DISTINCT"

            if state != "DISTINCT":
                for m in (a, b):
                    if m["_duplicate_state"] in {"UNKNOWN", "DISTINCT"}:
                        m["_duplicate_state"] = state
                    m["_duplicate_similarity"] = max(m.get("_duplicate_similarity") or 0.0, sim)
                relationships.append({
                    "type": "near_duplicate",
                    "text_ids": [a["text_id"], b["text_id"]],
                    "similarity": round(sim, 4),
                    "state": state,
                })
            else:
                for m in (a, b):
                    if m["_duplicate_state"] == "UNKNOWN":
                        m["_duplicate_state"] = "DISTINCT"

    for sk, ids in skeleton_groups.items():
        if len(ids) > 1:
            relationships.append({
                "type": "template_skeleton_match",
                "skeleton_hash": sk,
                "text_ids": sorted(ids),
                "note": "Shared normalized skeleton may indicate template, boilerplate, translation, or common source; not same author.",
            })

    # Rare shared phrases.
    n = int(settings.get("rare_phrase_ngram", 4))
    max_rare_df = int(settings.get("rare_phrase_max_df", 3))
    df: Counter = Counter()
    text_ngrams: Dict[str, Set[str]] = {}

    for t in texts:
        if not t.get("_analysis_enabled", True):
            continue
        toks = re.findall(r"\w+", t.get("_search_text", ""), flags=re.UNICODE)
        grams = set(word_ngrams(toks, n))
        text_ngrams[t["text_id"]] = grams
        for g in grams:
            df[g] += 1

    shared_rare: List[Dict[str, Any]] = []
    for gram, count in df.items():
        if 2 <= count <= max_rare_df:
            ids = [tid for tid, gs in text_ngrams.items() if gram in gs]
            if len(ids) >= 2:
                shared_rare.append({
                    "phrase": gram,
                    "document_frequency": count,
                    "text_ids": sorted(ids),
                })

    shared_rare.sort(key=lambda x: (-x["document_frequency"], x["phrase"]))

    return {
        "relationships": relationships,
        "exact_groups": {h: sorted(ids) for h, ids in exact_groups.items() if len(ids) > 1},
        "skeleton_groups": {h: sorted(ids) for h, ids in skeleton_groups.items() if len(ids) > 1},
        "shared_rare_phrases": shared_rare[:100],
        "note": "Similarity, templates, and shared phrases are not proof of common author, coordination, or intent.",
    }


def document_clusters(texts: List[Dict[str, Any]], duplicates: Dict[str, Any]) -> List[Dict[str, Any]]:
    dsu = DSU()
    for t in texts:
        dsu.find(t["text_id"])

    for rel in duplicates.get("relationships", []):
        ids = rel.get("text_ids") or []
        if len(ids) >= 2 and rel.get("type") != "template_skeleton_match":
            for a, b in zip(ids, ids[1:]):
                dsu.union(a, b)

    for h, ids in (duplicates.get("skeleton_groups") or {}).items():
        for a, b in zip(ids, ids[1:]):
            dsu.union(a, b)

    by_text = {t["text_id"]: t for t in texts}

    for t in texts:
        tr = t.get("_translation_of")
        if tr and tr in by_text:
            dsu.union(t["text_id"], tr)

    groups: Dict[str, List[str]] = defaultdict(list)
    for t in texts:
        root = dsu.find(t["text_id"])
        groups[root].append(t["text_id"])

    out: List[Dict[str, Any]] = []
    for i, (root, ids) in enumerate(sorted(groups.items(), key=lambda x: x[0]), 1):
        ids = sorted(ids)
        its = [by_text[x] for x in ids if x in by_text]
        types: List[str] = []

        if any(x.get("_translation_of") for x in its):
            types.append("TRANSLATION_CLUSTER")
        if len(ids) > 1 and any(x.get("_duplicate_state") in {"EXACT_DUPLICATE", "LIGHT_REWRITE", "PARTIAL_OVERLAP"} for x in its):
            types.append("CONTENT_CLUSTER")
        if len(set(x.get("_skeleton_hash") for x in its if x.get("_skeleton_hash"))) == 1 and len(ids) > 1:
            types.append("TEMPLATE_CLUSTER")
        if not types:
            types.append("SINGLETON")

        out.append({
            "cluster_id": f"CLU-{i:04d}",
            "text_ids": ids,
            "cluster_types": types,
            "languages": sorted({x.get("_language", {}).get("language") for x in its if x.get("_language", {}).get("language")}),
            "note": "Cluster type does not establish common author, operator, intent, or source.",
        })

    return out


def source_independence_analysis(
    texts: List[Dict[str, Any]],
    sources: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    family_members: Dict[str, List[str]] = defaultdict(list)
    per_text: List[Dict[str, Any]] = []

    for t in texts:
        sid = t.get("_source_id")
        src = sources.get(sid or "", {})
        family = src.get("_independence_group") or sid or t["text_id"]
        family = str(family).upper()
        t["_source_family_id"] = family
        family_members[family].append(t["text_id"])

        state = "UNKNOWN"
        if t.get("_translation_of"):
            state = "DEPENDENT_TRANSLATION"
        elif len(family_members[family]) == 1:
            state = "SINGLE_SOURCE"
        elif len({x.get("_source_id") for x in texts if x.get("_source_family_id") == family}) <= 1:
            state = "DEPENDENT_OR_SAME_SOURCE"
        else:
            state = "POSSIBLY_INDEPENDENT"

        per_text.append({
            "text_id": t["text_id"],
            "source_id": sid,
            "source_family_id": family,
            "independence_state": state,
            "limitations": [
                "Independence is assessed from supplied source metadata only.",
                "Multiple translations/copies are not independent evidence.",
            ],
        })

    independent_families = [f for f, ids in family_members.items() if len(ids) >= 1]

    return {
        "global_family_count": len(independent_families),
        "families": {f: sorted(ids) for f, ids in family_members.items()},
        "per_text": per_text,
        "note": "Count information families, not raw text count.",
    }


# -----------------------------------------------------------------------------
# Contradictions / facts / hypotheses / dual review
# -----------------------------------------------------------------------------

def modality_rank(m: str) -> int:
    return {
        "CERTAIN": 5,
        "HIGH_CONFIDENCE": 4,
        "MODERATE": 3,
        "TENTATIVE": 2,
        "SPECULATIVE": 1,
        "UNKNOWN": 0,
    }.get(str(m or "").upper(), -1)


def detect_contradictions(
    claims: List[Dict[str, Any]],
    texts: List[Dict[str, Any]],
    alignments: List[Dict[str, Any]],
    initial_contradictions: List[Dict[str, Any]],
    settings: Dict[str, Any],
) -> List[Dict[str, Any]]:
    contradictions = list(initial_contradictions)

    # Claim negation conflicts.
    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for c in claims:
        key = c.get("_semantic_key") or ""
        # Remove negation from key? semantic key doesn't include negation.
        groups[key].append(c)

    for key, cs in groups.items():
        if len(cs) < 2:
            continue
        negs = {bool(c.get("_negation")) for c in cs}
        if len(negs) > 1:
            for c in cs:
                add_flag(c, "claim_negation_conflict")
            contradictions.append({
                "type": "claim_negation_conflict",
                "semantic_key": key,
                "claim_ids": [c.get("claim_id") for c in cs],
                "note": "Same proposition appears asserted and negated across supplied claims.",
            })

        vals = [c.get("_numeric_value") for c in cs if c.get("_numeric_value") is not None]
        if len(vals) >= 2:
            lo, hi = min(vals), max(vals)
            scale = max(abs(lo), abs(hi), 1e-9)
            tol = float(settings.get("numeric_relative_tolerance", 0.05))
            if (hi - lo) / scale > tol:
                for c in cs:
                    add_flag(c, "numeric_claim_conflict")
                contradictions.append({
                    "type": "numeric_claim_conflict",
                    "semantic_key": key,
                    "claim_ids": [c.get("claim_id") for c in cs],
                    "values": vals,
                    "note": "Numeric claims conflict; preserve definitions and sources rather than averaging.",
                })

        mods = [modality_rank(c.get("_modality")) for c in cs if c.get("_modality")]
        if mods and max(mods) - min(mods) >= 3:
            for c in cs:
                add_flag(c, "modality_claim_conflict")
            contradictions.append({
                "type": "modality_claim_conflict",
                "semantic_key": key,
                "claim_ids": [c.get("claim_id") for c in cs],
                "modalities": [c.get("_modality") for c in cs],
                "note": "Certainty/modality differs materially across aligned claims.",
            })

    # Alignment contradictions.
    claims_by_id = {c["claim_id"]: c for c in claims}
    for a in alignments:
        if a.get("_relation") == "CONTRADICTORY_CLAIM":
            contradictions.append({
                "type": "aligned_claim_contradiction",
                "alignment_id": a.get("alignment_id"),
                "left_claim_id": a.get("_left_claim_id"),
                "right_claim_id": a.get("_right_claim_id"),
                "note": "Supplied claim alignment marks contradiction.",
            })

    # Translation drift as material linguistic contradiction candidate.
    for t in texts:
        drift = t.get("_translation_drift") or {}
        if drift.get("state") == "DRIFT_CANDIDATE":
            for ev in drift.get("drift_events", []):
                contradictions.append({
                    "type": "translation_drift_candidate",
                    "text_id": t.get("text_id"),
                    "drift_type": ev.get("type"),
                    "details": ev,
                    "note": "Translation may have dropped negation/modality or strengthened certainty. Human review required for consequential meaning.",
                })

    return contradictions


def build_facts(
    texts: List[Dict[str, Any]],
    claims: List[Dict[str, Any]],
    duplicates: Dict[str, Any],
    clusters: List[Dict[str, Any]],
    authorship: List[Dict[str, Any]],
    source_independence: Dict[str, Any],
    contradictions: List[Dict[str, Any]],
    sources: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    supported: List[Dict[str, Any]] = []
    candidates: List[Dict[str, Any]] = []
    partial: List[Dict[str, Any]] = []
    disputed: List[Dict[str, Any]] = []

    not_facts = [
        "Language is not nationality.",
        "Script is not language.",
        "Dialect is not birthplace.",
        "Accent is not ethnicity.",
        "Terminology is not organizational membership.",
        "Jargon is not insider access.",
        "Professional vocabulary is not occupation.",
        "Sentiment is not mental state.",
        "Emotion words are not deception.",
        "Good grammar is not truth.",
        "Bad grammar is not low intelligence or unreliability.",
        "Similar text is not same author.",
        "Same template is not same operator.",
        "Same style is not same person.",
        "Style shift is not account compromise.",
        "AI-generated text is not maliciousness.",
        "Machine translation is not foreign authorship.",
        "Multiple translations are not independent sources.",
        "Multiple articles copying one press release are not independent corroboration.",
        "Coordinated language is not coordinated inauthentic behavior without additional evidence.",
        "Propaganda signals are not falsehood.",
        "Misinformation is not disinformation without evidence of intent.",
        "Authorship is not account control.",
        "Account control is not real-world identity.",
        "AI agreement is not linguistic corroboration.",
        "No race, ethnicity, religion, sexuality, health, mental-health, criminality, or nationality inference is supported.",
        "No definitive author identification, lie detection, manipulation, propaganda, phishing, harassment, or private-person deanonymization is supported.",
    ]

    for t in texts:
        if not t.get("_analysis_enabled", True):
            partial.append({
                "fact_id": f"FCT-TEXT-{len(partial) + 1}",
                "statement": f"Text {t.get('text_id')} is redacted by privacy boundary.",
                "text_id": t.get("text_id"),
                "confidence": "HIGH",
                "limitation": "No linguistic inference performed on redacted private text.",
            })
            continue

        lang = t.get("_language", {})
        script = t.get("_script", {})
        candidates.append({
            "fact_id": f"FCT-TEXT-{len(supported) + len(candidates) + len(partial) + 1}",
            "statement": (
                f"Text {t.get('text_id')} has detected script {script.get('script')} "
                f"({script.get('confidence')}) and language candidate {lang.get('language')} "
                f"({lang.get('confidence')}); normalized hash {t.get('_normalized_hash')}."
            ),
            "text_id": t.get("text_id"),
            "confidence": "MODERATE" if lang.get("confidence") in {"HIGH", "MEDIUM"} else "LOW",
            "limitation": "Language/script detection does not establish identity, nationality, ethnicity, religion, or authorship.",
        })

        for term in (t.get("_terms") or [])[:10]:
            partial.append({
                "fact_id": f"FCT-TERM-{len(partial) + 1}",
                "statement": f"Term '{term.get('term')}' appears {term.get('count')} times in text {t.get('text_id')}.",
                "text_id": t.get("text_id"),
                "confidence": "HIGH",
                "limitation": "Term use does not prove membership, occupation, insider access, or identity.",
            })

        for q in (t.get("_quotes") or [])[:10]:
            partial.append({
                "fact_id": f"FCT-QUOTE-{len(partial) + 1}",
                "statement": f"Quote detected in text {t.get('text_id')}: {short_text(q.get('quote_text'), 120)}",
                "text_id": t.get("text_id"),
                "quote_id": q.get("quote_id"),
                "confidence": "LOW",
                "limitation": "Detected quotation does not verify speaker, verbatim accuracy, or context.",
            })

        drift = t.get("_translation_drift") or {}
        if drift.get("state") == "DRIFT_CANDIDATE":
            disputed.append({
                "fact_id": f"FCT-DRIFT-{len(disputed) + 1}",
                "statement": f"Translation drift candidate detected in text {t.get('text_id')}: {[e.get('type') for e in drift.get('drift_events', [])]}.",
                "text_id": t.get("text_id"),
                "confidence": "MODERATE",
                "limitation": "Heuristic drift detection requires human linguist review for consequential meaning.",
            })

    for c in claims:
        partial.append({
            "fact_id": f"FCT-CLAIM-{len(partial) + 1}",
            "statement": (
                f"Claim {c.get('claim_id')} in text {c.get('_text_id')} is typed {c.get('_claim_type')} "
                f"with negation={c.get('_negation')} and modality={c.get('_modality')}."
            ),
            "claim_id": c.get("claim_id"),
            "confidence": "MODERATE",
            "limitation": "Claim expression is not fact verification.",
        })

    for rel in (duplicates.get("relationships") or [])[:50]:
        candidates.append({
            "fact_id": f"FCT-DUP-{len(candidates) + 1}",
            "statement": f"Text relationship {rel.get('type')} among {rel.get('text_ids')}.",
            "confidence": "MODERATE" if rel.get("type") == "exact_duplicate" else "LOW",
            "limitation": "Duplicate/template similarity is not common authorship or coordination.",
        })

    for clus in clusters[:50]:
        candidates.append({
            "fact_id": f"FCT-CLU-{len(candidates) + 1}",
            "statement": f"Document cluster {clus.get('cluster_id')} contains {clus.get('text_ids')} with types {clus.get('cluster_types')}.",
            "confidence": "LOW",
            "limitation": "Cluster does not establish common author, operator, source, or intent.",
        })

    for a in authorship:
        if a.get("status") in {"CONSISTENT_WITH", "MORE_CONSISTENT_WITH", "LESS_CONSISTENT_WITH", "INCONSISTENT_WITH"}:
            candidates.append({
                "fact_id": f"FCT-AUTH-{len(candidates) + 1}",
                "statement": f"Text {a.get('text_id')} authorship status: {a.get('status')} within supplied closed-set candidates.",
                "text_id": a.get("text_id"),
                "confidence": "LOW",
                "limitation": "Stylometric consistency is not identity proof and does not establish account control.",
            })
        else:
            partial.append({
                "fact_id": f"FCT-AUTH-{len(partial) + 1}",
                "statement": f"Text {a.get('text_id')} authorship status: {a.get('status')}.",
                "text_id": a.get("text_id"),
                "confidence": "LOW",
                "limitation": "Insufficient or inconclusive stylometric evidence; no author identification.",
            })

    for c in contradictions:
        disputed.append({
            "disputed_id": f"DIS-{len(disputed) + 1}",
            "type": c.get("type"),
            "statement": "Material linguistic contradiction present; do not silently resolve.",
            "details": c,
        })

    return supported, candidates, partial, disputed, not_facts


def build_hypotheses(
    texts: List[Dict[str, Any]],
    duplicates: Dict[str, Any],
    clusters: List[Dict[str, Any]],
    authorship: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    issues: List[str],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    hypotheses: List[Dict[str, Any]] = []
    ach_matrix: List[Dict[str, Any]] = []

    # Duplicate/template hypotheses.
    if duplicates.get("relationships"):
        for idx, rel in enumerate(duplicates.get("relationships", [])[:10], 1):
            base = {
                "hypothesis_set_id": f"HSET-DUP-{idx}",
                "relationship_type": rel.get("type"),
                "text_ids": rel.get("text_ids"),
            }
            for hid, desc in [
                ("H1", "texts share a common upstream source or template"),
                ("H2", "one text directly copied another"),
                ("H3", "texts independently used standard genre/industry wording"),
                ("H4", "texts derive from an unknown third source"),
                ("H5", "similarity is caused by translation or editorial normalization"),
            ]:
                hypotheses.append({
                    **base,
                    "hypothesis_id": f"HDUP{idx}-{hid}",
                    "statement": f"Text relationship {rel.get('type')} among {rel.get('text_ids')} may be explained by: {desc}.",
                    "support": [f"Supplied similarity: {rel.get('similarity')}" if rel.get("similarity") else "Exact/shared skeleton or duplicate metadata supplied."],
                    "opposition": ["No temporal/order evidence." if not any(t.get("_published_at") for t in texts if t.get("text_id") in (rel.get("text_ids") or [])) else "Timestamps supplied; inspect chronology."],
                    "unknowns": ["upstream source", "editorial process", "template provenance", "author identity"],
                    "falsification_conditions": [
                        "Independent upstream source excluded by chronology or provenance.",
                        "Shared wording shown to be public boilerplate.",
                        "Translation/editing explains similarity.",
                    ],
                })
                ach_matrix.append({
                    "set_id": base["hypothesis_set_id"],
                    "hypothesis_id": f"HDUP{idx}-{hid}",
                    "evidence_consistency": ["CONSISTENT if shared phrase is rare and temporally plausible", "INCONSISTENT if public template explains overlap"],
                })

    # Translation drift hypotheses.
    for idx, t in enumerate([x for x in texts if (x.get("_translation_drift") or {}).get("state") == "DRIFT_CANDIDATE"], 1):
        drift = t.get("_translation_drift") or {}
        base = {
            "hypothesis_set_id": f"HSET-DRIFT-{idx}",
            "text_id": t.get("text_id"),
            "drift_types": [e.get("type") for e in drift.get("drift_events", [])],
        }
        for hid, desc in [
            ("H1", "translator omitted or normalized uncertainty/negation inadvertently"),
            ("H2", "machine translation produced literal or certainty-altered output"),
            ("H3", "editorial summary intentionally strengthened claim"),
            ("H4", "target-language convention expresses modality differently"),
            ("H5", "source and translation describe different snapshots or scopes"),
        ]:
            hypotheses.append({
                **base,
                "hypothesis_id": f"HDRIFT{idx}-{hid}",
                "statement": f"Translation drift in text {t.get('text_id')} may be explained by: {desc}.",
                "support": [f"Drift events: {base['drift_types']}"],
                "opposition": ["No human translation review supplied."],
                "unknowns": ["translator intent", "source scope", "target-language convention", "consequential legal meaning"],
                "falsification_conditions": [
                    "Independent human translation preserves original modality/negation.",
                    "Original and translation refer to different events/times.",
                    "Target-language grammar legitimately removes explicit hedge.",
                ],
            })
            ach_matrix.append({
                "set_id": base["hypothesis_set_id"],
                "hypothesis_id": f"HDRIFT{idx}-{hid}",
                "evidence_consistency": ["CONSISTENT with supplied lexical drift", "UNKNOWN without translator/editor evidence"],
            })

    # Authorship hypotheses.
    for idx, a in enumerate([x for x in authorship if x.get("candidates")], 1):
        base = {
            "hypothesis_set_id": f"HSET-AUTH-{idx}",
            "text_id": a.get("text_id"),
            "status": a.get("status"),
        }
        for hid, desc in [
            ("H1", "text is stylistically consistent with one supplied candidate corpus"),
            ("H2", "similarity reflects shared editor, team, template, or genre"),
            ("H3", "similarity reflects AI assistance or rewriting"),
            ("H4", "small corpus or topic effects produce false consistency"),
            ("H5", "unknown author outside supplied candidate set"),
        ]:
            hypotheses.append({
                **base,
                "hypothesis_id": f"HAUTH{idx}-{hid}",
                "statement": f"Authorship comparison for text {a.get('text_id')} may be explained by: {desc}.",
                "support": [f"Candidate labels: {[(c.get('author_candidate_id'), c.get('label')) for c in a.get('candidates', [])[:3]]}"],
                "opposition": ["Genre mismatch." if any(c.get("genre_mismatch") for c in a.get("candidates", [])) else "No genre mismatch flag supplied."],
                "unknowns": ["real-world author", "account control", "editing chain", "collaboration", "AI use"],
                "falsification_conditions": [
                    "Larger authorized corpus changes ranking.",
                    "Known editor/template/AI provenance explains style.",
                    "Non-linguistic evidence excludes candidate.",
                ],
            })
            ach_matrix.append({
                "set_id": base["hypothesis_set_id"],
                "hypothesis_id": f"HAUTH{idx}-{hid}",
                "evidence_consistency": ["CONSISTENT only as stylometric candidate", "NOT identity proof"],
            })

    if issues:
        hypotheses.append({
            "hypothesis_set_id": "HSET-GLOBAL",
            "hypothesis_id": "H-GLOBAL-VALIDATION-WEAKNESS",
            "statement": "Validation issues materially weaken all linguistic interpretations.",
            "support": issues[:10],
            "opposition": ["No independent clean corpus supplied yet."],
            "falsification_conditions": ["Resolve validation issues and rerun deterministic ingestion."],
        })
        ach_matrix.append({
            "set_id": "HSET-GLOBAL",
            "hypothesis_id": "H-GLOBAL-VALIDATION-WEAKNESS",
            "evidence_consistency": ["CONSISTENT with validation issues"],
        })

    return hypotheses, ach_matrix


def dual_ai_review(
    texts: List[Dict[str, Any]],
    claims: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    authorship: List[Dict[str, Any]],
    issues: List[str],
) -> Dict[str, Any]:
    primary = {
        "role": "Primary Linguistic Analyst",
        "assessment": (
            "Text artifacts, claims, translations, and/or author-sample metadata exist."
            if texts or claims
            else "No usable linguistic records were supplied."
        ),
        "classification": "Language, translation, discourse, terminology, and authorship-candidate conclusions remain conservative and evidence-bounded.",
    }

    if not texts and not claims:
        skeptic = {
            "role": "Independent Linguistic Skeptic",
            "verdict": "INSUFFICIENT_EVIDENCE",
            "reason": "No deterministic text records were supplied. Do not infer language, translation, author, identity, or intent from narrative.",
        }
    elif issues:
        skeptic = {
            "role": "Independent Linguistic Skeptic",
            "verdict": "PARTIAL_AGREEMENT",
            "reason": "Validation issues require downgraded confidence.",
        }
    elif contradictions:
        skeptic = {
            "role": "Independent Linguistic Skeptic",
            "verdict": "PARTIAL_AGREEMENT",
            "reason": "Contradictions and translation drift must be preserved; do not silently resolve meaning changes.",
        }
    elif any(a.get("status") in {"CONSISTENT_WITH", "MORE_CONSISTENT_WITH"} for a in authorship):
        skeptic = {
            "role": "Independent Linguistic Skeptic",
            "verdict": "PARTIAL_AGREEMENT",
            "reason": "Stylometric consistency is candidate-level only; do not convert to definitive authorship, identity, nationality, or intent.",
        }
    else:
        skeptic = {
            "role": "Independent Linguistic Skeptic",
            "verdict": "AGREE_ON_DESCRIPTIVE_LINGUISTIC_CONTEXT_ONLY",
            "reason": "Records may support descriptive language/translation/discourse analysis only, not sensitive-trait inference or consequential attribution.",
        }

    return {
        "primary": primary,
        "skeptic": skeptic,
        "comparison": skeptic.get("verdict", "INSUFFICIENT_EVIDENCE"),
        "note": "Rule-based dual-review scaffold. AI agreement is not independent linguistic evidence. Humans govern consequential attribution/translation decisions.",
    }


# -----------------------------------------------------------------------------
# Graphical memory scaffold
# -----------------------------------------------------------------------------

def build_graph(
    sources: Dict[str, Dict[str, Any]],
    texts: List[Dict[str, Any]],
    claims: List[Dict[str, Any]],
    alignments: List[Dict[str, Any]],
    duplicates: Dict[str, Any],
    clusters: List[Dict[str, Any]],
    authorship: List[Dict[str, Any]],
    source_independence: Dict[str, Any],
    facts: List[Dict[str, Any]],
    hypotheses: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    gaps: List[Dict[str, Any]],
) -> Dict[str, Any]:
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    def add_node(node_id: str, node_type: str, props: Dict[str, Any]) -> None:
        if not node_id:
            return
        if any(n.get("id") == node_id for n in nodes):
            return
        nodes.append({"id": node_id, "type": node_type, "properties": props})

    def add_edge(src: str, dst: str, rel: str, props: Dict[str, Any]) -> None:
        if not src or not dst:
            return
        edges.append({"from": src, "to": dst, "type": rel, "properties": props})

    for sid, s in sources.items():
        add_node(sid, "Source", public_dict(s))

    for t in texts:
        tid = t.get("text_id")
        add_node(
            tid,
            "TextArtifact",
            {
                "text_type": t.get("text_type"),
                "source_id": t.get("_source_id"),
                "published_at": iso_or_none(t.get("_published_at")),
                "language": t.get("_language", {}).get("language"),
                "language_confidence": t.get("_language", {}).get("confidence"),
                "script": t.get("_script", {}).get("script"),
                "script_confidence": t.get("_script", {}).get("confidence"),
                "normalized_hash": t.get("_normalized_hash"),
                "translation_of": t.get("_translation_of"),
                "source_family_id": t.get("_source_family_id"),
                "duplicate_state": t.get("_duplicate_state"),
                "quality_flags": t.get("_quality_flags"),
            },
        )
        if t.get("_source_id"):
            add_edge(tid, t["_source_id"], "SOURCED_FROM", {"text_id": tid})
        if t.get("_translation_of"):
            add_edge(tid, t["_translation_of"], "TRANSLATED_FROM", {"text_id": tid})
        if t.get("_source_family_id"):
            add_edge(tid, t["_source_family_id"], "BELONGS_TO_SOURCE_FAMILY", {"text_id": tid})

        lang = t.get("_language", {}).get("language")
        if lang and lang not in {"UNKNOWN", "REDACTED"}:
            add_node(lang, "Language", {"note": "Language does not establish identity."})
            add_edge(tid, lang, "WRITTEN_IN", {"text_id": tid})

        script = t.get("_script", {}).get("script")
        if script and script not in {"UNKNOWN", "REDACTED"}:
            add_node(script, "Script", {"note": "Script is not language."})
            add_edge(tid, script, "USES_SCRIPT", {"text_id": tid})

        for term in (t.get("_terms") or [])[:20]:
            term_id = "TERM-" + (sha256_text(term.get("term")) or term.get("term", ""))[:12]
            add_node(term_id, "Term", {"term": term.get("term"), "count": term.get("count")})
            add_edge(tid, term_id, "CONTAINS_TERM", {"text_id": tid})

        for q in (t.get("_quotes") or [])[:20]:
            qid = f"{tid}-{q.get('quote_id')}"
            add_node(qid, "Quote", {
                "text_id": tid,
                "quote_text": q.get("quote_text"),
                "speaker": q.get("speaker"),
                "mode": q.get("mode"),
                "verification_state": q.get("verification_state"),
            })
            add_edge(tid, qid, "CONTAINS_QUOTE", {"text_id": tid})

    for c in claims:
        cid = c.get("claim_id")
        add_node(cid, "Claim", {
            "text_id": c.get("_text_id"),
            "claim_type": c.get("_claim_type"),
            "subject": c.get("_subject"),
            "predicate": c.get("_predicate"),
            "object": c.get("_object"),
            "negation": c.get("_negation"),
            "modality": c.get("_modality"),
            "certainty": c.get("_certainty"),
            "summary": c.get("_claim_summary"),
        })
        if c.get("_text_id"):
            add_edge(cid, c["_text_id"], "EXPRESSED_IN", {"claim_id": cid})

    for a in alignments:
        aid = a.get("alignment_id")
        add_node(aid, "ClaimAlignment", public_dict(a))
        if a.get("_left_claim_id"):
            add_edge(aid, a["_left_claim_id"], "ALIGNS", {"alignment_id": aid})
        if a.get("_right_claim_id"):
            add_edge(aid, a["_right_claim_id"], "ALIGNS", {"alignment_id": aid})

    for rel in (duplicates.get("relationships") or [])[:100]:
        rid = "DUP-" + (sha256_text(json.dumps(rel, sort_keys=True, default=str)) or "")[:12]
        add_node(rid, "TextRelationship", rel)
        for tid in rel.get("text_ids") or []:
            add_edge(rid, tid, "RELATES_TO", {"relationship_id": rid})

    for clus in clusters:
        cid = clus.get("cluster_id")
        add_node(cid, "DocumentCluster", clus)
        for tid in clus.get("text_ids") or []:
            add_edge(tid, cid, "BELONGS_TO_CLUSTER", {"cluster_id": cid})

    for a in authorship:
        aid = "AUTH-" + str(a.get("text_id"))
        add_node(aid, "AuthorshipAssessment", a)
        if a.get("text_id"):
            add_edge(aid, a["text_id"], "ASSESSS_TEXT", {"assessment_id": aid})
        for cand in a.get("candidates") or []:
            cid = cand.get("author_candidate_id")
            if cid:
                add_node(cid, "AuthorCandidate", {"note": "Closed-set candidate only; not real-world identity."})
                add_edge(aid, cid, cand.get("label") or "COMPARES_TO", {"text_id": a.get("text_id")})

    for fam, ids in (source_independence.get("families") or {}).items():
        fid = "FAM-" + str(fam)
        add_node(fid, "SourceFamily", {"text_ids": ids})
        for tid in ids:
            add_edge(tid, fid, "BELONGS_TO_SOURCE_FAMILY", {"family_id": fid})

    for fac in facts:
        fid = fac.get("fact_id") or fac.get("disputed_id")
        add_node(fid, "Fact" if fac.get("fact_id") else "ContradictionFact", fac)
        for key in ("text_id", "claim_id", "quote_id"):
            if fac.get(key):
                add_edge(fid, fac[key], "SUPPORTED_BY", {"fact_id": fid})

    for h in hypotheses:
        add_node(h.get("hypothesis_id"), "Hypothesis", h)

    for i, c in enumerate(contradictions, 1):
        cid = f"CONTRA-{i}"
        add_node(cid, "Contradiction", c)

    for g in gaps:
        gid = g.get("gap_id") or f"GAP-{len(gaps)}"
        add_node(gid, "Gap", g)

    return {"nodes": nodes, "edges": edges, "version": VERSION}


# -----------------------------------------------------------------------------
# Gaps / actions / handoffs / summary
# -----------------------------------------------------------------------------

def build_knowledge_gaps(
    texts: List[Dict[str, Any]],
    claims: List[Dict[str, Any]],
    authorship: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    issues: List[str],
    sources: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    gaps: List[Dict[str, Any]] = []

    if not texts:
        gaps.append({
            "gap_id": "GAP-NO-TEXTS",
            "gap": "No text artifacts supplied",
            "importance": "HIGH",
            "recommended_source": "Authorized/public text snapshot with original preserved",
            "expected_information_value": "Establishes linguistic evidence base",
        })

    if any(t.get("_language", {}).get("confidence") == "LOW" or t.get("_language", {}).get("language") == "UNKNOWN" for t in texts):
        gaps.append({
            "gap_id": "GAP-LANGUAGE-UNCERTAIN",
            "gap": "Language identification uncertain for one or more texts",
            "importance": "MODERATE",
            "recommended_source": "Longer authorized excerpt, native linguist review, or metadata language field",
            "expected_information_value": "Improves language/script confidence without identity inference",
        })

    if any(t.get("_translation_of") and not t.get("_translation_text") for t in texts):
        gaps.append({
            "gap_id": "GAP-TRANSLATION-MISSING",
            "gap": "Translation relationship supplied but translated text missing",
            "importance": "HIGH",
            "recommended_source": "Official or authorized translation and original-language text",
            "expected_information_value": "Enables cross-language claim alignment and drift detection",
        })

    if any((t.get("_translation_drift") or {}).get("state") == "DRIFT_CANDIDATE" for t in texts):
        gaps.append({
            "gap_id": "GAP-TRANSLATION-DRIFT",
            "gap": "Translation drift candidate present",
            "importance": "HIGH",
            "recommended_source": "Independent human translation, original-language context, translator notes",
            "expected_information_value": "Prevents silent negation/modality/certainty changes",
        })

    if any(a.get("status") == "INSUFFICIENT_TEXT" for a in authorship):
        gaps.append({
            "gap_id": "GAP-AUTHORSHIP-INSUFFICIENT-TEXT",
            "gap": "Insufficient text length for stylometric comparison",
            "importance": "MODERATE",
            "recommended_source": "Larger authorized same-genre corpus",
            "expected_information_value": "Reduces small-sample stylometric noise",
        })

    if any(a.get("status") in {"INCONCLUSIVE", "UNKNOWN_AUTHOR"} for a in authorship):
        gaps.append({
            "gap_id": "GAP-AUTHORSHIP-UNRESOLVED",
            "gap": "Authorship candidate comparison unresolved",
            "importance": "HIGH",
            "recommended_source": "Authorized multi-source evidence; never style alone",
            "expected_information_value": "Prevents definitive authorship or identity overclaim",
        })

    if contradictions:
        gaps.append({
            "gap_id": "GAP-CONTRADICTIONS",
            "gap": "Material linguistic contradictions present",
            "importance": "HIGH",
            "recommended_source": "Raw text versions, original-language sources, translation memory, claim alignments",
            "expected_information_value": "Prevents silent false resolution",
        })

    if issues:
        gaps.append({
            "gap_id": "GAP-VALIDATION-ISSUES",
            "gap": "Input validation issues present",
            "importance": "HIGH",
            "recommended_source": "Corrected text/source/time/language/translation metadata",
            "expected_information_value": "Improves linguistic evidence trust",
        })

    if any(get_tags(t) & PRIVATE_TAGS for t in texts):
        gaps.append({
            "gap_id": "GAP-PRIVATE-BOUNDARY",
            "gap": "Private text/person boundary encountered",
            "importance": "PRIVACY_BOUNDARY",
            "recommended_source": "No deanonymization source recommended; use authorized sanitized records only",
            "expected_information_value": "Protects private persons and prevents style-based identification",
        })

    return gaps


def build_next_actions(
    texts: List[Dict[str, Any]],
    claims: List[Dict[str, Any]],
    authorship: List[Dict[str, Any]],
    gaps: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
) -> List[str]:
    actions: List[str] = []

    if not texts:
        actions.append("Supply deterministic authorized/public text artifacts with original preserved and source metadata")

    if any(g["gap_id"] == "GAP-LANGUAGE-UNCERTAIN" for g in gaps):
        actions.append("Obtain longer excerpt or native linguist review before relying on language identification")

    if any(g["gap_id"] == "GAP-TRANSLATION-MISSING" for g in gaps):
        actions.append("Retrieve original-language text and authorized translation before cross-language claim alignment")

    if any(g["gap_id"] == "GAP-TRANSLATION-DRIFT" for g in gaps):
        actions.append("Perform human linguist review for consequential negation/modality/certainty drift")

    if any(g["gap_id"] == "GAP-AUTHORSHIP-INSUFFICIENT-TEXT" for g in gaps):
        actions.append("Obtain larger authorized same-genre corpus before stylometric comparison")

    if any(g["gap_id"] == "GAP-AUTHORSHIP-UNRESOLVED" for g in gaps):
        actions.append("Do not infer author identity from style alone; require authorized multi-source evidence and human review")

    if contradictions:
        actions.append("Preserve contradictions and compare original versions, translations, and claim alignments before resolution")

    actions.append("Maintain sensitive-trait firewall: no race, ethnicity, religion, sexuality, health, mental-health, criminality, nationality, or political-belief inference")
    actions.append("Maintain safety boundary: no propaganda, manipulation, phishing, harassment, extremist content, or private-person deanonymization")

    return actions


def build_specialist_handoffs(
    texts: List[Dict[str, Any]],
    claims: List[Dict[str, Any]],
    authorship: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    handoffs: List[Dict[str, Any]] = []

    if any((t.get("_translation_drift") or {}).get("state") == "DRIFT_CANDIDATE" for t in texts):
        handoffs.append({
            "to": "HUMAN LINGUIST / LEGALINT if legal meaning material",
            "reason": "Translation drift may change negation, modality, certainty, or attribution",
            "restrictions": ["Do not rely on heuristic drift for consequential legal/operational decisions"],
        })

    if any(a.get("status") in {"CONSISTENT_WITH", "MORE_CONSISTENT_WITH", "INCONCLUSIVE"} for a in authorship):
        handoffs.append({
            "to": "AUTHORIZED FORENSIC LINGUIST / INVESTIGATIVE SPECIALIST",
            "reason": "Authorship candidate comparison requires larger corpus, genre controls, and non-linguistic evidence",
            "restrictions": ["No definitive authorship from stylometry alone", "No identity/nationality/ethnicity inference"],
        })

    if any("cyber" in str(c.get("_claim_summary", "")).lower() or "malware" in str(c.get("_claim_summary", "")).lower() for c in claims):
        handoffs.append({
            "to": "CTI / MALINT / TECHINT",
            "reason": "Technical cyber terminology requires domain validation",
            "restrictions": ["LINGINT extracts language only; it does not validate technical claims"],
        })

    if any("court" in str(c.get("_claim_summary", "")).lower() or "lawsuit" in str(c.get("_claim_summary", "")).lower() for c in claims):
        handoffs.append({
            "to": "LEGALINT",
            "reason": "Legal terminology and consequences exceed linguistic analysis",
            "restrictions": ["No legal conclusion from language alone"],
        })

    if contradictions:
        handoffs.append({
            "to": "DISINFOINT / MEDIAINT / DOCINT as appropriate",
            "reason": "Linguistic contradictions may require provenance, media context, or document metadata analysis",
            "restrictions": ["LINGINT does not adjudicate intent, campaign, or source identity"],
        })

    return handoffs


def analyst_summary(r: Dict[str, Any]) -> str:
    def fmt_list(lst: Any) -> str:
        if not lst:
            return "NONE"
        if isinstance(lst, list):
            return ", ".join(str(x) for x in lst)
        return str(lst)

    texts = r.get("text_artifacts") or []
    claims = r.get("claims") or []
    authorship = r.get("authorship_candidates") or []
    contradictions = r.get("contradictions") or []
    duplicates = r.get("exact_duplicates") or []
    templates = r.get("templates") or []
    drift = [t for t in texts if (t.get("translation_drift") or {}).get("state") == "DRIFT_CANDIDATE"]

    lines = [
        "LANGUAGE: " + fmt_list([f"{t.get('text_id')}={t.get('language')}({t.get('language_confidence')})" for t in texts[:10]]),
        "SCRIPT: " + fmt_list([f"{t.get('text_id')}={t.get('script')}({t.get('script_confidence')})" for t in texts[:10]]),
        "CODE-SWITCHING: " + fmt_list([f"{t.get('text_id')}={t.get('code_switching', {}).get('state')}" for t in texts[:10]]),
        "DIALECT / REGIONAL FEATURES: candidate only; no identity inference",
        "TRANSLATION STATUS: drift_candidates=" + str(len(drift)),
        "KEY TERMINOLOGY: " + fmt_list([term.get("term") for t in texts[:3] for term in (t.get("terms") or [])[:5]]),
        "ACRONYMS: " + fmt_list([a for t in texts[:5] for a in (t.get("acronyms") or [])[:5]]),
        "CLAIMS: " + str(len(claims)),
        "NEGATION / MODALITY: " + fmt_list([f"{t.get('text_id')} neg={t.get('features', {}).get('negation_count')} mod={t.get('features', {}).get('modality_count')}" for t in texts[:5]]),
        "CERTAINTY: " + fmt_list([f"{t.get('text_id')} cert={t.get('features', {}).get('certainty_count')}" for t in texts[:5]]),
        "QUOTED / REPORTED SPEECH: " + fmt_list([f"{t.get('text_id')} quotes={t.get('features', {}).get('quote_count')} reported={t.get('features', {}).get('reported_speech_count')}" for t in texts[:5]]),
        "REGISTER: " + fmt_list([f"{t.get('text_id')}={t.get('register', {}).get('primary_register')}" for t in texts[:10]]),
        "RHETORICAL / FRAMING FEATURES: " + fmt_list([sig.get("signal_type") for t in texts[:5] for sig in (t.get("rhetoric", {}).get("influence_signals") or [])[:5]]),
        "NARRATIVE: supplied narrative/frame labels only; no intent inference",
        "PHRASE / TEMPLATE REUSE: exact=" + str(len(duplicates)) + " templates=" + str(len(templates)),
        "DOCUMENT RELATIONSHIPS: clusters=" + str(len(r.get("document_clusters") or [])),
        "STYLOMETRIC SIGNALS: candidate comparison only",
        "AUTHORSHIP STATUS: " + fmt_list([f"{a.get('text_id')}={a.get('status')}" for a in authorship[:10]]),
        "AI / MACHINE-TRANSLATION CONTEXT: " + fmt_list([f"{t.get('text_id')} ai={t.get('ai_text_context')} mt={t.get('machine_translation_context')}" for t in texts[:5]]),
        "SOURCE PEDIGREE: families=" + str((r.get("source_independence") or {}).get("global_family_count", 0)),
        "SOURCE INDEPENDENCE: " + str((r.get("source_independence") or {}).get("note")),
        "SEMANTIC DRIFT: " + fmt_list([f"{t.get('text_id')}={[e.get('type') for e in (t.get('translation_drift', {}).get('drift_events') or [])]}" for t in drift[:5]]),
        "CONTRADICTIONS: " + str(len(contradictions)),
        "UNKNOWN: " + fmt_list(r.get("unknowns")),
        "NEXT ACTION: " + ((r.get("recommended_next_actions") or ["NONE"])[0]),
    ]

    return "\n".join(lines)


# -----------------------------------------------------------------------------
# Main analysis
# -----------------------------------------------------------------------------

def analyze(case: Dict[str, Any], input_path: Optional[str] = None, input_hash: Optional[str] = None) -> Dict[str, Any]:
    started = utcnow_iso()

    block_reasons = policy_block_reasons(case)
    if block_reasons:
        return blocked_result(case, block_reasons, started, input_path, input_hash)

    settings_raw = case.get("analysis_settings") or {}
    scope = case.get("scope") if isinstance(case.get("scope"), dict) else {}

    def setting_float(name: str, default: float) -> float:
        try:
            return float(settings_raw.get(name, default))
        except Exception:
            return default

    def setting_int(name: str, default: int) -> int:
        try:
            return int(settings_raw.get(name, default))
        except Exception:
            return default

    settings: Dict[str, Any] = {
        "shingle_size": setting_int("shingle_size", 3),
        "max_near_duplicate_pairs": setting_int("max_near_duplicate_pairs", 5000),
        "near_duplicate_light_threshold": setting_float("near_duplicate_light_threshold", 0.75),
        "near_duplicate_partial_threshold": setting_float("near_duplicate_partial_threshold", 0.45),
        "numeric_relative_tolerance": setting_float("numeric_relative_tolerance", 0.05),
        "min_authorship_chars": setting_int("min_authorship_chars", 200),
        "rare_phrase_ngram": setting_int("rare_phrase_ngram", 4),
        "rare_phrase_max_df": setting_int("rare_phrase_max_df", 3),
        "privacy_strict": scope.get("privacy_aware", True) is not False,
    }

    now = parse_dt(case.get("knowledge_time")) or datetime.now(timezone.utc)

    sources, src_issues = validate_sources(case)
    texts, texts_by_id, text_issues, text_warnings = validate_texts(case, sources, settings)
    samples, samp_issues, samp_warnings = validate_author_samples(case, settings)
    claims, claim_issues = validate_claims(case, texts_by_id)
    claims_by_id = {c["claim_id"]: c for c in claims}
    alignments, align_issues = validate_claim_alignments(case, claims_by_id)

    issues = src_issues + text_issues + samp_issues + claim_issues + align_issues
    warnings = text_warnings + samp_warnings

    for t in texts:
        analyze_text_artifact(t)

    duplicates = duplicate_analysis(texts, settings)
    clusters = document_clusters(texts, duplicates)
    source_independence = source_independence_analysis(texts, sources)
    authorship = authorship_analysis(texts, samples, settings)

    contradictions = detect_contradictions(
        claims,
        texts,
        alignments,
        list(case.get("existing_contradictions") or []),
        settings,
    )

    (
        supported_facts,
        candidate_facts,
        partial_facts,
        disputed_facts,
        not_facts,
    ) = build_facts(
        texts,
        claims,
        duplicates,
        clusters,
        authorship,
        source_independence,
        contradictions,
        sources,
    )

    hypotheses, ach_matrix = build_hypotheses(
        texts,
        duplicates,
        clusters,
        authorship,
        contradictions,
        issues,
    )

    dual = dual_ai_review(texts, claims, contradictions, authorship, issues)

    gaps = build_knowledge_gaps(
        texts,
        claims,
        authorship,
        contradictions,
        issues,
        sources,
    )

    next_actions = build_next_actions(texts, claims, authorship, gaps, contradictions)
    handoffs = build_specialist_handoffs(texts, claims, authorship, contradictions)

    graph = build_graph(
        sources,
        texts,
        claims,
        alignments,
        duplicates,
        clusters,
        authorship,
        source_independence,
        supported_facts + candidate_facts + partial_facts,
        hypotheses,
        contradictions,
        gaps,
    )

    # Public objects.
    text_public = []
    for t in texts:
        enabled = bool(t.get("_analysis_enabled", True))
        text_public.append({
            "text_id": t.get("text_id"),
            "text_type": t.get("text_type"),
            "source_id": t.get("_source_id"),
            "published_at": iso_or_none(t.get("_published_at")),
            "observed_at": iso_or_none(t.get("_observed_at")),
            "genre": t.get("_genre"),
            "language": t.get("_language", {}).get("language") if enabled else "REDACTED",
            "language_confidence": t.get("_language", {}).get("confidence") if enabled else "LOW",
            "language_candidates": t.get("_language", {}).get("candidates") if enabled else [],
            "script": t.get("_script", {}).get("script") if enabled else "REDACTED",
            "script_confidence": t.get("_script", {}).get("confidence") if enabled else "LOW",
            "code_switching": t.get("_code_switching") if enabled else {"state": "REDACTED"},
            "original_excerpt": short_text(t.get("_forensic_text"), 220) if enabled else "REDACTED",
            "normalized_hash": t.get("_normalized_hash") if enabled else None,
            "content_hash": t.get("_content_hash") if enabled else None,
            "translation_of": t.get("_translation_of"),
            "translated_excerpt": short_text(t.get("_translation_text"), 220) if enabled and t.get("_translation_text") else None,
            "features": t.get("_features") if enabled else {},
            "terms": t.get("_terms") if enabled else [],
            "acronyms": t.get("_acronyms") if enabled else [],
            "entity_mentions": t.get("_entity_mentions") if enabled else [],
            "quotes": t.get("_quotes") if enabled else [],
            "register": t.get("_register") if enabled else {},
            "rhetoric": t.get("_rhetoric") if enabled else {},
            "translation_drift": t.get("_translation_drift") if enabled else {},
            "terminology_consistency": t.get("_terminology_consistency") if enabled else [],
            "ai_text_context": t.get("_ai_text_indicator") or "INCONCLUSIVE",
            "machine_translation_context": t.get("_machine_translation_indicator") or "UNKNOWN",
            "source_family_id": t.get("_source_family_id"),
            "duplicate_state": t.get("_duplicate_state"),
            "duplicate_similarity": t.get("_duplicate_similarity"),
            "quality_flags": t.get("_quality_flags"),
            "limitations": [
                "Language and script do not establish identity, nationality, ethnicity, religion, or political belief.",
                "Quotation detection does not verify speaker or context.",
                "Stylistic similarity does not establish authorship.",
                "Private text is redacted and not used for authorship.",
            ],
        })

    claim_public = [
        {
            "claim_id": c.get("claim_id"),
            "text_id": c.get("_text_id"),
            "claim_type": c.get("_claim_type"),
            "subject": c.get("_subject"),
            "predicate": c.get("_predicate"),
            "object": c.get("_object"),
            "time_reference": c.get("_time_reference"),
            "location_reference": c.get("_location_reference"),
            "negation": c.get("_negation"),
            "modality": c.get("_modality"),
            "certainty": c.get("_certainty"),
            "numeric_value": c.get("_numeric_value"),
            "numeric_unit": c.get("_numeric_unit"),
            "claim_summary": c.get("_claim_summary"),
            "source_ids": c.get("_source_ids"),
            "evidence_ids": c.get("_evidence_ids"),
            "quality_flags": c.get("_quality_flags"),
            "limitations": [
                "Claim expression is not fact verification.",
                "Negation and modality must be preserved.",
            ],
        }
        for c in claims
    ]

    alignment_public = [public_dict(a) for a in alignments]

    authorship_public = authorship

    source_reliability = [
        {
            "source_id": s.get("source_id"),
            "source_type": s.get("_source_type"),
            "publisher": s.get("_publisher"),
            "organization": s.get("_organization"),
            "account": s.get("_account"),
            "domain": s.get("_domain"),
            "reliability": s.get("_reliability"),
            "independence_group": s.get("_independence_group"),
            "upstream_source_ids": s.get("_upstream_source_ids"),
            "limitations": s.get("_limitations"),
        }
        for s in sources.values()
    ]

    languages = sorted({t.get("_language", {}).get("language") for t in texts if t.get("_language", {}).get("language")})
    scripts = sorted({t.get("_script", {}).get("script") for t in texts if t.get("_script", {}).get("script")})
    terminology = sorted({term.get("term") for t in texts for term in (t.get("_terms") or []) if term.get("term")})
    acronyms = sorted({a for t in texts for a in (t.get("_acronyms") or []) if a})
    entity_mentions = sorted({m.get("mention") for t in texts for m in (t.get("_entity_mentions") or []) if m.get("mention")})

    templates = duplicates.get("skeleton_groups") or {}
    exact_duplicates = [rel for rel in duplicates.get("relationships", []) if rel.get("type") == "exact_duplicate"]
    near_duplicates = [rel for rel in duplicates.get("relationships", []) if rel.get("type") == "near_duplicate"]

    unknowns: List[str] = []
    if not texts:
        unknowns.append("Text evidence base unresolved")
    if any(t.get("_language", {}).get("confidence") == "LOW" for t in texts):
        unknowns.append("Language identification uncertain")
    if any((t.get("_translation_drift") or {}).get("state") == "DRIFT_CANDIDATE" for t in texts):
        unknowns.append("Translation meaning drift unresolved")
    if any(a.get("status") in {"INSUFFICIENT_TEXT", "INCONCLUSIVE", "UNKNOWN_AUTHOR"} for a in authorship):
        unknowns.append("Authorship candidate comparison unresolved")
    if contradictions:
        unknowns.append("Linguistic contradictions unresolved")
    unknowns.append("Nationality, ethnicity, religion, race, sexuality, health, mental health, criminality, intent, and real-person identity unresolved by design")
    unknowns.append("No definitive authorship, lie detection, manipulation, propaganda, phishing, harassment, or private-person deanonymization is supported")

    if contradictions:
        status = "SOURCE_CONFLICT"
    elif issues:
        status = "PARTIAL"
    elif not texts and not claims:
        status = "INCONCLUSIVE"
    elif supported_facts or candidate_facts:
        status = "SUCCEEDED"
    else:
        status = "PARTIAL"

    result: Dict[str, Any] = {
        "case_id": case.get("case_id"),
        "task_id": case.get("task_id"),
        "objective": case.get("objective"),
        "questions": case.get("questions") or [],
        "mode": case.get("model_mode", "LOCAL_ONLY"),
        "status": status,
        "source_ids": sorted(sources.keys()),
        "evidence_ids": sorted(
            {
                eid
                for obj in texts + claims
                for eid in (obj.get("_evidence_ids") or [])
                if eid
            }
        ),
        "text_artifacts": text_public,
        "languages": languages,
        "scripts": scripts,
        "language_spans": [
            {
                "text_id": t.get("text_id"),
                "code_switching": t.get("_code_switching"),
            }
            for t in texts
        ],
        "code_switching": [t.get("_code_switching") for t in texts],
        "dialect_features": [
            {
                "text_id": t.get("text_id"),
                "state": "DIALECT_FEATURE_CANDIDATE_NOT_ANALYZED_IN_SCAFFOLD",
                "note": "Dialect analysis requires authorized linguistic resources and must not infer birthplace, ethnicity, or identity.",
            }
            for t in texts
        ],
        "orthographic_features": [
            {
                "text_id": t.get("text_id"),
                "features": {
                    "quote_rate": (t.get("_style_features", {}).get("numeric", {}) or {}).get("quote_rate"),
                    "dash_rate": (t.get("_style_features", {}).get("numeric", {}) or {}).get("dash_rate"),
                    "period_rate": (t.get("_style_features", {}).get("numeric", {}) or {}).get("period_rate"),
                },
                "note": "Orthographic features may be affected by software, editing, and platform normalization.",
            }
            for t in texts
        ],
        "lexical_features": [
            {
                "text_id": t.get("text_id"),
                "lexical_diversity": (t.get("_style_features", {}).get("numeric", {}) or {}).get("lexical_diversity"),
                "function_word_ratio": (t.get("_style_features", {}).get("numeric", {}) or {}).get("function_word_ratio"),
                "avg_sentence_len": (t.get("_style_features", {}).get("numeric", {}) or {}).get("avg_sentence_len"),
            }
            for t in texts
        ],
        "terminology": terminology,
        "acronyms": acronyms,
        "entity_mentions": entity_mentions,
        "claims": claim_public,
        "negations": [
            {
                "text_id": t.get("text_id"),
                "negation_count": (t.get("_features") or {}).get("negation_count"),
                "examples": (t.get("_features") or {}).get("negation_examples"),
            }
            for t in texts
        ],
        "modality": [
            {
                "text_id": t.get("text_id"),
                "modality_count": (t.get("_features") or {}).get("modality_count"),
                "examples": (t.get("_features") or {}).get("modality_examples"),
            }
            for t in texts
        ],
        "certainty": [
            {
                "text_id": t.get("text_id"),
                "certainty_count": (t.get("_features") or {}).get("certainty_count"),
                "examples": (t.get("_features") or {}).get("certainty_examples"),
            }
            for t in texts
        ],
        "hedging": [
            {
                "text_id": t.get("text_id"),
                "hedging_count": (t.get("_features") or {}).get("hedging_count"),
                "examples": (t.get("_features") or {}).get("hedging_examples"),
            }
            for t in texts
        ],
        "reported_speech": [
            {
                "text_id": t.get("text_id"),
                "reported_speech_count": (t.get("_features") or {}).get("reported_speech_count"),
                "examples": (t.get("_features") or {}).get("reported_speech_examples"),
            }
            for t in texts
        ],
        "quotes": [
            {
                "text_id": t.get("text_id"),
                "quotes": t.get("_quotes"),
            }
            for t in texts
        ],
        "stances": [
            {
                "text_id": t.get("text_id"),
                "state": "STANCE_NOT_INFERRED_WITHOUT_EXPLICIT_PROPOSITION",
                "note": "Stance requires an explicitly defined proposition and context; isolated sentiment is not stance or belief.",
            }
            for t in texts
        ],
        "registers": [
            {
                "text_id": t.get("text_id"),
                "register": t.get("_register"),
            }
            for t in texts
        ],
        "rhetorical_features": [
            {
                "text_id": t.get("text_id"),
                "rhetoric": t.get("_rhetoric"),
            }
            for t in texts
        ],
        "discourse_structure": [
            {
                "text_id": t.get("text_id"),
                "state": "DISCOURSE_STRUCTURE_NOT_FULLY_PARSED_IN_SCAFFOLD",
                "note": "Argument structure requires deeper NLP or human discourse analysis.",
            }
            for t in texts
        ],
        "narratives": case.get("narratives") or [],
        "authorship_candidates": authorship_public,
        "claim_alignments": alignment_public,
        "exact_duplicates": exact_duplicates,
        "near_duplicates": near_duplicates,
        "document_clusters": clusters,
        "source_reliability": source_reliability,
        "source_independence": source_independence,
        "supported_facts": supported_facts,
        "candidate_facts": candidate_facts,
        "partial_facts": partial_facts,
        "hypotheses": hypotheses,
        "contradictions": contradictions,
        "knowledge_gaps": gaps,
        "unknowns": unknowns,
        "validation_issues": issues,
        "next_actions": next_actions,
        "specialist_handoffs": handoffs,
        "graph": graph,
        "source_authenticity_verified": False,
        "external_collection_performed": False,
    }
    result["analyst_summary"] = analyst_summary(result)
    return result
