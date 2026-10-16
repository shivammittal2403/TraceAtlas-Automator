"""Twenty-one distinct, evidence-bound human, social and information analyzers.

Only submitted text and metadata are processed. These handlers do not contact
people, intercept communications, access private accounts, or adjudicate truth.
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from email import policy
from email.parser import Parser
from email.utils import getaddresses, parsedate_to_datetime
import hashlib
import json
import math
import re
import unicodedata

from .common import AnalysisContext

LIMITATIONS = (
    "Analysis concerns submitted records; source authenticity and factual truth are not established.",
    "No account collection, message interception, contact with people, or identity confirmation occurred.",
)


def _groups(ctx, kinds, default):
    result = {kind: [] for kind in kinds}
    for record in ctx.records:
        kind = record.data.get("kind", default)
        if not isinstance(kind, str) or kind not in result:
            ctx.issue(record, "UNSUPPORTED_RECORD_KIND", "Unsupported record kind for this discipline")
        else:
            result[kind].append(record)
    return result


def _text(ctx, record, field, required=True):
    value = record.data.get(field)
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip():
        ctx.issue(record, "INVALID_FIELD", field + " must be a nonempty string")
        return None
    return value.strip()


def _strings(ctx, record, field):
    value = record.data.get(field, [])
    if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
        ctx.issue(record, "INVALID_ARRAY", field + " must be an array of nonempty strings")
        return []
    return list(dict.fromkeys(item.strip() for item in value))


def _moment(ctx, record, field, required=False):
    value = record.data.get(field)
    if value is None:
        if required:
            ctx.issue(record, "TIMESTAMP_MISSING", field + " is required for temporal analysis")
        return None
    try:
        if not isinstance(value, str):
            raise ValueError()
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None or result.utcoffset() is None:
            raise ValueError()
        return result.astimezone(timezone.utc)
    except ValueError:
        ctx.issue(record, "INVALID_TIMESTAMP", field + " must be an ISO timestamp with timezone")
        return None


def _normalized(value):
    return " ".join(unicodedata.normalize("NFKC", value).casefold().split())


def _hash(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _tokens(value):
    return re.findall(r"[^\W\d_]+(?:'[^\W\d_]+)?", unicodedata.normalize("NFKC", value).casefold(), re.UNICODE)


def _parameter(ctx, key, default, low, high):
    value = ctx.parameters.get(key, default)
    if type(value) not in (int, float) or not math.isfinite(value) or not low <= value <= high:
        ctx.issue(None, "INVALID_PARAMETER", key + " is outside its numeric analysis range")
        return default
    return value


def _finish(ctx, metrics=None, artifacts=None, extra=()):
    return ctx.output(metrics=metrics or {}, artifacts=artifacts or {}, limitations=(*LIMITATIONS, *extra))


def socmint(ctx: AnalysisContext):
    groups = _groups(ctx, {"post"}, "post")
    identities, content_groups, hashtags, authors, posts = defaultdict(list), defaultdict(list), Counter(), Counter(), []
    for record in groups["post"]:
        platform, post_id, author, text = (_text(ctx, record, key) for key in ("platform", "post_id", "author_id", "text"))
        if not all((platform, post_id, author, text)):
            continue
        digest = _hash(_normalized(text))
        identities[(platform.casefold(), post_id)].append((record, digest))
        content_groups[digest].append(record)
        authors[(platform.casefold(), author)] += 1
        hashtags.update(tag.casefold() for tag in re.findall(r"(?<!\w)#(\w+)", text, re.UNICODE))
        instant = _moment(ctx, record, "posted_at")
        if instant and instant > ctx.as_of:
            ctx.issue(record, "FUTURE_POST_TIME", "Post timestamp lies after analysis time")
        engagement = {}
        for key in ("likes", "comments", "reposts"):
            value = record.data.get(key)
            if value is not None:
                if type(value) is not int or value < 0:
                    ctx.issue(record, "INVALID_ENGAGEMENT", key + " must be a nonnegative integer")
                else:
                    engagement[key] = value
        posts.append({"record_id": record.record_id, "platform": platform.casefold(), "post_id": post_id,
                      "content_sha256": digest, "engagement": engagement})
    for (platform, post_id), rows in identities.items():
        if len({digest for _, digest in rows}) > 1:
            ctx.finding("SOCIAL_POST_CONTENT_CONFLICT", "One supplied platform/post ID has different content",
                        [record.record_id for record, _ in rows], {"platform": platform, "post_id": post_id})
    repeated = []
    for digest, rows in content_groups.items():
        if len(rows) > 1:
            repeated.append({"content_sha256": digest, "record_ids": [record.record_id for record in rows]})
            ctx.finding("REPEATED_SOCIAL_CONTENT", "Multiple submitted social records contain identical normalized text",
                        [record.record_id for record in rows], {"content_sha256": digest, "record_count": len(rows)})
    return _finish(ctx, {"valid_posts": len(posts), "declared_accounts": len(authors), "repeated_content_groups": len(repeated)},
                   {"posts": posts, "top_hashtags": dict(hashtags.most_common(50)), "repeated_content": repeated},
                   ("Repeated content and engagement counts do not establish coordination, automation, popularity authenticity, or intent.",))


def humint(ctx: AnalysisContext):
    groups = _groups(ctx, {"testimony"}, "testimony")
    claims, attributed = defaultdict(list), defaultdict(list)
    for record in groups["testimony"]:
        witness, claim, statement = (_text(ctx, record, key) for key in ("witness_id", "claim_id", "statement"))
        stance = _text(ctx, record, "stance")
        directness = record.data.get("directness", "UNKNOWN")
        if stance not in {"SUPPORTS", "REFUTES", "UNCERTAIN"}:
            ctx.issue(record, "INVALID_STANCE", "Testimony stance must be SUPPORTS, REFUTES, or UNCERTAIN")
            continue
        if not isinstance(directness, str) or directness not in {"FIRSTHAND", "SECONDHAND", "UNKNOWN"}:
            ctx.issue(record, "INVALID_DIRECTNESS", "Testimony directness must be FIRSTHAND, SECONDHAND, or UNKNOWN")
            continue
        if witness and claim and statement:
            item = {"record_id": record.record_id, "witness_id": witness, "source_id": record.source_id,
                    "stance": stance, "directness": directness, "statement_sha256": _hash(statement)}
            claims[claim].append(item)
            attributed[(witness, claim)].append(item)
            if directness == "SECONDHAND" and not _text(ctx, record, "heard_from", required=False):
                ctx.issue(record, "HEARSAY_CHAIN_MISSING", "Secondhand testimony lacks an attributed origin")
    for (witness, claim), rows in attributed.items():
        if {"SUPPORTS", "REFUTES"} <= {item["stance"] for item in rows}:
            ctx.finding("TESTIMONY_STANCE_VARIATION", "A declared witness has both supporting and refuting testimony for one claim",
                        [item["record_id"] for item in rows], {"witness_id": witness, "claim_id": claim})
    matrix = {claim: {"testimonies": rows, "declared_witnesses": len({item["witness_id"] for item in rows}),
                      "source_count": len({item["source_id"] for item in rows}),
                      "stance_counts": dict(Counter(item["stance"] for item in rows))} for claim, rows in claims.items()}
    return _finish(ctx, {"claims": len(claims), "testimony_records": sum(map(len, claims.values()))},
                   {"claim_testimony_matrix": matrix},
                   ("Witness identifiers, firsthand labels and source counts do not establish independence, credibility, or truth.",))


def comint(ctx: AnalysisContext):
    groups = _groups(ctx, {"communication"}, "communication")
    identities, pairs, buckets, senders = defaultdict(list), Counter(), defaultdict(list), set()
    threshold = _parameter(ctx, "burst_messages_per_minute", 10, 1, 500)
    valid = 0
    for record in groups["communication"]:
        channel, message, sender = (_text(ctx, record, key) for key in ("channel", "message_id", "sender_id"))
        recipients = _strings(ctx, record, "recipient_ids")
        instant = _moment(ctx, record, "sent_at")
        if not channel or not message or not sender or not recipients:
            if not recipients:
                ctx.issue(record, "RECIPIENTS_MISSING", "Communication metadata requires recipients")
            continue
        valid += 1
        senders.add(sender)
        identities[(channel, message)].append((record, sender, tuple(sorted(recipients))))
        pairs.update((sender, recipient) for recipient in recipients)
        if instant:
            if instant > ctx.as_of:
                ctx.issue(record, "FUTURE_COMMUNICATION_TIME", "Communication timestamp lies after analysis time")
            else:
                buckets[(channel, sender, instant.replace(second=0, microsecond=0).isoformat())].append(record)
    for (_, message), rows in identities.items():
        if len({(sender, recipients) for _, sender, recipients in rows}) > 1:
            ctx.finding("COMMUNICATION_METADATA_CONFLICT", "One supplied channel/message ID has conflicting sender or recipient metadata",
                        [record.record_id for record, _, _ in rows], {"message_id": message})
    bursts = []
    for (channel, sender, minute), rows in buckets.items():
        if len(rows) > threshold:
            bursts.append({"channel": channel, "sender_id": sender, "minute": minute, "count": len(rows)})
            ctx.finding("SUPPLIED_COMMUNICATION_BURST", "Submitted communication metadata exceeds the stated per-minute count threshold",
                        [record.record_id for record in rows], {"count": len(rows), "threshold": threshold, "minute": minute})
    return _finish(ctx, {"valid_communication_records": valid, "declared_senders": len(senders),
                         "unique_directed_pairs": len(pairs), "burst_buckets": len(bursts)},
                   {"top_directed_pairs": [{"sender_id": pair[0], "recipient_id": pair[1], "count": count}
                                           for pair, count in pairs.most_common(100)], "bursts": bursts},
                   ("Communication metadata does not establish message content, a real-world relationship, or interception capability.",))


def deceptionint(ctx: AnalysisContext):
    groups = _groups(ctx, {"assertion", "observation"}, "assertion")
    snapshots, comparisons = defaultdict(lambda: {"assertion": [], "observation": []}), []
    for kind in ("assertion", "observation"):
        for record in groups[kind]:
            subject, field, snapshot = (_text(ctx, record, key) for key in ("subject_id", "field", "snapshot_id"))
            if "value" not in record.data:
                ctx.issue(record, "ASSERTION_VALUE_MISSING", "Comparison requires an explicitly supplied value")
                continue
            if subject and field and snapshot:
                value = json.dumps(record.data["value"], sort_keys=True, ensure_ascii=False, separators=(",", ":"))
                snapshots[(subject, field, snapshot)][kind].append((record, value))
    for (subject, field, snapshot), values in snapshots.items():
        if not values["assertion"] or not values["observation"]:
            for record, _ in values["assertion"] + values["observation"]:
                ctx.issue(record, "COUNTERPART_MISSING", "No counterpart was supplied for this subject, field and snapshot")
        for assertion, asserted in values["assertion"]:
            for observation, observed in values["observation"]:
                if len(comparisons) >= 400:
                    ctx.issue(None, "SNAPSHOT_COMPARISON_LIMIT", "Only the first 400 assertion/observation comparisons are emitted")
                    break
                same = asserted == observed
                comparisons.append({"assertion_record_id": assertion.record_id, "observation_record_id": observation.record_id,
                                    "same_supplied_value": same})
                if not same:
                    ctx.finding("ASSERTION_OBSERVATION_DISCREPANCY", "Supplied assertion and observation values differ within one declared snapshot",
                                [assertion.record_id, observation.record_id],
                                {"subject_id": subject, "field": field, "snapshot_id": snapshot,
                                 "asserted_value_sha256": _hash(asserted), "observed_value_sha256": _hash(observed)})
    return _finish(ctx, {"snapshots": len(snapshots), "value_comparisons": len(comparisons)},
                   {"snapshot_comparisons": comparisons},
                   ("A discrepancy can arise from error, context, or inaccurate observations; it does not establish deception or intent.",))


def textint(ctx: AnalysisContext):
    groups = _groups(ctx, {"document"}, "document")
    documents, fingerprints, total = [], defaultdict(list), Counter()
    for record in groups["document"]:
        value = _text(ctx, record, "text")
        if not value:
            continue
        tokens = _tokens(value)
        total.update(tokens)
        digest = _hash(_normalized(value))
        fingerprints[digest].append(record)
        negations = sum(token in {"not", "no", "never", "neither", "without"} or token.endswith("n't") for token in tokens)
        documents.append({"record_id": record.record_id, "word_tokens": len(tokens), "distinct_tokens": len(set(tokens)),
                          "lexical_diversity": len(set(tokens)) / len(tokens) if tokens else 0,
                          "sentence_separator_count": len(re.findall(r"[.!?]+", value)), "negation_markers": negations,
                          "normalized_sha256": digest})
    for digest, rows in fingerprints.items():
        if len(rows) > 1:
            ctx.finding("DUPLICATE_NORMALIZED_TEXT", "Submitted documents contain identical normalized text",
                        [record.record_id for record in rows], {"normalized_sha256": digest})
    return _finish(ctx, {"documents": len(documents), "word_tokens": sum(total.values()), "distinct_tokens": len(total)},
                   {"document_statistics": documents, "top_terms": dict(total.most_common(30))},
                   ("Token and punctuation statistics are mechanical counts, not semantic understanding or authorship attribution.",))


def _scripts(value):
    counts = Counter()
    for character in value:
        if not unicodedata.category(character).startswith("L"):
            continue
        name = unicodedata.name(character, "")
        script = next((candidate for candidate in ("LATIN", "CYRILLIC", "ARABIC", "DEVANAGARI", "GREEK", "HEBREW", "HANGUL", "HIRAGANA", "KATAKANA", "THAI") if candidate in name), None)
        if script is None:
            script = "HAN" if "CJK" in name or "IDEOGRAPH" in name else "OTHER"
        counts[script] += 1
    return dict(counts)


def langint(ctx: AnalysisContext):
    groups = _groups(ctx, {"document", "translation"}, "document")
    documents, translations = [], []
    expected_scripts = {"en": "LATIN", "hi": "DEVANAGARI", "ru": "CYRILLIC", "ar": "ARABIC", "zh": "HAN", "el": "GREEK", "he": "HEBREW"}
    for record in groups["document"]:
        value = _text(ctx, record, "text")
        language = _text(ctx, record, "language", required=False)
        if not value:
            continue
        scripts = _scripts(value)
        dominant = max(scripts, key=scripts.get) if scripts else None
        if language and not re.fullmatch(r"[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*", language):
            ctx.issue(record, "INVALID_LANGUAGE_TAG", "Language labels require a BCP-47-like tag")
        elif language:
            expected = expected_scripts.get(language.split("-")[0].lower())
            if expected and dominant and dominant != expected:
                ctx.finding("DECLARED_LANGUAGE_SCRIPT_DIFFERENCE", "The dominant supplied script differs from a common script for the declared language",
                            [record.record_id], {"declared_language": language, "dominant_script": dominant})
        documents.append({"record_id": record.record_id, "script_letter_counts": scripts, "dominant_script": dominant,
                          "declared_language": language, "language_identified": False})
    for record in groups["translation"]:
        original, translated = _text(ctx, record, "original_text"), _text(ctx, record, "translated_text")
        if original and translated:
            left = Counter(re.findall(r"\d+(?:[.,]\d+)*", original))
            right = Counter(re.findall(r"\d+(?:[.,]\d+)*", translated))
            same = left == right
            translations.append({"record_id": record.record_id, "number_tokens_preserved": same})
            if not same:
                ctx.finding("TRANSLATION_NUMBER_TOKEN_VARIATION", "Supplied original and translated texts contain different numeric tokens",
                            [record.record_id], {"original_number_tokens": dict(left.most_common(100)), "translated_number_tokens": dict(right.most_common(100)),
                             "original_distinct_number_tokens": len(left), "translated_distinct_number_tokens": len(right)})
    return _finish(ctx, {"documents": len(documents), "translation_pairs": len(translations)},
                   {"script_profiles": documents, "translation_checks": translations},
                   ("Script is not language, ethnicity or nationality; transliteration and multilingual text can explain differences.",))


def narrativeint(ctx: AnalysisContext):
    groups = _groups(ctx, {"frame", "event"}, "frame")
    narratives, event_times, timelines = defaultdict(Counter), defaultdict(list), []
    for record in groups["frame"]:
        narrative, frame = _text(ctx, record, "narrative_id"), _text(ctx, record, "frame")
        if narrative and frame:
            narratives[narrative][_normalized(frame)] += 1
    for record in groups["event"]:
        narrative, event = _text(ctx, record, "narrative_id"), _text(ctx, record, "event_id")
        instant = _moment(ctx, record, "event_time", required=True)
        if narrative and event and instant:
            event_times[(narrative, event)].append((record, instant))
            timelines.append({"record_id": record.record_id, "narrative_id": narrative, "event_id": event, "event_time": instant.isoformat()})
    for (narrative, event), rows in event_times.items():
        if len({instant for _, instant in rows}) > 1:
            ctx.finding("NARRATIVE_EVENT_TIME_VARIATION", "One supplied narrative/event ID has different stated event times",
                        [record.record_id for record, _ in rows], {"narrative_id": narrative, "event_id": event})
    return _finish(ctx, {"narratives_with_frames": len(narratives), "event_records": len(timelines)},
                   {"frame_frequency": {key: dict(value.most_common(30)) for key, value in narratives.items()},
                    "declared_event_timeline": sorted(timelines, key=lambda item: (item["event_time"], item["record_id"]))},
                   ("Frames and narrative IDs are supplied classifications; event-time variation is not an adjudicated chronology.",))


def _claims_and_checks(ctx, groups):
    claims, checks = defaultdict(list), defaultdict(list)
    known = {record.record_id for record in ctx.records}
    for record in groups.get("claim", []):
        claim, statement = _text(ctx, record, "claim_id"), _text(ctx, record, "statement")
        if claim and statement:
            claims[claim].append((record, _hash(_normalized(statement))))
    for record in groups.get("check", []):
        claim, verdict = _text(ctx, record, "claim_id"), _text(ctx, record, "verdict")
        if verdict not in {"TRUE", "FALSE", "MIXED", "UNVERIFIED"}:
            ctx.issue(record, "INVALID_CHECK_VERDICT", "Supplied check verdict must be TRUE, FALSE, MIXED, or UNVERIFIED")
            continue
        if not claim:
            continue
        basis = _strings(ctx, record, "basis_record_ids")
        if not basis:
            ctx.issue(record, "CHECK_BASIS_MISSING", "Supplied fact-check metadata lacks registered supporting records")
        elif any(identifier not in known for identifier in basis):
            ctx.issue(record, "CHECK_BASIS_UNRESOLVED", "A check references record IDs absent from this input")
        checked = _moment(ctx, record, "checked_at")
        checks[claim].append((record, verdict, checked))
        if claim not in claims:
            ctx.issue(record, "CHECK_WITHOUT_CLAIM", "The checked claim is absent from the supplied claim inventory")
    return claims, checks


def disinfoint(ctx: AnalysisContext):
    groups = _groups(ctx, {"claim", "check", "publication", "intent_record"}, "claim")
    claims, checks = _claims_and_checks(ctx, groups)
    publications, later, intent = [], [], set()
    for record in groups["intent_record"]:
        claim = _text(ctx, record, "claim_id")
        allegation = _text(ctx, record, "allegation")
        if claim and allegation:
            intent.add(claim)
            ctx.issue(record, "INTENT_NOT_ADJUDICATED", "A supplied intent allegation does not establish deliberate deception")
    for record in groups["publication"]:
        claim = _text(ctx, record, "claim_id")
        published = _moment(ctx, record, "published_at", required=True)
        if not claim or not published:
            continue
        if claim not in claims:
            ctx.issue(record, "PUBLICATION_CLAIM_UNRESOLVED", "Publication references a claim absent from the supplied inventory")
        publications.append(record)
        for check, verdict, checked in checks[claim]:
            if verdict == "FALSE" and checked is not None and published > checked:
                if len(later) >= 400:
                    ctx.issue(None, "TEMPORAL_COMPARISON_LIMIT", "Only the first 400 qualifying publication/check comparisons are emitted")
                    break
                later.append({"publication_record_id": record.record_id, "check_record_id": check.record_id,
                              "claim_id": claim, "seconds_after_supplied_check": (published - checked).total_seconds()})
                ctx.finding("PUBLICATION_AFTER_SUPPLIED_FALSE_VERDICT", "A publication timestamp follows a supplied check that labels the claim false",
                            [record.record_id, check.record_id], {"claim_id": claim, "supplied_verdict": verdict})
    return _finish(ctx, {"claims": len(claims), "publication_records": len(publications),
                         "later_publication_comparisons": len(later), "claims_with_intent_allegations": len(intent)},
                   {"publication_check_timeline": later, "intent_established": False},
                   ("A check verdict can be wrong; later publication does not prove awareness, deception, or disinformation intent.",))


def misinfoint(ctx: AnalysisContext):
    groups = _groups(ctx, {"claim", "check"}, "claim")
    claims, checks = _claims_and_checks(ctx, groups)
    matrix = []
    for claim in sorted(set(claims) | set(checks)):
        rows = checks[claim]
        verdicts = Counter(verdict for _, verdict, _ in rows)
        if "TRUE" in verdicts and "FALSE" in verdicts:
            ctx.finding("SUPPLIED_CHECK_VERDICT_DISAGREEMENT", "Submitted checks give both TRUE and FALSE verdicts for one claim",
                        [record.record_id for record, _, _ in rows], {"claim_id": claim, "verdict_counts": dict(verdicts)})
        statements = claims[claim]
        if len({digest for _, digest in statements}) > 1:
            ctx.finding("CLAIM_ID_TEXT_VARIATION", "One supplied claim ID refers to different normalized statements",
                        [record.record_id for record, _ in statements], {"claim_id": claim})
        if not rows:
            for record, _ in statements:
                ctx.issue(record, "CHECK_MISSING", "No supplied check is available for this claim")
        matrix.append({"claim_id": claim, "verdict_counts": dict(verdicts),
                       "check_source_count": len({record.source_id for record, _, _ in rows}),
                       "truth_adjudicated": False})
    return _finish(ctx, {"claim_groups": len(matrix), "supplied_checks": sum(map(len, checks.values()))},
                   {"claim_check_matrix": matrix},
                   ("Agreement or disagreement among supplied check labels does not establish a claim's truth, falsity, or misinformation status.",))


RHETORIC_PATTERNS = {
    "ABSOLUTIST_LANGUAGE": r"\b(?:always|never|everyone|nobody)\b",
    "BANDWAGON_CUE": r"\b(?:everyone knows|everybody agrees|join the majority)\b",
    "FEAR_CUE": r"\b(?:catastrophe|destroy|imminent threat|disaster)\b",
    "DEHUMANIZING_LABEL_CUE": r"\b(?:vermin|subhuman)\b",
    "CIRCULATION_IMPERATIVE": r"\b(?:share this|forward this|spread the word)\b",
}


def propint(ctx: AnalysisContext):
    groups = _groups(ctx, {"text"}, "text")
    documents, totals = [], Counter()
    for record in groups["text"]:
        value = _text(ctx, record, "text")
        if not value:
            continue
        signals = []
        for technique, pattern in RHETORIC_PATTERNS.items():
            matches = list(re.finditer(pattern, value, re.I))
            totals[technique] += len(matches)
            for match in matches[:50]:
                prefix = _tokens(value[max(0, match.start() - 30):match.start()])
                signals.append({"technique": technique, "start": match.start(), "end": match.end(),
                                "nearby_negation": any(token in {"not", "no", "never"} for token in prefix[-3:])})
        if signals:
            ctx.finding("RHETORICAL_LEXICAL_SIGNALS", "Supplied English text contains transparent rhetorical pattern matches",
                        [record.record_id], {"signal_counts": dict(Counter(signal["technique"] for signal in signals))})
        documents.append({"record_id": record.record_id, "signals": signals})
    return _finish(ctx, {"documents": len(documents), "pattern_match_counts": dict(totals)},
                   {"rhetorical_signals": documents},
                   ("The small English pattern list does not classify propaganda, ideology, persuasion effectiveness, or speaker intent.",))


POSITIVE = {"good", "great", "excellent", "love", "happy", "helpful", "wonderful"}
NEGATIVE = {"bad", "poor", "terrible", "hate", "sad", "awful", "harmful"}
NEGATIONS = {"not", "no", "never", "without"}


def sentimentint(ctx: AnalysisContext):
    groups = _groups(ctx, {"text"}, "text")
    scores = []
    for record in groups["text"]:
        value = _text(ctx, record, "text")
        if not value:
            continue
        tokens, positive, negative, hits = _tokens(value), 0.0, 0.0, []
        for index, token in enumerate(tokens):
            polarity = 1 if token in POSITIVE else -1 if token in NEGATIVE else 0
            if not polarity:
                continue
            preceding = tokens[max(0, index - 3):index]
            negated = any(word in NEGATIONS or word.endswith("n't") for word in preceding)
            if negated:
                polarity *= -1
            weight = 1.5 if index and tokens[index - 1] in {"very", "extremely"} else 1.0
            if polarity > 0:
                positive += weight
            else:
                negative += weight
            if len(hits) < 100:
                hits.append({"token_index": index, "polarity": polarity, "weight": weight, "negated": negated})
        score = (positive - negative) / (positive + negative) if positive + negative else 0.0
        item = {"record_id": record.record_id, "positive_weight": positive, "negative_weight": negative,
                "normalized_lexicon_score": score, "matched_token_evidence": hits}
        scores.append(item)
        if positive + negative:
            ctx.finding("ENGLISH_LEXICON_SENTIMENT_MEASUREMENT", "A transparent English lexicon yields a supplied-text sentiment score",
                        [record.record_id], {"normalized_lexicon_score": score, "method": "EN_LEXICON_V1_NEGATION_3_TOKEN_WINDOW"})
        else:
            ctx.issue(record, "SENTIMENT_LEXICON_NO_MATCH", "No words from the declared English lexicon matched")
    return _finish(ctx, {"texts": len(scores), "method": "EN_LEXICON_V1_NEGATION_3_TOKEN_WINDOW"},
                   {"text_scores": scores},
                   ("This lexicon does not establish emotions, sarcasm, speaker intent, mental state, or sentiment in unsupported languages.",))


def memeint(ctx: AnalysisContext):
    groups = _groups(ctx, {"meme"}, "meme")
    images, perceptual, near = defaultdict(list), [], []
    threshold = _parameter(ctx, "phash_max_distance", 6, 0, 16)
    for record in groups["meme"]:
        digest, phash = record.data.get("image_sha256"), record.data.get("phash")
        caption = _text(ctx, record, "caption", required=False)
        valid = False
        if digest is not None:
            if isinstance(digest, str) and re.fullmatch(r"[0-9a-fA-F]{64}", digest):
                images[digest.lower()].append((record, _hash(_normalized(caption or ""))))
                valid = True
            else:
                ctx.issue(record, "INVALID_IMAGE_HASH", "image_sha256 requires 64 hexadecimal characters")
        if phash is not None:
            if isinstance(phash, str) and re.fullmatch(r"[0-9a-fA-F]{16}", phash):
                perceptual.append((record, int(phash, 16)))
                valid = True
            else:
                ctx.issue(record, "INVALID_PERCEPTUAL_HASH", "phash requires a supplied 64-bit hash encoded as 16 hexadecimal characters")
        if not valid:
            ctx.issue(record, "MEME_HASH_MISSING", "At least one valid supplied image hash is required")
    for digest, rows in images.items():
        if len({caption for _, caption in rows}) > 1:
            ctx.finding("SAME_IMAGE_CAPTION_VARIATION", "The same supplied image SHA-256 has different normalized captions",
                        [record.record_id for record, _ in rows], {"image_sha256": digest})
    close_pairs = 0
    for index, (left, left_hash) in enumerate(perceptual):
        for right, right_hash in perceptual[index + 1:]:
            distance = (left_hash ^ right_hash).bit_count()
            if distance <= threshold:
                close_pairs += 1
                if len(near) < 100:
                    near.append({"left_record_id": left.record_id, "right_record_id": right.record_id, "hamming_distance": distance})
                    ctx.finding("SUPPLIED_PERCEPTUAL_HASH_SIMILARITY", "Two supplied perceptual hashes are within the stated Hamming-distance threshold",
                                [left.record_id, right.record_id], {"hamming_distance": distance, "threshold": threshold})
    if close_pairs > len(near):
        ctx.issue(None, "MEME_PAIR_OUTPUT_LIMIT", "Only the first 100 perceptual similarity pairs are emitted")
    return _finish(ctx, {"exact_image_hashes": len(images), "perceptual_hash_records": len(perceptual),
                         "close_perceptual_pairs": close_pairs, "distance_threshold": threshold},
                   {"near_hash_pairs": near},
                   ("Hashes were supplied, not computed from images; similarity does not establish provenance, authorship, or identical visual content.",))


def _parent_cycles(parents):
    visited, cycles = set(), []
    for start in sorted(parents):
        if start in visited:
            continue
        path, positions, node = [], {}, start
        while node in parents and node not in visited:
            if node in positions:
                cycles.append(path[positions[node]:])
                break
            positions[node] = len(path)
            path.append(node)
            node = parents[node]
        visited.update(path)
    return cycles


def forumint(ctx: AnalysisContext):
    groups = _groups(ctx, {"post"}, "post")
    posts, thread_members, parents, instants = {}, defaultdict(set), {}, {}
    for record in groups["post"]:
        thread, post, author = (_text(ctx, record, key) for key in ("thread_id", "post_id", "author_id"))
        if not thread or not post or not author:
            continue
        key = thread, post
        if key in posts:
            ctx.issue(record, "DUPLICATE_FORUM_POST_ID", "A thread/post ID repeats; the first record is retained")
            continue
        posts[key] = record
        thread_members[thread].add(author)
        instant = _moment(ctx, record, "posted_at")
        if instant:
            instants[key] = instant
        parent = _text(ctx, record, "parent_post_id", required=False)
        if parent:
            parents[key] = (thread, parent)
    for key, parent in parents.items():
        if parent not in posts:
            ctx.issue(posts[key], "FORUM_PARENT_MISSING", "A reply points to a post absent from its supplied thread")
        elif key in instants and parent in instants and instants[key] < instants[parent]:
            ctx.finding("FORUM_REPLY_PRECEDES_PARENT", "A supplied reply timestamp precedes its parent timestamp",
                        [posts[key].record_id, posts[parent].record_id])
    cycles = _parent_cycles(parents)
    for cycle in cycles:
        ctx.finding("FORUM_REPLY_CYCLE", "Supplied forum replies contain a parent cycle",
                    [posts[key].record_id for key in cycle], {"post_ids": [key[1] for key in cycle]})
    return _finish(ctx, {"posts": len(posts), "threads": len(thread_members), "reply_cycles": len(cycles)},
                   {"thread_participant_counts": {thread: len(members) for thread, members in thread_members.items()},
                    "reply_edges": [{"record_id": posts[key].record_id, "thread_id": key[0], "post_id": key[1], "parent_post_id": parent[1]}
                                    for key, parent in parents.items()]},
                   ("Reply structure and declared handles do not establish a real-world social relationship or a person's identity.",))


def messengerint(ctx: AnalysisContext):
    groups = _groups(ctx, {"message"}, "message")
    messages, conversations, edits = {}, defaultdict(list), 0
    for record in groups["message"]:
        conversation, message, sender = (_text(ctx, record, key) for key in ("conversation_id", "message_id", "sender_id"))
        sent = _moment(ctx, record, "sent_at", required=True)
        if not conversation or not message or not sender or not sent:
            continue
        key = conversation, message
        if key in messages:
            ctx.issue(record, "DUPLICATE_MESSENGER_ID", "A conversation/message ID repeats")
            continue
        messages[key] = record, sent
        conversations[conversation].append((sent, record, sender))
        edited = _moment(ctx, record, "edited_at")
        if edited is not None:
            edits += 1
            if edited < sent:
                ctx.finding("MESSAGE_EDIT_PRECEDES_SEND", "A supplied edit timestamp precedes the message's send time", [record.record_id])
        if sent > ctx.as_of:
            ctx.issue(record, "FUTURE_MESSAGE_TIME", "A message timestamp lies after the analysis time")
    for (conversation, _), (record, sent) in messages.items():
        for field in ("reply_to", "forwarded_from_message_id"):
            reference = _text(ctx, record, field, required=False)
            if reference:
                parent = messages.get((conversation, reference))
                if parent is None:
                    ctx.issue(record, "MESSENGER_REFERENCE_MISSING", field + " is not available in this conversation's supplied export")
                elif field == "reply_to" and sent < parent[1]:
                    ctx.finding("MESSAGE_REPLY_PRECEDES_PARENT", "A supplied reply precedes the referenced message", [record.record_id, parent[0].record_id])
    summaries = {}
    for conversation, rows in conversations.items():
        ordered = sorted(rows, key=lambda row: (row[0], row[1].record_id))
        gaps = [(right[0] - left[0]).total_seconds() for left, right in zip(ordered, ordered[1:])]
        transitions = sum(left[2] != right[2] for left, right in zip(ordered, ordered[1:]))
        summaries[conversation] = {"messages": len(rows), "declared_senders": len({sender for _, _, sender in rows}),
                                   "sender_transitions": transitions, "maximum_supplied_gap_seconds": max(gaps, default=0)}
    return _finish(ctx, {"messages": len(messages), "conversations": len(conversations), "edited_message_records": edits},
                   {"conversation_statistics": summaries},
                   ("Export timestamps, edit fields and forwarding labels are unverified metadata; no encrypted-message decryption or account access occurred.",))


def _address_domain(ctx, record, value, field):
    addresses = [address for _, address in getaddresses([value]) if address]
    if len(addresses) != 1 or addresses[0].count("@") != 1:
        ctx.issue(record, "EMAIL_ADDRESS_UNRESOLVED", field + " does not contain one unambiguous address")
        return None
    domain = addresses[0].rsplit("@", 1)[1]
    try:
        result = domain.encode("idna").decode("ascii").lower()
        if not result or "." not in result or any(character.isspace() for character in result):
            raise ValueError()
        return result
    except (ValueError, UnicodeError):
        ctx.issue(record, "EMAIL_DOMAIN_INVALID", field + " contains an invalid domain")
        return None


def emailint(ctx: AnalysisContext):
    groups = _groups(ctx, {"email"}, "email")
    messages, identities = [], defaultdict(list)
    for record in groups["email"]:
        raw = record.data.get("raw_message")
        if not isinstance(raw, str) or not raw.strip():
            ctx.issue(record, "INVALID_FIELD", "raw_message must be nonempty supplied text")
            continue
        try:
            message = Parser(policy=policy.default).parsestr(raw)
            from_headers = message.get_all("From", [])
            if len(from_headers) != 1:
                ctx.issue(record, "EMAIL_FROM_HEADER_AMBIGUOUS", "Exactly one From header is required for domain comparison")
                origin = None
            else:
                origin = _address_domain(ctx, record, str(from_headers[0]), "From")
            reply = _address_domain(ctx, record, str(message["Reply-To"]), "Reply-To") if message["Reply-To"] is not None else None
            returned = _address_domain(ctx, record, str(message["Return-Path"]), "Return-Path") if message["Return-Path"] is not None else None
            if origin and reply and origin != reply:
                ctx.finding("EMAIL_REPLY_DOMAIN_DIFFERENCE", "Supplied From and Reply-To headers name different domains",
                            [record.record_id], {"from_domain": origin, "reply_to_domain": reply})
            auth = defaultdict(set)
            for header in message.get_all("Authentication-Results", []):
                for mechanism, result in re.findall(r"\b(spf|dkim|dmarc)\s*=\s*(pass|fail|neutral|none|softfail|temperror|permerror)\b", str(header), re.I):
                    auth[mechanism.lower()].add(result.lower())
            if any("fail" in results or "softfail" in results for results in auth.values()):
                ctx.finding("SUPPLIED_EMAIL_AUTH_FAILURE_CLAIM", "Authentication-Results text contains a failure claim",
                            [record.record_id], {"mechanisms": sorted(mechanism for mechanism, results in auth.items() if "fail" in results or "softfail" in results)})
            hops = []
            for received in message.get_all("Received", []):
                header = str(received)
                try:
                    instant = parsedate_to_datetime(header.rsplit(";", 1)[1])
                    if instant.tzinfo is None or instant.utcoffset() is None:
                        raise ValueError()
                    hops.append(instant.astimezone(timezone.utc))
                except (ValueError, TypeError, IndexError, OverflowError):
                    ctx.issue(record, "EMAIL_HOP_TIME_UNRESOLVED", "A supplied Received header lacks a usable timezone-aware timestamp")
            if any(left < right for left, right in zip(hops, hops[1:])):
                ctx.finding("EMAIL_HOP_TIME_ORDER_VARIATION", "Supplied Received-header timestamps violate their expected newest-first ordering",
                            [record.record_id])
            message_id = str(message["Message-ID"]).strip() if message["Message-ID"] is not None else None
            digest = _hash(raw)
            if message_id:
                identities[message_id].append((record, digest))
            else:
                ctx.issue(record, "EMAIL_MESSAGE_ID_MISSING", "Message-ID was not supplied")
            messages.append({"record_id": record.record_id, "message_id": message_id, "from_domain": origin,
                             "reply_to_domain": reply, "return_path_domain": returned, "parsed_hop_times": len(hops),
                             "authentication_header_claims": {key: sorted(value) for key, value in auth.items()},
                             "cryptographic_authentication_verified": False})
        except (ValueError, TypeError):
            ctx.issue(record, "EMAIL_PARSE_ERROR", "The supplied email record could not be parsed")
    for message_id, rows in identities.items():
        if len({digest for _, digest in rows}) > 1:
            ctx.finding("EMAIL_MESSAGE_ID_CONTENT_VARIATION", "One supplied Message-ID appears with different message bytes",
                        [record.record_id for record, _ in rows], {"message_id": message_id})
    return _finish(ctx, {"email_records": len(messages)}, {"message_header_analysis": messages},
                   ("Header domains can legitimately differ; Authentication-Results and Received headers can be forged and were not independently verified.",))


def phoneint(ctx: AnalysisContext):
    groups = _groups(ctx, {"phone"}, "phone")
    normalized, duplicates = [], defaultdict(list)
    for record in groups["phone"]:
        raw = _text(ctx, record, "phone")
        if not raw:
            continue
        raw = unicodedata.normalize("NFKC", raw)
        extension = None
        match = re.search(r"(?:ext\.?|x|#)\s*([0-9]{1,8})\s*$", raw, re.I)
        if match:
            extension, raw = match.group(1), raw[:match.start()].strip()
        if not re.fullmatch(r"[+0-9().\-\s]+", raw) or raw.count("+") > 1 or ("+" in raw and not raw.startswith("+")):
            ctx.issue(record, "PHONE_SYNTAX_INVALID", "Phone input contains unsupported characters or misplaced plus signs")
            continue
        digits = re.sub(r"[^0-9]", "", raw)
        if not raw.startswith("+"):
            country = _text(ctx, record, "country_calling_code", required=False)
            if not country or not re.fullmatch(r"\+?[1-9][0-9]{0,2}", country):
                ctx.issue(record, "PHONE_COUNTRY_CODE_REQUIRED", "National input requires an explicit country calling code")
                continue
            if digits.startswith("0"):
                ctx.issue(record, "PHONE_TRUNK_PREFIX_UNRESOLVED", "National trunk-prefix rules were not supplied; use international form")
                continue
            digits = country.lstrip("+") + digits
        if not re.fullmatch(r"[1-9][0-9]{6,14}", digits):
            ctx.issue(record, "PHONE_LENGTH_OR_PREFIX_INVALID", "International syntax requires 7 to 15 digits and a nonzero first digit")
            continue
        number = "+" + digits
        normalized.append({"record_id": record.record_id, "international_syntax": number, "extension": extension,
                           "numbering_plan_verified": False, "active_or_owned_verified": False})
        duplicates[(number, extension)].append(record)
    for (number, extension), rows in duplicates.items():
        if len(rows) > 1:
            ctx.finding("DUPLICATE_NORMALIZED_PHONE_SYNTAX", "Supplied phone records normalize to the same international syntax and extension",
                        [record.record_id for record in rows], {"international_syntax": number, "extension": extension})
    return _finish(ctx, {"valid_syntax_records": len(normalized), "distinct_number_extension_pairs": len(duplicates)},
                   {"normalized_phone_records": normalized},
                   ("Syntax does not prove numbering-plan assignment, activity, location, carrier, or ownership.",))


def usernameint(ctx: AnalysisContext):
    groups = _groups(ctx, {"username"}, "username")
    identities, across, profiles = defaultdict(list), defaultdict(list), []
    patterns = {"github": r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?",
                "twitter": r"[A-Za-z0-9_]{1,15}", "x": r"[A-Za-z0-9_]{1,15}",
                "instagram": r"[A-Za-z0-9_.]{1,30}"}
    for record in groups["username"]:
        platform, handle = _text(ctx, record, "platform"), _text(ctx, record, "username")
        if not platform or not handle:
            continue
        platform, handle = platform.casefold(), unicodedata.normalize("NFKC", handle).removeprefix("@")
        if any(unicodedata.category(character) == "Cf" or character.isspace() for character in handle) or not handle:
            ctx.issue(record, "USERNAME_INVISIBLE_OR_SPACE", "Usernames cannot contain whitespace or invisible format characters")
            continue
        if platform in patterns:
            if not re.fullmatch(patterns[platform], handle) or (platform == "github" and "--" in handle):
                ctx.issue(record, "USERNAME_PLATFORM_SYNTAX_INVALID", "Handle fails the declared platform's supported syntax")
                continue
            canonical = handle.casefold()
        else:
            canonical = handle
            ctx.issue(record, "USERNAME_CASE_POLICY_UNKNOWN", "Unknown platform case rules were not guessed")
        scripts = sorted(_scripts(handle))
        if len(scripts) > 1:
            ctx.finding("MIXED_SCRIPT_USERNAME", "A supplied username mixes multiple writing scripts",
                        [record.record_id], {"platform": platform, "scripts": scripts, "username_sha256": _hash(handle)})
        identities[(platform, canonical)].append(record)
        across[canonical].append((record, platform))
        profiles.append({"record_id": record.record_id, "platform": platform, "normalized_handle": canonical, "scripts": scripts})
    for handle, rows in across.items():
        if len({platform for _, platform in rows}) > 1:
            ctx.finding("CROSS_PLATFORM_HANDLE_STRING_MATCH", "The same normalized handle string occurs on different supplied platforms",
                        [record.record_id for record, _ in rows], {"normalized_handle": handle})
    return _finish(ctx, {"valid_handle_records": len(profiles), "distinct_platform_handles": len(identities)},
                   {"normalized_handles": profiles},
                   ("Shared handle strings and mixed scripts do not prove impersonation, account linkage, or real-world identity.",))


def identityint(ctx: AnalysisContext):
    groups = _groups(ctx, {"identity"}, "identity")
    identifiers, entities, profiles = defaultdict(list), set(), []
    for record in groups["identity"]:
        entity = _text(ctx, record, "entity_id")
        values = record.data.get("identifiers")
        if not entity or not isinstance(values, dict) or not values:
            ctx.issue(record, "IDENTIFIERS_MISSING", "Identity analysis requires a nonempty identifier-type/value object")
            continue
        entities.add(entity)
        normalized_ids = []
        for kind, raw in values.items():
            if not isinstance(kind, str) or not kind.strip() or not isinstance(raw, str) or not raw.strip():
                ctx.issue(record, "IDENTIFIER_VALUE_INVALID", "Identifier types and values must be nonempty strings")
                continue
            kind, value = kind.strip().casefold(), raw.strip()
            if kind == "email":
                if value.count("@") != 1 or any(character.isspace() for character in value):
                    ctx.issue(record, "IDENTIFIER_EMAIL_INVALID", "Email identifier requires one @ separator")
                    continue
                local, domain = value.rsplit("@", 1)
                if not local or not domain:
                    ctx.issue(record, "IDENTIFIER_EMAIL_INVALID", "Email identifier requires local and domain parts")
                    continue
                value = local + "@" + domain.casefold()
            elif kind in {"domain", "username"}:
                value = unicodedata.normalize("NFKC", value).casefold()
            digest = _hash(kind + "\0" + value)
            identifiers[(kind, digest)].append((record, entity))
            normalized_ids.append({"identifier_type": kind, "identifier_sha256": digest})
        profiles.append({"record_id": record.record_id, "entity_id": entity, "identifier_fingerprints": normalized_ids})
    shared = 0
    for (kind, digest), rows in identifiers.items():
        involved = sorted({entity for _, entity in rows})
        if len(involved) > 1:
            shared += 1
            ctx.finding("SHARED_SUPPLIED_IDENTITY_IDENTIFIER", "Different supplied entity IDs share an identifier value",
                        [record.record_id for record, _ in rows],
                        {"identifier_type": kind, "identifier_sha256": digest, "entity_ids": involved})
    return _finish(ctx, {"declared_entities": len(entities), "distinct_identifier_fingerprints": len(identifiers),
                         "shared_identifier_groups": shared}, {"identity_identifier_profiles": profiles},
                   ("Identifiers are not verified; shared identifiers can be recycled, communal, erroneous, or adversarial and never trigger automatic entity merges.",))


def personaint(ctx: AnalysisContext):
    groups = _groups(ctx, {"persona", "activity"}, "persona")
    accounts, profiles, activities = defaultdict(list), [], 0
    for record in groups["persona"]:
        persona, account, role = (_text(ctx, record, key) for key in ("persona_id", "account_id", "claimed_role"))
        start, end = _moment(ctx, record, "active_from"), _moment(ctx, record, "active_to")
        if start and end and start > end:
            ctx.issue(record, "PERSONA_INTERVAL_INVALID", "Persona active_from is after active_to")
            continue
        if persona and account and role:
            accounts[account].append((record, persona, start, end))
            profiles.append({"record_id": record.record_id, "persona_id": persona, "account_id": account,
                             "claimed_role": role, "active_from": start.isoformat() if start else None, "active_to": end.isoformat() if end else None})
    for record in groups["activity"]:
        account = _text(ctx, record, "account_id")
        instant = _moment(ctx, record, "activity_at", required=True)
        if not account or instant is None:
            continue
        activities += 1
        if account not in accounts:
            ctx.issue(record, "PERSONA_ACCOUNT_UNDECLARED", "Activity account is absent from the supplied persona inventory")
        for persona_record, persona, start, end in accounts[account]:
            if (start and instant < start) or (end and instant > end):
                ctx.finding("ACTIVITY_OUTSIDE_DECLARED_PERSONA_INTERVAL", "A supplied activity lies outside a declared persona interval",
                            [record.record_id, persona_record.record_id], {"persona_id": persona, "account_id": account, "activity_at": instant.isoformat()})
    return _finish(ctx, {"persona_records": len(profiles), "activity_records": activities},
                   {"declared_persona_profiles": profiles},
                   ("Declared roles and activity timing do not verify biography, personal attributes, authenticity, or deception.",))


def relationint(ctx: AnalysisContext):
    groups = _groups(ctx, {"relationship"}, "relationship")
    assertions, relationships = defaultdict(list), []
    for record in groups["relationship"]:
        subject, predicate, target = (_text(ctx, record, key) for key in ("subject_id", "predicate", "object_id"))
        negated = record.data.get("negated", False)
        if not isinstance(negated, bool):
            ctx.issue(record, "RELATION_NEGATION_INVALID", "negated must be true or false")
            continue
        start, end = _moment(ctx, record, "valid_from"), _moment(ctx, record, "valid_to")
        if start and end and start > end:
            ctx.issue(record, "RELATION_INTERVAL_INVALID", "valid_from must not exceed valid_to")
            continue
        if subject and predicate and target:
            assertions[(subject, predicate, target)].append((record, negated, start, end))
            relationships.append({"record_id": record.record_id, "subject_id": subject, "predicate": predicate,
                                  "object_id": target, "negated": negated,
                                  "active_at_analysis_time": (start is None or start <= ctx.as_of) and (end is None or ctx.as_of <= end)})
    conflicts = 0
    for (subject, predicate, target), rows in assertions.items():
        positives = [row for row in rows if row[1] is False]
        negatives = [row for row in rows if row[1] is True]
        for left in positives:
            for right in negatives:
                starts = [instant for instant in (left[2], right[2]) if instant is not None]
                ends = [instant for instant in (left[3], right[3], ctx.as_of) if instant is not None]
                begin, finish = max(starts) if starts else None, min(ends)
                if begin is None or begin <= finish:
                    if conflicts >= 400:
                        ctx.issue(None, "RELATION_COMPARISON_LIMIT", "Only the first 400 overlapping opposite-assertion pairs are emitted")
                        break
                    conflicts += 1
                    ctx.finding("OVERLAPPING_RELATION_ASSERTION_OPPOSITION", "Positive and negated relationship assertions have overlapping supplied validity intervals",
                                [left[0].record_id, right[0].record_id],
                                {"subject_id": subject, "predicate": predicate, "object_id": target,
                                 "overlap_start": begin.isoformat() if begin else None, "overlap_end": finish.isoformat()})
    return _finish(ctx, {"relationship_records": len(relationships), "opposed_overlapping_pairs": conflicts},
                   {"supplied_relationships": relationships},
                   ("A relationship assertion or graph edge is not a confirmed real-world affiliation; opposite assertions can reflect incomplete context.",))


def _components(adjacency, excluded=None):
    unseen = set(adjacency) - ({excluded} if excluded is not None else set())
    components = []
    while unseen:
        start = min(unseen)
        component, queue = [], [start]
        unseen.remove(start)
        while queue:
            node = queue.pop()
            component.append(node)
            for child in adjacency[node]:
                if child in unseen:
                    unseen.remove(child)
                    queue.append(child)
        components.append(sorted(component))
    return sorted(components)


def networkint(ctx: AnalysisContext):
    groups = _groups(ctx, {"node", "edge"}, "edge")
    declared, edges, edge_records = set(), set(), defaultdict(list)
    for record in groups["node"]:
        node = _text(ctx, record, "node_id")
        if node:
            declared.add(node)
    for record in groups["edge"]:
        left, right = _text(ctx, record, "from"), _text(ctx, record, "to")
        directed = record.data.get("directed", True)
        if not isinstance(directed, bool):
            ctx.issue(record, "NETWORK_DIRECTION_INVALID", "directed must be true or false")
            continue
        if not left or not right:
            continue
        if declared and (left not in declared or right not in declared):
            ctx.issue(record, "NETWORK_NODE_UNDECLARED", "An edge endpoint is absent from the supplied node inventory")
        canonical = (left, right, True) if directed else (*sorted((left, right)), False)
        edges.add(canonical)
        edge_records[canonical].append(record)
    nodes = declared | {node for left, right, _ in edges for node in (left, right)}
    adjacency, incoming, outgoing = {node: set() for node in nodes}, Counter(), Counter()
    for left, right, directed in edges:
        adjacency[left].add(right)
        adjacency[right].add(left)
        outgoing[left] += 1
        incoming[right] += 1
        if not directed and left != right:
            outgoing[right] += 1
            incoming[left] += 1
    components = _components(adjacency)
    articulation = []
    for node in sorted(nodes):
        if len(adjacency[node]) > 1 and len(_components(adjacency, excluded=node)) > len(components):
            articulation.append(node)
            related = [record.record_id for edge, rows in edge_records.items() if node in edge[:2] for record in rows]
            ctx.finding("SUPPLIED_GRAPH_ARTICULATION_NODE", "Removing this supplied graph node increases the number of weak components",
                        related, {"node_id": node, "method": "UNDIRECTED_PROJECTION_NODE_REMOVAL"})
    statistics = [{"node_id": node, "in_degree": incoming[node], "out_degree": outgoing[node],
                   "weak_degree": len(adjacency[node] - {node}), "weak_degree_centrality": len(adjacency[node] - {node}) / (len(nodes) - 1) if len(nodes) > 1 else 0}
                  for node in sorted(nodes)]
    if len(statistics) > 500:
        ctx.issue(None, "NETWORK_NODE_OUTPUT_LIMIT", "Only the first 500 node statistics are emitted; aggregate metrics use all supplied nodes")
    return _finish(ctx, {"nodes": len(nodes), "unique_edges": len(edges), "weak_components": len(components),
                         "articulation_nodes": len(articulation), "method": "UNWEIGHTED_SUPPLIED_GRAPH"},
                   {"node_statistics": statistics[:500], "weak_component_sizes": [len(component) for component in components],
                    "articulation_node_ids": articulation[:500]},
                   ("Centrality and articulation describe this incomplete supplied graph; they do not establish influence, importance, or real-world relationships.",))


HANDLERS = {
    "SOCMINT": socmint, "HUMINT": humint, "COMINT": comint, "DECEPTIONINT": deceptionint, "TEXTINT": textint,
    "LANGINT": langint, "NARRATIVEINT": narrativeint, "DISINFOINT": disinfoint, "MISINFOINT": misinfoint,
    "PROPINT": propint, "SENTIMENTINT": sentimentint, "MEMEINT": memeint, "FORUMINT": forumint,
    "MESSENGERINT": messengerint, "EMAILINT": emailint, "PHONEINT": phoneint, "USERNAMEINT": usernameint,
    "IDENTITYINT": identityint, "PERSONAINT": personaint, "RELATIONINT": relationint, "NETWORKINT": networkint,
}
