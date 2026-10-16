"""Deterministic discovery analysis over supplied, cited records."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib
from html.parser import HTMLParser
import json
import math
import re
from urllib.parse import urljoin, urlsplit, urlunsplit

from .common import AnalysisContext

UTC = timezone.utc
ARTIFACT_LIMIT = 200
OPERATORS = frozenset({"site", "filetype", "intitle", "inurl"})
BRAVE_OPERATOR_DOC = (
    "https://api-dashboard.search.brave.com/documentation/resources/search-operators"
)


def _text(value):
    return value.strip() if isinstance(value, str) else ""


def _digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _json(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False,
    )


def _value_key(value):
    """Keep booleans distinct; treat equivalent finite JSON numbers equally."""
    if isinstance(value, bool):
        return ("boolean", value)
    if isinstance(value, (int, float)):
        number = Decimal(str(value))
        return ("number", "0" if number == 0 else str(number.normalize()))
    if isinstance(value, dict):
        return ("object", tuple(sorted((k, _value_key(v)) for k, v in value.items())))
    if isinstance(value, list):
        return ("array", tuple(_value_key(v) for v in value))
    return (type(value).__name__, value)


def _url(value):
    if not isinstance(value, str):
        raise ValueError("URL must be text")
    parsed = urlsplit(value.strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL requires an HTTP(S) host")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Credential-bearing URLs are not accepted")
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    port = parsed.port
    if ":" in host:
        host = "[" + host + "]"
    scheme = parsed.scheme.lower()
    authority = host
    if port is not None and (scheme, port) not in {("http", 80), ("https", 443)}:
        authority += ":" + str(port)
    return urlunsplit((scheme, authority, parsed.path or "/", parsed.query, ""))


def _interval(value):
    """Return a half-open interval without inventing sub-day precision."""
    if not isinstance(value, (str, datetime)):
        raise ValueError("Time requires an ISO string")
    if isinstance(value, str):
        value = value.strip()
        if re.fullmatch(r"\d{4}", value):
            start = datetime(int(value), 1, 1, tzinfo=UTC)
            return start, start.replace(year=start.year + 1), "year"
        if re.fullmatch(r"\d{4}-\d{2}", value):
            year, month = map(int, value.split("-"))
            start = datetime(year, month, 1, tzinfo=UTC)
            end = (
                datetime(year + 1, 1, 1, tzinfo=UTC)
                if month == 12 else datetime(year, month + 1, 1, tzinfo=UTC)
            )
            return start, end, "month"
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            start = datetime.fromisoformat(value).replace(tzinfo=UTC)
            return start, start + timedelta(days=1), "day"
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Sub-day timestamps require a timezone")
    start = value.astimezone(UTC)
    return start, start + timedelta(microseconds=1), "instant"


def _record_time(ctx, record):
    value = record.observed_at or record.data.get("observed_at")
    if value is None:
        return None
    try:
        start, _, precision = _interval(value)
        if precision != "instant":
            raise ValueError("Capture ordering requires a timestamp")
        if start > ctx.as_of:
            raise ValueError("Observation follows the analysis as_of")
        return start
    except (ValueError, OverflowError):
        ctx.issue(record.record_id, "ambiguous_observation_time",
                  "Observation time cannot establish capture order.")
        return None


def _origin(ctx, record, data=None):
    data = data or {}
    source = ctx.sources.get(record.source_id, {})
    original = (
        _text(data.get("upstream_id"))
        or _text(record.data.get("upstream_id"))
        or _text(source.get("original_source_id"))
    )
    if original:
        return "origin:" + original
    publisher = _text(source.get("publisher_id"))
    return "publisher:" + publisher if publisher else None


def _ids(rows):
    return sorted({r.record_id for r in rows})


def osint(ctx: AnalysisContext):
    """Compare typed source assertions and declared origin coverage."""
    assertions = defaultdict(list)
    origins, unresolved, source_types = set(), set(), set()
    accepted = 0
    for record in ctx.records:
        source_types.add(_text(record.data.get("source_type")) or "undeclared")
        claims = record.data.get("claims")
        if not isinstance(claims, list):
            ctx.issue(record.record_id, "invalid_claims",
                      "OSINT records require a claims array.")
            continue
        for claim in claims:
            if not isinstance(claim, dict):
                ctx.issue(record.record_id, "invalid_claim", "Claim must be an object.")
                continue
            subject, predicate = _text(claim.get("subject")), _text(claim.get("predicate"))
            if not subject or not predicate or "value" not in claim:
                ctx.issue(record.record_id, "incomplete_claim",
                          "Claim requires subject, predicate and an explicit value.")
                continue
            try:
                lower = _interval(claim["valid_from"])[0] if claim.get("valid_from") else None
                upper = _interval(claim["valid_to"])[1] if claim.get("valid_to") else None
                if lower is not None and upper is not None and upper <= lower:
                    raise ValueError("Reversed interval")
                if (lower is not None and ctx.as_of < lower) or (
                    upper is not None and ctx.as_of >= upper
                ):
                    ctx.issue(record.record_id, "outside_as_of",
                              "Claim is outside the requested temporal snapshot.")
                    continue
            except (ValueError, OverflowError):
                ctx.issue(record.record_id, "invalid_claim_time",
                          "Claim validity interval is malformed.")
                continue
            origin = _origin(ctx, record, claim)
            if origin:
                origins.add(origin)
            else:
                unresolved.add(record.source_id)
            assertions[(subject, predicate)].append((record, claim["value"], origin))
            accepted += 1
    conflicts, matrix = 0, []
    for (subject, predicate), rows in sorted(assertions.items()):
        variants = defaultdict(list)
        for record, value, origin in rows:
            variants[_value_key(value)].append((record, value, origin))
        values = []
        for group in variants.values():
            values.append({
                "value": group[0][1],
                "record_ids": sorted({r.record_id for r, _, _ in group}),
                "declared_origin_groups": sorted({o for _, _, o in group if o}),
                "unresolved_source_ids": sorted({r.source_id for r, _, o in group if not o}),
            })
        disputed = len(values) > 1
        conflicts += disputed
        item = {
            "subject": subject, "predicate": predicate, "variants": values,
            "conflicting_assertions": disputed, "independence_verified": False,
        }
        matrix.append(item)
        ctx.finding(
            "source_assertion_conflict" if disputed else "source_assertion_agreement",
            f"{subject}: {predicate} has {len(values)} asserted value variant(s).",
            sorted({r.record_id for r, _, _ in rows}), data=item,
        )
    return ctx.output(
        metrics={
            "accepted_assertions": accepted, "assertion_groups": len(assertions),
            "conflicting_groups": conflicts, "source_count": len({r.source_id for r in ctx.records}),
            "declared_origin_groups": len(origins),
            "sources_with_unresolved_origin": len(unresolved),
            "source_types": sorted(source_types),
        },
        artifacts={"assertion_matrix": matrix},
        limitations=(
            "Agreement between records is not verification of their contents.",
            "Origin and publisher groups are asserted metadata, not proven independence.",
        ),
    )


class _Page(HTMLParser):
    def __init__(self, base):
        super().__init__(convert_charrefs=True)
        self.base, self.canonical = base, None
        self.suppressed, self.in_head, self.in_title = [], False, False
        self.text, self.title, self.links, self.headings = [], [], [], Counter()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if self.suppressed:
            if tag in {"script", "style", "template"}:
                self.suppressed.append(tag)
            return
        if tag in {"script", "style", "template"}:
            self.suppressed.append(tag)
            return
        if tag == "head":
            self.in_head = True
        if tag == "title":
            self.in_title = True
        if tag in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            self.headings[tag] += 1
        if tag == "link" and "canonical" in attrs.get("rel", "").lower().split():
            try:
                self.canonical = _url(urljoin(self.base, attrs.get("href", "")))
            except (ValueError, UnicodeError):
                pass
        if tag == "a" and attrs.get("href"):
            try:
                self.links.append(_url(urljoin(self.base, attrs["href"])))
            except (ValueError, UnicodeError):
                pass

    def handle_endtag(self, tag):
        if self.suppressed:
            if tag == self.suppressed[-1]:
                self.suppressed.pop()
            return
        if tag == "head":
            self.in_head = False
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.suppressed:
            return
        if self.in_title:
            self.title.append(data)
        elif not self.in_head:
            self.text.append(data)


def webint(ctx: AnalysisContext):
    captures, histories = [], defaultdict(list)
    for record in ctx.records:
        try:
            requested = _url(record.data.get("url"))
            final = _url(record.data.get("final_url", requested))
        except (ValueError, UnicodeError):
            ctx.issue(record.record_id, "invalid_url", "Capture requires a valid HTTP(S) URL.")
            continue
        html = record.data.get("html")
        plain = record.data.get("text")
        if isinstance(html, str):
            page = _Page(final)
            page.feed(html)
            page.close()
            text = " ".join(" ".join(page.text).split())
            title = " ".join(" ".join(page.title).split())
            canonical = page.canonical or final
            links, headings = sorted(set(page.links)), dict(page.headings)
        elif isinstance(plain, str):
            text = " ".join(plain.split())
            title = _text(record.data.get("title"))
            canonical, links, headings = final, [], {}
        else:
            ctx.issue(record.record_id, "missing_capture_content",
                      "Capture requires html or text.")
            continue
        stamp = _record_time(ctx, record)
        item = {
            "record_id": record.record_id, "requested_url": requested,
            "final_url": final, "canonical_url": canonical, "title": title,
            "visible_text": text, "text_sha256": _digest(text),
            "links": links, "heading_counts": headings,
            "observed_at": stamp.isoformat() if stamp else None,
        }
        captures.append(item)
        if stamp is not None:
            histories[canonical].append((stamp, record, item))
        ctx.finding("web_capture", "Extracted visible content from a supplied capture.",
                    [record.record_id], data=item)
    changes = []
    for canonical, rows in sorted(histories.items()):
        rows.sort(key=lambda row: (row[0], row[1].record_id))
        for previous, current in zip(rows, rows[1:]):
            if previous[0] == current[0]:
                if previous[2]["text_sha256"] != current[2]["text_sha256"]:
                    ctx.issue(current[1].record_id, "simultaneous_capture_conflict",
                              "Different content at the same observation time cannot be ordered.")
                continue
            old, new = previous[2]["visible_text"], current[2]["visible_text"]
            if old == new:
                continue
            before, after = Counter(old.split()), Counter(new.split())
            union_size = sum((before | after).values())
            change = {
                "canonical_url": canonical,
                "previous_record_id": previous[1].record_id,
                "current_record_id": current[1].record_id,
                "text_similarity": sum((before & after).values()) / union_size if union_size else 1.0,
                "similarity_basis": "token_multiset_jaccard",
                "added_word_count": sum((after - before).values()),
                "removed_word_count": sum((before - after).values()),
            }
            changes.append(change)
            ctx.finding("web_content_change", "Supplied page captures contain different visible text.",
                        [previous[1].record_id, current[1].record_id], data=change)
    return ctx.output(
        metrics={"captures": len(captures), "content_changes": len(changes)},
        artifacts={"captures": captures, "changes": changes},
        limitations=("Captured content and canonical-link declarations remain source assertions.",),
    )


def searchint(ctx: AnalysisContext):
    groups, engines, supplied = defaultdict(dict), set(), 0
    for record in ctx.records:
        query = _text(record.data.get("query"))
        results = record.data.get("results")
        engine = _text(record.data.get("engine")) or record.source_id
        if not query or not isinstance(results, list):
            ctx.issue(record.record_id, "invalid_search_results",
                      "Search records require query text and a results array.")
            continue
        engines.add(engine)
        for position, result in enumerate(results, 1):
            if not isinstance(result, dict):
                ctx.issue(record.record_id, "invalid_search_result", "Search result must be an object.")
                continue
            rank = result.get("rank", position)
            if isinstance(rank, bool) or not isinstance(rank, int) or not 1 <= rank <= 1_000_000:
                ctx.issue(record.record_id, "invalid_rank", "Search rank must be a positive integer.")
                continue
            try:
                url = _url(result.get("url"))
            except (ValueError, UnicodeError):
                ctx.issue(record.record_id, "invalid_result_url", "Search result URL is invalid.")
                continue
            supplied += 1
            item = groups[(query, url)].setdefault(
                engine, {"rank": rank, "record_ids": set(), "titles": set()},
            )
            item["rank"] = min(item["rank"], rank)
            item["record_ids"].add(record.record_id)
            if _text(result.get("title")):
                item["titles"].add(result["title"].strip())
    fused = []
    for (query, url), rows in groups.items():
        item = {
            "query": query, "url": url,
            "reciprocal_rank_score": sum(1 / (60 + row["rank"]) for row in rows.values()),
            "engine_ranks": {key: row["rank"] for key, row in sorted(rows.items())},
            "record_ids": sorted({rid for row in rows.values() for rid in row["record_ids"]}),
            "titles": sorted({title for row in rows.values() for title in row["titles"]}),
            "content_verified": False,
        }
        fused.append(item)
    fused.sort(key=lambda row: (row["query"], -row["reciprocal_rank_score"], row["url"]))
    for item in fused:
        ctx.finding("ranked_search_candidate", "Rank-fused search candidate; page content is unverified.",
                    item["record_ids"], data=item)
    return ctx.output(
        metrics={"supplied_results": supplied, "unique_query_urls": len(fused),
                 "engine_count": len(engines)},
        artifacts={"ranked_results": fused},
        limitations=("Search rank is relevance evidence, not factual confidence or index completeness.",),
    )


_QUERY_TOKEN = re.compile(
    r'\s*(?:(?P<operator>-?[A-Za-z][A-Za-z0-9_-]*):)?'
    r'(?P<value>"(?:[^"\\]|\\.)*"|[^\s":]+)'
)


def parse_query(query):
    """Parse a deliberately bounded grammar, preserving unsupported operators."""
    if not isinstance(query, str) or not query.strip() or len(query) > 4096:
        raise ValueError("Query must contain 1–4096 characters")
    tokens, position = [], 0
    while position < len(query):
        if not query[position:].strip():
            break
        match = _QUERY_TOKEN.match(query, position)
        if not match:
            raise ValueError("Malformed query quoting or operator value")
        raw = match.group("value")
        quoted = raw.startswith('"')
        value = json.loads(raw) if quoted else raw
        if not value.strip() or any(ord(char) < 32 for char in value):
            raise ValueError("Query values must contain visible text")
        operator = match.group("operator")
        if not operator and not quoted and value.upper() in {"AND", "OR", "NOT"}:
            raise ValueError("Boolean operators are outside the supported grammar")
        negative = bool(operator and operator.startswith("-"))
        operator = operator.lstrip("-").lower() if operator else None
        if operator == "site":
            if not re.fullmatch(r"(?:\*\.)?[A-Za-z0-9.-]+", value) or ".." in value:
                raise ValueError("site requires a domain or suffix")
            value = value.lower()
        if operator == "filetype" and not re.fullmatch(r"[A-Za-z0-9]{1,10}", value):
            raise ValueError("filetype requires a short extension")
        tokens.append({"operator": operator, "value": value, "negative": negative})
        position = match.end()
    return tokens


def _render_query(tokens):
    parts = []
    for token in tokens:
        value = json.dumps(token["value"], ensure_ascii=False)
        prefix = ("-" if token["negative"] else "") + token["operator"] + ":" if token["operator"] else ""
        parts.append(prefix + value)
    return " ".join(parts)


def _check_result(tokens, result):
    try:
        url = _url(result.get("url"))
    except (ValueError, UnicodeError):
        return "INVALID", []
    parsed, checks = urlsplit(url), []
    for token in tokens:
        operator, value = token["operator"], token["value"].casefold()
        if operator is None:
            continue
        matched = None
        if operator == "site":
            domain = value.removeprefix("*.")
            host = (parsed.hostname or "").casefold()
            matched = host == domain or host.endswith("." + domain)
        elif operator == "filetype":
            matched = parsed.path.casefold().endswith("." + value)
        elif operator == "inurl":
            matched = value in url.casefold()
        elif operator == "intitle" and isinstance(result.get("title"), str):
            matched = value in result["title"].casefold()
        if matched is not None and token["negative"]:
            matched = not matched
        checks.append({"operator": operator, "value": token["value"], "matched": matched})
    state = "MISMATCH" if any(row["matched"] is False for row in checks) else (
        "UNKNOWN" if any(row["matched"] is None for row in checks) else "MATCH"
    )
    return state, checks


def dorkint(ctx: AnalysisContext):
    queries, evaluations, operations = [], [], []
    for record in ctx.records:
        try:
            tokens = parse_query(record.data.get("query"))
        except (ValueError, json.JSONDecodeError):
            ctx.issue(record.record_id, "invalid_query", "Query does not satisfy the typed grammar.")
            continue
        unsupported = sorted({row["operator"] for row in tokens
                              if row["operator"] and row["operator"] not in OPERATORS})
        if unsupported:
            ctx.issue(record.record_id, "unsupported_operator",
                      "Unsupported operators prevent source-operation creation: " + ", ".join(unsupported))
            continue
        provider = _text(record.data.get("provider")) or "brave"
        if provider not in {"brave", "searxng"}:
            ctx.issue(record.record_id, "unsupported_search_provider",
                      "Typed public queries support brave or searxng operation specifications.")
            continue
        rendered = _render_query(tokens)
        operation = {
            "tool_id": "search.execute", "source_id": provider,
            "arguments": {"query": rendered, "query_kind": "typed-public-query"},
            "query_sha256": _digest(rendered),
            "dispatch_state": "NOT_DISPATCHED",
            "requires_approved_task": True,
            "operator_support": "documented" if provider == "brave" else "upstream-dependent",
        }
        if provider == "brave":
            operation["operator_documentation"] = BRAVE_OPERATOR_DOC
        operations.append(operation)
        item = {"record_id": record.record_id, "tokens": tokens,
                "normalized_query": rendered, "source_operation": operation}
        queries.append(item)
        ctx.finding("typed_public_search_query", "Parsed a typed query and created a source-operation specification.",
                    [record.record_id], data=item)
        results = record.data.get("results", [])
        if not isinstance(results, list):
            ctx.issue(record.record_id, "invalid_query_results", "Captured results must be an array.")
            continue
        for index, result in enumerate(results):
            if not isinstance(result, dict):
                ctx.issue(record.record_id, "invalid_query_result", "Captured result must be an object.")
                continue
            state, checks = _check_result(tokens, result)
            evaluation = {"record_id": record.record_id, "result_index": index,
                          "url": result.get("url"), "constraint_state": state, "checks": checks}
            evaluations.append(evaluation)
            if state in {"INVALID", "MISMATCH"}:
                ctx.issue(record.record_id, "query_result_constraint_mismatch",
                          "A captured result does not satisfy the supplied query constraints.")
    return ctx.output(
        metrics={"valid_queries": len(queries), "source_operations": len(operations),
                 "captured_results_evaluated": len(evaluations),
                 "constraint_mismatches": sum(row["constraint_state"] in {"INVALID", "MISMATCH"}
                                             for row in evaluations)},
        artifacts={"queries": queries, "source_operations": operations,
                   "result_evaluations": evaluations},
        limitations=(
            "This analyzer performs no network dispatch.",
            "Captured results do not prove execution of the compiled query.",
            "Search operators and result snippets do not verify captured page contents.",
        ),
    )


def archiveint(ctx: AnalysisContext):
    histories, accepted, duplicates = defaultdict(list), 0, 0
    for record in ctx.records:
        captures = record.data.get("captures", record.data.get("cdx"))
        if not isinstance(captures, list):
            ctx.issue(record.record_id, "invalid_cdx", "Archive records require captures or cdx arrays.")
            continue
        if captures and isinstance(captures[0], list):
            header = captures[0]
            if not all(isinstance(key, str) for key in header) or len(header) != len(set(header)):
                ctx.issue(record.record_id, "invalid_cdx_header", "CDX column names must be unique strings.")
                continue
            converted = []
            for row in captures[1:]:
                if not isinstance(row, list) or len(row) != len(header):
                    ctx.issue(record.record_id, "invalid_cdx_row", "CDX row does not match its header.")
                    continue
                converted.append(dict(zip(header, row)))
            captures = converted
        for capture in captures:
            if not isinstance(capture, dict):
                ctx.issue(record.record_id, "invalid_capture", "Archive capture must be an object.")
                continue
            try:
                url = _url(capture.get("url", capture.get("original", record.data.get("url"))))
                raw_stamp = capture.get("timestamp")
                if isinstance(raw_stamp, str) and re.fullmatch(r"\d{14}", raw_stamp):
                    stamp = datetime.strptime(raw_stamp, "%Y%m%d%H%M%S").replace(tzinfo=UTC)
                else:
                    stamp, _, precision = _interval(raw_stamp)
                    if precision != "instant":
                        raise ValueError("Capture needs a timestamp")
                if stamp > ctx.as_of:
                    raise ValueError("Future capture")
                status = capture.get("status", capture.get("statuscode"))
                if isinstance(status, str) and re.fullmatch(r"\d{3}", status):
                    status = int(status)
                if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
                    raise ValueError("Invalid HTTP status")
            except (ValueError, UnicodeError, OverflowError):
                ctx.issue(record.record_id, "invalid_archive_capture",
                          "Capture URL, timestamp or HTTP status is invalid for the as_of snapshot.")
                continue
            item = {"record_id": record.record_id, "url": url, "timestamp": stamp.isoformat(),
                    "status": status, "digest": _text(capture.get("digest")) or None}
            histories[url].append((stamp, record, item))
            accepted += 1
    outputs, changes = [], []
    for url, rows in sorted(histories.items()):
        rows.sort(key=lambda row: (row[0], row[1].record_id))
        unique, seen = [], set()
        for row in rows:
            key = (row[0], row[2]["status"], row[2]["digest"])
            if key in seen:
                duplicates += 1
                continue
            seen.add(key)
            unique.append(row)
        successful = [row for row in unique if row[2]["status"] == 200]
        url_changes = 0
        for before, after in zip(successful, successful[1:]):
            if before[0] == after[0]:
                if before[2]["digest"] != after[2]["digest"]:
                    ctx.issue(after[1].record_id, "simultaneous_archive_conflict",
                              "Different digests at the same capture time cannot establish change order.")
                continue
            if before[2]["digest"] and after[2]["digest"] and before[2]["digest"] != after[2]["digest"]:
                change = {"url": url, "before": before[2], "after": after[2]}
                changes.append(change)
                url_changes += 1
                ctx.finding("archive_digest_change", "Successful archive captures have different declared digests.",
                            [before[1].record_id, after[1].record_id], data=change)
        gaps = [(b[0] - a[0]).total_seconds() for a, b in zip(unique, unique[1:])]
        item = {
            "url": url, "captures": [row[2] for row in unique],
            "successful_captures": len(successful),
            "known_content_digests": len({row[2]["digest"] for row in successful if row[2]["digest"]}),
            "unknown_digest_captures": sum(row[2]["digest"] is None for row in successful),
            "largest_observed_gap_seconds": max(gaps) if gaps else None,
            "digest_changes": url_changes,
        }
        outputs.append(item)
        ctx.finding("archive_history", "Reconstructed supplied capture history.",
                    _ids([row[1] for row in unique]), data=item)
    return ctx.output(
        metrics={"accepted_captures": accepted, "duplicate_capture_rows": duplicates,
                 "urls": len(outputs), "digest_changes": len(changes)},
        artifacts={"histories": outputs, "changes": changes},
        limitations=("Capture time is not publication or event time; gaps do not prove absence of content.",),
    )


def newsint(ctx: AnalysisContext):
    articles = []
    for record in ctx.records:
        title = _text(record.data.get("title"))
        body = _text(record.data.get("body", record.data.get("text")))
        if not title and not body:
            ctx.issue(record.record_id, "missing_article", "Article requires title or body text.")
            continue
        try:
            url = _url(record.data.get("url"))
            published = record.data.get("published_at")
            interval = _interval(published) if published else None
            if interval and interval[0] > ctx.as_of:
                raise ValueError("Publication follows as_of")
        except (ValueError, UnicodeError, OverflowError):
            ctx.issue(record.record_id, "invalid_article_metadata",
                      "Article URL or publication time is invalid for the snapshot.")
            continue
        normalized = " ".join(body.casefold().split())
        tokens = re.findall(r"\w+", normalized, re.UNICODE)
        shingles = {tuple(tokens[index:index + 4]) for index in range(max(0, len(tokens) - 3))}
        origin = _text(record.data.get("wire_id")) or _origin(ctx, record)
        if record.data.get("original_url"):
            try:
                origin = "url:" + _url(record.data["original_url"])
            except (ValueError, UnicodeError):
                ctx.issue(record.record_id, "invalid_original_url", "Declared original URL is invalid.")
        articles.append({"record": record, "url": url, "title": title, "body": normalized,
                         "shingles": shingles, "origin": origin, "published_at": published})
    parent = list(range(len(articles)))

    def find(index):
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    links = []
    for right, b in enumerate(articles):
        for left, a in enumerate(articles[:right]):
            method = None
            if a["origin"] and a["origin"] == b["origin"]:
                method = "declared_origin"
            elif a["body"] and a["body"] == b["body"]:
                method = "exact_body"
            elif min(len(a["shingles"]), len(b["shingles"])) >= 20:
                similarity = len(a["shingles"] & b["shingles"]) / len(a["shingles"] | b["shingles"])
                if similarity >= 0.85:
                    method = "near_copy"
            if method:
                parent[find(right)] = find(left)
                links.append({"left": a["record"].record_id, "right": b["record"].record_id,
                              "method": method})
    groups = defaultdict(list)
    for index, article in enumerate(articles):
        groups[find(index)].append(article)
    clusters = []
    for rows in groups.values():
        ids = _ids([row["record"] for row in rows])
        item = {
            "record_ids": ids, "urls": sorted({row["url"] for row in rows}),
            "titles": sorted({row["title"] for row in rows if row["title"]}),
            "declared_origin_groups": sorted({row["origin"] for row in rows if row["origin"]}),
            "source_ids": sorted({row["record"].source_id for row in rows}),
            "copy_links": [link for link in links if link["left"] in ids and link["right"] in ids],
            "independence_verified": False,
        }
        clusters.append(item)
        ctx.finding("news_content_cluster", "Grouped supplied articles by content or declared origin.",
                    ids, data=item)
    return ctx.output(
        metrics={"articles": len(articles), "content_clusters": len(clusters),
                 "candidate_republished_articles": len(articles) - len(clusters)},
        artifacts={"clusters": clusters},
        limitations=(
            "Content similarity and declared wire/origin metadata identify candidate copies.",
            "Distinct publishers and cluster counts do not establish independent corroboration.",
        ),
    )


def _type(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    return "object" if isinstance(value, dict) else "array"


def datasetint(ctx: AnalysisContext):
    profiles, snapshots = [], defaultdict(list)
    allowed = {"string", "number", "integer", "boolean", "object", "array", "null"}
    for record in ctx.records:
        rows = record.data.get("rows")
        schema = record.data.get("schema", {})
        keys = record.data.get("key_fields", [])
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            ctx.issue(record.record_id, "invalid_dataset_rows", "Dataset rows must be objects.")
            continue
        if not isinstance(schema, dict) or any(value not in allowed for value in schema.values()):
            ctx.issue(record.record_id, "invalid_dataset_schema", "Schema must name supported JSON types.")
            continue
        if not isinstance(keys, list) or any(not isinstance(key, str) or not key for key in keys):
            ctx.issue(record.record_id, "invalid_dataset_keys", "key_fields must be column names.")
            continue
        columns = sorted(set(schema) | {key for row in rows for key in row})
        profile, violations = {}, []
        for column in columns:
            counts = Counter(_type(row[column]) if column in row else "missing" for row in rows)
            numbers = [float(row[column]) for row in rows
                       if column in row and isinstance(row[column], (int, float))
                       and not isinstance(row[column], bool)]
            item = {"type_counts": dict(counts), "blank_strings": sum(
                isinstance(row.get(column), str) and not row[column].strip() for row in rows)}
            if numbers:
                item["numeric"] = {"minimum": min(numbers), "maximum": max(numbers),
                                   "mean": math.fsum(value / len(numbers) for value in numbers)}
            profile[column] = item
            expected = schema.get(column)
            if expected:
                for index, row in enumerate(rows):
                    if column not in row or row[column] is None:
                        continue
                    actual = _type(row[column])
                    if actual != expected and not (expected == "number" and actual == "integer"):
                        violations.append({"row_index": index, "column": column,
                                           "expected": expected, "actual": actual})
        key_rows, incomplete = defaultdict(list), []
        if keys:
            for index, row in enumerate(rows):
                if any(key not in row or row[key] is None for key in keys):
                    incomplete.append(index)
                else:
                    key_rows[tuple(_value_key(row[key]) for key in keys)].append(index)
        duplicates = [indices for indices in key_rows.values() if len(indices) > 1]
        item = {
            "record_id": record.record_id, "dataset_id": _text(record.data.get("dataset_id")) or record.record_id,
            "row_count": len(rows), "columns": profile, "duplicate_key_row_groups": duplicates,
            "incomplete_key_rows": incomplete, "schema_violations": violations[:ARTIFACT_LIMIT],
            "schema_violation_count": len(violations),
            "schema_violations_truncated": len(violations) > ARTIFACT_LIMIT,
        }
        profiles.append(item)
        stamp = _record_time(ctx, record)
        if stamp:
            snapshots[item["dataset_id"]].append((stamp, record, profile))
        ctx.finding("dataset_quality_profile", "Profiled supplied rows without treating missing values as zero.",
                    [record.record_id], data=item)
    drifts = []
    for dataset_id, rows in sorted(snapshots.items()):
        rows.sort(key=lambda row: (row[0], row[1].record_id))
        for before, after in zip(rows, rows[1:]):
            if before[0] == after[0]:
                continue
            old, new = before[2], after[2]
            changed = [column for column in sorted(set(old) & set(new))
                       if set(old[column]["type_counts"]) != set(new[column]["type_counts"])]
            item = {"dataset_id": dataset_id, "before_record_id": before[1].record_id,
                    "after_record_id": after[1].record_id,
                    "added_columns": sorted(set(new) - set(old)),
                    "removed_columns": sorted(set(old) - set(new)), "changed_type_columns": changed}
            if item["added_columns"] or item["removed_columns"] or changed:
                drifts.append(item)
                ctx.finding("dataset_schema_drift", "Supplied dataset snapshots have different schemas.",
                            [before[1].record_id, after[1].record_id], data=item)
    return ctx.output(
        metrics={"datasets": len(profiles), "rows": sum(row["row_count"] for row in profiles),
                 "duplicate_key_groups": sum(len(row["duplicate_key_row_groups"]) for row in profiles),
                 "schema_violations": sum(row["schema_violation_count"] for row in profiles),
                 "schema_drifts": len(drifts)},
        artifacts={"profiles": profiles, "schema_drifts": drifts},
        limitations=("Statistics describe supplied rows; population coverage and column semantics remain unverified.",),
    )


def _event_interval(data):
    start, end, precision = _interval(data.get("start", data.get("time")))
    if data.get("end") is not None:
        _, declared_end, end_precision = _interval(data["end"])
        if declared_end <= start:
            raise ValueError("Event ends before it starts")
        end = declared_end
        precision = precision + "/" + end_precision
    return start, end, precision


def _coordinates(data):
    if "latitude" not in data and "longitude" not in data:
        return None
    latitude, longitude = data.get("latitude"), data.get("longitude")
    if any(isinstance(value, bool) or not isinstance(value, (int, float))
           for value in (latitude, longitude)):
        raise ValueError("Coordinates require numbers")
    if not -90 <= latitude <= 90 or not -180 <= longitude <= 180:
        raise ValueError("Coordinates outside WGS84 bounds")
    uncertainty = data.get("uncertainty_m", 0)
    if isinstance(uncertainty, bool) or not isinstance(uncertainty, (int, float)) or uncertainty < 0:
        raise ValueError("Coordinate uncertainty must be nonnegative")
    return float(latitude), float(longitude), float(uncertainty)


def _distance(a, b):
    lat1, lon1, _ = a
    lat2, lon2, _ = b
    p1, p2, dp = map(math.radians, (lat1, lat2, lat2 - lat1))
    dl = math.radians(lon2 - lon1)
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 6_371_000 * 2 * math.asin(math.sqrt(min(1, max(0, h))))


def _same_event_candidate(a, b):
    if a["type"] != b["type"] or max(a["start"], b["start"]) >= min(a["end"], b["end"]):
        return False
    if a["place"] and b["place"]:
        return a["place"] == b["place"]
    if a["coordinates"] and b["coordinates"]:
        tolerance = max(100, a["coordinates"][2] + b["coordinates"][2])
        return _distance(a["coordinates"], b["coordinates"]) <= tolerance
    return False


def eventint(ctx: AnalysisContext):
    events = []
    for record in ctx.records:
        kind = _text(record.data.get("event_type")).casefold()
        try:
            start, end, precision = _event_interval(record.data)
            coordinates = _coordinates(record.data)
            if not kind or start > ctx.as_of:
                raise ValueError("Missing type or future event")
        except (ValueError, OverflowError):
            ctx.issue(record.record_id, "invalid_event", "Event type, interval or location is invalid.")
            continue
        events.append({"record": record, "type": kind, "start": start, "end": end,
                       "precision": precision, "coordinates": coordinates,
                       "place": _text(record.data.get("place_id"))})
    groups = []
    # Complete-link grouping prevents a chain of nearby but incompatible events
    # from becoming one large event.
    for event in sorted(events, key=lambda row: (row["start"], row["record"].record_id)):
        group = next((rows for rows in groups if all(
            _same_event_candidate(event, other) for other in rows)), None)
        if group is None:
            groups.append([event])
        else:
            group.append(event)
    clusters = []
    for rows in groups:
        item = {
            "record_ids": _ids([row["record"] for row in rows]),
            "event_type": rows[0]["type"],
            "time_intervals": [{"record_id": row["record"].record_id,
                               "start": row["start"].isoformat(), "end_exclusive": row["end"].isoformat(),
                               "precision": row["precision"]} for row in rows],
            "place_ids": sorted({row["place"] for row in rows if row["place"]}),
            "candidate_only": True,
            "uncertain_time": any(row["precision"] != "instant" for row in rows),
        }
        clusters.append(item)
        ctx.finding("event_candidate_cluster", "Grouped compatible supplied event observations.",
                    item["record_ids"], data=item)
    return ctx.output(
        metrics={"events": len(events), "candidate_clusters": len(clusters)},
        artifacts={"event_clusters": clusters},
        limitations=("Compatible time and location identify candidates, not verified event identity or causation.",),
    )


def _strong_components(nodes, edges):
    adjacency = {node: set() for node in nodes}
    for left, right in edges:
        adjacency[left].add(right)
    index, stack, active, order, low, components = 0, [], set(), {}, {}, []

    def visit(node):
        nonlocal index
        order[node] = low[node] = index
        index += 1
        stack.append(node)
        active.add(node)
        for target in sorted(adjacency[node]):
            if target not in order:
                visit(target)
                low[node] = min(low[node], low[target])
            elif target in active:
                low[node] = min(low[node], order[target])
        if low[node] == order[node]:
            component = []
            while True:
                target = stack.pop()
                active.remove(target)
                component.append(target)
                if target == node:
                    break
            if len(component) > 1 or node in adjacency[node]:
                components.append(sorted(component))
    for node in sorted(nodes):
        if node not in order:
            visit(node)
    return components


def timelineint(ctx: AnalysisContext):
    events, by_event_id = [], defaultdict(list)
    for record in ctx.records:
        try:
            start, end, precision = _event_interval(record.data)
            if start > ctx.as_of:
                raise ValueError("Future observation")
        except (ValueError, OverflowError):
            ctx.issue(record.record_id, "invalid_timeline_time",
                      "Timeline time is malformed, timezone-ambiguous or after as_of.")
            continue
        event_id = _text(record.data.get("event_id")) or record.record_id
        item = {"record": record, "event_id": event_id, "start": start, "end": end,
                "precision": precision}
        events.append(item)
        by_event_id[event_id].append(item)
    for event_id, rows in by_event_id.items():
        if len(rows) > 1:
            ctx.issue(rows[0]["record"].record_id, "ambiguous_event_identifier",
                      "Repeated event IDs remain separate observations: " + event_id)
    declared, contradictions = set(), []
    by_record = {row["record"].record_id: row for row in events}
    for row in events:
        for field in ("before", "after"):
            targets = row["record"].data.get(field, [])
            if not isinstance(targets, list) or any(not isinstance(target, str) for target in targets):
                ctx.issue(row["record"].record_id, "invalid_precedence", "before/after require event-ID arrays.")
                continue
            for target in targets:
                candidates = by_event_id.get(target, [])
                if len(candidates) != 1:
                    ctx.issue(row["record"].record_id, "unresolved_precedence_target",
                              "Precedence target is missing or ambiguous: " + target)
                    continue
                other = candidates[0]
                left, right = (row, other) if field == "before" else (other, row)
                pair = (left["record"].record_id, right["record"].record_id)
                declared.add(pair)
                if left["start"] >= right["end"]:
                    contradictions.append(pair)
                    ctx.finding("timeline_order_conflict",
                                "Declared precedence conflicts with supplied time intervals.",
                                list(pair), data={"before_record_id": pair[0], "after_record_id": pair[1]})
    cycles = _strong_components(by_record, declared)
    for members in cycles:
        ctx.finding("timeline_constraint_cycle", "Declared precedence contains a directed cycle.",
                    members, data={"record_ids": members})
    chronological = sorted(events, key=lambda row: (row["start"], row["end"], row["record"].record_id))
    certain, overlaps, certain_count, overlap_count = [], [], 0, 0
    for index, left in enumerate(chronological):
        for right in chronological[index + 1:]:
            pair = [left["record"].record_id, right["record"].record_id]
            if left["end"] <= right["start"]:
                certain_count += 1
                if len(certain) < ARTIFACT_LIMIT:
                    certain.append(pair)
            else:
                overlap_count += 1
                if len(overlaps) < ARTIFACT_LIMIT:
                    overlaps.append(pair)
    intervals = [{"record_id": row["record"].record_id, "event_id": row["event_id"],
                  "start": row["start"].isoformat(), "end_exclusive": row["end"].isoformat(),
                  "precision": row["precision"]} for row in chronological]
    if intervals:
        ctx.finding("timeline_interval_order",
                    "Ordered interval bounds without imposing an order on overlapping observations.",
                    [row["record_id"] for row in intervals],
                    data={"intervals": intervals, "certain_pair_count": certain_count,
                          "overlapping_pair_count": overlap_count})
    return ctx.output(
        metrics={"events": len(events), "declared_precedence_edges": len(declared),
                 "precedence_cycles": len(cycles), "time_order_conflicts": len(contradictions),
                 "certain_pairs": certain_count, "overlapping_pairs": overlap_count},
        artifacts={"intervals": intervals, "declared_precedence": [list(pair) for pair in sorted(declared)],
                   "cycles": cycles, "certain_pairs": certain, "overlapping_pairs": overlaps,
                   "pair_artifacts_truncated": certain_count > len(certain) or overlap_count > len(overlaps)},
        limitations=("Date/month/year precision is retained; overlapping intervals do not establish event order.",),
    )


HANDLERS = {
    "OSINT": osint, "WEBINT": webint, "SEARCHINT": searchint,
    "DORKINT": dorkint, "ARCHIVEINT": archiveint, "NEWSINT": newsint,
    "DATASETINT": datasetint, "EVENTINT": eventint, "TIMELINEINT": timelineint,
}
