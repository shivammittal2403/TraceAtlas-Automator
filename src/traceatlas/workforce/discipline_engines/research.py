"""Evidence-bound research, government and policy employees.

All legal, sanctions, accreditation, ownership and scientific conclusions remain
supplied assertions. Algorithms compare records and declared dates or terms;
they do not determine current legal status, regulatory compliance or validity.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import date
from decimal import Decimal
import re
import unicodedata
from urllib.parse import unquote, urlsplit

from .common import AnalysisContext, canonical, digest, identifier, instant, number, text

MAX_ARTIFACTS = 200
LIMITS = (
    "Only supplied records were analyzed; no authoritative registry or live source was queried.",
    "Source identities and provenance remain assertions in one captured input artifact.",
    "Findings require human review and do not certify current legal, sanctions, accreditation or scientific status.",
)


def _bool(value, name):
    if type(value) is not bool:
        raise ValueError(name + " must be a boolean")
    return value


def _array(value, name, maximum=100):
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError(name + " must be a bounded array")
    return value


def _texts(value, name, width=256):
    return [text(item, name, maximum=width) for item in _array(value, name)]


def _ids(value, name):
    return [identifier(item, name) for item in _array(value, name)]


def _unique(items, name):
    if len(items) != len(set(items)):
        raise ValueError(name + " contains duplicate IDs")


def _invalid(ctx, record, exc):
    ctx.issue(record.record_id, "invalid_record", str(exc))


def _date(value, name):
    value = text(value, name, maximum=10)
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
        raise ValueError(name + " requires YYYY-MM-DD")
    return date.fromisoformat(value)


def _interval(data, start_name, end_name, optional_end=False):
    start = instant(data.get(start_name), start_name)
    end = instant(data[end_name], end_name) if end_name in data else None
    if end is None and not optional_end:
        raise ValueError(end_name + " is required")
    if end is not None and end <= start:
        raise ValueError(end_name + " must follow " + start_name)
    return start, end


def _doi(value):
    value = text(value, "DOI", maximum=512).strip()
    if value.casefold().startswith(("http://", "https://")):
        parsed = urlsplit(value)
        if (parsed.hostname not in {"doi.org", "dx.doi.org"} or parsed.username is not None or
                parsed.password is not None or parsed.port is not None or parsed.query or parsed.fragment):
            raise ValueError("DOI URL requires an unqualified doi.org host")
        try:
            value = unquote(parsed.path.lstrip("/"), errors="strict")
        except UnicodeError as exc:
            raise ValueError("DOI URL contains invalid encoding") from exc
    elif value.casefold().startswith("doi:"):
        value = value[4:].strip()
    if not re.fullmatch(r"10\.[0-9]{4,9}/[^\s]{1,240}", value):
        raise ValueError("DOI has invalid syntax")
    return value.casefold()


def _name(value):
    value = text(value, "name", maximum=256)
    normalized = unicodedata.normalize("NFKC", value).casefold()
    result = " ".join(re.findall(r"\w+", normalized, flags=re.UNICODE))
    if not result:
        raise ValueError("name has no comparable tokens")
    return result


def _identifiers(value):
    if not isinstance(value, dict) or set(value) - {"lei", "registration_id", "imo", "tax_id"}:
        raise ValueError("identifiers require lei, registration_id, imo or tax_id")
    return {key: text(item, key, maximum=128).strip().casefold() for key, item in value.items()}


def _money(value, name):
    number(value, name, minimum=0, maximum=10 ** 15)
    result = Decimal(str(value))
    if result.as_tuple().exponent < -6:
        raise ValueError(name + " permits at most six decimal places")
    return result


def _decimal(value):
    return format(value.normalize(), "f")


def _currency(value):
    value = text(value, "currency", maximum=3)
    if not re.fullmatch(r"[A-Z]{3}", value):
        raise ValueError("currency requires three uppercase letters")
    return value


def _cycles(graph):
    """Deterministic DFS back-edge cycles over supplied, uniquely keyed nodes."""
    state = {}
    active = []
    positions = {}
    cycles = set()

    def visit(node):
        state[node] = 1
        positions[node] = len(active)
        active.append(node)
        for target in sorted(graph.get(node, ())):
            if target not in graph:
                continue
            if state.get(target, 0) == 0:
                visit(target)
            elif state[target] == 1 and len(cycles) < MAX_ARTIFACTS:
                cycle = active[positions[target]:]
                offset = min(range(len(cycle)), key=lambda index: cycle[index])
                cycles.add(tuple(cycle[offset:] + cycle[:offset]))
        active.pop()
        positions.pop(node)
        state[node] = 2

    for node in sorted(graph):
        if state.get(node, 0) == 0:
            visit(node)
    return [list(item) for item in sorted(cycles)]


def academicint(ctx: AnalysisContext):
    papers = []
    by_doi = defaultdict(list)
    by_id = defaultdict(list)
    for record in ctx.records:
        try:
            data = record.data
            paper_id = identifier(data.get("paper_id"), "paper_id")
            title = text(data.get("title"), "title", maximum=2000)
            authors = _texts(data.get("authors"), "authors")
            if not authors:
                raise ValueError("authors must identify at least one supplied author label")
            doi = _doi(data["doi"]) if "doi" in data else None
            references = sorted(set(_doi(item) for item in _array(data.get("references", []), "references")))
            year = data.get("year")
            if year is not None and (type(year) is not int or not 1000 <= year <= 9999):
                raise ValueError("year requires a four-digit integer")
            retracted = _bool(data["retracted"], "retracted") if "retracted" in data else None
            if year is not None and year > ctx.as_of.year:
                ctx.issue(record.record_id, "future_publication_year", "Supplied publication year follows as_of.")
            if retracted is True:
                ctx.issue(record.record_id, "retraction_asserted", "Retraction status was asserted and needs primary-source verification.")
            item = {"record_id": record.record_id, "paper_id": paper_id, "title": title, "authors": authors,
                    "doi": doi, "year": year, "references": references}
            papers.append(item)
            by_id[paper_id].append(item)
            if doi:
                by_doi[doi].append(item)
            ctx.finding("academic_record", "Bibliographic assertions and references were normalized without merging records.",
                        [record.record_id], {"paper_id": paper_id, "title": title, "doi": doi, "year": year,
                                             "authors": authors, "reference_count": len(references),
                                             "retraction_asserted": retracted, "source_truth_verified": False})
        except (ValueError, TypeError) as exc:
            _invalid(ctx, record, exc)
    for doi, rows in by_doi.items():
        if len(rows) < 2:
            continue
        signatures = {(re.sub(r"\s+", " ", unicodedata.normalize("NFKC", row["title"]).casefold()).strip(), row["year"],
                       tuple(re.sub(r"\s+", " ", unicodedata.normalize("NFKC", author).casefold()).strip()
                             for author in row["authors"])) for row in rows}
        for row in rows:
            ctx.issue(row["record_id"], "conflicting_doi" if len(signatures) > 1 else "duplicate_doi",
                      "DOI assertions remain separate; bibliographic conflicts require verification.")
    for rows in by_id.values():
        if len(rows) > 1:
            for row in rows:
                ctx.issue(row["record_id"], "duplicate_paper_id", "Paper ID has multiple supplied assertions.")
    edges = []
    edge_count = 0
    for paper in papers:
        for cited in paper["references"]:
            targets = [target for target in by_doi.get(cited, []) if target["record_id"] != paper["record_id"]]
            edge_count += len(targets)
            for target in targets[:max(0, MAX_ARTIFACTS - len(edges))]:
                edges.append({"from_record_id": paper["record_id"], "to_record_id": target["record_id"],
                              "doi": cited, "citation_verified": False})
    if edge_count > MAX_ARTIFACTS:
        ctx.issue(None, "artifact_truncated", "Citation edges are limited to 200 supplied-record links.")
    return ctx.output(metrics={"papers": len(papers), "normalized_dois": len(by_doi), "local_citation_links": edge_count},
                      artifacts={"citation_edges": edges}, limitations=LIMITS)


def regint(ctx: AnalysisContext):
    rows = []
    namespaces = defaultdict(lambda: defaultdict(list))
    for record in ctx.records:
        try:
            data = record.data
            regulation = identifier(data.get("regulation_id"), "regulation_id")
            jurisdiction = text(data.get("jurisdiction"), "jurisdiction", maximum=128)
            subject = text(data.get("subject"), "subject", maximum=1000)
            status = data.get("status")
            if status not in {"enacted", "proposed", "repealed"}:
                raise ValueError("status requires enacted, proposed or repealed")
            start, end = _interval(data, "effective_from", "effective_until", True)
            amendment = identifier(data["amendment_of"], "amendment_of") if "amendment_of" in data else None
            temporal = (status if status in {"proposed", "repealed"} else
                        "not_yet_effective" if start > ctx.as_of else
                        "expired" if end is not None and end <= ctx.as_of else "active_declared")
            item = {"record_id": record.record_id, "regulation_id": regulation, "jurisdiction": jurisdiction,
                    "amendment_of": amendment, "status": status, "start": start, "end": end}
            rows.append(item)
            namespaces[jurisdiction][regulation].append(item)
            ctx.finding("regulation_interval", "Declared regulatory status was evaluated within supplied effective dates.",
                        [record.record_id], {"regulation_id": regulation, "jurisdiction": jurisdiction, "subject": subject,
                                             "temporal_status": temporal, "effective_from": start.isoformat(),
                                             "effective_until": end.isoformat() if end else None, "legal_status_verified": False})
        except (ValueError, TypeError) as exc:
            _invalid(ctx, record, exc)
    cycles = []
    for jurisdiction, items in sorted(namespaces.items()):
        graph = {key: set() for key, values in items.items() if len(values) == 1}
        for key, values in items.items():
            if len(values) > 1:
                for row in values:
                    ctx.issue(row["record_id"], "ambiguous_regulation_id", "Duplicate regulation IDs are excluded from amendment graph.")
                continue
            row = values[0]
            if row["amendment_of"]:
                if row["amendment_of"] not in graph:
                    ctx.issue(row["record_id"], "unresolved_amendment", "Amended regulation is absent or ambiguous in this jurisdiction.")
                else:
                    graph[key].add(row["amendment_of"])
        for cycle in _cycles(graph):
            cycles.append({"jurisdiction": jurisdiction, "regulation_ids": cycle})
    for cycle in cycles:
        for regulation in cycle["regulation_ids"]:
            ctx.issue(namespaces[cycle["jurisdiction"]][regulation][0]["record_id"],
                      "amendment_cycle", "Declared amendment relationships form a cycle.")
    if len(cycles) >= MAX_ARTIFACTS:
        ctx.issue(None, "cycle_reporting_limit", "At most 200 representative amendment cycles are shown.")
    return ctx.output(metrics={"regulatory_assertions": len(rows), "amendment_cycles": len(cycles)},
                      artifacts={"amendment_cycles": cycles[:MAX_ARTIFACTS]}, limitations=LIMITS)


def legalint(ctx: AnalysisContext):
    decisions = []
    by_id = defaultdict(list)
    for record in ctx.records:
        try:
            data = record.data
            decision = identifier(data.get("decision_id"), "decision_id")
            court = text(data.get("court"), "court", maximum=256)
            jurisdiction = text(data.get("jurisdiction"), "jurisdiction", maximum=128)
            when = instant(data.get("decision_at"), "decision_at")
            outcome = text(data.get("outcome"), "outcome", maximum=1000)
            tags = sorted(set(_texts(data.get("issue_tags"), "issue_tags", 128)))
            cited = sorted(set(_ids(data.get("cites", []), "cites")))
            if when > ctx.as_of:
                ctx.issue(record.record_id, "future_decision", "Decision timestamp follows as_of.")
            item = {"record_id": record.record_id, "decision_id": decision, "when": when, "cites": cited}
            decisions.append(item)
            by_id[decision].append(item)
            ctx.finding("legal_decision", "Supplied decision metadata was indexed for local citation review.",
                        [record.record_id], {"decision_id": decision, "court": court, "jurisdiction": jurisdiction,
                                             "decision_at": when.isoformat(), "outcome": outcome, "issue_tags": tags,
                                             "precedent_authority_verified": False})
        except (ValueError, TypeError) as exc:
            _invalid(ctx, record, exc)
    edges = []
    edge_count = 0
    for values in by_id.values():
        if len(values) > 1:
            for item in values:
                ctx.issue(item["record_id"], "ambiguous_decision_id", "Duplicate decision ID is excluded as a citation target.")
    for item in decisions:
        for cited in item["cites"]:
            targets = by_id.get(cited, [])
            if len(targets) != 1:
                ctx.issue(item["record_id"], "unresolved_citation", "Cited decision is absent or ambiguous: " + cited)
                continue
            target = targets[0]
            future = target["when"] > item["when"]
            if future:
                ctx.issue(item["record_id"], "future_citation", "Declared citation points to a later decision.")
            edge_count += 1
            if len(edges) < MAX_ARTIFACTS:
                edges.append({"from_record_id": item["record_id"], "to_record_id": target["record_id"],
                              "chronologically_possible": not future, "authority_verified": False})
    if edge_count > MAX_ARTIFACTS:
        ctx.issue(None, "artifact_truncated", "Local legal citation edges are limited to 200 entries.")
    return ctx.output(metrics={"decisions": len(decisions), "local_citations": edge_count},
                      artifacts={"citation_edges": edges}, limitations=LIMITS)


def sanctionsint(ctx: AnalysisContext):
    entries = []
    subjects = []
    for record in ctx.records:
        try:
            data = record.data
            record_type = data.get("record_type")
            if record_type == "entry":
                entry_id = identifier(data.get("list_entry_id"), "list_entry_id")
                list_name = text(data.get("list_name"), "list_name", maximum=256)
                jurisdiction = text(data.get("jurisdiction"), "jurisdiction", maximum=128)
                program = text(data.get("program"), "program", maximum=256)
                subject_name = text(data.get("subject_name"), "subject_name", maximum=256)
                aliases = _texts(data.get("aliases", []), "aliases")
                identifiers = _identifiers(data.get("identifiers", {}))
                start, end = _interval(data, "effective_from", "effective_until", True)
                snapshot = instant(data.get("snapshot_at"), "snapshot_at")
                if snapshot > ctx.as_of:
                    ctx.issue(record.record_id, "future_snapshot", "Snapshot follows as_of and is excluded from matching.")
                active = start <= ctx.as_of and (end is None or ctx.as_of < end) and snapshot <= ctx.as_of
                entries.append({"record_id": record.record_id, "entry_id": entry_id, "list_name": list_name,
                                "jurisdiction": jurisdiction, "program": program, "identifiers": identifiers,
                                "names": {_name(item) for item in [subject_name] + aliases}, "active": active,
                                "snapshot_at": snapshot.isoformat(),
                                "snapshot_age_days": (ctx.as_of - snapshot).total_seconds() / 86400})
            elif record_type == "subject":
                subject = identifier(data.get("subject_id"), "subject_id")
                name = text(data.get("name"), "name", maximum=256)
                subjects.append({"record_id": record.record_id, "subject_id": subject, "name": _name(name),
                                 "identifiers": _identifiers(data.get("identifiers", {}))})
            else:
                raise ValueError("record_type requires entry or subject")
        except (ValueError, TypeError) as exc:
            _invalid(ctx, record, exc)
    candidates = []
    pair_count = 0
    for subject in subjects:
        matches = []
        for entry in entries:
            if not entry["active"]:
                continue
            shared_ids = sorted(key for key, value in subject["identifiers"].items() if entry["identifiers"].get(key) == value)
            name_match = subject["name"] in entry["names"]
            if not shared_ids and not name_match:
                continue
            matches.append({"subject_id": subject["subject_id"], "list_entry_id": entry["entry_id"],
                            "list_name": entry["list_name"], "jurisdiction": entry["jurisdiction"], "program": entry["program"],
                            "basis": "exact_identifier" if shared_ids else "exact_normalized_name",
                            "identifier_types": shared_ids, "candidate_only": True, "clearance_verified": False,
                            "snapshot_at": entry["snapshot_at"], "snapshot_age_days": entry["snapshot_age_days"],
                            "record_ids": [subject["record_id"], entry["record_id"]]})
        matches.sort(key=lambda item: (item["basis"] != "exact_identifier", item["list_name"], item["list_entry_id"], item["record_ids"]))
        pair_count += len(matches)
        candidates.extend(matches[:max(0, MAX_ARTIFACTS - len(candidates))])
        shown = matches[:20]
        if len(matches) > 20:
            ctx.issue(subject["record_id"], "candidate_details_truncated", "Subject details show the first 20 of all counted candidates.")
        ctx.finding("sanctions_candidate_review", "Entity matching is limited to the dated supplied sanctions snapshot.",
                    [subject["record_id"]] + [item["record_ids"][1] for item in shown],
                    {"subject_id": subject["subject_id"], "candidate_count": len(matches), "candidates": shown,
                     "result": "candidate_review_required" if matches else "no_candidate_in_supplied_snapshot",
                     "clearance_verified": False, "current_list_status_verified": False})
    if not subjects:
        ctx.issue(None, "missing_screening_subject", "No valid screening subjects were supplied.")
    if pair_count > MAX_ARTIFACTS:
        ctx.issue(None, "artifact_truncated", "Candidate match artifact is limited to 200 entries.")
    return ctx.output(metrics={"supplied_entries": len(entries), "temporally_eligible_entries": sum(item["active"] for item in entries),
                               "subjects": len(subjects), "candidate_pairs": pair_count},
                      artifacts={"candidate_matches": candidates}, limitations=LIMITS)

def govint(ctx: AnalysisContext):
    programs = []
    for record in ctx.records:
        try:
            data = record.data
            agency = text(data.get("agency"), "agency", maximum=256)
            program = identifier(data.get("program_id"), "program_id")
            budget = _money(data.get("budget"), "budget")
            spent = _money(data.get("spent"), "spent")
            currency = _currency(data.get("currency"))
            start, end = _interval(data, "period_start", "period_end")
            if start > ctx.as_of:
                ctx.issue(record.record_id, "future_reporting_period", "Reporting period starts after as_of.")
            programs.append({"record_id": record.record_id, "agency": agency, "program_id": program,
                             "budget": budget, "spent": spent, "currency": currency, "start": start, "end": end})
        except (ValueError, TypeError) as exc:
            _invalid(ctx, record, exc)
    ambiguous = set()
    for index, left in enumerate(programs):
        for right in programs[index + 1:]:
            if ((left["agency"], left["program_id"], left["currency"]) ==
                    (right["agency"], right["program_id"], right["currency"]) and
                    max(left["start"], right["start"]) < min(left["end"], right["end"])):
                ambiguous.update((left["record_id"], right["record_id"]))
    totals = defaultdict(lambda: {"budget": Decimal(0), "spent": Decimal(0), "report_count": 0})
    for item in programs:
        if item["record_id"] in ambiguous:
            ctx.issue(item["record_id"], "overlapping_program_reports", "Overlapping program reports are excluded from aggregate totals.")
        else:
            total = totals[item["currency"]]
            total["budget"] += item["budget"]
            total["spent"] += item["spent"]
            total["report_count"] += 1
        ctx.finding("public_program_spend", "Reported spending was compared within its declared period and currency.",
                    [item["record_id"]], {"agency": item["agency"], "program_id": item["program_id"],
                                         "budget": _decimal(item["budget"]), "spent": _decimal(item["spent"]),
                                         "currency": item["currency"], "variance": _decimal(item["spent"] - item["budget"]),
                                         "overspend_asserted": item["spent"] > item["budget"],
                                         "included_in_totals": item["record_id"] not in ambiguous, "audit_verified": False})
    return ctx.output(metrics={"program_reports": len(programs), "excluded_overlapping_reports": len(ambiguous)},
                      artifacts={"totals_by_currency": {
                          currency: {"budget": _decimal(value["budget"]), "spent": _decimal(value["spent"]),
                                     "variance": _decimal(value["spent"] - value["budget"]), "report_count": value["report_count"]}
                          for currency, value in sorted(totals.items())}}, limitations=LIMITS)


def policyint(ctx: AnalysisContext):
    policies = 0
    uncovered_count = 0
    for record in ctx.records:
        try:
            data = record.data
            policy = identifier(data.get("policy_id"), "policy_id")
            deadline = instant(data.get("deadline"), "deadline")
            objectives = {}
            for item in _array(data.get("objectives"), "objectives"):
                if not isinstance(item, dict) or set(item) != {"objective_id", "text"}:
                    raise ValueError("objectives require exactly objective_id and text")
                objective_id = identifier(item["objective_id"], "objective_id")
                if objective_id in objectives:
                    raise ValueError("duplicate objective_id")
                objectives[objective_id] = text(item["text"], "objective text", maximum=1000)
            if not objectives:
                raise ValueError("policy requires objectives")
            covered = set()
            measure_ids = set()
            for item in _array(data.get("measures"), "measures"):
                if not isinstance(item, dict) or set(item) != {"measure_id", "objective_ids"}:
                    raise ValueError("measures require exactly measure_id and objective_ids")
                measure_id = identifier(item["measure_id"], "measure_id")
                if measure_id in measure_ids:
                    raise ValueError("duplicate measure_id")
                refs = set(_ids(item["objective_ids"], "objective_ids"))
                if not refs or refs - set(objectives):
                    raise ValueError("measure references unknown or empty objectives")
                measure_ids.add(measure_id)
                covered.update(refs)
            metric_ids = set()
            metrics = []
            for item in _array(data.get("metrics"), "metrics"):
                if not isinstance(item, dict) or set(item) - {"metric_id", "baseline", "target", "direction", "current", "observed_at"}:
                    raise ValueError("metric has unknown fields")
                metric_id = identifier(item.get("metric_id"), "metric_id")
                if metric_id in metric_ids:
                    raise ValueError("duplicate metric_id")
                metric_ids.add(metric_id)
                baseline = number(item.get("baseline"), "baseline", minimum=-10 ** 12, maximum=10 ** 12)
                target = number(item.get("target"), "target", minimum=-10 ** 12, maximum=10 ** 12)
                direction = item.get("direction")
                if direction not in {"increase", "decrease"} or (direction == "increase" and target <= baseline) or (direction == "decrease" and target >= baseline):
                    raise ValueError("metric target must agree with its nonzero direction")
                current = None
                progress = None
                observed = None
                if "current" in item:
                    current = number(item["current"], "current", minimum=-10 ** 12, maximum=10 ** 12)
                    observed = instant(item.get("observed_at"), "observed_at")
                    if observed > ctx.as_of:
                        raise ValueError("metric observation follows as_of")
                    ratio = (Decimal(str(current)) - Decimal(str(baseline))) / (Decimal(str(target)) - Decimal(str(baseline)))
                    try:
                        progress = number(float(ratio), "progress fraction")
                    except ValueError:
                        ctx.issue(record.record_id, "progress_unresolved", "Reported metric scale exceeds finite progress output.")
                elif "observed_at" in item:
                    raise ValueError("observed_at requires current")
                metrics.append({"metric_id": metric_id, "baseline": baseline, "target": target, "direction": direction,
                                "current": current, "observed_at": observed.isoformat() if observed else None,
                                "progress_fraction": progress,
                                "target_met_in_supplied_observation": progress is not None and progress >= 1})
            uncovered = sorted(set(objectives) - covered)
            overdue = deadline <= ctx.as_of and (not metrics or any(not item["target_met_in_supplied_observation"] for item in metrics))
            if uncovered:
                ctx.issue(record.record_id, "uncovered_objectives", "Some supplied objectives have no linked measure.")
            if overdue:
                ctx.issue(record.record_id, "deadline_review", "Deadline passed without complete supplied target support.")
            uncovered_count += len(uncovered)
            policies += 1
            ctx.finding("policy_logic", "Declared policy objectives, measures and metric progress were compared.",
                        [record.record_id], {"policy_id": policy, "uncovered_objective_ids": uncovered,
                                             "measure_count": len(measure_ids), "metrics": metrics,
                                             "deadline": deadline.isoformat(), "deadline_review_required": overdue,
                                             "outcome_verified": False})
        except (ValueError, TypeError, ArithmeticError, OverflowError) as exc:
            _invalid(ctx, record, exc)
    return ctx.output(metrics={"policies": policies, "uncovered_objectives": uncovered_count}, limitations=LIMITS)


def diploint(ctx: AnalysisContext):
    pairs = defaultdict(list)
    by_id = defaultdict(list)
    relations = {"agreement", "meeting", "statement", "dispute", "sanction", "aid"}
    for record in ctx.records:
        try:
            data = record.data
            event_id = identifier(data.get("event_id"), "event_id")
            when = instant(data.get("timestamp"), "timestamp")
            actor = text(data.get("actor"), "actor", maximum=256)
            counterparty = text(data.get("counterparty"), "counterparty", maximum=256)
            relation = data.get("relation")
            if actor == counterparty or relation not in relations:
                raise ValueError("bilateral event requires distinct actor labels and a recognized relation")
            event = {"record_id": record.record_id, "event_id": event_id, "timestamp": when.isoformat(),
                     "actor": actor, "counterparty": counterparty, "relation": relation}
            pairs[tuple(sorted([actor, counterparty]))].append(event)
            by_id[event_id].append(event)
            if when > ctx.as_of:
                ctx.issue(record.record_id, "future_event", "Diplomatic event timestamp follows as_of.")
        except (ValueError, TypeError) as exc:
            _invalid(ctx, record, exc)
    for values in by_id.values():
        if len(values) > 1:
            signatures = {canonical({key: value for key, value in event.items() if key != "record_id"}) for event in values}
            for event in values:
                ctx.issue(event["record_id"], "conflicting_event_id" if len(signatures) > 1 else "duplicate_event_id",
                          "Multiple diplomatic event assertions are preserved without deduplication.")
    timelines = []
    for pair, events in sorted(pairs.items()):
        events.sort(key=lambda item: (item["timestamp"], item["event_id"], item["record_id"]))
        counts = dict(sorted(Counter(item["relation"] for item in events).items()))
        timelines.append({"actors": list(pair), "events": events})
        ctx.finding("bilateral_event_set", "Supplied bilateral interactions were ordered without inferring intent.",
                    [item["record_id"] for item in events], {"actors": list(pair), "event_count": len(events),
                                                           "relation_counts": counts, "first_at": events[0]["timestamp"],
                                                           "last_at": events[-1]["timestamp"], "intent_verified": False})
    return ctx.output(metrics={"actor_pairs": len(pairs), "event_rows": sum(len(items) for items in pairs.values())},
                      artifacts={"timelines": timelines}, limitations=LIMITS)


def ngoint(ctx: AnalysisContext):
    reports = 0
    keys = defaultdict(list)
    for record in ctx.records:
        try:
            data = record.data
            organization = identifier(data.get("organization_id"), "organization_id")
            name = text(data.get("name"), "name", maximum=256)
            year = data.get("reporting_year")
            if type(year) is not int or not 1000 <= year <= 9999:
                raise ValueError("reporting_year requires a four-digit integer")
            currency = _currency(data.get("currency"))
            income = _money(data.get("income"), "income")
            program = _money(data.get("program_expense"), "program_expense")
            admin = _money(data.get("admin_expense"), "admin_expense")
            fundraising = _money(data.get("fundraising_expense"), "fundraising_expense")
            total = program + admin + fundraising
            supplied_total = _money(data["reported_total_expense"], "reported_total_expense") if "reported_total_expense" in data else None
            agrees = None if supplied_total is None else supplied_total == total
            if agrees is False:
                ctx.issue(record.record_id, "expense_total_mismatch", "Reported total differs from supplied expense components.")
            if total > income:
                ctx.issue(record.record_id, "expenses_exceed_income", "Reported expenses exceed period income; reserves and scope need review.")
            if year > ctx.as_of.year:
                ctx.issue(record.record_id, "future_reporting_year", "Reporting year follows as_of.")
            reports += 1
            keys[(organization, year, currency)].append(record.record_id)
            ctx.finding("ngo_report_metrics", "Reported organization expense components were reconciled in one currency.",
                        [record.record_id], {"organization_id": organization, "name": name, "reporting_year": year,
                                             "currency": currency, "income": _decimal(income), "total_expense": _decimal(total),
                                             "program_expense_ratio": float(program / total) if total else None,
                                             "net_reported_income": _decimal(income - total), "reported_total_agrees": agrees,
                                             "registration_verified": False, "fraud_verified": False})
        except (ValueError, TypeError, ArithmeticError) as exc:
            _invalid(ctx, record, exc)
    for refs in keys.values():
        if len(refs) > 1:
            for ref in refs:
                ctx.issue(ref, "duplicate_reporting_period", "Organization period has multiple supplied reports; no aggregate was inferred.")
    return ctx.output(metrics={"organization_reports": reports}, limitations=LIMITS)


def eduint(ctx: AnalysisContext):
    claims = []
    allowed = {"accredited", "probation", "withdrawn", "claimed"}
    for record in ctx.records:
        try:
            data = record.data
            institution = identifier(data.get("institution_id"), "institution_id")
            program = identifier(data.get("program_id"), "program_id")
            body = text(data.get("accreditation_body"), "accreditation_body", maximum=256)
            status = data.get("accreditation_status")
            if status not in allowed:
                raise ValueError("accreditation_status has an unknown value")
            start, end = _interval(data, "valid_from", "valid_until")
            level = text(data.get("qualification_level"), "qualification_level", maximum=128)
            active = start <= ctx.as_of < end and status == "accredited"
            item = {"record_id": record.record_id, "institution_id": institution, "program_id": program,
                    "body": body, "status": status, "start": start, "end": end}
            claims.append(item)
            ctx.finding("education_claim", "Accreditation claim dates were compared only within the supplied body and program scope.",
                        [record.record_id], {"institution_id": institution, "program_id": program,
                                             "accreditation_body": body, "accreditation_status": status,
                                             "qualification_level": level, "valid_from": start.isoformat(),
                                             "valid_until": end.isoformat(), "declared_active": active,
                                             "accreditation_verified": False})
        except (ValueError, TypeError) as exc:
            _invalid(ctx, record, exc)
    conflicts = []
    conflict_count = 0
    for index, left in enumerate(claims):
        for right in claims[index + 1:]:
            if ((left["institution_id"], left["program_id"], left["body"]) !=
                    (right["institution_id"], right["program_id"], right["body"])):
                continue
            if max(left["start"], right["start"]) >= min(left["end"], right["end"]) or left["status"] == right["status"]:
                continue
            conflict_count += 1
            refs = sorted([left["record_id"], right["record_id"]])
            for ref in refs:
                ctx.issue(ref, "conflicting_accreditation", "Same body and program have overlapping contradictory status assertions.")
            if len(conflicts) < MAX_ARTIFACTS:
                conflicts.append({"record_ids": refs, "institution_id": left["institution_id"], "program_id": left["program_id"],
                                  "accreditation_body": left["body"], "statuses": sorted([left["status"], right["status"]])})
    if conflict_count > MAX_ARTIFACTS:
        ctx.issue(None, "artifact_truncated", "Accreditation conflicts are limited to 200 entries.")
    return ctx.output(metrics={"accreditation_claims": len(claims), "conflicting_pairs": conflict_count},
                      artifacts={"conflicting_claims": conflicts}, limitations=LIMITS)


def patentint(ctx: AnalysisContext):
    threshold = number(ctx.parameters.get("similarity_threshold", 0.5), "similarity_threshold", minimum=0.1, maximum=1)
    patents = []
    families = defaultdict(list)
    by_publication = defaultdict(list)
    stop = {"the", "and", "for", "with", "that", "this", "from", "comprising", "wherein", "method", "system", "said"}
    for record in ctx.records:
        try:
            data = record.data
            publication = identifier(data.get("publication_number"), "publication_number")
            application = identifier(data["application_number"], "application_number") if "application_number" in data else None
            family = identifier(data["family_id"], "family_id") if "family_id" in data else None
            jurisdiction = text(data.get("jurisdiction"), "jurisdiction", maximum=128)
            filing = _date(data.get("filing_date"), "filing_date")
            priority = _date(data["priority_date"], "priority_date") if "priority_date" in data else None
            published = _date(data.get("publication_date"), "publication_date")
            claims = _texts(data.get("claims"), "claims", 3000)
            inventors = _texts(data.get("inventors"), "inventors")
            legal_status = text(data["legal_status"], "legal_status", maximum=256) if "legal_status" in data else None
            flags = []
            if priority and priority > filing:
                flags.append("priority_after_filing")
            if published < filing:
                flags.append("publication_before_filing")
            if published > ctx.as_of.date():
                flags.append("future_publication")
            for flag in flags:
                ctx.issue(record.record_id, flag, "Supplied patent chronology requires bibliographic review.")
            tokens = set(re.findall(r"[^\W_]{2,}", unicodedata.normalize("NFKC", " ".join(claims)).casefold())) - stop
            item = {"record_id": record.record_id, "publication_number": publication, "tokens": tokens}
            patents.append(item)
            by_publication[publication].append(record.record_id)
            if family:
                families[family].append({"publication_number": publication, "record_id": record.record_id})
            ctx.finding("patent_record", "Supplied publication chronology, family labels and claim text were indexed.",
                        [record.record_id], {"publication_number": publication, "application_number": application,
                                             "family_id": family, "jurisdiction": jurisdiction, "filing_date": filing.isoformat(),
                                             "priority_date": priority.isoformat() if priority else None,
                                             "publication_date": published.isoformat(), "inventors": inventors,
                                             "claim_count": len(claims), "claim_token_count": len(tokens),
                                             "legal_status_asserted": legal_status, "chronology_flags": flags,
                                             "validity_verified": False, "novelty_verified": False})
        except (ValueError, TypeError) as exc:
            _invalid(ctx, record, exc)
    for refs in by_publication.values():
        if len(refs) > 1:
            for ref in refs:
                ctx.issue(ref, "duplicate_publication_number", "Duplicate publication assertions are preserved as separate records.")
    overlaps = []
    pair_count = 0
    for index, left in enumerate(patents):
        for right in patents[index + 1:]:
            if left["publication_number"] == right["publication_number"] or not left["tokens"] or not right["tokens"]:
                continue
            intersection = left["tokens"] & right["tokens"]
            score = len(intersection) / len(left["tokens"] | right["tokens"])
            if score < threshold:
                continue
            pair_count += 1
            if len(overlaps) < MAX_ARTIFACTS:
                overlaps.append({"record_ids": sorted([left["record_id"], right["record_id"]]),
                                 "publication_numbers": [left["publication_number"], right["publication_number"]],
                                 "jaccard_similarity": score, "shared_token_count": len(intersection),
                                 "candidate_only": True, "novelty_verified": False})
    if pair_count > MAX_ARTIFACTS:
        ctx.issue(None, "artifact_truncated", "Lexical patent overlap artifact is limited to 200 pairs.")
    return ctx.output(metrics={"publications": len(patents), "lexical_candidate_pairs": pair_count},
                      artifacts={"families": [{"family_id": key, "members": value, "relationship_verified": False}
                                               for key, value in sorted(families.items())],
                                 "lexical_overlap": overlaps},
                      limitations=LIMITS + ("Claim token overlap is a review aid; it does not assess novelty, infringement or freedom to operate.",))

def iprint(ctx: AnalysisContext):
    licenses = defaultdict(list)
    usages = []
    for record in ctx.records:
        try:
            data = record.data
            record_type = data.get("record_type")
            if record_type == "license":
                license_id = identifier(data.get("license_id"), "license_id")
                asset = identifier(data.get("asset_id"), "asset_id")
                start, end = _interval(data, "valid_from", "valid_until")
                permissions = defaultdict(set)
                for item in _array(data.get("permissions"), "permissions"):
                    if not isinstance(item, dict) or set(item) != {"action", "territories"}:
                        raise ValueError("permission requires exactly action and territories")
                    action = identifier(item["action"], "action").casefold()
                    territories = {text(value, "territory", maximum=128).strip().casefold()
                                   for value in _array(item["territories"], "territories")}
                    if not territories:
                        raise ValueError("permission requires a territory scope")
                    permissions[action].update(territories)
                prohibited = {item.casefold() for item in _ids(data.get("prohibitions"), "prohibitions")}
                conditions = {item.strip().casefold() for item in _texts(data.get("conditions"), "conditions")}
                licenses[license_id].append({"record_id": record.record_id, "license_id": license_id, "asset_id": asset,
                                            "start": start, "end": end, "permissions": dict(permissions),
                                            "prohibited": prohibited, "conditions": conditions})
            elif record_type == "usage":
                usage = identifier(data.get("usage_id"), "usage_id")
                asset = identifier(data.get("asset_id"), "asset_id")
                license_id = identifier(data.get("license_id"), "license_id")
                action = identifier(data.get("action"), "action").casefold()
                territory = text(data.get("territory"), "territory", maximum=128).strip().casefold()
                conditions = {item.strip().casefold() for item in _texts(data.get("conditions_satisfied"), "conditions_satisfied")}
                when = instant(data.get("when"), "when")
                usages.append({"record_id": record.record_id, "usage_id": usage, "asset_id": asset, "license_id": license_id,
                               "action": action, "territory": territory, "conditions": conditions, "when": when})
                if when > ctx.as_of:
                    ctx.issue(record.record_id, "future_usage", "Usage time follows as_of; it remains a planned assertion.")
            else:
                raise ValueError("record_type requires license or usage")
        except (ValueError, TypeError) as exc:
            _invalid(ctx, record, exc)
    for values in licenses.values():
        if len(values) > 1:
            for item in values:
                ctx.issue(item["record_id"], "ambiguous_license_id", "Duplicate license IDs are excluded from term evaluation.")
    counts = Counter()
    for usage in usages:
        values = licenses.get(usage["license_id"], [])
        license = values[0] if len(values) == 1 else None
        refs = [usage["record_id"]]
        missing_conditions = []
        if license is None:
            status = "unknown_license"
            ctx.issue(usage["record_id"], "unresolved_license", "License ID is missing or ambiguous.")
        else:
            refs.append(license["record_id"])
            territories = license["permissions"].get(usage["action"], set())
            in_territory = "*" in territories or usage["territory"] in territories
            missing_conditions = sorted(license["conditions"] - usage["conditions"])
            if license["asset_id"] != usage["asset_id"]:
                status = "asset_mismatch"
            elif not license["start"] <= usage["when"] < license["end"]:
                status = "outside_declared_term"
            elif usage["action"] in license["prohibited"] and in_territory:
                status = "conflicting_terms"
            elif usage["action"] in license["prohibited"]:
                status = "prohibited"
            elif usage["action"] not in license["permissions"]:
                status = "not_granted_in_supplied_license"
            elif not in_territory:
                status = "territory_mismatch"
            elif missing_conditions:
                status = "conditions_unmet"
            else:
                status = "within_supplied_terms"
        counts[status] += 1
        ctx.finding("license_usage_review", "Proposed usage was compared against explicit supplied license terms.",
                    refs, {"usage_id": usage["usage_id"], "asset_id": usage["asset_id"], "license_id": usage["license_id"],
                           "action": usage["action"], "territory": usage["territory"], "when": usage["when"].isoformat(),
                           "status": status, "missing_condition_labels": missing_conditions,
                           "legal_clearance_verified": False, "ownership_verified": False})
    if not usages:
        ctx.issue(None, "missing_usage", "No valid proposed usage was supplied for term evaluation.")
    return ctx.output(metrics={"license_ids": len(licenses), "usage_rows": len(usages), "status_counts": dict(sorted(counts.items()))},
                      limitations=LIMITS + ("Only exact action, territory and condition labels are compared; full license interpretation remains human work.",))


def standardsint(ctx: AnalysisContext):
    requirements = defaultdict(list)
    controls = []
    evidence = {}
    for record in ctx.records:
        try:
            data = record.data
            record_type = data.get("record_type")
            if record_type == "requirement":
                standard = identifier(data.get("standard_id"), "standard_id")
                version = identifier(data.get("version"), "version")
                requirement = identifier(data.get("requirement_id"), "requirement_id")
                description = text(data.get("text"), "requirement text", maximum=2000)
                mandatory = _bool(data.get("mandatory"), "mandatory")
                requirements[(standard, version, requirement)].append({
                    "record_id": record.record_id, "text": description, "mandatory": mandatory})
            elif record_type == "evidence":
                artifact = identifier(data.get("artifact_id"), "artifact_id")
                description = text(data.get("description"), "description", maximum=1000)
                collected = instant(data.get("collected_at"), "collected_at")
                expires = instant(data["valid_until"], "valid_until") if "valid_until" in data else None
                if expires is not None and expires <= collected:
                    raise ValueError("evidence valid_until must follow collected_at")
                eligible = collected <= ctx.as_of and (expires is None or ctx.as_of < expires)
                if not eligible:
                    ctx.issue(record.record_id, "out_of_scope_evidence_time", "Evidence is future-dated or expired at as_of.")
                evidence[record.record_id] = {"artifact_id": artifact, "description": description, "eligible": eligible}
            elif record_type == "control":
                control = identifier(data.get("control_id"), "control_id")
                standard = identifier(data.get("standard_id"), "standard_id")
                version = identifier(data.get("version"), "version")
                reqs = _ids(data.get("requirement_ids"), "requirement_ids")
                evidence_refs = _ids(data.get("evidence_record_ids"), "evidence_record_ids")
                if not reqs or not evidence_refs:
                    raise ValueError("control requires requirement and evidence record references")
                known_records = {item.record_id for item in ctx.records}
                if set(evidence_refs) - known_records:
                    raise ValueError("control references unknown evidence record IDs")
                implemented = _bool(data.get("implemented"), "implemented")
                result = data.get("test_result")
                if result not in {"pass", "fail", "not_tested"}:
                    raise ValueError("test_result requires pass, fail or not_tested")
                controls.append({"record_id": record.record_id, "control_id": control, "standard_id": standard, "version": version,
                                 "requirements": set(reqs), "evidence": sorted(set(evidence_refs)),
                                 "implemented": implemented, "test_result": result})
            else:
                raise ValueError("record_type requires requirement, control or evidence")
        except (ValueError, TypeError) as exc:
            _invalid(ctx, record, exc)
    control_counts = Counter((item["standard_id"], item["version"], item["control_id"]) for item in controls)
    valid_controls = []
    for control in controls:
        invalid_refs = set(control["evidence"]) - set(evidence)
        missing_reqs = [requirement for requirement in control["requirements"]
                        if len(requirements.get((control["standard_id"], control["version"], requirement), [])) != 1]
        if control_counts[(control["standard_id"], control["version"], control["control_id"])] > 1:
            ctx.issue(control["record_id"], "ambiguous_control_id", "Duplicate control IDs are excluded.")
            continue
        if invalid_refs:
            ctx.issue(control["record_id"], "unresolved_evidence", "Control evidence references are not valid evidence records.")
            continue
        if missing_reqs:
            ctx.issue(control["record_id"], "unresolved_requirement", "Control requirement IDs do not resolve in this exact standard version.")
            continue
        if not control["implemented"] and control["test_result"] == "pass":
            ctx.issue(control["record_id"], "inconsistent_control_test", "A passing test was asserted for an unimplemented control.")
        valid_controls.append(control)
    covered_count = 0
    mandatory_gaps = 0
    for (standard, version, requirement), rows in sorted(requirements.items()):
        matching = [control for control in valid_controls
                    if (control["standard_id"], control["version"]) == (standard, version) and requirement in control["requirements"]]
        for row in rows:
            ambiguous = len(rows) != 1
            if ambiguous:
                ctx.issue(row["record_id"], "ambiguous_requirement_id", "Duplicate requirement ID has no selected definition.")
            passing = [control for control in matching if control["implemented"] and control["test_result"] == "pass"
                       and all(evidence[ref]["eligible"] for ref in control["evidence"])]
            covered = not ambiguous and bool(passing)
            covered_count += covered
            mandatory_gaps += row["mandatory"] and not covered
            refs = [row["record_id"]] + [control["record_id"] for control in matching]
            refs += [ref for control in matching for ref in control["evidence"]]
            ctx.finding("standard_requirement_review", "Exact-version requirement coverage was compared with supplied controls and dated evidence.",
                        refs, {"standard_id": standard, "version": version, "requirement_id": requirement,
                               "mandatory": row["mandatory"], "covered_by_supplied_test": covered,
                               "passing_control_ids": sorted(control["control_id"] for control in passing) if not ambiguous else [],
                               "compliance_verified": False, "evidence_authenticity_verified": False})
    if not requirements:
        ctx.issue(None, "missing_requirements", "No valid standard requirement definitions were supplied.")
    return ctx.output(metrics={"requirement_assertions": sum(len(rows) for rows in requirements.values()),
                               "covered_requirement_assertions": covered_count, "mandatory_gaps": mandatory_gaps,
                               "valid_controls": len(valid_controls)}, limitations=LIMITS)


def rndint(ctx: AnalysisContext):
    projects = 0
    for record in ctx.records:
        try:
            data = record.data
            project = identifier(data.get("project_id"), "project_id")
            hypothesis = text(data.get("hypothesis"), "hypothesis", maximum=2000)
            minimum_effect = number(data.get("minimum_effect", 0), "minimum_effect", minimum=0, maximum=1)
            experiments = []
            ids = []
            control_n = treatment_n = control_successes = treatment_successes = 0
            for item in _array(data.get("experiments"), "experiments"):
                if not isinstance(item, dict) or set(item) != {"experiment_id", "control_n", "treatment_n", "control_successes", "treatment_successes"}:
                    raise ValueError("experiment requires ID and binary outcome counts")
                experiment_id = identifier(item["experiment_id"], "experiment_id")
                ids.append(experiment_id)
                for group in ("control", "treatment"):
                    size, successes = item[group + "_n"], item[group + "_successes"]
                    if type(size) is not int or not 1 <= size <= 10 ** 9 or type(successes) is not int or not 0 <= successes <= size:
                        raise ValueError("experiment counts require positive bounded samples and successes within sample size")
                effect = item["treatment_successes"] / item["treatment_n"] - item["control_successes"] / item["control_n"]
                experiments.append({"experiment_id": experiment_id, "absolute_effect": effect})
                control_n += item["control_n"]
                treatment_n += item["treatment_n"]
                control_successes += item["control_successes"]
                treatment_successes += item["treatment_successes"]
            if not experiments:
                raise ValueError("project requires experiments")
            _unique(ids, "experiments")
            control_rate = control_successes / control_n
            treatment_rate = treatment_successes / treatment_n
            effect = treatment_rate - control_rate
            positive = [item["experiment_id"] for item in experiments if item["absolute_effect"] > 0]
            negative = [item["experiment_id"] for item in experiments if item["absolute_effect"] < 0]
            contradictory = sorted(positive + negative) if positive and negative else []
            if contradictory:
                ctx.issue(record.record_id, "contradictory_experiment_directions", "Supplied experiments have both positive and negative observed effects.")
            projects += 1
            ctx.finding("research_experiment_summary", "Reported binary experiment counts were summarized descriptively.",
                        [record.record_id], {"project_id": project, "hypothesis": hypothesis, "experiment_count": len(experiments),
                                             "pooled_control_n": control_n, "pooled_treatment_n": treatment_n,
                                             "pooled_control_rate": control_rate, "pooled_treatment_rate": treatment_rate,
                                             "absolute_effect": effect, "minimum_effect": minimum_effect,
                                             "observed_threshold_met": effect >= minimum_effect,
                                             "contradictory_experiment_ids": contradictory, "causal_effect_verified": False,
                                             "sample_independence_verified": False, "statistical_significance_established": False})
        except (ValueError, TypeError, ArithmeticError) as exc:
            _invalid(ctx, record, exc)
    return ctx.output(metrics={"projects": projects},
                      limitations=LIMITS + ("Reported counts may reuse participants; pooled descriptive rates do not establish independence, significance or causality.",))


def innovationint(ctx: AnalysisContext):
    innovations = []
    by_id = defaultdict(list)
    known_records = {item.record_id for item in ctx.records}
    for record in ctx.records:
        try:
            data = record.data
            innovation = identifier(data.get("innovation_id"), "innovation_id")
            title = text(data.get("title"), "title", maximum=1000)
            declared = data.get("readiness_level")
            if type(declared) is not int or not 1 <= declared <= 9:
                raise ValueError("readiness_level requires an integer from 1 through 9")
            levels = set()
            refs = {record.record_id}
            for item in _array(data.get("readiness_evidence"), "readiness_evidence"):
                if not isinstance(item, dict) or set(item) != {"level", "description", "record_ids"}:
                    raise ValueError("readiness evidence requires level, description and record_ids")
                level = item["level"]
                if type(level) is not int or not 1 <= level <= 9:
                    raise ValueError("evidence level requires an integer from 1 through 9")
                text(item["description"], "evidence description", maximum=1000)
                evidence_refs = set(_ids(item["record_ids"], "evidence record_ids"))
                if not evidence_refs or evidence_refs - known_records:
                    raise ValueError("readiness evidence requires known input record IDs")
                levels.add(level)
                refs.update(evidence_refs)
            supported = 0
            while supported + 1 in levels:
                supported += 1
            milestone_ids = []
            overdue = []
            for item in _array(data.get("milestones"), "milestones"):
                if not isinstance(item, dict) or set(item) != {"milestone_id", "completed", "due_at"}:
                    raise ValueError("milestone requires milestone_id, completed and due_at")
                milestone = identifier(item["milestone_id"], "milestone_id")
                milestone_ids.append(milestone)
                completed = _bool(item["completed"], "completed")
                due = instant(item["due_at"], "due_at")
                if not completed and due <= ctx.as_of:
                    overdue.append(milestone)
            _unique(milestone_ids, "milestones")
            dependencies = sorted(set(_ids(data.get("dependencies"), "dependencies")))
            item = {"record_id": record.record_id, "innovation_id": innovation, "dependencies": dependencies}
            innovations.append(item)
            by_id[innovation].append(item)
            if supported < declared:
                ctx.issue(record.record_id, "readiness_support_gap", "Declared level exceeds contiguous supplied evidence levels.")
            if overdue:
                ctx.issue(record.record_id, "overdue_milestone", "Incomplete supplied milestones are due at or before as_of.")
            ctx.finding("innovation_readiness", "Declared readiness was compared against sequential supplied evidence and milestones.",
                        refs, {"innovation_id": innovation, "title": title, "declared_level": declared,
                               "sequentially_supported_level": supported, "supplied_evidence_levels": sorted(levels),
                               "overdue_milestone_ids": sorted(overdue), "dependencies": dependencies,
                               "readiness_verified": False})
        except (ValueError, TypeError) as exc:
            _invalid(ctx, record, exc)
    graph = {key: set() for key, values in by_id.items() if len(values) == 1}
    missing = []
    for item in innovations:
        if len(by_id[item["innovation_id"]]) != 1:
            ctx.issue(item["record_id"], "ambiguous_innovation_id", "Duplicate innovation ID is excluded from dependency graph.")
            continue
        for dependency in item["dependencies"]:
            if dependency not in graph:
                if len(missing) < MAX_ARTIFACTS:
                    missing.append({"record_id": item["record_id"], "innovation_id": item["innovation_id"], "dependency_id": dependency})
                ctx.issue(item["record_id"], "missing_dependency", "Dependency is absent or ambiguous: " + dependency)
            else:
                graph[item["innovation_id"]].add(dependency)
    cycles = _cycles(graph)
    if len(cycles) >= MAX_ARTIFACTS:
        ctx.issue(None, "cycle_reporting_limit", "At most 200 representative dependency cycles are shown.")
    for cycle in cycles:
        for innovation in cycle:
            ctx.issue(by_id[innovation][0]["record_id"], "dependency_cycle", "Declared innovation dependencies form a cycle.")
    return ctx.output(metrics={"innovation_assertions": len(innovations), "dependency_cycles": len(cycles)},
                      artifacts={"dependency_cycles": cycles, "missing_dependencies": missing},
                      limitations=LIMITS + ("Readiness levels are ordinal supplied labels; references do not certify a technology-readiness assessment.",))


HANDLERS = {
    "ACADEMICINT": academicint,
    "REGINT": regint,
    "LEGALINT": legalint,
    "SANCTIONSINT": sanctionsint,
    "GOVINT": govint,
    "POLICYINT": policyint,
    "DIPLOINT": diploint,
    "NGOINT": ngoint,
    "EDUINT": eduint,
    "PATENTINT": patentint,
    "IPRINT": iprint,
    "STANDARDSINT": standardsint,
    "RNDINT": rndint,
    "INNOVATIONINT": innovationint,
}
