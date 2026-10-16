"""Corporate/economic processors over submitted records, with exact decimal arithmetic.

No current registry, legal, tax, financial, employment or ownership status is
independently verified. Arithmetic uses declared periods, units and currencies.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, localcontext
from functools import wraps
import re
import unicodedata

from .common import AnalysisContext, canonical, instant, number, text


def _s(value):
    return value.strip() if isinstance(value, str) else ""


def _d(value, name="amount", minimum=None):
    if type(value) not in (str, int, float) or type(value) is bool:
        raise ValueError(name + " requires a decimal number")
    if isinstance(value, str) and (len(value) > 100 or not re.fullmatch(r"[+-]?\d+(?:\.\d{1,18})?", value)):
        raise ValueError(name + " requires bounded decimal notation")
    try:
        value = Decimal(str(value))
    except InvalidOperation as exc:
        raise ValueError("Invalid decimal " + name) from exc
    if not value.is_finite() or abs(value) > Decimal("1e30") or value.as_tuple().exponent < -18:
        raise ValueError(name + " exceeds decimal limits")
    if minimum is not None and value < Decimal(str(minimum)):
        raise ValueError(name + " is below its minimum")
    return value


def _out(value):
    return format(value, "f") if value is not None else None


def _currency(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Z]{3}", value):
        raise ValueError("Currency requires a declared three-letter code")
    return value


def _day(value):
    if isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
    return instant(value)


def _list(data, key, optional=False):
    value = data.get(key, [] if optional else None)
    if not isinstance(value, list):
        raise ValueError(key + " requires an array")
    return value


def _bool(data, key):
    value = data.get(key)
    if value is not None and type(value) is not bool:
        raise ValueError(key + " requires a boolean")
    return value


def _rows(ctx, parser):
    rows = []
    for record in ctx.records:
        try:
            rows.append((record, parser(record.data)))
        except (ValueError, TypeError, KeyError, UnicodeError, InvalidOperation, OverflowError) as exc:
            ctx.issue(record, "invalid_economic_record", str(exc)[:1000] or "Malformed economic record")
    return rows


def _finish(ctx, rows, kind, artifact, metrics=None, limitations=()):
    for record, item in rows:
        ctx.finding(kind, "Calculated " + artifact + " from supplied records.", [record.record_id], item)
    return ctx.output(metrics={"accepted_records": len(rows), **(metrics or {})},
                      artifacts={artifact: [item for _, item in rows]},
                      limitations=("Declared data and calculations do not verify current legal status or factual accuracy.",
                                   *limitations))


def finint(ctx: AnalysisContext):
    """Check balance identities, operating margins and liquidity using declared financial periods."""
    def parse(data):
        entity, period = text(data["entity_id"], "entity_id"), text(data["period"], "period")
        currency = _currency(data["currency"])
        values = {key: _d(data[key], key) for key in (
            "assets", "liabilities", "equity", "revenue", "operating_profit")}
        current_assets = _d(data["current_assets"], "current_assets", 0) if "current_assets" in data else None
        current_liabilities = _d(data["current_liabilities"], "current_liabilities", 0) if "current_liabilities" in data else None
        difference = values["assets"] - values["liabilities"] - values["equity"]
        margin = values["operating_profit"] / values["revenue"] if values["revenue"] != 0 else None
        liquidity = current_assets / current_liabilities if current_assets is not None and current_liabilities else None
        return {"entity_id": entity, "period": period, "currency": currency,
                **{key: _out(value) for key, value in values.items()},
                "balance_identity_difference": _out(difference), "balance_identity_holds": difference == 0,
                "operating_margin": _out(margin), "current_ratio": _out(liquidity)}
    with localcontext() as context:
        context.prec = 60
        rows = _rows(ctx, parse)
    return _finish(ctx, rows, "financial_statement_checks", "statements",
                   limitations=("Ratios concern supplied accounting figures and periods, with no valuation or investment recommendation.",))


def corpint(ctx: AnalysisContext):
    """Reconcile jurisdiction-scoped corporate identifiers and active registry-status assertions."""
    def parse(data):
        jurisdiction = text(data["jurisdiction"], "jurisdiction", maximum=80).upper()
        registry_id = text(data["registry_id"], "registry_id", maximum=160)
        name = " ".join(unicodedata.normalize("NFKC", text(data["name"], "name")).casefold().split())
        status = text(data["status"], "status", maximum=80).casefold()
        since = _day(data["valid_from"]) if data.get("valid_from") else None
        until = _day(data["valid_to"]) if data.get("valid_to") else None
        if since and until and until <= since:
            raise ValueError("Corporate validity interval is reversed")
        active = (since is None or since <= ctx.as_of) and (until is None or ctx.as_of < until)
        return {"jurisdiction": jurisdiction, "registry_id": registry_id, "normalized_name": name,
                "asserted_status": status, "applicable_at_snapshot": active}
    rows = _rows(ctx, parse)
    groups = defaultdict(list)
    for record, item in rows:
        if item["applicable_at_snapshot"]:
            groups[(item["jurisdiction"], item["registry_id"])].append((record, item))
    conflicts = 0
    for identity, items in groups.items():
        if len({item["asserted_status"] for _, item in items}) > 1:
            conflicts += 1
            ctx.finding("corporate_status_conflict", "Applicable registry records assert different corporate statuses.",
                        [record.record_id for record, _ in items], {"jurisdiction": identity[0], "registry_id": identity[1]})
    return _finish(ctx, rows, "corporate_registry_record", "corporations", {"status_conflicts": conflicts},
                   ("Normalized names are search keys; matching names alone do not resolve entity identity.",))


def orgint(ctx: AnalysisContext):
    """Build supplied organizational reporting graphs and identify hierarchy cycles."""
    rows = _rows(ctx, lambda data: {
        "organization_id": text(data["organization_id"], "organization_id"),
        "unit_id": text(data["unit_id"], "unit_id"),
        "parent_unit_id": text(data["parent_unit_id"], "parent_unit_id") if data.get("parent_unit_id") else None,
        "staff_count": _out(_d(data["staff_count"], "staff_count", 0)) if "staff_count" in data else None})
    units, cycles = defaultdict(dict), []
    for record, item in rows:
        org, unit = item["organization_id"], item["unit_id"]
        if unit in units[org]:
            ctx.issue(record, "duplicate_org_unit", "Organizational unit identity repeats.")
        units[org].setdefault(unit, (record, item))
    for org, inventory in sorted(units.items()):
        done = set()
        for start in inventory:
            path, current = [], start
            while current is not None and current in inventory and current not in done:
                if current in path:
                    members = sorted(path[path.index(current):])
                    cycles.append({"organization_id": org, "unit_ids": members})
                    ctx.finding("organization_hierarchy_cycle", "The supplied reporting hierarchy contains a cycle.",
                                [inventory[unit][0].record_id for unit in members], cycles[-1])
                    break
                path.append(current)
                current = inventory[current][1]["parent_unit_id"]
            done.update(path)
            if current is not None and current not in inventory:
                ctx.issue(inventory[start][0], "unresolved_org_parent", "Reporting parent is absent from the supplied organization.")
    result = _finish(ctx, rows, "organization_unit", "units", {"hierarchy_cycles": len(cycles)})
    result["artifacts"]["cycles"] = cycles
    return result


def tradeint(ctx: AnalysisContext):
    """Aggregate declared trade flows by direction, commodity, currency and quantity unit."""
    def parse(data):
        direction = data["direction"]
        if direction not in {"IMPORT", "EXPORT"}:
            raise ValueError("Trade direction requires IMPORT or EXPORT")
        return {"flow_id": text(data["flow_id"], "flow_id"), "direction": direction,
                "commodity": text(data["commodity"], "commodity"),
                "origin": text(data["origin"], "origin"), "destination": text(data["destination"], "destination"),
                "currency": _currency(data["currency"]), "value": _out(_d(data["value"], "value", 0)),
                "quantity": _out(_d(data["quantity"], "quantity", 0)), "unit": text(data["unit"], "unit", maximum=80)}
    rows = _rows(ctx, parse)
    groups, seen, duplicates = defaultdict(lambda: [Decimal(0), Decimal(0), []]), {}, 0
    for record, item in rows:
        identity = item["flow_id"]
        if identity in seen:
            duplicates += 1
            if item != seen[identity][1]:
                ctx.issue(record, "trade_flow_conflict", "Repeated trade-flow ID has different data.")
            continue
        seen[identity] = (record, item)
        key = item["direction"], item["commodity"], item["currency"], item["unit"]
        groups[key][0] += Decimal(item["value"])
        groups[key][1] += Decimal(item["quantity"])
        groups[key][2].append(record.record_id)
    aggregates = [{"direction": key[0], "commodity": key[1], "currency": key[2], "unit": key[3],
                   "value": _out(values[0]), "quantity": _out(values[1]), "record_ids": values[2]}
                  for key, values in sorted(groups.items())]
    result = _finish(ctx, rows, "trade_flow_record", "flows", {"unique_flows": len(seen), "duplicate_ids": duplicates},
                     ("Trade values are not converted across currencies or units; supplied flows need not cover a market.",))
    result["artifacts"]["aggregates"] = aggregates
    return result


def jobint(ctx: AnalysisContext):
    """Deduplicate job postings and summarize declared skill demand and comparable pay ranges."""
    def parse(data):
        low, high = _d(data["pay_min"], "pay_min", 0), _d(data["pay_max"], "pay_max", 0)
        if high < low:
            raise ValueError("Pay range is reversed")
        skills = sorted({text(value, "skill", maximum=120).casefold() for value in _list(data, "skills")})
        return {"posting_id": text(data["posting_id"], "posting_id"), "employer_id": text(data["employer_id"], "employer_id"),
                "role": text(data["role"], "role").casefold(), "skills": skills,
                "currency": _currency(data["currency"]), "pay_period": text(data["pay_period"], "pay_period"),
                "pay_min": _out(low), "pay_max": _out(high)}
    rows, unique = _rows(ctx, parse), {}
    for record, item in rows:
        identity = item["employer_id"], item["posting_id"]
        if identity in unique and unique[identity][1] != item:
            ctx.issue(record, "job_posting_conflict", "Repeated posting identity has different supplied fields.")
        unique.setdefault(identity, (record, item))
    counts = Counter(skill for _, item in unique.values() for skill in item["skills"])
    result = _finish(ctx, rows, "job_posting_profile", "postings", {"unique_postings": len(unique)},
                     ("Posting counts are not workforce headcounts, hiring outcomes or verified job offers.",))
    result["artifacts"]["declared_skill_counts"] = dict(sorted(counts.items()))
    return result


def ownershipint(ctx: AnalysisContext):
    """Calculate declared direct ownership totals and bounded multiplicative ownership paths."""
    def parse(data):
        percent = _d(data["percent"], "percent", 0)
        if percent > 100:
            raise ValueError("Ownership percentage exceeds 100")
        return {"owner_id": text(data["owner_id"], "owner_id"), "entity_id": text(data["entity_id"], "entity_id"),
                "percent": _out(percent), "share_class": text(data.get("share_class", "ordinary"), "share_class"),
                "voting_rights": _bool(data, "voting_rights")}
    rows = _rows(ctx, parse)
    totals, adjacency = defaultdict(Decimal), defaultdict(list)
    for record, item in rows:
        totals[(item["entity_id"], item["share_class"])] += Decimal(item["percent"])
        adjacency[item["owner_id"]].append((record, item))
    for identity, total in totals.items():
        if total > 100:
            refs = [record.record_id for record, item in rows if (item["entity_id"], item["share_class"]) == identity]
            ctx.finding("ownership_total_exceeds_100", "Supplied ownership percentages exceed 100 in one declared share class.",
                        refs, {"entity_id": identity[0], "share_class": identity[1], "total_percent": _out(total)})
    paths, cycles, budget = [], set(), 0
    with localcontext() as context:
        context.prec = 60
        for origin in sorted(adjacency):
            stack = [(origin, (), Decimal(1), (origin,))]
            while stack:
                node, refs, fraction, members = stack.pop()
                for record, item in adjacency.get(node, []):
                    budget += 1
                    if budget > 5000:
                        ctx.issue(None, "ownership_path_budget", "Ownership path enumeration reached its bounded budget.")
                        stack.clear()
                        break
                    target = item["entity_id"]
                    if target in members:
                        cycles.add(tuple(sorted(members[members.index(target):])))
                        continue
                    new_fraction = fraction * Decimal(item["percent"]) / 100
                    new_refs = refs + (record.record_id,)
                    if len(new_refs) > 1 and len(paths) < 200:
                        paths.append({"origin_id": origin, "entity_id": target, "path_fraction": _out(new_fraction),
                                      "record_ids": list(new_refs), "control_inferred": False})
                    if len(new_refs) < 12:
                        stack.append((target, new_refs, new_fraction, members + (target,)))
            if budget > 5000:
                break
    result = _finish(ctx, rows, "declared_ownership_edge", "ownership_edges",
                     {"enumerated_paths": len(paths), "cycles": len(cycles), "traversal_steps": budget},
                     ("Path products describe declared stakes only; cycles, share classes, voting agreements and overlapping paths prevent automatic beneficial-control attribution.",))
    result["artifacts"].update({"indirect_paths": paths, "cycles": [list(cycle) for cycle in sorted(cycles)]})
    return result


def procurementint(ctx: AnalysisContext):
    """Compare published bid records within exact tenders and currencies."""
    def parse(data):
        deadline = _day(data["deadline"])
        submitted = instant(data["submitted_at"])
        return {"tender_id": text(data["tender_id"], "tender_id"), "bid_id": text(data["bid_id"], "bid_id"),
                "vendor_id": text(data["vendor_id"], "vendor_id"), "currency": _currency(data["currency"]),
                "amount": _out(_d(data["amount"], "amount", 0)), "late_under_declared_deadline": submitted > deadline,
                "awarded": _bool(data, "awarded")}
    rows, groups = _rows(ctx, parse), defaultdict(list)
    for record, item in rows:
        groups[(item["tender_id"], item["currency"])].append((record, item))
    comparisons = []
    for key, items in sorted(groups.items()):
        unique = {}
        for record, item in items:
            if item["bid_id"] in unique:
                ctx.issue(record, "duplicate_bid_identity", "Bid identity repeats; price comparison is unresolved.")
            unique.setdefault(item["bid_id"], (record, item))
        minimum = min(Decimal(item["amount"]) for _, item in unique.values())
        comparisons.append({"tender_id": key[0], "currency": key[1], "minimum_supplied_bid": _out(minimum),
                            "unique_bids": len(unique)})
        for record, item in unique.values():
            if item["awarded"] is True and Decimal(item["amount"]) > minimum:
                ctx.finding("award_above_supplied_minimum", "Declared award amount exceeds another supplied bid in the same currency.",
                            [record.record_id] + [r.record_id for r, i in unique.values() if Decimal(i["amount"]) == minimum],
                            {"tender_id": key[0], "difference": _out(Decimal(item["amount"]) - minimum)})
    result = _finish(ctx, rows, "procurement_bid", "bids",
                     limitations=("Price alone does not decide lawful procurement, bid qualification or fraud; date-only deadlines mean UTC midnight and must be supplied precisely for time-sensitive use.",))
    result["artifacts"]["tender_comparisons"] = comparisons
    return result


def contractint(ctx: AnalysisContext):
    """Check supplied contract intervals, milestone coverage and payment arithmetic."""
    def parse(data):
        start, end = _day(data["starts_at"]), _day(data["ends_at"])
        if end <= start:
            raise ValueError("Contract end must follow its start")
        total, payments = _d(data["amount"], "amount", 0), []
        for payment in _list(data, "payments"):
            stamp = _day(payment["due_at"])
            payments.append({"due_at": stamp.isoformat(), "amount": _out(_d(payment["amount"], "payment", 0)),
                             "outside_term": not start <= stamp <= end})
        paid = sum((Decimal(value["amount"]) for value in payments), Decimal(0))
        return {"contract_id": text(data["contract_id"], "contract_id"), "currency": _currency(data["currency"]),
                "amount": _out(total), "payment_schedule_total": _out(paid), "schedule_difference": _out(paid - total),
                "starts_at": start.isoformat(), "ends_at": end.isoformat(),
                "in_term_at_snapshot": start <= ctx.as_of <= end, "payments": payments}
    return _finish(ctx, _rows(ctx, parse), "contract_schedule_check", "contracts",
                   limitations=("The payment schedule is supplied; enforceability, actual payment and contract performance were not verified.",))


def _address(data):
    components = data["components"]
    if not isinstance(components, dict) or not components:
        raise ValueError("Address requires structured components")
    allowed = {"line1", "line2", "city", "region", "postal_code", "country"}
    if set(components) - allowed:
        raise ValueError("Unknown address component")
    normalized = {key: " ".join(unicodedata.normalize("NFKC", text(value, "address component")).casefold().split())
                  for key, value in components.items()}
    return {"address_id": text(data["address_id"], "address_id"), "normalized_components": normalized,
            "complete_for_declared_minimum": all(normalized.get(key) for key in ("line1", "city", "country")),
            "geocoded": False}


def addressint(ctx: AnalysisContext):
    """Normalize structured address components and identify exact normalized duplicates."""
    rows, groups = _rows(ctx, _address), defaultdict(list)
    for record, item in rows:
        groups[canonical(item["normalized_components"])].append((record, item))
    duplicates = 0
    for items in groups.values():
        if len(items) > 1:
            duplicates += 1
            ctx.finding("normalized_address_match", "Supplied structured addresses normalize to the same components.",
                        [record.record_id for record, _ in items],
                        {"address_ids": [item["address_id"] for _, item in items], "same_occupant_inferred": False})
    return _finish(ctx, rows, "address_normalization", "addresses", {"duplicate_groups": duplicates},
                   ("Normalization does not establish delivery validity, location, shared occupants or residence.",))


def propertyint(ctx: AnalysisContext):
    """Reconcile parcel-scoped title assertions and declared valuations without name-only joins."""
    def parse(data):
        return {"jurisdiction": text(data["jurisdiction"], "jurisdiction"), "parcel_id": text(data["parcel_id"], "parcel_id"),
                "title_id": text(data["title_id"], "title_id"), "owner_id": text(data["owner_id"], "owner_id"),
                "valuation": _out(_d(data["valuation"], "valuation", 0)), "currency": _currency(data["currency"])}
    rows, groups = _rows(ctx, parse), defaultdict(list)
    for record, item in rows:
        groups[(item["jurisdiction"], item["parcel_id"], item["title_id"])].append((record, item))
    conflicts = 0
    for key, items in groups.items():
        if len({item["owner_id"] for _, item in items}) > 1:
            conflicts += 1
            ctx.finding("property_title_owner_conflict", "The same declared parcel/title identity names different owners.",
                        [record.record_id for record, _ in items], {"jurisdiction": key[0], "parcel_id": key[1], "title_id": key[2]})
    return _finish(ctx, rows, "property_title_assertion", "properties", {"title_owner_conflicts": conflicts},
                   ("Title records can be historical or joint interests; no ownership verdict or property appraisal is produced.",))


def assetint(ctx: AnalysisContext):
    """Compute declared straight-line carrying values and reconcile asset serial identities."""
    def parse(data):
        cost, salvage = _d(data["cost"], "cost", 0), _d(data["salvage"], "salvage", 0)
        life, elapsed = _d(data["useful_life_years"], "useful_life", 0), _d(data["elapsed_years"], "elapsed_years", 0)
        if life == 0 or salvage > cost:
            raise ValueError("Useful life must be positive and salvage cannot exceed cost")
        carrying = cost - (cost - salvage) * min(elapsed, life) / life
        return {"asset_id": text(data["asset_id"], "asset_id"), "serial_id": text(data["serial_id"], "serial_id"),
                "currency": _currency(data["currency"]), "cost": _out(cost), "salvage": _out(salvage),
                "carrying_value_under_declared_model": _out(carrying), "model": "SUPPLIED_STRAIGHT_LINE"}
    with localcontext() as context:
        context.prec = 60
        rows = _rows(ctx, parse)
    serials = defaultdict(list)
    for record, item in rows:
        serials[item["serial_id"]].append((record, item))
    duplicates = 0
    for serial, items in serials.items():
        if len({item["asset_id"] for _, item in items}) > 1:
            duplicates += 1
            ctx.finding("asset_serial_collision", "Different supplied asset IDs share a declared serial identity.",
                        [record.record_id for record, _ in items], {"serial_id": serial})
    return _finish(ctx, rows, "asset_model_calculation", "assets", {"serial_collisions": duplicates},
                   ("Carrying value is arithmetic under submitted assumptions, not a tax treatment, market value or accounting advice.",))


def taxint(ctx: AnalysisContext):
    """Recalculate supplied tax line arithmetic with explicitly declared rates and rounding."""
    def parse(data):
        rounding = data.get("decimal_places", 2)
        if type(rounding) is not int or not 0 <= rounding <= 6:
            raise ValueError("decimal_places outside 0-6")
        rows, total = [], Decimal(0)
        quantum = Decimal(1).scaleb(-rounding)
        for line in _list(data, "lines"):
            base, rate = _d(line["base"], "base"), _d(line["rate_fraction"], "rate", 0)
            if rate > 1:
                raise ValueError("Supplied fractional rate exceeds 1")
            computed = (base * rate).quantize(quantum)
            declared = _d(line["declared_tax"], "declared_tax")
            total += computed
            rows.append({"line_id": text(line["line_id"], "line_id"), "computed": _out(computed),
                         "declared": _out(declared), "difference": _out(declared - computed)})
        return {"statement_id": text(data["statement_id"], "statement_id"), "currency": _currency(data["currency"]),
                "lines": rows, "computed_total": _out(total), "rounding": "ROUND_HALF_EVEN",
                "law_or_rate_applicability_verified": False}
    with localcontext() as context:
        context.prec = 60
        rows = _rows(ctx, parse)
    return _finish(ctx, rows, "supplied_tax_arithmetic", "tax_statements",
                   limitations=("Only user-supplied rates and half-even decimal rounding are recalculated; no jurisdiction's tax law, liabilities or filing correctness is assessed.",))


def insolvencyint(ctx: AnalysisContext):
    """Order supplied proceeding events and flag simultaneous incompatible status assertions."""
    def parse(data):
        stamp = _day(data["event_at"])
        if stamp > ctx.as_of:
            raise ValueError("Proceeding event follows snapshot")
        status = text(data["status"], "status", maximum=80)
        return {"proceeding_id": text(data["proceeding_id"], "proceeding_id"), "entity_id": text(data["entity_id"], "entity_id"),
                "jurisdiction": text(data["jurisdiction"], "jurisdiction"), "event_at": stamp.isoformat(), "asserted_status": status}
    rows, groups = _rows(ctx, parse), defaultdict(list)
    for record, item in rows:
        groups[(item["jurisdiction"], item["proceeding_id"])].append((record, item))
    latest, conflicts = [], 0
    for key, items in sorted(groups.items()):
        last_time = max(item["event_at"] for _, item in items)
        selected = [(record, item) for record, item in items if item["event_at"] == last_time]
        states = sorted({item["asserted_status"] for _, item in selected})
        if len(states) > 1:
            conflicts += 1
            ctx.finding("proceeding_status_conflict", "Latest supplied proceeding events assert different statuses.",
                        [record.record_id for record, _ in selected], {"proceeding_id": key[1], "statuses": states})
        latest.append({"jurisdiction": key[0], "proceeding_id": key[1], "latest_observed_statuses": states, "at": last_time})
    result = _finish(ctx, rows, "proceeding_event", "proceedings", {"latest_status_conflicts": conflicts},
                     ("Latest in the supplied set does not establish current insolvency, liability or proceeding outcome.",))
    result["artifacts"]["latest_supplied_events"] = latest
    return result


def mnaint(ctx: AnalysisContext):
    """Order declared acquisition milestones and distinguish announced from completed deals."""
    stages = {"ANNOUNCED": 0, "APPROVED": 1, "CLOSED": 2, "TERMINATED": 3}
    def parse(data):
        stage = data["stage"]
        if stage not in stages:
            raise ValueError("Unknown transaction milestone")
        stamp = _day(data["at"])
        if stamp > ctx.as_of:
            raise ValueError("Transaction milestone follows snapshot")
        stake = _d(data["stake_percent"], "stake_percent", 0)
        if stake > 100:
            raise ValueError("Transaction stake exceeds 100")
        return {"deal_id": text(data["deal_id"], "deal_id"), "acquirer_id": text(data["acquirer_id"], "acquirer_id"),
                "target_id": text(data["target_id"], "target_id"), "stage": stage, "at": stamp.isoformat(),
                "stake_percent": _out(stake)}
    rows, groups = _rows(ctx, parse), defaultdict(list)
    for record, item in rows:
        groups[item["deal_id"]].append((record, item))
    reversals = 0
    for deal, items in groups.items():
        ordered = sorted(items, key=lambda row: row[1]["at"])
        for before, after in zip(ordered, ordered[1:]):
            if stages[after[1]["stage"]] < stages[before[1]["stage"]]:
                reversals += 1
                ctx.finding("transaction_milestone_reversal", "Supplied transaction milestones reverse the declared stage progression.",
                            [before[0].record_id, after[0].record_id], {"deal_id": deal})
    return _finish(ctx, rows, "acquisition_milestone", "transactions", {"stage_reversals": reversals},
                   ("Announcements and approvals are distinct from asserted closing; deal identity, conditions and completion remain unverified.",))


def marketint(ctx: AnalysisContext):
    """Compute supplied market shares and concentration only within comparable currency/period cells."""
    def parse(data):
        return {"seller_id": text(data["seller_id"], "seller_id"), "market_id": text(data["market_id"], "market_id"),
                "period": text(data["period"], "period"), "currency": _currency(data["currency"]),
                "revenue": _out(_d(data["revenue"], "revenue", 0))}
    rows, groups = _rows(ctx, parse), defaultdict(list)
    for record, item in rows:
        groups[(item["market_id"], item["period"], item["currency"])].append((record, item))
    shares = []
    with localcontext() as context:
        context.prec = 60
        for key, items in sorted(groups.items()):
            sellers = defaultdict(Decimal)
            for _, item in items:
                sellers[item["seller_id"]] += Decimal(item["revenue"])
            total = sum(sellers.values(), Decimal(0))
            values = {seller: value / total if total else None for seller, value in sorted(sellers.items())}
            shares.append({"market_id": key[0], "period": key[1], "currency": key[2],
                           "supplied_revenue_total": _out(total), "fraction_by_seller": {k: _out(v) for k, v in values.items()},
                           "hhi_0_10000": _out(sum((value * 100) ** 2 for value in values.values())) if total else None,
                           "population_coverage_verified": False})
    result = _finish(ctx, rows, "market_sales_cell", "sales",
                     limitations=("Concentration describes supplied rows; duplicate/revised revenue must be reconciled and no legal market-power conclusion follows.",))
    result["artifacts"]["shares"] = shares
    return result


def competitorint(ctx: AnalysisContext):
    """Compare declared product feature sets within a supplied comparison cohort."""
    def parse(data):
        return {"product_id": text(data["product_id"], "product_id"), "cohort_id": text(data["cohort_id"], "cohort_id"),
                "features": sorted({text(value, "feature", maximum=120).casefold() for value in _list(data, "features")})}
    rows, comparisons = _rows(ctx, parse), []
    for index, (left_record, left) in enumerate(rows):
        for right_record, right in rows[index+1:]:
            if left["cohort_id"] != right["cohort_id"]:
                continue
            a, b = set(left["features"]), set(right["features"])
            if len(comparisons) >= 200:
                ctx.issue(None, "competitor_pair_budget", "Comparison artifact reached its 200-pair budget.")
                break
            comparisons.append({"left_product": left["product_id"], "right_product": right["product_id"],
                                "common_features": sorted(a & b), "left_only": sorted(a - b), "right_only": sorted(b - a),
                                "jaccard": len(a & b) / len(a | b) if a | b else None,
                                "record_ids": [left_record.record_id, right_record.record_id]})
    result = _finish(ctx, rows, "product_feature_inventory", "products",
                     limitations=("Declared features and cohort membership do not verify quality, equivalence, competitiveness or purchasing suitability.",))
    result["artifacts"]["comparisons"] = comparisons
    return result


def customerint(ctx: AnalysisContext):
    """Calculate declared-period customer retention and currency-separated revenue cohorts."""
    def parse(data):
        revenue = _d(data["revenue"], "revenue", 0)
        return {"customer_id": text(data["customer_id"], "customer_id"), "period": text(data["period"], "period"),
                "currency": _currency(data["currency"]), "revenue": _out(revenue)}
    rows, cells = _rows(ctx, parse), defaultdict(dict)
    try:
        periods = _list(ctx.parameters, "ordered_periods")
    except ValueError:
        ctx.issue(None, "customer_period_order_required", "Supply ordered_periods for temporal cohort comparisons.")
        periods = []
    if any(not isinstance(period, str) or not period for period in periods) or len(set(periods)) != len(periods):
        ctx.issue(None, "invalid_customer_period_order", "ordered_periods requires unique nonempty period IDs.")
        periods = []
    for record, item in rows:
        key = item["period"], item["currency"]
        customer = item["customer_id"]
        if customer in cells[key]:
            ctx.issue(record, "duplicate_customer_period", "Repeated customer/currency/period requires reconciliation.")
            continue
        cells[key][customer] = Decimal(item["revenue"])
    cohorts = []
    for before, after in zip(periods, periods[1:]):
        for currency in sorted({key[1] for key in cells}):
            left, right = cells[(before, currency)], cells[(after, currency)]
            original = sum(left.values(), Decimal(0))
            retained = sum((right.get(customer, Decimal(0)) for customer in left), Decimal(0))
            cohorts.append({"before_period": before, "after_period": after, "currency": currency,
                            "baseline_customers": len(left), "retained_customers": len(set(left) & set(right)),
                            "lost_customers": len(set(left) - set(right)), "new_customers": len(set(right) - set(left)),
                            "customer_retention_fraction": _out(Decimal(len(set(left) & set(right))) / len(left)) if left else None,
                            "net_revenue_retention": _out(retained / original) if original else None})
    result = _finish(ctx, rows, "customer_period_record", "customers",
                     limitations=("Absence from supplied rows is missing coverage as well as a possible departure; retention is conditional on cohort completeness.",))
    result["artifacts"]["cohorts"] = cohorts
    return result


HANDLERS = {
    "FININT": finint, "CORPINT": corpint, "ORGINT": orgint, "TRADEINT": tradeint, "JOBINT": jobint,
    "OWNERSHIPINT": ownershipint, "PROCUREMENTINT": procurementint, "CONTRACTINT": contractint,
    "ADDRESSINT": addressint, "PROPERTYINT": propertyint, "ASSETINT": assetint, "TAXINT": taxint,
    "INSOLVENCYINT": insolvencyint, "MNAINT": mnaint, "MARKETINT": marketint,
    "COMPETITORINT": competitorint, "CUSTOMERINT": customerint,
}


def _precision(handler):
    @wraps(handler)
    def analyze(ctx):
        with localcontext() as context:
            context.prec = 80
            return handler(ctx)
    return analyze


HANDLERS = {label: _precision(handler) for label, handler in HANDLERS.items()}
