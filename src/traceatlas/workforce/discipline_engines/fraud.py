"""Twelve dedicated fraud/exposure record analyzers with no guilt verdicts."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, localcontext
import hashlib
import json
import math
import re
import unicodedata
from urllib.parse import urlsplit

from .common import AnalysisContext

LIMITATIONS = (
    "Only supplied records were analyzed; authenticity, intent, criminality and external state remain unverified.",
    "No credential use or extraction, account access, payment execution, blockchain requests or external collection occurred.",
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


def _text(ctx, record, key, required=True):
    value = record.data.get(key)
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip():
        ctx.issue(record, "INVALID_FIELD", key + " requires nonempty text")
        return None
    return value.strip()


def _strings(ctx, record, key):
    values = record.data.get(key, [])
    if not isinstance(values, list) or any(not isinstance(value, str) or not value.strip() for value in values):
        ctx.issue(record, "INVALID_ARRAY", key + " requires an array of nonempty strings")
        return []
    return list(dict.fromkeys(value.strip() for value in values))


def _moment(ctx, record, key, required=False):
    value = record.data.get(key)
    if value is None:
        if required:
            ctx.issue(record, "TIMESTAMP_MISSING", key + " is required")
        return None
    try:
        if not isinstance(value, str):
            raise ValueError()
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None or result.utcoffset() is None:
            raise ValueError()
        return result.astimezone(timezone.utc)
    except ValueError:
        ctx.issue(record, "INVALID_TIMESTAMP", key + " requires an ISO timestamp with timezone")
        return None


def _amount(ctx, record, key="amount", max_scale=8):
    value = record.data.get(key)
    try:
        if isinstance(value, bool) or not isinstance(value, (int, float, str)):
            raise ValueError()
        if isinstance(value, str) and (len(value) > 80 or not re.fullmatch(r"[0-9]+(?:\.[0-9]{1," + str(max_scale) + r"})?", value)):
            raise ValueError()
        result = Decimal(str(value))
        if not result.is_finite() or result < 0 or result > Decimal("1e30") or result.as_tuple().exponent < -max_scale:
            raise ValueError()
        return result
    except (InvalidOperation, ValueError):
        ctx.issue(record, "INVALID_AMOUNT", key + " requires a finite nonnegative decimal amount")
        return None



def _sum(values):
    with localcontext() as context:
        context.prec = 96
        return sum(values, Decimal(0))


def _difference(left, right):
    with localcontext() as context:
        context.prec = 96
        return left - right


def _ratio(left, right):
    with localcontext() as context:
        context.prec = 96
        return left / right


def _median(values):
    values = sorted(values)
    center = len(values) // 2
    return values[center] if len(values) % 2 else _ratio(_sum((values[center - 1], values[center])), Decimal(2))


def _currency(ctx, record):
    value = _text(ctx, record, "currency")
    if value and not re.fullmatch(r"[A-Za-z]{3}", value):
        ctx.issue(record, "INVALID_CURRENCY", "currency requires a three-letter code")
        return None
    return value.upper() if value else None


def _param(ctx, key, default, low, high):
    value = ctx.parameters.get(key, default)
    if type(value) not in (int, float) or not math.isfinite(value) or not low <= value <= high:
        ctx.issue(None, "INVALID_PARAMETER", key + " is outside its allowed analysis range")
        return default
    return value


def _hash(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _norm(value):
    return " ".join(unicodedata.normalize("NFKC", value).casefold().split())


def _finish(ctx, metrics=None, artifacts=None, extra=()):
    return ctx.output(metrics=metrics or {}, artifacts=artifacts or {}, limitations=(*LIMITATIONS, *extra))


def exposureint(ctx: AnalysisContext):
    groups = _groups(ctx, {"exposure"}, "exposure")
    snapshots, inventory = defaultdict(list), []
    for record in groups["exposure"]:
        asset, snapshot = _text(ctx, record, "asset_id"), _text(ctx, record, "snapshot_id")
        visibility = record.data.get("visibility")
        auth = record.data.get("authentication_required")
        classes = _strings(ctx, record, "sensitive_classes")
        if not isinstance(visibility, str) or visibility not in {"PUBLIC", "PRIVATE", "UNKNOWN"}:
            ctx.issue(record, "INVALID_VISIBILITY", "visibility must be PUBLIC, PRIVATE, or UNKNOWN")
            continue
        if auth is not None and not isinstance(auth, bool):
            ctx.issue(record, "INVALID_AUTH_FLAG", "authentication_required must be true or false")
            auth = None
        if not asset or not snapshot:
            continue
        snapshots[(asset, snapshot)].append((record, visibility))
        inventory.append({"record_id": record.record_id, "asset_id": asset, "snapshot_id": snapshot,
                          "visibility": visibility, "authentication_required": auth, "sensitive_classes": classes})
        if visibility == "PUBLIC" and auth is False and classes:
            ctx.finding("PUBLIC_SENSITIVE_RESOURCE_DECLARED", "A supplied snapshot declares a public resource without authentication and with sensitive data classes",
                        [record.record_id], {"asset_id": asset, "snapshot_id": snapshot, "sensitive_classes": classes})
        elif visibility == "PUBLIC" and auth is None:
            ctx.issue(record, "EXPOSURE_AUTH_UNKNOWN", "Public visibility does not establish authentication requirements")
    for (asset, snapshot), rows in snapshots.items():
        if {"PUBLIC", "PRIVATE"} <= {visibility for _, visibility in rows}:
            ctx.finding("EXPOSURE_SNAPSHOT_VISIBILITY_CONFLICT", "The same declared asset snapshot has public and private visibility labels",
                        [record.record_id for record, _ in rows], {"asset_id": asset, "snapshot_id": snapshot})
    return _finish(ctx, {"exposure_records": len(inventory), "asset_snapshots": len(snapshots)},
                   {"supplied_exposure_inventory": inventory},
                   ("A declared exposure candidate does not prove internet reachability, sensitive content, or unauthorized access.",))


def breachint(ctx: AnalysisContext):
    groups = _groups(ctx, {"notice"}, "notice")
    incidents, notices = defaultdict(list), []
    for record in groups["notice"]:
        notice, organization, incident = (_text(ctx, record, key) for key in ("notice_id", "organization_id", "incident_id"))
        disclosed = _moment(ctx, record, "disclosed_at", required=True)
        start, end = _moment(ctx, record, "incident_start"), _moment(ctx, record, "incident_end")
        affected = record.data.get("affected_records")
        if affected is not None and (type(affected) is not int or affected < 0):
            ctx.issue(record, "INVALID_AFFECTED_COUNT", "affected_records must be a nonnegative integer")
            affected = None
        if start and end and end < start:
            ctx.issue(record, "BREACH_INTERVAL_INVALID", "incident_end precedes incident_start")
            continue
        if not notice or not organization or not incident or disclosed is None:
            continue
        anchor = end or start
        lag = (disclosed - anchor).total_seconds() / 86400 if anchor else None
        if lag is not None and lag < 0:
            ctx.issue(record, "NOTICE_PRECEDES_INCIDENT_ANCHOR", "Disclosure precedes the supplied incident timing anchor")
        if disclosed > ctx.as_of:
            ctx.issue(record, "FUTURE_DISCLOSURE", "Notice disclosure lies after analysis time")
        item = {"record_id": record.record_id, "notice_id": notice, "organization_id": organization,
                "incident_id": incident, "affected_records_claimed": affected, "reporting_lag_days": lag,
                "data_classes_claimed": _strings(ctx, record, "data_classes")}
        incidents[(organization, incident)].append(item)
        notices.append(item)
    for (organization, incident), rows in incidents.items():
        if len({row["affected_records_claimed"] for row in rows if row["affected_records_claimed"] is not None}) > 1:
            ctx.finding("BREACH_NOTICE_SCOPE_VARIATION", "Supplied notices for one declared incident report different affected-record counts",
                        [row["record_id"] for row in rows], {"organization_id": organization, "incident_id": incident})
    return _finish(ctx, {"notice_records": len(notices), "declared_incidents": len(incidents)},
                   {"notice_metadata": notices},
                   ("Counts are notice claims and are never summed across potentially overlapping notices; no leaked records were obtained or searched.",))


def _secret_keys(value):
    pending = [value]
    forbidden = {"password", "secret", "token", "private_key", "seed_phrase", "recovery_codes", "api_key"}
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            if any(key.casefold().replace("-", "_") in forbidden for key in item):
                return True
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    return False


def credint(ctx: AnalysisContext):
    groups = _groups(ctx, {"credential_metadata"}, "credential_metadata")
    fingerprints, inventory = defaultdict(list), []
    max_age = _param(ctx, "rotation_max_age_days", 90, 1, 3650)
    for record in groups["credential_metadata"]:
        if _secret_keys(record.data):
            ctx.issue(record, "SECRET_MATERIAL_REJECTED", "This analyzer accepts metadata only; secret-bearing records are not processed")
            continue
        credential, account = _text(ctx, record, "credential_id"), _text(ctx, record, "account_id")
        digest = _text(ctx, record, "credential_sha256", required=False)
        if digest and not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            ctx.issue(record, "CREDENTIAL_FINGERPRINT_INVALID", "credential_sha256 requires a supplied SHA-256 fingerprint")
            digest = None
        rotated, expires = _moment(ctx, record, "last_rotated_at"), _moment(ctx, record, "expires_at")
        if not credential or not account:
            continue
        token = _hash(digest.lower()) if digest else None
        age = (ctx.as_of - rotated).total_seconds() / 86400 if rotated else None
        if age is not None and age < 0:
            ctx.issue(record, "FUTURE_CREDENTIAL_ROTATION", "Rotation timestamp lies after analysis time")
        elif age is not None and age > max_age:
            ctx.finding("CREDENTIAL_ROTATION_AGE_EXCEEDED", "Supplied rotation metadata exceeds the stated age threshold",
                        [record.record_id], {"credential_id": credential, "age_days": age, "threshold_days": max_age})
        if expires and expires < ctx.as_of:
            ctx.finding("CREDENTIAL_METADATA_EXPIRED", "A supplied credential expiry timestamp precedes analysis time",
                        [record.record_id], {"credential_id": credential})
        if token:
            fingerprints[token].append((record, account))
        inventory.append({"record_id": record.record_id, "credential_id": credential, "account_id": account,
                          "fingerprint_token": token, "rotation_age_days": age, "validity_verified": False})
    for token, rows in fingerprints.items():
        if len({account for _, account in rows}) > 1:
            ctx.finding("SHARED_CREDENTIAL_METADATA_FINGERPRINT", "Different supplied accounts share a credential fingerprint",
                        [record.record_id for record, _ in rows], {"fingerprint_token": token})
    return _finish(ctx, {"metadata_records": len(inventory), "fingerprint_groups": len(fingerprints)},
                   {"credential_metadata_inventory": inventory},
                   ("No passwords, tokens, private keys or recovery phrases were extracted, tested, recovered or validated.",))


def fraudint(ctx: AnalysisContext):
    groups = _groups(ctx, {"transaction", "reversal"}, "transaction")
    transactions, ambiguous, reversals, by_currency = {}, set(), defaultdict(list), defaultdict(list)
    for record in groups["transaction"]:
        transaction = _text(ctx, record, "transaction_id")
        amount, currency = _amount(ctx, record), _currency(ctx, record)
        if not transaction or amount is None or not currency:
            continue
        if transaction in transactions:
            previous, previous_amount, previous_currency = transactions[transaction]
            if (previous_amount, previous_currency, previous.data.get("account_id"), previous.data.get("payee_id")) != (amount, currency, record.data.get("account_id"), record.data.get("payee_id")):
                ambiguous.add(transaction)
                ctx.finding("TRANSACTION_ID_VALUE_CONFLICT", "One supplied transaction ID has conflicting amount or currency",
                            [previous.record_id, record.record_id], {"transaction_id": transaction})
        else:
            transactions[transaction] = record, amount, currency
    for transaction, row in transactions.items():
        if transaction not in ambiguous:
            by_currency[row[2]].append((transaction, *row))
    for record in groups["reversal"]:
        transaction = _text(ctx, record, "transaction_id")
        amount, currency = _amount(ctx, record), _currency(ctx, record)
        if not transaction or amount is None or not currency:
            continue
        if transaction not in transactions or transaction in ambiguous:
            ctx.issue(record, "REVERSAL_TRANSACTION_UNRESOLVED", "Reversal references an absent or ambiguous supplied transaction")
        elif transactions[transaction][2] != currency:
            ctx.issue(record, "REVERSAL_CURRENCY_MISMATCH", "Reversal and transaction currencies differ")
        else:
            reversals[transaction].append((record, amount))
    for transaction, rows in reversals.items():
        original, amount, currency = transactions[transaction]
        total = _sum(value for _, value in rows)
        if total > amount:
            ctx.finding("REVERSALS_EXCEED_SUPPLIED_TRANSACTION", "Submitted reversal amounts exceed their supplied original transaction amount",
                        [original.record_id, *(record.record_id for record, _ in rows)],
                        {"transaction_id": transaction, "currency": currency, "original_amount": str(amount), "reversed_amount": str(total)})
    outliers = []
    multiplier = _param(ctx, "mad_multiplier", 6, 1, 100)
    for currency, rows in by_currency.items():
        values = [amount for _, _, amount, _ in rows]
        if len(values) < 5:
            continue
        center = _median(values)
        deviation = _median([_difference(value, center).copy_abs() for value in values])
        if deviation == 0:
            ctx.issue(None, "MAD_ZERO", "Robust outlier scoring is undefined when median absolute deviation is zero")
            continue
        for transaction, record, value, _ in rows:
            robust = _ratio(abs(_difference(value, center)), deviation)
            if robust > Decimal(str(multiplier)):
                outliers.append({"transaction_id": transaction, "currency": currency, "median_amount": str(center), "mad": str(deviation), "absolute_deviation_over_mad": str(robust)})
                ctx.finding("SUPPLIED_TRANSACTION_AMOUNT_OUTLIER", "A supplied amount exceeds the stated median-absolute-deviation threshold",
                            [record.record_id], {"transaction_id": transaction, "currency": currency, "absolute_deviation_over_mad": str(robust)})
    return _finish(ctx, {"unique_transaction_ids": len(transactions), "ambiguous_transaction_ids": len(ambiguous),
                         "reversal_groups": len(reversals), "amount_outliers": len(outliers)},
                   {"robust_amount_outliers": outliers, "amount_method": "DECIMAL_MEDIAN_ABSOLUTE_DEVIATION_WITHIN_CURRENCY"},
                   ("Ledger differences and statistical outliers are review candidates, not findings of fraud or criminality.",))


SCAM_PATTERNS = {
    "GUARANTEED_RETURN_CUE": r"\b(?:guaranteed (?:profit|return)|risk[- ]free investment|double your money)\b",
    "RECOVERY_SECRET_REQUEST_CUE": r"\b(?:send|share|provide|enter)\b.{0,40}\b(?:seed phrase|private key|recovery phrase|password)\b",
    "GIFT_CARD_PAYMENT_CUE": r"\b(?:pay|payment|purchase)\b.{0,40}\bgift cards?\b",
    "URGENT_PAYMENT_CUE": r"\b(?:pay now|immediate payment|final warning|account will be closed)\b",
}


def _domain(ctx, record, value, field):
    if not isinstance(value, str):
        ctx.issue(record, "DOMAIN_INVALID", field + " must be supplied domain text")
        return None
    try:
        parsed = urlsplit(value if "://" in value else "https://" + value)
        if not parsed.hostname or parsed.username or parsed.password or parsed.scheme not in {"http", "https"}:
            raise ValueError()
        domain = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        if len(domain) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in domain.split(".")):
            raise ValueError()
        return domain
    except (ValueError, UnicodeError):
        ctx.issue(record, "DOMAIN_INVALID", field + " contains an invalid or credential-bearing domain/URL")
        return None


def scamint(ctx: AnalysisContext):
    groups = _groups(ctx, {"message"}, "message")
    profiles, totals = [], Counter()
    for record in groups["message"]:
        text = _text(ctx, record, "text")
        if not text:
            continue
        cues = {}
        for label, pattern in SCAM_PATTERNS.items():
            count = len(re.findall(pattern, text, re.I))
            if count:
                cues[label] = count
                totals[label] += count
        expected_raw = record.data.get("expected_domain")
        expected = _domain(ctx, record, expected_raw, "expected_domain") if expected_raw is not None else None
        domains = []
        for url in _strings(ctx, record, "urls"):
            domain = _domain(ctx, record, url, "urls")
            if domain:
                domains.append(domain)
                if expected and domain != expected and not domain.endswith("." + expected):
                    ctx.finding("MESSAGE_LINK_OUTSIDE_DECLARED_DOMAIN", "A supplied message links outside its supplied expected domain namespace",
                                [record.record_id], {"expected_domain": expected, "linked_domain": domain})
        if cues:
            ctx.finding("SCAM_LEXICAL_CANDIDATE_SIGNALS", "Submitted text matches transparent financial/deception cue patterns",
                        [record.record_id], {"cue_counts": cues})
        profiles.append({"record_id": record.record_id, "cue_counts": cues, "supplied_link_domains": sorted(set(domains))})
    return _finish(ctx, {"message_records": len(profiles), "cue_totals": dict(totals)},
                   {"message_signal_profiles": profiles},
                   ("Cues and domain differences can occur in legitimate warnings, quotations or resellers; no scam verdict is issued.",))


def paymentint(ctx: AnalysisContext):
    groups = _groups(ctx, {"invoice", "payment"}, "invoice")
    invoices, payments, ambiguous_invoices, ambiguous_payments = {}, {}, set(), set()
    for record in groups["invoice"]:
        invoice = _text(ctx, record, "invoice_id")
        amount, currency = _amount(ctx, record), _currency(ctx, record)
        due = _moment(ctx, record, "due_at")
        if not invoice or amount is None or not currency:
            continue
        if invoice in invoices and invoices[invoice][1:3] != (amount, currency):
            ambiguous_invoices.add(invoice)
            ctx.finding("INVOICE_ID_VALUE_CONFLICT", "One supplied invoice ID has conflicting amount or currency",
                        [invoices[invoice][0].record_id, record.record_id], {"invoice_id": invoice})
        invoices.setdefault(invoice, (record, amount, currency, due))
    for record in groups["payment"]:
        payment, invoice = _text(ctx, record, "payment_id"), _text(ctx, record, "invoice_id")
        amount, currency = _amount(ctx, record), _currency(ctx, record)
        status = record.data.get("status")
        if not isinstance(status, str) or status not in {"SETTLED", "PENDING", "FAILED"}:
            ctx.issue(record, "PAYMENT_STATUS_INVALID", "status requires SETTLED, PENDING, or FAILED")
            continue
        if not payment or not invoice or amount is None or not currency:
            continue
        item = record, invoice, amount, currency, status
        if payment in payments and payments[payment][1:] != item[1:]:
            ambiguous_payments.add(payment)
            ctx.finding("PAYMENT_ID_VALUE_CONFLICT", "One supplied payment ID has conflicting reconciliation metadata",
                        [payments[payment][0].record_id, record.record_id], {"payment_id": payment})
        payments.setdefault(payment, item)
    matched = defaultdict(list)
    for payment, (record, invoice, amount, currency, status) in payments.items():
        if payment in ambiguous_payments:
            continue
        if invoice not in invoices or invoice in ambiguous_invoices:
            ctx.issue(record, "PAYMENT_INVOICE_UNRESOLVED", "Payment references an absent or ambiguous invoice")
        elif invoices[invoice][2] != currency:
            ctx.issue(record, "PAYMENT_CURRENCY_MISMATCH", "Payment and invoice currencies differ")
        elif status == "SETTLED":
            matched[invoice].append((record, amount))
    balances = []
    for invoice, (record, amount, currency, due) in invoices.items():
        if invoice in ambiguous_invoices:
            continue
        paid = _sum(value for _, value in matched[invoice])
        outstanding = _difference(amount, paid)
        balances.append({"invoice_id": invoice, "currency": currency, "invoice_amount": str(amount),
                         "settled_supplied_amount": str(paid), "outstanding_supplied_amount": str(outstanding)})
        if outstanding < 0:
            ctx.finding("SUPPLIED_INVOICE_OVERPAYMENT", "Submitted settled payments exceed the supplied invoice amount",
                        [record.record_id, *(payment.record_id for payment, _ in matched[invoice])],
                        {"invoice_id": invoice, "currency": currency, "overpayment_amount": str(outstanding.copy_negate())})
        elif outstanding > 0 and due and due < ctx.as_of:
            ctx.finding("SUPPLIED_INVOICE_PAST_DUE", "A supplied invoice has an unpaid balance after its declared due time",
                        [record.record_id], {"invoice_id": invoice, "outstanding_amount": str(outstanding), "currency": currency})
    return _finish(ctx, {"invoice_ids": len(invoices), "payment_ids": len(payments),
                         "reconciled_invoices": len(balances), "ambiguous_payment_ids": len(ambiguous_payments)},
                   {"invoice_reconciliation": balances, "amount_method": "DECIMAL_SETTLED_PAYMENTS_WITHIN_CURRENCY"},
                   ("Only submitted settled-payment labels are used; this is not bank reconciliation or payment confirmation.",))


def _crypto_address(ctx, record, chain, address):
    if not isinstance(address, str):
        ctx.issue(record, "CRYPTO_ADDRESS_INVALID", "Addresses must be supplied strings")
        return None
    if chain in {"ethereum", "evm"}:
        if re.fullmatch(r"0x[0-9a-fA-F]{40}", address):
            return address.lower()
    elif chain == "bitcoin":
        if re.fullmatch(r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}", address):
            return address
        if (address == address.lower() or address == address.upper()) and re.fullmatch(r"(?:bc1|tb1)[ac-hj-np-z02-9]{11,71}", address.lower()):
            return address.lower()
    else:
        ctx.issue(record, "CRYPTO_CHAIN_UNSUPPORTED", "This syntax analyzer supports supplied ethereum/evm/bitcoin namespaces")
        return None
    ctx.issue(record, "CRYPTO_ADDRESS_INVALID", "Address does not match the declared chain's supported syntax")
    return None


def cryptoint(ctx: AnalysisContext):
    groups = _groups(ctx, {"transfer"}, "transfer")
    transfers, ambiguous, balances, directed = {}, set(), defaultdict(lambda: Decimal(0)), defaultdict(list)
    for record in groups["transfer"]:
        chain, transfer, asset = _text(ctx, record, "chain"), _text(ctx, record, "transfer_id"), _text(ctx, record, "asset")
        amount = _amount(ctx, record, max_scale=18)
        if not chain or not transfer or not asset or amount is None:
            continue
        chain = chain.casefold()
        left = _crypto_address(ctx, record, chain, record.data.get("from_address"))
        right = _crypto_address(ctx, record, chain, record.data.get("to_address"))
        status = record.data.get("status")
        if not isinstance(status, str) or status not in {"CONFIRMED", "PENDING", "FAILED"}:
            ctx.issue(record, "CRYPTO_STATUS_UNKNOWN", "Supplied transfer status requires CONFIRMED, PENDING, or FAILED")
            continue
        instant = _moment(ctx, record, "timestamp")
        if not left or not right:
            continue
        key = chain, transfer
        item = record, left, right, asset, amount, status, instant
        if key in transfers and transfers[key][1:6] != item[1:6]:
            ambiguous.add(key)
            ctx.finding("CRYPTO_TRANSFER_ID_CONFLICT", "One supplied chain/transfer ID has different transfer metadata",
                        [transfers[key][0].record_id, record.record_id], {"chain": chain, "transfer_id": transfer})
        transfers.setdefault(key, item)
    for key, (record, left, right, asset, amount, status, instant) in transfers.items():
        if key in ambiguous or status != "CONFIRMED":
            continue
        chain = key[0]
        balances[(chain, asset, left)] = _difference(balances[(chain, asset, left)], amount)
        balances[(chain, asset, right)] = _sum((balances[(chain, asset, right)], amount))
        directed[(chain, asset, left, right, amount)].append((record, instant))
    window = _param(ctx, "reciprocal_window_seconds", 86400, 1, 31536000)
    reciprocal = []
    for (chain, asset, left, right, amount), rows in directed.items():
        if left >= right:
            continue
        for outbound, sent in rows:
            for inbound, returned in directed.get((chain, asset, right, left, amount), []):
                if sent is None or returned is None:
                    ctx.issue(outbound, "CRYPTO_RECIPROCITY_TIME_MISSING", "Reciprocal timing requires both supplied transfer timestamps")
                elif abs((returned - sent).total_seconds()) <= window:
                    if len(reciprocal) >= 100:
                        ctx.issue(None, "CRYPTO_RECIPROCAL_OUTPUT_LIMIT", "Only the first 100 reciprocal transfer pairs are emitted")
                        break
                    reciprocal.append({"outbound_record_id": outbound.record_id, "return_record_id": inbound.record_id,
                                       "chain": chain, "asset": asset, "amount": str(amount)})
                    ctx.finding("SUPPLIED_RECIPROCAL_CRYPTO_TRANSFERS", "Two submitted confirmed-status transfers reverse the same supplied amount within the stated window",
                                [outbound.record_id, inbound.record_id], {"chain": chain, "asset": asset, "amount": str(amount)})
    flows = [{"chain": chain, "asset": asset, "address": address, "net_supplied_flow": str(value)}
             for (chain, asset, address), value in sorted(balances.items())]
    if len(flows) > 500:
        ctx.issue(None, "CRYPTO_FLOW_OUTPUT_LIMIT", "Only the first 500 supplied address-flow totals are emitted")
    return _finish(ctx, {"unique_transfer_ids": len(transfers), "ambiguous_transfer_ids": len(ambiguous),
                         "reciprocal_pairs": len(reciprocal), "address_asset_flow_groups": len(flows)},
                   {"net_supplied_flows": flows[:500], "reciprocal_transfer_pairs": reciprocal,
                    "address_checksum_verified": False, "chain_confirmation_verified": False},
                   ("Address syntax and declared confirmation are unverified; net submitted flows are not wallet balances, ownership, or laundering conclusions.",))


def marketplaceint(ctx: AnalysisContext):
    groups = _groups(ctx, {"listing"}, "listing")
    identities, ambiguous, images, products, profiles = {}, set(), defaultdict(list), defaultdict(list), []
    for record in groups["listing"]:
        market, listing, seller, product = (_text(ctx, record, key) for key in ("marketplace", "listing_id", "seller_id", "product_id"))
        price, currency = _amount(ctx, record, "price"), _currency(ctx, record)
        image = record.data.get("image_sha256")
        if image is not None and (not isinstance(image, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", image)):
            ctx.issue(record, "LISTING_IMAGE_HASH_INVALID", "image_sha256 requires a supplied SHA-256 hash")
            image = None
        if not all((market, listing, seller, product, currency)) or price is None:
            continue
        key = market, listing
        value = record, seller, product, price, currency, image.lower() if image else None
        if key in identities and identities[key][1:] != value[1:]:
            ambiguous.add(key)
            ctx.finding("MARKETPLACE_LISTING_ID_VARIATION", "One supplied marketplace/listing ID has different inventory or price metadata",
                        [identities[key][0].record_id, record.record_id], {"marketplace": market, "listing_id": listing})
        identities.setdefault(key, value)
    for key, (record, seller, product, price, currency, image) in identities.items():
        if key in ambiguous:
            continue
        products[(product, currency)].append((record, price))
        if image:
            images[image].append((record, seller))
        profiles.append({"record_id": record.record_id, "marketplace": key[0], "listing_id": key[1], "seller_id": seller,
                         "product_id": product, "price": str(price), "currency": currency})
    for digest, rows in images.items():
        if len({seller for _, seller in rows}) > 1:
            ctx.finding("LISTING_IMAGE_SHARED_ACROSS_SELLERS", "Different supplied seller IDs reuse an identical supplied image hash",
                        [record.record_id for record, _ in rows], {"image_sha256": digest})
    pricing = []
    factor = Decimal(str(_param(ctx, "price_median_factor", 2, 1.1, 20)))
    for (product, currency), rows in products.items():
        if len(rows) < 3:
            continue
        center = _median([value for _, value in rows])
        pricing.append({"product_id": product, "currency": currency, "median_supplied_price": str(center)})
        if center <= 0:
            ctx.issue(None, "PRICE_MEDIAN_ZERO", "Relative price comparisons are undefined for a zero median")
            continue
        for record, price in rows:
            ratio = _ratio(price, center)
            if ratio > factor or ratio < _ratio(Decimal(1), factor):
                ctx.finding("SUPPLIED_LISTING_PRICE_VARIATION", "A submitted price differs from its product/currency median beyond the stated factor",
                            [record.record_id], {"product_id": product, "currency": currency, "price_over_median": str(ratio), "factor": str(factor)})
    return _finish(ctx, {"unique_listing_ids": len(identities), "ambiguous_listing_ids": len(ambiguous),
                         "analyzed_listings": len(profiles)}, {"listing_inventory": profiles, "product_price_context": pricing},
                   ("Images can be licensed or shared, and product condition/quantity can differ; reuse and price variation do not establish scams or counterfeits.",))


def _distance(left, right, limit=2):
    if abs(len(left) - len(right)) > limit:
        return limit + 1
    previous = {index: index for index in range(min(len(right), limit) + 1)}
    for i, character in enumerate(left, 1):
        current = {0: i} if i <= limit else {}
        for j in range(max(1, i - limit), min(len(right), i + limit) + 1):
            current[j] = min(previous.get(j, limit + 1) + 1, current.get(j - 1, limit + 1) + 1,
                             previous.get(j - 1, limit + 1) + (character != right[j - 1]))
        if not current or min(current.values()) > limit:
            return limit + 1
        previous = current
    return previous.get(len(right), limit + 1)


def brandint(ctx: AnalysisContext):
    groups = _groups(ctx, {"official_brand", "mention"}, "mention")
    brands, mentions = {}, []
    for record in groups["official_brand"]:
        brand, name = _text(ctx, record, "brand_id"), _text(ctx, record, "name")
        domains = [domain for raw in _strings(ctx, record, "domains") if (domain := _domain(ctx, record, raw, "domains"))]
        if brand and name and domains:
            if brand in brands:
                ctx.issue(record, "BRAND_REGISTRY_ID_DUPLICATE", "Multiple supplied brand-registry records require reconciliation")
                continue
            brands[brand] = record, _norm(name), domains
    for record in groups["mention"]:
        brand, display = _text(ctx, record, "brand_id"), _text(ctx, record, "display_name")
        domain = _domain(ctx, record, record.data.get("domain"), "domain")
        if not brand or not display or not domain:
            continue
        if brand not in brands:
            ctx.issue(record, "BRAND_REGISTRY_MISSING", "Mention has no supplied official-brand reference record")
            continue
        official, name, domains = brands[brand]
        inside = any(domain == expected or domain.endswith("." + expected) for expected in domains)
        display_matches = _norm(display) == name
        comparisons = domains[:20]
        if len(domains) > 20:
            ctx.issue(official, "BRAND_DISTANCE_REFERENCE_LIMIT", "Typographical comparisons use only the first 20 supplied domains; namespace membership uses all")
        distance, closest = min((_distance(domain, expected), expected) for expected in comparisons)
        if display_matches and not inside:
            ctx.finding("BRAND_NAME_OUTSIDE_SUPPLIED_DOMAIN_LIST", "A supplied matching brand name appears outside its supplied domain namespaces",
                        [record.record_id, official.record_id], {"brand_id": brand, "observed_domain": domain, "closest_compared_domain": closest,
                                                                "bounded_edit_distance": distance if distance <= 2 else "GREATER_THAN_2"})
        mentions.append({"record_id": record.record_id, "brand_id": brand, "display_name_matches": display_matches,
                         "domain": domain, "within_supplied_domain_namespace": inside})
    return _finish(ctx, {"brand_reference_records": len(brands), "mentions_analyzed": len(mentions)},
                   {"brand_domain_observations": mentions},
                   ("The supplied domain registry is not verified ownership; legitimate resellers, delegated hosts and name collisions can explain observations.",))


def adint(ctx: AnalysisContext):
    groups = _groups(ctx, {"ad_period"}, "ad_period")
    periods, ambiguous, by_ad, profiles = {}, set(), defaultdict(list), []
    for record in groups["ad_period"]:
        ad = _text(ctx, record, "ad_id")
        start, end = _moment(ctx, record, "period_start", required=True), _moment(ctx, record, "period_end", required=True)
        spend, currency = _amount(ctx, record, "spend"), _currency(ctx, record)
        counts = [record.data.get(key) for key in ("impressions", "clicks", "conversions")]
        basis = record.data.get("count_basis")
        if any(type(value) is not int or value < 0 for value in counts):
            ctx.issue(record, "AD_COUNTS_INVALID", "Impressions, clicks and conversions require nonnegative integers")
            continue
        if not isinstance(basis, str) or basis not in {"EVENTS", "UNIQUE_USERS"}:
            ctx.issue(record, "AD_COUNT_BASIS_INVALID", "count_basis requires EVENTS or UNIQUE_USERS")
            continue
        if not ad or not start or not end or spend is None or not currency:
            continue
        if end <= start:
            ctx.issue(record, "AD_PERIOD_INVALID", "period_end must be after period_start")
            continue
        if end > ctx.as_of:
            ctx.issue(record, "AD_PERIOD_AFTER_ANALYSIS_TIME", "A metric period extends beyond the supplied analysis time")
            continue
        impressions, clicks, conversions = counts
        if basis == "UNIQUE_USERS" and (clicks > impressions or conversions > clicks):
            ctx.finding("AD_UNIQUE_USER_FUNNEL_ORDER_VARIATION", "Supplied unique-user funnel counts are not nested in the declared order",
                        [record.record_id], {"ad_id": ad, "impressions": impressions, "clicks": clicks, "conversions": conversions})
        if impressions == 0 and clicks:
            ctx.issue(record, "AD_CTR_DENOMINATOR_ZERO", "Click-through ratio is undefined without supplied impressions")
        key = ad, start, end
        item = record, spend, currency, tuple(counts), basis
        if key in periods and periods[key][1:] != item[1:]:
            ambiguous.add(key)
            ctx.finding("AD_PERIOD_METADATA_CONFLICT", "One supplied ad period has different metric metadata", [periods[key][0].record_id, record.record_id], {"ad_id": ad})
        periods.setdefault(key, item)
    for key, row in periods.items():
        by_ad[key[0]].append((key, row))
    overlap_count = 0
    for ad, rows in by_ad.items():
        for index, (left, left_row) in enumerate(rows):
            for right, right_row in rows[index + 1:]:
                if max(left[1], right[1]) < min(left[2], right[2]):
                    ambiguous.update((left, right))
                    overlap_count += 1
                    if overlap_count <= 100:
                        ctx.finding("AD_PERIOD_OVERLAP", "Supplied metric periods overlap and are excluded from spend aggregation",
                                    [left_row[0].record_id, right_row[0].record_id], {"ad_id": ad})
    if overlap_count > 100:
        ctx.issue(None, "AD_OVERLAP_OUTPUT_LIMIT", "Only the first 100 period-overlap pairs are emitted")
    totals = defaultdict(list)
    for key, (record, spend, currency, counts, basis) in periods.items():
        impressions, clicks, conversions = counts
        included = key not in ambiguous
        if included:
            totals[currency].append(spend)
        profiles.append({"record_id": record.record_id, "ad_id": key[0], "count_basis": basis,
                         "clicks_over_impressions": clicks / impressions if impressions else None,
                         "conversions_over_clicks": conversions / clicks if clicks else None,
                         "cost_per_supplied_click": str(_ratio(spend, Decimal(clicks))) if clicks else None,
                         "included_in_spend_sum": included})
    return _finish(ctx, {"unique_metric_periods": len(periods), "excluded_ambiguous_periods": len(ambiguous),
                         "overlap_pairs": overlap_count, "spend_by_currency": {currency: str(_sum(values)) for currency, values in totals.items()}},
                   {"ad_period_ratios": profiles, "aggregation_method": "UNIQUE_NONOVERLAPPING_DECLARED_PERIODS"},
                   ("Rates use submitted metric definitions; event counts need not form a unique-user funnel and no ad-fraud verdict is made.",))


def complaintint(ctx: AnalysisContext):
    groups = _groups(ctx, {"complaint"}, "complaint")
    selected, profiles, categories, ambiguous = {}, [], Counter(), set()
    sla = _param(ctx, "response_sla_hours", 24, 0.1, 8760)
    for record in groups["complaint"]:
        complaint = _text(ctx, record, "complaint_id")
        opened = _moment(ctx, record, "opened_at", required=True)
        updated = _moment(ctx, record, "updated_at")
        status = record.data.get("status")
        if not isinstance(status, str) or status not in {"OPEN", "RESOLVED"}:
            ctx.issue(record, "COMPLAINT_STATUS_INVALID", "status requires OPEN or RESOLVED")
            continue
        if not complaint or not opened:
            continue
        if opened > ctx.as_of or (updated and updated > ctx.as_of):
            ctx.issue(record, "FUTURE_COMPLAINT_RECORD", "Complaint timing lies after the supplied analysis time")
            continue
        if complaint in selected:
            previous, previous_open, previous_updated, _ = selected[complaint]
            if updated is None or previous_updated is None or updated == previous_updated:
                ambiguous.add(complaint)
                ctx.issue(record, "COMPLAINT_VERSION_UNRESOLVED", "Duplicate complaint IDs require distinct updated_at timestamps")
                continue
            if updated < previous_updated:
                continue
        selected[complaint] = record, opened, updated, status
    for complaint, (record, opened, _, status) in selected.items():
        if complaint in ambiguous:
            continue
        response, resolved = _moment(ctx, record, "first_response_at"), _moment(ctx, record, "resolved_at")
        if (response and response < opened) or (resolved and resolved < opened):
            ctx.issue(record, "COMPLAINT_CHRONOLOGY_INVALID", "Response/resolution precedes complaint opening")
            continue
        if (response and response > ctx.as_of) or (resolved and resolved > ctx.as_of):
            ctx.issue(record, "FUTURE_COMPLAINT_OUTCOME", "Response/resolution lies after analysis time")
            continue
        if status == "OPEN" and resolved is not None:
            ctx.issue(record, "COMPLAINT_STATUS_TIME_VARIATION", "Open status appears alongside a supplied resolution timestamp")
        if status == "RESOLVED" and resolved is None:
            ctx.issue(record, "COMPLAINT_RESOLUTION_TIME_MISSING", "Resolved status lacks a supplied resolution timestamp")
        elapsed = ((response or resolved or ctx.as_of) - opened).total_seconds() / 3600
        if status == "OPEN" and response is None and resolved is None and elapsed > sla:
            ctx.finding("SUPPLIED_COMPLAINT_RESPONSE_SLA_EXCEEDED", "No supplied response/resolution is available within the stated response threshold",
                        [record.record_id], {"complaint_id": complaint, "elapsed_hours": elapsed, "threshold_hours": sla})
        category = _text(ctx, record, "category", required=False)
        if category:
            categories[category] += 1
        profiles.append({"record_id": record.record_id, "complaint_id": complaint, "status": status,
                         "response_or_resolution_elapsed_hours": elapsed,
                         "resolution_elapsed_hours": (resolved - opened).total_seconds() / 3600 if resolved else None})
    return _finish(ctx, {"selected_complaint_ids": len(selected) - len(ambiguous), "ambiguous_complaint_ids": len(ambiguous),
                         "chronologically_usable_records": len(profiles),
                         "supplied_category_counts": dict(categories)}, {"complaint_timelines": profiles},
                   ("Missing responses in an export do not prove that no response occurred; complaints are allegations and SLA thresholds are supplied analysis criteria.",))


def reputationint(ctx: AnalysisContext):
    groups = _groups(ctx, {"review"}, "review")
    reviews, ambiguous, texts, entities = {}, set(), defaultdict(list), defaultdict(list)
    for record in groups["review"]:
        entity, platform, review, reviewer = (_text(ctx, record, key) for key in ("entity_id", "platform", "review_id", "reviewer_id"))
        rating, low, high = (record.data.get(key) for key in ("rating", "scale_min", "scale_max"))
        if any(type(value) not in (int, float) or not math.isfinite(value) for value in (rating, low, high)) or low >= high or not low <= rating <= high:
            ctx.issue(record, "REVIEW_SCALE_INVALID", "Review rating requires finite explicit scale bounds and a value within them")
            continue
        if not all((entity, platform, review, reviewer)):
            continue
        if not math.isfinite(high - low) or not math.isfinite(rating - low):
            ctx.issue(record, "REVIEW_SCALE_OVERFLOW", "Rating scale arithmetic exceeds its finite representable range")
            continue
        score = (rating - low) / (high - low)
        key = platform, review
        item = record, entity, reviewer, score
        if key in reviews and reviews[key][1:] != item[1:]:
            ambiguous.add(key)
            ctx.finding("REVIEW_ID_METADATA_VARIATION", "One supplied platform/review ID has different entity, reviewer or normalized rating",
                        [reviews[key][0].record_id, record.record_id], {"platform": platform, "review_id": review})
        reviews.setdefault(key, item)
    for key, (record, entity, reviewer, score) in reviews.items():
        if key in ambiguous:
            continue
        entities[entity].append((record, score))
        text = _text(ctx, record, "text", required=False)
        if text:
            texts[(entity, _hash(_norm(text)))].append((record, reviewer))
    for (entity, digest), rows in texts.items():
        if len({reviewer for _, reviewer in rows}) > 1:
            ctx.finding("REPEATED_REVIEW_TEXT_ACROSS_DECLARED_REVIEWERS", "Different supplied reviewer IDs contain identical normalized review text",
                        [record.record_id for record, _ in rows], {"entity_id": entity, "normalized_text_sha256": digest})
    aggregates = [{"entity_id": entity, "unique_unambiguous_reviews": len(rows),
                   "mean_normalized_supplied_rating": sum(value for _, value in rows) / len(rows)}
                  for entity, rows in sorted(entities.items())]
    return _finish(ctx, {"unique_review_ids": len(reviews), "ambiguous_review_ids": len(ambiguous),
                         "entities_with_usable_reviews": len(entities)}, {"supplied_review_aggregates": aggregates},
                   ("Ratings describe this supplied sample; repeated text can be legitimate and does not establish fake reviews, verified purchase, or population reputation.",))


HANDLERS = {
    "EXPOSUREINT": exposureint, "BREACHINT": breachint, "CREDINT": credint, "FRAUDINT": fraudint,
    "SCAMINT": scamint, "PAYMENTINT": paymentint, "CRYPTOINT": cryptoint, "MARKETPLACEINT": marketplaceint,
    "BRANDINT": brandint, "ADINT": adint, "COMPLAINTINT": complaintint, "REPUTATIONINT": reputationint,
}
