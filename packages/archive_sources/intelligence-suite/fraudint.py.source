from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any, Optional


class PolicyBlocked(RuntimeError):
    """Raised if request appears to ask for fraud enablement instead of defense."""


class FraudStatus(str, Enum):
    NO_MATERIAL_FRAUD_SIGNAL = "NO_MATERIAL_FRAUD_SIGNAL"
    ANOMALY_ONLY = "ANOMALY_ONLY"
    FRAUD_INDICATORS_PRESENT = "FRAUD_INDICATORS_PRESENT"
    FRAUD_HYPOTHESIS = "FRAUD_HYPOTHESIS"
    FRAUD_HYPOTHESIS_SUPPORTED = "FRAUD_HYPOTHESIS_SUPPORTED"
    FRAUD_STRONGLY_SUPPORTED = "FRAUD_STRONGLY_SUPPORTED"
    DISPUTED = "DISPUTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    LEGAL_OR_REGULATORY_FINDING_EXISTS = "LEGAL_OR_REGULATORY_FINDING_EXISTS"


class TxnStatus(str, Enum):
    INITIATED = "INITIATED"
    AUTHORIZED = "AUTHORIZED"
    PENDING = "PENDING"
    POSTED = "POSTED"
    SETTLED = "SETTLED"
    FAILED = "FAILED"
    REVERSED = "REVERSED"
    REFUNDED = "REFUNDED"
    CHARGEDBACK = "CHARGEDBACK"
    CANCELLED = "CANCELLED"
    UNKNOWN = "UNKNOWN"


class DuplicateState(str, Enum):
    DISTINCT = "DISTINCT"
    EXACT_DUPLICATE = "EXACT_DUPLICATE"
    PROBABLE_DUPLICATE = "PROBABLE_DUPLICATE"
    AUTH_SETTLEMENT_PAIR = "AUTH_SETTLEMENT_PAIR"
    REFUND_PAIR = "REFUND_PAIR"
    REVERSAL_PAIR = "REVERSAL_PAIR"
    UNKNOWN = "UNKNOWN"


class LossState(str, Enum):
    CLAIMED_LOSS = "CLAIMED_LOSS"
    ATTEMPTED_LOSS = "ATTEMPTED_LOSS"
    GROSS_TRANSFER = "GROSS_TRANSFER"
    RECOVERED = "RECOVERED"
    REFUNDED = "REFUNDED"
    CHARGEDBACK = "CHARGEDBACK"
    NET_VERIFIED_LOSS = "NET_VERIFIED_LOSS"
    UNKNOWN = "UNKNOWN"


class Typology(str, Enum):
    PAYMENT_FRAUD = "PAYMENT_FRAUD"
    ACCOUNT_TAKEOVER = "ACCOUNT_TAKEOVER"
    IDENTITY_FRAUD = "IDENTITY_FRAUD"
    SYNTHETIC_IDENTITY = "SYNTHETIC_IDENTITY"
    APPLICATION_FRAUD = "APPLICATION_FRAUD"
    MERCHANT_FRAUD = "MERCHANT_FRAUD"
    INVOICE_FRAUD = "INVOICE_FRAUD"
    VENDOR_FRAUD = "VENDOR_FRAUD"
    PROCUREMENT_FRAUD = "PROCUREMENT_FRAUD"
    PAYROLL_FRAUD = "PAYROLL_FRAUD"
    EXPENSE_FRAUD = "EXPENSE_FRAUD"
    REFUND_ABUSE = "REFUND_ABUSE"
    CHARGEBACK_ABUSE = "CHARGEBACK_ABUSE"
    INSURANCE_CLAIMS_FRAUD = "INSURANCE_CLAIMS_FRAUD"
    LOAN_CREDIT_FRAUD = "LOAN_CREDIT_FRAUD"
    BEC_FRAUD = "BEC_FRAUD"
    MARKETPLACE_FRAUD = "MARKETPLACE_FRAUD"
    ECOMMERCE_FRAUD = "ECOMMERCE_FRAUD"
    INVESTMENT_FRAUD = "INVESTMENT_FRAUD"
    CRYPTO_FRAUD = "CRYPTO_FRAUD"
    SUBSCRIPTION_ABUSE = "SUBSCRIPTION_ABUSE"
    PROMOTION_ABUSE = "PROMOTION_ABUSE"
    AFFILIATE_AD_FRAUD = "AFFILIATE_AD_FRAUD"
    INTERNAL_FRAUD = "INTERNAL_FRAUD"
    COLLUSION_CANDIDATE = "COLLUSION_CANDIDATE"
    OTHER = "OTHER"
    UNKNOWN = "UNKNOWN"


@dataclass
class Evidence:
    evidence_id: str
    source_id: str
    source_type: str
    content: Any
    reliability: str = "UNKNOWN"
    dependencies: list[str] = field(default_factory=list)

    def digest(self) -> str:
        payload = json.dumps(
            {
                "source_id": self.source_id,
                "source_type": self.source_type,
                "content": self.content,
                "reliability": self.reliability,
                "dependencies": self.dependencies,
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:16]


@dataclass
class Transaction:
    txn_id: str
    payer: str
    payee: str
    amount: Decimal
    currency: str
    status: TxnStatus = TxnStatus.UNKNOWN
    event_time: Optional[str] = None
    reference: Optional[str] = None
    duplicate_state: DuplicateState = DuplicateState.DISTINCT
    duplicate_group: Optional[str] = None


@dataclass
class Claim:
    claim_id: str
    claimant: str
    subject: str
    predicate: str
    object: str
    amount: Optional[Decimal] = None
    currency: Optional[str] = None
    basis: str = ""
    status: str = "ALLEGED"
    evidence_ids: list[str] = field(default_factory=list)


@dataclass
class Hypothesis:
    hypothesis_id: str
    description: str
    supporting_evidence: list[str] = field(default_factory=list)
    contradicting_evidence: list[str] = field(default_factory=list)
    falsification_conditions: list[str] = field(default_factory=list)
    confidence: float = 0.0


@dataclass
class Loss:
    gross_verified_outflow: Decimal = Decimal("0")
    verified_recovery: Decimal = Decimal("0")
    net_verified_loss: Decimal = Decimal("0")
    currency: str = "UNKNOWN"
    states: dict[str, Any] = field(default_factory=dict)


class FraudInt:
    """
    Compact defensive FRAUDINT core.

    It does NOT create fraud, enable fraud, or make legal findings.
    It supports evidence-linked fraud hypothesis analysis only.
    """

    PROHIBITED_PATTERNS = (
        "create fake invoice",
        "create fake identity",
        "create fake receipt",
        "create fake bank statement",
        "generate phishing",
        "send phishing",
        "launder",
        "money laundering",
        "bypass kyc",
        "bypass aml",
        "evade fraud detection",
        "evade transaction monitoring",
        "take over account",
        "account takeover attack",
        "recruit mule",
        "money mule recruit",
        "fabricate chargeback",
        "fabricate refund",
        "steal credential",
        "use otp",
        "use mfa code",
    )

    COMPLETED_STATUSES = {TxnStatus.POSTED, TxnStatus.SETTLED}
    INITIATED_STATUSES = {TxnStatus.INITIATED, TxnStatus.AUTHORIZED, TxnStatus.PENDING}

    def __init__(self, case_id: str, objective: str, scope: str):
        self._guard(objective)
        self._guard(scope)

        self.case_id = case_id
        self.objective = objective
        self.scope = scope

        self.evidence: dict[str, Evidence] = {}
        self.transactions: dict[str, Transaction] = {}
        self.claims: dict[str, Claim] = {}
        self.hypotheses: dict[str, Hypothesis] = {}

        self.outflows: set[str] = set()
        self.recoveries: list[dict[str, Any]] = []

    @classmethod
    def _guard(cls, text: str) -> None:
        low = (text or "").lower()
        for pattern in cls.PROHIBITED_PATTERNS:
            if pattern in low:
                raise PolicyBlocked(
                    f"Policy blocked: '{pattern}'. FRAUDINT only supports defensive analysis."
                )

    @staticmethod
    def _decimal(value: Any, field_name: str) -> Decimal:
        try:
            return Decimal(str(value))
        except (InvalidOperation, TypeError, ValueError) as exc:
            raise ValueError(f"Invalid decimal for {field_name}: {value!r}") from exc

    def add_evidence(
        self,
        source_id: str,
        source_type: str,
        content: Any,
        reliability: str = "UNKNOWN",
        dependencies: Optional[list[str]] = None,
    ) -> Evidence:
        evidence_id = f"EV-{uuid.uuid4().hex[:8]}"
        ev = Evidence(
            evidence_id=evidence_id,
            source_id=source_id,
            source_type=source_type,
            content=content,
            reliability=reliability.upper(),
            dependencies=dependencies or [],
        )
        self.evidence[evidence_id] = ev
        return ev

    def add_transaction(
        self,
        txn_id: Optional[str] = None,
        payer: str = "",
        payee: str = "",
        amount: Any = 0,
        currency: str = "USD",
        status: TxnStatus = TxnStatus.UNKNOWN,
        event_time: Optional[str] = None,
        reference: Optional[str] = None,
    ) -> Transaction:
        tid = txn_id or f"TXN-{uuid.uuid4().hex[:8]}"
        txn = Transaction(
            txn_id=tid,
            payer=payer,
            payee=payee,
            amount=self._decimal(amount, "transaction.amount"),
            currency=currency.upper(),
            status=status,
            event_time=event_time,
            reference=reference,
        )
        self.transactions[tid] = txn
        return txn

    def mark_outflow(self, txn_id: str) -> None:
        if txn_id not in self.transactions:
            raise KeyError(f"Unknown transaction: {txn_id}")
        self.outflows.add(txn_id)

    def add_recovery(
        self,
        recovery_id: Optional[str] = None,
        amount: Any = 0,
        currency: str = "USD",
        source: str = "recovery",
        evidence_id: Optional[str] = None,
    ) -> dict[str, Any]:
        rid = recovery_id or f"REC-{uuid.uuid4().hex[:8]}"
        rec = {
            "recovery_id": rid,
            "amount": self._decimal(amount, "recovery.amount"),
            "currency": currency.upper(),
            "source": source,
            "evidence_id": evidence_id,
        }
        self.recoveries.append(rec)
        return rec

    def add_claim(
        self,
        claim_id: Optional[str] = None,
        claimant: str = "",
        subject: str = "",
        predicate: str = "",
        object: str = "",
        amount: Any = None,
        currency: Optional[str] = None,
        basis: str = "",
        evidence_ids: Optional[list[str]] = None,
    ) -> Claim:
        cid = claim_id or f"CLM-{uuid.uuid4().hex[:8]}"
        claim = Claim(
            claim_id=cid,
            claimant=claimant,
            subject=subject,
            predicate=predicate,
            object=object,
            amount=None if amount is None else self._decimal(amount, "claim.amount"),
            currency=currency.upper() if currency else None,
            basis=basis,
            status="ALLEGED",
            evidence_ids=evidence_ids or [],
        )
        self.claims[cid] = claim
        return claim

    def add_hypothesis(
        self,
        hypothesis_id: Optional[str] = None,
        description: str = "",
        supporting_evidence: Optional[list[str]] = None,
        contradicting_evidence: Optional[list[str]] = None,
        falsification_conditions: Optional[list[str]] = None,
    ) -> Hypothesis:
        hid = hypothesis_id or f"HYP-{uuid.uuid4().hex[:8]}"
        hyp = Hypothesis(
            hypothesis_id=hid,
            description=description,
            supporting_evidence=supporting_evidence or [],
            contradicting_evidence=contradicting_evidence or [],
            falsification_conditions=falsification_conditions or [],
            confidence=0.0,
        )
        self.hypotheses[hid] = hyp
        return hyp

    def _dedupe_transactions(self) -> None:
        groups: dict[tuple[Any, ...], list[str]] = {}
        for txn in self.transactions.values():
            key = (
                txn.payer,
                txn.payee,
                str(txn.amount),
                txn.currency,
                txn.reference,
                txn.status.value,
            )
            groups.setdefault(key, []).append(txn.txn_id)

        for idx, ids in enumerate(groups.values(), start=1):
            if len(ids) > 1:
                group_id = f"DUP-{idx}"
                for tid in ids:
                    self.transactions[tid].duplicate_state = DuplicateState.EXACT_DUPLICATE
                    self.transactions[tid].duplicate_group = group_id

    def _unique_completed_outflows(self) -> list[Transaction]:
        seen: set[str] = set()
        result: list[Transaction] = []

        for tid in sorted(self.outflows):
            txn = self.transactions.get(tid)
            if not txn or txn.status not in self.COMPLETED_STATUSES:
                continue

            key = txn.duplicate_group or txn.txn_id
            if key not in seen:
                seen.add(key)
                result.append(txn)

        return result

    def _fact_gate(self) -> list[dict[str, Any]]:
        facts: list[dict[str, Any]] = []

        for claim in self.claims.values():
            matches: list[Transaction] = []

            if claim.subject and claim.object and claim.amount is not None and claim.currency:
                cur = str(claim.currency).upper()
                for txn in self.transactions.values():
                    if (
                        claim.subject == txn.payer
                        and claim.object == txn.payee
                        and claim.amount == txn.amount
                        and cur == txn.currency
                    ):
                        matches.append(txn)

            completed = [t for t in matches if t.status in self.COMPLETED_STATUSES]
            initiated = [t for t in matches if t.status in self.INITIATED_STATUSES]
            predicate = (claim.predicate or "").lower()

            if completed and predicate in {"paid", "sent", "transferred", "debited"}:
                claim.status = "SUPPORTED_FACT"
                facts.append(
                    {
                        "claim_id": claim.claim_id,
                        "state": "SUPPORTED_FACT",
                        "statement": f"{claim.subject} paid {claim.amount} {claim.currency} to {claim.object}.",
                        "transaction_ids": [t.txn_id for t in completed],
                        "evidence_ids": claim.evidence_ids,
                    }
                )
            elif completed and predicate in {"received", "credited", "deposited"}:
                claim.status = "SUPPORTED_FACT"
                facts.append(
                    {
                        "claim_id": claim.claim_id,
                        "state": "SUPPORTED_FACT",
                        "statement": f"{claim.object} received {claim.amount} {claim.currency} from {claim.subject}.",
                        "transaction_ids": [t.txn_id for t in completed],
                        "evidence_ids": claim.evidence_ids,
                    }
                )
            elif initiated and predicate in {"initiated", "requested", "authorized"}:
                claim.status = "PARTIAL_FACT"
                facts.append(
                    {
                        "claim_id": claim.claim_id,
                        "state": "PARTIAL_FACT",
                        "statement": f"Transaction initiation is supported, but settlement is not verified.",
                        "transaction_ids": [t.txn_id for t in initiated],
                        "evidence_ids": claim.evidence_ids,
                    }
                )
            else:
                claim.status = "ALLEGED"

        return facts

    def _source_independence(self) -> dict[str, Any]:
        by_source: dict[str, list[str]] = {}
        edges: list[dict[str, str]] = []
        dependent_ids: set[str] = set()

        for ev in self.evidence.values():
            by_source.setdefault(ev.source_id, []).append(ev.evidence_id)
            for dep in ev.dependencies:
                if dep in self.evidence:
                    edges.append(
                        {
                            "derived": ev.evidence_id,
                            "upstream": dep,
                            "relationship": "DEPENDENT",
                        }
                    )
                    dependent_ids.add(ev.evidence_id)

        independent_sources = [
            sid
            for sid, eids in by_source.items()
            if len(eids) == 1 and eids[0] not in dependent_ids
        ]

        return {
            "independent_source_count": len(independent_sources),
            "independent_sources": independent_sources,
            "sources": by_source,
            "dependency_edges": edges,
        }

    def _benign_explanations(self) -> list[str]:
        explanations = {
            "administrative_error",
            "billing_mistake",
            "legitimate_vendor_change",
            "duplicate_data_import",
            "timing_or_settlement_lag",
            "currency_conversion",
            "customer_dispute",
            "account_compromise_alternative",
            "data_lag",
            "normal_seasonality",
        }

        if any(t.duplicate_state == DuplicateState.EXACT_DUPLICATE for t in self.transactions.values()):
            explanations.add("duplicate_import_or_ledger_copy")

        if self.recoveries:
            explanations.add("refund_or_reversal")

        if any(t.status in self.INITIATED_STATUSES for t in self.transactions.values()):
            explanations.add("processing_delay")

        if any(
            ev.reliability.lower() in {"victim", "complaint", "anonymous", "media"}
            for ev in self.evidence.values()
        ):
            explanations.add("claimant_interpretation_or_bias")

        return sorted(explanations)

    def _typologies(self) -> list[Typology]:
        parts: list[str] = []

        for claim in self.claims.values():
            parts.extend([claim.claimant, claim.subject, claim.predicate, claim.object, claim.basis])

        for hyp in self.hypotheses.values():
            parts.append(hyp.description)

        for ev in self.evidence.values():
            if isinstance(ev.content, dict):
                parts.extend(str(v) for v in ev.content.values())
            elif isinstance(ev.content, list):
                parts.extend(str(item) for item in ev.content)
            else:
                parts.append(str(ev.content))

        blob = " ".join(parts).lower()

        rules = {
            "invoice": Typology.INVOICE_FRAUD,
            "vendor": Typology.VENDOR_FRAUD,
            "account takeover": Typology.ACCOUNT_TAKEOVER,
            "refund": Typology.REFUND_ABUSE,
            "chargeback": Typology.CHARGEBACK_ABUSE,
            "identity": Typology.IDENTITY_FRAUD,
            "synthetic": Typology.SYNTHETIC_IDENTITY,
            "procurement": Typology.PROCUREMENT_FRAUD,
            "expense": Typology.EXPENSE_FRAUD,
            "payroll": Typology.PAYROLL_FRAUD,
            "insurance claim": Typology.INSURANCE_CLAIMS_FRAUD,
            "loan": Typology.LOAN_CREDIT_FRAUD,
            "bec": Typology.BEC_FRAUD,
            "merchant": Typology.MERCHANT_FRAUD,
            "crypto": Typology.CRYPTO_FRAUD,
            "investment": Typology.INVESTMENT_FRAUD,
            "collusion": Typology.COLLUSION_CANDIDATE,
        }

        found: list[Typology] = []
        for keyword, typology in rules.items():
            if keyword in blob and typology not in found:
                found.append(typology)

        return found or [Typology.UNKNOWN]

    def _ach_and_confidence(self) -> dict[str, dict[str, str]]:
        matrix: dict[str, dict[str, str]] = {}

        for hyp in self.hypotheses.values():
            row: dict[str, str] = {}

            for evidence_id in self.evidence:
                if evidence_id in hyp.supporting_evidence:
                    row[evidence_id] = "CONSISTENT"
                elif evidence_id in hyp.contradicting_evidence:
                    row[evidence_id] = "INCONSISTENT"
                else:
                    row[evidence_id] = "NEUTRAL"

            consistent = sum(1 for v in row.values() if v == "CONSISTENT")
            inconsistent = sum(1 for v in row.values() if v == "INCONSISTENT")
            denom = max(1, len(row))

            hyp.confidence = round(max(0.0, min(1.0, (consistent - inconsistent) / denom)), 3)
            matrix[hyp.hypothesis_id] = row

        return matrix

    def _calculate_loss(self) -> Loss:
        outflows = self._unique_completed_outflows()

        gross_by_cur: dict[str, Decimal] = {}
        for txn in outflows:
            gross_by_cur[txn.currency] = gross_by_cur.get(txn.currency, Decimal("0")) + txn.amount

        rec_by_cur: dict[str, Decimal] = {}
        for rec in self.recoveries:
            cur = str(rec["currency"]).upper()
            amt = Decimal(str(rec["amount"]))
            rec_by_cur[cur] = rec_by_cur.get(cur, Decimal("0")) + amt

        all_currencies = set(gross_by_cur) | set(rec_by_cur)
        net_by_cur = {
            cur: max(
                gross_by_cur.get(cur, Decimal("0")) - rec_by_cur.get(cur, Decimal("0")),
                Decimal("0"),
            )
            for cur in all_currencies
        }

        if not all_currencies:
            currency = "UNKNOWN"
            gross = Decimal("0")
            recovered = Decimal("0")
            net = Decimal("0")
        elif len(all_currencies) == 1:
            currency = next(iter(all_currencies))
            gross = gross_by_cur.get(currency, Decimal("0"))
            recovered = rec_by_cur.get(currency, Decimal("0"))
            net = net_by_cur[currency]
        else:
            currency = "MULTI"
            gross = Decimal("0")
            recovered = Decimal("0")
            net = Decimal("0")

        states = {
            "gross_by_currency": {k: str(v) for k, v in gross_by_cur.items()},
            "recovered_by_currency": {k: str(v) for k, v in rec_by_cur.items()},
            "net_by_currency": {k: str(v) for k, v in net_by_cur.items()},
        }

        if currency not in {"MULTI", "UNKNOWN"}:
            states.update(
                {
                    "GROSS_TRANSFER": str(gross),
                    "RECOVERED": str(recovered),
                    "NET_VERIFIED_LOSS": str(net),
                }
            )
        else:
            states["NOTE"] = "Do not aggregate multiple currencies without FX normalization."

        return Loss(
            gross_verified_outflow=gross,
            verified_recovery=recovered,
            net_verified_loss=net,
            currency=currency,
            states=states,
        )

    def _fraud_status(self, facts: list[dict[str, Any]], independence: dict[str, Any]) -> FraudStatus:
        if not self.evidence:
            return FraudStatus.NO_MATERIAL_FRAUD_SIGNAL

        max_conf = max((h.confidence for h in self.hypotheses.values()), default=0.0)
        indep_count = int(independence.get("independent_source_count", 0))

        if facts and max_conf >= 0.90 and indep_count >= 2:
            return FraudStatus.FRAUD_STRONGLY_SUPPORTED

        if facts and max_conf >= 0.65:
            return FraudStatus.FRAUD_HYPOTHESIS_SUPPORTED

        if self.hypotheses and any(h.supporting_evidence for h in self.hypotheses.values()):
            return FraudStatus.FRAUD_HYPOTHESIS

        if facts:
            return FraudStatus.FRAUD_INDICATORS_PRESENT

        if self.transactions or self.claims:
            return FraudStatus.ANOMALY_ONLY

        return FraudStatus.INCONCLUSIVE

    def _contradictions(self) -> list[dict[str, Any]]:
        contradictions: list[dict[str, Any]] = []

        for claim in self.claims.values():
            if claim.amount is None or not claim.currency:
                continue

            cur = str(claim.currency).upper()
            for txn in self.transactions.values():
                if (
                    claim.subject == txn.payer
                    and claim.object == txn.payee
                    and claim.amount == txn.amount
                    and cur == txn.currency
                ):
                    if txn.status in {
                        TxnStatus.FAILED,
                        TxnStatus.REVERSED,
                        TxnStatus.CANCELLED,
                        TxnStatus.REFUNDED,
                    }:
                        contradictions.append(
                            {
                                "type": "CLAIM_VS_TRANSACTION_STATUS",
                                "claim_id": claim.claim_id,
                                "txn_id": txn.txn_id,
                                "note": "Claimed completed payment conflicts with non-completed transaction status.",
                            }
                        )
                        if claim.status == "SUPPORTED_FACT":
                            claim.status = "DISPUTED"

        return contradictions

    def _knowledge_gaps(
        self,
        facts: list[dict[str, Any]],
        loss: Loss,
        independence: dict[str, Any],
    ) -> list[str]:
        gaps: list[str] = []

        if not facts:
            gaps.append("no_verified_transaction_fact")

        if loss.currency == "MULTI":
            gaps.append("multi_currency_loss_requires_separate_calculation")

        if int(independence.get("independent_source_count", 0)) < 2:
            gaps.append("insufficient_independent_sources")

        if not self.hypotheses:
            gaps.append("no_competing_hypothesis_generated")

        if any(not h.falsification_conditions for h in self.hypotheses.values()):
            gaps.append("falsification_conditions_missing")

        if any(h.confidence < 0.5 for h in self.hypotheses.values()):
            gaps.append("some_hypotheses_weakly_supported")

        return gaps

    def _next_actions(self, status: FraudStatus, loss: Loss) -> list[str]:
        actions = [
            "preserve_original_evidence",
            "verify_beneficiary_through_authorized_source",
            "check_refunds_reversals_and_chargebacks",
            "resolve_duplicate_transaction_records_before_counting",
            "request_human_review_before_any_accusation",
        ]

        if status in {
            FraudStatus.FRAUD_HYPOTHESIS_SUPPORTED,
            FraudStatus.FRAUD_STRONGLY_SUPPORTED,
        }:
            actions.insert(0, "escalate_to_authorized_fraud_investigator")

        if loss.net_verified_loss > Decimal("0"):
            actions.insert(0, "confirm_net_loss_with_primary_financial_records")

        return actions

    def _handoffs(self, typologies: list[Typology], loss: Loss) -> list[str]:
        handoffs: list[str] = []

        if Typology.ACCOUNT_TAKEOVER in typologies:
            handoffs.append("INCIDENTINT/CREDINT/LOGINT for compromise context")

        if Typology.BEC_FRAUD in typologies or Typology.VENDOR_FRAUD in typologies:
            handoffs.append("CORPINT/PROCUREMENTINT for vendor legal identity verification")

        if Typology.INVOICE_FRAUD in typologies:
            handoffs.append("DOCINT/METADATAINT for invoice authenticity")

        if loss.currency == "MULTI":
            handoffs.append("FININT/PAYMENTINT for currency and payment-rail resolution")

        handoffs.append("HUMAN_REVIEW required before consequential action")
        return handoffs

    def analyze(self) -> dict[str, Any]:
        self._dedupe_transactions()
        facts = self._fact_gate()
        ach_matrix = self._ach_and_confidence()
        loss = self._calculate_loss()
        independence = self._source_independence()
        status = self._fraud_status(facts, independence)
        typologies = self._typologies()
        benign = self._benign_explanations()
        contradictions = self._contradictions()
        gaps = self._knowledge_gaps(facts, loss, independence)
        next_actions = self._next_actions(status, loss)
        handoffs = self._handoffs(typologies, loss)

        duplicate_count = sum(
            1 for t in self.transactions.values() if t.duplicate_state == DuplicateState.EXACT_DUPLICATE
        )

        observations: list[str] = []
        if duplicate_count:
            observations.append(
                f"{duplicate_count} transaction record(s) flagged as exact duplicates and counted once."
            )
        if self.recoveries:
            observations.append("Recoveries are tracked separately from gross outflow.")
        if any(t.status in self.INITIATED_STATUSES for t in self.transactions.values()):
            observations.append("Some transactions are initiated/authorized but not settled.")

        report = {
            "case_id": self.case_id,
            "objective": self.objective,
            "authorized_scope": self.scope,
            "fraud_status": status.value,
            "fraud_typologies": [t.value for t in typologies],
            "evidence": [
                {
                    "evidence_id": ev.evidence_id,
                    "source_id": ev.source_id,
                    "source_type": ev.source_type,
                    "reliability": ev.reliability,
                    "digest": ev.digest(),
                    "dependencies": ev.dependencies,
                }
                for ev in self.evidence.values()
            ],
            "transactions": [
                {
                    "txn_id": t.txn_id,
                    "payer": t.payer,
                    "payee": t.payee,
                    "amount": str(t.amount),
                    "currency": t.currency,
                    "status": t.status.value,
                    "event_time": t.event_time,
                    "reference": t.reference,
                    "duplicate_state": t.duplicate_state.value,
                    "duplicate_group": t.duplicate_group,
                }
                for t in self.transactions.values()
            ],
            "claims": [
                {
                    "claim_id": c.claim_id,
                    "claimant": c.claimant,
                    "subject": c.subject,
                    "predicate": c.predicate,
                    "object": c.object,
                    "amount": str(c.amount) if c.amount is not None else None,
                    "currency": c.currency,
                    "basis": c.basis,
                    "status": c.status,
                    "evidence_ids": c.evidence_ids,
                }
                for c in self.claims.values()
            ],
            "hypotheses": [
                {
                    "hypothesis_id": h.hypothesis_id,
                    "description": h.description,
                    "supporting_evidence": h.supporting_evidence,
                    "contradicting_evidence": h.contradicting_evidence,
                    "falsification_conditions": h.falsification_conditions,
                    "confidence": h.confidence,
                }
                for h in self.hypotheses.values()
            ],
            "ach_matrix": ach_matrix,
            "loss": {
                "currency": loss.currency,
                "gross_verified_outflow": str(loss.gross_verified_outflow),
                "verified_recovery": str(loss.verified_recovery),
                "net_verified_loss": str(loss.net_verified_loss),
                "states": loss.states,
            },
            "facts": facts,
            "observations": observations,
            "contradictions": contradictions,
            "benign_explanations": benign,
            "source_independence": independence,
            "knowledge_gaps": gaps,
            "recommended_next_actions": next_actions,
            "specialist_handoffs": handoffs,
            "privacy_flags": [
                "mask_bank_and_card_identifiers",
                "local_only_recommended_for_sensitive_financial_data",
            ],
            "legal_flags": [
                "no_legal_guilt_determination",
                "human_review_required_before_accusation",
            ],
            "limitations": [
                "Compact defensive skeleton only.",
                "Does not replace deterministic enterprise ledgers, AML systems, or investigators.",
                "Cannot declare guilt, intent, or legal fraud.",
            ],
        }

        return json.loads(json.dumps(report, default=str))


def demo() -> None:
    agent = FraudInt(
        case_id="CASE-DEMO-001",
        objective="Defensive analysis of alleged vendor payment diversion",
        scope="Authorized bank records and vendor email metadata only",
    )

    ev_bank = agent.add_evidence(
        source_id="SRC-BANK",
        source_type="bank_record",
        content={"txn_id": "T1", "status": "SETTLED", "amount": "1500000", "currency": "INR"},
        reliability="PRIMARY",
    )

    ev_mail = agent.add_evidence(
        source_id="SRC-MAIL",
        source_type="email_metadata",
        content={"sender_domain": "example-vendor.com", "bank_change_requested": True},
        reliability="SUPPORTING",
    )

    agent.add_transaction(
        txn_id="T1",
        payer="ORG-O",
        payee="ACCT-A",
        amount=Decimal("1500000"),
        currency="INR",
        status=TxnStatus.SETTLED,
        event_time="2026-10-01T10:00:00Z",
        reference="INV-99",
    )

    agent.mark_outflow("T1")

    agent.add_recovery(
        recovery_id="R1",
        amount=Decimal("500000"),
        currency="INR",
        source="bank_recall",
        evidence_id=ev_bank.evidence_id,
    )

    agent.add_claim(
        claim_id="C1",
        claimant="Finance team",
        subject="ORG-O",
        predicate="paid",
        object="ACCT-A",
        amount=Decimal("1500000"),
        currency="INR",
        basis="Payment record indicates transfer to changed vendor account.",
        evidence_ids=[ev_bank.evidence_id],
    )

    agent.add_hypothesis(
        hypothesis_id="H1",
        description="Vendor impersonation / BEC fraud",
        supporting_evidence=[ev_bank.evidence_id],
        falsification_conditions=["Approved vendor bank-change request is found."],
    )

    agent.add_hypothesis(
        hypothesis_id="H2",
        description="Legitimate vendor bank change",
        supporting_evidence=[ev_mail.evidence_id],
        falsification_conditions=["Sender domain is not controlled by the real vendor."],
    )

    result = agent.analyze()
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    demo()