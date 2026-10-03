"""Three-layer material-claim verification with visible uncertainty."""
from __future__ import annotations

from datetime import datetime, timezone

from .contracts import Claim, EvidenceObject, Observation, SourceLineage, VerificationDecision, VerificationStatus


class VerificationEngine:
    def verify(self, claim: Claim, observations: tuple[Observation, ...], evidence: tuple[EvidenceObject, ...],
               lineage: tuple[SourceLineage, ...], *, contradicting_observation_ids: tuple[str, ...] = (),
               adversarial_gaps: tuple[str, ...] = (), required_independent_groups: int = 2,
               evidence_validator=None) -> VerificationDecision:
        if type(required_independent_groups) is not int or not 2 <= required_independent_groups <= 20:
            raise ValueError("verification requires 2-20 independent groups")
        if len({item.case_id for item in evidence}) > 1:
            raise ValueError("verification evidence crosses case boundaries")
        observation_index = {item.observation_id: item for item in observations}
        evidence_index = {item.evidence_id: item for item in evidence}
        lineage_index = {item.source_id: item for item in lineage}
        selected = [observation_index[item] for item in claim.observation_ids if item in observation_index]
        integrity = bool(selected) and len(selected) == len(claim.observation_ids) and all(
            item.evidence_id in evidence_index and evidence_index[item.evidence_id].acquisition_id == item.acquisition_id
            and (evidence_validator is None or evidence_validator(evidence_index[item.evidence_id]))
            for item in selected
        )
        groups = tuple(sorted({lineage_index[evidence_index[item.evidence_id].source_id].independence_group
                               for item in selected if item.evidence_id in evidence_index
                               and evidence_index[item.evidence_id].source_id in lineage_index}))
        contradictions = tuple(item for item in contradicting_observation_ids if item in observation_index)
        gaps = list(adversarial_gaps)
        if not integrity:
            gaps.append("integrity_or_reference_failure")
        if len(groups) < required_independent_groups:
            gaps.append("insufficient_independent_sources")
        if not integrity:
            status = VerificationStatus.UNSUPPORTED
        elif contradictions:
            status = VerificationStatus.DISPUTED
        elif "unverified_semantic_extraction" in gaps or "untrusted_instruction_content" in gaps:
            status = VerificationStatus.INCONCLUSIVE
        elif len(groups) >= required_independent_groups and not gaps:
            status = VerificationStatus.SUPPORTED
        elif selected:
            status = VerificationStatus.PARTIALLY_SUPPORTED
        else:
            status = VerificationStatus.INCONCLUSIVE
        return VerificationDecision(
            claim_id=claim.claim_id, status=status, integrity_passed=integrity,
            independent_groups=groups, supporting_observation_ids=tuple(item.observation_id for item in selected),
            contradicting_observation_ids=contradictions, information_gaps=tuple(dict.fromkeys(gaps)),
            human_review_required=claim.material or status != VerificationStatus.SUPPORTED,
            decided_at=datetime.now(timezone.utc).isoformat(),
        )
