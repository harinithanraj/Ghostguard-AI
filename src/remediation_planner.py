"""Evidence-backed remediation planning without executing any operation.

The available sample output is the only supplied step-format reference. This
module uses its observed operation vocabulary and phase names, but does not
claim that the examples define an official operation or ordering contract.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Dict, List, Optional, Sequence, Set, Tuple

if __package__:
    from .data_loader import Dataset
    from .evidence_analyzer import (
        AT_AUDIT,
        PRE_AUDIT,
        EvidenceFinding,
        RequestEvidenceAnalysis,
        analyze_all_requests,
    )
    from .identity_resolver import (
        CONFIRMED,
        IdentityResolution,
        resolve_all_requests,
    )
    from .policy_engine import (
        PERMITTED_RETENTION,
        RuleAssessment,
        SATISFIED,
        UNMET,
        UNRESOLVED,
        PolicyResult,
        evaluate_all_requests,
    )
else:
    from data_loader import Dataset
    from evidence_analyzer import (
        AT_AUDIT,
        PRE_AUDIT,
        EvidenceFinding,
        RequestEvidenceAnalysis,
        analyze_all_requests,
    )
    from identity_resolver import (
        CONFIRMED,
        IdentityResolution,
        resolve_all_requests,
    )
    from policy_engine import (
        PERMITTED_RETENTION,
        RuleAssessment,
        SATISFIED,
        UNMET,
        UNRESOLVED,
        PolicyResult,
        evaluate_all_requests,
    )


DELETE_STATES = {"ABSENT", "DELETED", "ERASED", "PURGED", "NOT_FOUND", "MISSING"}
REDACTION_STATES = {"REDACTED"}
ANONYMIZATION_STATES = {"ANONYMIZED", "ANONYMISED", "DEIDENTIFIED", "DE_IDENTIFIED"}
POSITIVE_STATES = {
    "ACTIVE",
    "EXISTS",
    "FOUND",
    "IDENTIFIABLE",
    "PRESENT",
    "RETAINED",
    "HIT",
}
FAILED_RESULTS = {"FAILED", "FAILURE", "PARTIAL", "PARTIALLY_COMPLETE"}
NON_FINAL_RESULTS = {"SUCCESS", "OK", "COMPLETED", "COMPLETE"}
PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}


@dataclass(frozen=True)
class RemediationStep:
    """One proposed, non-executing action with its complete source trace."""

    step_no: int
    case_id: Optional[str]
    subject_id: Optional[str]
    rule_id: str
    phase: str
    system_id: Optional[str]
    resource_id: Optional[str]
    operation: str
    state: Optional[str]
    evidence_id: Optional[str]
    evidence_references: Tuple[str, ...]
    reason: str

    def to_dict(self) -> Dict[str, object]:
        """Return a JSON-serializable representation for a future steps_json."""
        return {
            "step_no": self.step_no,
            "case_id": self.case_id,
            "subject_id": self.subject_id,
            "rule_id": self.rule_id,
            "phase": self.phase,
            "system_id": self.system_id,
            "resource_id": self.resource_id,
            "operation": self.operation,
            "state": self.state,
            "evidence_id": self.evidence_id,
            "evidence_references": list(self.evidence_references),
            "reason": self.reason,
        }


@dataclass(frozen=True)
class RemediationPlan:
    """Deterministic proposed steps and obligations that cannot safely be planned."""

    case_id: Optional[str]
    subject_id: Optional[str]
    identity_status: str
    steps: Tuple[RemediationStep, ...]
    unresolved_obligations: Tuple[str, ...]

    def to_steps_json_value(self) -> List[Dict[str, object]]:
        """Return the structured list suitable for JSON serialization."""
        return [step.to_dict() for step in self.steps]


@dataclass(frozen=True)
class _DraftStep:
    case_id: Optional[str]
    subject_id: Optional[str]
    rule_id: str
    phase: str
    system_id: Optional[str]
    resource_id: Optional[str]
    operation: str
    state: Optional[str]
    evidence_id: Optional[str]
    evidence_references: Tuple[str, ...]
    reason: str


def _parse_datetime(value: Optional[str]) -> Optional[datetime]:
    """Parse an offset-aware ISO datetime and normalize it to UTC."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except (ValueError, OverflowError):
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _eligible_findings(
    findings: Sequence[EvidenceFinding],
) -> List[EvidenceFinding]:
    """Return findings that the evidence analyzer marked as audit-time evidence."""
    eligible = [
        finding
        for finding in findings
        if finding.as_of_audit
        and finding.temporal_relation in {PRE_AUDIT, AT_AUDIT}
        and _parse_datetime(finding.timestamp) is not None
    ]
    return sorted(
        eligible,
        key=lambda finding: (
            _parse_datetime(finding.timestamp) or datetime.min,
            finding.file_path.casefold(),
            finding.source_reference.casefold(),
        ),
    )


def _state(finding: EvidenceFinding) -> Optional[str]:
    value = finding.explicit_state or finding.result_or_state
    if value is None:
        return None
    return re.sub(r"[\s-]+", "_", value.strip().upper())


def _attributes(finding: EvidenceFinding) -> Dict[str, str]:
    return {
        key.rsplit(".", 1)[-1].casefold(): value.strip()
        for key, value in finding.policy_attributes
        if value.strip()
    }


def _system_id(finding: EvidenceFinding) -> Optional[str]:
    return finding.system_id or finding.target_system or finding.source_system


def _finding_reference(finding: EvidenceFinding) -> str:
    return f"{finding.file_path}#{finding.source_reference}"


def _assessment_findings(
    assessment: RuleAssessment,
    analysis: RequestEvidenceAnalysis,
) -> Dict[str, List[EvidenceFinding]]:
    references = {
        reference.reference
        for reference in assessment.evidence_references
    }
    resources = set(assessment.resource_ids)
    grouped: Dict[str, List[EvidenceFinding]] = {}
    for finding in analysis.findings:
        if (
            _finding_reference(finding) in references
            and finding.resource_id
            and (not resources or finding.resource_id in resources)
        ):
            grouped.setdefault(finding.resource_id, []).append(finding)
    return grouped


def _unique_references(findings: Sequence[EvidenceFinding]) -> Tuple[str, ...]:
    return tuple(sorted({_finding_reference(finding) for finding in findings}))


def _evidence_id(findings: Sequence[EvidenceFinding]) -> Optional[str]:
    identifiers = sorted(
        {finding.evidence_id for finding in findings if finding.evidence_id}
    )
    return identifiers[0] if len(identifiers) == 1 else None


def _desired_state(action: str) -> Optional[str]:
    return {
        "DELETE": "ABSENT",
        "REDACT": "REDACTED",
        "ANONYMIZE": "ANONYMIZED",
    }.get(action.strip().upper())


def _local_action_state(
    action: str, findings: Sequence[EvidenceFinding]
) -> Tuple[str, Optional[EvidenceFinding], str]:
    eligible = _eligible_findings(findings)
    if not eligible:
        return UNRESOLVED, None, "No reliable event timestamp at or before audit_at."

    latest_time = _parse_datetime(eligible[-1].timestamp)
    latest = [
        finding for finding in eligible
        if _parse_datetime(finding.timestamp) == latest_time
    ]
    states = {_state(finding) for finding in latest}
    states.discard(None)
    if any(finding.conflict_references for finding in latest):
        return UNRESOLVED, None, "Conflicting observations prevent a safe action."
    if (
        states & (DELETE_STATES | REDACTION_STATES | ANONYMIZATION_STATES)
        and states & POSITIVE_STATES
    ) or len(states & (DELETE_STATES | REDACTION_STATES | ANONYMIZATION_STATES)) > 1:
        return UNRESOLVED, None, "Conflicting states exist at the latest observation."

    finding = latest[-1]
    state = _state(finding)
    normalized_action = action.strip().upper()
    satisfied_states = {
        "DELETE": DELETE_STATES,
        "REDACT": REDACTION_STATES,
        "ANONYMIZE": ANONYMIZATION_STATES,
    }.get(normalized_action, set())
    if state in satisfied_states:
        return SATISFIED, finding, "The required terminal state is already observed."
    if state in POSITIVE_STATES:
        return UNMET, finding, f"The resource is explicitly {state} at audit_at."

    operation = (finding.operation or "").strip().upper()
    result = (finding.result_or_state or "").strip().upper()
    operation_matches = {
        "DELETE": {"DELETE_RECORD", "DELETE", "ERASE_RECORD"},
        "REDACT": {"REDACT_RECORD", "REDACT"},
        "ANONYMIZE": {"ANONYMIZE_RECORD", "ANONYMIZE"},
    }.get(normalized_action, set())
    if operation in operation_matches and result in FAILED_RESULTS:
        return UNMET, finding, f"The {normalized_action} operation reported {result}."
    if operation in operation_matches and result in NON_FINAL_RESULTS:
        return (
            UNRESOLVED,
            finding,
            "Operation success does not establish the final resource state.",
        )
    return UNRESOLVED, finding, "The available state does not establish completion."


def _finding_operation(category: str, action: str) -> str:
    if category == "BACKUP_ARCHIVE":
        return "REPORT_RESTORE_RISK"
    if category == "UNRESOLVED" and action == "DISABLE_DATA_FLOW":
        return "REPORT_ACTIVE_DATA_FLOW"
    if action in {"REDACT", "ANONYMIZE"}:
        return "REPORT_EXPOSED_PII"
    return "REPORT_REMAINING_RECORD"


def _append_step(
    drafts: List[_DraftStep],
    *,
    case_id: Optional[str],
    subject_id: Optional[str],
    rule_id: str,
    phase: str,
    finding: EvidenceFinding,
    operation: str,
    state: Optional[str],
    evidence_findings: Sequence[EvidenceFinding],
    reason: str,
) -> bool:
    system_id = _system_id(finding)
    if not finding.resource_id or not system_id:
        return False
    references = _unique_references(evidence_findings)
    if not references:
        return False
    drafts.append(
        _DraftStep(
            case_id=case_id,
            subject_id=subject_id,
            rule_id=rule_id,
            phase=phase,
            system_id=system_id,
            resource_id=finding.resource_id,
            operation=operation,
            state=state,
            evidence_id=_evidence_id(evidence_findings),
            evidence_references=references,
            reason=reason,
        )
    )
    return True


def _plan_rule(
    policy: PolicyResult,
    subject_id: str,
    assessment: RuleAssessment,
    analysis: RequestEvidenceAnalysis,
    drafts: List[_DraftStep],
    notes: Set[str],
) -> None:
    if assessment.outcome in {SATISFIED, PERMITTED_RETENTION}:
        return
    if assessment.outcome not in {UNMET, UNRESOLVED}:
        notes.add(
            f"{assessment.rule_id}: unsupported policy outcome "
            f"{assessment.outcome!r}; no action proposed."
        )
        return

    category = assessment.data_category
    action = assessment.required_action.strip().upper()
    by_resource = _assessment_findings(assessment, analysis)
    if not by_resource:
        notes.add(
            f"{assessment.rule_id}: {assessment.reason} No owned resource and "
            "audit-time evidence jointly support a proposed step."
        )
        return

    if assessment.rule_id == "EVIDENCE_CONFLICT":
        notes.add(
            "Evidence conflict: preserve both source records for human review; "
            "no destructive action is safe."
        )
        return

    if category == "UNRESOLVED" and action == "RESOLVE_CONFLICT":
        notes.add(
            f"{assessment.rule_id}: conflicting observations require review; "
            "no operation is proposed."
        )
        return

    for resource_id in sorted(by_resource, key=str.casefold):
        resource_findings = by_resource[resource_id]
        eligible = _eligible_findings(resource_findings)
        if not eligible:
            notes.add(
                f"{assessment.rule_id} / {resource_id}: findings have no reliable "
                "event timestamp at or before audit_at; no action proposed."
            )
            continue
        if any(finding.conflict_references for finding in eligible):
            notes.add(
                f"{assessment.rule_id} / {resource_id}: conflicting source states "
                "require review; no destructive action proposed."
            )
            continue

        latest = eligible[-1]
        if action == "RETAIN":
            if category == "BACKUP_ARCHIVE":
                restore_values = {
                    _attributes(finding).get("restore_allowed", "").casefold()
                    for finding in eligible
                }
                if restore_values & {"true", "1", "yes"}:
                    operation = "BLOCK_RESTORE"
                    verification = "VERIFY_RESTORE_BLOCKED"
                    finding_state = "PRESENT"
                else:
                    notes.add(
                        f"{assessment.rule_id} / {resource_id}: retention or "
                        "restore state is unresolved; do not delete retained data."
                    )
                    continue
            else:
                notes.add(
                    f"{assessment.rule_id} / {resource_id}: retention evidence is "
                    "unresolved; do not propose deletion."
                )
                continue
            _append_step(
                drafts,
                case_id=policy.case_id,
                subject_id=subject_id,
                rule_id=assessment.rule_id,
                phase="FINDING",
                finding=latest,
                operation="REPORT_RESTORE_RISK",
                state=finding_state,
                evidence_findings=eligible,
                reason=assessment.reason,
            )
            _append_step(
                drafts,
                case_id=policy.case_id,
                subject_id=subject_id,
                rule_id=assessment.rule_id,
                phase="REMEDIATION",
                finding=latest,
                operation=operation,
                state=None,
                evidence_findings=eligible,
                reason="The supplied evidence says restore access is allowed; block restore without deleting the retained archive.",
            )
            _append_step(
                drafts,
                case_id=policy.case_id,
                subject_id=subject_id,
                rule_id=assessment.rule_id,
                phase="VERIFICATION",
                finding=latest,
                operation=verification,
                state="BLOCKED",
                evidence_findings=eligible,
                reason="Verify the restore restriction after it is applied.",
            )
            continue

        if category == "UNRESOLVED" and resource_id.casefold().startswith("data_flow_"):
            attributes = [_attributes(finding) for finding in eligible]
            is_active = any(
                values.get("enabled", "").casefold() in {"true", "1", "yes"}
                or values.get("last_delivery_status", "").casefold()
                in {"active", "delivered", "running"}
                for values in attributes
            )
            if is_active:
                _append_step(
                    drafts,
                    case_id=policy.case_id,
                    subject_id=subject_id,
                    rule_id=assessment.rule_id,
                    phase="FINDING",
                    finding=latest,
                    operation="REPORT_ACTIVE_DATA_FLOW",
                    state="ACTIVE",
                    evidence_findings=eligible,
                    reason="An at-cutoff connector record reports active processing.",
                )
                _append_step(
                    drafts,
                    case_id=policy.case_id,
                    subject_id=subject_id,
                    rule_id=assessment.rule_id,
                    phase="REMEDIATION",
                    finding=latest,
                    operation="DISABLE_DATA_FLOW",
                    state=None,
                    evidence_findings=eligible,
                    reason="Stop the evidenced active downstream processing flow.",
                )
            else:
                notes.add(
                    f"{assessment.rule_id} / {resource_id}: flow state is not "
                    "explicitly active; propose verification only."
                )
            _append_step(
                drafts,
                case_id=policy.case_id,
                subject_id=subject_id,
                rule_id=assessment.rule_id,
                phase="VERIFICATION",
                finding=latest,
                operation="VERIFY_DATA_FLOW_DISABLED",
                state="DISABLED",
                evidence_findings=eligible,
                reason="Verify the connector is disabled and no longer delivering.",
            )
            continue

        if category == "ACCOUNT_TOMBSTONE":
            notes.add(
                f"{assessment.rule_id} / {resource_id}: rule 15's stable-user-id "
                "condition is unresolved; do not alter the tombstone."
            )
            continue

        if category == "SUPPORT_MESSAGE" and assessment.outcome == UNRESOLVED:
            _append_step(
                drafts,
                case_id=policy.case_id,
                subject_id=subject_id,
                rule_id=assessment.rule_id,
                phase="FINDING",
                finding=latest,
                operation="REPORT_REMAINING_RECORD",
                state="PRESENT",
                evidence_findings=eligible,
                reason="The linked support record exists, but the shared-context condition is unresolved.",
            )
            notes.add(
                f"{assessment.rule_id} / {resource_id}: shared-context applicability "
                "is unresolved; no redaction is proposed."
            )
            continue

        local_outcome, action_finding, local_reason = _local_action_state(
            action, resource_findings
        )
        verification = {
            "DELETE": "VERIFY_RECORD_ABSENT",
            "REDACT": "VERIFY_RECORD_REDACTED",
            "ANONYMIZE": "VERIFY_RECORD_ANONYMIZED",
        }.get(action)
        remediation = {
            "DELETE": "DELETE_RECORD",
            "REDACT": "REDACT_RECORD",
            "ANONYMIZE": "ANONYMIZE_RECORD",
        }.get(action)
        desired_state = _desired_state(action)
        if verification is None or remediation is None or desired_state is None:
            notes.add(
                f"{assessment.rule_id} / {resource_id}: no supplied/sample-backed "
                f"operation maps safely to action {action!r}."
            )
            continue
        if local_outcome == SATISFIED:
            continue
        if action_finding is None:
            notes.add(
                f"{assessment.rule_id} / {resource_id}: {local_reason}"
            )
            continue
        if not _system_id(action_finding):
            notes.add(
                f"{assessment.rule_id} / {resource_id}: system identifier is "
                "missing; no operation can be targeted safely."
            )
            continue

        finding_state = _state(action_finding)
        if local_outcome == UNMET:
            _append_step(
                drafts,
                case_id=policy.case_id,
                subject_id=subject_id,
                rule_id=assessment.rule_id,
                phase="FINDING",
                finding=action_finding,
                operation=_finding_operation(category, action),
                state=finding_state or "PRESENT",
                evidence_findings=eligible,
                reason=local_reason,
            )
            _append_step(
                drafts,
                case_id=policy.case_id,
                subject_id=subject_id,
                rule_id=assessment.rule_id,
                phase="REMEDIATION",
                finding=action_finding,
                operation=remediation,
                state=None,
                evidence_findings=eligible,
                reason=f"Rule {assessment.rule_id} requires {action}; {local_reason}",
            )
        else:
            notes.add(
                f"{assessment.rule_id} / {resource_id}: state is unresolved; "
                "no destructive remediation is proposed pending verification."
            )
        _append_step(
            drafts,
            case_id=policy.case_id,
            subject_id=subject_id,
            rule_id=assessment.rule_id,
            phase="VERIFICATION",
            finding=action_finding,
            operation=verification,
            state=desired_state,
            evidence_findings=eligible,
            reason=f"Verify the required {desired_state} state after review or remediation.",
        )


def plan_remediation(
    policy: PolicyResult,
    resolution: IdentityResolution,
    analysis: RequestEvidenceAnalysis,
) -> RemediationPlan:
    """Plan deterministic, evidence-backed steps for one policy result.

    This function proposes steps only; it never executes the named operations.
    """
    if (
        policy.case_id != resolution.case_id
        or policy.case_id != analysis.case_id
    ):
        raise ValueError(
            "Policy result, identity resolution, and evidence analysis must have "
            "the same case_id."
        )

    confirmed_subjects = {
        candidate.user_id for candidate in resolution.candidates
    }
    subject_id = (
        next(iter(confirmed_subjects))
        if resolution.status == CONFIRMED and len(confirmed_subjects) == 1
        else None
    )
    if subject_id is None:
        return RemediationPlan(
            case_id=policy.case_id,
            subject_id=None,
            identity_status=resolution.status,
            steps=(),
            unresolved_obligations=(
                "Identity ownership is not uniquely confirmed; no resource-specific "
                "remediation is proposed.",
            ),
        )

    drafts: List[_DraftStep] = []
    notes: Set[str] = set()
    for assessment in policy.rule_assessments:
        _plan_rule(policy, subject_id, assessment, analysis, drafts, notes)

    unique_drafts: Dict[Tuple[object, ...], _DraftStep] = {}
    for draft in drafts:
        key = (
            draft.case_id,
            draft.subject_id,
            draft.rule_id,
            draft.phase,
            draft.system_id,
            draft.resource_id,
            draft.operation,
            draft.state,
            draft.evidence_references,
        )
        unique_drafts.setdefault(key, draft)

    ordered = sorted(
        unique_drafts.values(),
        key=lambda draft: (
            PHASE_ORDER[draft.phase],
            (draft.system_id or "").casefold(),
            (draft.resource_id or "").casefold(),
            draft.rule_id.casefold(),
            draft.operation.casefold(),
            draft.evidence_references,
        ),
    )
    steps = tuple(
        RemediationStep(
            step_no=index,
            case_id=draft.case_id,
            subject_id=draft.subject_id,
            rule_id=draft.rule_id,
            phase=draft.phase,
            system_id=draft.system_id,
            resource_id=draft.resource_id,
            operation=draft.operation,
            state=draft.state,
            evidence_id=draft.evidence_id,
            evidence_references=draft.evidence_references,
            reason=draft.reason,
        )
        for index, draft in enumerate(ordered, start=1)
    )
    return RemediationPlan(
        case_id=policy.case_id,
        subject_id=subject_id,
        identity_status=resolution.status,
        steps=steps,
        unresolved_obligations=tuple(sorted(notes)),
    )


def plan_all_requests(
    dataset: Dataset,
    resolutions: Optional[Sequence[IdentityResolution]] = None,
    analyses: Optional[Sequence[RequestEvidenceAnalysis]] = None,
    policies: Optional[Sequence[PolicyResult]] = None,
) -> Tuple[RemediationPlan, ...]:
    """Plan the full request set in dataset order, validating aligned inputs."""
    if resolutions is None:
        resolutions = resolve_all_requests(dataset)
    if analyses is None:
        analyses = analyze_all_requests(dataset, resolutions)
    if policies is None:
        policies = evaluate_all_requests(dataset, resolutions, analyses)

    count = len(dataset.deletion_requests)
    if len(resolutions) != count or len(analyses) != count or len(policies) != count:
        raise ValueError(
            "Resolutions, analyses, and policy results must match deletion_requests: "
            f"requests={count}, resolutions={len(resolutions)}, "
            f"analyses={len(analyses)}, policies={len(policies)}"
        )
    plans = []
    for request, resolution, analysis, policy in zip(
        dataset.deletion_requests, resolutions, analyses, policies
    ):
        case_id = request.get("case_id")
        if (
            case_id != resolution.case_id
            or case_id != analysis.case_id
            or case_id != policy.case_id
        ):
            raise ValueError(
                "Planner inputs must match deletion requests in order: "
                f"{case_id!r}, {resolution.case_id!r}, "
                f"{analysis.case_id!r}, {policy.case_id!r}"
            )
        plans.append(plan_remediation(policy, resolution, analysis))
    return tuple(plans)