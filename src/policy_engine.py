"""Conservative, evidence-backed policy evaluation for deletion requests.

This is a provisional interpretation of the supplied deletion_rules.csv, not
an official competition status contract.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Dict, List, Mapping, Optional, Sequence, Set, Tuple

if __package__:
    from .data_loader import Dataset
    from .evidence_analyzer import AT_AUDIT, PRE_AUDIT, EvidenceFinding, RequestEvidenceAnalysis
    from .identity_resolver import CONFIRMED, IdentityResolution, resolve_all_requests
else:
    from data_loader import Dataset
    from evidence_analyzer import AT_AUDIT, PRE_AUDIT, EvidenceFinding, RequestEvidenceAnalysis
    from identity_resolver import CONFIRMED, IdentityResolution, resolve_all_requests


SATISFIED = "SATISFIED"
UNMET = "UNMET"
UNRESOLVED = "UNRESOLVED"
PERMITTED_RETENTION = "PERMITTED_RETENTION"

DELETION_STATES = {"ABSENT", "DELETED", "ERASED", "PURGED", "NOT_FOUND", "MISSING"}
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
NON_FINAL_RESULTS = {"SUCCESS", "OK", "COMPLETED", "COMPLETE"}
FAILED_RESULTS = {"FAILED", "FAILURE", "PARTIAL", "PARTIALLY_COMPLETE"}
LINK_ONLY_OPERATIONS = {"LINK_RESOURCE_IDENTITY"}


@dataclass(frozen=True)
class PolicyEvidenceReference:
    """A source reference retained with identifying evidence metadata."""

    evidence_id: Optional[str]
    file_path: str
    source_reference: str
    record_id: Optional[str]
    event_id: Optional[str]
    system_id: Optional[str]
    resource_id: Optional[str]
    operation: Optional[str]
    timestamp: Optional[str]
    temporal_relation: str

    @property
    def reference(self) -> str:
        """Return a stable, human-readable path and record reference."""
        return f"{self.file_path}#{self.source_reference}"


@dataclass(frozen=True)
class RuleAssessment:
    """Evaluation of one supplied rule for one identified resource scope."""

    rule_id: str
    data_category: str
    condition: str
    required_action: str
    outcome: str
    resource_ids: Tuple[str, ...]
    evidence_references: Tuple[PolicyEvidenceReference, ...]
    reason: str


@dataclass(frozen=True)
class PolicyResult:
    """One policy result for a deletion request, without remediation steps."""

    case_id: Optional[str]
    requested_identifier: Optional[str]
    deletion_status: str
    identity_status: str
    rule_assessments: Tuple[RuleAssessment, ...]
    identity_evidence_references: Tuple[str, ...]
    evidence_references: Tuple[PolicyEvidenceReference, ...]
    decision_reasons: Tuple[str, ...]
    unresolved_interpretations: Tuple[str, ...]


def _normalize(value: Optional[str]) -> str:
    return value.strip().casefold() if value else ""


def _parse_datetime(value: Optional[str]) -> Optional[datetime]:
    """Parse an offset-aware ISO timestamp and normalize it to UTC."""
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except (ValueError, OverflowError):
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _normal_state(finding: EvidenceFinding) -> Optional[str]:
    """Read a final state token, never treating operation success as a state."""
    value = finding.explicit_state or finding.result_or_state
    if value is not None:
        state = re.sub(r"[\s-]+", "_", value.strip().upper())
        if state in DELETION_STATES | REDACTION_STATES | ANONYMIZATION_STATES:
            return state
        if state in POSITIVE_STATES:
            return state
    attributes = _policy_attributes(finding)
    status_code = attributes.get("http_status") or attributes.get("status_code")
    row_count = attributes.get("rows")
    operation = f"{finding.operation or ''} {finding.source_reference}".casefold()
    if (
        status_code == "404"
        and (
            row_count == "0"
            or "profile_lookups[" in operation
        )
        and any(token in operation for token in ("lookup", "query", "read"))
    ):
        return "ABSENT"
    identifier_fields = (
        "customer_reference",
        "email",
        "phone",
        "email_hash",
    )
    context = (
        f"{finding.system_id or ''} {finding.source_reference}"
    ).casefold()
    if (
        any(token in context for token in ("analytics", "telemetry"))
        and all(attributes.get(field, "").casefold() == "null" for field in identifier_fields)
    ):
        return "ANONYMIZED"
    return None


def _policy_attributes(finding: EvidenceFinding) -> Dict[str, str]:
    return {
        key.rsplit(".", 1)[-1].casefold(): value.strip()
        for key, value in finding.policy_attributes
        if value.strip()
    }


def _category_for_finding(
    finding: EvidenceFinding, rule_categories: Set[str]
) -> Set[str]:
    """Resolve categories from explicit record types or narrow source markers."""
    categories: Set[str] = set()
    for value in (finding.data_category, finding.operation):
        normalized = value.strip().upper().replace(" ", "_") if value else ""
        if normalized in rule_categories:
            categories.add(normalized)

    system = " ".join(
        value or ""
        for value in (
            finding.system_id,
            finding.source_system,
            finding.target_system,
        )
    ).casefold()
    resource = (finding.resource_id or "").casefold()
    source = finding.file_path.casefold()
    source_reference = finding.source_reference.casefold()
    operation = (finding.operation or "").casefold()
    context = f"{system} {resource} {source} {source_reference} {operation}"

    if "USER_PROFILE" in rule_categories and (
        "account_service" in context or resource.startswith("account_")
    ):
        categories.add("USER_PROFILE")
    if "SEARCH_INDEX_ENTRY" in rule_categories and (
        "search_service" in context or resource.startswith("search_")
    ):
        categories.add("SEARCH_INDEX_ENTRY")
    if "CACHE_ENTRY" in rule_categories and (
        "cache_service" in system or resource.startswith("cache_")
    ):
        categories.add("CACHE_ENTRY")
    if "ANALYTICS_PROFILE" in rule_categories and (
        "analytics" in context or resource.startswith("analytics_")
    ):
        categories.add("ANALYTICS_PROFILE")
    if "PRODUCT_TELEMETRY" in rule_categories and (
        "telemetry" in context or resource.startswith("telemetry_")
    ):
        categories.add("PRODUCT_TELEMETRY")
    if "SUPPORT_ATTACHMENT" in rule_categories and (
        "attachment" in context or resource.startswith("attachment_")
    ):
        categories.add("SUPPORT_ATTACHMENT")
    if "SUPPORT_MESSAGE" in rule_categories and (
        "support_message" in context
        or "support message" in context
        or ".support_platform.tickets[" in source_reference
        or resource.startswith("message_")
    ):
        categories.add("SUPPORT_MESSAGE")
    if "USER_EXPORT" in rule_categories and (
        "export_service" in context or resource.startswith("export_")
    ):
        categories.add("USER_EXPORT")
    if "MARKETING_PROFILE" in rule_categories and (
        "marketing" in context or resource.startswith("marketing_")
    ):
        categories.add("MARKETING_PROFILE")
    if "EMAIL_DELIVERY_LOG" in rule_categories and (
        "email_delivery" in system
        or "mail_service" in system
        or operation == "send_email"
    ):
        categories.add("EMAIL_DELIVERY_LOG")
    if "SECURITY_AUDIT_LOG" in rule_categories and (
        "security_service" in context or resource.startswith("audit_record_")
    ):
        categories.add("SECURITY_AUDIT_LOG")
    if "LEGAL_HOLD_RECORD" in rule_categories and (
        "legal_hold" in context or resource.startswith("legal_hold_")
    ):
        categories.add("LEGAL_HOLD_RECORD")
    if "BACKUP_ARCHIVE" in rule_categories and (
        "backup_service" in context or resource.startswith("backup_")
    ):
        categories.add("BACKUP_ARCHIVE")
    if "ACCOUNT_TOMBSTONE" in rule_categories and (
        "tombstone" in context or resource.startswith("tombstone_")
    ):
        categories.add("ACCOUNT_TOMBSTONE")
    if "SECONDARY_IDENTIFIER" in rule_categories and (
        "secondary_identifier" in context
        or "secondary identifier" in context
        or resource.startswith("identifier_")
    ):
        categories.add("SECONDARY_IDENTIFIER")

    return categories


def _reference(finding: EvidenceFinding) -> PolicyEvidenceReference:
    system_id = finding.system_id or finding.source_system or finding.target_system
    if system_id is None:
        service_match = re.search(
            r"\.service_exports\.([a-z0-9_-]+)\.", finding.source_reference.casefold()
        )
        if service_match:
            system_id = service_match.group(1)
    return PolicyEvidenceReference(
        evidence_id=finding.evidence_id,
        file_path=finding.file_path,
        source_reference=finding.source_reference,
        record_id=finding.record_id,
        event_id=finding.event_id,
        system_id=system_id,
        resource_id=finding.resource_id,
        operation=finding.operation,
        timestamp=finding.timestamp,
        temporal_relation=finding.temporal_relation,
    )


def _eligible_at_audit(finding: EvidenceFinding, audit_at: Optional[str]) -> bool:
    event_time = _parse_datetime(finding.timestamp)
    cutoff = _parse_datetime(audit_at)
    return (
        event_time is not None
        and cutoff is not None
        and event_time <= cutoff
        and finding.temporal_relation in {PRE_AUDIT, AT_AUDIT}
        and finding.as_of_audit
    )


def _resource_key(finding: EvidenceFinding) -> str:
    if finding.resource_id:
        return _normalize(finding.resource_id)
    return f"{finding.file_path}#{finding.source_reference}".casefold()


def _group_resources(
    findings: Sequence[EvidenceFinding],
) -> Dict[str, List[EvidenceFinding]]:
    grouped: Dict[str, List[EvidenceFinding]] = {}
    for finding in findings:
        grouped.setdefault(_resource_key(finding), []).append(finding)
    return grouped


def _action_outcome(
    action: str,
    latest_state: Optional[str],
    latest_finding: EvidenceFinding,
) -> Tuple[str, str]:
    normalized_action = action.strip().upper()
    result = (latest_finding.result_or_state or "").strip().upper()
    operation = (latest_finding.operation or "").strip().upper()
    action_operations = {
        "DELETE": {"DELETE_RECORD", "DELETE", "ERASE_RECORD"},
        "REDACT": {"REDACT_RECORD", "REDACT"},
        "ANONYMIZE": {"ANONYMIZE_RECORD", "ANONYMIZE"},
    }
    if (
        result in FAILED_RESULTS
        and operation in action_operations.get(normalized_action, set())
    ):
        return UNMET, f"The {normalized_action.lower()} operation explicitly reported {result}."

    if normalized_action == "DELETE":
        if latest_state in DELETION_STATES:
            return SATISFIED, f"Explicit terminal state {latest_state} verifies absence."
        if latest_state in POSITIVE_STATES:
            return UNMET, f"Explicit state {latest_state} shows the resource remains."
        if operation in action_operations["DELETE"] and result in NON_FINAL_RESULTS:
            return (
                UNRESOLVED,
                "A successful deletion operation is not final-state verification.",
            )
        return UNRESOLVED, "No explicit deletion or absence state is available at audit_at."

    if normalized_action == "REDACT":
        if latest_state in REDACTION_STATES:
            return SATISFIED, "Explicit REDACTED state verifies the required treatment."
        if latest_state in POSITIVE_STATES:
            return UNMET, f"Explicit state {latest_state} shows the record remains attributable."
        return UNRESOLVED, "No explicit redaction state is available at audit_at."

    if normalized_action == "ANONYMIZE":
        if latest_state in ANONYMIZATION_STATES:
            return SATISFIED, "Explicit anonymized state verifies the required treatment."
        if latest_state in POSITIVE_STATES:
            return UNMET, f"Explicit state {latest_state} shows the record remains attributable."
        return UNRESOLVED, "No explicit anonymization state is available at audit_at."

    return UNRESOLVED, f"Unsupported required_action value: {action!r}."


def _condition_outcome(
    rule: Mapping[str, str],
    findings: Sequence[EvidenceFinding],
    request: Mapping[str, object],
) -> Optional[Tuple[str, str]]:
    """Return an explicit outcome for conditional retention/action rules."""
    category = rule["data_category"].strip().upper()
    action = rule["required_action"].strip().upper()
    audit_value = request.get("audit_at")
    audit_at = audit_value if isinstance(audit_value, str) else None
    cutoff = _parse_datetime(audit_at)
    if cutoff is None:
        return UNRESOLVED, "The request audit_at is missing or invalid."

    eligible = [finding for finding in findings if _eligible_at_audit(finding, audit_at)]
    if not eligible:
        return UNRESOLVED, "The category is only supported by post-audit or untimed evidence."

    states = {_normal_state(finding) for finding in eligible}
    states.discard(None)
    attributes = [_policy_attributes(finding) for finding in eligible]

    if category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
        if states & ANONYMIZATION_STATES:
            return SATISFIED, "Explicit anonymized state satisfies the conditional action."
        if any(finding.matched_identifiers for finding in eligible):
            return None
        return UNRESOLVED, "Evidence does not establish whether the record remains attributable."

    if category == "EMAIL_DELIVERY_LOG":
        if states & REDACTION_STATES:
            return SATISFIED, "Explicit REDACTED state verifies the email-log treatment."
        if any("@" in identifier for finding in eligible
               for identifier in finding.matched_identifiers):
            return None
        return UNRESOLVED, "Evidence does not establish that the log contains a user email address."

    if category == "SUPPORT_MESSAGE":
        if states & REDACTION_STATES:
            return SATISFIED, "Explicit REDACTED state verifies the message treatment."
        return UNRESOLVED, (
            "The supplied evidence does not establish whether shared customer, "
            "agent, or order context must be retained."
        )

    if category == "SECURITY_AUDIT_LOG":
        for values in attributes:
            retention_until = _parse_datetime(values.get("retention_until"))
            if retention_until is not None and retention_until > cutoff:
                return (
                    PERMITTED_RETENTION,
                    "A supplied retention_until value extends beyond audit_at.",
                )
        return UNRESOLVED, (
            "The evidence does not establish that the record is within a supplied "
            "retention period."
        )

    if category == "LEGAL_HOLD_RECORD":
        if "ACTIVE" in states:
            return PERMITTED_RETENTION, (
                "An explicit ACTIVE state supports the supplied legal-hold exception."
            )
        return UNRESOLVED, "The supplied evidence does not establish an active legal hold."

    if category == "BACKUP_ARCHIVE":
        values = {
            value.casefold()
            for attributes_for_finding in attributes
            for key, value in attributes_for_finding.items()
            if key == "restore_allowed"
        }
        if values & {"false", "0", "no"}:
            return PERMITTED_RETENTION, (
                "restore_allowed is explicitly false at or before audit_at."
            )
        if values & {"true", "1", "yes"}:
            return UNMET, (
                "Restore access is explicitly allowed; the retention condition is not secured."
            )
        return UNRESOLVED, "Evidence does not establish that restore access is blocked."

    if category == "ACCOUNT_TOMBSTONE":
        return UNRESOLVED, (
            "The evidence does not establish that only a stable internal user_id "
            "remains in the tombstone."
        )

    if action == "RETAIN":
        return UNRESOLVED, "The supplied rule's retention condition is not established."
    return None


def _assess_rule(
    rule: Mapping[str, str],
    findings: Sequence[EvidenceFinding],
    request: Mapping[str, object],
) -> RuleAssessment:
    category = rule["data_category"].strip().upper()
    action = rule["required_action"].strip().upper()
    references = tuple(_reference(finding) for finding in findings)
    resources = tuple(
        sorted(
            {finding.resource_id for finding in findings if finding.resource_id},
            key=str.casefold,
        )
    )

    conditional = _condition_outcome(rule, findings, request)
    if conditional is not None:
        outcome, reason = conditional
        if outcome in {SATISFIED, PERMITTED_RETENTION, UNMET, UNRESOLVED}:
            return RuleAssessment(
                rule_id=rule["rule_id"],
                data_category=category,
                condition=rule["condition"],
                required_action=action,
                outcome=outcome,
                resource_ids=resources,
                evidence_references=references,
                reason=reason,
            )

    audit_value = request.get("audit_at")
    audit_at = audit_value if isinstance(audit_value, str) else None
    results: List[Tuple[str, str]] = []
    for resource_findings in _group_resources(findings).values():
        eligible = [
            finding
            for finding in resource_findings
            if _eligible_at_audit(finding, audit_at)
        ]
        if not eligible:
            results.append(
                (
                    UNRESOLVED,
                    "This resource has no timestamped evidence at or before audit_at.",
                )
            )
            continue
        ordered = sorted(
            eligible,
            key=lambda finding: _parse_datetime(finding.timestamp)
            or datetime.max.replace(tzinfo=timezone.utc),
        )
        latest = ordered[-1]
        instant = _parse_datetime(latest.timestamp)
        at_same_instant = [
            finding for finding in eligible
            if _parse_datetime(finding.timestamp) == instant
        ]
        states = {
            state for finding in at_same_instant
            if (state := _normal_state(finding)) is not None
        }
        terminal_states = states & (
            DELETION_STATES | REDACTION_STATES | ANONYMIZATION_STATES
        )
        if (
            (terminal_states and states & POSITIVE_STATES)
            or len(terminal_states) > 1
        ):
            results.append(
                (
                    UNRESOLVED,
                    "Contradictory explicit states exist for this resource at the same instant.",
                )
            )
            continue
        results.append(_action_outcome(action, _normal_state(latest), latest))

    outcomes = {outcome for outcome, _ in results}
    if UNMET in outcomes:
        outcome = UNMET
    elif UNRESOLVED in outcomes:
        outcome = UNRESOLVED
    else:
        outcome = SATISFIED
    reason = " ".join(dict.fromkeys(reason for _, reason in results))
    return RuleAssessment(
        rule_id=rule["rule_id"],
        data_category=category,
        condition=rule["condition"],
        required_action=action,
        outcome=outcome,
        resource_ids=resources,
        evidence_references=references,
        reason=reason,
    )


def evaluate_request(
    dataset: Dataset,
    request: Mapping[str, object],
    resolution: IdentityResolution,
    analysis: RequestEvidenceAnalysis,
) -> PolicyResult:
    """Evaluate one request against supplied rules and its audit-cutoff evidence."""
    raw_case_id = request.get("case_id")
    case_id = raw_case_id if isinstance(raw_case_id, str) else None
    raw_identifier = request.get("email")
    requested_identifier = raw_identifier if isinstance(raw_identifier, str) else None
    if resolution.case_id != case_id or analysis.case_id != case_id:
        raise ValueError(
            "Request, identity resolution, and evidence analysis must have the same case_id."
        )
    audit_value = request.get("audit_at")
    audit_at = audit_value if isinstance(audit_value, str) else None

    rules_by_category: Dict[str, Mapping[str, str]] = {}
    for rule in dataset.deletion_rules:
        category = rule["data_category"].strip().upper()
        if category in rules_by_category:
            raise ValueError(f"Duplicate deletion rule for data category {category!r}.")
        rules_by_category[category] = rule

    categorized: Dict[str, List[EvidenceFinding]] = {
        category: [] for category in rules_by_category
    }
    unmapped: List[EvidenceFinding] = []
    findings_by_resource: Dict[str, List[EvidenceFinding]] = {}
    rule_categories = set(rules_by_category)
    categories_by_index: Dict[int, Set[str]] = {}
    categories_by_resource: Dict[str, Set[str]] = {}
    for index, finding in enumerate(analysis.findings):
        categories = _category_for_finding(finding, rule_categories)
        categories_by_index[index] = categories
        if finding.resource_id:
            resource_key = _normalize(finding.resource_id)
            findings_by_resource.setdefault(resource_key, []).append(finding)
            categories_by_resource.setdefault(resource_key, set()).update(categories)

    for index, finding in enumerate(analysis.findings):
        categories = categories_by_index[index]
        if not categories and finding.resource_id:
            categories = categories_by_resource.get(
                _normalize(finding.resource_id), set()
            )
        if not categories and finding.resource_id:
            if (finding.operation or "").strip().upper() not in LINK_ONLY_OPERATIONS:
                unmapped.append(finding)
        for category in categories:
            categorized[category].append(finding)

    unresolved_flow_resources = set()
    for resource_key, resource_findings in findings_by_resource.items():
        if not resource_key.startswith("data_flow_"):
            continue
        eligible = [
            finding
            for finding in resource_findings
            if _eligible_at_audit(finding, audit_at)
        ]
        flow_states = [
            _policy_attributes(finding)
            for finding in eligible
            if _policy_attributes(finding).get("enabled")
            or _policy_attributes(finding).get("last_delivery_status")
        ]
        if not any(
            values.get("enabled", "").casefold() in {"false", "0", "no"}
            and values.get("last_delivery_status", "").casefold() in {"stopped", "disabled"}
            for values in flow_states
        ):
            unresolved_flow_resources.add(resource_key)

    unmapped = [
        finding
        for finding in unmapped
        if not (
            _normalize(finding.resource_id).startswith("data_flow_")
            and _normalize(finding.resource_id) not in unresolved_flow_resources
        )
    ]

    assessments: List[RuleAssessment] = []
    for category, rule in rules_by_category.items():
        category_findings = categorized[category]
        unconditional_profile = (
            category == "USER_PROFILE"
            and rule["condition"].strip().casefold() == "always"
        )
        if not category_findings and not unconditional_profile:
            continue
        if not category_findings:
            assessments.append(
                RuleAssessment(
                    rule_id=rule["rule_id"],
                    data_category=category,
                    condition=rule["condition"],
                    required_action=rule["required_action"],
                    outcome=UNRESOLVED,
                    resource_ids=(),
                    evidence_references=(),
                    reason=(
                        "The USER_PROFILE rule is unconditional, but no "
                        "identity-linked profile resource is evidenced."
                    ),
                )
            )
        else:
            assessments.append(_assess_rule(rule, category_findings, request))

    if unmapped:
        assessments.append(
            RuleAssessment(
                rule_id="UNMAPPED_EVIDENCE",
                data_category="UNRESOLVED",
                condition="Identity-linked resource requires policy categorization.",
                required_action="UNRESOLVED",
                outcome=UNRESOLVED,
                resource_ids=tuple(
                    sorted(
                        {finding.resource_id for finding in unmapped if finding.resource_id},
                        key=str.casefold,
                    )
                ),
                evidence_references=tuple(_reference(finding) for finding in unmapped),
                reason=(
                    "An identity-linked resource was found, but its category does "
                    "not match a supplied deletion rule."
                ),
            )
        )

    conflicts = []
    for conflict in analysis.conflicts:
        event_time = _parse_datetime(conflict.timestamp)
        cutoff = _parse_datetime(audit_at)
        if event_time is not None and cutoff is not None and event_time <= cutoff:
            conflicts.append(conflict)
    conflict_findings = [
        finding
        for finding in analysis.findings
        if finding.conflict_references and _eligible_at_audit(finding, audit_at)
    ]
    if conflicts or conflict_findings:
        conflict_refs = [_reference(finding) for finding in conflict_findings]
        for conflict in conflicts:
            for reference in conflict.evidence_references:
                file_path, _, source_reference = reference.partition("#")
                conflict_refs.append(
                    PolicyEvidenceReference(
                        evidence_id=None,
                        file_path=file_path,
                        source_reference=source_reference,
                        record_id=None,
                        event_id=None,
                        system_id=None,
                        resource_id=conflict.resource_id,
                        operation=None,
                        timestamp=conflict.timestamp,
                        temporal_relation=AT_AUDIT,
                    )
                )
        deduplicated = {
            reference.reference: reference for reference in conflict_refs
        }
        assessments.append(
            RuleAssessment(
                rule_id="EVIDENCE_CONFLICT",
                data_category="UNRESOLVED",
                condition="Explicit states must not conflict at the audit cutoff.",
                required_action="RESOLVE_CONFLICT",
                outcome=UNRESOLVED,
                resource_ids=tuple(
                    sorted({conflict.resource_id for conflict in conflicts}, key=str.casefold)
                ),
                evidence_references=tuple(
                    deduplicated[key] for key in sorted(deduplicated)
                ),
                reason="Conflicting explicit evidence exists at or before audit_at.",
            )
        )

    reasons: List[str] = []
    if resolution.status != CONFIRMED:
        reasons.append(
            f"Identity resolution is {resolution.status}; policy evidence cannot be confidently attributed."
        )
    if _parse_datetime(audit_at) is None:
        reasons.append("The audit_at timestamp is missing, invalid, or timezone-naive.")
    for assessment in assessments:
        if assessment.outcome in {UNMET, UNRESOLVED}:
            reasons.append(f"{assessment.rule_id}: {assessment.reason}")
    if (
        resolution.status == CONFIRMED
        and assessments
        and not any(
            assessment.outcome in {UNMET, UNRESOLVED}
            for assessment in assessments
        )
    ):
        reasons.append(
            "All evaluated applicable rules are supported by eligible evidence at or before audit_at."
        )
    if not assessments:
        reasons.append("No applicable deletion rule could be evaluated from the supplied data.")

    blocking = any(
        assessment.outcome in {UNMET, UNRESOLVED}
        for assessment in assessments
    )
    has_profile_rule = any(
        assessment.data_category == "USER_PROFILE" for assessment in assessments
    )
    if resolution.status != CONFIRMED or blocking or not has_profile_rule:
        deletion_status = "INCOMPLETE"
    else:
        deletion_status = "COMPLETE"

    all_references = [_reference(finding) for finding in analysis.findings]
    all_references.extend(
        reference
        for assessment in assessments
        for reference in assessment.evidence_references
    )
    unique_references = {
        reference.reference: reference for reference in all_references
    }
    return PolicyResult(
        case_id=case_id,
        requested_identifier=requested_identifier,
        deletion_status=deletion_status,
        identity_status=resolution.status,
        rule_assessments=tuple(assessments),
        identity_evidence_references=resolution.evidence_references,
        evidence_references=tuple(
            unique_references[key] for key in sorted(unique_references)
        ),
        decision_reasons=tuple(dict.fromkeys(reasons)),
        unresolved_interpretations=(
            "Provisional status mapping: insufficient or ambiguous evidence is INCOMPLETE; "
            "this mapping is not confirmed by an official competition specification.",
            "The supplied rules do not define an exhaustive resource inventory. Categories "
            "not identified in evidence are not treated as deleted or as proof that a "
            "category is absent.",
            "NOT_APPLICABLE is not emitted: the supplied rules include an unconditional "
            "USER_PROFILE deletion obligation, and the request schema has no explicit "
            "out-of-scope indicator.",
        ),
    )


def evaluate_all_requests(
    dataset: Dataset,
    resolutions: Optional[Sequence[IdentityResolution]] = None,
    analyses: Optional[Sequence[RequestEvidenceAnalysis]] = None,
) -> Tuple[PolicyResult, ...]:
    """Evaluate all full-dataset requests, preserving their original order."""
    if resolutions is None:
        resolutions = resolve_all_requests(dataset)
    if analyses is None:
        if __package__:
            from .evidence_analyzer import analyze_all_requests
        else:
            from evidence_analyzer import analyze_all_requests
        analyses = analyze_all_requests(dataset, resolutions)

    count = len(dataset.deletion_requests)
    if len(resolutions) != count or len(analyses) != count:
        raise ValueError(
            "Identity resolutions and evidence analyses must match deletion_requests: "
            f"requests={count}, resolutions={len(resolutions)}, analyses={len(analyses)}"
        )
    results = []
    for request, resolution, analysis in zip(
        dataset.deletion_requests, resolutions, analyses
    ):
        if request.get("case_id") != resolution.case_id:
            raise ValueError(
                "Identity resolutions must match deletion requests in order: "
                f"{request.get('case_id')!r} != {resolution.case_id!r}"
            )
        if request.get("case_id") != analysis.case_id:
            raise ValueError(
                "Evidence analyses must match deletion requests in order: "
                f"{request.get('case_id')!r} != {analysis.case_id!r}"
            )
        results.append(evaluate_request(dataset, request, resolution, analysis))
    return tuple(results)
