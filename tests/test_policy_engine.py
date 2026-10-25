"""Tests for the provisional deletion policy engine."""

from dataclasses import replace
import unittest

from src.data_loader import load_dataset
from src.evidence_analyzer import (
    AT_AUDIT,
    POST_AUDIT,
    PRE_AUDIT,
    EvidenceAnalyzer,
    EvidenceConflict,
    EvidenceFinding,
    RequestEvidenceAnalysis,
)
from src.identity_resolver import (
    CONFIRMED,
    UNCERTAIN,
    resolve_request,
)
from src.policy_engine import (
    PERMITTED_RETENTION,
    SATISFIED,
    UNMET,
    UNRESOLVED,
    evaluate_all_requests,
    evaluate_request,
)


AUDIT_AT = "2026-06-15T12:00:00Z"


def make_request(case_id: str = "case_01", audit_at: str = AUDIT_AT) -> dict:
    return {
        "case_id": case_id,
        "email": "person@example.test",
        "requested_at": "2026-06-01T00:00:00Z",
        "reported_status": "COMPLETE",
        "reported_at": "2026-06-02T00:00:00Z",
        "audit_at": audit_at,
        "request_text": "Delete my account.",
    }


def make_identity() -> dict:
    return {
        "user_id": "user_01",
        "name": "Example Person",
        "email": "person@example.test",
        "phone": "+1 555 0100",
        "email_hash": "hash_01",
        "updated_at": "2026-01-01T00:00:00Z",
    }


def make_resolution(request: dict = None, identity_status: str = CONFIRMED):
    request = request or make_request()
    if identity_status == UNCERTAIN:
        return resolve_request(
            request,
            [
                {
                    "user_id": None,
                    "name": "Example Person",
                    "email": request["email"],
                    "phone": "",
                    "email_hash": "",
                    "updated_at": "",
                }
            ],
            [],
        )
    return resolve_request(request, [make_identity()], [])


def make_finding(
    *,
    case_id: str = "case_01",
    category: str = "USER_PROFILE",
    resource_id: str = "account_001",
    system_id: str = "account_service",
    state: str = "ABSENT",
    timestamp: str = AUDIT_AT,
    operation: str = "VERIFY_RECORD_ABSENT",
    result_or_state: str = None,
    as_of_audit: bool = True,
    temporal_relation: str = AT_AUDIT,
    attributes: tuple = (),
    matched_identifiers: tuple = ("person@example.test",),
    conflict_references: tuple = (),
    source_reference: str = "$.records[0]",
    evidence_id: str = "evidence_test",
) -> EvidenceFinding:
    return EvidenceFinding(
        case_id=case_id,
        evidence_id=evidence_id,
        file_path="evidence/test.json",
        source_reference=source_reference,
        record_id="record_test",
        event_id="event_test",
        timestamp=timestamp,
        timestamp_field="observed_at",
        source_captured_at=None,
        temporal_relation=temporal_relation,
        as_of_audit=as_of_audit,
        system_id=system_id,
        source_system=None,
        target_system=None,
        resource_id=resource_id,
        operation=operation,
        result_or_state=result_or_state or state,
        explicit_state=state,
        finding_types=("OBSERVATION",),
        match_type="DIRECT",
        matched_identifiers=matched_identifiers,
        conflict_references=conflict_references,
        data_category=category,
        policy_attributes=attributes,
    )


def make_analysis(
    request: dict,
    findings: tuple = (),
    conflicts: tuple = (),
    identity_status: str = CONFIRMED,
) -> RequestEvidenceAnalysis:
    return RequestEvidenceAnalysis(
        case_id=request["case_id"],
        requested_identifier=request["email"],
        identity_status=identity_status,
        findings=findings,
        gaps=(),
        conflicts=conflicts,
    )


class PolicyEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dataset = load_dataset()

    def evaluate(self, request: dict, findings: tuple, identity_status: str = CONFIRMED,
                 conflicts: tuple = ()):
        resolution = make_resolution(request, identity_status)
        analysis = make_analysis(request, findings, conflicts, identity_status)
        return evaluate_request(self.dataset, request, resolution, analysis)

    def test_explicit_profile_absence_at_inclusive_audit_boundary_is_complete(self) -> None:
        request = make_request()
        finding = make_finding(timestamp=request["audit_at"])

        result = self.evaluate(request, (finding,))

        self.assertEqual(result.deletion_status, "COMPLETE")
        self.assertEqual(result.case_id, request["case_id"])
        self.assertTrue(result.identity_evidence_references)
        profile = next(
            assessment
            for assessment in result.rule_assessments
            if assessment.data_category == "USER_PROFILE"
        )
        self.assertEqual(profile.outcome, SATISFIED)
        self.assertEqual(profile.resource_ids, ("account_001",))
        reference = result.evidence_references[0]
        self.assertEqual(reference.evidence_id, "evidence_test")
        self.assertEqual(reference.source_reference, "$.records[0]")
        self.assertEqual(reference.system_id, "account_service")

    def test_explicit_profile_lookup_404_verifies_profile_absence(self) -> None:
        request = make_request()
        lookup = make_finding(
            resource_id="account_404",
            state=None,
            result_or_state=None,
            operation="profile_lookup_completed",
            attributes=(("http_status", "404"),),
            source_reference="$.service_exports.account_service.profile_lookups[0]",
        )
        lookup = replace(lookup, explicit_state=None, result_or_state=None)

        result = self.evaluate(request, (lookup,))

        self.assertEqual(result.deletion_status, "COMPLETE")
        self.assertEqual(
            next(
                item for item in result.rule_assessments
                if item.data_category == "USER_PROFILE"
            ).outcome,
            SATISFIED,
        )

    def test_explicit_null_identity_fields_support_anonymization(self) -> None:
        request = make_request()
        analytics = make_finding(
            category="ANALYTICS_PROFILE",
            resource_id="analytics_001",
            system_id="analytics_platform",
            state=None,
            result_or_state=None,
            operation="analytics_profile_read_completed",
            attributes=(
                ("customer_reference", "null"),
                ("email", "null"),
                ("phone", "null"),
                ("email_hash", "null"),
            ),
        )
        analytics = replace(analytics, explicit_state=None, result_or_state=None)

        result = self.evaluate(request, (make_finding(), analytics))

        self.assertEqual(result.deletion_status, "COMPLETE")
        self.assertEqual(
            next(
                item for item in result.rule_assessments
                if item.data_category == "ANALYTICS_PROFILE"
            ).outcome,
            SATISFIED,
        )

    def test_successful_delete_operation_without_final_state_is_unresolved(self) -> None:
        request = make_request()
        finding = make_finding(
            state=None,
            result_or_state="SUCCESS",
            operation="DELETE_RECORD",
            timestamp="2026-06-14T12:00:00Z",
            temporal_relation=PRE_AUDIT,
        )
        finding = replace(finding, explicit_state=None)

        result = self.evaluate(request, (finding,))

        self.assertEqual(result.deletion_status, "INCOMPLETE")
        self.assertIn("not final-state verification", result.decision_reasons[0])

    def test_failed_delete_operation_is_explicitly_unmet(self) -> None:
        request = make_request()
        failed = make_finding(
            state=None,
            result_or_state="FAILED",
            operation="DELETE_RECORD",
            timestamp="2026-06-14T12:00:00Z",
            temporal_relation=PRE_AUDIT,
        )
        failed = replace(failed, explicit_state=None)

        result = self.evaluate(request, (failed,))

        profile = next(
            item for item in result.rule_assessments
            if item.data_category == "USER_PROFILE"
        )
        self.assertEqual(profile.outcome, UNMET)
        self.assertEqual(result.deletion_status, "INCOMPLETE")

    def test_positive_profile_state_is_incomplete(self) -> None:
        result = self.evaluate(
            make_request(),
            (make_finding(state="ACTIVE", operation="PROFILE_LOOKUP"),),
        )

        profile = next(
            assessment
            for assessment in result.rule_assessments
            if assessment.data_category == "USER_PROFILE"
        )
        self.assertEqual(result.deletion_status, "INCOMPLETE")
        self.assertEqual(profile.outcome, UNMET)

    def test_unresolved_identity_blocks_completion_even_with_absence_evidence(self) -> None:
        result = self.evaluate(
            make_request(),
            (make_finding(),),
            identity_status=UNCERTAIN,
        )

        self.assertEqual(result.deletion_status, "INCOMPLETE")
        self.assertEqual(result.identity_status, UNCERTAIN)
        self.assertTrue(result.identity_evidence_references)

    def test_partial_deletion_of_search_index_keeps_request_incomplete(self) -> None:
        request = make_request()
        findings = (
            make_finding(),
            make_finding(
                category="SEARCH_INDEX_ENTRY",
                resource_id="search_001",
                system_id="search_service",
                state="FOUND",
                operation="INDEX_LOOKUP",
            ),
        )

        result = self.evaluate(request, findings)

        search = next(
            assessment
            for assessment in result.rule_assessments
            if assessment.data_category == "SEARCH_INDEX_ENTRY"
        )
        self.assertEqual(result.deletion_status, "INCOMPLETE")
        self.assertEqual(search.outcome, UNMET)

    def test_present_user_export_is_incomplete_until_explicitly_deleted(self) -> None:
        request = make_request()
        export = make_finding(
            category="USER_EXPORT",
            resource_id="export_001",
            system_id="export_service",
            state="PRESENT",
            operation="EXPORT_LOOKUP",
        )

        result = self.evaluate(request, (make_finding(), export))

        self.assertEqual(result.deletion_status, "INCOMPLETE")
        self.assertEqual(
            next(
                item for item in result.rule_assessments
                if item.data_category == "USER_EXPORT"
            ).outcome,
            UNMET,
        )

    def test_anonymized_analytics_and_permitted_security_retention_do_not_hide_other_work(self) -> None:
        request = make_request()
        findings = (
            make_finding(),
            make_finding(
                category="ANALYTICS_PROFILE",
                resource_id="analytics_001",
                system_id="analytics_platform",
                state="ANONYMIZED",
                operation="ANONYMIZE_RECORD",
            ),
            make_finding(
                category="SECURITY_AUDIT_LOG",
                resource_id="audit_record_001",
                system_id="security_service",
                state="RETAINED",
                operation="READ_AUDIT_RECORD",
                attributes=(("retention_until", "2027-01-01T00:00:00Z"),),
            ),
        )

        result = self.evaluate(request, findings)

        self.assertEqual(result.deletion_status, "COMPLETE")
        self.assertIn(
            PERMITTED_RETENTION,
            {assessment.outcome for assessment in result.rule_assessments},
        )

        without_profile = self.evaluate(request, findings[1:])
        self.assertEqual(without_profile.deletion_status, "INCOMPLETE")

    def test_retention_after_deadline_is_not_assumed_permitted(self) -> None:
        request = make_request()
        result = self.evaluate(
            request,
            (
                make_finding(),
                make_finding(
                    category="SECURITY_AUDIT_LOG",
                    resource_id="audit_record_002",
                    system_id="security_service",
                    state="RETAINED",
                    attributes=(("retention_until", "2026-06-14T00:00:00Z"),),
                ),
            ),
        )

        assessment = next(
            item
            for item in result.rule_assessments
            if item.data_category == "SECURITY_AUDIT_LOG"
        )
        self.assertEqual(result.deletion_status, "INCOMPLETE")
        self.assertEqual(assessment.outcome, UNRESOLVED)

    def test_backup_retention_requires_restore_access_to_be_blocked(self) -> None:
        request = make_request()
        blocked = make_finding(
            category="BACKUP_ARCHIVE",
            resource_id="backup_001",
            system_id="backup_service",
            state="RETAINED",
            attributes=(("restore_allowed", "false"),),
        )
        allowed = replace(
            blocked,
            policy_attributes=(("restore_allowed", "true"),),
        )
        no_restore_value = replace(blocked, policy_attributes=())

        allowed_result = self.evaluate(request, (make_finding(), blocked))
        self.assertEqual(allowed_result.deletion_status, "COMPLETE")
        backup = next(
            item
            for item in allowed_result.rule_assessments
            if item.data_category == "BACKUP_ARCHIVE"
        )
        self.assertEqual(backup.outcome, PERMITTED_RETENTION)

        unblocked_result = self.evaluate(request, (make_finding(), allowed))
        self.assertEqual(unblocked_result.deletion_status, "INCOMPLETE")
        self.assertEqual(
            next(
                item for item in unblocked_result.rule_assessments
                if item.data_category == "BACKUP_ARCHIVE"
            ).outcome,
            UNMET,
        )
        unknown_result = self.evaluate(request, (make_finding(), no_restore_value))
        self.assertEqual(unknown_result.deletion_status, "INCOMPLETE")
        self.assertEqual(
            next(
                item for item in unknown_result.rule_assessments
                if item.data_category == "BACKUP_ARCHIVE"
            ).outcome,
            UNRESOLVED,
        )

    def test_replica_state_is_checked_separately_from_primary_deletion(self) -> None:
        request = make_request()
        findings = (
            make_finding(
                resource_id="account_primary_001",
                system_id="account_service",
                state="ABSENT",
            ),
            make_finding(
                resource_id="account_replica_001",
                system_id="read_replica",
                state="ACTIVE",
                operation="REPLICA_LOOKUP",
                timestamp="2026-06-15T11:00:00Z",
                temporal_relation=PRE_AUDIT,
            ),
        )

        result = self.evaluate(request, findings)

        profile = next(
            item for item in result.rule_assessments
            if item.data_category == "USER_PROFILE"
        )
        self.assertEqual(profile.outcome, UNMET)
        self.assertEqual(
            set(profile.resource_ids),
            {"account_primary_001", "account_replica_001"},
        )
        self.assertEqual(result.deletion_status, "INCOMPLETE")

    def test_active_legal_hold_is_permitted_but_does_not_replace_profile_proof(self) -> None:
        request = make_request()
        legal_hold = make_finding(
            category="LEGAL_HOLD_RECORD",
            resource_id="legal_hold_001",
            system_id="legal_service",
            state="ACTIVE",
            operation="LEGAL_HOLD_RECORD",
        )

        result = self.evaluate(request, (make_finding(), legal_hold))
        self.assertEqual(result.deletion_status, "COMPLETE")
        self.assertEqual(
            next(
                item for item in result.rule_assessments
                if item.data_category == "LEGAL_HOLD_RECORD"
            ).outcome,
            PERMITTED_RETENTION,
        )
        without_profile = self.evaluate(request, (legal_hold,))
        self.assertEqual(without_profile.deletion_status, "INCOMPLETE")

    def test_restore_operation_success_does_not_itself_prove_restore_blocked(self) -> None:
        request = make_request()
        backup = make_finding(
            category="BACKUP_ARCHIVE",
            resource_id="backup_002",
            system_id="backup_service",
            state=None,
            result_or_state="SUCCESS",
            operation="BLOCK_RESTORE",
        )
        backup = replace(backup, explicit_state=None)

        result = self.evaluate(request, (make_finding(), backup))

        self.assertEqual(result.deletion_status, "INCOMPLETE")
        self.assertEqual(
            next(
                item for item in result.rule_assessments
                if item.data_category == "BACKUP_ARCHIVE"
            ).outcome,
            UNRESOLVED,
        )

    def test_downstream_data_flow_requires_observed_disabled_and_stopped_state(self) -> None:
        request = make_request()
        disabled = make_finding(
            category="",
            resource_id="data_flow_001",
            system_id="integration_service",
            state=None,
            result_or_state=None,
            operation=None,
            attributes=(
                ("enabled", "false"),
                ("last_delivery_status", "stopped"),
            ),
            source_reference="$.service_exports.integration_service.connectors[0]",
        )
        disabled = replace(disabled, explicit_state=None, result_or_state=None)
        active = replace(
            disabled,
            policy_attributes=(
                ("enabled", "true"),
                ("last_delivery_status", "delivered"),
            ),
        )

        disabled_result = self.evaluate(request, (make_finding(), disabled))
        self.assertEqual(disabled_result.deletion_status, "COMPLETE")
        self.assertFalse(
            any(item.rule_id == "UNMAPPED_EVIDENCE"
                for item in disabled_result.rule_assessments)
        )

        active_result = self.evaluate(request, (make_finding(), active))
        self.assertEqual(active_result.deletion_status, "INCOMPLETE")
        self.assertTrue(
            any(item.rule_id == "UNMAPPED_EVIDENCE"
                for item in active_result.rule_assessments)
        )

    def test_post_audit_deletion_does_not_prove_completion_at_audit_time(self) -> None:
        request = make_request()
        post_audit = make_finding(
            timestamp="2026-06-16T12:00:00Z",
            state="DELETED",
            as_of_audit=False,
            temporal_relation=POST_AUDIT,
        )

        result = self.evaluate(request, (post_audit,))

        self.assertEqual(result.deletion_status, "INCOMPLETE")
        self.assertEqual(
            next(
                item for item in result.rule_assessments
                if item.data_category == "USER_PROFILE"
            ).outcome,
            UNRESOLVED,
        )

    def test_same_instant_conflict_is_unresolved_and_references_both_sources(self) -> None:
        request = make_request()
        absent = make_finding(state="ABSENT", conflict_references=("other-ref",))
        active = replace(
            make_finding(state="ACTIVE", source_reference="$.records[1]",
                         conflict_references=("first-ref",)),
            evidence_id="evidence_other",
        )
        conflict = EvidenceConflict(
            resource_id="account_001",
            timestamp=AUDIT_AT,
            evidence_references=(
                "evidence/test.json#$.records[0]",
                "evidence/test.json#$.records[1]",
            ),
            states=("ABSENT", "ACTIVE"),
            explanation="Opposing explicit states at one event time.",
        )

        result = self.evaluate(request, (absent, active), conflicts=(conflict,))

        self.assertEqual(result.deletion_status, "INCOMPLETE")
        self.assertTrue(
            any(assessment.rule_id == "EVIDENCE_CONFLICT"
                for assessment in result.rule_assessments)
        )
        self.assertEqual(
            {reference.source_reference for reference in result.evidence_references},
            {"$.records[0]", "$.records[1]"},
        )

    def test_contradictory_redacted_and_identifiable_states_are_conflicting(self) -> None:
        request = make_request()
        redacted = make_finding(state="REDACTED")
        identifiable = make_finding(
            state="IDENTIFIABLE",
            source_reference="$.records[1]",
            evidence_id="evidence_other",
        )

        result = self.evaluate(request, (redacted, identifiable))

        profile = next(
            item for item in result.rule_assessments
            if item.data_category == "USER_PROFILE"
        )
        self.assertEqual(profile.outcome, UNRESOLVED)
        self.assertIn("Contradictory explicit states", profile.reason)
        self.assertEqual(result.deletion_status, "INCOMPLETE")

    def test_redaction_and_anonymization_require_explicit_final_states(self) -> None:
        request = make_request()
        findings = (
            make_finding(),
            make_finding(
                category="EMAIL_DELIVERY_LOG",
                resource_id="delivery_001",
                system_id="email_delivery_service",
                state="REDACTED",
                operation="REDACT_RECORD",
            ),
            make_finding(
                category="ANALYTICS_PROFILE",
                resource_id="analytics_001",
                system_id="analytics_platform",
                state="ANONYMIZED",
                operation="ANONYMIZE_RECORD",
            ),
        )

        result = self.evaluate(request, findings)

        self.assertEqual(result.deletion_status, "COMPLETE")
        self.assertEqual(
            {
                assessment.data_category: assessment.outcome
                for assessment in result.rule_assessments
            }["EMAIL_DELIVERY_LOG"],
            SATISFIED,
        )

    def test_missing_evidence_is_incomplete_not_not_applicable(self) -> None:
        request = make_request()
        result = self.evaluate(request, ())

        self.assertEqual(result.deletion_status, "INCOMPLETE")
        self.assertNotEqual(result.deletion_status, "NOT_APPLICABLE")
        self.assertEqual(
            next(
                item for item in result.rule_assessments
                if item.data_category == "USER_PROFILE"
            ).outcome,
            UNRESOLVED,
        )

    def test_tombstone_redaction_without_stable_id_only_proof_is_unresolved(self) -> None:
        request = make_request()
        tombstone = make_finding(
            category="ACCOUNT_TOMBSTONE",
            resource_id="tombstone_001",
            system_id="identity_service",
            state="REDACTED",
            operation="REDACT_RECORD",
        )

        result = self.evaluate(request, (make_finding(), tombstone))

        assessment = next(
            item for item in result.rule_assessments
            if item.data_category == "ACCOUNT_TOMBSTONE"
        )
        self.assertEqual(result.deletion_status, "INCOMPLETE")
        self.assertEqual(assessment.outcome, UNRESOLVED)

    def test_timestamp_without_timezone_or_invalid_cutoff_cannot_prove_completion(self) -> None:
        request = make_request()
        naive = make_finding(timestamp="2026-06-15T12:00:00", as_of_audit=False,
                             temporal_relation="UNKNOWN")
        self.assertEqual(self.evaluate(request, (naive,)).deletion_status, "INCOMPLETE")
        invalid_audit = make_request(audit_at="invalid")
        timed = make_finding()
        self.assertEqual(
            self.evaluate(invalid_audit, (timed,)).deletion_status,
            "INCOMPLETE",
        )

    def test_all_request_evaluation_preserves_order_and_validates_inputs(self) -> None:
        dataset = replace(
            self.dataset,
            deletion_requests=[make_request("case_01"), make_request("case_02")],
        )
        resolutions = tuple(make_resolution(request) for request in dataset.deletion_requests)
        analyses = tuple(
            make_analysis(request, (make_finding(case_id=request["case_id"]),))
            for request in dataset.deletion_requests
        )

        results = evaluate_all_requests(dataset, resolutions, analyses)

        self.assertEqual([result.case_id for result in results], ["case_01", "case_02"])
        with self.assertRaises(ValueError):
            evaluate_all_requests(dataset, resolutions[:1], analyses)

    def test_real_sample_case_03_is_supported_by_profile_and_retention_evidence(self) -> None:
        request = next(
            item
            for item in self.dataset.sample_deletion_requests
            if item["case_id"] == "case_03"
        )
        resolution = resolve_request(
            request,
            self.dataset.user_identities,
            self.dataset.user_audit_log,
        )
        analysis = EvidenceAnalyzer(self.dataset).analyze_request(request, resolution)

        result = evaluate_request(self.dataset, request, resolution, analysis)

        self.assertEqual(result.deletion_status, "COMPLETE")
        self.assertTrue(
            any(
                reference.file_path.endswith(
                    "resource_lookup_trace_20260926_103856.log"
                )
                and reference.source_reference == "line=19"
                for reference in result.evidence_references
            )
        )
        self.assertEqual(
            {
                assessment.data_category: assessment.outcome
                for assessment in result.rule_assessments
                if assessment.data_category != "UNRESOLVED"
            },
            {
                "USER_PROFILE": SATISFIED,
                "SECURITY_AUDIT_LOG": PERMITTED_RETENTION,
            },
        )


if __name__ == "__main__":
    unittest.main()
