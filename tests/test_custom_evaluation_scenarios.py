"""Synthetic, non-official scenarios for the documented provisional policy."""

import unittest

from src.data_loader import load_dataset
from src.evidence_analyzer import (
    POST_AUDIT,
    PRE_AUDIT,
    EvidenceFinding,
    RequestEvidenceAnalysis,
)
from src.identity_resolver import CONFIRMED, UNCERTAIN, resolve_request
from src.policy_engine import PERMITTED_RETENTION, SATISFIED, UNMET, evaluate_request
from src.remediation_planner import plan_remediation


AUDIT_AT = "2026-06-15T12:00:00Z"


class CustomProvisionalPolicyScenarios(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dataset = load_dataset()

    def request(self, case_id: str = "custom_case") -> dict:
        return {
            "case_id": case_id,
            "email": "person@example.test",
            "requested_at": "2026-06-01T00:00:00Z",
            "reported_status": "COMPLETE",
            "reported_at": "2026-06-02T00:00:00Z",
            "audit_at": AUDIT_AT,
            "request_text": "Delete my account.",
        }

    @staticmethod
    def finding(
        request: dict,
        *,
        category: str = "USER_PROFILE",
        resource_id: str = "account_custom",
        system_id: str = "account_service",
        state: str = "ABSENT",
        timestamp: str = "2026-06-15T11:00:00Z",
        temporal_relation: str = PRE_AUDIT,
        as_of_audit: bool = True,
        operation: str = "PROFILE_LOOKUP",
        result_or_state: str = None,
        attributes: tuple = (),
    ) -> EvidenceFinding:
        return EvidenceFinding(
            case_id=request["case_id"],
            evidence_id="custom_evidence",
            file_path="evidence/custom.json",
            source_reference="$.records[0]",
            record_id="custom_record",
            event_id="custom_event",
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
            result_or_state=(
                result_or_state if result_or_state is not None else state
            ),
            explicit_state=state,
            finding_types=("OBSERVATION",),
            match_type="DIRECT",
            matched_identifiers=(request["email"],),
            conflict_references=(),
            data_category=category,
            policy_attributes=attributes,
        )

    def run_case(self, request: dict, findings: tuple, identity_status: str = CONFIRMED):
        if identity_status == UNCERTAIN:
            resolution = resolve_request(
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
        else:
            resolution = resolve_request(
                request,
                [
                    {
                        "user_id": "user_custom",
                        "name": "Example Person",
                        "email": request["email"],
                        "phone": "+1 555 0100",
                        "email_hash": "hash_custom",
                        "updated_at": "2026-01-01T00:00:00Z",
                    }
                ],
                [],
            )
        analysis = RequestEvidenceAnalysis(
            case_id=request["case_id"],
            requested_identifier=request["email"],
            identity_status=resolution.status,
            findings=findings,
            gaps=(),
            conflicts=(),
        )
        policy = evaluate_request(
            self.dataset,
            request,
            resolution,
            analysis,
        )
        plan = plan_remediation(policy, resolution, analysis)
        return policy, plan

    def test_pre_cutoff_absence_confirms_completion(self) -> None:
        """Pre-cutoff ABSENT profile satisfies unconditional rule_01."""
        request = self.request()
        profile = self.finding(request)

        policy, plan = self.run_case(request, (profile,))

        self.assertEqual(policy.deletion_status, "COMPLETE")
        assessment = next(
            item for item in policy.rule_assessments if item.rule_id == "rule_01"
        )
        self.assertEqual(assessment.outcome, SATISFIED)
        self.assertEqual(plan.steps, ())

    def test_identified_active_profile_requires_targeted_remediation(self) -> None:
        """An identified ACTIVE profile is unmet and safely targetable."""
        request = self.request()
        active = self.finding(
            request,
            state="ACTIVE",
            operation="PROFILE_LOOKUP",
        )

        policy, plan = self.run_case(request, (active,))

        self.assertEqual(policy.deletion_status, "INCOMPLETE")
        self.assertEqual(
            next(
                item for item in policy.rule_assessments if item.rule_id == "rule_01"
            ).outcome,
            UNMET,
        )
        self.assertIn(
            ("account_custom", "DELETE_RECORD"),
            {(step.resource_id, step.operation) for step in plan.steps},
        )

    def test_post_audit_absence_does_not_prove_cutoff_completion(self) -> None:
        """Evidence after audit_at remains ineligible for cutoff completion."""
        request = self.request()
        post_audit = self.finding(
            request,
            timestamp="2026-06-15T12:00:01Z",
            temporal_relation=POST_AUDIT,
            as_of_audit=False,
        )

        policy, plan = self.run_case(request, (post_audit,))

        self.assertEqual(policy.deletion_status, "INCOMPLETE")
        self.assertEqual(
            next(
                item for item in policy.rule_assessments if item.rule_id == "rule_01"
            ).outcome,
            "UNRESOLVED",
        )
        self.assertFalse(
            any(step.operation == "DELETE_RECORD" for step in plan.steps)
        )

    def test_security_record_with_future_retention_is_permitted(self) -> None:
        """A retention_until after audit_at permits retention under rule_12."""
        request = self.request()
        profile = self.finding(request)
        security_record = self.finding(
            request,
            category="SECURITY_AUDIT_LOG",
            resource_id="audit_record_custom",
            system_id="security_service",
            state="RETAINED",
            operation="READ_AUDIT_RECORD",
            attributes=(("retention_until", "2027-01-01T00:00:00Z"),),
        )

        policy, plan = self.run_case(request, (profile, security_record))

        self.assertEqual(policy.deletion_status, "COMPLETE")
        retention = next(
            item for item in policy.rule_assessments if item.rule_id == "rule_12"
        )
        self.assertEqual(retention.outcome, PERMITTED_RETENTION)
        self.assertFalse(
            any(step.resource_id == "audit_record_custom" for step in plan.steps)
        )

    def test_uncertain_identity_never_triggers_destructive_remediation(self) -> None:
        """Unconfirmed ownership blocks completion and all resource actions."""
        request = self.request()
        active = self.finding(request, state="ACTIVE")

        policy, plan = self.run_case(
            request,
            (active,),
            identity_status=UNCERTAIN,
        )

        self.assertEqual(policy.deletion_status, "INCOMPLETE")
        self.assertEqual(plan.steps, ())
        self.assertIsNone(plan.subject_id)

    def test_backup_restore_access_risk_is_blocked_without_deleting_archive(self) -> None:
        """Explicit restore_allowed=true requires blocking restore, not deletion."""
        request = self.request()
        profile = self.finding(request)
        backup = self.finding(
            request,
            category="BACKUP_ARCHIVE",
            resource_id="backup_custom",
            system_id="backup_service",
            state="RETAINED",
            operation="RESTORE_ENTRY_LOOKUP",
            attributes=(("restore_allowed", "true"),),
        )

        policy, plan = self.run_case(request, (profile, backup))

        self.assertEqual(policy.deletion_status, "INCOMPLETE")
        self.assertEqual(
            next(
                item for item in policy.rule_assessments if item.rule_id == "rule_14"
            ).outcome,
            UNMET,
        )
        operations = {
            (step.resource_id, step.operation) for step in plan.steps
        }
        self.assertIn(("backup_custom", "BLOCK_RESTORE"), operations)
        self.assertNotIn(("backup_custom", "DELETE_RECORD"), operations)


if __name__ == "__main__":
    unittest.main()
