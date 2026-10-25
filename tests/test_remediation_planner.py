"""Tests for evidence-backed remediation planning."""

from dataclasses import replace
import json
import unittest

from src.data_loader import load_dataset
from src.evidence_analyzer import (
    AT_AUDIT,
    POST_AUDIT,
    PRE_AUDIT,
    EvidenceConflict,
    EvidenceFinding,
    RequestEvidenceAnalysis,
)
from src.identity_resolver import UNCERTAIN, resolve_request
from src.policy_engine import evaluate_request
from src.remediation_planner import plan_remediation


class RemediationPlannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dataset = load_dataset()
        cls.request = next(
            request
            for request in cls.dataset.sample_deletion_requests
            if request["case_id"] == "case_03"
        )
        cls.resolution = resolve_request(
            cls.request,
            cls.dataset.user_identities,
            cls.dataset.user_audit_log,
        )

    def make_finding(
        self,
        *,
        category: str = "USER_PROFILE",
        resource_id: str = "account_7566",
        system_id: str = "account_service",
        state: str = "ABSENT",
        timestamp: str = None,
        temporal_relation: str = None,
        as_of_audit: bool = True,
        operation: str = "PROFILE_LOOKUP",
        result_or_state: str = None,
        attributes: tuple = (),
        source_reference: str = "$.records[0]",
        conflict_references: tuple = (),
    ) -> EvidenceFinding:
        event_timestamp = timestamp or self.request["audit_at"]
        relation = temporal_relation or (
            AT_AUDIT
            if event_timestamp == self.request["audit_at"]
            else PRE_AUDIT
        )
        return EvidenceFinding(
            case_id=self.request["case_id"],
            evidence_id="evidence_test",
            file_path="evidence/test.json",
            source_reference=source_reference,
            record_id="record_test",
            event_id="event_test",
            timestamp=event_timestamp,
            timestamp_field="observed_at",
            source_captured_at=None,
            temporal_relation=relation,
            as_of_audit=as_of_audit,
            system_id=system_id,
            source_system=None,
            target_system=None,
            resource_id=resource_id,
            operation=operation,
            result_or_state=(
                result_or_state
                if result_or_state is not None
                else state
            ),
            explicit_state=state,
            finding_types=("OBSERVATION",),
            match_type="DIRECT",
            matched_identifiers=(self.request["email"],),
            conflict_references=conflict_references,
            data_category=category,
            policy_attributes=attributes,
        )

    def evaluate_and_plan(
        self,
        findings: tuple,
        *,
        resolution=None,
        conflicts: tuple = (),
    ):
        identity = resolution or self.resolution
        analysis = RequestEvidenceAnalysis(
            case_id=self.request["case_id"],
            requested_identifier=self.request["email"],
            identity_status=identity.status,
            findings=findings,
            gaps=(),
            conflicts=conflicts,
        )
        policy = evaluate_request(
            self.dataset,
            self.request,
            identity,
            analysis,
        )
        return policy, plan_remediation(policy, identity, analysis)

    def test_fully_completed_request_has_no_remediation_steps(self) -> None:
        _, plan = self.evaluate_and_plan((self.make_finding(),))

        self.assertEqual(plan.steps, ())
        self.assertEqual(plan.unresolved_obligations, ())

    def test_incomplete_profile_has_report_delete_and_verification_steps(self) -> None:
        finding = self.make_finding(state="ACTIVE")
        finding = replace(
            finding,
            source_system="deletion_worker",
            target_system="account_service",
        )

        policy, plan = self.evaluate_and_plan((finding,))

        self.assertEqual(policy.deletion_status, "INCOMPLETE")
        self.assertEqual(
            [(step.phase, step.operation) for step in plan.steps],
            [
                ("FINDING", "REPORT_REMAINING_RECORD"),
                ("REMEDIATION", "DELETE_RECORD"),
                ("VERIFICATION", "VERIFY_RECORD_ABSENT"),
            ],
        )
        self.assertTrue(all(step.subject_id == self.resolution.candidates[0].user_id
                            for step in plan.steps))
        self.assertTrue(all(step.rule_id == "rule_01" for step in plan.steps))
        self.assertTrue(all(step.evidence_references for step in plan.steps))
        self.assertTrue(all(step.reason for step in plan.steps))
        self.assertTrue(all(step.system_id == "account_service" for step in plan.steps))

    def test_uncertain_identity_never_yields_resource_deletion(self) -> None:
        uncertain = replace(self.resolution, status=UNCERTAIN)
        _, plan = self.evaluate_and_plan(
            (self.make_finding(state="ACTIVE"),),
            resolution=uncertain,
        )

        self.assertEqual(plan.steps, ())
        self.assertIsNone(plan.subject_id)
        self.assertIn("not uniquely confirmed", plan.unresolved_obligations[0])

    def test_permitted_security_retention_does_not_generate_deletion(self) -> None:
        profile = self.make_finding()
        security = self.make_finding(
            category="SECURITY_AUDIT_LOG",
            resource_id="audit_record_01",
            system_id="security_service",
            state="PRESENT",
            attributes=(("retention_until", "2030-01-01T00:00:00Z"),),
            source_reference="$.audit_records[0]",
        )

        policy, plan = self.evaluate_and_plan((profile, security))

        self.assertEqual(policy.deletion_status, "COMPLETE")
        self.assertEqual(plan.steps, ())

    def test_replica_and_restore_allowed_backup_get_distinct_actions(self) -> None:
        profile = self.make_finding(
            resource_id="account_primary_01",
            system_id="account_service",
        )
        replica = self.make_finding(
            resource_id="account_replica_01",
            system_id="read_replica",
            state="ACTIVE",
            source_reference="$.replicas[0]",
        )
        backup = self.make_finding(
            category="BACKUP_ARCHIVE",
            resource_id="backup_01",
            system_id="backup_service",
            state="RETAINED",
            attributes=(("restore_allowed", "true"),),
            source_reference="$.backups[0]",
        )

        policy, plan = self.evaluate_and_plan((profile, replica, backup))

        self.assertEqual(policy.deletion_status, "INCOMPLETE")
        operations = {
            (step.resource_id, step.operation)
            for step in plan.steps
        }
        self.assertIn(("account_replica_01", "DELETE_RECORD"), operations)
        self.assertIn(("backup_01", "BLOCK_RESTORE"), operations)
        self.assertNotIn(("backup_01", "DELETE_RECORD"), operations)
        self.assertNotIn(("account_primary_01", "DELETE_RECORD"), operations)

    def test_active_data_flow_is_disabled_and_then_verified(self) -> None:
        profile = self.make_finding()
        flow = self.make_finding(
            category="",
            resource_id="data_flow_01",
            system_id="integration_service",
            state=None,
            operation="CONNECTOR_LOOKUP",
            result_or_state=None,
            attributes=(
                ("enabled", "true"),
                ("last_delivery_status", "delivered"),
            ),
            source_reference="$.connectors[0]",
        )
        flow = replace(flow, explicit_state=None, result_or_state=None)

        _, plan = self.evaluate_and_plan((profile, flow))

        self.assertEqual(
            [(step.phase, step.operation) for step in plan.steps
             if step.resource_id == "data_flow_01"],
            [
                ("FINDING", "REPORT_ACTIVE_DATA_FLOW"),
                ("REMEDIATION", "DISABLE_DATA_FLOW"),
                ("VERIFICATION", "VERIFY_DATA_FLOW_DISABLED"),
            ],
        )

    def test_identifiable_analytics_is_anonymized_not_deleted(self) -> None:
        profile = self.make_finding()
        analytics = self.make_finding(
            category="ANALYTICS_PROFILE",
            resource_id="analytics_01",
            system_id="analytics_platform",
            state="IDENTIFIABLE",
            source_reference="$.analytics[0]",
        )

        policy, plan = self.evaluate_and_plan((profile, analytics))

        self.assertEqual(policy.deletion_status, "INCOMPLETE")
        self.assertIn(
            ("analytics_01", "ANONYMIZE_RECORD"),
            {(step.resource_id, step.operation) for step in plan.steps},
        )
        self.assertNotIn(
            ("analytics_01", "DELETE_RECORD"),
            {(step.resource_id, step.operation) for step in plan.steps},
        )

    def test_unresolved_tombstone_condition_does_not_propose_redaction(self) -> None:
        profile = self.make_finding()
        tombstone = self.make_finding(
            category="ACCOUNT_TOMBSTONE",
            resource_id="tombstone_01",
            system_id="identity_service",
            state="DELETED",
            source_reference="$.tombstones[0]",
        )

        _, plan = self.evaluate_and_plan((profile, tombstone))

        self.assertFalse(
            any(
                step.resource_id == "tombstone_01"
                and step.operation in {"REDACT_RECORD", "DELETE_RECORD"}
                for step in plan.steps
            )
        )
        self.assertTrue(any("stable-user-id" in note
                            for note in plan.unresolved_obligations))

    def test_post_audit_event_does_not_generate_cutoff_remediation(self) -> None:
        post_audit = self.make_finding(
            state="ACTIVE",
            timestamp="2026-09-16T00:00:00Z",
            temporal_relation=POST_AUDIT,
            as_of_audit=False,
        )

        _, plan = self.evaluate_and_plan((post_audit,))

        self.assertEqual(plan.steps, ())
        self.assertTrue(any("no reliable event timestamp at or before audit_at" in note
                            for note in plan.unresolved_obligations))

    def test_conflicting_states_never_generate_destructive_steps(self) -> None:
        absent = self.make_finding(source_reference="$.records[0]")
        active = self.make_finding(
            state="ACTIVE",
            source_reference="$.records[1]",
        )
        conflict = EvidenceConflict(
            resource_id="account_7566",
            timestamp=self.request["audit_at"],
            evidence_references=(
                "evidence/test.json#$.records[0]",
                "evidence/test.json#$.records[1]",
            ),
            states=("ABSENT", "ACTIVE"),
            explanation="Opposing states at the same instant.",
        )

        _, plan = self.evaluate_and_plan(
            (absent, active),
            conflicts=(conflict,),
        )

        self.assertFalse(
            any(
                step.phase == "REMEDIATION"
                and step.operation in {
                    "DELETE_RECORD",
                    "REDACT_RECORD",
                    "ANONYMIZE_RECORD",
                }
                for step in plan.steps
            )
        )
        self.assertTrue(any("conflicting" in note.casefold()
                            for note in plan.unresolved_obligations))

    def test_empty_input_assessment_produces_empty_step_list(self) -> None:
        _, plan = self.evaluate_and_plan(())

        self.assertEqual(plan.steps, ())
        serialized = json.dumps(plan.to_steps_json_value(), sort_keys=True)
        self.assertEqual(json.loads(serialized), [])

    def test_steps_have_deterministic_phase_system_resource_order(self) -> None:
        first = self.make_finding(
            resource_id="account_z",
            system_id="z_service",
            state="ACTIVE",
            source_reference="$.records[0]",
        )
        second = self.make_finding(
            resource_id="account_a",
            system_id="a_service",
            state="ACTIVE",
            source_reference="$.records[1]",
        )

        _, plan_forward = self.evaluate_and_plan((first, second))
        _, plan_reverse = self.evaluate_and_plan((second, first))

        self.assertEqual(
            plan_forward.to_steps_json_value(),
            plan_reverse.to_steps_json_value(),
        )
        self.assertEqual(
            [(step.phase, step.system_id, step.resource_id)
             for step in plan_forward.steps],
            [
                ("FINDING", "a_service", "account_a"),
                ("FINDING", "z_service", "account_z"),
                ("REMEDIATION", "a_service", "account_a"),
                ("REMEDIATION", "z_service", "account_z"),
                ("VERIFICATION", "a_service", "account_a"),
                ("VERIFICATION", "z_service", "account_z"),
            ],
        )

    def test_repeat_runs_produce_identical_serializable_results(self) -> None:
        findings = (
            self.make_finding(
                resource_id="account_b",
                state="ACTIVE",
                source_reference="$.records[1]",
            ),
            self.make_finding(
                resource_id="account_a",
                state="ACTIVE",
                source_reference="$.records[0]",
            ),
        )

        _, first = self.evaluate_and_plan(findings)
        _, second = self.evaluate_and_plan(findings)

        self.assertEqual(first, second)
        self.assertEqual(
            json.dumps(first.to_steps_json_value(), sort_keys=True),
            json.dumps(second.to_steps_json_value(), sort_keys=True),
        )


if __name__ == "__main__":
    unittest.main()
