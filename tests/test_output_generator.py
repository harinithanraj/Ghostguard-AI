"""Tests for validated output CSV generation."""

import csv
from dataclasses import replace
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from src.data_loader import EXPECTED_REQUEST_COUNT, load_dataset
from src.evidence_analyzer import analyze_all_requests
from src.identity_resolver import resolve_all_requests
from src.output_generator import (
    ALLOWED_STATUSES,
    OUTPUT_COLUMNS,
    STEP_KEYS,
    validate_output_csv,
    write_output_csv,
)
from src.policy_engine import evaluate_all_requests
from src.remediation_planner import (
    RemediationPlan,
    RemediationStep,
    plan_all_requests,
)


class OutputGeneratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dataset = load_dataset()
        cls.resolutions = resolve_all_requests(cls.dataset)
        cls.analyses = analyze_all_requests(cls.dataset, cls.resolutions)
        cls.policies = evaluate_all_requests(
            cls.dataset, cls.resolutions, cls.analyses
        )
        cls.plans = plan_all_requests(
            cls.dataset, cls.resolutions, cls.analyses, cls.policies
        )

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    @staticmethod
    def make_step(case_id: str, step_no: int = 1, **overrides) -> RemediationStep:
        values = {
            "step_no": step_no,
            "case_id": case_id,
            "subject_id": "user_1",
            "rule_id": "rule_01",
            "phase": "VERIFICATION",
            "system_id": "account_service",
            "resource_id": "account_1",
            "operation": "VERIFY_RECORD_ABSENT",
            "state": "ABSENT",
            "evidence_id": "evidence_1",
            "evidence_references": ("evidence/example.json#$.records[0]",),
            "reason": "An eligible source state supports the verification.",
        }
        values.update(overrides)
        return RemediationStep(**values)

    @classmethod
    def make_plan(
        cls, case_id: str, steps=(), **overrides
    ) -> RemediationPlan:
        values = {
            "case_id": case_id,
            "subject_id": "user_1",
            "identity_status": "CONFIRMED",
            "steps": tuple(steps),
            "unresolved_obligations": (),
        }
        values.update(overrides)
        return RemediationPlan(**values)

    @staticmethod
    def make_policy(case_id: str, status: str):
        return SimpleNamespace(case_id=case_id, deletion_status=status)

    def write_synthetic(self, cases, statuses=None, plans=None, output_path=None):
        statuses = statuses or ["COMPLETE"] * len(cases)
        plans = plans or [self.make_plan(case_id) for case_id in cases]
        return write_output_csv(
            [{"case_id": case_id} for case_id in cases],
            [
                self.make_policy(case_id, status)
                for case_id, status in zip(cases, statuses)
            ],
            plans,
            output_path=output_path or self.root / "output.csv",
            project_root=self.root,
            expected_row_count=len(cases),
        )

    def test_real_dataset_generates_518_valid_rows_with_exact_schema(self) -> None:
        path = write_output_csv(
            self.dataset.deletion_requests,
            self.policies,
            self.plans,
            output_path=self.root / "artifacts" / "output.csv",
            project_root=self.root,
            expected_row_count=EXPECTED_REQUEST_COUNT,
        )

        rows = validate_output_csv(
            path,
            expected_row_count=EXPECTED_REQUEST_COUNT,
            expected_case_ids=[
                request["case_id"] for request in self.dataset.deletion_requests
            ],
        )
        self.assertEqual(len(rows), EXPECTED_REQUEST_COUNT)
        self.assertTrue(all(isinstance(row["case_id"], str) for row in rows))
        self.assertEqual(
            [row["case_id"] for row in rows],
            sorted(row["case_id"] for row in rows),
        )
        self.assertEqual(
            set(row["deletion_status"] for row in rows),
            {policy.deletion_status for policy in self.policies},
        )
        self.assertTrue(
            {row["deletion_status"] for row in rows}.issubset(ALLOWED_STATUSES)
        )
        for row in rows:
            steps = json.loads(row["steps_json"])
            self.assertIsInstance(steps, list)
            for step in steps:
                self.assertEqual(tuple(step), STEP_KEYS)

        with path.open("r", encoding="utf-8", newline="") as output_file:
            reader = csv.reader(output_file)
            self.assertEqual(tuple(next(reader)), OUTPUT_COLUMNS)

    def test_default_output_path_does_not_overwrite_dataset_output(self) -> None:
        dataset_output = self.root / "dataset" / "output.csv"
        dataset_output.parent.mkdir()
        dataset_output.write_text("preserve this file\n", encoding="utf-8")

        path = write_output_csv(
            [{"case_id": "case_1"}],
            [self.make_policy("case_1", "COMPLETE")],
            [self.make_plan("case_1")],
            project_root=self.root,
            expected_row_count=1,
        )

        self.assertEqual(path, self.root / "artifacts" / "output.csv")
        self.assertEqual(dataset_output.read_text(encoding="utf-8"), "preserve this file\n")

    def test_steps_json_uses_sample_key_order_and_preserves_special_characters(self) -> None:
        step = self.make_step(
            "case_1",
            system_id='east,"東京"\nservice',
            resource_id='resource,"quoted"\nwith newline',
            reason='quotes " commas, Unicode café, and newline\nkept internally',
        )
        path = self.write_synthetic(
            ["case_1"],
            statuses=["INCOMPLETE"],
            plans=[self.make_plan("case_1", [step])],
        )
        row = validate_output_csv(path)[0]
        serialized = json.loads(row["steps_json"])

        self.assertEqual(tuple(serialized[0]), STEP_KEYS)
        self.assertEqual(serialized[0]["system_id"], step.system_id)
        self.assertEqual(serialized[0]["resource_id"], step.resource_id)
        self.assertEqual(serialized[0]["step_no"], 1)

    def test_empty_step_lists_are_serialized_as_json_arrays(self) -> None:
        path = self.write_synthetic(["case_1"], plans=[self.make_plan("case_1")])

        rows = validate_output_csv(path, expected_row_count=1)

        self.assertEqual(json.loads(rows[0]["steps_json"]), [])

    def test_rows_are_lexically_sorted_and_repeated_runs_are_identical(self) -> None:
        cases = ["case_2", "case_10", "case_002"]
        statuses = ["INCOMPLETE", "COMPLETE", "NOT_APPLICABLE"]
        plans = [self.make_plan(case_id) for case_id in cases]
        first = self.root / "first.csv"
        second = self.root / "second.csv"

        self.write_synthetic(cases, statuses, plans, first)
        self.write_synthetic(cases, statuses, plans, second)

        self.assertEqual(first.read_bytes(), second.read_bytes())
        rows = validate_output_csv(first, expected_case_ids=cases)
        self.assertEqual(
            [row["case_id"] for row in rows],
            ["case_002", "case_10", "case_2"],
        )
        self.assertEqual(
            {row["deletion_status"] for row in rows},
            {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"},
        )

    def test_duplicate_or_missing_case_ids_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "Duplicate case_id"):
            write_output_csv(
                [{"case_id": "case_1"}, {"case_id": "case_1"}],
                [],
                [],
                project_root=self.root,
            )
        with self.assertRaisesRegex(ValueError, "case_id"):
            write_output_csv(
                [{"not_case_id": "case_1"}],
                [],
                [],
                project_root=self.root,
            )

    def test_missing_policy_or_plan_result_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "exactly one result per request"):
            write_output_csv(
                [{"case_id": "case_1"}],
                [],
                [self.make_plan("case_1")],
                project_root=self.root,
            )
        with self.assertRaisesRegex(ValueError, "exactly one result per request"):
            write_output_csv(
                [{"case_id": "case_1"}],
                [self.make_policy("case_1", "COMPLETE")],
                [],
                project_root=self.root,
            )

    def test_invalid_status_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "Invalid deletion status"):
            self.write_synthetic(["case_1"], statuses=["PENDING"])

    def test_invalid_and_non_serializable_steps_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "exactly the sample-observed"):
            self.write_synthetic(
                ["case_1"],
                plans=[
                    self.make_plan(
                        "case_1",
                        [
                            {
                                "step_no": 1,
                                "operation": "DELETE_RECORD",
                            }
                        ],
                    )
                ],
            )

        bad_step = self.make_step("case_1", system_id=object())
        with self.assertRaisesRegex(ValueError, "system_id must be a string or None"):
            self.write_synthetic(
                ["case_1"], plans=[self.make_plan("case_1", [bad_step])]
            )

    def test_step_case_id_and_order_must_match_the_request_and_plan(self) -> None:
        wrong_case_step = self.make_step("case_2")
        with self.assertRaisesRegex(ValueError, "does not match its request"):
            self.write_synthetic(
                ["case_1"], plans=[self.make_plan("case_1", [wrong_case_step])]
            )

        out_of_order = (
            self.make_step("case_1", step_no=2),
            self.make_step("case_1", step_no=1),
        )
        with self.assertRaisesRegex(ValueError, "consecutive and match the plan order"):
            self.write_synthetic(
                ["case_1"], plans=[self.make_plan("case_1", out_of_order)]
            )

    def test_read_back_validation_rejects_wrong_header_and_invalid_json(self) -> None:
        malformed = self.root / "malformed.csv"
        malformed.write_text(
            "case_id,steps_json,deletion_status\ncase_1,[],COMPLETE\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "Invalid output header"):
            validate_output_csv(malformed)

        malformed.write_text(
            "case_id,deletion_status,steps_json\ncase_1,COMPLETE,not-json\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "Invalid steps_json"):
            validate_output_csv(malformed)

    def test_sample_status_and_step_comparison_is_reported_separately(self) -> None:
        sample_dataset = replace(
            self.dataset,
            deletion_requests=self.dataset.sample_deletion_requests,
        )
        sample_resolutions = resolve_all_requests(sample_dataset)
        sample_analyses = analyze_all_requests(sample_dataset, sample_resolutions)
        sample_policies = evaluate_all_requests(
            sample_dataset, sample_resolutions, sample_analyses
        )
        sample_plans = plan_all_requests(
            sample_dataset,
            sample_resolutions,
            sample_analyses,
            sample_policies,
        )
        expected = {
            row["case_id"]: row for row in self.dataset.sample_output
        }
        policies_by_id = {result.case_id: result for result in sample_policies}
        plans_by_id = {plan.case_id: plan for plan in sample_plans}

        status_matches = sum(
            policies_by_id[case_id].deletion_status
            == expected[case_id]["deletion_status"]
            for case_id in expected
        )
        step_matches = 0
        for case_id, sample_row in expected.items():
            actual_steps = [
                {
                    key: getattr(step, key)
                    for key in STEP_KEYS
                }
                for step in plans_by_id[case_id].steps
            ]
            if actual_steps == json.loads(sample_row["steps_json"]):
                step_matches += 1

        self.assertEqual(status_matches, 23)
        self.assertEqual(step_matches, 0)
        self.assertEqual(
            sum(not plan.steps for plan in sample_plans),
            22,
        )


if __name__ == "__main__":
    unittest.main()
