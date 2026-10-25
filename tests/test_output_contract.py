"""Read-only tests for the observed output and planner serialization contract."""

import csv
import io
import json
import unittest

from src.data_loader import EXPECTED_REQUEST_COUNT, load_dataset
from src.remediation_planner import RemediationStep


EXPECTED_OUTPUT_COLUMNS = ("case_id", "deletion_status", "steps_json")
EXPECTED_SAMPLE_STEP_KEYS = {
    "step_no",
    "phase",
    "system_id",
    "resource_id",
    "operation",
    "state",
    "evidence_id",
}


class OutputContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dataset = load_dataset()

    def test_sample_top_level_schema_and_all_step_shapes_are_consistent(self) -> None:
        self.assertEqual(
            tuple(self.dataset.sample_output[0].keys()),
            EXPECTED_OUTPUT_COLUMNS,
        )
        self.assertEqual(len(self.dataset.sample_output), 32)
        self.assertTrue(
            {
                row["deletion_status"] for row in self.dataset.sample_output
            }.issubset({"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"})
        )

        for row in self.dataset.sample_output:
            with self.subTest(case_id=row["case_id"]):
                steps = json.loads(row["steps_json"])
                self.assertIsInstance(steps, list)
                for step in steps:
                    self.assertEqual(set(step), EXPECTED_SAMPLE_STEP_KEYS)
                self.assertEqual(
                    [step["step_no"] for step in steps],
                    list(range(1, len(steps) + 1)),
                )

    def test_sample_steps_do_not_establish_empty_list_status_semantics(self) -> None:
        observed = {
            status: {
                not bool(json.loads(row["steps_json"]))
                for row in self.dataset.sample_output
                if row["deletion_status"] == status
            }
            for status in {row["deletion_status"] for row in self.dataset.sample_output}
        }

        self.assertEqual(observed, {"COMPLETE": {False}, "INCOMPLETE": {False}})

    def test_full_request_count_and_case_ids_remain_strings(self) -> None:
        requests = self.dataset.deletion_requests
        case_ids = [request["case_id"] for request in requests]

        self.assertEqual(len(requests), EXPECTED_REQUEST_COUNT)
        self.assertEqual(len(set(case_ids)), EXPECTED_REQUEST_COUNT)
        self.assertTrue(all(isinstance(case_id, str) for case_id in case_ids))
        self.assertEqual(sorted(case_ids), sorted(case_ids))
        self.assertEqual(sorted(["case_10", "case_2"]), ["case_10", "case_2"])
        self.assertEqual(sorted(["case_010", "case_002"]), ["case_002", "case_010"])

    def test_planner_json_and_csv_cell_round_trip_preserves_special_characters(self) -> None:
        step = RemediationStep(
            step_no=1,
            case_id="case_0007",
            subject_id="user_0007",
            rule_id="rule_01",
            phase="FINDING",
            system_id='service,"east"\n東京',
            resource_id="resource,quoted\"line\nwith newline",
            operation="REPORT_REMAINING_RECORD",
            state="PRESENT",
            evidence_id="evidence_01",
            evidence_references=("evidence/例.json#$.records[0]",),
            reason='quoted "text", commas, newline\nand Unicode café.',
        )
        steps = [step.to_dict()]
        json_cell = json.dumps(steps, ensure_ascii=False)
        buffer = io.StringIO(newline="")
        writer = csv.writer(buffer)
        writer.writerow((step.case_id, "INCOMPLETE", json_cell))

        buffer.seek(0)
        case_id, status, serialized_steps = next(csv.reader(buffer))

        self.assertEqual(case_id, "case_0007")
        self.assertEqual(status, "INCOMPLETE")
        self.assertEqual(json.loads(serialized_steps), steps)
        self.assertEqual(json.loads(serialized_steps)[0]["resource_id"], step.resource_id)


if __name__ == "__main__":
    unittest.main()
