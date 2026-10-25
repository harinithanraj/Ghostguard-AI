"""Focused tests for evaluator metrics and external step validation."""

import unittest

from evaluation.evaluate import _classification_metrics, _step_validation
from src.output_generator import STEP_KEYS


class EvaluationUnitTests(unittest.TestCase):
    def test_per_status_metrics_mark_unobserved_classes_as_not_applicable(self) -> None:
        metrics = _classification_metrics(
            ["COMPLETE", "COMPLETE", "INCOMPLETE"],
            ["COMPLETE", "INCOMPLETE", "INCOMPLETE"],
        )

        self.assertEqual(metrics["COMPLETE"]["support"], 2)
        self.assertEqual(metrics["COMPLETE"]["precision"], 1.0)
        self.assertEqual(metrics["COMPLETE"]["recall"], 0.5)
        self.assertEqual(metrics["INCOMPLETE"]["support"], 1)
        self.assertEqual(metrics["INCOMPLETE"]["precision"], 0.5)
        self.assertEqual(metrics["NOT_APPLICABLE"]["precision"], None)
        self.assertEqual(metrics["NOT_APPLICABLE"]["recall"], None)
        self.assertEqual(metrics["NOT_APPLICABLE"]["f1"], None)

    def test_step_validator_requires_ordered_sample_keys_and_json_types(self) -> None:
        valid = {
            "step_no": 1,
            "phase": "FINDING",
            "system_id": "account_service",
            "resource_id": "account_1",
            "operation": "REPORT_REMAINING_RECORD",
            "state": "PRESENT",
            "evidence_id": "evidence_1",
        }

        self.assertEqual(tuple(valid), STEP_KEYS)
        self.assertIsNone(_step_validation(valid, "case_1", 1))
        self.assertIn(
            "keys/order",
            _step_validation(dict(reversed(list(valid.items()))), "case_1", 1),
        )
        invalid_number = dict(valid, step_no=True)
        self.assertIn(
            "invalid step_no",
            _step_validation(invalid_number, "case_1", 1),
        )


if __name__ == "__main__":
    unittest.main()
