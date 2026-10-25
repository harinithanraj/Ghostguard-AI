"""Tests for loading and validating deletion-audit input files."""

import csv
from pathlib import Path
import tempfile
import unittest

from src.data_loader import REQUIRED_COLUMNS, load_dataset


def create_project_fixture(
    project_root: Path,
    request_count: int = 518,
    duplicate_case_id: bool = False,
    missing_identity_column: bool = False,
) -> None:
    """Create the minimum valid CSV fixture used by loader tests."""
    dataset_dir = project_root / "dataset"
    evidence_dir = dataset_dir / "evidence"
    evidence_dir.mkdir(parents=True)

    for filename, required_columns in REQUIRED_COLUMNS.items():
        columns = list(required_columns)
        if filename == "user_identities.csv" and missing_identity_column:
            columns.remove("email_hash")

        rows = []
        if filename == "deletion_requests.csv":
            for index in range(request_count):
                case_number = 0 if duplicate_case_id and index == 1 else index
                record = {column: "value" for column in columns}
                record["case_id"] = f"case_{case_number:03d}"
                rows.append(record)
        elif filename == "evidence_files.csv":
            rows.append(
                {
                    "file_id": "evidence_01",
                    "file_path": "evidence/logs/missing.log",
                    "origin": "test",
                    "captured_at": "2026-01-01T00:00:00Z",
                }
            )

        with (dataset_dir / filename).open(
            "w", encoding="utf-8", newline=""
        ) as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=columns)
            writer.writeheader()
            writer.writerows(rows)


class DataLoaderTests(unittest.TestCase):
    def test_missing_files_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            project_root = Path(temporary_directory)
            with self.assertRaisesRegex(FileNotFoundError, "Required dataset"):
                load_dataset(project_root)

    def test_missing_required_column_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            project_root = Path(temporary_directory)
            create_project_fixture(project_root, missing_identity_column=True)

            with self.assertRaisesRegex(ValueError, "email_hash"):
                load_dataset(project_root)

    def test_duplicate_case_ids_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            project_root = Path(temporary_directory)
            create_project_fixture(project_root, duplicate_case_id=True)

            with self.assertRaisesRegex(ValueError, "Duplicate case_id"):
                load_dataset(project_root)

    def test_incorrect_request_row_count_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            project_root = Path(temporary_directory)
            create_project_fixture(project_root, request_count=517)

            with self.assertRaisesRegex(ValueError, "exactly 518 data rows"):
                load_dataset(project_root)

    def test_valid_data_preserves_ids_and_reports_missing_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            project_root = Path(temporary_directory)
            create_project_fixture(project_root)

            dataset = load_dataset(project_root)

            self.assertEqual(len(dataset.deletion_requests), 518)
            self.assertEqual(dataset.deletion_requests[0]["case_id"], "case_000")
            self.assertIsInstance(dataset.deletion_requests[0]["case_id"], str)
            self.assertEqual(dataset.evidence_found, ())
            self.assertEqual(dataset.evidence_missing, ("evidence/logs/missing.log",))


if __name__ == "__main__":
    unittest.main()
