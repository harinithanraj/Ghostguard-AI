"""Load and validate the inputs for the deletion-audit project."""

import csv
from dataclasses import dataclass
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple


LOGGER = logging.getLogger(__name__)
EXPECTED_REQUEST_COUNT = 518

REQUIRED_COLUMNS = {
    "deletion_requests.csv": (
        "case_id",
        "email",
        "requested_at",
        "reported_status",
        "reported_at",
        "audit_at",
        "request_text",
    ),
    "sample_deletion_requests.csv": (
        "case_id",
        "email",
        "requested_at",
        "reported_status",
        "reported_at",
        "audit_at",
        "request_text",
    ),
    "sample_output.csv": ("case_id", "deletion_status", "steps_json"),
    "user_identities.csv": (
        "user_id",
        "name",
        "email",
        "phone",
        "email_hash",
        "updated_at",
    ),
    "user_audit_log.csv": (
        "audit_id",
        "user_id",
        "event_time",
        "field_name",
        "old_value",
        "new_value",
    ),
    "system_activity.csv": (
        "activity_id",
        "event_time",
        "event_type",
        "source_system",
        "target_system",
        "resource_id",
        "reported_result",
        "details",
    ),
    "deletion_rules.csv": (
        "rule_id",
        "data_category",
        "condition",
        "required_action",
    ),
    "evidence_files.csv": ("file_id", "file_path", "origin", "captured_at"),
}

IDENTIFIER_COLUMNS = {
    "deletion_requests.csv": ("case_id",),
    "sample_deletion_requests.csv": ("case_id",),
    "sample_output.csv": ("case_id",),
    "user_identities.csv": ("user_id",),
    "user_audit_log.csv": ("audit_id", "user_id"),
    "system_activity.csv": ("activity_id", "resource_id"),
    "deletion_rules.csv": ("rule_id",),
    "evidence_files.csv": ("file_id", "file_path"),
}


@dataclass
class Dataset:
    """Validated CSV records and evidence-manifest path results."""

    project_root: Path
    deletion_requests: List[Dict[str, str]]
    sample_deletion_requests: List[Dict[str, str]]
    sample_output: List[Dict[str, str]]
    user_identities: List[Dict[str, str]]
    user_audit_log: List[Dict[str, str]]
    system_activity: List[Dict[str, str]]
    deletion_rules: List[Dict[str, str]]
    evidence_files: List[Dict[str, str]]
    evidence_found: Tuple[str, ...]
    evidence_missing: Tuple[str, ...]


def resolve_project_root(project_root: Optional[Path] = None) -> Path:
    """Return the supplied project root or infer it from this source file."""
    if project_root is not None:
        return Path(project_root).expanduser().resolve()
    return Path(__file__).resolve().parents[1]


def _read_csv(path: Path, required_columns: Tuple[str, ...]) -> List[Dict[str, str]]:
    """Read a CSV as strings, validating its header and record shapes."""
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as csv_file:
            reader = csv.reader(csv_file, strict=True)
            try:
                headers = next(reader)
            except StopIteration as error:
                raise ValueError(f"CSV file is empty: {path}") from error

            if len(headers) != len(set(headers)):
                raise ValueError(f"Duplicate column names in {path}: {headers}")

            missing_columns = [
                column for column in required_columns if column not in headers
            ]
            if missing_columns:
                raise ValueError(
                    f"Missing required columns in {path}: "
                    f"{', '.join(missing_columns)}"
                )

            records = []
            for line_number, values in enumerate(reader, start=2):
                if not values:
                    continue
                if len(values) != len(headers):
                    raise ValueError(
                        f"Malformed CSV row in {path} at line {line_number}: "
                        f"expected {len(headers)} fields, found {len(values)}"
                    )
                records.append(dict(zip(headers, values)))
    except csv.Error as error:
        raise ValueError(f"Could not parse CSV file {path}: {error}") from error

    for column in IDENTIFIER_COLUMNS[path.name]:
        blank_rows = [
            str(row_number)
            for row_number, record in enumerate(records, start=2)
            if not record[column].strip()
        ]
        if blank_rows:
            raise ValueError(
                f"Blank identifier values in {path} column '{column}' "
                f"at data row(s): {', '.join(blank_rows[:10])}"
            )

    return records


def _evidence_path_exists(dataset_dir: Path, evidence_path: str) -> bool:
    """Check a manifest path only if it resolves inside dataset/evidence."""
    evidence_root = (dataset_dir / "evidence").resolve()
    candidate = (dataset_dir / evidence_path).resolve()
    try:
        candidate.relative_to(evidence_root)
    except ValueError:
        return False
    return candidate.is_file()


def load_dataset(project_root: Optional[Path] = None) -> Dataset:
    """Load all required inputs and validate the full deletion-request file."""
    root = resolve_project_root(project_root)
    dataset_dir = root / "dataset"
    missing_files = [
        str(dataset_dir / filename)
        for filename in REQUIRED_COLUMNS
        if not (dataset_dir / filename).is_file()
    ]
    if missing_files:
        raise FileNotFoundError(
            "Required dataset file(s) are missing: " + ", ".join(missing_files)
        )

    loaded = {
        filename: _read_csv(dataset_dir / filename, columns)
        for filename, columns in REQUIRED_COLUMNS.items()
    }

    requests = loaded["deletion_requests.csv"]
    if len(requests) != EXPECTED_REQUEST_COUNT:
        raise ValueError(
            "deletion_requests.csv must contain exactly "
            f"{EXPECTED_REQUEST_COUNT} data rows; found {len(requests)}"
        )

    case_ids = [record["case_id"] for record in requests]
    seen_case_ids = set()
    duplicate_case_ids = set()
    for case_id in case_ids:
        if case_id in seen_case_ids:
            duplicate_case_ids.add(case_id)
        seen_case_ids.add(case_id)
    if duplicate_case_ids:
        duplicates = ", ".join(sorted(duplicate_case_ids))
        raise ValueError(f"Duplicate case_id values in deletion_requests.csv: {duplicates}")

    evidence_records = loaded["evidence_files.csv"]
    evidence_found = []
    evidence_missing = []
    for record in evidence_records:
        manifest_path = record["file_path"]
        if _evidence_path_exists(dataset_dir, manifest_path):
            evidence_found.append(manifest_path)
        else:
            evidence_missing.append(manifest_path)

    if evidence_missing:
        LOGGER.warning(
            "%d evidence manifest path(s) are missing under %s",
            len(evidence_missing),
            dataset_dir / "evidence",
        )

    return Dataset(
        project_root=root,
        deletion_requests=requests,
        sample_deletion_requests=loaded["sample_deletion_requests.csv"],
        sample_output=loaded["sample_output.csv"],
        user_identities=loaded["user_identities.csv"],
        user_audit_log=loaded["user_audit_log.csv"],
        system_activity=loaded["system_activity.csv"],
        deletion_rules=loaded["deletion_rules.csv"],
        evidence_files=evidence_records,
        evidence_found=tuple(evidence_found),
        evidence_missing=tuple(evidence_missing),
    )


def print_dataset_summary(dataset: Dataset) -> None:
    """Print record counts and the status of every evidence manifest path."""
    print("Dataset summary")
    print(f"Deletion requests: {len(dataset.deletion_requests)}")
    print(f"Sample requests: {len(dataset.sample_deletion_requests)}")
    print(f"Identity records: {len(dataset.user_identities)}")
    print(f"Audit-log records: {len(dataset.user_audit_log)}")
    print(f"System activity records: {len(dataset.system_activity)}")
    print(f"Deletion rules: {len(dataset.deletion_rules)}")
    print(f"Evidence manifest entries: {len(dataset.evidence_files)}")
    print(f"Evidence files found: {len(dataset.evidence_found)}")
    print(f"Evidence files missing: {len(dataset.evidence_missing)}")
    for path in dataset.evidence_found:
        print(f"FOUND   {path}")
    for path in dataset.evidence_missing:
        print(f"MISSING {path}")
