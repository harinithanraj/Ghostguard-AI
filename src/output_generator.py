"""Validated CSV serialization for policy and remediation results."""

import csv
import json
import os
from pathlib import Path
import tempfile
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

if __package__:
    from .data_loader import resolve_project_root
else:
    from data_loader import resolve_project_root


OUTPUT_COLUMNS = ("case_id", "deletion_status", "steps_json")
ALLOWED_STATUSES = frozenset({"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"})
STEP_KEYS = (
    "step_no",
    "phase",
    "system_id",
    "resource_id",
    "operation",
    "state",
    "evidence_id",
)


def _required_string(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _reject_json_constant(value: str) -> None:
    raise json.JSONDecodeError(f"Invalid JSON constant {value}", value, 0)


def _read_field(item: object, field_name: str, context: str) -> object:
    if isinstance(item, Mapping):
        if field_name not in item:
            raise ValueError(f"{context} is missing required field {field_name!r}")
        return item[field_name]
    if not hasattr(item, field_name):
        raise ValueError(f"{context} is missing required field {field_name!r}")
    return getattr(item, field_name)


def _index_records(
    records: Sequence[object],
    *,
    context: str,
    status_field: Optional[str] = None,
) -> Dict[str, object]:
    indexed: Dict[str, object] = {}
    for index, record in enumerate(records):
        case_id = _required_string(
            _read_field(record, "case_id", f"{context} at index {index}"),
            f"{context} case_id",
        )
        if case_id in indexed:
            raise ValueError(f"Duplicate case_id {case_id!r} in {context}")
        if status_field is not None:
            status = _required_string(
                _read_field(record, status_field, f"{context} for {case_id!r}"),
                f"{context} {status_field}",
            )
            if status not in ALLOWED_STATUSES:
                raise ValueError(
                    f"Invalid deletion status {status!r} for case_id {case_id!r}; "
                    f"expected one of {', '.join(sorted(ALLOWED_STATUSES))}"
                )
        indexed[case_id] = record
    return indexed


def _normalize_step(step: object, case_id: str, step_index: int) -> Dict[str, object]:
    context = f"Step {step_index} for case_id {case_id!r}"
    if isinstance(step, Mapping):
        keys = set(step)
        if keys != set(STEP_KEYS):
            missing = sorted(set(STEP_KEYS) - keys)
            extra = sorted(keys - set(STEP_KEYS))
            raise ValueError(
                f"{context} must use exactly the sample-observed step keys; "
                f"missing={missing}, extra={extra}"
            )
        values = step
    else:
        values = {}
        for key in STEP_KEYS:
            if not hasattr(step, key):
                raise ValueError(f"{context} is missing required field {key!r}")
            values[key] = getattr(step, key)
        step_case_id = getattr(step, "case_id", case_id)
        if step_case_id != case_id:
            raise ValueError(
                f"{context} case_id {step_case_id!r} does not match its request"
            )

    step_no = values["step_no"]
    if isinstance(step_no, bool) or not isinstance(step_no, int) or step_no < 1:
        raise ValueError(f"{context} step_no must be a positive integer")
    normalized: Dict[str, object] = {"step_no": step_no}
    for key in STEP_KEYS[1:]:
        value = values[key]
        if value is not None and not isinstance(value, str):
            raise ValueError(f"{context} {key} must be a string or None")
        normalized[key] = value
    return normalized


def _steps_for_case(plan: object, case_id: str) -> List[Dict[str, object]]:
    plan_case_id = _required_string(
        _read_field(plan, "case_id", f"Remediation plan for {case_id!r}"),
        "Remediation plan case_id",
    )
    if plan_case_id != case_id:
        raise ValueError(
            f"Remediation plan case_id {plan_case_id!r} does not match request "
            f"{case_id!r}"
        )

    steps = _read_field(plan, "steps", f"Remediation plan for {case_id!r}")
    if isinstance(steps, (str, bytes)) or not isinstance(steps, Sequence):
        raise ValueError(f"Remediation plan steps for {case_id!r} must be a sequence")
    normalized = [
        _normalize_step(step, case_id, index)
        for index, step in enumerate(steps, start=1)
    ]
    actual_numbers = [step["step_no"] for step in normalized]
    expected_numbers = list(range(1, len(normalized) + 1))
    if actual_numbers != expected_numbers:
        raise ValueError(
            f"Step numbers for case_id {case_id!r} must be consecutive and "
            "match the plan order"
        )
    return normalized


def serialize_plan_steps(plan: object) -> List[Dict[str, object]]:
    """Project a rich plan into the seven sample-observed output fields."""
    case_id = _required_string(
        _read_field(plan, "case_id", "Remediation plan"),
        "Remediation plan case_id",
    )
    return _steps_for_case(plan, case_id)


def _validate_csv(
    path: Path,
    *,
    expected_row_count: Optional[int],
    expected_case_ids: Optional[Sequence[str]],
) -> Tuple[Dict[str, str], ...]:
    records: List[Dict[str, str]] = []
    case_ids: List[str] = []
    try:
        with path.open("r", encoding="utf-8", newline="") as csv_file:
            reader = csv.reader(csv_file, strict=True)
            headers = next(reader, None)
            if tuple(headers or ()) != OUTPUT_COLUMNS:
                raise ValueError(
                    f"Invalid output header in {path}: {headers!r}; "
                    f"expected {list(OUTPUT_COLUMNS)!r}"
                )

            for row_number, row in enumerate(reader, start=2):
                if len(row) != len(OUTPUT_COLUMNS):
                    raise ValueError(
                        f"Output row {row_number} in {path} has {len(row)} columns; "
                        f"expected {len(OUTPUT_COLUMNS)}"
                    )
                record = dict(zip(OUTPUT_COLUMNS, row))
                case_id = _required_string(record["case_id"], f"row {row_number} case_id")
                if record["deletion_status"] not in ALLOWED_STATUSES:
                    raise ValueError(
                        f"Invalid deletion status {record['deletion_status']!r} "
                        f"for case_id {case_id!r}"
                    )
                try:
                    steps = json.loads(
                        record["steps_json"],
                        parse_constant=_reject_json_constant,
                    )
                except json.JSONDecodeError as error:
                    raise ValueError(
                        f"Invalid steps_json for case_id {case_id!r}: {error}"
                    ) from error
                if not isinstance(steps, list):
                    raise ValueError(
                        f"steps_json for case_id {case_id!r} must be a JSON array"
                    )
                for step_index, step in enumerate(steps, start=1):
                    if not isinstance(step, dict) or tuple(step) != STEP_KEYS:
                        raise ValueError(
                            f"Step {step_index} for case_id {case_id!r} must be an "
                            f"object with ordered keys {STEP_KEYS!r}"
                        )
                    _normalize_step(step, case_id, step_index)
                if [step["step_no"] for step in steps] != list(
                    range(1, len(steps) + 1)
                ):
                    raise ValueError(
                        f"Step numbers for case_id {case_id!r} are not consecutive"
                    )
                case_ids.append(case_id)
                records.append(record)
    except (OSError, csv.Error) as error:
        raise ValueError(f"Could not read and validate output CSV {path}: {error}") from error

    if expected_row_count is not None and len(records) != expected_row_count:
        raise ValueError(
            f"Output CSV {path} has {len(records)} data rows; "
            f"expected {expected_row_count}"
        )
    if len(case_ids) != len(set(case_ids)):
        raise ValueError(f"Output CSV {path} contains duplicate case_id values")
    if case_ids != sorted(case_ids):
        raise ValueError(f"Output CSV {path} is not sorted lexically by case_id")
    if expected_case_ids is not None and case_ids != sorted(expected_case_ids):
        raise ValueError(
            f"Output CSV case IDs do not match the supplied deletion requests"
        )
    return tuple(records)


def validate_output_csv(
    output_path: Path,
    *,
    expected_row_count: Optional[int] = None,
    expected_case_ids: Optional[Sequence[str]] = None,
) -> Tuple[Dict[str, str], ...]:
    """Reopen and validate a generated CSV, returning its parsed data rows."""
    return _validate_csv(
        Path(output_path),
        expected_row_count=expected_row_count,
        expected_case_ids=expected_case_ids,
    )


def write_output_csv(
    deletion_requests: Sequence[Mapping[str, object]],
    policy_results: Sequence[object],
    remediation_plans: Sequence[object],
    output_path: Optional[Path] = None,
    *,
    project_root: Optional[Path] = None,
    expected_row_count: Optional[int] = None,
) -> Path:
    """Write one validated output row per request using deterministic ordering.

    ``case_id`` ordering uses Python's lexical string ordering, matching the
    project's documented interpretation of sorting without converting IDs to
    numbers. The default destination is ``artifacts/output.csv`` under the
    project root; the dataset's supplied output is never selected implicitly.
    """
    if not isinstance(deletion_requests, Sequence) or isinstance(
        deletion_requests, (str, bytes)
    ):
        raise ValueError("deletion_requests must be a sequence of request records")
    requests_by_id = _index_records(deletion_requests, context="deletion requests")
    policies_by_id = _index_records(
        policy_results, context="policy results", status_field="deletion_status"
    )
    plans_by_id = _index_records(remediation_plans, context="remediation plans")

    request_ids = set(requests_by_id)
    for context, indexed in (
        ("policy results", policies_by_id),
        ("remediation plans", plans_by_id),
    ):
        if set(indexed) != request_ids:
            missing = sorted(request_ids - set(indexed))
            extra = sorted(set(indexed) - request_ids)
            raise ValueError(
                f"{context} must have exactly one result per request; "
                f"missing={missing}, extra={extra}"
            )
    if expected_row_count is not None and len(requests_by_id) != expected_row_count:
        raise ValueError(
            f"Expected {expected_row_count} deletion requests; found "
            f"{len(requests_by_id)}"
        )

    root = resolve_project_root(project_root)
    destination = (
        Path(output_path).expanduser().resolve()
        if output_path is not None
        else (root / "artifacts" / "output.csv").resolve()
    )
    destination.parent.mkdir(parents=True, exist_ok=True)

    rows: List[Tuple[str, str, str]] = []
    for case_id in sorted(request_ids):
        policy = policies_by_id[case_id]
        status = _required_string(
            _read_field(policy, "deletion_status", f"Policy result for {case_id!r}"),
            f"Policy result deletion_status for {case_id!r}",
        )
        if status not in ALLOWED_STATUSES:
            raise ValueError(
                f"Invalid deletion status {status!r} for case_id {case_id!r}"
            )
        steps = serialize_plan_steps(plans_by_id[case_id])
        steps_json = json.dumps(
            steps,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )
        rows.append((case_id, status, steps_json))

    if expected_row_count is not None and len(rows) != expected_row_count:
        raise ValueError(
            f"Expected {expected_row_count} output rows; found {len(rows)}"
        )
    if [row[0] for row in rows] != sorted(request_ids):
        raise ValueError("Prepared output rows are not deterministically sorted")

    temporary_path: Optional[Path] = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=str(destination.parent),
        )
        temporary_path = Path(temporary_name)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as csv_file:
            writer = csv.writer(csv_file, lineterminator="\n")
            writer.writerow(OUTPUT_COLUMNS)
            writer.writerows(rows)
            csv_file.flush()
            os.fsync(csv_file.fileno())

        _validate_csv(
            temporary_path,
            expected_row_count=expected_row_count,
            expected_case_ids=tuple(request_ids),
        )
        os.replace(temporary_path, destination)
        temporary_path = None
        _validate_csv(
            destination,
            expected_row_count=expected_row_count,
            expected_case_ids=tuple(request_ids),
        )
    finally:
        if temporary_path is not None:
            temporary_path.unlink()

    return destination
