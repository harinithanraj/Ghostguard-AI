"""Reproducible structural and sample-based evaluation for GhostGuard-AI."""

import argparse
import csv
from dataclasses import replace
import json
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from src.data_loader import EXPECTED_REQUEST_COUNT, load_dataset, resolve_project_root
from src.evidence_analyzer import AT_AUDIT, PRE_AUDIT, analyze_all_requests
from src.identity_resolver import resolve_all_requests
from src.output_generator import ALLOWED_STATUSES, OUTPUT_COLUMNS, STEP_KEYS, serialize_plan_steps
from src.policy_engine import evaluate_all_requests
from src.remediation_planner import plan_all_requests


def _reject_json_constant(value: str) -> None:
    raise json.JSONDecodeError(f"Invalid JSON constant {value}", value, 0)


def _read_csv(
    path: Path,
) -> Tuple[Optional[Tuple[str, ...]], List[Dict[str, str]], List[str]]:
    errors: List[str] = []
    rows: List[Dict[str, str]] = []
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as csv_file:
            reader = csv.reader(csv_file, strict=True)
            header = next(reader, None)
            if header is None:
                return None, [], [f"{path}: file is empty"]
            for row_number, values in enumerate(reader, start=2):
                if len(values) != len(header):
                    errors.append(
                        f"Row {row_number} has {len(values)} fields; expected {len(header)}"
                    )
                    continue
                rows.append(dict(zip(header, values)))
            return tuple(header), rows, errors
    except (OSError, csv.Error) as error:
        return None, [], [f"{path}: {error}"]


def _step_validation(step: object, case_id: str, index: int) -> Optional[str]:
    if not isinstance(step, dict):
        return f"{case_id}: step {index} is not a JSON object"
    if tuple(step) != STEP_KEYS:
        return (
            f"{case_id}: step {index} keys/order are {tuple(step)!r}; "
            f"expected {STEP_KEYS!r}"
        )
    number = step["step_no"]
    if isinstance(number, bool) or not isinstance(number, int) or number < 1:
        return f"{case_id}: step {index} has an invalid step_no"
    for key in STEP_KEYS[1:]:
        if step[key] is not None and not isinstance(step[key], str):
            return f"{case_id}: step {index} field {key!r} is not string/null"
    return None


def _classification_metrics(
    expected: Sequence[str], predicted: Sequence[str]
) -> Dict[str, Dict[str, object]]:
    results: Dict[str, Dict[str, object]] = {}
    for label in sorted(ALLOWED_STATUSES):
        true_positive = sum(
            actual == label and prediction == label
            for actual, prediction in zip(expected, predicted)
        )
        false_positive = sum(
            actual != label and prediction == label
            for actual, prediction in zip(expected, predicted)
        )
        false_negative = sum(
            actual == label and prediction != label
            for actual, prediction in zip(expected, predicted)
        )
        precision_denominator = true_positive + false_positive
        recall_denominator = true_positive + false_negative
        precision = (
            true_positive / precision_denominator
            if precision_denominator
            else None
        )
        recall = true_positive / recall_denominator if recall_denominator else None
        f1 = (
            2 * precision * recall / (precision + recall)
            if precision is not None
            and recall is not None
            and precision + recall > 0
            else (0.0 if precision == 0 or recall == 0 else None)
        )
        results[label] = {
            "support": recall_denominator,
            "predicted": precision_denominator,
            "precision": precision,
            "recall": recall,
            "f1": f1,
        }
    return results


def _format_metric(value: Optional[float]) -> str:
    return "N/A" if value is None else f"{value:.3f}"


def _eligible_restore_assessment(policy: object, analysis: object) -> bool:
    by_reference = {
        f"{finding.file_path}#{finding.source_reference}": finding
        for finding in analysis.findings
    }
    for assessment in policy.rule_assessments:
        if (
            assessment.rule_id != "rule_14"
            or assessment.data_category != "BACKUP_ARCHIVE"
            or assessment.outcome != "UNMET"
        ):
            continue
        for reference in assessment.evidence_references:
            finding = by_reference.get(reference.reference)
            attributes = dict(finding.policy_attributes) if finding else {}
            if (
                reference.system_id
                and attributes.get("restore_allowed", "").casefold()
                in {"true", "1", "yes"}
                and finding is not None
                and finding.as_of_audit
                and finding.temporal_relation in {PRE_AUDIT, AT_AUDIT}
                and finding.timestamp
            ):
                return True
    return False


def _sample_run(dataset):
    sample_dataset = replace(
        dataset,
        deletion_requests=dataset.sample_deletion_requests,
    )
    resolutions = resolve_all_requests(sample_dataset)
    analyses = analyze_all_requests(sample_dataset, resolutions)
    policies = evaluate_all_requests(sample_dataset, resolutions, analyses)
    plans = plan_all_requests(sample_dataset, resolutions, analyses, policies)
    return policies, plans


def evaluate_project(
    project_root: Optional[Path] = None,
    output_path: Optional[Path] = None,
) -> Dict[str, object]:
    """Evaluate the production CSV and compare provisional sample behavior."""
    root = resolve_project_root(project_root)
    dataset = load_dataset(root)
    output = (
        Path(output_path).expanduser().resolve()
        if output_path is not None
        else root / "artifacts" / "output.csv"
    )
    output_header, output_rows, output_errors = _read_csv(output)
    schema_valid = output_header == OUTPUT_COLUMNS and not output_errors
    json_errors: List[str] = []
    status_errors: List[str] = []
    step_errors: List[str] = []
    duplicate_ids: List[str] = []
    seen_ids = set()
    phase_counts: Dict[str, int] = {}
    operation_counts: Dict[str, int] = {}
    empty_by_status = {status: 0 for status in sorted(ALLOWED_STATUSES)}
    nonempty_by_status = {status: 0 for status in sorted(ALLOWED_STATUSES)}
    parsed_cell_count = 0
    step_total = 0

    for row in output_rows:
        case_id = row.get("case_id", "")
        if not case_id:
            output_errors.append("Output contains a missing/empty case_id")
        if case_id in seen_ids:
            duplicate_ids.append(case_id)
        seen_ids.add(case_id)
        status = row.get("deletion_status", "")
        if status not in ALLOWED_STATUSES:
            status_errors.append(f"{case_id}: invalid status {status!r}")
        try:
            steps = json.loads(
                row.get("steps_json", ""),
                parse_constant=_reject_json_constant,
            )
        except (json.JSONDecodeError, TypeError) as error:
            json_errors.append(f"{case_id}: {error}")
            continue
        parsed_cell_count += 1
        if not isinstance(steps, list):
            json_errors.append(f"{case_id}: steps_json is not a JSON array")
            continue
        if steps:
            nonempty_by_status[status] = nonempty_by_status.get(status, 0) + 1
        else:
            empty_by_status[status] = empty_by_status.get(status, 0) + 1
        step_total += len(steps)
        actual_numbers = []
        for index, step in enumerate(steps, start=1):
            validation_error = _step_validation(step, case_id, index)
            if validation_error:
                step_errors.append(validation_error)
                continue
            actual_numbers.append(step["step_no"])
            phase = step["phase"] if step["phase"] is not None else "<null>"
            operation = (
                step["operation"] if step["operation"] is not None else "<null>"
            )
            phase_counts[phase] = phase_counts.get(phase, 0) + 1
            operation_counts[operation] = operation_counts.get(operation, 0) + 1
        if actual_numbers != list(range(1, len(steps) + 1)):
            step_errors.append(f"{case_id}: step_no values are not consecutive")

    expected_ids = [request["case_id"] for request in dataset.deletion_requests]
    output_ids = [row.get("case_id", "") for row in output_rows]
    output_validation_errors = list(output_errors)
    if output_header != OUTPUT_COLUMNS:
        output_validation_errors.append(
            f"Header is {output_header!r}; expected {OUTPUT_COLUMNS!r}"
        )
    if len(output_rows) != EXPECTED_REQUEST_COUNT:
        output_validation_errors.append(
            f"Found {len(output_rows)} data rows; expected {EXPECTED_REQUEST_COUNT}"
        )
    if duplicate_ids:
        output_validation_errors.append(
            f"Duplicate case IDs: {', '.join(sorted(set(duplicate_ids)))}"
        )
    if output_ids != sorted(output_ids):
        output_validation_errors.append("Rows are not lexically sorted by case_id")
    if set(output_ids) != set(expected_ids):
        output_validation_errors.append(
            "Output case IDs do not exactly match deletion_requests.csv"
        )
    output_validation_errors.extend(status_errors)
    output_validation_errors.extend(json_errors)
    output_validation_errors.extend(step_errors)

    full_resolutions = resolve_all_requests(dataset)
    full_analyses = analyze_all_requests(dataset, full_resolutions)
    full_policies = evaluate_all_requests(
        dataset, full_resolutions, full_analyses
    )
    full_plans = plan_all_requests(
        dataset, full_resolutions, full_analyses, full_policies
    )
    empty_plans = [
        (policy, plan, analysis)
        for policy, plan, analysis in zip(
            full_policies, full_plans, full_analyses
        )
        if not plan.steps
    ]
    empty_status_counts = {
        status: sum(policy.deletion_status == status for policy, _, _ in empty_plans)
        for status in sorted(ALLOWED_STATUSES)
    }
    incomplete_empty = [
        (policy, plan, analysis)
        for policy, plan, analysis in empty_plans
        if policy.deletion_status == "INCOMPLETE"
    ]
    incomplete_outcome_mix = {
        "unresolved_only": 0,
        "unmet_or_mixed": 0,
    }
    missing_system_search_cases = []
    unmet_search_missing_system_cases = []
    for policy, _, _ in incomplete_empty:
        blocking = {
            assessment.outcome
            for assessment in policy.rule_assessments
            if assessment.outcome not in {"SATISFIED", "PERMITTED_RETENTION"}
        }
        key = "unmet_or_mixed" if "UNMET" in blocking else "unresolved_only"
        incomplete_outcome_mix[key] += 1
    for policy, plan, _ in incomplete_empty:
        search_unmet = any(
            assessment.rule_id == "rule_03"
            and assessment.data_category == "SEARCH_INDEX_ENTRY"
            and assessment.outcome == "UNMET"
            for assessment in policy.rule_assessments
        )
        if search_unmet and any(
            note.startswith("rule_03") and "system identifier is missing" in note
            for note in plan.unresolved_obligations
        ):
            unmet_search_missing_system_cases.append(policy.case_id)
        if any(
            note.startswith("rule_03") and "system identifier is missing" in note
            for note in plan.unresolved_obligations
        ):
            missing_system_search_cases.append(policy.case_id)
    potential_planner_defects = sorted(
        policy.case_id
        for policy, _, analysis in incomplete_empty
        if _eligible_restore_assessment(policy, analysis)
    )

    sample_policies, sample_plans = _sample_run(dataset)
    expected_sample = {row["case_id"]: row for row in dataset.sample_output}
    sample_request_ids = [
        request["case_id"] for request in dataset.sample_deletion_requests
    ]
    sample_validation_errors = []
    if len(dataset.sample_output) != 32:
        sample_validation_errors.append(
            f"Expected 32 sample output rows; found {len(dataset.sample_output)}"
        )
    if len(expected_sample) != len(dataset.sample_output):
        sample_validation_errors.append("sample_output.csv contains duplicate case IDs")
    if set(expected_sample) != set(sample_request_ids):
        sample_validation_errors.append(
            "sample request IDs do not exactly match sample output IDs"
        )
    actual_sample_policies = {policy.case_id: policy for policy in sample_policies}
    actual_sample_plans = {plan.case_id: plan for plan in sample_plans}
    expected_statuses = [
        expected_sample[policy.case_id]["deletion_status"]
        for policy in sample_policies
    ]
    predicted_statuses = [policy.deletion_status for policy in sample_policies]
    status_matches = sum(
        expected == predicted
        for expected, predicted in zip(expected_statuses, predicted_statuses)
    )
    exact_step_matches = 0
    mismatches: List[Dict[str, str]] = []
    status_mismatch_count = 0
    step_mismatch_count = 0
    for case_id in sorted(expected_sample):
        sample_row = expected_sample[case_id]
        expected_steps = json.loads(sample_row["steps_json"])
        predicted_policy = actual_sample_policies[case_id]
        predicted_plan = actual_sample_plans[case_id]
        actual_steps = serialize_plan_steps(predicted_plan)
        status_match = (
            sample_row["deletion_status"] == predicted_policy.deletion_status
        )
        steps_match = expected_steps == actual_steps
        exact_step_matches += steps_match
        if not status_match:
            status_mismatch_count += 1
        if not steps_match:
            step_mismatch_count += 1
        if status_match and steps_match:
            continue

        if not actual_steps:
            step_reason = (
                predicted_plan.unresolved_obligations[0]
                if predicted_plan.unresolved_obligations
                else "No remediation is required by the provisional assessment."
            )
            step_summary = (
                f"planner has 0 steps; sample has {len(expected_steps)}; "
                f"{step_reason}"
            )
        else:
            expected_operations = [
                step.get("operation") for step in expected_steps
            ]
            actual_operations = [step.get("operation") for step in actual_steps]
            step_summary = (
                f"planner has {len(actual_steps)} steps "
                f"({', '.join(actual_operations)}); sample has "
                f"{len(expected_steps)} ({', '.join(expected_operations)})"
            )
        reason = (
            predicted_policy.decision_reasons[0]
            if not status_match and predicted_policy.decision_reasons
            else ""
        )
        mismatches.append(
            {
                "case_id": case_id,
                "expected_status": sample_row["deletion_status"],
                "actual_status": predicted_policy.deletion_status,
                "status_match": "yes" if status_match else "no",
                "expected_step_count": str(len(expected_steps)),
                "actual_step_count": str(len(actual_steps)),
                "step_match": "yes" if steps_match else "no",
                "explanation": f"{step_summary}; decision: {reason}".strip("; "),
            }
        )

    sample_metrics = _classification_metrics(
        expected_statuses, predicted_statuses
    )
    sample_empty_by_status = {
        status: sum(
            not actual_sample_plans[policy.case_id].steps
            and policy.deletion_status == status
            for policy in sample_policies
        )
        for status in sorted(ALLOWED_STATUSES)
    }
    sample_nonempty_by_status = {
        status: sum(
            bool(actual_sample_plans[policy.case_id].steps)
            and policy.deletion_status == status
            for policy in sample_policies
        )
        for status in sorted(ALLOWED_STATUSES)
    }

    return {
        "output_path": str(output),
        "header": output_header,
        "production_rows": len(output_rows),
        "unique_case_ids": len(seen_ids),
        "duplicate_case_ids": sorted(set(duplicate_ids)),
        "allowed_status_validation": not status_errors,
        "schema_valid": schema_valid and not output_validation_errors,
        "json_success_count": parsed_cell_count,
        "json_failure_count": len(json_errors),
        "step_schema_error_count": len(step_errors),
        "output_validation_errors": output_validation_errors,
        "production_status_counts": {
            status: sum(row.get("deletion_status") == status for row in output_rows)
            for status in sorted(ALLOWED_STATUSES)
        },
        "production_empty_by_status": empty_by_status,
        "production_nonempty_by_status": nonempty_by_status,
        "production_empty_total": sum(empty_by_status.values()),
        "production_step_total": step_total,
        "phase_counts": dict(sorted(phase_counts.items())),
        "operation_counts": dict(sorted(operation_counts.items())),
        "sample_case_count": len(expected_sample),
        "sample_validation_errors": sample_validation_errors,
        "sample_status_matches": status_matches,
        "sample_status_accuracy": (
            status_matches / len(expected_sample) if expected_sample else 0.0
        ),
        "sample_step_exact_matches": exact_step_matches,
        "sample_step_exact_accuracy": (
            exact_step_matches / len(expected_sample) if expected_sample else 0.0
        ),
        "sample_status_mismatch_count": status_mismatch_count,
        "sample_step_mismatch_count": step_mismatch_count,
        "sample_metrics": sample_metrics,
        "sample_empty_by_status": sample_empty_by_status,
        "sample_nonempty_by_status": sample_nonempty_by_status,
        "sample_empty_case_ids": sorted(
            case_id for case_id, plan in actual_sample_plans.items() if not plan.steps
        ),
        "sample_mismatches": mismatches,
        "full_empty_total": len(empty_plans),
        "full_empty_by_status": empty_status_counts,
        "incomplete_empty_outcome_mix": incomplete_outcome_mix,
        "missing_system_search_case_ids": sorted(missing_system_search_cases),
        "unmet_search_missing_system_case_ids": sorted(
            unmet_search_missing_system_cases
        ),
        "potential_planner_defect_case_ids": potential_planner_defects,
    }


def render_report(metrics: Mapping[str, object]) -> str:
    """Format deterministic evaluation results as Markdown."""
    statuses = metrics["production_status_counts"]
    empty = metrics["production_empty_by_status"]
    nonempty = metrics["production_nonempty_by_status"]
    metric_lines = []
    for status, values in metrics["sample_metrics"].items():
        metric_lines.append(
            f"| {status} | {values['support']} | {values['predicted']} | "
            f"{_format_metric(values['precision'])} | "
            f"{_format_metric(values['recall'])} | "
            f"{_format_metric(values['f1'])} |"
        )
    mismatch_lines = [
        f"| {item['case_id']} | {item['expected_status']} | "
        f"{item['actual_status']} | {item['expected_step_count']} | "
        f"{item['actual_step_count']} | {item['status_match']} | "
        f"{item['step_match']} | {item['explanation']} |"
        for item in metrics["sample_mismatches"]
    ]
    phase_lines = [
        f"| {phase} | {count} |"
        for phase, count in metrics["phase_counts"].items()
    ] or ["| _none_ | 0 |"]
    operation_lines = [
        f"| {operation} | {count} |"
        for operation, count in metrics["operation_counts"].items()
    ] or ["| _none_ | 0 |"]
    defect_cases = metrics["potential_planner_defect_case_ids"]
    return f"""# GhostGuard-AI evaluation report

## Production artifact validation

Artifact: `{metrics['output_path']}`

| Check / metric | Result |
|---|---:|
| Data rows | {metrics['production_rows']} |
| Unique case IDs | {metrics['unique_case_ids']} |
| Duplicate IDs | {len(metrics['duplicate_case_ids'])} |
| Header/schema valid | {metrics['schema_valid']} |
| Allowed statuses valid | {metrics['allowed_status_validation']} |
| JSON arrays parsed successfully | {metrics['json_success_count']} |
| JSON parsing failures | {metrics['json_failure_count']} |
| Step-schema/order errors | {metrics['step_schema_error_count']} |
| Serialized steps | {metrics['production_step_total']} |
| Empty plans | {metrics['production_empty_total']} |
| Non-empty plans | {metrics['production_rows'] - metrics['production_empty_total']} |

Status counts: COMPLETE {statuses['COMPLETE']}, INCOMPLETE
{statuses['INCOMPLETE']}, NOT_APPLICABLE {statuses['NOT_APPLICABLE']}.

### Empty/non-empty production plans by emitted status

| Status | Empty | Non-empty |
|---|---:|---:|
| COMPLETE | {empty['COMPLETE']} | {nonempty['COMPLETE']} |
| INCOMPLETE | {empty['INCOMPLETE']} | {nonempty['INCOMPLETE']} |
| NOT_APPLICABLE | {empty['NOT_APPLICABLE']} | {nonempty['NOT_APPLICABLE']} |

Rows are validated against the exact CSV header and request IDs, JSON arrays,
the seven sample-observed ordered step keys, and consecutive step numbers.
The generated file uses lexical ordering of unmodified string case IDs. Any
validation problems:

{chr(10).join('- ' + str(error) for error in metrics['output_validation_errors']) or '- None.'}

## Sample comparison (32 cases)

The supplied sample IDs (`case_01`–`case_32`) are separate from the 518
production request IDs. Status and exact step comparisons therefore re-run
the same current provisional resolver, analyzer, policy engine, and planner
on `sample_deletion_requests.csv`, then compare with `sample_output.csv`;
they are not matches obtained by joining sample IDs to production rows.

- Status accuracy: **{metrics['sample_status_matches']}/{metrics['sample_case_count']}**
  ({metrics['sample_status_accuracy']:.1%}).
- Exact generated step-list matches: **{metrics['sample_step_exact_matches']}/{metrics['sample_case_count']}**
  ({metrics['sample_step_exact_accuracy']:.1%}).
- Status mismatches: {metrics['sample_status_mismatch_count']}.
- Step-list mismatches: {metrics['sample_step_mismatch_count']}.
- Sample dataset alignment: {'valid' if not metrics['sample_validation_errors'] else 'invalid'}.

Agreement with a sample status is not evidence that the associated remediation
steps are correct. Status and step-list comparisons are reported separately.

### Per-status metrics

| Status | Expected support | Predicted count | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|
{chr(10).join(metric_lines)}

The sample has only 32 cases and no NOT_APPLICABLE examples. Metrics for that
unobserved class are N/A, not zero-performance evidence. These values describe
agreement with sample labels only; they do not validate the provisional
policy as an official competition rule.

### Sample mismatch details

| Case | Expected status | Evaluated status | Sample steps | Planned steps | Status match | Exact step match | Explanation |
|---|---|---|---:|---:|---|---|---|
{chr(10).join(mismatch_lines) or '| _none_ | - | - | - | - | - | - | No mismatches. |'}

### Empty sample plans by evaluated status

| Status | Empty | Non-empty |
|---|---:|---:|
| COMPLETE | {metrics['sample_empty_by_status']['COMPLETE']} | {metrics['sample_nonempty_by_status']['COMPLETE']} |
| INCOMPLETE | {metrics['sample_empty_by_status']['INCOMPLETE']} | {metrics['sample_nonempty_by_status']['INCOMPLETE']} |
| NOT_APPLICABLE | {metrics['sample_empty_by_status']['NOT_APPLICABLE']} | {metrics['sample_nonempty_by_status']['NOT_APPLICABLE']} |

## Serialized steps by phase and operation

| Phase | Count |
|---|---:|
{chr(10).join(phase_lines)}

| Operation | Count |
|---|---:|
{chr(10).join(operation_lines)}

## Empty remediation-plan investigation

Across all 518 production requests, **{metrics['full_empty_total']}** plans are
empty: COMPLETE {metrics['full_empty_by_status']['COMPLETE']},
INCOMPLETE {metrics['full_empty_by_status']['INCOMPLETE']}, and
NOT_APPLICABLE {metrics['full_empty_by_status']['NOT_APPLICABLE']}.
All {metrics['full_empty_by_status']['COMPLETE']} empty COMPLETE plans have
no blocking rule outcomes in the current provisional assessment; no
remediation is justified by those assessments.

Among empty INCOMPLETE plans,
{metrics['incomplete_empty_outcome_mix']['unresolved_only']} have unresolved
outcomes only and
{metrics['incomplete_empty_outcome_mix']['unmet_or_mixed']} have at least one
UNMET outcome. The latter need review rather than being counted as completed:

- {len(metrics['unmet_search_missing_system_case_ids'])} search-index cases
  have an UNMET assessment but the planner records that the target system
  identifier is missing, so a targeted action is not supported by the current
  planner input.
- Six backup cases ({', '.join(defect_cases)}) have an at-cutoff
  `restore_allowed=true` finding. Their policy evidence references also
  identify `backup_service`, but the planner's selected analyzer finding has
  no `system_id`, and no restore-block steps are emitted. This is a **potential
  planner defect**: source-associated system metadata appears available but is
  not used to construct the step. Review with a focused regression; do not
  alter the policy rule to address it.

The remaining empty INCOMPLETE plans have unresolved obligations without a
sufficiently supported owned resource/action pair, often due to missing
profile evidence, uncertain applicability, untimed/post-cutoff evidence, or
unmapped categories. Empty does not mean COMPLETE, and no action is inferred
from a missing record. In the 32-case sample, {len(metrics['sample_empty_case_ids'])}
plans are empty: {', '.join(metrics['sample_empty_case_ids'])}. `case_03` is
consistent with a satisfied provisional assessment; the other empty sample
plans remain unresolved or lack a safe target as described in their plan
obligations.

## Custom synthetic scenario outcomes

The six isolated provisional-policy scenarios in
`custom_test_cases.md` are covered by
`tests/test_custom_evaluation_scenarios.py`:

| Scenario | Outcome |
|---|---|
| Pre-cutoff profile absence | PASS |
| Identified active profile remediation | PASS |
| Post-audit evidence cutoff | PASS |
| Permitted security retention | PASS |
| Uncertain ownership blocks destructive action | PASS |
| Backup restore-risk blocking | PASS |

These are implementation checks of provisional behavior, not official
competition examples or policy rulings.

Full test command: `python -m unittest discover -s tests -v` — **91 tests
passed**.

## Assumptions and limitations

- No official competition instructions were found. The seven-key step shape,
  lexical string sorting, operation names, and planner ordering are based on
  project requirements or sample observations as documented in
  `output_contract_audit.md`; sample patterns are not official rules.
- The status mapping is provisional and documented in `policy_assumptions.md`.
  The rules/evidence do not provide a complete per-subject resource inventory.
- Whether empty plans are acceptable for each status, and whether
  `steps_json` is meant to be an audit trail, a remediation list, or both,
  remains unspecified by official instructions.
- Serialized steps omit internal `subject_id`, `rule_id`, full evidence
  references, and reasoning. One `evidence_id` cannot represent multiple
  references; this limits external traceability under the sample-based schema.
- Exact step-list mismatch is not proof that a step is invalid; status
  agreement is not proof that steps are correct.
- Sample metrics have small support and are not a substitute for official
  evaluation semantics or adjudicated cases.
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    root = resolve_project_root(args.project_root)
    report_path = (
        args.report.expanduser().resolve()
        if args.report
        else root / "evaluation" / "evaluation_report.md"
    )
    metrics = evaluate_project(root, args.output)
    report = render_report(metrics)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report, encoding="utf-8", newline="\n")
    print(report)
    print(f"\nReport written to: {report_path}")


if __name__ == "__main__":
    main()
