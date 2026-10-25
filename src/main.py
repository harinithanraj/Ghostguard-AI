"""Command-line entry point for loading and summarizing the audit dataset."""

import argparse
import logging
from collections import Counter

if __package__:
    from .data_loader import EXPECTED_REQUEST_COUNT, load_dataset, print_dataset_summary
    from .evidence_analyzer import analyze_all_requests
    from .identity_resolver import resolve_all_requests
    from .output_generator import write_output_csv
    from .policy_engine import evaluate_all_requests
    from .remediation_planner import plan_all_requests
else:
    from data_loader import EXPECTED_REQUEST_COUNT, load_dataset, print_dataset_summary
    from evidence_analyzer import analyze_all_requests
    from identity_resolver import resolve_all_requests
    from output_generator import write_output_csv
    from policy_engine import evaluate_all_requests
    from remediation_planner import plan_all_requests


def main() -> None:
    """Load and analyze the dataset, optionally generating the output CSV."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--generate-output",
        action="store_true",
        help="write the validated development CSV to artifacts/output.csv",
    )
    parser.add_argument(
        "--output",
        help=(
            "output CSV path (also enables output generation); defaults to "
            "artifacts/output.csv under the project root"
        ),
    )
    arguments = parser.parse_args()

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
    dataset = load_dataset()
    print_dataset_summary(dataset)
    resolutions = resolve_all_requests(dataset)
    status_counts = Counter(resolution.status for resolution in resolutions)
    print("Identity resolution summary")
    for status in ("CONFIRMED", "UNCERTAIN", "CONFLICTING", "UNMATCHED"):
        print(f"{status}: {status_counts.get(status, 0)}")
    evidence_analyses = analyze_all_requests(dataset, resolutions)
    finding_count = sum(len(analysis.findings) for analysis in evidence_analyses)
    conflict_count = sum(len(analysis.conflicts) for analysis in evidence_analyses)
    gap_count = len(
        {
            (gap.file_path, gap.reason)
            for analysis in evidence_analyses
            for gap in analysis.gaps
        }
    )
    print("Evidence analysis summary")
    print(f"Requests analyzed: {len(evidence_analyses)}")
    print(f"Identity-linked findings: {finding_count}")
    print(f"Evidence conflicts: {conflict_count}")
    print(f"Evidence source gaps (unique): {gap_count}")

    if arguments.generate_output or arguments.output is not None:
        policy_results = evaluate_all_requests(
            dataset, resolutions, evidence_analyses
        )
        plans = plan_all_requests(
            dataset, resolutions, evidence_analyses, policy_results
        )
        policy_counts = Counter(result.deletion_status for result in policy_results)
        output_path = write_output_csv(
            dataset.deletion_requests,
            policy_results,
            plans,
            output_path=arguments.output,
            project_root=dataset.project_root,
            expected_row_count=EXPECTED_REQUEST_COUNT,
        )
        print(f"Output rows: {len(dataset.deletion_requests)}")
        for status in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"):
            print(f"{status}: {policy_counts.get(status, 0)}")
        print(f"Empty remediation plans: {sum(not plan.steps for plan in plans)}")
        print(f"Output CSV: {output_path}")


if __name__ == "__main__":
    main()
