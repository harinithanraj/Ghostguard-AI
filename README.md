# Ghost Data Still Exists

Phases 1 through 4 load and validate supplied inputs, resolve request emails
against current identity records and explicitly linked historical email
values, extract identity-linked evidence, and evaluate the supplied deletion
rules with a provisional policy engine. They do not call an AI service.

## Run the dataset summary

From any working directory, run the entry point by its full path:

```powershell
python C:\path\to\GhostGuard-AI\src\main.py
```

The loader locates the project root relative to `src\data_loader.py`, checks
the required CSV files and columns, validates that `deletion_requests.csv`
contains 518 unique case IDs, and prints record counts and the status of each
evidence-manifest path. The entry point also prints identity-resolution and
evidence-analysis counts. Missing or unreadable files are reported, not
synthesized.

Identity results preserve each request's case ID and email, list candidate
user IDs separately, and include evidence references and explanations.
Statuses are `CONFIRMED`, `UNCERTAIN`, `CONFLICTING`, and `UNMATCHED`; these
are identity-resolution statuses, not deletion decisions. Exact email matches
are used. Historical values are considered only when an audit record links
them to a user ID.

Evidence analysis records direct identifier matches and resource-linked
indirect matches, source paths and record references, relevant timestamps,
systems, resources, operations, and findings. Records later than `audit_at`
are retained for review but are not treated as proof of the earlier state.
An empty evidence search is not interpreted as proof of deletion.

The policy engine returns structured per-case rule assessments and only uses
`COMPLETE`, `INCOMPLETE`, and `NOT_APPLICABLE` as deletion statuses. Its
provisional status mapping and limits are documented in
[evaluation/policy_assumptions.md](./evaluation/policy_assumptions.md). The
entry point can optionally run the planner and output writer.

JSON, SQLite-compatible SQL snapshots, key-value logs, plain-text records,
and `system_activity.csv` are parsed. Text embedded in PDFs is extracted with
`pypdf`, with page numbers retained as source references. On Windows, PNG
evidence is interpreted using local Windows OCR and the language packs
installed for the current user. Scanned PDFs are not OCRed. If PDF text
extraction or local image OCR is unavailable or fails, the source is reported
as an evidence-extraction gap; no content is guessed. OCR text may contain
recognition errors and should be checked against the cited image.

Event timestamps are compared with each request's own `audit_at` after
normalization to UTC. Timestamps without a timezone, missing or invalid event
timestamps, and invalid audit times are classified as `UNKNOWN`; file capture
times remain separate metadata and do not replace event times. An event
exactly at `audit_at` is classified as `AT_AUDIT` and is considered available
at the inclusive audit boundary. Opposing explicit states are marked as a
conflict only when they refer to the same resource at the same normalized
event instant; later state changes remain separate findings.

## Run the tests

From the project root:

```powershell
python -m unittest discover -s tests -v
```

To inspect an individual result from the project root:

```powershell
python -c "from src.data_loader import load_dataset; from src.identity_resolver import resolve_all_requests; print(resolve_all_requests(load_dataset())[0])"
```

To inspect identity-linked evidence for an individual request:

```powershell
python -c "from src.data_loader import load_dataset; from src.identity_resolver import resolve_all_requests; from src.evidence_analyzer import analyze_all_requests; d=load_dataset(); print(analyze_all_requests(d, resolve_all_requests(d))[0])"
```

To evaluate the full request set with the provisional policy engine:

```powershell
python -c "from src.data_loader import load_dataset; from src.policy_engine import evaluate_all_requests; d=load_dataset(); results=evaluate_all_requests(d); print(results[0])"
```

This returns structured policy results in request order. It does not write an
output file or create remediation steps.

## Plan evidence-backed remediation

Phase 5 exposes a deterministic planner that accepts the policy results,
identity resolutions, and evidence analyses. It proposes steps but never
executes them:

```powershell
python -c "from src.data_loader import load_dataset; from src.remediation_planner import plan_all_requests; plans=plan_all_requests(load_dataset()); print(plans[0])"
```

Each plan retains the case, confirmed subject when available, rule, system,
resource, source references, reason, operation, phase, and sequential step
number. Use `plan.to_steps_json_value()` to get a JSON-serializable list. The
sample output is the only supplied step-format example; exact acceptance of
additional traceability fields and official operation ordering are not
specified. These limits and the planner's conservative behavior are documented
in [evaluation/policy_assumptions.md](./evaluation/policy_assumptions.md).
The planner does not execute any proposed operation. The main pipeline can
serialize the plans to a validated development CSV when explicitly requested.

## Generate and validate the development CSV

From the project root, run:

```powershell
python -m src.main --generate-output
```

This executes the loader, identity resolver, evidence analyzer, provisional
policy engine, and remediation planner, then writes and reopens the validated
518-row CSV at `artifacts/output.csv`. The writer checks the exact header,
unique and lexically sorted string case IDs, allowed statuses, JSON-array
syntax, ordered step keys, and consecutive step numbers. Its default path is
under `artifacts/`; it does not select or overwrite `dataset/output.csv`.

To choose a different destination (which explicitly authorizes that path):

```powershell
python -m src.main --output artifacts/output.csv
```

The serialized step objects use the seven keys observed in the supplied
sample output: `step_no`, `phase`, `system_id`, `resource_id`, `operation`,
`state`, and `evidence_id`. This is a sample-based compatibility choice, not a
confirmed official competition schema. Additional provenance such as
`subject_id`, `rule_id`, evidence references, and reasons remains available in
the in-memory plan but is not represented in those seven output fields. The
official operation vocabulary, ordering contract, and acceptance of extra
keys remain unresolved; see
[evaluation/output_contract_audit.md](./evaluation/output_contract_audit.md).

## Evaluate the development output

From the project root, run:

```powershell
python -m evaluation.evaluate
```

This reads and validates `artifacts/output.csv`, reports production row,
status, JSON, schema, phase, operation, and empty-plan counts, then evaluates
all 32 sample requests through the current provisional pipeline for separate
status and exact step-list comparisons against `dataset/sample_output.csv`.
The deterministic Markdown report is written to
`evaluation/evaluation_report.md`. Evaluation and custom-scenario limitations
are documented in
[evaluation/custom_test_cases.md](./evaluation/custom_test_cases.md) and
[evaluation/output_contract_audit.md](./evaluation/output_contract_audit.md).