# Pre-release output-contract audit

## Scope and source authority

No original competition instructions, Orchestrate prompt, or formal schema
document was found in the workspace. `src/output_generator.py` exists but is
empty. The project request provided in the conversation specifies the final
top-level columns as `case_id,deletion_status,steps_json`, exactly 518 data
rows, and sorting by `case_id`; the supplied CSVs provide sample evidence for
those requirements. The sample files do not by themselves prove the official
competition contract.

This report separates:

- **Project-request requirement:** explicitly required by the project owner.
- **Sample-observed:** true in all 32 supplied examples, but not confirmed as
  an official rule beyond those examples.
- **Unresolved:** cannot be determined from available instructions or data.

The original contract audit did not create or modify an output file. Phase 6
subsequently added a development writer and generated `artifacts/output.csv`;
the supplied `dataset/output.csv` was not changed.

## 1. Required output schema

### Top-level CSV

| Item | Audit finding | Authority |
|---|---|---|
| Header and order | `case_id,deletion_status,steps_json` | Project-request requirement; also exactly matches `sample_output.csv` header and the header-only `dataset/output.csv` |
| Data-row count | 518 | Project-request requirement; `deletion_requests.csv` contains 518 unique request IDs |
| Case ordering | Sort by `case_id` while preserving IDs as strings | Project-request requirement. Numeric-versus-lexical sorting is not defined; do not parse IDs as integers or normalize/pad them |
| Status values | `COMPLETE`, `INCOMPLETE`, `NOT_APPLICABLE` | Project-request requirement and policy-engine output constraints |
| Final CSV writer | `src/output_generator.py` writes and reopens output for validation; `src/main.py` integrates it behind an explicit CLI option | Current implementation fact |

The sample request and output files each contain 32 rows. The 518 full-request
IDs are strings and unique; the range represented is `case_33` through
`case_550`. Sorting lexically preserves their original spellings. The sample
IDs such as `case_01` also demonstrate why conversion to integers and
reconstruction is unsafe: it would discard leading zeros.

### `steps_json`

Each of the 32 sample cells parses as a JSON array. Across all 193 sample steps:

- Every step is an object with exactly these seven keys:
  `step_no`, `phase`, `system_id`, `resource_id`, `operation`, `state`,
  `evidence_id`.
- `step_no` is an integer, starts at 1 for each case, and is consecutive.
- The observed phases are `FINDING`, `REMEDIATION`, and `VERIFICATION`.
- All sample phase sequences are nondecreasing in the order
  `FINDING` → `REMEDIATION` → `VERIFICATION`.
- The sample contains 15 distinct operation names, all listed in the
  ordering section below.

These are **sample-observed**, not confirmed official restrictions. No
available instruction says whether additional step keys are accepted. The
current planner's `to_steps_json_value()` includes the seven sample keys plus
`case_id`, `subject_id`, `rule_id`, `evidence_references`, and `reason`.
Therefore the planner's JSON shape is not sample-exact. This is a
compatibility risk, not a proven competition rejection, because permission for
additional fields is undocumented.

Recommended before output generation: retain rich provenance in the internal
`RemediationStep`, but add an explicit serialization adapter that emits exactly
the seven sample keys unless official instructions confirm extra keys are
allowed. Do not silently lose traceability from the internal plan.

## 2. Ordering and operation contract

### Confirmed versus observed

No formal phase order, operation allowlist/order, or system/resource
tie-breakers are defined in any available instruction file. In all 32 sample
plans, phases are grouped monotonically as `FINDING`, then `REMEDIATION`, then
`VERIFICATION`; this is consistent observed behavior, not a written official
contract.

The sample's 41 remediation operations appear in nine distinct operation
sequences:

| Remediation operation sequence | Sample cases |
|---|---:|
| `DELETE_RECORD` | 6 |
| `BLOCK_RESTORE` | 3 |
| `DISABLE_DATA_FLOW`, `DELETE_RECORD`, `REDACT_RECORD`, `ANONYMIZE_RECORD` | 4 |
| `DELETE_RECORD`, `DELETE_RECORD` | 4 |
| `DISABLE_DATA_FLOW` | 1 |
| `DELETE_RECORD`, `REDACT_RECORD` | 1 |
| `DISABLE_DATA_FLOW`, `DELETE_RECORD` | 1 |
| `DELETE_RECORD`, `ANONYMIZE_RECORD` | 1 |
| `REDACT_RECORD` | 1 |

The 15 operation names observed anywhere in sample steps are:

`REPORT_REMAINING_RECORD`, `REPORT_EXPOSED_PII`,
`REPORT_ACTIVE_DATA_FLOW`, `REPORT_RESTORE_RISK`, `DELETE_RECORD`,
`REDACT_RECORD`, `ANONYMIZE_RECORD`, `DISABLE_DATA_FLOW`, `BLOCK_RESTORE`,
`VERIFY_RECORD_ABSENT`, `VERIFY_RECORD_PRESENT`,
`VERIFY_RECORD_REDACTED`, `VERIFY_RECORD_ANONYMIZED`,
`VERIFY_DATA_FLOW_DISABLED`, and `VERIFY_RESTORE_BLOCKED`.

No formal source declares this list exhaustive or explains when each reporting
or verification step is mandatory. All 32 samples are phase-monotonic, but
system/resource sorting is not a consistent sample rule: within phase groups,
system order is sorted in only 26/26 finding groups, 27/27 remediation groups,
and 13/31 verification groups. A universal system/resource tie-breaker cannot
be inferred.

### Current planner comparison

`src/remediation_planner.py` orders phase, then case-insensitive
`system_id`, `resource_id`, `rule_id`, `operation`, and source references.
This matches the sample's broad phase grouping but is not supported as an
official tie-breaker. Its lexical sort can produce a different ordering from
the sample's remediation sequence (for example, sample multi-action cases
place `DISABLE_DATA_FLOW` before record deletion/redaction/anonymization).

The planner's sorting is deterministic and tested; do not label it the
competition ordering contract. Recommended before release: obtain the actual
instructions or treat an agreed, explicit project contract as a prerequisite
for final output generation. Until then, document the chosen implementation
order as provisional.

## 3. Status and step-list consistency

The sample contains:

| Status | Cases | Empty step arrays | Non-empty step arrays |
|---|---:|---:|---:|
| COMPLETE | 10 | 0 | 10 |
| INCOMPLETE | 22 | 0 | 22 |
| NOT_APPLICABLE | 0 | Unknown | Unknown |

Thus, the examples do **not** establish the meaning of an empty list or whether
either status may legally have an empty list. In particular, do not infer that
empty means `COMPLETE`. The project policy mapping is provisional and distinct
from the step-list contract.

The planner yields empty arrays for all ten COMPLETE sample cases and for
twelve INCOMPLETE cases; it yields non-empty arrays for the other ten
INCOMPLETE cases. Across the 32 sample requests, **22 plans are empty**:

| Empty-plan cases | Sample / policy status | Evidence-based explanation |
|---|---|---|
| case_03 | COMPLETE / COMPLETE | All evaluated applicable rules are satisfied. No remediation is justified by the current policy/evidence inputs. |
| case_01, case_02, case_04, case_10, case_16, case_21, case_22, case_25 | COMPLETE / INCOMPLETE for case_01, case_02, case_04, case_21, case_25; INCOMPLETE / INCOMPLETE otherwise | The required profile state is unresolved because there is no eligible identity-linked profile resource to target. Related findings do not establish that a specific profile belongs to the subject. |
| case_07 | INCOMPLETE / INCOMPLETE | Profile ownership is not evidenced; the additional category is supported only by post-audit or untimed evidence. |
| case_09 | INCOMPLETE / INCOMPLETE | No linked profile target is established, and restore access for the backup remains unresolved; deletion is not justified. |
| case_14 | INCOMPLETE / INCOMPLETE | Security-retention and restore obligations are unresolved; the planner correctly proposes no destructive action against retained/uncertain records. |
| case_15 | INCOMPLETE / INCOMPLETE | The security record is not established as permitted retention, and there is no safe action supported for it. |
| case_23 | INCOMPLETE / INCOMPLETE | Profile, search, export, and retention obligations remain unresolved; relevant resources lack sufficient target-system or eligible timestamp evidence. |
| case_24 | INCOMPLETE / INCOMPLETE | Resource findings exist, but missing system identifiers or eligible at-cutoff state prevent safe targeting. |
| case_26 | COMPLETE / INCOMPLETE | Support-message shared-context applicability is unresolved; redaction is not justified without knowing whether required context would be removed. |
| case_27 | COMPLETE / INCOMPLETE | Profile evidence lacks a reliable eligible timestamp, and support-message applicability is unresolved. |
| case_28 | COMPLETE / INCOMPLETE | No eligible linked profile target is established; support-message shared-context applicability is also unresolved. |
| case_29, case_30 | INCOMPLETE / INCOMPLETE | Multiple categories and unmapped evidence remain unresolved; the planner does not infer ownership or invent targets. |
| case_31, case_32 | COMPLETE / INCOMPLETE for case_31; INCOMPLETE / INCOMPLETE for case_32 | Profile evidence is unresolved, with retention/tombstone requirements not established sufficiently for a safe action. |

The actual policy results, rule assessments, evidence analyses, and
`RemediationPlan.unresolved_obligations` were inspected for these cases. The
planner receives both the policy results and evidence analyses; the empty
plans do not result from an omitted input interface. For `case_03`, no
remediation is warranted under the current assessment. For the other empty
plans, the policy has unresolved obligations but no sufficiently evidenced
resource/action pair that can be safely proposed. The sample includes
finding/verification steps even for completed cases, while this planner
proposes remediation only. Whether the final field must also contain
non-remediation audit findings or verification records remains unresolved.
Do not manufacture destructive steps to fill empty arrays or infer status from
step-list emptiness.

## 4. JSON and CSV serialization audit

`src/output_generator.py` serializes with Python's standard `json` and `csv`
modules. It projects each `RemediationStep` into the seven sample-observed
keys in that key order, writes UTF-8 with correct newline handling, then
reopens and validates the generated CSV's header, row count, unique and sorted
case IDs, statuses, JSON arrays, ordered step keys, and consecutive step
numbers. The tests cover quotes, commas, Unicode, embedded newlines, empty
arrays, invalid inputs, and repeat-run determinism.

The writer retains rich diagnostics on the in-memory plan objects but does
not serialize `subject_id`, `rule_id`, evidence references, or reasons into
the seven-key step shape. A single `evidence_id` also cannot encode every
supporting reference when a step has multiple references. The planner data is
not mutated, and this information remains inspectable in the internal plan;
however, it is not present in the generated CSV. The seven-key projection is
a sample-based compatibility choice, not a confirmed official contract. If
the competition requires all traceability fields in the output, the sample
schema is insufficient and the official instructions must resolve that
conflict before submission.

IDs must remain strings through input and output; avoid numeric conversion,
trimming, or zero-padding. `case_id` sorting should use the agreed string
comparison directly. Exact lexical-versus-natural sort semantics remain
unwritten in the available project specification.

## 5. All 32 sample cases: policy and plan comparison

Policy status comparison: **23/32 exact matches**. The nine status mismatches
are cases expected `COMPLETE` but provisionally evaluated `INCOMPLETE`:
case_01, case_02, case_04, case_21, case_25, case_26, case_27, case_28, and
case_31. Their evidence/specification analysis is documented in
`policy_assumptions.md`; this audit did not change policy behavior.

Step comparison is separate. Every sample case has at least one step, but the
planner has no sample case whose seven sample fields match exactly and in
order (**0/32 exact step-list matches**). Twenty-two planner cases are empty;
on the other ten, counts or step content differ. “Expected/planned” counts
below compare sample steps with `plan_remediation()` output:

| Case | Sample status | Policy status | Sample steps | Planned steps |
|---|---|---|---:|---:|
| case_01 | COMPLETE | INCOMPLETE | 1 | 0 |
| case_02 | COMPLETE | INCOMPLETE | 1 | 0 |
| case_03 | COMPLETE | COMPLETE | 3 | 0 |
| case_04 | COMPLETE | INCOMPLETE | 2 | 0 |
| case_05 | INCOMPLETE | INCOMPLETE | 3 | 1 |
| case_06 | INCOMPLETE | INCOMPLETE | 4 | 4 |
| case_07 | INCOMPLETE | INCOMPLETE | 4 | 0 |
| case_08 | INCOMPLETE | INCOMPLETE | 4 | 3 |
| case_09 | INCOMPLETE | INCOMPLETE | 5 | 0 |
| case_10 | INCOMPLETE | INCOMPLETE | 4 | 0 |
| case_11 | INCOMPLETE | INCOMPLETE | 14 | 8 |
| case_12 | INCOMPLETE | INCOMPLETE | 5 | 1 |
| case_13 | INCOMPLETE | INCOMPLETE | 8 | 6 |
| case_14 | INCOMPLETE | INCOMPLETE | 5 | 0 |
| case_15 | INCOMPLETE | INCOMPLETE | 5 | 0 |
| case_16 | INCOMPLETE | INCOMPLETE | 7 | 0 |
| case_17 | INCOMPLETE | INCOMPLETE | 5 | 1 |
| case_18 | INCOMPLETE | INCOMPLETE | 14 | 7 |
| case_19 | INCOMPLETE | INCOMPLETE | 8 | 3 |
| case_20 | INCOMPLETE | INCOMPLETE | 8 | 6 |
| case_21 | COMPLETE | INCOMPLETE | 3 | 0 |
| case_22 | INCOMPLETE | INCOMPLETE | 8 | 0 |
| case_23 | INCOMPLETE | INCOMPLETE | 8 | 0 |
| case_24 | INCOMPLETE | INCOMPLETE | 7 | 0 |
| case_25 | COMPLETE | INCOMPLETE | 3 | 0 |
| case_26 | COMPLETE | INCOMPLETE | 6 | 0 |
| case_27 | COMPLETE | INCOMPLETE | 6 | 0 |
| case_28 | COMPLETE | INCOMPLETE | 6 | 0 |
| case_29 | INCOMPLETE | INCOMPLETE | 14 | 0 |
| case_30 | INCOMPLETE | INCOMPLETE | 14 | 0 |
| case_31 | COMPLETE | INCOMPLETE | 3 | 0 |
| case_32 | INCOMPLETE | INCOMPLETE | 5 | 0 |

The planner's `steps_json` projection also has additional keys not present in
the samples. No behavior was altered to increase sample match percentage.
Status mismatches remain policy/evidence questions; step-content mismatches
are principally the unresolved distinction between audit evidence reporting
and remediation planning, plus the unconfirmed serialization shape.

## 6. Phase 6 writer and validation

Added `tests/test_output_contract.py` to validate the observed sample header,
all sample JSON arrays and exact step key sets, consecutive `step_no`, sample
status/non-empty-list observations, the full request count and string IDs, and
an in-memory JSON/CSV round trip for quotes, commas, Unicode, newlines, and a
zero-padded case ID. Added `tests/test_output_generator.py` for synthetic
invalid inputs and the real 518-request pipeline, including output read-back,
determinism, status/schema checks, and sample comparison. `src/main.py`
generates output only when `--generate-output` or `--output` is supplied.
Without an explicit path, it writes to `artifacts/output.csv`; it does not
select `dataset/output.csv`.

The complete requested test command passed: `python -m unittest discover -s
tests -v` — **83 tests, OK**.

The development artifact was generated and independently reopened:

| Validation | Result |
|---|---:|
| Header | `case_id,deletion_status,steps_json` |
| Data rows | 518 |
| Unique case IDs | 518 |
| Lexically sorted IDs | Pass |
| Statuses | 27 `COMPLETE`, 491 `INCOMPLETE`, 0 `NOT_APPLICABLE` |
| Valid JSON arrays | Pass for all rows |
| Ordered seven-key step objects | Pass |
| Consecutive step numbers | Pass |
| Empty plans | 353 |
| Serialized steps | 687 |
| Sample status accuracy | 23/32 |
| Exact sample step-list matches | 0/32 |

The generated path is `artifacts/output.csv`. The supplied
`dataset/output.csv` remains unchanged.

## 7. Remaining pre-release uncertainties

1. Obtain or confirm the official step schema and whether additional
   traceability keys are permitted. Current serialization uses seven keys
   observed in examples; omitted diagnostics remain on internal plan objects,
   not in the CSV.
2. Confirm phase and operation vocabulary/order, system/resource tie-breakers,
   and lexical versus natural `case_id` sorting. Current sorting uses the
   documented project interpretation: direct lexical ordering of unmodified
   string IDs. Planner step order is the existing deterministic planner order,
   not a proven competition order.
3. Decide whether `steps_json` represents an audit trail, a remediation plan,
   or both, and specify empty-list semantics for every allowed status.
   Current empty plans are not rewritten as status changes or fabricated
   actions; their unresolved obligations remain in the internal plan.
4. The seven-key sample schema has only one `evidence_id`; it cannot encode
   every source reference plus `subject_id`, `rule_id`, and `reason`. Confirm
   whether these details are required in the competition file or may remain
   internal.
5. Status mismatches and step-content mismatches remain separate. The policy
   remains 23/32 on sample status labels; no status behavior was changed to
   improve that score. Step lists match exactly in 0/32 samples, largely
   because sample examples include finding/verification records while the
   planner proposes remediation steps.
