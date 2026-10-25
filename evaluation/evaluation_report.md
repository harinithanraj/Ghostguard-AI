# GhostGuard-AI evaluation report

## Production artifact validation

Artifact: `C:\Users\user\Desktop\GhostGuard-AI\artifacts\output.csv`

| Check / metric | Result |
|---|---:|
| Data rows | 518 |
| Unique case IDs | 518 |
| Duplicate IDs | 0 |
| Header/schema valid | True |
| Allowed statuses valid | True |
| JSON arrays parsed successfully | 518 |
| JSON parsing failures | 0 |
| Step-schema/order errors | 0 |
| Serialized steps | 687 |
| Empty plans | 353 |
| Non-empty plans | 165 |

Status counts: COMPLETE 27, INCOMPLETE
491, NOT_APPLICABLE 0.

### Empty/non-empty production plans by emitted status

| Status | Empty | Non-empty |
|---|---:|---:|
| COMPLETE | 27 | 0 |
| INCOMPLETE | 326 | 165 |
| NOT_APPLICABLE | 0 | 0 |

Rows are validated against the exact CSV header and request IDs, JSON arrays,
the seven sample-observed ordered step keys, and consecutive step numbers.
The generated file uses lexical ordering of unmodified string case IDs. Any
validation problems:

- None.

## Sample comparison (32 cases)

The supplied sample IDs (`case_01`–`case_32`) are separate from the 518
production request IDs. Status and exact step comparisons therefore re-run
the same current provisional resolver, analyzer, policy engine, and planner
on `sample_deletion_requests.csv`, then compare with `sample_output.csv`;
they are not matches obtained by joining sample IDs to production rows.

- Status accuracy: **23/32**
  (71.9%).
- Exact generated step-list matches: **0/32**
  (0.0%).
- Status mismatches: 9.
- Step-list mismatches: 32.
- Sample dataset alignment: valid.

Agreement with a sample status is not evidence that the associated remediation
steps are correct. Status and step-list comparisons are reported separately.

### Per-status metrics

| Status | Expected support | Predicted count | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|
| COMPLETE | 10 | 1 | 1.000 | 0.100 | 0.182 |
| INCOMPLETE | 22 | 31 | 0.710 | 1.000 | 0.830 |
| NOT_APPLICABLE | 0 | 0 | N/A | N/A | N/A |

The sample has only 32 cases and no NOT_APPLICABLE examples. Metrics for that
unobserved class are N/A, not zero-performance evidence. These values describe
agreement with sample labels only; they do not validate the provisional
policy as an official competition rule.

### Sample mismatch details

| Case | Expected status | Evaluated status | Sample steps | Planned steps | Status match | Exact step match | Explanation |
|---|---|---|---:|---:|---|---|---|
| case_01 | COMPLETE | INCOMPLETE | 1 | 0 | no | no | planner has 0 steps; sample has 1; rule_01: The USER_PROFILE rule is unconditional, but no identity-linked profile resource is evidenced. No owned resource and audit-time evidence jointly support a proposed step.; decision: rule_01: The USER_PROFILE rule is unconditional, but no identity-linked profile resource is evidenced. |
| case_02 | COMPLETE | INCOMPLETE | 1 | 0 | no | no | planner has 0 steps; sample has 1; rule_01: The USER_PROFILE rule is unconditional, but no identity-linked profile resource is evidenced. No owned resource and audit-time evidence jointly support a proposed step.; decision: rule_01: The USER_PROFILE rule is unconditional, but no identity-linked profile resource is evidenced. |
| case_03 | COMPLETE | COMPLETE | 3 | 0 | yes | no | planner has 0 steps; sample has 3; No remediation is required by the provisional assessment.; decision: |
| case_04 | COMPLETE | INCOMPLETE | 2 | 0 | no | no | planner has 0 steps; sample has 2; rule_01: The USER_PROFILE rule is unconditional, but no identity-linked profile resource is evidenced. No owned resource and audit-time evidence jointly support a proposed step.; decision: rule_01: The USER_PROFILE rule is unconditional, but no identity-linked profile resource is evidenced. |
| case_05 | INCOMPLETE | INCOMPLETE | 3 | 1 | yes | no | planner has 1 steps (VERIFY_RECORD_ABSENT); sample has 3 (REPORT_REMAINING_RECORD, DELETE_RECORD, VERIFY_RECORD_ABSENT); decision: |
| case_06 | INCOMPLETE | INCOMPLETE | 4 | 4 | yes | no | planner has 4 steps (REPORT_REMAINING_RECORD, DELETE_RECORD, VERIFY_RECORD_ABSENT, VERIFY_RECORD_ABSENT); sample has 4 (REPORT_REMAINING_RECORD, DELETE_RECORD, VERIFY_RECORD_ABSENT, VERIFY_RECORD_ABSENT); decision: |
| case_07 | INCOMPLETE | INCOMPLETE | 4 | 0 | yes | no | planner has 0 steps; sample has 4; rule_01: The USER_PROFILE rule is unconditional, but no identity-linked profile resource is evidenced. No owned resource and audit-time evidence jointly support a proposed step.; decision: |
| case_08 | INCOMPLETE | INCOMPLETE | 4 | 3 | yes | no | planner has 3 steps (REPORT_REMAINING_RECORD, DELETE_RECORD, VERIFY_RECORD_ABSENT); sample has 4 (REPORT_REMAINING_RECORD, DELETE_RECORD, VERIFY_RECORD_ABSENT, VERIFY_RECORD_ABSENT); decision: |
| case_09 | INCOMPLETE | INCOMPLETE | 5 | 0 | yes | no | planner has 0 steps; sample has 5; rule_01: The USER_PROFILE rule is unconditional, but no identity-linked profile resource is evidenced. No owned resource and audit-time evidence jointly support a proposed step.; decision: |
| case_10 | INCOMPLETE | INCOMPLETE | 4 | 0 | yes | no | planner has 0 steps; sample has 4; rule_01: The USER_PROFILE rule is unconditional, but no identity-linked profile resource is evidenced. No owned resource and audit-time evidence jointly support a proposed step.; decision: |
| case_11 | INCOMPLETE | INCOMPLETE | 14 | 8 | yes | no | planner has 8 steps (REPORT_EXPOSED_PII, REPORT_REMAINING_RECORD, REPORT_REMAINING_RECORD, ANONYMIZE_RECORD, DELETE_RECORD, VERIFY_RECORD_ANONYMIZED, VERIFY_DATA_FLOW_DISABLED, VERIFY_RECORD_ABSENT); sample has 14 (REPORT_REMAINING_RECORD, REPORT_EXPOSED_PII, REPORT_EXPOSED_PII, REPORT_ACTIVE_DATA_FLOW, DISABLE_DATA_FLOW, DELETE_RECORD, REDACT_RECORD, ANONYMIZE_RECORD, VERIFY_RECORD_ABSENT, VERIFY_RECORD_ABSENT, VERIFY_RECORD_PRESENT, VERIFY_RECORD_REDACTED, VERIFY_RECORD_ANONYMIZED, VERIFY_DATA_FLOW_DISABLED); decision: |
| case_12 | INCOMPLETE | INCOMPLETE | 5 | 1 | yes | no | planner has 1 steps (VERIFY_RECORD_ANONYMIZED); sample has 5 (REPORT_REMAINING_RECORD, DELETE_RECORD, VERIFY_RECORD_ABSENT, VERIFY_RECORD_ABSENT, VERIFY_RECORD_PRESENT); decision: |
| case_13 | INCOMPLETE | INCOMPLETE | 8 | 6 | yes | no | planner has 6 steps (REPORT_REMAINING_RECORD, REPORT_REMAINING_RECORD, DELETE_RECORD, DELETE_RECORD, VERIFY_RECORD_ABSENT, VERIFY_RECORD_ABSENT); sample has 8 (REPORT_REMAINING_RECORD, REPORT_REMAINING_RECORD, DELETE_RECORD, DELETE_RECORD, VERIFY_RECORD_ABSENT, VERIFY_RECORD_ABSENT, VERIFY_RECORD_ABSENT, VERIFY_RECORD_PRESENT); decision: |
| case_14 | INCOMPLETE | INCOMPLETE | 5 | 0 | yes | no | planner has 0 steps; sample has 5; rule_12 / audit_record_987: retention evidence is unresolved; do not propose deletion.; decision: |
| case_15 | INCOMPLETE | INCOMPLETE | 5 | 0 | yes | no | planner has 0 steps; sample has 5; rule_12: The evidence does not establish that the record is within a supplied retention period. No owned resource and audit-time evidence jointly support a proposed step.; decision: |
| case_16 | INCOMPLETE | INCOMPLETE | 7 | 0 | yes | no | planner has 0 steps; sample has 7; rule_01: The USER_PROFILE rule is unconditional, but no identity-linked profile resource is evidenced. No owned resource and audit-time evidence jointly support a proposed step.; decision: |
| case_17 | INCOMPLETE | INCOMPLETE | 5 | 1 | yes | no | planner has 1 steps (VERIFY_RECORD_ABSENT); sample has 5 (REPORT_RESTORE_RISK, BLOCK_RESTORE, VERIFY_RECORD_ABSENT, VERIFY_RECORD_PRESENT, VERIFY_RESTORE_BLOCKED); decision: |
| case_18 | INCOMPLETE | INCOMPLETE | 14 | 7 | yes | no | planner has 7 steps (REPORT_ACTIVE_DATA_FLOW, REPORT_REMAINING_RECORD, DISABLE_DATA_FLOW, DELETE_RECORD, VERIFY_RECORD_ANONYMIZED, VERIFY_DATA_FLOW_DISABLED, VERIFY_RECORD_ABSENT); sample has 14 (REPORT_REMAINING_RECORD, REPORT_EXPOSED_PII, REPORT_EXPOSED_PII, REPORT_ACTIVE_DATA_FLOW, DISABLE_DATA_FLOW, DELETE_RECORD, REDACT_RECORD, ANONYMIZE_RECORD, VERIFY_RECORD_ABSENT, VERIFY_RECORD_ABSENT, VERIFY_RECORD_PRESENT, VERIFY_RECORD_REDACTED, VERIFY_RECORD_ANONYMIZED, VERIFY_DATA_FLOW_DISABLED); decision: |
| case_19 | INCOMPLETE | INCOMPLETE | 8 | 3 | yes | no | planner has 3 steps (REPORT_REMAINING_RECORD, DELETE_RECORD, VERIFY_RECORD_ABSENT); sample has 8 (REPORT_REMAINING_RECORD, REPORT_EXPOSED_PII, DELETE_RECORD, REDACT_RECORD, VERIFY_RECORD_ABSENT, VERIFY_RECORD_ABSENT, VERIFY_RECORD_PRESENT, VERIFY_RECORD_REDACTED); decision: |
| case_20 | INCOMPLETE | INCOMPLETE | 8 | 6 | yes | no | planner has 6 steps (REPORT_ACTIVE_DATA_FLOW, REPORT_REMAINING_RECORD, DISABLE_DATA_FLOW, DELETE_RECORD, VERIFY_DATA_FLOW_DISABLED, VERIFY_RECORD_ABSENT); sample has 8 (REPORT_REMAINING_RECORD, REPORT_ACTIVE_DATA_FLOW, DISABLE_DATA_FLOW, DELETE_RECORD, VERIFY_RECORD_ABSENT, VERIFY_RECORD_ABSENT, VERIFY_RECORD_PRESENT, VERIFY_DATA_FLOW_DISABLED); decision: |
| case_21 | COMPLETE | INCOMPLETE | 3 | 0 | no | no | planner has 0 steps; sample has 3; rule_01: The USER_PROFILE rule is unconditional, but no identity-linked profile resource is evidenced. No owned resource and audit-time evidence jointly support a proposed step.; decision: rule_01: The USER_PROFILE rule is unconditional, but no identity-linked profile resource is evidenced. |
| case_22 | INCOMPLETE | INCOMPLETE | 8 | 0 | yes | no | planner has 0 steps; sample has 8; rule_01: The USER_PROFILE rule is unconditional, but no identity-linked profile resource is evidenced. No owned resource and audit-time evidence jointly support a proposed step.; decision: |
| case_23 | INCOMPLETE | INCOMPLETE | 8 | 0 | yes | no | planner has 0 steps; sample has 8; rule_01: The USER_PROFILE rule is unconditional, but no identity-linked profile resource is evidenced. No owned resource and audit-time evidence jointly support a proposed step.; decision: |
| case_24 | INCOMPLETE | INCOMPLETE | 7 | 0 | yes | no | planner has 0 steps; sample has 7; rule_01 / account_5334: system identifier is missing; no operation can be targeted safely.; decision: |
| case_25 | COMPLETE | INCOMPLETE | 3 | 0 | no | no | planner has 0 steps; sample has 3; rule_01: The USER_PROFILE rule is unconditional, but no identity-linked profile resource is evidenced. No owned resource and audit-time evidence jointly support a proposed step.; decision: rule_01: The USER_PROFILE rule is unconditional, but no identity-linked profile resource is evidenced. |
| case_26 | COMPLETE | INCOMPLETE | 6 | 0 | no | no | planner has 0 steps; sample has 6; rule_05 / support_4715: shared-context applicability is unresolved; no redaction is proposed.; decision: rule_05: The supplied evidence does not establish whether shared customer, agent, or order context must be retained. |
| case_27 | COMPLETE | INCOMPLETE | 6 | 0 | no | no | planner has 0 steps; sample has 6; rule_01 / account_3866: findings have no reliable event timestamp at or before audit_at; no action proposed.; decision: rule_01: The category is only supported by post-audit or untimed evidence. |
| case_28 | COMPLETE | INCOMPLETE | 6 | 0 | no | no | planner has 0 steps; sample has 6; rule_01: The USER_PROFILE rule is unconditional, but no identity-linked profile resource is evidenced. No owned resource and audit-time evidence jointly support a proposed step.; decision: rule_01: The USER_PROFILE rule is unconditional, but no identity-linked profile resource is evidenced. |
| case_29 | INCOMPLETE | INCOMPLETE | 14 | 0 | yes | no | planner has 0 steps; sample has 14; rule_01: The USER_PROFILE rule is unconditional, but no identity-linked profile resource is evidenced. No owned resource and audit-time evidence jointly support a proposed step.; decision: |
| case_30 | INCOMPLETE | INCOMPLETE | 14 | 0 | yes | no | planner has 0 steps; sample has 14; rule_01: The USER_PROFILE rule is unconditional, but no identity-linked profile resource is evidenced. No owned resource and audit-time evidence jointly support a proposed step.; decision: |
| case_31 | COMPLETE | INCOMPLETE | 3 | 0 | no | no | planner has 0 steps; sample has 3; rule_01: The USER_PROFILE rule is unconditional, but no identity-linked profile resource is evidenced. No owned resource and audit-time evidence jointly support a proposed step.; decision: rule_01: The USER_PROFILE rule is unconditional, but no identity-linked profile resource is evidenced. |
| case_32 | INCOMPLETE | INCOMPLETE | 5 | 0 | yes | no | planner has 0 steps; sample has 5; rule_01: The USER_PROFILE rule is unconditional, but no identity-linked profile resource is evidenced. No owned resource and audit-time evidence jointly support a proposed step.; decision: |

### Empty sample plans by evaluated status

| Status | Empty | Non-empty |
|---|---:|---:|
| COMPLETE | 1 | 0 |
| INCOMPLETE | 21 | 10 |
| NOT_APPLICABLE | 0 | 0 |

## Serialized steps by phase and operation

| Phase | Count |
|---|---:|
| FINDING | 221 |
| REMEDIATION | 194 |
| VERIFICATION | 272 |

| Operation | Count |
|---|---:|
| ANONYMIZE_RECORD | 30 |
| BLOCK_RESTORE | 4 |
| DELETE_RECORD | 144 |
| DISABLE_DATA_FLOW | 16 |
| REPORT_ACTIVE_DATA_FLOW | 16 |
| REPORT_EXPOSED_PII | 30 |
| REPORT_REMAINING_RECORD | 171 |
| REPORT_RESTORE_RISK | 4 |
| VERIFY_DATA_FLOW_DISABLED | 49 |
| VERIFY_RECORD_ABSENT | 182 |
| VERIFY_RECORD_ANONYMIZED | 37 |
| VERIFY_RESTORE_BLOCKED | 4 |

## Empty remediation-plan investigation

Across all 518 production requests, **353** plans are
empty: COMPLETE 27,
INCOMPLETE 326, and
NOT_APPLICABLE 0.
All 27 empty COMPLETE plans have
no blocking rule outcomes in the current provisional assessment; no
remediation is justified by those assessments.

Among empty INCOMPLETE plans,
295 have unresolved
outcomes only and
31 have at least one
UNMET outcome. The latter need review rather than being counted as completed:

- 25 search-index cases
  have an UNMET assessment but the planner records that the target system
  identifier is missing, so a targeted action is not supported by the current
  planner input.
- Six backup cases (case_147, case_171, case_279, case_471, case_531, case_99) have an at-cutoff
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
from a missing record. In the 32-case sample, 22
plans are empty: case_01, case_02, case_03, case_04, case_07, case_09, case_10, case_14, case_15, case_16, case_21, case_22, case_23, case_24, case_25, case_26, case_27, case_28, case_29, case_30, case_31, case_32. `case_03` is
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
