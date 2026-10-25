# Provisional policy-engine assumptions

These interpretations are provisional and are not represented as official
HackerRank competition requirements. No official status/specification document
was present in the inspected workspace. The supplied `deletion_rules.csv`,
sample request/output CSVs, identity results, and evidence analyses are the
available policy sources.

## Status mapping

- `COMPLETE` requires a confirmed identity, an explicit timestamped state at
  or before `audit_at` satisfying the unconditional `USER_PROFILE` deletion
  rule, and no identified applicable rule that is unmet or unresolved.
- `INCOMPLETE` is used for explicit remaining data, failed/partial actions,
  ambiguous or insufficient evidence for an identified obligation, unresolved
  identity, post-audit-only evidence, unmapped identity-linked resources, or
  cutoff conflicts.
- `NOT_APPLICABLE` is not emitted. Every request is treated as in scope for the
  supplied unconditional `USER_PROFILE` rule, and the request schema has no
  explicit out-of-scope field. The available files do not define any separate
  condition that would establish this status.

## Evidence and rule interpretation

- Evidence is eligible only when its timezone-aware event timestamp is at or
  before that request's `audit_at`. The boundary is inclusive. Source capture
  time is never used to establish event chronology.
- A successful `DELETE_RECORD`/`DELETE`/`ERASE_RECORD` result is not treated as
  final-state verification. An explicit `ABSENT`, `DELETED`, `ERASED`,
  `PURGED`, `NOT_FOUND`, or `MISSING` state can satisfy a `DELETE` action.
- An action event that explicitly reports `FAILED` or `PARTIAL` is treated as
  unmet work for that action, not as final-state proof.
- A linked profile lookup result with status `404` and either `rows=0` or a
  specific `profile_lookups` source record is treated as explicit absence for
  that resource. A generic 404, an empty search result, or no analyzer match
  is not sufficient.
- Explicit `REDACTED` and `ANONYMIZED` states are required for those respective
  actions. `SUCCESS` alone does not prove the required final state.
- For analytics/telemetry records, explicit `null` values for all four observed
  identifying fields (`customer_reference`, `email`, `phone`, and `email_hash`)
  are treated as anonymized. Other missing or omitted fields do not establish
  anonymization.
- The data category is taken from the analyzer's explicit `record_type`,
  `data_category`, or `category` value when available. Narrow system/resource
  markers (for example, `account_service`/`account_*` or
  `search_service`/`search_*`) are used only to classify the resource types
  represented in this dataset.
- A rule category is assessed when evidence identifies a record in that
  category. The unconditional `USER_PROFILE` rule is assessed even when no
  profile finding exists; the missing profile evidence is unresolved, not
  proof of deletion. Absence of evidence for another category does not prove
  that the category has no records. The dataset does not expose an exhaustive
  per-user resource inventory, so this remains an important scope limitation.
- Rule 12 retention is permitted only when a matching `retention_until` value
  extends beyond `audit_at`; this field was observed in the supplied evidence.
  A retained security record does not satisfy any other rule.
- Rule 13 retention is permitted only on an explicit `ACTIVE` state for a
  `LEGAL_HOLD_RECORD`.
- Rule 14 retention is permitted only when `restore_allowed` is explicitly
  false at or before the audit cutoff. Explicitly allowed restore access is
  incomplete; missing restore evidence is unresolved.
- Rule 15's condition that only a stable internal `user_id` remains cannot be
  verified from the current structured analyzer output. A tombstone finding
  therefore remains unresolved unless a future evidence representation proves
  that condition.
- `DATA_FLOW` is not a data category in `deletion_rules.csv`. It is treated as
  a processing-risk check, not a deletion rule: an observed connector is
  considered non-blocking only when an at-cutoff record explicitly says
  `enabled=false` and `last_delivery_status=stopped` (or `disabled`). Otherwise
  the unclassified resource remains unresolved. A `DISABLE_DATA_FLOW SUCCESS`
  activity alone is not a current-state verification.
- Rule 05 requires shared customer/agent/order context to be retained, but the
  available structured evidence does not consistently expose enough context
  to establish that condition. An unredacted support message therefore
  remains unresolved instead of being guessed applicable or exempt.
- `NOT_FOUND` is treated as explicit absence only when it is present as a
  source state for a linked, identified resource. A missing analyzer match is
  never used as deletion proof.

## Result structure and limitations

Each `PolicyResult` preserves the request `case_id` and requested email,
identity provenance, rule assessments, evidence IDs, exact evidence paths and
record references, system/resource IDs, event timestamps, reasons, and
unresolved interpretations. Rule outcomes (`SATISFIED`, `UNMET`,
`UNRESOLVED`, `PERMITTED_RETENTION`) are internal explanations; the
`deletion_status` itself is restricted to the three supplied competition
values.

The rule CSV does not define a full applicability or status-mapping contract,
and the evidence does not provide a comprehensive resource inventory.
Consequently, even a provisional `COMPLETE` applies only to identified
evidence-backed resource categories and should not be treated as an official
competition judgment. The 32 sample statuses are used for comparison, not as
rules to force implementation matches.

## Supplied sample-output comparison

The provisional engine matched **23 of 32** sample statuses both before and
after the review. The sample labels contain 10 `COMPLETE` and 22 `INCOMPLETE`;
the engine returns 1 `COMPLETE` and 31 `INCOMPLETE`. The nine mismatches are
listed below. “Actual” is the status after the review fixes.

| Case | Audit cutoff | Expected / actual | Mismatch classification | Decision trace |
|---|---|---|---|---|
| case_01 | 2026-09-03 11:30Z | COMPLETE / INCOMPLETE | Conservative policy choice not established by sample labels alone | Identity is confirmed as `user_01`. Rule 01 applies, but there are no identity-linked findings. Sample step claims `account_001` is absent in `evidence_54`; the actual failover SQL contains neither `account_001` nor `user_01` (its profile rows are for other subjects). No state evidence can be assessed at cutoff, so rule 01 is unresolved. |
| case_02 | 2026-09-04 15:00Z | COMPLETE / INCOMPLETE | Conservative policy choice not established by sample labels alone | Identity is confirmed as `user_02`. Rule 01 applies, but there are no linked findings. `evidence_54` contains no `account_002` or `user_02` row, so the sample's absent-state claim has no matching source record. Rule 01 is unresolved. |
| case_04 | 2026-09-07 10:20Z | COMPLETE / INCOMPLETE | Conservative policy choice not established by sample labels alone | Identity is confirmed as `user_04`; rule 01 is unresolved because no profile is linked. `evidence_56` does contain `analytics_901`, but its `user_id`, email, phone, and email hash are explicitly null. The record does not identify `user_04`; rule 07 cannot be applied to that resource. |
| case_21 | 2026-09-15 12:00Z | COMPLETE / INCOMPLETE | Conservative policy choice not established by sample labels alone | Identity is confirmed as `user_21`. Rule 01 has no linked profile proof. Rule 12 is permitted for `audit_record_3737`: evidence_92 directly links `subject_reference=user_21`, observes it at 09:59:10Z, and supplies retention through 2034. The sample's `account_6440` lookup (404 at 09:31:19Z) and anonymized `analytics_5335` record are resource-ID-only records with no source link to `user_21`; their states cannot discharge this request's rule 01 or 07. The additional legal-retention PDF finding has no eligible event timestamp. |
| case_25 | 2026-09-15 12:00Z | COMPLETE / INCOMPLETE | Conservative policy choice not established by sample labels alone | Identity is confirmed as `user_25`. Rule 01 has no linked profile proof. Rule 12 is permitted for `audit_record_451`: evidence_92 links its subject reference to `user_25`, observes it at 10:07:33Z, and supplies retention through 2031. The sample's `account_3136` 404 lookup and `analytics_1895` all-null profile are not linked to `user_25`; the evidence does not establish that they belong to this request. |
| case_26 | 2026-09-15 12:00Z | COMPLETE / INCOMPLETE | Genuine ambiguity in the available specification | Identity is confirmed as `user_26`. Rule 01 is satisfied: the nested profile snapshot is explicitly captured on 2026-09-09, linking `account_5684` to the subject; evidence_92 records a 404 lookup for that resource at 09:01:48Z on 2026-09-15. Rule 12 retention and rule 14 blocked restore are supported; the integration connector was observed disabled/stopped before cutoff. Rule 05 remains unresolved: the pre-cutoff support excerpt says “order update,” while a pre-cutoff `REDACT_RECORD SUCCESS` activity is not a final redacted-state observation. The only explicit `[REDACTED]` text is in a snapshot captured on 2026-09-17, after cutoff and without an event timestamp. Analytics resource `analytics_4566` is all-null but has no source link to `user_26`. |
| case_27 | 2026-09-15 12:00Z | COMPLETE / INCOMPLETE | Potential evidence-linking defect (fixed) | Identity is confirmed as `user_27`. Rule 12 retention and rule 14 restore blocking are supported; its connector is observed disabled/stopped. The account lookup `account_3866` returned 404 at 09:59:48Z, but the only subject-to-account association was in evidence_02's 2026-09-17 snapshot. The prior analyzer used that post-cutoff association to attach the older lookup; it is now excluded as a link at this cutoff, leaving rule 01 unresolved. Rule 05 is also unresolved: the pre-cutoff ticket excerpt says “account access,” and the pre-cutoff redaction activity reports success but not a final state; `[REDACTED]` appears only in the later snapshot. |
| case_28 | 2026-09-15 12:00Z | COMPLETE / INCOMPLETE | Conservative policy choice not established by sample labels alone | Identity is confirmed as `user_28`. Rule 12 retention and rule 14 restore blocking are supported; its connector is observed disabled/stopped. The `account_5482` lookup returned 404 at 11:07:16Z, but no at-cutoff identity-to-account link exists; the resource ID alone is insufficient for attribution, so rule 01 is unresolved. Rule 05 is also unresolved: the linked ticket excerpt says “delivery query,” while the only `[REDACTED]` text is in the post-cutoff snapshot and the pre-cutoff activity only reports redaction-operation success. |
| case_31 | 2026-09-15 12:00Z | COMPLETE / INCOMPLETE | Potential implementation defect (explicit-null and tombstone metadata extraction fixed); remaining cutoff/rule ambiguity | Identity is confirmed as `user_541`. Rule 01 has no profile absence proof. Rule 12's `audit_record_6909` has no event timestamp or `retention_until`; its snapshot capture time alone is not treated as an event. Rule 15's tombstone row was captured exactly at the cutoff and says `account_status=DELETED`, `subject_reference=user_541`, with name/email/phone/hash explicitly null. The analyzer previously dropped nulls, `name`, and `subject_reference`; it now preserves those fields for policy inspection without treating null as an identifier. However, no reliable event-time redaction state proves the sample's `REDACTED` claim, and whether `subject_reference` is the rule's stable internal `user_id` is not explicit. The `REDACT_RECORD SUCCESS` activity on 2026-09-06 is not final-state proof. |

### Review findings and changes

1. **Temporal resource-link defect:** resource IDs were previously propagated
   from any direct identity match, including records observed after the request
   cutoff. That could attach an old resource state to a subject based on a
   later association. The analyzer now seeds indirect resource links only from
   a direct match whose explicit event time is at/before the cutoff; if there
   is no event time, it can use a source-capture time at/before the cutoff to
   time the identity/resource observation. A later capture never overrides an
   explicit event timestamp. Event-state eligibility remains based on event
   timestamps, not capture time. Regression coverage verifies that a
   post-cutoff subject/resource link cannot attach an older absence record.
2. **Explicit JSON null extraction defect:** JSON `null` fields were omitted
   from findings, which prevented downstream policy logic from distinguishing
   explicit nulls from absent fields. They are now retained as the literal
   `"null"` in extracted scalar attributes, including tombstone name and
   subject-reference metadata, and excluded from identifier and resource
   matching. A regression test checks both behaviors. This does not establish
   ownership of an all-null analytics record or prove that a particular
   subject-reference field is the rule's stable `user_id`.

Sample accuracy remains **23/32**; no status mapping or deletion rule was
changed to force sample matches. On the full 518-request dataset, results
changed from 28 `COMPLETE` / 490 `INCOMPLETE` before the review to 27
`COMPLETE` / 491 `INCOMPLETE` after the temporal-link correction. The one-count
change reflects applying the cutoff to identity/resource links, not changing
the policy status definitions.

### Remaining questions

- Does the competition treat `sample_output.csv`'s `steps_json` as authoritative
  proof, or only as expected-output examples? Its expected resource IDs and
  state labels are not consistently corroborated by source records linked to
  the subject.
- Does an untimed snapshot captured exactly at `audit_at` establish a
  contemporaneous state, distinct from an event timestamp? In particular,
  this affects case_31's tombstone and audit record.
- Does `subject_reference=user_541` in the tombstone explicitly satisfy rule
  15's “stable internal user_id” condition, and do explicit null values for
  all personal fields establish its redaction condition?
- For rule 05, when the excerpt does not establish whether shared context must
  be retained, should the result be unresolved/incomplete, or is there an
  authoritative condition/applicability signal elsewhere?
- Do all-null analytics records belong to the request subject when no
  explicit subject/resource relationship remains? The available records do not
  provide a safe link for the cases listed above.

## Phase 5 remediation-planner assumptions

The repository contains no official competition instructions defining an
allowed operation vocabulary, execution semantics, or required ordering
contract. The only available step examples are the JSON objects in
`dataset/sample_output.csv`; they use the phases `FINDING`, `REMEDIATION`, and
`VERIFICATION`, and operations including:

- `REPORT_REMAINING_RECORD`, `REPORT_EXPOSED_PII`,
  `REPORT_ACTIVE_DATA_FLOW`, and `REPORT_RESTORE_RISK`
- `DELETE_RECORD`, `REDACT_RECORD`, `ANONYMIZE_RECORD`, `DISABLE_DATA_FLOW`,
  and `BLOCK_RESTORE`
- `VERIFY_RECORD_ABSENT`, `VERIFY_RECORD_REDACTED`,
  `VERIFY_RECORD_ANONYMIZED`, `VERIFY_RECORD_PRESENT`,
  `VERIFY_DATA_FLOW_DISABLED`, and `VERIFY_RESTORE_BLOCKED`

The planner emits only operation names observed in those examples. This
observed vocabulary is not claimed to be the official exhaustive allowlist.
No code executes any proposed operation.
For action targets, `system_id` prefers the observed destination (`target_system`)
over the acting component (`source_system`), matching sample examples that name
the affected service.

### Step justification

- A uniquely confirmed identity is required before any resource-specific step
  is proposed. Candidate identities are never collapsed, and similar names or
  unrelated identifiers are not used to claim ownership.
- Only findings marked `as_of_audit` with a valid event timestamp and
  `PRE_AUDIT` or `AT_AUDIT` relation can support an action. Post-audit,
  untimed, and invalid-time observations can explain why planning is blocked,
  but cannot justify a state-changing operation.
- `SATISFIED` and `PERMITTED_RETENTION` assessments do not produce remediation.
  In particular, permitted security/legal/backup retention is not translated
  into deletion. Backup evidence with restore explicitly allowed can produce
  `BLOCK_RESTORE`, never deletion; already blocked restore is not modified.
- `UNMET` delete/redact/anonymize requirements produce a finding step, the
  operation corresponding to the rule's `required_action`, and a verification
  step only when the resource has eligible evidence and an explicit positive
  state or failed/partial matching operation.
- For an identified resource with an unresolved state but a clear, unconditional
  delete/redact/anonymize action, the planner may propose a verification step
  without proposing the destructive operation. Conditional support-message
  applicability, retention exceptions, tombstone conditions, and conflicts
  are not guessed; these are preserved as unresolved obligations instead.
- An active data flow with an at-cutoff connector state can produce
  `DISABLE_DATA_FLOW` and a disabled-state verification. If the flow is known
  but not explicitly active, it may produce verification only. A mere successful
  disable event is not evidence of the current disabled state.
- Conflicting observations block destructive operations for the affected
  resource. Missing resource IDs, systems, reliable timestamps, or source
  references prevent a targetable step from being emitted.
- A completed assessment yields an empty remediation list. Empty lists are
  valid and serialize to `[]`.

Each structured `RemediationStep` includes `case_id`, confirmed `subject_id`,
`rule_id`, phase, system/resource IDs, operation, expected/observed state,
evidence ID, all source references, reason, and `step_no`. The sample's step
objects contain only seven keys (`step_no`, `phase`, `system_id`,
`resource_id`, `operation`, `state`, and `evidence_id`). It is unknown whether
the eventual evaluator permits the planner's additional traceability fields;
the planner keeps them in its JSON-serializable representation rather than
discarding provenance. A final output writer should resolve this contract
before emitting the competition artifact.

### Deterministic ordering

No official operation ordering is present in the repository. Sample outputs
visibly group `FINDING` before `REMEDIATION` before `VERIFICATION`, but do not
establish a universal ordering among all operations or resources. The planner
therefore applies a disclosed implementation order, not an official contract:
phase order `FINDING` → `REMEDIATION` → `VERIFICATION`, then case-insensitive
`system_id`, `resource_id`, `rule_id`, `operation`, and source references.
`step_no` is assigned consecutively after this sort. Repeated runs with the
same inputs return identical plans.

### Validation examples and limits

- An explicitly active primary profile can receive `REPORT_REMAINING_RECORD`,
  `DELETE_RECORD`, and `VERIFY_RECORD_ABSENT`; an observed deleted profile
  receives no deletion step.
- An explicitly identifiable analytics profile maps to `ANONYMIZE_RECORD`
  and `VERIFY_RECORD_ANONYMIZED`, not `DELETE_RECORD`.
- An active connector can receive `REPORT_ACTIVE_DATA_FLOW`,
  `DISABLE_DATA_FLOW`, and `VERIFY_DATA_FLOW_DISABLED`.
- A backup with `restore_allowed=true` can receive `REPORT_RESTORE_RISK`,
  `BLOCK_RESTORE`, and `VERIFY_RESTORE_BLOCKED`; a retained backup with restore
  already blocked is left untouched.
- An unresolved tombstone condition or a same-instant conflict does not
  produce a destructive step. The plan records why it is blocked.

These are proposed next steps, not a record that the operation has run or
succeeded. Verification steps are recommendations only. The planner does not
infer ownership for resources cited only by `sample_output.csv`, does not
change policy statuses, and does not generate or overwrite root `output.csv`.
