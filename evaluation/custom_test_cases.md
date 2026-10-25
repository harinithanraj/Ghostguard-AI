# Custom provisional-policy scenarios

These are isolated synthetic tests of GhostGuard-AI's **documented
provisional policy**. They are not official competition cases, do not extend
the supplied rules, and do not modify source datasets. Each fixture uses a
synthetic request and synthetic evidence findings while loading the supplied
deletion-rule table.

| Scenario | Setup | Expected behavior | Policy basis |
|---|---|---|---|
| Pre-cutoff confirmed deletion | Identity is uniquely confirmed; an explicit `ABSENT` profile state for `account_custom` is timestamped before `audit_at`. | Policy returns `COMPLETE`; rule 01 is `SATISFIED`; no remediation step is proposed. | The documented status mapping requires confirmed identity and explicit profile evidence at or before the audit cutoff. |
| Specifically identified remaining profile | Identity is confirmed; an at-cutoff `ACTIVE` finding identifies `account_custom` in `account_service`. | Policy returns `INCOMPLETE`; plan targets that resource with `DELETE_RECORD` and associated finding/verification steps. | An explicit positive state is `UNMET`; the identity, resource, system, and cutoff evidence support targeting it. |
| Post-audit absence | Identity is confirmed; `ABSENT` is observed one second after `audit_at` and marked `POST_AUDIT`. | Policy remains `INCOMPLETE`; the event cannot satisfy rule 01 and cannot be used as proof of cutoff completion. | Policy eligibility requires a reliable event timestamp at or before the request's cutoff; post-audit evidence is excluded. |
| Permitted security retention | The profile is explicitly absent before cutoff; a linked security audit record is retained with `retention_until` after `audit_at`. | Policy returns `COMPLETE`; rule 12 is `PERMITTED_RETENTION`; planner does not propose deleting the retained audit record. | The documented rule-12 interpretation permits retention through an evidenced future retention deadline; that exception does not erase other obligations. |
| Uncertain ownership | Evidence reports an active profile, but the identity resolver cannot uniquely confirm the subject. | Policy remains `INCOMPLETE`; the plan has no destructive steps and has no confirmed `subject_id`. | The documented policy and planner require confirmed identity before attributing or targeting a resource. |
| Backup restore risk | Profile is absent; a linked, at-cutoff backup finding identifies `backup_custom`, `backup_service`, and `restore_allowed=true`. | Policy is `INCOMPLETE`; plan proposes `BLOCK_RESTORE` and verification, but not `DELETE_RECORD` for the retained archive. | Rule 14 treats explicitly allowed restore access as unmet; the planner's documented retention behavior blocks restore rather than deleting retained backups. |

## Test results

The corresponding six tests are in
`tests/test_custom_evaluation_scenarios.py`. All six passed in the full test
run. Their passing demonstrates only that the implementation follows the
current documented provisional interpretations for these synthetic inputs;
it does not establish official competition semantics.

## Unresolved points

- The official status contract and rule applicability semantics are
  unavailable.
- The test fixtures use the evaluator's current interpretation of `audit_at`
  and the supplied rules; future official instructions may change those
  expectations.
- The discovered empty production backup plans (reported in
  `evaluation_report.md`) are distinct from this synthetic scenario: those
  real analyzer findings lack `system_id` even though associated policy
  evidence references expose a system value. This test uses a finding with an
  explicit system and therefore does not cover or resolve that planner defect.
