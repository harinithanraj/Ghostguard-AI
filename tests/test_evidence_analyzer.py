"""Tests for identity-linked evidence extraction."""

import json
from pathlib import Path
import tempfile
import unittest

from src.data_loader import Dataset, load_dataset
from src.evidence_analyzer import (
    AT_AUDIT,
    DIRECT,
    INDIRECT,
    POST_AUDIT,
    PRE_AUDIT,
    UNKNOWN_TIME,
    EvidenceAnalyzer,
    analyze_all_requests,
)
from src.identity_resolver import resolve_request


def make_request(
    email: str = "person@example.test",
    audit_at: str = "2026-06-15T12:00:00Z",
) -> dict:
    """Build a request with the observed deletion_requests.csv fields."""
    return {
        "case_id": "case_01",
        "email": email,
        "requested_at": "2026-06-01T12:00:00Z",
        "reported_status": "COMPLETE",
        "reported_at": "2026-06-02T12:00:00Z",
        "audit_at": audit_at,
        "request_text": "Please delete my account.",
    }


def make_identity() -> dict:
    """Build an identity row with the observed user_identities.csv fields."""
    return {
        "user_id": "user_01",
        "name": "Example Person",
        "email": "person@example.test",
        "phone": "+1 555 0100",
        "email_hash": "hash_01",
        "updated_at": "2026-01-01T00:00:00Z",
    }


def make_audit_log() -> list:
    """Build the audit rows consumed by the existing identity resolver."""
    return []


def make_dataset(
    root: Path,
    manifest: list,
    activity: list = None,
) -> Dataset:
    """Create a minimal Dataset with the actual project's field names."""
    return Dataset(
        project_root=root,
        deletion_requests=[],
        sample_deletion_requests=[],
        sample_output=[],
        user_identities=[make_identity()],
        user_audit_log=make_audit_log(),
        system_activity=activity or [],
        deletion_rules=[],
        evidence_files=manifest,
        evidence_found=tuple(entry["file_path"] for entry in manifest),
        evidence_missing=(),
    )


def make_resolution(request: dict = None):
    """Resolve a synthetic request using the real Phase 2 resolver."""
    return resolve_request(
        request or make_request(),
        [make_identity()],
        make_audit_log(),
    )


class EvidenceAnalyzerTests(unittest.TestCase):
    def test_json_and_log_matches_preserve_paths_timestamps_and_resource_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            evidence_dir = root / "dataset" / "evidence"
            (evidence_dir / "records").mkdir(parents=True)
            (evidence_dir / "logs").mkdir()
            (evidence_dir / "documents").mkdir()
            json_path = evidence_dir / "records" / "snapshot.json"
            json_path.write_text(
                json.dumps(
                    {
                        "exported_at": "2026-06-14T10:00:00Z",
                        "snapshots": [
                            {
                                "captured_at": "2026-06-14T09:00:00Z",
                                "data_store": "account_service",
                                "records": [
                                    {
                                        "resource_id": "account_77",
                                        "customer_reference": "user_01",
                                        "email": "person@example.test",
                                        "account_status": "ACTIVE",
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            log_path = evidence_dir / "logs" / "activity.log"
            log_path.write_text(
                "2026-06-14T11:00:00Z level=INFO service=search_service "
                "event=index_query_completed resource_id=account_77 "
                "result=hit\n",
                encoding="utf-8",
            )
            text_path = evidence_dir / "documents" / "handover.txt"
            text_path.write_text(
                "- 2026-06-14T11:30:00Z | account_service | account_77 | "
                "USER_PROFILE | NOT_FOUND | person@example.test\n",
                encoding="utf-8",
            )
            manifest = [
                {
                    "file_id": "evidence_01",
                    "file_path": "evidence/records/snapshot.json",
                    "origin": "test",
                    "captured_at": "2026-06-14T10:00:00Z",
                },
                {
                    "file_id": "evidence_02",
                    "file_path": "evidence/logs/activity.log",
                    "origin": "test",
                    "captured_at": "2026-06-14T11:00:00Z",
                },
                {
                    "file_id": "evidence_03",
                    "file_path": "evidence/documents/handover.txt",
                    "origin": "test",
                    "captured_at": "2026-06-14T11:30:00Z",
                },
            ]
            dataset = make_dataset(root, manifest)

            result = EvidenceAnalyzer(dataset).analyze_request(
                make_request(), make_resolution()
            )

            self.assertEqual(len(result.findings), 3)
            json_finding = next(
                item for item in result.findings if item.file_path.endswith(".json")
            )
            log_finding = next(
                item for item in result.findings if item.file_path.endswith(".log")
            )
            text_finding = next(
                item for item in result.findings if item.file_path.endswith(".txt")
            )
            self.assertEqual(json_finding.evidence_id, "evidence_01")
            self.assertEqual(json_finding.resource_id, "account_77")
            self.assertEqual(json_finding.match_type, DIRECT)
            self.assertEqual(json_finding.temporal_relation, UNKNOWN_TIME)
            self.assertFalse(json_finding.as_of_audit)
            self.assertEqual(
                json_finding.source_captured_at, "2026-06-14T09:00:00Z"
            )
            self.assertEqual(log_finding.resource_id, "account_77")
            self.assertEqual(log_finding.match_type, INDIRECT)
            self.assertEqual(log_finding.source_reference, "line=1")
            self.assertEqual(log_finding.timestamp, "2026-06-14T11:00:00Z")
            self.assertIn("ACTIVE_PROCESSING", log_finding.finding_types)
            self.assertEqual(text_finding.resource_id, "account_77")
            self.assertEqual(text_finding.result_or_state, "NOT_FOUND")
            self.assertEqual(text_finding.source_reference, "line=1")

    def test_sql_snapshot_and_system_activity_rows_are_linked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            evidence_dir = root / "dataset" / "evidence" / "databases"
            evidence_dir.mkdir(parents=True)
            sql_path = evidence_dir / "snapshot.sql"
            sql_path.write_text(
                "CREATE TABLE profiles (resource_id TEXT, user_id TEXT, "
                "email TEXT, account_status TEXT, updated_at TEXT);"
                "INSERT INTO profiles VALUES "
                "('account_77', 'user_01', 'person@example.test', 'ACTIVE', "
                "'2026-06-14T10:00:00Z');",
                encoding="utf-8",
            )
            manifest = [
                {
                    "file_id": "evidence_sql",
                    "file_path": "evidence/databases/snapshot.sql",
                    "origin": "test",
                    "captured_at": "2026-06-14T11:00:00Z",
                }
            ]
            activity = [
                {
                    "activity_id": "activity_10",
                    "event_time": "2026-06-14T11:30:00Z",
                    "event_type": "LINK_RESOURCE_IDENTITY",
                    "source_system": "data_catalog",
                    "target_system": "account_service",
                    "resource_id": "account_77",
                    "reported_result": "SUCCESS",
                    "details": "Linked account_77 to user_01 and person@example.test.",
                },
                {
                    "activity_id": "activity_11",
                    "event_time": "2026-06-14T11:31:00Z",
                    "event_type": "DELETE_RECORD",
                    "source_system": "deletion_worker",
                    "target_system": "account_service",
                    "resource_id": "account_77",
                    "reported_result": "SUCCESS",
                    "details": "Deletion worker submitted profile account_77.",
                },
            ]
            dataset = make_dataset(root, manifest, activity)

            result = EvidenceAnalyzer(dataset).analyze_request(
                make_request(), make_resolution()
            )

            sql_finding = next(
                item for item in result.findings if item.file_path.endswith(".sql")
            )
            activity_findings = [
                item
                for item in result.findings
                if item.file_path == "system_activity.csv"
            ]
            self.assertEqual(sql_finding.match_type, DIRECT)
            self.assertIn("table=profiles,row=1", sql_finding.source_reference)
            self.assertEqual(sql_finding.resource_id, "account_77")
            self.assertEqual(len(activity_findings), 2)
            self.assertTrue(
                next(
                    item
                    for item in activity_findings
                    if item.operation == "LINK_RESOURCE_IDENTITY"
                ).match_type
                == DIRECT
            )
            linked_finding = next(
                item
                for item in activity_findings
                if item.operation == "LINK_RESOURCE_IDENTITY"
            )
            self.assertEqual(linked_finding.source_system, "data_catalog")
            self.assertEqual(linked_finding.target_system, "account_service")
            self.assertIsNone(linked_finding.source_captured_at)
            self.assertTrue(
                next(
                    item
                    for item in activity_findings
                    if item.operation == "DELETE_RECORD"
                ).match_type
                == INDIRECT
            )
            self.assertTrue(
                all(item.as_of_audit for item in activity_findings)
            )
            self.assertTrue(
                any("DELETION" in item.finding_types for item in activity_findings)
            )
            self.assertEqual(result.conflicts, ())

    def test_post_audit_evidence_is_not_treated_as_audit_time_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            evidence_dir = root / "dataset" / "evidence" / "logs"
            evidence_dir.mkdir(parents=True)
            (evidence_dir / "after.log").write_text(
                "2026-06-16T00:00:00Z level=INFO service=account_service "
                "event=profile_lookup_completed lookup_key=person@example.test "
                "resource_id=account_77 result=FOUND\n",
                encoding="utf-8",
            )
            manifest = [
                {
                    "file_id": "evidence_after",
                    "file_path": "evidence/logs/after.log",
                    "origin": "test",
                    "captured_at": "2026-06-16T01:00:00Z",
                }
            ]
            result = EvidenceAnalyzer(make_dataset(root, manifest)).analyze_request(
                make_request(), make_resolution()
            )

            self.assertEqual(len(result.findings), 1)
            self.assertEqual(result.findings[0].temporal_relation, POST_AUDIT)
            self.assertFalse(result.findings[0].as_of_audit)

    def test_post_audit_identity_resource_link_does_not_attach_older_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            evidence_dir = root / "dataset" / "evidence" / "records"
            evidence_dir.mkdir(parents=True)
            (evidence_dir / "late_link.json").write_text(
                json.dumps(
                    {
                        "records": [
                            {
                                "user_id": "user_01",
                                "resource_id": "account_77",
                                "observed_at": "2026-06-16T00:00:00Z",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (evidence_dir / "older_state.json").write_text(
                json.dumps(
                    {
                        "records": [
                            {
                                "resource_id": "account_77",
                                "state": "ABSENT",
                                "observed_at": "2026-06-14T00:00:00Z",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            manifest = [
                {
                    "file_id": "evidence_late_link",
                    "file_path": "evidence/records/late_link.json",
                    "origin": "test",
                    "captured_at": "2026-06-16T00:00:00Z",
                },
                {
                    "file_id": "evidence_older_state",
                    "file_path": "evidence/records/older_state.json",
                    "origin": "test",
                    "captured_at": "2026-06-14T00:00:00Z",
                },
            ]

            result = EvidenceAnalyzer(make_dataset(root, manifest)).analyze_request(
                make_request(), make_resolution()
            )

            self.assertEqual(len(result.findings), 1)
            self.assertEqual(
                result.findings[0].file_path,
                "evidence/records/late_link.json",
            )
            self.assertEqual(result.findings[0].temporal_relation, POST_AUDIT)

    def test_explicit_json_nulls_are_preserved_without_becoming_identifiers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            evidence_dir = root / "dataset" / "evidence" / "records"
            evidence_dir.mkdir(parents=True)
            (evidence_dir / "analytics.json").write_text(
                json.dumps(
                    {
                        "records": [
                            {
                                "resource_id": "analytics_77",
                                "user_id": "user_01",
                                "system_id": "analytics_platform",
                                "subject_reference": "user_01",
                                "name": None,
                                "customer_reference": None,
                                "email": None,
                                "phone": None,
                                "email_hash": None,
                                "observed_at": "2026-06-14T10:00:00Z",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            manifest = [
                {
                    "file_id": "evidence_analytics",
                    "file_path": "evidence/records/analytics.json",
                    "origin": "test",
                    "captured_at": "2026-06-14T10:00:00Z",
                }
            ]

            result = EvidenceAnalyzer(make_dataset(root, manifest)).analyze_request(
                make_request(), make_resolution()
            )

            self.assertEqual(len(result.findings), 1)
            finding = result.findings[0]
            self.assertEqual(
                dict(finding.policy_attributes),
                {
                    "subject_reference": "user_01",
                    "name": "null",
                    "customer_reference": "null",
                    "email": "null",
                    "phone": "null",
                    "email_hash": "null",
                    "user_id": "user_01",
                },
            )
            self.assertNotIn("null", finding.matched_identifiers)

    def test_explicit_opposing_states_are_reported_as_a_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            evidence_dir = root / "dataset" / "evidence" / "records"
            evidence_dir.mkdir(parents=True)
            (evidence_dir / "states.json").write_text(
                json.dumps(
                    {
                        "records": [
                            {
                                "resource_id": "account_77",
                                "user_id": "user_01",
                                "state": "ACTIVE",
                                "observed_at": "2026-06-14T12:00:00Z",
                            },
                            {
                                "resource_id": "account_77",
                                "email": "person@example.test",
                                "state": "ABSENT",
                                "observed_at": "2026-06-14T14:00:00+02:00",
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            manifest = [
                {
                    "file_id": "evidence_states",
                    "file_path": "evidence/records/states.json",
                    "origin": "test",
                    "captured_at": "2026-06-14T12:00:00Z",
                }
            ]
            result = EvidenceAnalyzer(make_dataset(root, manifest)).analyze_request(
                make_request(), make_resolution()
            )

            self.assertEqual(len(result.conflicts), 1)
            self.assertEqual(result.conflicts[0].resource_id, "account_77")
            self.assertEqual(result.conflicts[0].timestamp, "2026-06-14T12:00:00Z")
            self.assertEqual(result.conflicts[0].states, ("ABSENT", "ACTIVE"))
            self.assertEqual(
                set(result.conflicts[0].evidence_references),
                {
                    f"{finding.file_path}#{finding.source_reference}"
                    for finding in result.findings
                },
            )
            self.assertTrue(
                all(finding.conflict_references for finding in result.findings)
            )

    def test_opposing_states_at_different_times_are_not_a_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            evidence_dir = root / "dataset" / "evidence" / "records"
            evidence_dir.mkdir(parents=True)
            (evidence_dir / "transitions.json").write_text(
                json.dumps(
                    {
                        "records": [
                            {
                                "resource_id": "account_77",
                                "email": "person@example.test",
                                "result": "FOUND",
                                "observed_at": "2026-06-14T10:00:00Z",
                            },
                            {
                                "resource_id": "account_77",
                                "email": "person@example.test",
                                "result": "NOT_FOUND",
                                "observed_at": "2026-06-14T11:00:00Z",
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            manifest = [
                {
                    "file_id": "evidence_transition",
                    "file_path": "evidence/records/transitions.json",
                    "origin": "test",
                    "captured_at": "2026-06-14T12:00:00Z",
                }
            ]
            result = EvidenceAnalyzer(make_dataset(root, manifest)).analyze_request(
                make_request(), make_resolution()
            )

            self.assertEqual(len(result.findings), 2)
            self.assertEqual(
                {finding.explicit_state for finding in result.findings},
                {"FOUND", "NOT_FOUND"},
            )
            self.assertEqual(result.conflicts, ())

    def test_missing_files_malformed_json_and_unsupported_media_are_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            evidence_dir = root / "dataset" / "evidence" / "records"
            evidence_dir.mkdir(parents=True)
            (evidence_dir / "bad.json").write_text("{broken", encoding="utf-8")
            (evidence_dir / "image.png").write_bytes(b"not-a-real-image")
            (evidence_dir / "unreadable.pdf").write_bytes(b"not-a-real-pdf")
            (evidence_dir / "unsafe.sql").write_text(
                "ATTACH DATABASE 'outside.db' AS external_data;",
                encoding="utf-8",
            )
            manifest = [
                {
                    "file_id": "evidence_missing",
                    "file_path": "evidence/records/missing.txt",
                    "origin": "test",
                    "captured_at": "",
                },
                {
                    "file_id": "evidence_bad",
                    "file_path": "evidence/records/bad.json",
                    "origin": "test",
                    "captured_at": "",
                },
                {
                    "file_id": "evidence_image",
                    "file_path": "evidence/records/image.png",
                    "origin": "test",
                    "captured_at": "",
                },
                {
                    "file_id": "evidence_pdf",
                    "file_path": "evidence/records/unreadable.pdf",
                    "origin": "test",
                    "captured_at": "",
                },
                {
                    "file_id": "evidence_unsafe_sql",
                    "file_path": "evidence/records/unsafe.sql",
                    "origin": "test",
                    "captured_at": "",
                },
            ]
            result = EvidenceAnalyzer(make_dataset(root, manifest)).analyze_request(
                make_request(), make_resolution()
            )

            reasons = {gap.file_path: gap.reason for gap in result.gaps}
            self.assertIn("evidence/records/missing.txt", reasons)
            self.assertIn("could not be parsed", reasons["evidence/records/bad.json"])
            self.assertIn("OCR", reasons["evidence/records/image.png"])
            self.assertIn("PDF", reasons["evidence/records/unreadable.pdf"])
            self.assertIn("not authorized", reasons["evidence/records/unsafe.sql"])
            self.assertEqual(result.findings, ())

    def test_event_timestamp_takes_precedence_over_source_capture_time(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            evidence_dir = root / "dataset" / "evidence" / "records"
            evidence_dir.mkdir(parents=True)
            (evidence_dir / "snapshot.json").write_text(
                json.dumps(
                    {
                        "exported_at": "2026-06-16T00:00:00Z",
                        "records": [
                            {
                                "email": "person@example.test",
                                "resource_id": "account_77",
                                "observed_at": "2026-06-14T10:00:00Z",
                                "state": "ACTIVE",
                            },
                            {
                                "email": "person@example.test",
                                "resource_id": "account_78",
                                "observed_at": "2026-06-16T10:00:00Z",
                                "state": "ACTIVE",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            manifest = [
                {
                    "file_id": "evidence_capture",
                    "file_path": "evidence/records/snapshot.json",
                    "origin": "test",
                    "captured_at": "2026-06-17T00:00:00Z",
                }
            ]
            result = EvidenceAnalyzer(make_dataset(root, manifest)).analyze_request(
                make_request(), make_resolution()
            )

            by_resource = {finding.resource_id: finding for finding in result.findings}
            before = by_resource["account_77"]
            after = by_resource["account_78"]
            self.assertEqual(before.temporal_relation, PRE_AUDIT)
            self.assertTrue(before.as_of_audit)
            self.assertEqual(before.source_captured_at, "2026-06-16T00:00:00Z")
            self.assertEqual(after.temporal_relation, POST_AUDIT)
            self.assertFalse(after.as_of_audit)
            self.assertEqual(after.source_captured_at, "2026-06-16T00:00:00Z")

    def test_missing_invalid_and_naive_event_timestamps_remain_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            evidence_dir = root / "dataset" / "evidence" / "records"
            evidence_dir.mkdir(parents=True)
            (evidence_dir / "timestamps.json").write_text(
                json.dumps(
                    {
                        "exported_at": "2026-06-14T08:00:00Z",
                        "records": [
                            {
                                "email": "person@example.test",
                                "resource_id": "account_missing",
                            },
                            {
                                "email": "person@example.test",
                                "resource_id": "account_invalid",
                                "observed_at": "yesterday",
                            },
                            {
                                "email": "person@example.test",
                                "resource_id": "account_naive",
                                "observed_at": "2026-06-14T10:00:00",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            manifest = [
                {
                    "file_id": "evidence_timestamps",
                    "file_path": "evidence/records/timestamps.json",
                    "origin": "test",
                    "captured_at": "2026-06-14T08:00:00Z",
                }
            ]
            result = EvidenceAnalyzer(make_dataset(root, manifest)).analyze_request(
                make_request(), make_resolution()
            )

            self.assertEqual(len(result.findings), 3)
            self.assertTrue(
                all(finding.temporal_relation == UNKNOWN_TIME
                    for finding in result.findings)
            )
            self.assertTrue(all(not finding.as_of_audit for finding in result.findings))
            self.assertTrue(
                all(finding.source_captured_at == "2026-06-14T08:00:00Z"
                    for finding in result.findings)
            )

    def test_each_request_uses_its_own_audit_at_with_inclusive_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            evidence_dir = root / "dataset" / "evidence" / "records"
            evidence_dir.mkdir(parents=True)
            (evidence_dir / "event.json").write_text(
                json.dumps(
                    {
                        "records": [
                            {
                                "email": "person@example.test",
                                "resource_id": "account_77",
                                "observed_at": "2026-06-14T14:00:00+02:00",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            manifest = [
                {
                    "file_id": "evidence_boundary",
                    "file_path": "evidence/records/event.json",
                    "origin": "test",
                    "captured_at": "",
                }
            ]
            requests = [
                make_request(audit_at="2026-06-14T12:00:00Z"),
                {**make_request(audit_at="2026-06-14T11:00:00Z"), "case_id": "case_02"},
                {**make_request(audit_at="2026-06-14T13:00:00Z"), "case_id": "case_03"},
            ]
            dataset = make_dataset(root, manifest)
            dataset.deletion_requests = requests
            resolutions = [
                resolve_request(request, dataset.user_identities, dataset.user_audit_log)
                for request in requests
            ]

            results = analyze_all_requests(dataset, resolutions)

            self.assertEqual(
                [result.findings[0].temporal_relation for result in results],
                [AT_AUDIT, POST_AUDIT, PRE_AUDIT],
            )
            self.assertEqual(
                [result.findings[0].as_of_audit for result in results],
                [True, False, True],
            )
            self.assertEqual(
                [result.case_id for result in results],
                ["case_01", "case_02", "case_03"],
            )

    def test_unparseable_audit_time_keeps_temporal_relation_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            evidence_dir = root / "dataset" / "evidence" / "records"
            evidence_dir.mkdir(parents=True)
            (evidence_dir / "record.json").write_text(
                json.dumps(
                    {
                        "records": [
                            {
                                "user_id": "user_01",
                                "email": "person@example.test",
                                "observed_at": "2026-06-14T10:00:00Z",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            manifest = [
                {
                    "file_id": "evidence_unknown_time",
                    "file_path": "evidence/records/record.json",
                    "origin": "test",
                    "captured_at": "",
                }
            ]
            result = EvidenceAnalyzer(make_dataset(root, manifest)).analyze_request(
                make_request(audit_at="not-a-timestamp"), make_resolution()
            )

            self.assertEqual(result.findings[0].temporal_relation, UNKNOWN_TIME)
            self.assertFalse(result.findings[0].as_of_audit)

    def test_absence_of_matches_is_not_reported_as_deletion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            evidence_dir = root / "dataset" / "evidence" / "records"
            evidence_dir.mkdir(parents=True)
            (evidence_dir / "unrelated.json").write_text(
                json.dumps(
                    {"records": [{"email": "someone-else@example.test"}]}
                ),
                encoding="utf-8",
            )
            manifest = [
                {
                    "file_id": "evidence_unrelated",
                    "file_path": "evidence/records/unrelated.json",
                    "origin": "test",
                    "captured_at": "",
                }
            ]
            result = EvidenceAnalyzer(make_dataset(root, manifest)).analyze_request(
                make_request(), make_resolution()
            )

            self.assertEqual(result.findings, ())
            self.assertEqual(result.conflicts, ())

    def test_real_evidence_formats_and_all_requests_are_analyzed(self) -> None:
        dataset = load_dataset()
        sample_request = dataset.deletion_requests[0]
        resolution = resolve_request(
            sample_request,
            dataset.user_identities,
            dataset.user_audit_log,
        )
        analyzer = EvidenceAnalyzer(dataset)
        sample = analyzer.analyze_request(sample_request, resolution)

        self.assertTrue(
            any(finding.file_path.endswith((".json", ".log", ".sql", ".txt"))
                for finding in sample.findings)
        )
        extensions = {Path(entry["file_path"]).suffix.lower()
                      for entry in dataset.evidence_files}
        self.assertTrue({".json", ".log", ".sql", ".txt", ".pdf", ".png"} <= extensions)
        pdf_manifest_paths = {
            entry["file_path"]
            for entry in dataset.evidence_files
            if entry["file_path"].endswith(".pdf")
        }
        image_manifest_paths = {
            entry["file_path"]
            for entry in dataset.evidence_files
            if entry["file_path"].endswith(".png")
        }
        pdf_paths = {
            record.file_path
            for record in analyzer.records
            if record.file_path.endswith(".pdf")
        }
        image_paths = {
            record.file_path
            for record in analyzer.records
            if record.file_path.endswith(".png")
        }
        pdf_gaps = {
            gap.file_path
            for gap in analyzer.gaps
            if gap.file_path.endswith(".pdf")
        }
        image_gaps = {
            gap.file_path
            for gap in analyzer.gaps
            if gap.file_path.endswith(".png")
        }
        self.assertEqual(pdf_paths | pdf_gaps, pdf_manifest_paths)
        self.assertFalse(pdf_paths & pdf_gaps)
        self.assertEqual(image_paths | image_gaps, image_manifest_paths)
        self.assertFalse(image_paths & image_gaps)

        results = analyze_all_requests(dataset)
        self.assertEqual(len(results), 518)
        self.assertTrue(all(result.case_id for result in results))
        self.assertEqual(sum(len(result.conflicts) for result in results), 0)

    def test_case_33_timestamps_are_relative_to_its_actual_audit_at(self) -> None:
        dataset = load_dataset()
        request = next(
            item for item in dataset.deletion_requests if item["case_id"] == "case_33"
        )
        self.assertEqual(request["audit_at"], "2026-07-19T13:00:00Z")
        resolution = resolve_request(
            request, dataset.user_identities, dataset.user_audit_log
        )
        analysis = EvidenceAnalyzer(dataset).analyze_request(request, resolution)

        june_link = next(
            finding
            for finding in analysis.findings
            if finding.operation == "LINK_RESOURCE_IDENTITY"
            and finding.timestamp == "2026-06-18T12:07:01Z"
        )
        july_link = next(
            finding
            for finding in analysis.findings
            if finding.operation == "LINK_RESOURCE_IDENTITY"
            and finding.timestamp == "2026-07-18T11:07:01Z"
        )
        august_delete = next(
            finding
            for finding in analysis.findings
            if finding.operation == "DELETE_RECORD"
            and finding.timestamp == "2026-08-19T12:49:28Z"
        )
        september_event = next(
            finding
            for finding in analysis.findings
            if finding.timestamp == "2026-09-15T11:53:13Z"
        )
        self.assertEqual(june_link.temporal_relation, PRE_AUDIT)
        self.assertEqual(july_link.temporal_relation, PRE_AUDIT)
        self.assertEqual(august_delete.temporal_relation, POST_AUDIT)
        self.assertEqual(september_event.temporal_relation, POST_AUDIT)
        self.assertFalse(august_delete.as_of_audit)
        self.assertFalse(september_event.as_of_audit)

    def test_real_opposing_state_pairs_are_chronological_observations(self) -> None:
        dataset = load_dataset()
        analyses = analyze_all_requests(dataset)
        parsed_references = {
            (record.file_path, record.source_reference)
            for record in EvidenceAnalyzer(dataset).records
        }
        six_reported_pairs = {
            ("case_86", "account_8473"),
            ("case_135", "account_1417"),
            ("case_238", "account_945"),
            ("case_383", "account_5043"),
            ("case_390", "account_7618"),
            ("case_486", "account_9031"),
        }
        additional_pairs = {
            ("case_239", "account_2838"),
            ("case_335", "account_8892"),
        }
        observed = set()
        for analysis in analyses:
            grouped = {}
            for finding in analysis.findings:
                if finding.explicit_state in {"FOUND", "NOT_FOUND"}:
                    grouped.setdefault(finding.resource_id, []).append(finding)
            for resource_id, findings in grouped.items():
                states = {finding.explicit_state for finding in findings}
                if states == {"FOUND", "NOT_FOUND"}:
                    observed.add((analysis.case_id, resource_id))
                    self.assertEqual(
                        len({finding.timestamp for finding in findings}), 2
                    )
                    self.assertTrue(
                        all(finding.timestamp is not None for finding in findings)
                    )
                    self.assertTrue(
                        all(
                            finding.file_path and finding.source_reference
                            for finding in findings
                        )
                    )
                    self.assertTrue(
                        all(
                            (finding.file_path, finding.source_reference)
                            in parsed_references
                            and (
                                dataset.project_root
                                / "dataset"
                                / finding.file_path
                            ).is_file()
                            for finding in findings
                        )
                    )
        self.assertEqual(observed, six_reported_pairs | additional_pairs)
        for analysis in analyses:
            for conflict in analysis.conflicts:
                self.assertTrue(conflict.evidence_references)
        self.assertTrue(all(not analysis.conflicts for analysis in analyses))


if __name__ == "__main__":
    unittest.main()
