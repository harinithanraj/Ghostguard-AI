"""Tests for evidence-backed deletion-request identity resolution."""

import unittest

from src.data_loader import load_dataset
from src.identity_resolver import (
    CONFIRMED,
    CONFLICTING,
    UNCERTAIN,
    UNMATCHED,
    resolve_all_requests,
    resolve_request,
)


def make_request(email: object = "person@example.test") -> dict:
    """Create a request using the observed deletion-request column names."""
    return {"case_id": "case_01", "email": email}


def make_identity(
    user_id: object = "user_01",
    email: object = "person@example.test",
    phone: object = "+1 555 0100",
    email_hash: object = "hash_01",
    name: object = "Example Person",
) -> dict:
    """Create an identity record using the observed identity CSV schema."""
    return {
        "user_id": user_id,
        "name": name,
        "email": email,
        "phone": phone,
        "email_hash": email_hash,
        "updated_at": "2026-01-01T00:00:00Z",
    }


def make_audit(
    audit_id: object = "audit_01",
    user_id: object = "user_01",
    field_name: object = "email",
    old_value: object = "old@example.test",
    new_value: object = "person@example.test",
) -> dict:
    """Create an audit record using the observed audit-log column names."""
    return {
        "audit_id": audit_id,
        "user_id": user_id,
        "event_time": "2026-01-01T00:00:00Z",
        "field_name": field_name,
        "old_value": old_value,
        "new_value": new_value,
    }


class IdentityResolverTests(unittest.TestCase):
    def test_current_email_match_preserves_request_and_identifier_provenance(self) -> None:
        request = make_request(" Person@Example.Test ")
        result = resolve_request(request, [make_identity()], [])

        self.assertEqual(result.case_id, "case_01")
        self.assertEqual(result.requested_identifier, " Person@Example.Test ")
        self.assertEqual(result.status, CONFIRMED)
        self.assertEqual(len(result.candidates), 1)
        candidate = result.candidates[0]
        self.assertEqual(candidate.user_id, "user_01")
        self.assertEqual(
            {identifier.identifier_type for identifier in candidate.identifiers},
            {"email", "phone", "email_hash"},
        )
        self.assertIn("user_identities.csv#record=1 (user_id=user_01)",
                      result.evidence_references)
        self.assertIn("current email", result.explanation)

    def test_historical_email_is_linked_only_through_audit_user_id(self) -> None:
        request = make_request("old@example.test")
        identity = make_identity(email="person@example.test")
        audit = make_audit()
        result = resolve_request(request, [identity], [audit])

        self.assertEqual(result.status, CONFIRMED)
        self.assertEqual(result.candidates[0].user_id, "user_01")
        self.assertIn("user_audit_log.csv#record=1 (audit_id=audit_01)",
                      result.evidence_references)
        old_email = next(
            item
            for item in result.candidates[0].identifiers
            if item.identifier_type == "email"
            and item.value == "old@example.test"
        )
        self.assertEqual(
            old_email.historical_evidence,
            ("user_audit_log.csv#record=1 (audit_id=audit_01)",),
        )
        self.assertIn("audited email history", result.explanation)

    def test_similar_name_or_unrelated_identifier_does_not_match(self) -> None:
        result = resolve_request(
            make_request("different@example.test"),
            [make_identity(email="person@example.test")],
            [make_audit(field_name="phone", old_value="different@example.test")],
        )

        self.assertEqual(result.status, UNMATCHED)
        self.assertEqual(result.candidates, ())
        self.assertEqual(result.evidence_references, ())

    def test_conflicting_email_matches_keep_candidate_identities_separate(self) -> None:
        result = resolve_request(
            make_request(),
            [
                make_identity(user_id="user_01", phone="+1 555 0101"),
                make_identity(user_id="user_02", phone="+1 555 0102"),
            ],
            [],
        )

        self.assertEqual(result.status, CONFLICTING)
        self.assertEqual(
            [candidate.user_id for candidate in result.candidates],
            ["user_01", "user_02"],
        )
        self.assertEqual(
            [
                next(
                    identifier.value
                    for identifier in candidate.identifiers
                    if identifier.identifier_type == "phone"
                )
                for candidate in result.candidates
            ],
            ["+1 555 0101", "+1 555 0102"],
        )

    def test_conflicting_current_records_for_one_user_are_not_silently_merged(self) -> None:
        result = resolve_request(
            make_request(),
            [
                make_identity(email="person@example.test"),
                make_identity(email="person@example.test", phone="+1 555 0199"),
            ],
            [],
        )

        self.assertEqual(result.status, CONFLICTING)
        self.assertEqual(len(result.candidates), 1)
        self.assertTrue(result.candidates[0].has_conflicting_current_values)
        self.assertEqual(len(result.candidates[0].match_evidence), 2)

    def test_missing_user_id_with_matching_evidence_is_uncertain(self) -> None:
        result = resolve_request(
            make_request(),
            [make_identity(user_id=None)],
            [],
        )

        self.assertEqual(result.status, UNCERTAIN)
        self.assertEqual(result.candidates, ())
        self.assertEqual(len(result.unresolved_evidence), 1)
        self.assertTrue(result.evidence_references)

    def test_missing_values_and_duplicate_records_are_handled_safely(self) -> None:
        identity = make_identity(phone=None, email_hash="")
        result = resolve_request(
            make_request(),
            [identity, dict(identity)],
            [make_audit(field_name="phone", old_value=None, new_value="")],
        )

        self.assertEqual(result.status, CONFIRMED)
        identifiers = result.candidates[0].identifiers
        self.assertEqual([item.identifier_type for item in identifiers], ["email"])
        self.assertEqual(len(result.candidates[0].match_evidence), 2)

    def test_real_dataset_resolves_current_and_historical_request_emails(self) -> None:
        dataset = load_dataset()
        results = resolve_all_requests(dataset)

        self.assertEqual(len(results), 518)
        self.assertTrue(all(result.status == CONFIRMED for result in results))
        historical_only = [
            result
            for result in results
            if result.candidates
            and all(
                evidence.relationship != "current"
                for evidence in result.candidates[0].match_evidence
            )
        ]
        self.assertEqual(len(historical_only), 100)
        self.assertTrue(
            all(result.case_id is not None for result in results)
        )


if __name__ == "__main__":
    unittest.main()
