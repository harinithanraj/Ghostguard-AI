"""Resolve deletion-request email identifiers to evidence-backed identities."""

from dataclasses import dataclass
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

if __package__:
    from .data_loader import Dataset
else:
    from data_loader import Dataset


IDENTIFIER_FIELDS = ("email", "phone", "email_hash")

CONFIRMED = "CONFIRMED"
UNCERTAIN = "UNCERTAIN"
CONFLICTING = "CONFLICTING"
UNMATCHED = "UNMATCHED"


@dataclass(frozen=True)
class EvidenceReference:
    """A source record and field value supporting an identity link."""

    source_file: str
    record_reference: str
    field_name: str
    value: str
    relationship: str

    @property
    def reference(self) -> str:
        """Return a compact, stable reference to the source record."""
        return f"{self.source_file}#{self.record_reference}"


@dataclass(frozen=True)
class ResolvedIdentifier:
    """An identifier associated with one candidate and its provenance."""

    identifier_type: str
    value: str
    current_evidence: Tuple[str, ...]
    historical_evidence: Tuple[str, ...]


@dataclass(frozen=True)
class IdentityCandidate:
    """One separately represented identity supported by matching evidence."""

    user_id: str
    match_evidence: Tuple[EvidenceReference, ...]
    identifiers: Tuple[ResolvedIdentifier, ...]
    has_conflicting_current_values: bool


@dataclass(frozen=True)
class IdentityResolution:
    """Identity-resolution result for one deletion request."""

    case_id: Optional[str]
    requested_identifier: Optional[str]
    status: str
    candidates: Tuple[IdentityCandidate, ...]
    unresolved_evidence: Tuple[EvidenceReference, ...]
    evidence_references: Tuple[str, ...]
    explanation: str


def _string_value(record: Mapping[str, object], field_name: str) -> Optional[str]:
    """Return a nonblank string field without coercing missing/non-string data."""
    value = record.get(field_name)
    if not isinstance(value, str) or not value.strip():
        return None
    return value


def _normalize_email(value: Optional[str]) -> Optional[str]:
    """Normalize an email for exact case-insensitive comparison only."""
    if value is None:
        return None
    return value.strip().casefold()


def _record_reference(
    record: Mapping[str, object],
    record_number: int,
    identifier_field: str,
) -> str:
    """Build a stable reference that remains distinct for duplicate records."""
    identifier = _string_value(record, identifier_field)
    suffix = f" ({identifier_field}={identifier})" if identifier else ""
    return f"record={record_number}{suffix}"


def _make_evidence(
    source_file: str,
    record: Mapping[str, object],
    record_number: int,
    record_id_field: str,
    field_name: str,
    value: str,
    relationship: str,
) -> EvidenceReference:
    """Construct provenance for a value found in one source record."""
    return EvidenceReference(
        source_file=source_file,
        record_reference=_record_reference(
            record, record_number, record_id_field
        ),
        field_name=field_name,
        value=value,
        relationship=relationship,
    )


def _unique_evidence(
    evidence: Sequence[EvidenceReference],
) -> Tuple[EvidenceReference, ...]:
    """Remove duplicate evidence references while preserving source order."""
    unique: Dict[Tuple[str, str, str, str, str], EvidenceReference] = {}
    for item in evidence:
        key = (
            item.source_file,
            item.record_reference,
            item.field_name,
            item.value,
            item.relationship,
        )
        unique.setdefault(key, item)
    return tuple(unique.values())


def _collect_identifiers(
    user_id: str,
    identity_records: Sequence[Mapping[str, object]],
    audit_log: Sequence[Mapping[str, object]],
) -> Tuple[Tuple[ResolvedIdentifier, ...], bool]:
    """Collect this user ID's current and audited identifiers without cross-linking."""
    identifiers: Dict[
        Tuple[str, str], Dict[str, List[str]]
    ] = {}
    current_values: Dict[str, set] = {field: set() for field in IDENTIFIER_FIELDS}

    for record_number, record in enumerate(identity_records, start=1):
        if _string_value(record, "user_id") != user_id:
            continue
        for field_name in IDENTIFIER_FIELDS:
            value = _string_value(record, field_name)
            if value is None:
                continue
            normalized = value.strip().casefold()
            current_values[field_name].add(normalized)
            entry = identifiers.setdefault(
                (field_name, normalized),
                {"value": value, "current": [], "historical": []},
            )
            entry["current"].append(
                "user_identities.csv#"
                + _record_reference(
                    record, record_number, "user_id"
                )
            )

    for record_number, record in enumerate(audit_log, start=1):
        if _string_value(record, "user_id") != user_id:
            continue
        field_name = _string_value(record, "field_name")
        if field_name not in IDENTIFIER_FIELDS:
            continue
        for audit_field in ("old_value", "new_value"):
            value = _string_value(record, audit_field)
            if value is None:
                continue
            normalized = value.strip().casefold()
            entry = identifiers.setdefault(
                (field_name, normalized),
                {"value": value, "current": [], "historical": []},
            )
            entry["historical"].append(
                "user_audit_log.csv#"
                + _record_reference(
                    record, record_number, "audit_id"
                )
            )

    resolved = []
    for identifier_key, sources in sorted(identifiers.items()):
        field_name = identifier_key[0]
        resolved.append(
            ResolvedIdentifier(
                identifier_type=field_name,
                value=sources["value"],
                current_evidence=tuple(dict.fromkeys(sources["current"])),
                historical_evidence=tuple(dict.fromkeys(sources["historical"])),
            )
        )

    has_conflicting_current_values = any(
        len(values) > 1 for values in current_values.values()
    )
    return tuple(resolved), has_conflicting_current_values


def resolve_request(
    request: Mapping[str, object],
    identity_records: Sequence[Mapping[str, object]],
    audit_log: Sequence[Mapping[str, object]],
) -> IdentityResolution:
    """Resolve a request's exact email using current and explicitly audited data.

    Similar names, phone numbers, hashes, or email spelling are never used to
    infer a link. Historical email values are usable only when an audit record
    associates that value with a user ID.
    """
    case_id = _string_value(request, "case_id")
    requested_identifier = _string_value(request, "email")
    normalized_request = _normalize_email(requested_identifier)

    matched_by_user: Dict[str, List[EvidenceReference]] = {}
    unresolved_evidence: List[EvidenceReference] = []

    if normalized_request is not None:
        for record_number, record in enumerate(identity_records, start=1):
            value = _string_value(record, "email")
            if _normalize_email(value) != normalized_request:
                continue
            evidence = _make_evidence(
                "user_identities.csv",
                record,
                record_number,
                "user_id",
                "email",
                value or "",
                "current",
            )
            user_id = _string_value(record, "user_id")
            if user_id is None:
                unresolved_evidence.append(evidence)
            else:
                matched_by_user.setdefault(user_id, []).append(evidence)

        for record_number, record in enumerate(audit_log, start=1):
            if _string_value(record, "field_name") != "email":
                continue
            user_id = _string_value(record, "user_id")
            for audit_field, relationship in (
                ("old_value", "historical_old"),
                ("new_value", "historical_new"),
            ):
                value = _string_value(record, audit_field)
                if _normalize_email(value) != normalized_request:
                    continue
                evidence = _make_evidence(
                    "user_audit_log.csv",
                    record,
                    record_number,
                    "audit_id",
                    audit_field,
                    value or "",
                    relationship,
                )
                if user_id is None:
                    unresolved_evidence.append(evidence)
                else:
                    matched_by_user.setdefault(user_id, []).append(evidence)

    candidates = []
    for user_id in sorted(matched_by_user):
        identifiers, has_conflicting_current_values = _collect_identifiers(
            user_id, identity_records, audit_log
        )
        candidates.append(
            IdentityCandidate(
                user_id=user_id,
                match_evidence=_unique_evidence(matched_by_user[user_id]),
                identifiers=identifiers,
                has_conflicting_current_values=has_conflicting_current_values,
            )
        )

    unresolved = _unique_evidence(unresolved_evidence)
    candidate_tuple = tuple(candidates)
    if len(candidate_tuple) > 1:
        status = CONFLICTING
        explanation = (
            "The exact requested email is linked by source records to multiple "
            "user IDs; candidate identities are kept separate."
        )
    elif any(candidate.has_conflicting_current_values for candidate in candidate_tuple):
        status = CONFLICTING
        explanation = (
            "The matched user ID has multiple distinct current values for at "
            "least one identifier field in user_identities.csv."
        )
    elif unresolved:
        status = UNCERTAIN
        explanation = (
            "Matching email evidence exists, but at least one matching source "
            "record has no usable user_id."
        )
    elif candidate_tuple:
        match_types = {
            evidence.relationship
            for evidence in candidate_tuple[0].match_evidence
        }
        if match_types == {"current"}:
            explanation = (
                "The requested email exactly matches a current email in "
                "user_identities.csv."
            )
        elif match_types and match_types.issubset(
            {"historical_old", "historical_new"}
        ):
            explanation = (
                "The requested email exactly matches audited email history "
                "(an old or new value) linked to this user_id."
            )
        else:
            explanation = (
                "The requested email exactly matches current identity data "
                "and/or audited email history linked to this user_id."
            )
        status = CONFIRMED
    elif normalized_request is None:
        status = UNMATCHED
        explanation = "The request has no nonblank email identifier to resolve."
    else:
        status = UNMATCHED
        explanation = (
            "No exact current or audited historical email match was found."
        )

    references = []
    for candidate in candidate_tuple:
        references.extend(evidence.reference for evidence in candidate.match_evidence)
        for identifier in candidate.identifiers:
            references.extend(identifier.current_evidence)
            references.extend(identifier.historical_evidence)
    references.extend(evidence.reference for evidence in unresolved)

    return IdentityResolution(
        case_id=case_id,
        requested_identifier=requested_identifier,
        status=status,
        candidates=candidate_tuple,
        unresolved_evidence=unresolved,
        evidence_references=tuple(dict.fromkeys(references)),
        explanation=explanation,
    )


def resolve_all_requests(dataset: Dataset) -> Tuple[IdentityResolution, ...]:
    """Resolve all deletion requests in their original dataset order."""
    return tuple(
        resolve_request(
            request,
            dataset.user_identities,
            dataset.user_audit_log,
        )
        for request in dataset.deletion_requests
    )
