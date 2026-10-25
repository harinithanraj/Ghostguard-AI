"""Extract identity-linked evidence without making deletion-policy decisions."""

import csv
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import asyncio
import json
import logging
from pathlib import Path
import re
import sqlite3
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

if __package__:
    from .data_loader import Dataset
    from .identity_resolver import IdentityResolution
else:
    from data_loader import Dataset
    from identity_resolver import IdentityResolution


LOGGER = logging.getLogger(__name__)

DIRECT = "DIRECT"
INDIRECT = "INDIRECT"

PRE_AUDIT = "PRE_AUDIT"
AT_AUDIT = "AT_AUDIT"
POST_AUDIT = "POST_AUDIT"
UNKNOWN_TIME = "UNKNOWN"

RESOURCE_FIELDS = {
    "resource_id",
    "resource",
    "source_resource_id",
    "target_resource_id",
    "downstream_resource_id",
    "parent_resource_id",
    "related_resource_id",
    "backup_resource_id",
    "restore_resource_id",
}
EVENT_TIME_FIELDS = {
    "event_time",
    "event_timestamp",
    "occurred_at",
    "observed_at",
    "recorded_at",
    "timestamp",
}
IDENTIFIER_TOKEN_PATTERN = re.compile(
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    r"|\buser_[A-Za-z0-9_-]+\b"
    r"|\b[0-9a-fA-F]{32,128}\b"
    r"|\+?\d[\d ().-]{5,}\d"
)
POSITIVE_STATES = {"ACTIVE", "EXISTS", "FOUND", "PRESENT", "RETAINED"}
NEGATIVE_STATES = {
    "ABSENT",
    "DELETED",
    "ERASED",
    "NOT_FOUND",
    "MISSING",
    "PURGED",
}
TEXT_FIELDS = {
    "details",
    "message",
    "raw_text",
    "description",
    "lookup_key",
    "subject_reference",
    "customer_reference",
    "owner_email",
}


@dataclass(frozen=True)
class EvidenceFinding:
    """One identity-linked record or event extracted from a source."""

    case_id: Optional[str]
    evidence_id: Optional[str]
    file_path: str
    source_reference: str
    record_id: Optional[str]
    event_id: Optional[str]
    timestamp: Optional[str]
    timestamp_field: Optional[str]
    source_captured_at: Optional[str]
    temporal_relation: str
    as_of_audit: bool
    system_id: Optional[str]
    source_system: Optional[str]
    target_system: Optional[str]
    resource_id: Optional[str]
    operation: Optional[str]
    result_or_state: Optional[str]
    explicit_state: Optional[str]
    finding_types: Tuple[str, ...]
    match_type: str
    matched_identifiers: Tuple[str, ...]
    conflict_references: Tuple[str, ...] = ()
    data_category: Optional[str] = None
    policy_attributes: Tuple[Tuple[str, str], ...] = ()


@dataclass(frozen=True)
class EvidenceGap:
    """A manifest source that could not be examined for this request."""

    evidence_id: Optional[str]
    file_path: str
    reason: str


@dataclass(frozen=True)
class EvidenceConflict:
    """Two records that report incompatible explicit states for one resource."""

    resource_id: str
    timestamp: str
    evidence_references: Tuple[str, ...]
    states: Tuple[str, ...]
    explanation: str


@dataclass(frozen=True)
class RequestEvidenceAnalysis:
    """Evidence findings for one request, independent of deletion status."""

    case_id: Optional[str]
    requested_identifier: Optional[str]
    identity_status: str
    findings: Tuple[EvidenceFinding, ...]
    gaps: Tuple[EvidenceGap, ...]
    conflicts: Tuple[EvidenceConflict, ...]


@dataclass(frozen=True)
class _EvidenceRecord:
    """Parsed source record used internally for identity matching."""

    evidence_id: Optional[str]
    file_path: str
    source_reference: str
    values: Tuple[Tuple[str, str], ...]
    source_captured_at: Optional[str]


def _normalize(value: str) -> str:
    """Normalize identifiers for exact case-insensitive matching."""
    return value.strip().casefold()


def _as_text(value: object) -> Optional[str]:
    """Convert scalar evidence values to text while preserving explicit nulls."""
    if isinstance(value, (dict, list, tuple, set)):
        return None
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value).strip()
    return text or None


def _field_name(value: str) -> str:
    """Return a normalized terminal field name for dotted JSON paths."""
    return value.rsplit(".", 1)[-1].casefold()


def _parse_datetime(value: Optional[str]) -> Optional[datetime]:
    """Parse timezone-aware ISO timestamps and normalize them to UTC."""
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except (ValueError, OverflowError):
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _json_records(
    path: Path, file_path: str, evidence_id: Optional[str]
) -> Iterable[_EvidenceRecord]:
    """Yield scalar-bearing JSON objects with JSON-path provenance."""
    root = json.loads(path.read_text(encoding="utf-8-sig"))
    records: List[_EvidenceRecord] = []

    def visit(node: object, node_path: str, context: Mapping[str, str]) -> None:
        if isinstance(node, dict):
            scalars = {
                str(key): text
                for key, value in node.items()
                if (text := _as_text(value)) is not None
            }
            values = dict(context)
            values.update(scalars)
            if scalars:
                records.append(
                    _EvidenceRecord(
                        evidence_id=evidence_id,
                        file_path=file_path,
                        source_reference=node_path,
                        values=tuple(values.items()),
                        source_captured_at=(
                            scalars.get("captured_at")
                            or scalars.get("exported_at")
                            or context.get("captured_at")
                            or context.get("exported_at")
                        ),
                    )
                )
            child_context = dict(context)
            for key, value in scalars.items():
                if key.casefold() in {
                    "captured_at",
                    "exported_at",
                    "system",
                    "source",
                    "data_store",
                    "collection",
                }:
                    child_context[key] = value
            for key, value in node.items():
                if isinstance(value, (dict, list)):
                    visit(value, f"{node_path}.{key}", child_context)
        elif isinstance(node, list):
            for index, value in enumerate(node):
                visit(value, f"{node_path}[{index}]", context)

    visit(root, "$", {})
    return records


def _key_value_pairs(line: str) -> Tuple[Tuple[str, str], ...]:
    """Parse logfmt-like key=value tokens while preserving the original line."""
    pairs = []
    for match in re.finditer(
        r"(?<![\w])([A-Za-z_][A-Za-z0-9_.-]*)=(\"[^\"]*\"|'[^']*'|\S+)",
        line,
    ):
        value = match.group(2).strip("\"'")
        pairs.append((match.group(1), value))
    pairs.append(("raw_text", line))
    return tuple(pairs)


def _text_records(
    path: Path,
    file_path: str,
    evidence_id: Optional[str],
    is_log: bool,
) -> Iterable[_EvidenceRecord]:
    """Yield line-based records from log or plain-text evidence."""
    with path.open("r", encoding="utf-8-sig", errors="replace") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            if is_log:
                values = list(_key_value_pairs(line))
            else:
                values = [("raw_text", line)]
                fields = [part.strip() for part in line.strip(" -").split("|")]
                if len(fields) >= 5 and _parse_datetime(fields[0]) is not None:
                    values.extend(
                        (
                            ("timestamp", fields[0]),
                            ("system_id", fields[1]),
                            ("resource_id", fields[2]),
                            ("record_type", fields[3]),
                            ("result", fields[4]),
                        )
                    )
                    if len(fields) >= 6:
                        values.append(("email", fields[5]))
            timestamp_match = re.search(
                r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
                r"(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\b",
                line,
            )
            if timestamp_match:
                values.append(("timestamp", timestamp_match.group(0)))
            yield _EvidenceRecord(
                evidence_id=evidence_id,
                file_path=file_path,
                source_reference=f"line={line_number}",
                values=tuple(values),
                source_captured_at=None,
            )


def _sql_records(
    path: Path, file_path: str, evidence_id: Optional[str]
) -> Iterable[_EvidenceRecord]:
    """Read SQLite-compatible SQL snapshots in an isolated in-memory database."""
    script = path.read_text(encoding="utf-8-sig", errors="replace")
    captured_match = re.search(
        r"(?im)^\s*--\s*Captured at:\s*"
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
        r"(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)",
        script,
    )
    source_captured_at = captured_match.group(1) if captured_match else None
    connection = sqlite3.connect(":memory:")

    def authorize(
        action: int,
        argument_one: Optional[str],
        argument_two: Optional[str],
        database_name: Optional[str],
        trigger_name: Optional[str],
    ) -> int:
        permitted = {
            sqlite3.SQLITE_CREATE_TABLE,
            sqlite3.SQLITE_INSERT,
            sqlite3.SQLITE_TRANSACTION,
            sqlite3.SQLITE_SELECT,
            sqlite3.SQLITE_READ,
        }
        if database_name not in (None, "main", "temp") or trigger_name is not None:
            return sqlite3.SQLITE_DENY
        if action in permitted:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_UPDATE and argument_one == "sqlite_master":
            return sqlite3.SQLITE_OK
        if action in {sqlite3.SQLITE_CREATE_INDEX, sqlite3.SQLITE_REINDEX}:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_FUNCTION and argument_two == "json_valid":
            return sqlite3.SQLITE_OK
        if (
            action == sqlite3.SQLITE_PRAGMA
            and argument_one == "foreign_keys"
            and argument_two in (None, "ON", "1")
        ):
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY

    try:
        connection.set_authorizer(authorize)
        connection.executescript(script)
        connection.set_authorizer(None)
        tables = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
        ).fetchall()
        for (table_name,) in tables:
            columns = [
                row[1]
                for row in connection.execute(
                    f'PRAGMA table_info("{table_name.replace(chr(34), chr(34) * 2)}")'
                )
            ]
            quoted_table = table_name.replace('"', '""')
            rows = connection.execute(
                f'SELECT * FROM "{quoted_table}"'
            ).fetchall()
            for row_number, row in enumerate(rows, start=1):
                values = tuple(
                    (column, text)
                    for column, value in zip(columns, row)
                    if (text := _as_text(value)) is not None
                )
                yield _EvidenceRecord(
                    evidence_id=evidence_id,
                    file_path=file_path,
                    source_reference=f"table={table_name},row={row_number}",
                    values=values,
                    source_captured_at=source_captured_at,
                )
    finally:
        connection.close()


def _pdf_records(
    path: Path, file_path: str, evidence_id: Optional[str]
) -> List[_EvidenceRecord]:
    """Extract embedded PDF text, retaining page numbers as source references."""
    try:
        from pypdf import PdfReader
        from pypdf.errors import PdfReadError
    except ImportError as error:
        raise ImportError("pypdf is not installed; PDF text cannot be extracted.") from error

    try:
        reader = PdfReader(path, strict=False)
        if reader.is_encrypted:
            raise ValueError("PDF is encrypted and no password was supplied.")
        records = []
        for page_number, page in enumerate(reader.pages, start=1):
            text = page.extract_text() or ""
            if text.strip():
                records.append(
                    _EvidenceRecord(
                        evidence_id=evidence_id,
                        file_path=file_path,
                        source_reference=f"page={page_number}",
                        values=(("raw_text", text),),
                        source_captured_at=None,
                    )
                )
        if not records:
            raise ValueError(
                "PDF contains no extractable text; scanned-page OCR is not "
                "performed by the PDF text extractor."
            )
        return records
    except PdfReadError as error:
        raise ValueError(f"PDF could not be read: {error}") from error


async def _recognize_image(path: Path) -> str:
    """Run local Windows OCR using the installed user-profile language packs."""
    from winrt.windows.graphics.imaging import BitmapDecoder
    from winrt.windows.media.ocr import OcrEngine
    from winrt.windows.storage import FileAccessMode, StorageFile

    engine = OcrEngine.try_create_from_user_profile_languages()
    if engine is None:
        raise RuntimeError(
            "Windows OCR has no available recognition language for this user."
        )
    storage_file = await StorageFile.get_file_from_path_async(str(path))
    stream = await storage_file.open_async(FileAccessMode.READ)
    try:
        decoder = await BitmapDecoder.create_async(stream)
        bitmap = await decoder.get_software_bitmap_async()
        if max(bitmap.pixel_width, bitmap.pixel_height) > OcrEngine.max_image_dimension:
            raise ValueError(
                "Image exceeds the Windows OCR engine's maximum dimension."
            )
        result = await engine.recognize_async(bitmap)
        if not result.text.strip():
            raise ValueError("Windows OCR returned no readable text.")
        return result.text
    finally:
        stream.close()


def _image_records(
    path: Path, file_path: str, evidence_id: Optional[str]
) -> List[_EvidenceRecord]:
    """OCR image text locally; fail explicitly when OCR is unavailable."""
    try:
        text = asyncio.run(_recognize_image(path))
    except ImportError as error:
        raise ImportError(
            "PyWinRT Windows OCR packages are unavailable on this system."
        ) from error
    except RuntimeError as error:
        raise RuntimeError(f"Local image OCR is unavailable: {error}") from error
    except (OSError, ValueError) as error:
        raise ValueError(f"Local image OCR failed: {error}") from error
    return [
        _EvidenceRecord(
            evidence_id=evidence_id,
            file_path=file_path,
            source_reference="image=1",
            values=(("raw_text", text),),
            source_captured_at=None,
        )
    ]


def _manifest_timestamp(entry: Mapping[str, str]) -> Optional[str]:
    """Return the manifest capture time when it is present."""
    return entry.get("captured_at") or None


class EvidenceAnalyzer:
    """Parse available evidence once, then link records to resolved identities."""

    def __init__(self, dataset: Dataset) -> None:
        self.dataset = dataset
        self.records: List[_EvidenceRecord] = []
        self.gaps: List[EvidenceGap] = []
        self._value_index: Dict[str, Set[int]] = {}
        self._resource_index: Dict[str, Set[int]] = {}
        self.manifest_by_path: Dict[str, Mapping[str, str]] = {
            entry["file_path"]: entry for entry in dataset.evidence_files
        }
        self._load_evidence()
        self._build_indexes()

    def _load_evidence(self) -> None:
        """Load parsable records and record explicit extraction limitations."""
        dataset_dir = self.dataset.project_root / "dataset"
        for entry in self.dataset.evidence_files:
            file_path = entry["file_path"]
            evidence_id = entry.get("file_id") or None
            path = (dataset_dir / file_path).resolve()
            evidence_root = (dataset_dir / "evidence").resolve()
            try:
                path.relative_to(evidence_root)
            except ValueError:
                self.gaps.append(
                    EvidenceGap(
                        evidence_id, file_path, "Manifest path is outside dataset/evidence."
                    )
                )
                continue
            if not path.is_file():
                self.gaps.append(
                    EvidenceGap(evidence_id, file_path, "Manifest file is missing.")
                )
                continue

            extension = path.suffix.casefold()
            try:
                if extension == ".json":
                    parsed = _json_records(path, file_path, evidence_id)
                elif extension == ".sql":
                    parsed = _sql_records(path, file_path, evidence_id)
                elif extension == ".log":
                    parsed = _text_records(path, file_path, evidence_id, True)
                elif extension == ".txt":
                    parsed = _text_records(path, file_path, evidence_id, False)
                elif extension == ".pdf":
                    parsed = _pdf_records(path, file_path, evidence_id)
                elif extension in {".png", ".jpg", ".jpeg"}:
                    parsed = _image_records(path, file_path, evidence_id)
                else:
                    self.gaps.append(
                        EvidenceGap(
                            evidence_id,
                            file_path,
                            f"Unsupported evidence file format: {extension or '(none)'}.",
                        )
                    )
                    continue
                self.records.extend(parsed)
            except (
                OSError,
                UnicodeError,
                ValueError,
                RuntimeError,
                ImportError,
                csv.Error,
                sqlite3.Error,
            ) as error:
                LOGGER.warning("Could not parse evidence file %s: %s", file_path, error)
                self.gaps.append(
                    EvidenceGap(
                        evidence_id,
                        file_path,
                        f"Evidence could not be parsed: {error}",
                    )
                )

        for activity in self.dataset.system_activity:
            activity_id = activity.get("activity_id") or "unknown"
            self.records.append(
                _EvidenceRecord(
                    evidence_id=None,
                    file_path="system_activity.csv",
                    source_reference=f"activity_id={activity_id}",
                    values=tuple(
                        (key, value)
                        for key, value in activity.items()
                        if value is not None and value.strip()
                    ),
                    source_captured_at=None,
                )
            )

    def _build_indexes(self) -> None:
        """Index exact scalar identifiers and explicit resource-id fields."""
        for index, record in enumerate(self.records):
            for key, value in record.values:
                normalized = _normalize(value)
                if normalized and normalized != "null":
                    self._value_index.setdefault(normalized, set()).add(index)
                field = _field_name(key)
                if field in RESOURCE_FIELDS and normalized and normalized != "null":
                    self._resource_index.setdefault(normalized, set()).add(index)
                if field in TEXT_FIELDS or field == "raw_text" or "details" in field:
                    for token in IDENTIFIER_TOKEN_PATTERN.findall(value):
                        token = token.strip(" ,;:()[]{}")
                        if token:
                            self._value_index.setdefault(
                                _normalize(token), set()
                            ).add(index)

    @staticmethod
    def _candidate_identifiers(
        resolution: IdentityResolution,
    ) -> Dict[str, str]:
        """Build a normalized set of identifiers explicitly supplied by resolver."""
        identifiers: Dict[str, str] = {}
        if resolution.requested_identifier:
            value = resolution.requested_identifier.strip()
            if value:
                identifiers.setdefault(_normalize(value), value)
        for candidate in resolution.candidates:
            identifiers.setdefault(_normalize(candidate.user_id), candidate.user_id)
            for identifier in candidate.identifiers:
                value = identifier.value.strip()
                if value:
                    identifiers.setdefault(_normalize(value), value)
        return identifiers

    @staticmethod
    def _resource_ids(record: _EvidenceRecord) -> Tuple[str, ...]:
        """Extract only resource identifiers from explicitly resource-named fields."""
        return tuple(
            dict.fromkeys(
                value.strip()
                for key, value in record.values
                if (
                    _field_name(key) in RESOURCE_FIELDS
                    and value.strip()
                    and value.strip().casefold() != "null"
                )
            )
        )

    @staticmethod
    def _value_for(
        record: _EvidenceRecord, field_names: Set[str]
    ) -> Optional[str]:
        """Get the first nonblank value whose normalized field name is requested."""
        for key, value in record.values:
            if (
                _field_name(key) in field_names
                and value.strip()
                and value.strip().casefold() != "null"
            ):
                return value.strip()
        return None

    @staticmethod
    def _timestamp(record: _EvidenceRecord) -> Tuple[Optional[str], Optional[str]]:
        """Return only an explicit event/observation timestamp.

        File capture, export, creation, and update times are retained separately
        as source metadata and are never substituted for an event timestamp.
        """
        ordered_fields = (
            "event_time",
            "event_timestamp",
            "occurred_at",
            "observed_at",
            "recorded_at",
            "timestamp",
        )
        for field_name in ordered_fields:
            value = EvidenceAnalyzer._value_for(record, {field_name})
            if value is not None:
                return value, field_name
        return None, None

    @staticmethod
    def _finding_types(record: _EvidenceRecord) -> Tuple[str, ...]:
        """Describe operations and data states explicitly present in the record."""
        types = set()
        descriptive_fields = {
            "event",
            "event_name",
            "event_type",
            "operation",
            "action",
            "record_type",
            "details",
            "message",
            "raw_text",
            "description",
        }
        operation = " ".join(
            value.casefold()
            for key, value in record.values
            if _field_name(key) in descriptive_fields
        )
        state = " ".join(
            value.casefold()
            for key, value in record.values
            if _field_name(key)
            in {
                "account_status",
                "deletion_status",
                "lookup_status",
                "lookup_result",
                "record_state",
                "state",
                "status",
                "result",
            }
        )
        system_context = " ".join(
            value.casefold()
            for key, value in record.values
            if _field_name(key)
            in {
                "system",
                "system_id",
                "service",
                "data_store",
                "source_system",
                "target_system",
                "origin_system",
            }
        )
        field_context = " ".join(
            key.casefold() for key, _ in record.values
        )
        source_context = (
            f"{record.file_path} {record.source_reference} {field_context}"
        ).casefold()
        combined = f"{operation} {state} {source_context}".replace("_", " ")
        if re.search(r"\b(delete|deleted|deletion|erase|erased|purge|purged)\b", combined):
            types.add("DELETION")
        if re.search(r"\b(redact|redacted|redaction)\b", combined):
            types.add("REDACTION")
        if re.search(r"\b(anonymi[sz]e|anonymi[sz]ed|de[- ]?identif)\b", combined):
            types.add("ANONYMIZATION")
        if re.search(r"\b(export|exported|exporting)\b", combined):
            types.add("EXPORT")
        if re.search(r"\b(backup|backups|archive)\b", f"{combined} {system_context}"):
            types.add("BACKUP")
        if re.search(r"\b(restore|restored|repopulate|repopulated|recovery)\b", combined):
            types.add("RESTORE")
        if re.search(
            r"\b(replica|replicated|replication|failover)\b",
            f"{combined} {system_context}",
        ):
            types.add("REPLICA")
        if re.search(r"\b(sync|synchroni[sz]e|index|refresh|process|delivery|connector)\b", combined):
            types.add("ACTIVE_PROCESSING")
        if re.search(
            r"\b(found|active|present|retained|exists|stored|record exists)\b",
            combined,
        ):
            types.add("CONTINUED_STORAGE")
        if any(
            _field_name(key) in {"target_system", "downstream_system"}
            for key, _ in record.values
        ):
            types.add("DOWNSTREAM_SYSTEM")
        if not types:
            types.add("OBSERVATION")
        return tuple(sorted(types))

    @staticmethod
    def _temporal_relation(
        timestamp: Optional[str],
        audit_at: Optional[str],
        timestamp_field: Optional[str],
    ) -> Tuple[str, bool]:
        """Compare a record time with audit_at without promoting later captures."""
        record_time = _parse_datetime(timestamp)
        audit_time = _parse_datetime(audit_at)
        if record_time is None or audit_time is None:
            return UNKNOWN_TIME, False
        if record_time < audit_time:
            relation = PRE_AUDIT
        elif record_time == audit_time:
            relation = AT_AUDIT
        else:
            relation = POST_AUDIT
        if relation == POST_AUDIT:
            return relation, False
        # The audit boundary is inclusive: an observation exactly at audit_at
        # is considered available as of that audit instant.
        event_time_is_explicit = timestamp_field in EVENT_TIME_FIELDS
        return relation, event_time_is_explicit

    @staticmethod
    def _resource_link_is_as_of_audit(
        record: _EvidenceRecord,
        audit_at: Optional[str],
        manifest: Mapping[str, str],
    ) -> bool:
        """Require an at-cutoff observation before using its identity/resource link."""
        cutoff = _parse_datetime(audit_at)
        if cutoff is None:
            return False

        timestamp, timestamp_field = EvidenceAnalyzer._timestamp(record)
        if timestamp is not None:
            event_time = _parse_datetime(timestamp)
            return (
                timestamp_field in EVENT_TIME_FIELDS
                and event_time is not None
                and event_time <= cutoff
            )

        captured_at = record.source_captured_at or _manifest_timestamp(manifest)
        capture_time = _parse_datetime(captured_at)
        return capture_time is not None and capture_time <= cutoff

    def analyze_request(
        self, request: Mapping[str, object], resolution: IdentityResolution
    ) -> RequestEvidenceAnalysis:
        """Extract direct and resource-linked evidence for one request."""
        case_id = request.get("case_id")
        if not isinstance(case_id, str):
            case_id = None
        requested_identifier = request.get("email")
        if not isinstance(requested_identifier, str):
            requested_identifier = None
        audit_at = request.get("audit_at")
        if not isinstance(audit_at, str):
            audit_at = None

        identifiers = self._candidate_identifiers(resolution)
        direct_records: Dict[int, Set[str]] = {}
        for normalized_identifier in identifiers:
            for record_index in self._value_index.get(normalized_identifier, ()):
                direct_records.setdefault(record_index, set()).add(normalized_identifier)

        linked_resources: Set[str] = set()
        for index in direct_records:
            record = self.records[index]
            manifest = self.manifest_by_path.get(record.file_path, {})
            if direct_records[index] and self._resource_link_is_as_of_audit(
                record, audit_at, manifest
            ):
                linked_resources.update(
                    _normalize(resource_id)
                    for resource_id in self._resource_ids(record)
                )

        provisional: List[EvidenceFinding] = []
        matched_resources_by_index: Dict[int, Set[str]] = {}
        for resource in linked_resources:
            for record_index in self._resource_index.get(resource, ()):
                matched_resources_by_index.setdefault(record_index, set()).add(
                    resource
                )

        matching_indexes = sorted(
            set(direct_records) | set(matched_resources_by_index)
        )
        for index in matching_indexes:
            record = self.records[index]
            direct = tuple(
                identifiers[key] for key in sorted(direct_records.get(index, set()))
            )
            matched_resources = tuple(
                sorted(matched_resources_by_index.get(index, set()))
            )
            if not direct and not matched_resources:
                continue

            timestamp, timestamp_field = self._timestamp(record)
            manifest = self.manifest_by_path.get(record.file_path, {})
            source_captured_at = (
                record.source_captured_at
                or _manifest_timestamp(manifest)
            )
            temporal_relation, event_at_or_before_audit = self._temporal_relation(
                timestamp, audit_at, timestamp_field
            )
            as_of_audit = event_at_or_before_audit

            system_id = self._value_for(
                record,
                {"system", "system_id", "service"},
            )
            source_system = self._value_for(
                record,
                {"source_system"},
            )
            target_system = self._value_for(
                record,
                {"target_system", "downstream_system"},
            )
            resource_id = self._value_for(record, RESOURCE_FIELDS)
            if resource_id is None and matched_resources:
                resource_id = sorted(matched_resources, key=str.casefold)[0]
            operation = self._value_for(
                record,
                {"event", "event_name", "event_type", "operation", "action", "record_type"},
            )
            result_or_state = self._value_for(
                record,
                {
                    "reported_result",
                    "result",
                    "state",
                    "status",
                    "account_status",
                    "deletion_status",
                    "lookup_result",
                    "lookup_status",
                },
            )
            explicit_state = self._explicit_state_value(record)
            data_category = self._value_for(
                record, {"data_category", "category", "record_type"}
            )
            policy_attributes = tuple(
                (key, value)
                for key, value in record.values
                if _field_name(key)
                in {
                    "retention_until",
                    "retention_reason",
                    "restore_allowed",
                    "http_status",
                    "status_code",
                    "rows",
                    "customer_reference",
                    "subject_reference",
                    "user_id",
                    "name",
                    "full_name",
                    "email",
                    "phone",
                    "email_hash",
                    "enabled",
                    "last_delivery_status",
                }
            )
            record_id = self._value_for(
                record, {"record_id", "audit_id", "activity_id"}
            )
            event_id = self._value_for(
                record, {"event_id", "trace_id", "request_id"}
            )
            provisional.append(
                EvidenceFinding(
                    case_id=case_id,
                    evidence_id=record.evidence_id,
                    file_path=record.file_path,
                    source_reference=record.source_reference,
                    record_id=record_id,
                    event_id=event_id,
                    timestamp=timestamp,
                    timestamp_field=timestamp_field,
                    source_captured_at=source_captured_at,
                    temporal_relation=temporal_relation,
                    as_of_audit=as_of_audit,
                    system_id=system_id,
                    source_system=source_system,
                    target_system=target_system,
                    resource_id=resource_id,
                    operation=operation,
                    result_or_state=result_or_state,
                    explicit_state=explicit_state,
                    finding_types=self._finding_types(record),
                    match_type=DIRECT if direct else INDIRECT,
                    matched_identifiers=(
                        direct
                        or tuple(
                            next(
                                (
                                    value
                                    for value in self._resource_ids(record)
                                    if _normalize(value) == resource
                                ),
                                resource,
                            )
                            for resource in matched_resources
                        )
                    ),
                    data_category=data_category,
                    policy_attributes=policy_attributes,
                )
            )

        findings = self._mark_conflicts(provisional)
        conflicts = self._conflicts(findings)
        return RequestEvidenceAnalysis(
            case_id=case_id,
            requested_identifier=requested_identifier,
            identity_status=resolution.status,
            findings=tuple(findings),
            gaps=tuple(self.gaps),
            conflicts=tuple(conflicts),
        )

    @staticmethod
    def _explicit_state_value(record: _EvidenceRecord) -> Optional[str]:
        """Find an actual state token without mistaking operation success."""
        state_fields = {
            "account_status",
            "deletion_status",
            "lookup_status",
            "lookup_result",
            "record_state",
            "state",
            "status",
            "result",
        }
        for key, value in record.values:
            if _field_name(key) not in state_fields:
                continue
            normalized = value.strip().upper().replace(" ", "_")
            if normalized in POSITIVE_STATES or normalized in NEGATIVE_STATES:
                return normalized
        return None

    @staticmethod
    def _explicit_state(record: EvidenceFinding) -> Optional[str]:
        """Normalize only explicit state values for cross-record conflict checks."""
        return record.explicit_state

    @classmethod
    def _mark_conflicts(
        cls, findings: Sequence[EvidenceFinding]
    ) -> List[EvidenceFinding]:
        """Attach references when the same resource has opposing explicit states."""
        by_resource_and_time: Dict[
            Tuple[str, datetime], List[Tuple[int, str]]
        ] = {}
        for index, finding in enumerate(findings):
            if finding.resource_id is None or not finding.as_of_audit:
                continue
            state = cls._explicit_state(finding)
            event_time = _parse_datetime(finding.timestamp)
            if state is not None and event_time is not None:
                key = (_normalize(finding.resource_id), event_time)
                by_resource_and_time.setdefault(key, []).append((index, state))

        conflicts_for_index: Dict[int, Set[str]] = {}
        for state_records in by_resource_and_time.values():
            positive = {
                index
                for index, state in state_records
                if state in POSITIVE_STATES
            }
            negative = {
                index
                for index, state in state_records
                if state in NEGATIVE_STATES
            }
            if not positive or not negative:
                continue
            references = {
                f"{findings[index].file_path}#{findings[index].source_reference}"
                for index in positive | negative
            }
            for index in positive | negative:
                conflicts_for_index.setdefault(index, set()).update(
                    references
                    - {
                        f"{findings[index].file_path}#"
                        f"{findings[index].source_reference}"
                    }
                )

        return [
            replace(
                finding,
                conflict_references=tuple(sorted(conflicts_for_index.get(index, set()))),
            )
            for index, finding in enumerate(findings)
        ]

    @classmethod
    def _conflicts(
        cls, findings: Sequence[EvidenceFinding]
    ) -> List[EvidenceConflict]:
        """Create case-level conflict summaries for marked findings."""
        conflicts = []
        grouped: Dict[Tuple[str, datetime], List[EvidenceFinding]] = {}
        for finding in findings:
            event_time = _parse_datetime(finding.timestamp)
            if (
                finding.resource_id
                and finding.conflict_references
                and event_time is not None
            ):
                grouped.setdefault(
                    (_normalize(finding.resource_id), event_time), []
                ).append(finding)
        for (_, event_time), group in sorted(
            grouped.items(), key=lambda item: (item[0][0], item[0][1])
        ):
            states = tuple(
                sorted(
                    {
                        state
                        for finding in group
                        if (state := cls._explicit_state(finding)) is not None
                    }
                )
            )
            references = tuple(
                sorted(
                    {
                        f"{finding.file_path}#{finding.source_reference}"
                        for finding in group
                    }
                )
            )
            conflicts.append(
                EvidenceConflict(
                    resource_id=group[0].resource_id or "",
                    timestamp=event_time.isoformat().replace("+00:00", "Z"),
                    evidence_references=references,
                    states=states,
                    explanation=(
                        "Evidence records report opposing explicit states for "
                        "the same resource at or before audit_at."
                    ),
                )
            )
        return conflicts


def analyze_request(
    dataset: Dataset,
    request: Mapping[str, object],
    resolution: IdentityResolution,
) -> RequestEvidenceAnalysis:
    """Convenience API for analyzing one request against dataset evidence."""
    return EvidenceAnalyzer(dataset).analyze_request(request, resolution)


def analyze_all_requests(
    dataset: Dataset,
    resolutions: Optional[Sequence[IdentityResolution]] = None,
) -> Tuple[RequestEvidenceAnalysis, ...]:
    """Analyze all requests while parsing the evidence corpus only once."""
    if resolutions is None:
        if __package__:
            from .identity_resolver import resolve_all_requests
        else:
            from identity_resolver import resolve_all_requests
        resolutions = resolve_all_requests(dataset)
    if len(resolutions) != len(dataset.deletion_requests):
        raise ValueError(
            "The number of identity resolutions must match deletion requests: "
            f"{len(resolutions)} != {len(dataset.deletion_requests)}"
        )
    for request, resolution in zip(dataset.deletion_requests, resolutions):
        if request.get("case_id") != resolution.case_id:
            raise ValueError(
                "Identity resolutions must match deletion requests in order; "
                f"expected case_id {request.get('case_id')!r}, "
                f"found {resolution.case_id!r}"
            )
    analyzer = EvidenceAnalyzer(dataset)
    return tuple(
        analyzer.analyze_request(request, resolution)
        for request, resolution in zip(dataset.deletion_requests, resolutions)
    )
