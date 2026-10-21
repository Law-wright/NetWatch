"""Local SQLite storage for packet metadata and security events.

The database lives under ``data/`` unless ``NETWATCH_DB`` points at another
``.db`` file. Rows are the same records the dashboard already uses. Payloads,
command lines, and free-text log messages are not columns.
"""

from __future__ import annotations

import logging
import os
import sqlite3
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import pandas as pd

from core.log_analyzer import events_to_frame
from core.models import EVENT_COLUMNS, PACKET_COLUMNS, PacketRecord, SecurityEvent
from core.sample_data import records_to_frame

logger = logging.getLogger(__name__)

_PACKET_KINDS = frozenset({"simulated", "imported"})
_EVENT_KINDS = frozenset({"simulated", "local"})
_DATASETS = frozenset({"packets", "events"})


@dataclass(frozen=True)
class DatasetMeta:
    """Where the current packet or event set came from."""

    dataset: str
    source_kind: str
    source_name: str
    note: str | None


def resolve_database_path(path: Path | str | None = None) -> Path:
    """Return the SQLite file for this process.

    An explicit argument wins, then ``NETWATCH_DB``, then ``data/netwatch.db``
    beside the repository. The path must use a ``.db`` suffix.
    """
    if path is not None:
        candidate = Path(path)
    else:
        override = os.environ.get("NETWATCH_DB", "").strip()
        if override:
            candidate = Path(override).expanduser()
        else:
            candidate = Path(__file__).resolve().parent.parent / "data" / "netwatch.db"
    if candidate.suffix.lower() != ".db":
        raise ValueError("The database path must be a .db file.")
    return candidate


def _meta_text(value: str, field_name: str, max_length: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be text.")
    stripped = value.strip()
    if not stripped or len(stripped) > max_length or any(ord(character) < 32 for character in stripped):
        raise ValueError(f"{field_name} must be a single line of text.")
    return stripped


def _optional_note(value: str | None) -> str | None:
    if value is None:
        return None
    return _meta_text(value, "note", 500)


def _cell(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, pd.Timestamp):
        return value.to_pydatetime()
    if isinstance(value, str):
        return value
    try:
        if pd.isna(value):
            return None
    except TypeError:
        return value
    return value


def _as_datetime(value: Any) -> datetime:
    taken = _cell(value)
    if isinstance(taken, datetime):
        parsed = taken
    elif isinstance(taken, str):
        parsed = datetime.fromisoformat(taken)
    else:
        raise ValueError("timestamp must be a datetime.")
    if parsed.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware UTC.")
    return parsed.astimezone(timezone.utc)


def _as_optional_datetime(value: Any) -> datetime | None:
    if _cell(value) is None:
        return None
    return _as_datetime(value)


def _as_int(value: Any) -> int | None:
    taken = _cell(value)
    if taken is None:
        return None
    if isinstance(taken, bool):
        raise ValueError("Expected an integer.")
    return int(taken)


def _as_text(value: Any) -> str | None:
    taken = _cell(value)
    if taken is None:
        return None
    return str(taken)


def _packet_from_mapping(row: Mapping[str, Any]) -> PacketRecord:
    return PacketRecord(
        timestamp=_as_datetime(row["timestamp"]),
        src_ip=str(_cell(row["src_ip"])),
        dst_ip=str(_cell(row["dst_ip"])),
        protocol=str(_cell(row["protocol"])),
        src_port=_as_int(row["src_port"]),
        dst_port=_as_int(row["dst_port"]),
        packet_length=int(_cell(row["packet_length"])),
        ip_version=int(_cell(row["ip_version"])),
        tcp_flags=_as_text(row["tcp_flags"]),
        import_id=str(_cell(row["import_id"])),
        is_simulated=bool(_cell(row["is_simulated"])),
    )


def _event_from_mapping(row: Mapping[str, Any]) -> SecurityEvent:
    return SecurityEvent(
        event_uid=str(_cell(row["event_uid"])),
        timestamp=_as_datetime(row["timestamp"]),
        channel=str(_cell(row["channel"])),
        provider=str(_cell(row["provider"])),
        event_id=int(_cell(row["event_id"])),
        account_name=_as_text(row["account_name"]),
        src_ip=_as_text(row["src_ip"]),
        dst_ip=_as_text(row["dst_ip"]),
        src_port=_as_int(row["src_port"]),
        dst_port=_as_int(row["dst_port"]),
        process_name=_as_text(row["process_name"]),
        process_id=_as_int(row["process_id"]),
        parent_process=_as_text(row["parent_process"]),
        logon_type=_as_int(row["logon_type"]),
        outcome=_as_text(row["outcome"]),
        message=str(_cell(row["message"])),
        is_simulated=bool(_cell(row["is_simulated"])),
        record_id=_as_int(row["record_id"]),
        ingested_at=_as_optional_datetime(row["ingested_at"]),
    )


def _rows_from_frame(frame: pd.DataFrame, columns: Sequence[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index in range(len(frame)):
        rows.append({column: frame.iloc[index][column] for column in columns})
    return rows


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat()


class NetWatchStore:
    """One SQLite file holding the active packet set and the active event set."""

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = resolve_database_path(path)

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=5)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA journal_mode = WAL")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        """Create tables if they are not already there."""
        with self.connection() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    src_port INTEGER,
                    dst_port INTEGER,
                    packet_length INTEGER NOT NULL,
                    ip_version INTEGER NOT NULL,
                    tcp_flags TEXT,
                    import_id TEXT NOT NULL,
                    is_simulated INTEGER NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY,
                    event_uid TEXT NOT NULL UNIQUE,
                    timestamp TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    event_id INTEGER NOT NULL,
                    account_name TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    process_name TEXT,
                    process_id INTEGER,
                    parent_process TEXT,
                    logon_type INTEGER,
                    outcome TEXT,
                    message TEXT NOT NULL,
                    is_simulated INTEGER NOT NULL,
                    record_id INTEGER,
                    ingested_at TEXT
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS dataset_meta (
                    dataset TEXT PRIMARY KEY,
                    source_kind TEXT NOT NULL,
                    source_name TEXT NOT NULL,
                    note TEXT
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets (timestamp)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events (timestamp)"
            )

    def replace_packets(
        self,
        frame: pd.DataFrame,
        *,
        source_kind: str,
        source_name: str,
        note: str | None,
    ) -> int:
        """Replace the saved packet set with ``frame``."""
        if source_kind not in _PACKET_KINDS:
            raise ValueError("Packet source is not supported.")
        name = _meta_text(source_name, "source_name", 120)
        stored_note = _optional_note(note)
        records = [_packet_from_mapping(row) for row in _rows_from_frame(frame, PACKET_COLUMNS)]
        self.initialize()
        with self.connection() as connection:
            connection.execute("DELETE FROM packets")
            connection.executemany(
                """
                INSERT INTO packets (
                    timestamp, src_ip, dst_ip, protocol, src_port, dst_port,
                    packet_length, ip_version, tcp_flags, import_id, is_simulated
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        _iso(record.timestamp),
                        record.src_ip,
                        record.dst_ip,
                        record.protocol,
                        record.src_port,
                        record.dst_port,
                        record.packet_length,
                        record.ip_version,
                        record.tcp_flags,
                        record.import_id,
                        int(record.is_simulated),
                    )
                    for record in records
                ],
            )
            _write_meta(connection, "packets", source_kind, name, stored_note)
        logger.info("Saved %s packets source %s", len(records), source_kind)
        return len(records)

    def load_packets(self) -> pd.DataFrame:
        """Return the saved packet set. Invalid rows are skipped."""
        self.initialize()
        with self.connection() as connection:
            fetched = connection.execute(
                """
                SELECT timestamp, src_ip, dst_ip, protocol, src_port, dst_port,
                       packet_length, ip_version, tcp_flags, import_id, is_simulated
                FROM packets
                ORDER BY timestamp, id
                """
            ).fetchall()
        records: list[PacketRecord] = []
        for index, row in enumerate(fetched):
            try:
                records.append(_packet_from_mapping(row))
            except (TypeError, ValueError) as exc:
                logger.warning("Skipped stored packet row %s: %s", index, str(exc)[:200])
        return records_to_frame(records)

    def replace_events(
        self,
        frame: pd.DataFrame,
        *,
        source_kind: str,
        source_name: str,
        note: str | None,
    ) -> int:
        """Replace the saved event set with ``frame``."""
        if source_kind not in _EVENT_KINDS:
            raise ValueError("Event source is not supported.")
        name = _meta_text(source_name, "source_name", 120)
        stored_note = _optional_note(note)
        records = [_event_from_mapping(row) for row in _rows_from_frame(frame, EVENT_COLUMNS)]
        unique: list[SecurityEvent] = []
        seen: set[str] = set()
        for record in records:
            if record.event_uid in seen:
                continue
            seen.add(record.event_uid)
            unique.append(record)
        if len(unique) != len(records):
            logger.warning(
                "Skipped %s duplicate event rows before saving.",
                len(records) - len(unique),
            )
        self.initialize()
        with self.connection() as connection:
            connection.execute("DELETE FROM security_events")
            connection.executemany(
                """
                INSERT INTO security_events (
                    event_uid, timestamp, channel, provider, event_id, account_name,
                    src_ip, dst_ip, src_port, dst_port, process_name, process_id,
                    parent_process, logon_type, outcome, message, is_simulated,
                    record_id, ingested_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        record.event_uid,
                        _iso(record.timestamp),
                        record.channel,
                        record.provider,
                        record.event_id,
                        record.account_name,
                        record.src_ip,
                        record.dst_ip,
                        record.src_port,
                        record.dst_port,
                        record.process_name,
                        record.process_id,
                        record.parent_process,
                        record.logon_type,
                        record.outcome,
                        record.message,
                        int(record.is_simulated),
                        record.record_id,
                        _iso(record.ingested_at),
                    )
                    for record in unique
                ],
            )
            _write_meta(connection, "events", source_kind, name, stored_note)
        logger.info("Saved %s events source %s", len(unique), source_kind)
        return len(unique)

    def load_events(self) -> pd.DataFrame:
        """Return the saved event set. Invalid rows are skipped."""
        self.initialize()
        with self.connection() as connection:
            fetched = connection.execute(
                """
                SELECT event_uid, timestamp, channel, provider, event_id, account_name,
                       src_ip, dst_ip, src_port, dst_port, process_name, process_id,
                       parent_process, logon_type, outcome, message, is_simulated,
                       record_id, ingested_at
                FROM security_events
                ORDER BY timestamp, event_uid
                """
            ).fetchall()
        records: list[SecurityEvent] = []
        for index, row in enumerate(fetched):
            try:
                records.append(_event_from_mapping(row))
            except (TypeError, ValueError) as exc:
                logger.warning("Skipped stored event row %s: %s", index, str(exc)[:200])
        return events_to_frame(records)

    def load_meta(self, dataset: str) -> DatasetMeta | None:
        """Return the saved label for ``packets`` or ``events``."""
        if dataset not in _DATASETS:
            raise ValueError("Dataset is not supported.")
        self.initialize()
        with self.connection() as connection:
            row = connection.execute(
                """
                SELECT dataset, source_kind, source_name, note
                FROM dataset_meta
                WHERE dataset = ?
                """,
                (dataset,),
            ).fetchone()
        if row is None:
            return None
        return DatasetMeta(
            dataset=str(row["dataset"]),
            source_kind=str(row["source_kind"]),
            source_name=str(row["source_name"]),
            note=None if row["note"] is None else str(row["note"]),
        )


def _write_meta(
    connection: sqlite3.Connection,
    dataset: str,
    source_kind: str,
    source_name: str,
    note: str | None,
) -> None:
    connection.execute(
        """
        INSERT INTO dataset_meta (dataset, source_kind, source_name, note)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(dataset) DO UPDATE SET
            source_kind = excluded.source_kind,
            source_name = excluded.source_name,
            note = excluded.note
        """,
        (dataset, source_kind, source_name, note),
    )
