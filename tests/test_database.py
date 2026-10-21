"""Tests for the local SQLite packet and event store."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from core.database import NetWatchStore, resolve_database_path
from core.log_analyzer import events_to_frame, generate_event_frame, parse_event_xml
from core.sample_data import generate_packet_frame
from tests.test_log_analyzer import SECRET, _INGESTED, _event_xml


def test_database_path_must_be_a_db_file(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETWATCH_DB", "notes.txt")
    with pytest.raises(ValueError, match=r"\.db"):
        resolve_database_path()


def test_packet_and_event_roundtrip(tmp_path: Path) -> None:
    store = NetWatchStore(tmp_path / "netwatch.db")
    packets = generate_packet_frame(count=5)
    assert store.load_packets().empty
    assert store.replace_packets(
        packets,
        source_kind="simulated",
        source_name="Fictional demonstration set",
        note=None,
    ) == 5
    pd.testing.assert_frame_equal(store.load_packets(), packets)
    meta = store.load_meta("packets")
    assert meta is not None
    assert meta.source_kind == "simulated"
    assert meta.note is None

    events = generate_event_frame(count=8)
    store.replace_events(
        events,
        source_kind="simulated",
        source_name="Fictional demonstration set",
        note=None,
    )
    pd.testing.assert_frame_equal(store.load_events(), events)

    store.replace_packets(
        packets.iloc[:1].copy(),
        source_kind="imported",
        source_name="office.pcap",
        note="Parsed 1 packets.",
    )
    assert len(store.load_packets()) == 1
    reloaded = store.load_meta("packets")
    assert reloaded is not None
    assert reloaded.source_kind == "imported"
    assert reloaded.source_name == "office.pcap"
    assert reloaded.note == "Parsed 1 packets."


def test_imported_packet_flag_survives_reload(tmp_path: Path) -> None:
    store = NetWatchStore(tmp_path / "netwatch.db")
    frame = generate_packet_frame(count=1).copy()
    frame["is_simulated"] = False
    frame["import_id"] = "saved-office"
    store.replace_packets(frame, source_kind="imported", source_name="office.pcap", note=None)
    loaded = store.load_packets()
    assert len(loaded) == 1
    assert bool(loaded.iloc[0]["is_simulated"]) is False
    assert loaded.iloc[0]["import_id"] == "saved-office"
    with pytest.raises(ValueError):
        store.replace_packets(frame, source_kind="local", source_name="office.pcap", note=None)


def test_command_line_from_xml_is_not_written(tmp_path: Path) -> None:
    xml = _event_xml(
        event_id=4688,
        record_id=50,
        channel="Security",
        body=(
            "<Data Name='NewProcessName'>C:\\Windows\\Temp\\demo-agent.exe</Data>"
            f"<Data Name='CommandLine'>demo-agent.exe --password {SECRET}</Data>"
        ),
    )
    events, _skipped = parse_event_xml(xml, channel="Security", ingested_at=_INGESTED)
    store = NetWatchStore(tmp_path / "netwatch.db")
    store.replace_events(
        events_to_frame(events),
        source_kind="local",
        source_name="Local Windows logs",
        note="Kept 1 events from local Windows logs.",
    )
    blob = b"".join(path.read_bytes() for path in tmp_path.iterdir() if path.is_file())
    assert SECRET.encode() not in blob
    assert b"Process started." in blob
    loaded = store.load_events()
    assert loaded.iloc[0]["message"] == "Process started."
    assert bool(loaded.iloc[0]["is_simulated"]) is False


def test_duplicate_event_rows_are_collapsed(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    frame = generate_event_frame(count=8)
    doubled = pd.concat([frame, frame], ignore_index=True)
    store = NetWatchStore(tmp_path / "netwatch.db")
    with caplog.at_level("WARNING", logger="core.database"):
        stored = store.replace_events(
            doubled,
            source_kind="simulated",
            source_name="Fictional demonstration set",
            note=None,
        )
    assert stored == 8
    assert len(store.load_events()) == 8
    assert "duplicate event rows" in caplog.text
