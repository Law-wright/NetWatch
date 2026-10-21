"""Dashboard tests for security events and reloading a saved packet set."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from core.database import NetWatchStore
from core.log_analyzer import ChannelRead, LocalLogRead
from core.models import SecurityEvent
from core.sample_data import generate_packet_frame


def _visible_text(app: object) -> str:
    parts: list[str] = []
    for collection_name in ("markdown", "caption", "error", "metric"):
        for root_name in ("", "sidebar"):
            root = getattr(app, root_name) if root_name else app
            collection = getattr(root, collection_name, None)
            if collection is None:
                continue
            for element in collection:
                parts.append(str(getattr(element, "value", "")))
                label = getattr(element, "label", "")
                if label:
                    parts.append(str(label))
    return "\n".join(parts)


def _local_read() -> LocalLogRead:
    moment = datetime(2026, 1, 15, 14, 8, tzinfo=timezone.utc)
    event = SecurityEvent(
        event_uid="system-42",
        timestamp=moment,
        channel="System",
        provider="Service Control Manager",
        event_id=7045,
        account_name="svc.backup",
        src_ip=None,
        dst_ip=None,
        src_port=None,
        dst_port=None,
        process_name="backup-job.exe",
        process_id=1200,
        parent_process=None,
        logon_type=None,
        outcome=None,
        message="Service installed.",
        is_simulated=False,
        record_id=42,
        ingested_at=moment,
    )
    return LocalLogRead(
        channels=(
            ChannelRead(
                "Security",
                "access_denied",
                0,
                0,
                "Access was denied. This channel was left unread.",
            ),
            ChannelRead("System", "ok", 1, 0, "Read completed.", events=(event,)),
            ChannelRead(
                "Application",
                "ok",
                0,
                3,
                "Read completed. Skipped 3 events outside the supported set.",
            ),
            ChannelRead(
                "Sysmon",
                "missing",
                0,
                0,
                "This channel is not available on this computer.",
            ),
        )
    )


def test_security_page_reads_channels_and_restores_the_fictional_set(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from streamlit.testing.v1 import AppTest

    import core.log_analyzer as log_analyzer

    monkeypatch.setenv("NETWATCH_DB", str(tmp_path / "netwatch.db"))
    monkeypatch.setattr(log_analyzer, "read_local_events", lambda *args, **kwargs: _local_read())
    app = AppTest.from_file(Path(__file__).resolve().parents[1] / "app.py", default_timeout=60)
    app.run()
    assert not app.exception

    app.switch_page("dashboard/security_events.py").run()
    assert not app.exception
    visible = _visible_text(app)
    assert "Simulated events." in visible
    events = app.session_state["events"]
    assert len(events) == 80
    assert events["is_simulated"].all()
    failures = events[(events["outcome"] == "failure") & (events["src_ip"] == "192.0.2.25")]
    assert len(failures) == 8

    read = next(button for button in app.button if button.label == "Read local Windows logs")
    read.click()
    app.run()
    assert not app.exception
    local = app.session_state["events"]
    assert len(local) == 1
    assert bool(local.iloc[0]["is_simulated"]) is False
    assert local.iloc[0]["event_uid"] == "system-42"
    after_read = _visible_text(app)
    assert "Local Windows logs." in after_read
    assert "Access was denied" in after_read
    assert "not available on this computer" in after_read

    restore = next(button for button in app.button if button.label == "Use simulated events")
    restore.click()
    app.run()
    assert not app.exception
    restored = app.session_state["events"]
    assert len(restored) == 80
    assert restored["is_simulated"].all()
    assert "Simulated events." in _visible_text(app)


def test_dashboard_reloads_a_saved_capture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from streamlit.testing.v1 import AppTest

    database = tmp_path / "netwatch.db"
    monkeypatch.setenv("NETWATCH_DB", str(database))
    frame = generate_packet_frame(count=1).copy()
    frame["is_simulated"] = False
    frame["import_id"] = "saved-office"
    NetWatchStore(database).replace_packets(
        frame,
        source_kind="imported",
        source_name="office.pcap",
        note="Parsed 1 packets.",
    )

    app = AppTest.from_file(Path(__file__).resolve().parents[1] / "app.py", default_timeout=60)
    app.run()
    assert not app.exception
    loaded = app.session_state["packets"]
    assert len(loaded) == 1
    assert app.session_state["data_source"] == "imported"
    assert app.session_state["source_name"] == "office.pcap"
    assert app.session_state["import_note"] == "Parsed 1 packets."
    assert bool(loaded.iloc[0]["is_simulated"]) is False
    assert "Offline capture" in _visible_text(app)
    assert any(button.label == "Use simulated data" for button in app.sidebar.button)
    assert len(NetWatchStore(database).load_packets()) == 1
