"""Tests for evidence reconstruction, alert status updates, and Investigation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from core.database import NetWatchStore
from core.detection_engine import default_rules, evaluate, normalize_parameters
from core.investigation import RELATED_ROW_LIMIT, related_evidence
from core.log_analyzer import (
    FAILED_BURST_ACCOUNT,
    FAILED_BURST_COUNT,
    FAILED_BURST_SOURCE,
    events_to_frame,
    generate_event_frame,
)
from core.models import DetectionRule, PacketRecord, SecurityAlert
from core.sample_data import (
    SCAN_DESTINATION,
    SCAN_PORT_COUNT,
    SCAN_PORT_START,
    SCAN_SOURCE,
    VOLUME_PACKET_COUNT,
    generate_packet_frame,
    records_to_frame,
)
from tests.test_security_events import _visible_text

_START = datetime(2026, 1, 15, 14, 0, tzinfo=timezone.utc)
_EVALUATED = datetime(2026, 1, 15, 16, 0, tzinfo=timezone.utc)


def _seeded_alerts() -> tuple[list[SecurityAlert], object, object]:
    packets = generate_packet_frame()
    events = generate_event_frame()
    alerts = evaluate(packets, events, list(default_rules()), evaluated_at=_EVALUATED)
    return alerts, packets, events


def _by_rule(alerts: list[SecurityAlert], rule_key: str) -> SecurityAlert:
    matches = [alert for alert in alerts if alert.rule_key == rule_key]
    assert matches, f"expected a finding for {rule_key}"
    return matches[0]


def test_related_evidence_for_seeded_findings() -> None:
    alerts, packets, events = _seeded_alerts()

    failed = related_evidence(_by_rule(alerts, "failed_auth"), packets, events)
    assert failed.event_total == FAILED_BURST_COUNT
    assert failed.packet_total == 0
    assert set(failed.events["account_name"]) == {FAILED_BURST_ACCOUNT}
    assert set(failed.events["src_ip"]) == {FAILED_BURST_SOURCE}
    assert failed.events["event_id"].eq(4625).all()

    scan = related_evidence(_by_rule(alerts, "possible_port_scan"), packets, events)
    assert scan.packet_total >= SCAN_PORT_COUNT
    assert scan.event_total == 0
    assert set(scan.packets["src_ip"]) == {SCAN_SOURCE}
    assert set(scan.packets["dst_ip"]) == {SCAN_DESTINATION}
    ports = set(int(port) for port in scan.packets["dst_port"].tolist())
    expected = set(range(SCAN_PORT_START, SCAN_PORT_START + SCAN_PORT_COUNT))
    assert expected <= ports

    volume = related_evidence(_by_rule(alerts, "volume_change"), packets, events)
    assert volume.packet_total >= VOLUME_PACKET_COUNT
    assert volume.event_total == 0


def test_related_evidence_for_watch_and_limit() -> None:
    packets = records_to_frame(
        [
            PacketRecord(
                timestamp=_START + timedelta(seconds=index),
                src_ip="192.168.1.10",
                dst_ip="192.0.2.10",
                protocol="TCP",
                src_port=50000 + index,
                dst_port=22,
                packet_length=60,
                ip_version=4,
                tcp_flags="ACK",
                import_id="unit",
                is_simulated=True,
            )
            for index in range(3)
        ]
    )
    events = events_to_frame([])
    rule = DetectionRule(
        rule_key="watch_001",
        name="SSH watch",
        description="Matching packets where destination port 22.",
        enabled=True,
        severity="low",
        parameters=normalize_parameters("watch_001", {"subject": "packet", "dst_port": 22}),
    )
    alert = evaluate(packets, events, [rule], evaluated_at=_EVALUATED)[0]
    related = related_evidence(alert, packets, events)
    assert related.packet_total == 3
    assert related.event_total == 0
    assert related.packets["dst_port"].eq(22).all()

    capped = related_evidence(alert, packets, events, limit=2)
    assert capped.packet_total == 3
    assert len(capped.packets) == 2
    assert capped.note is not None
    assert str(RELATED_ROW_LIMIT).isdigit()

    empty = related_evidence(
        SecurityAlert(
            alert_uid="a" + "0" * 32,
            created_at=_EVALUATED,
            rule_key="unknown_rule",
            severity="low",
            status="open",
            src_ip=None,
            dst_ip=None,
            title="Unknown",
            description="A rule without a related-row lookup.",
            first_seen=_START,
            last_seen=_START,
            evidence={},
        ),
        packets,
        events,
    )
    assert empty.packet_total == 0
    assert empty.event_total == 0
    assert empty.note is not None


def test_update_alert_status_roundtrip_and_survives_replace(tmp_path: Path) -> None:
    store = NetWatchStore(tmp_path / "netwatch.db")
    alerts, packets, events = _seeded_alerts()
    failed = _by_rule(alerts, "failed_auth")
    store.replace_alerts(alerts)
    store.update_alert_status(failed.alert_uid, "acknowledged")
    loaded = {alert.alert_uid: alert for alert in store.load_alerts()}
    assert loaded[failed.alert_uid].status == "acknowledged"

    with pytest.raises(ValueError, match="status"):
        store.update_alert_status(failed.alert_uid, "closed")
    with pytest.raises(ValueError, match="not stored"):
        store.update_alert_status("missing-alert", "dismissed")

    revised = evaluate(packets, events, list(default_rules()), evaluated_at=_EVALUATED)
    store.replace_alerts(revised)
    kept = {alert.alert_uid: alert for alert in store.load_alerts()}
    assert kept[failed.alert_uid].status == "acknowledged"


def test_investigation_page_reviews_evidence_and_saves_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("NETWATCH_DB", str(tmp_path / "netwatch.db"))
    app = AppTest.from_file(Path(__file__).resolve().parents[1] / "app.py", default_timeout=90)
    app.run()
    assert not app.exception
    app.switch_page("dashboard/investigation.py").run()
    assert not app.exception

    visible = _visible_text(app)
    for element in (*app.dataframe, *getattr(app, "selectbox", [])):
        visible += "\n" + str(getattr(element, "label", ""))
        value = getattr(element, "value", None)
        if hasattr(value, "to_csv"):
            visible += "\n" + value.to_csv(index=False)
        else:
            visible += "\n" + str(value)
    assert "Investigation." in visible
    assert "Repeated failed authentication" in visible
    assert "T1110.001 Password Guessing" in visible
    assert FAILED_BURST_ACCOUNT in visible or "Failed logon" in visible

    status_box = next(widget for widget in app.selectbox if widget.label == "Triage status")
    status_box.select("acknowledged")
    next(button for button in app.button if button.label == "Save status").click()
    app.run()
    assert not app.exception

    after = _visible_text(app)
    for element in (*app.dataframe, *getattr(app, "selectbox", []), *getattr(app, "metric", [])):
        after += "\n" + str(getattr(element, "label", ""))
        value = getattr(element, "value", None)
        if hasattr(value, "to_csv"):
            after += "\n" + value.to_csv(index=False)
        else:
            after += "\n" + str(value)
    assert "Acknowledged" in after

    store = NetWatchStore(tmp_path / "netwatch.db")
    statuses = {alert.title: alert.status for alert in store.load_alerts()}
    assert statuses.get("Repeated failed authentication") == "acknowledged"
