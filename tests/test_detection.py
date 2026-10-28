"""Tests for detection rules, stored findings, and the Alerts page."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import pytest

from core.database import NetWatchStore
from core.detection_engine import (
    default_rules,
    describe_watch,
    evaluate,
    next_watch_key,
    normalize_parameters,
)
from core.log_analyzer import (
    FAILED_BURST_ACCOUNT,
    FAILED_BURST_COUNT,
    FAILED_BURST_SOURCE,
    events_to_frame,
    generate_event_frame,
)
from core.models import DetectionRule, SecurityAlert
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
_BANNED = ("confirmed attack", "compromise", "malicious", "breach", "intrusion")
_SECRET_KEYS = {"payload", "command", "command_line", "password", "message"}


def _rule(key: str, *, enabled: bool = True, **parameter_overrides: object) -> DetectionRule:
    base = next(rule for rule in default_rules() if rule.rule_key == key)
    parameters = dict(base.parameters)
    parameters.update(parameter_overrides)
    return DetectionRule(
        rule_key=base.rule_key,
        name=base.name,
        description=base.description,
        enabled=enabled,
        severity=base.severity,
        parameters=parameters,
    )


def _packets(rows: list[dict[str, object]]) -> pd.DataFrame:
    records = []
    for index, overrides in enumerate(rows):
        fields: dict[str, object] = {
            "timestamp": _START + timedelta(seconds=index),
            "src_ip": "192.168.1.10",
            "dst_ip": "192.0.2.10",
            "protocol": "TCP",
            "src_port": 49152 + (index % 16000),
            "dst_port": 443,
            "packet_length": 60,
            "ip_version": 4,
            "tcp_flags": "ACK",
            "import_id": "unit",
            "is_simulated": True,
        }
        fields.update(overrides)
        from core.models import PacketRecord

        records.append(PacketRecord(**fields))
    return records_to_frame(records)


def _events(rows: list[dict[str, object]]) -> pd.DataFrame:
    from core.models import SecurityEvent

    events = []
    for index, overrides in enumerate(rows):
        fields: dict[str, object] = {
            "event_uid": f"evt-{index}",
            "timestamp": _START + timedelta(seconds=index),
            "channel": "Security",
            "provider": "Microsoft-Windows-Security-Auditing",
            "event_id": 4625,
            "account_name": "demo.user",
            "src_ip": "192.0.2.25",
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
            "process_name": None,
            "process_id": None,
            "parent_process": None,
            "logon_type": 3,
            "outcome": "failure",
            "message": "Failed logon.",
            "is_simulated": True,
        }
        fields.update(overrides)
        events.append(SecurityEvent(**fields))
    return events_to_frame(events)


def _findings(packets: pd.DataFrame, events: pd.DataFrame, rules: list[DetectionRule]) -> list[SecurityAlert]:
    return evaluate(packets, events, rules, evaluated_at=_EVALUATED)


def test_seeded_sets_raise_three_builtin_findings() -> None:
    alerts = _findings(generate_packet_frame(), generate_event_frame(), list(default_rules()))
    by_rule: dict[str, list[SecurityAlert]] = {}
    for alert in alerts:
        by_rule.setdefault(alert.rule_key, []).append(alert)
        text = f"{alert.title} {alert.description}".lower()
        assert not any(word in text for word in _BANNED)
        assert _SECRET_KEYS.isdisjoint(alert.evidence)
        assert alert.status == "open"

    failed = by_rule["failed_auth"]
    assert len(failed) == 1
    assert failed[0].evidence["count"] == FAILED_BURST_COUNT
    assert failed[0].evidence["account_name"] == FAILED_BURST_ACCOUNT
    assert failed[0].src_ip == FAILED_BURST_SOURCE

    scan = by_rule["possible_port_scan"]
    assert len(scan) == 1
    assert scan[0].src_ip == SCAN_SOURCE
    assert scan[0].dst_ip == SCAN_DESTINATION
    assert scan[0].evidence["distinct_ports"] >= SCAN_PORT_COUNT
    expected_ports = set(range(SCAN_PORT_START, SCAN_PORT_START + SCAN_PORT_COUNT))
    assert expected_ports <= set(scan[0].evidence["ports"])

    volume = by_rule["volume_change"]
    assert len(volume) == 1
    assert volume[0].evidence["packet_count"] >= VOLUME_PACKET_COUNT
    assert volume[0].src_ip is None

    again = _findings(generate_packet_frame(), generate_event_frame(), list(default_rules()))
    assert [alert.alert_uid for alert in again] == [alert.alert_uid for alert in alerts]


def test_failed_authentication_uses_a_window_and_ignores_success() -> None:
    close = [
        {"timestamp": _START + timedelta(seconds=30 * offset), "event_uid": f"close-{offset}"}
        for offset in range(5)
    ]
    late = [{"timestamp": _START + timedelta(minutes=20), "event_uid": "late"}]
    success = [{"event_id": 4624, "outcome": "success", "message": "Successful logon.", "event_uid": "ok"}]
    alerts = _findings(
        records_to_frame([]),
        _events([*close, *late, *success]),
        [_rule("failed_auth", threshold=5, window_seconds=300)],
    )
    assert len(alerts) == 1
    assert alerts[0].evidence["count"] == 5

    sparse = _findings(
        records_to_frame([]),
        _events(close[:4]),
        [_rule("failed_auth")],
    )
    assert sparse == []

    outside = [
        {"timestamp": _START + timedelta(seconds=301 * offset), "event_uid": f"far-{offset}"}
        for offset in range(5)
    ]
    assert _findings(records_to_frame([]), _events(outside), [_rule("failed_auth", window_seconds=300)]) == []


def test_failed_authentication_splits_accounts() -> None:
    rows = []
    for account, source, prefix in (
        ("demo.user", "192.0.2.25", "a"),
        ("lab.admin", "198.51.100.7", "b"),
    ):
        for offset in range(5):
            rows.append(
                {
                    "event_uid": f"{prefix}-{offset}",
                    "timestamp": _START + timedelta(seconds=offset),
                    "account_name": account,
                    "src_ip": source,
                }
            )
    alerts = _findings(records_to_frame([]), _events(rows), [_rule("failed_auth")])
    assert len(alerts) == 2
    assert {alert.evidence["account_name"] for alert in alerts} == {"demo.user", "lab.admin"}


def test_port_scan_counts_syn_probes_only() -> None:
    syn = [
        {
            "timestamp": _START + timedelta(milliseconds=100 * port),
            "dst_port": 2000 + port,
            "tcp_flags": "SYN",
            "src_ip": "10.0.0.18",
            "dst_ip": "203.0.113.80",
        }
        for port in range(15)
    ]
    alerts = _findings(_packets(syn), events_to_frame([]), [_rule("possible_port_scan")])
    assert len(alerts) == 1
    assert alerts[0].evidence["distinct_ports"] == 15

    short = _findings(_packets(syn[:14]), events_to_frame([]), [_rule("possible_port_scan")])
    assert short == []

    handshake = [{**row, "tcp_flags": "SYN-ACK"} for row in syn]
    assert _findings(_packets(handshake), events_to_frame([]), [_rule("possible_port_scan")]) == []


def test_volume_change_compares_a_bucket_with_the_other_median() -> None:
    def frame_for(counts: list[int]) -> pd.DataFrame:
        rows = []
        for bucket, count in enumerate(counts):
            for offset in range(count):
                rows.append(
                    {"timestamp": _START + timedelta(seconds=bucket * 60, milliseconds=offset)}
                )
        return _packets(rows)

    alerts = _findings(frame_for([10, 10, 10, 10, 40]), events_to_frame([]), [_rule("volume_change")])
    assert len(alerts) == 1
    assert alerts[0].evidence["packet_count"] == 40
    assert alerts[0].evidence["baseline_median"] == 10

    below_multiplier = _findings(
        frame_for([20, 20, 20, 20, 50]),
        events_to_frame([]),
        [_rule("volume_change")],
    )
    assert below_multiplier == []
    assert _findings(frame_for([30, 30, 30, 30]), events_to_frame([]), [_rule("volume_change")]) == []


def test_disabled_rule_and_bad_parameters_are_skipped(caplog: pytest.LogCaptureFixture) -> None:
    packets = generate_packet_frame()
    events = generate_event_frame()
    disabled = _findings(packets, events, [_rule("failed_auth", enabled=False)])
    assert disabled == []

    broken = DetectionRule(
        rule_key="failed_auth",
        name="Repeated failed authentication",
        description="Counts failed logons for the same account and source address inside a time window.",
        enabled=True,
        severity="high",
        parameters={"threshold": 1, "window_seconds": 300},
    )
    with caplog.at_level("WARNING", logger="core.detection_engine"):
        skipped = evaluate(packets, events, [broken], evaluated_at=_EVALUATED)
    assert skipped == []
    assert "Skipped rule failed_auth" in caplog.text


def test_watch_matches_only_the_fields_it_sets() -> None:
    packets = _packets(
        [
            {"dst_port": 22, "src_ip": "192.168.1.20"},
            {"dst_port": 22, "src_ip": "192.168.1.35"},
            {"dst_port": 80, "src_ip": "192.168.1.20"},
        ]
    )
    parameters = normalize_parameters("watch_001", {"subject": "packet", "dst_port": "22"})
    assert parameters["dst_port"] == 22
    rule = DetectionRule(
        rule_key="watch_001",
        name="SSH watch",
        description=describe_watch(parameters),
        enabled=True,
        severity="low",
        parameters=parameters,
    )
    alerts = _findings(packets, events_to_frame([]), [rule])
    assert len(alerts) == 1
    assert alerts[0].evidence["match_count"] == 2
    assert alerts[0].title == "SSH watch"
    assert "22" in alerts[0].description or alerts[0].evidence["match_count"] == 2

    missed = DetectionRule(
        rule_key="watch_002",
        name="Absent host",
        description="Matching packets where destination 192.0.2.199.",
        enabled=True,
        severity="low",
        parameters={"subject": "packet", "dst_ip": "192.0.2.199"},
    )
    assert _findings(packets, events_to_frame([]), [missed]) == []
    assert next_watch_key({"watch_001"}) == "watch_002"


def test_normalize_rejects_bad_watch_input_without_echoing_it() -> None:
    with pytest.raises(ValueError, match="src_ip") as caught:
        normalize_parameters("watch_001", {"subject": "packet", "src_ip": "999.1.1.1"})
    assert "999.1.1.1" not in str(caught.value)
    with pytest.raises(ValueError, match="at least one"):
        normalize_parameters("watch_001", {"subject": "event"})
    with pytest.raises(ValueError, match="does not use"):
        normalize_parameters("watch_001", {"subject": "packet", "account_name": "demo.user"})
    with pytest.raises(ValueError, match="watch_"):
        normalize_parameters("custom_thing", {"subject": "packet", "dst_port": 22})


def test_rules_and_alerts_roundtrip_and_keep_status(tmp_path: Path) -> None:
    store = NetWatchStore(tmp_path / "netwatch.db")
    store.ensure_rules(default_rules())
    stored_rules = store.load_rules()
    assert [rule.rule_key for rule in stored_rules] == ["failed_auth", "possible_port_scan", "volume_change"]

    failed = stored_rules[0]
    store.save_rule(
        DetectionRule(
            rule_key=failed.rule_key,
            name="Renamed",
            description="Replacement description that should not replace the built-in text.",
            enabled=False,
            severity="medium",
            parameters={"threshold": 9, "window_seconds": 120},
        )
    )
    store.ensure_rules(default_rules())
    reloaded = {rule.rule_key: rule for rule in store.load_rules()}
    assert reloaded["failed_auth"].name == failed.name
    assert reloaded["failed_auth"].enabled is False
    assert reloaded["failed_auth"].parameters["threshold"] == 9
    with pytest.raises(ValueError, match="Disable"):
        store.delete_rule("failed_auth")

    watch = DetectionRule(
        rule_key="watch_001",
        name="SSH watch",
        description="Matching packets where destination port 22.",
        enabled=True,
        severity="low",
        parameters={"dst_port": 22, "subject": "packet"},
    )
    store.save_rule(watch)
    assert any(rule.rule_key == "watch_001" for rule in store.load_rules())
    store.delete_rule("watch_001")
    assert all(rule.rule_key != "watch_001" for rule in store.load_rules())
    with pytest.raises(ValueError, match="watch_"):
        store.save_rule(
            DetectionRule(
                rule_key="custom_thing",
                name="Custom",
                description="A key the engine does not install.",
                enabled=True,
                severity="low",
                parameters={"subject": "packet", "dst_port": 22},
            )
        )

    original = _findings(
        _packets(
            [
                {
                    "timestamp": _START + timedelta(milliseconds=100 * port),
                    "dst_port": 2000 + port,
                    "tcp_flags": "SYN",
                    "src_ip": "10.0.0.18",
                    "dst_ip": "203.0.113.80",
                }
                for port in range(15)
            ]
        ),
        events_to_frame([]),
        [_rule("possible_port_scan")],
    )[0]
    created = datetime(2026, 1, 15, 15, 0, tzinfo=timezone.utc)
    acknowledged = SecurityAlert(
        alert_uid=original.alert_uid,
        created_at=created,
        rule_key=original.rule_key,
        severity=original.severity,
        status="acknowledged",
        src_ip=original.src_ip,
        dst_ip=original.dst_ip,
        title=original.title,
        description=original.description,
        first_seen=original.first_seen,
        last_seen=original.last_seen,
        evidence=dict(original.evidence),
    )
    assert store.replace_alerts([acknowledged]) == 1
    revised = SecurityAlert(
        alert_uid=original.alert_uid,
        created_at=_EVALUATED,
        rule_key=original.rule_key,
        severity=original.severity,
        status="open",
        src_ip=original.src_ip,
        dst_ip=original.dst_ip,
        title=original.title,
        description="TCP SYN packets reached 15 distinct destination ports inside 60 seconds.",
        first_seen=original.first_seen,
        last_seen=original.last_seen,
        evidence=dict(original.evidence),
    )
    store.replace_alerts([revised])
    loaded = store.load_alerts()
    assert len(loaded) == 1
    assert loaded[0].status == "acknowledged"
    assert loaded[0].created_at == created
    assert loaded[0].description.startswith("TCP SYN packets reached 15")
    assert loaded[0].evidence["distinct_ports"] == 15

    store.replace_alerts([])
    assert store.load_alerts() == []


def test_alerts_page_lists_seeded_findings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("NETWATCH_DB", str(tmp_path / "netwatch.db"))
    app = AppTest.from_file(Path(__file__).resolve().parents[1] / "app.py", default_timeout=90)
    app.run()
    assert not app.exception
    app.switch_page("dashboard/alerts.py").run()
    assert not app.exception
    visible = _visible_text(app)
    for element in (*app.dataframe, *getattr(app, "expander", [])):
        visible += "\n" + str(getattr(element, "label", ""))
        value = getattr(element, "value", None)
        if hasattr(value, "to_csv"):
            visible += "\n" + value.to_csv(index=False)
        else:
            visible += "\n" + str(value)
    assert "Detection findings." in visible
    assert "Repeated failed authentication" in visible
    assert "Possible port scanning" in visible
    assert "Packet volume change" in visible

    next(widget for widget in app.text_input if widget.label == "Name").set_value("Port 22 watch")
    next(widget for widget in app.text_input if widget.label == "Destination port").set_value("22")
    next(button for button in app.button if button.label == "Add watch").click()
    app.run()
    assert not app.exception
    after = _visible_text(app)
    for element in (*app.dataframe, *getattr(app, "expander", [])):
        after += "\n" + str(getattr(element, "label", ""))
        value = getattr(element, "value", None)
        if hasattr(value, "to_csv"):
            after += "\n" + value.to_csv(index=False)
        else:
            after += "\n" + str(value)
    assert "Port 22 watch" in after
    assert "matched this watch" in after
