"""Tests for fictional packet generation and the shared record contracts."""

from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timedelta, timezone

import pandas as pd
import pytest

from core.models import (
    PACKET_COLUMNS,
    DetectionRule,
    PacketRecord,
    SecurityAlert,
    SecurityEvent,
)
from core.sample_data import (
    DESTINATION_CHOICES,
    SAMPLE_PACKET_COUNT,
    SAMPLE_SEED,
    SAMPLE_START,
    SAMPLE_WINDOW,
    SCAN_DESTINATION,
    SCAN_PORT_COUNT,
    SCAN_PORT_START,
    SCAN_SOURCE,
    SOURCE_CHOICES,
    TCP_PORT_CHOICES,
    UDP_PORT_CHOICES,
    VOLUME_DESTINATION,
    VOLUME_PACKET_COUNT,
    VOLUME_SOURCE,
    generate_packet_frame,
    generate_packets,
    packets_from_mappings,
)

DOCUMENTATION_AND_PRIVATE = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def _in_demo_space(address: str) -> bool:
    parsed = ipaddress.ip_address(address)
    return any(parsed in network for network in DOCUMENTATION_AND_PRIVATE)


def _sample_event() -> SecurityEvent:
    moment = datetime(2026, 1, 15, 14, 5, tzinfo=timezone.utc)
    return SecurityEvent(
        event_uid="evt-1",
        timestamp=moment,
        channel="Security",
        provider="Microsoft-Windows-Security-Auditing",
        event_id=4625,
        account_name="demo.user",
        src_ip="192.0.2.10",
        dst_ip=None,
        src_port=None,
        dst_port=None,
        process_name=None,
        process_id=None,
        parent_process=None,
        logon_type=3,
        outcome="failure",
        message="Simulated failed logon for demonstration.",
        is_simulated=True,
        ingested_at=moment,
    )


def test_generator_contract() -> None:
    frame = generate_packet_frame()

    assert list(frame.columns) == list(PACKET_COLUMNS)
    assert "payload" not in frame.columns
    assert len(frame) == SAMPLE_PACKET_COUNT
    assert frame["is_simulated"].all()
    assert set(frame["import_id"]) == {f"simulated-seed-{SAMPLE_SEED}"}
    assert set(frame["protocol"]) == {"TCP", "UDP", "ICMP"}
    assert set(frame["ip_version"]) == {4}
    assert set(frame["src_ip"]) == {ip for ip, _ in SOURCE_CHOICES}
    assert set(frame["dst_ip"]) == {ip for ip, _ in DESTINATION_CHOICES}
    assert frame["src_ip"].map(_in_demo_space).all()
    assert frame["dst_ip"].map(_in_demo_space).all()

    window_end = SAMPLE_START + SAMPLE_WINDOW
    assert frame["timestamp"].min() >= pd.Timestamp(SAMPLE_START)
    assert frame["timestamp"].max() < pd.Timestamp(window_end)
    assert frame["timestamp"].is_monotonic_increasing

    icmp = frame[frame["protocol"] == "ICMP"]
    tcp = frame[frame["protocol"] == "TCP"]
    udp = frame[frame["protocol"] == "UDP"]
    assert icmp["src_port"].isna().all()
    assert icmp["dst_port"].isna().all()
    assert icmp["tcp_flags"].isna().all()
    assert tcp["src_port"].notna().all()
    assert tcp["dst_port"].notna().all()
    assert tcp["tcp_flags"].notna().all()
    assert udp["tcp_flags"].isna().all()
    scan_ports = set(range(SCAN_PORT_START, SCAN_PORT_START + SCAN_PORT_COUNT))
    assert set(tcp["dst_port"].astype(int)) <= {port for port, _ in TCP_PORT_CHOICES} | scan_ports
    assert set(udp["dst_port"].astype(int)) <= {port for port, _ in UDP_PORT_CHOICES}
    scan = tcp[
        (tcp["src_ip"] == SCAN_SOURCE)
        & (tcp["dst_ip"] == SCAN_DESTINATION)
        & (tcp["tcp_flags"] == "SYN")
    ]
    assert scan_ports <= set(scan["dst_port"].astype(int))
    volume_start = pd.Timestamp(SAMPLE_START + timedelta(minutes=6))
    volume = frame[
        (frame["timestamp"] >= volume_start)
        & (frame["timestamp"] < volume_start + pd.Timedelta(minutes=1))
        & (frame["src_ip"] == VOLUME_SOURCE)
        & (frame["dst_ip"] == VOLUME_DESTINATION)
        & (frame["dst_port"] == 443)
        & (frame["tcp_flags"] == "ACK")
    ]
    assert len(volume) >= VOLUME_PACKET_COUNT
    assert tcp["src_port"].between(49152, 65535).all()
    assert udp["src_port"].between(49152, 65535).all()
    assert frame["packet_length"].between(1, 65535).all()


def test_generator_is_deterministic() -> None:
    pd.testing.assert_frame_equal(generate_packet_frame(), generate_packet_frame())
    assert not generate_packet_frame(seed=99).equals(generate_packet_frame(seed=SAMPLE_SEED))


def test_generator_rejects_bad_arguments() -> None:
    with pytest.raises(ValueError):
        generate_packets(count=0)
    with pytest.raises(ValueError):
        generate_packets(seed=True)  # type: ignore[arg-type]


def test_invalid_row_is_skipped(caplog: pytest.LogCaptureFixture) -> None:
    record = generate_packets(count=1)[0]
    good = {name: getattr(record, name) for name in PACKET_COLUMNS}
    bad = dict(good)
    bad["src_ip"] = "999.1.1.1"

    with caplog.at_level(logging.WARNING, logger="core.sample_data"):
        kept = packets_from_mappings([good, bad])

    assert kept == [record]
    assert "Skipped packet row 1" in caplog.text
    assert "999.1.1.1" not in caplog.text


def test_packet_record_rejects_unsafe_or_incomplete_metadata() -> None:
    record = generate_packets(count=1)[0]
    fields = {name: getattr(record, name) for name in PACKET_COLUMNS}

    naive = dict(fields)
    naive["timestamp"] = datetime(2026, 1, 15, 14, 0)
    with pytest.raises(ValueError, match="UTC"):
        PacketRecord(**naive)

    icmp_with_port = dict(fields)
    icmp_with_port["protocol"] = "ICMP"
    icmp_with_port["src_port"] = 1
    icmp_with_port["dst_port"] = None
    icmp_with_port["tcp_flags"] = None
    with pytest.raises(ValueError, match="Ports"):
        PacketRecord(**icmp_with_port)

    missing_tcp_port = dict(fields)
    missing_tcp_port["protocol"] = "TCP"
    missing_tcp_port["src_port"] = None
    with pytest.raises(ValueError, match="src_port"):
        PacketRecord(**missing_tcp_port)

    flags_on_udp = dict(fields)
    flags_on_udp["protocol"] = "UDP"
    flags_on_udp["tcp_flags"] = "SYN"
    with pytest.raises(ValueError, match="TCP flags"):
        PacketRecord(**flags_on_udp)


def test_security_contracts_reject_unknown_categories() -> None:
    event = _sample_event()
    assert event.outcome == "failure"
    with pytest.raises(ValueError, match="Outcome"):
        SecurityEvent(**{**event.__dict__, "outcome": "compromised"})

    rule = DetectionRule(
        rule_key="failed_auth",
        name="Repeated failed authentication",
        description="Multiple failures in a short window may be consistent with password guessing.",
        enabled=True,
        severity="high",
        parameters={"threshold": 5, "window_seconds": 120},
    )
    assert dict(rule.parameters)["threshold"] == 5
    with pytest.raises(ValueError, match="Severity"):
        DetectionRule(
            rule_key="failed_auth",
            name="Repeated failed authentication",
            description="Multiple failures in a short window.",
            enabled=True,
            severity="urgent",
            parameters={},
        )

    moment = datetime(2026, 1, 15, 14, 6, tzinfo=timezone.utc)
    alert = SecurityAlert(
        alert_uid="alert-1",
        created_at=moment,
        rule_key="failed_auth",
        severity="high",
        status="open",
        src_ip="192.0.2.10",
        dst_ip=None,
        title="Repeated failed authentication",
        description="Five simulated failures occurred within two minutes.",
        first_seen=moment - timedelta(minutes=2),
        last_seen=moment,
        evidence={"count": 5, "record_ids": [1, 2, 3, 4, 5]},
    )
    assert alert.evidence["count"] == 5
    with pytest.raises(ValueError, match="status"):
        SecurityAlert(
            alert_uid="alert-2",
            created_at=moment,
            rule_key="failed_auth",
            severity="high",
            status="closed",
            src_ip=None,
            dst_ip=None,
            title="Repeated failed authentication",
            description="Status is not a supported value.",
            first_seen=moment,
            last_seen=moment,
            evidence={},
        )
