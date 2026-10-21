"""Tests for packet filtering and summary helpers."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import pandas as pd
import pytest

from core.filters import (
    filter_packets,
    packet_summary,
    packets_over_time,
    protocol_counts,
    top_ips,
    top_ports,
)
from core.sample_data import SAMPLE_START, generate_packet_frame


@pytest.fixture
def packets() -> pd.DataFrame:
    return generate_packet_frame()


def test_ip_protocol_and_port_filters(packets: pd.DataFrame) -> None:
    ip = "192.0.2.10"
    by_ip = filter_packets(packets, ip=ip)
    assert by_ip.error is None
    assert not by_ip.frame.empty
    assert ((by_ip.frame["src_ip"] == ip) | (by_ip.frame["dst_ip"] == ip)).all()

    by_protocol = filter_packets(packets, protocol="tcp")
    assert by_protocol.error is None
    assert set(by_protocol.frame["protocol"]) == {"TCP"}

    by_port = filter_packets(packets, port="443")
    assert by_port.error is None
    assert not by_port.frame.empty
    assert ((by_port.frame["src_port"] == 443) | (by_port.frame["dst_port"] == 443)).all()


def test_time_filter_is_inclusive(packets: pd.DataFrame) -> None:
    start = SAMPLE_START
    end = SAMPLE_START + timedelta(minutes=5)
    outcome = filter_packets(packets, start=start, end=end)

    assert outcome.error is None
    assert not outcome.frame.empty
    assert outcome.frame["timestamp"].min() >= pd.Timestamp(start)
    assert outcome.frame["timestamp"].max() <= pd.Timestamp(end)


def test_combined_filters_and_empty_result(packets: pd.DataFrame) -> None:
    tcp = packets[packets["protocol"] == "TCP"].iloc[0]
    matched = filter_packets(
        packets,
        ip=tcp["src_ip"],
        protocol=tcp["protocol"],
        port=int(tcp["dst_port"]),
        start=SAMPLE_START,
        end=SAMPLE_START + timedelta(minutes=30),
    )
    assert matched.error is None
    assert not matched.frame.empty
    assert (matched.frame["protocol"] == "TCP").all()
    assert (
        (matched.frame["src_ip"] == tcp["src_ip"]) | (matched.frame["dst_ip"] == tcp["src_ip"])
    ).all()

    empty = filter_packets(
        packets,
        ip="192.0.2.199",
        protocol="TCP",
        port=1,
        start=SAMPLE_START,
        end=SAMPLE_START + timedelta(seconds=1),
    )
    assert empty.error is None
    assert empty.frame.empty


def test_filter_does_not_change_the_original_frame(packets: pd.DataFrame) -> None:
    original = packets.copy(deep=True)
    filter_packets(packets, protocol="UDP", port=53)
    pd.testing.assert_frame_equal(packets, original)


def test_invalid_filters_return_a_message(packets: pd.DataFrame, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="core.filters"):
        bad_ip = filter_packets(packets, ip="not-an-ip")
    assert bad_ip.frame.empty
    assert bad_ip.error == "Enter a valid IPv4 or IPv6 address."
    assert "Rejected packet filter" in caplog.text

    bad_port = filter_packets(packets, port="abc")
    assert bad_port.frame.empty
    assert bad_port.error is not None

    high_port = filter_packets(packets, port="70000")
    assert high_port.error is not None

    bad_protocol = filter_packets(packets, protocol="SCTP")
    assert bad_protocol.error is not None

    reversed_window = filter_packets(
        packets,
        start=SAMPLE_START + timedelta(minutes=10),
        end=SAMPLE_START,
    )
    assert reversed_window.frame.empty
    assert reversed_window.error is not None

    naive = filter_packets(packets, start=datetime(2026, 1, 15, 14, 0))
    assert naive.error is not None
    assert "UTC" in naive.error

    blank = filter_packets(packets, ip="  ", protocol="", port="")
    assert blank.error is None
    assert len(blank.frame) == len(packets)


def test_missing_columns_are_rejected(packets: pd.DataFrame) -> None:
    broken = packets.drop(columns=["src_ip"])
    outcome = filter_packets(broken, protocol="TCP")
    assert outcome.frame.empty
    assert outcome.error == "Packet table is missing required columns."


def test_summaries_match_the_frame(packets: pd.DataFrame) -> None:
    summary = packet_summary(packets)
    assert summary.total_packets == len(packets)
    assert summary.unique_src_ips == packets["src_ip"].nunique()
    assert summary.unique_dst_ips == packets["dst_ip"].nunique()

    filtered = filter_packets(packets, protocol="ICMP").frame
    filtered_summary = packet_summary(filtered)
    assert filtered_summary.total_packets == len(filtered)
    assert packet_summary(packets.iloc[0:0]).total_packets == 0
    assert packet_summary(packets.iloc[0:0]).unique_src_ips == 0

    assert int(protocol_counts(packets)["packets"].sum()) == len(packets)
    assert int(packets_over_time(packets)["packets"].sum()) == len(packets)

    ports = top_ports(packets)
    assert set(ports["port"]).intersection({80, 443, 53, 22, 445, 3389})
    assert top_ips(packets, "src_ip")["src_ip"].is_unique
    with pytest.raises(ValueError):
        top_ips(packets, "protocol")
