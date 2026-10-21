"""Tests for offline PCAP parsing. Packets are built in memory and are not sent."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import pytest

logging.getLogger("scapy").setLevel(logging.ERROR)

from scapy.data import DLT_RAW  # noqa: E402
from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6, IPv6ExtHdrHopByHop  # noqa: E402
from scapy.layers.l2 import ARP, Ether  # noqa: E402
from scapy.packet import Raw  # noqa: E402
from scapy.utils import wrpcap, wrpcapng  # noqa: E402

from core.filters import filter_packets  # noqa: E402
from core.models import PACKET_COLUMNS  # noqa: E402
from core.packet_analyzer import (  # noqa: E402
    MAX_PCAP_BYTES,
    MAX_PCAP_PACKETS,
    capture_label,
    describe_import,
    parse_pcap_bytes,
)
from core import packet_analyzer  # noqa: E402

_MAC_SRC = "02:00:00:00:00:01"
_MAC_DST = "02:00:00:00:00:02"
_MARKER = b"PAYLOADMARKER9f3a"
_BASE = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)


def _moment(seconds: int) -> datetime:
    return _BASE + timedelta(seconds=seconds)


def _stamp(packet: Ether, moment: datetime) -> Ether:
    packet.time = moment.timestamp()
    return packet


def _tcp(
    src: str,
    dst: str,
    sport: int,
    dport: int,
    flags: str,
    moment: datetime,
    payload: bytes = b"",
) -> Ether:
    layered = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    if payload:
        layered = layered / Raw(load=payload)
    return _stamp(Ether(src=_MAC_SRC, dst=_MAC_DST) / layered, moment)


def _write_capture(packets: list, *, pcapng: bool = False, linktype: int | None = None) -> bytes:
    import os
    import tempfile

    fd, name = tempfile.mkstemp(suffix=".pcapng" if pcapng else ".pcap")
    os.close(fd)
    path = Path(name)
    try:
        if pcapng:
            wrpcapng(str(path), packets)
        elif linktype is None:
            wrpcap(str(path), packets)
        else:
            wrpcap(str(path), packets, linktype=linktype)
        return path.read_bytes()
    finally:
        path.unlink(missing_ok=True)


def test_parser_reads_metadata_and_drops_payload(caplog: pytest.LogCaptureFixture) -> None:
    packets = [
        _tcp("192.0.2.10", "198.51.100.7", 49152, 443, "SA", _moment(5), _MARKER),
        _tcp("192.0.2.11", "198.51.100.8", 49153, 80, "PA", _moment(1)),
        _stamp(
            Ether(src=_MAC_SRC, dst=_MAC_DST)
            / IP(src="10.0.0.5", dst="192.0.2.20")
            / UDP(sport=53000, dport=53),
            _moment(2),
        ),
        _stamp(
            Ether(src=_MAC_SRC, dst=_MAC_DST) / IP(src="172.16.4.8", dst="203.0.113.15") / ICMP(),
            _moment(3),
        ),
        _stamp(
            Ether(src=_MAC_SRC, dst=_MAC_DST) / IP(src="192.0.2.40", dst="192.0.2.41") / Raw(load=b"abc"),
            _moment(4),
        ),
        _stamp(
            Ether(src=_MAC_SRC, dst=_MAC_DST)
            / ARP(op=1, psrc="203.0.113.50", pdst="203.0.113.1", hwsrc=_MAC_SRC, hwdst=_MAC_DST),
            _moment(6),
        ),
    ]

    with caplog.at_level(logging.DEBUG, logger="core.packet_analyzer"):
        result = parse_pcap_bytes(_write_capture(packets))

    assert result.error is None
    assert result.accepted == 5
    assert result.skipped == 1
    assert not result.truncated
    assert result.import_id.startswith("pcap-")
    assert list(result.frame.columns) == list(PACKET_COLUMNS)
    assert "payload" not in result.frame.columns
    assert result.frame["is_simulated"].eq(False).all()
    assert set(result.frame["import_id"]) == {result.import_id}
    assert result.frame["timestamp"].is_monotonic_increasing
    assert _MARKER not in result.frame.to_csv().encode()
    assert _MARKER.decode() not in caplog.text
    assert "203.0.113.50" not in caplog.text
    assert "203.0.113.50" not in set(result.frame["src_ip"])

    tcp = result.frame[result.frame["protocol"] == "TCP"].reset_index(drop=True)
    assert list(tcp["tcp_flags"]) == ["PSH-ACK", "SYN-ACK"]
    assert list(tcp["dst_port"].astype(int)) == [80, 443]
    assert list(tcp["src_ip"]) == ["192.0.2.11", "192.0.2.10"]

    udp = result.frame[result.frame["protocol"] == "UDP"].iloc[0]
    assert int(udp["src_port"]) == 53000
    assert int(udp["dst_port"]) == 53
    assert pd.isna(udp["tcp_flags"])

    icmp = result.frame[result.frame["protocol"] == "ICMP"].iloc[0]
    assert pd.isna(icmp["src_port"])
    assert pd.isna(icmp["dst_port"])
    assert pd.isna(icmp["tcp_flags"])
    assert icmp["src_ip"] == "172.16.4.8"

    other = result.frame[result.frame["protocol"] == "OTHER"].iloc[0]
    assert other["src_ip"] == "192.0.2.40"
    assert pd.isna(other["src_port"])
    assert pd.isna(other["dst_port"])

    matched = filter_packets(result.frame, ip="192.0.2.10", protocol="TCP", port=443)
    assert matched.error is None
    assert len(matched.frame) == 1
    assert matched.frame.iloc[0]["tcp_flags"] == "SYN-ACK"


def test_ipv6_extension_header_and_icmp() -> None:
    moment = _moment(8)
    packets = [
        _stamp(
            Ether(src=_MAC_SRC, dst=_MAC_DST)
            / IPv6(src="2001:db8::10", dst="2001:db8::20")
            / IPv6ExtHdrHopByHop()
            / TCP(sport=41000, dport=443, flags="S"),
            moment,
        ),
        _stamp(
            Ether(src=_MAC_SRC, dst=_MAC_DST)
            / IPv6(src="2001:db8::1", dst="2001:db8::2")
            / ICMPv6EchoRequest(),
            moment + timedelta(seconds=1),
        ),
    ]
    result = parse_pcap_bytes(_write_capture(packets))

    assert result.error is None
    assert result.accepted == 2
    tcp = result.frame[result.frame["protocol"] == "TCP"].iloc[0]
    assert tcp["ip_version"] == 6
    assert tcp["src_ip"] == "2001:db8::10"
    assert tcp["dst_ip"] == "2001:db8::20"
    assert int(tcp["dst_port"]) == 443
    assert tcp["tcp_flags"] == "SYN"
    icmp = result.frame[result.frame["protocol"] == "ICMP"].iloc[0]
    assert icmp["ip_version"] == 6
    assert pd.isna(icmp["src_port"])
    assert pd.isna(icmp["dst_port"])


def test_pcapng_and_raw_ip_link_type() -> None:
    pcapng = _write_capture(
        [_tcp("192.0.2.70", "198.51.100.70", 12000, 22, "A", _moment(9))],
        pcapng=True,
    )
    assert pcapng.startswith(b"\x0a\x0d\x0d\x0a")
    parsed_ng = parse_pcap_bytes(pcapng)
    assert parsed_ng.error is None
    assert parsed_ng.accepted == 1
    assert parsed_ng.frame.iloc[0]["tcp_flags"] == "ACK"
    assert parsed_ng.frame.iloc[0]["dst_port"] == 22

    raw_ip = _stamp(IP(src="192.0.2.30", dst="198.51.100.30") / UDP(sport=12345, dport=53), _moment(10))
    parsed_raw = parse_pcap_bytes(_write_capture([raw_ip], linktype=DLT_RAW))
    assert parsed_raw.error is None
    assert parsed_raw.accepted == 1
    assert parsed_raw.frame.iloc[0]["protocol"] == "UDP"
    assert parsed_raw.frame.iloc[0]["src_ip"] == "192.0.2.30"


def test_repeat_parse_is_stable_and_import_id_changes_with_bytes() -> None:
    first_bytes = _write_capture([_tcp("192.0.2.1", "192.0.2.2", 10, 20, "S", _moment(1))])
    second_bytes = _write_capture([_tcp("192.0.2.3", "192.0.2.4", 10, 20, "S", _moment(1))])
    first = parse_pcap_bytes(first_bytes)
    again = parse_pcap_bytes(bytearray(first_bytes))
    second = parse_pcap_bytes(second_bytes)

    assert first.error is None and again.error is None
    assert first.import_id == again.import_id
    pd.testing.assert_frame_equal(first.frame, again.frame)
    assert first.import_id != second.import_id


def test_limits_and_rejected_files(caplog: pytest.LogCaptureFixture) -> None:
    packets = [
        _tcp("192.0.2.1", "192.0.2.2", 11, 80, "S", _moment(1)),
        _tcp("192.0.2.3", "192.0.2.4", 12, 80, "S", _moment(2)),
        _tcp("192.0.2.5", "192.0.2.6", 13, 80, "S", _moment(3)),
    ]
    truncated = parse_pcap_bytes(_write_capture(packets), max_packets=2)
    assert truncated.error is None
    assert truncated.accepted == 2
    assert truncated.truncated
    assert "192.0.2.5" not in set(truncated.frame["src_ip"])
    assert "Only the first 2 packets were kept." in describe_import(truncated)

    empty = parse_pcap_bytes(b"")
    assert empty.error == "The file is empty."
    assert empty.frame.empty

    nonsense = parse_pcap_bytes(b"this is not a capture")
    assert nonsense.error == "The file is not a PCAP or PCAPNG capture."
    assert nonsense.accepted == 0

    short = parse_pcap_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 8)
    assert short.error == "The capture could not be read."

    oversized = parse_pcap_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20, max_bytes=8)
    assert oversized.error == "The file is larger than the upload limit."

    with caplog.at_level(logging.WARNING, logger="core.packet_analyzer"):
        default_limit = parse_pcap_bytes(b"x" * (MAX_PCAP_BYTES + 1))
    assert default_limit.error == "The file is larger than 50 MB."
    assert "x" * 20 not in caplog.text

    assert parse_pcap_bytes(None).error == "The capture must be provided as bytes."  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        parse_pcap_bytes(b"abc", max_bytes=True)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        parse_pcap_bytes(b"abc", max_packets=0)

    header_only = parse_pcap_bytes(_write_capture([]))
    assert header_only.error is None
    assert header_only.accepted == 0
    assert header_only.skipped == 0


def test_labels_and_skip_summary() -> None:
    assert capture_label(r"C:\Users\Lawson\secret\evidence.pcap") == "evidence.pcap"
    assert capture_label("../../evidence.pcapng") == "evidence.pcapng"
    assert capture_label("weird\nname.pcap") == "weirdname.pcap"
    assert capture_label("name\u202e.pcap") == "name.pcap"
    assert capture_label("") == "uploaded capture"
    assert capture_label(None) == "uploaded capture"  # type: ignore[arg-type]
    assert len(capture_label("a" * 200 + ".pcap")) == 80

    arp_only = parse_pcap_bytes(
        _write_capture(
            [
                _stamp(
                    Ether(src=_MAC_SRC, dst=_MAC_DST)
                    / ARP(op=1, psrc="203.0.113.50", pdst="203.0.113.1", hwsrc=_MAC_SRC, hwdst=_MAC_DST),
                    _moment(1),
                )
            ]
        )
    )
    assert arp_only.error is None
    assert arp_only.accepted == 0
    assert arp_only.skipped == 1
    assert "Skipped 1 packets" in describe_import(arp_only)


def test_upload_cap_matches_streamlit_config() -> None:
    config = Path(".streamlit/config.toml").read_text(encoding="utf-8")
    assert "maxUploadSize = 50" in config
    assert MAX_PCAP_BYTES == 50 * 1024 * 1024
    assert MAX_PCAP_PACKETS == 100_000


def test_parser_does_not_capture_live_traffic() -> None:
    source = Path(packet_analyzer.__file__).read_text(encoding="utf-8")
    assert "sniff(" not in source
    assert "AsyncSniffer" not in source


def test_dashboard_upload_replaces_and_restores_the_fictional_set(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("NETWATCH_DB", str(tmp_path / "netwatch.db"))
    capture = _write_capture([_tcp("192.0.2.10", "198.51.100.7", 49152, 443, "S", _moment(4))])
    app = AppTest.from_file(Path(__file__).resolve().parents[1] / "app.py", default_timeout=60)
    app.run()
    assert not app.exception
    assert len(app.session_state["packets"]) == 800
    assert app.session_state["data_source"] == "simulated"
    assert "Simulated data" in _visible_text(app)
    assert app.sidebar.button.len == 0

    app.sidebar.file_uploader[0].set_value(("notes.pcap", b"not-a-capture", "application/octet-stream"))
    app.run()
    assert not app.exception
    assert len(app.session_state["packets"]) == 800
    assert app.session_state["data_source"] == "simulated"
    assert any(error.value == "The file is not a PCAP or PCAPNG capture." for error in app.sidebar.error)

    app.sidebar.file_uploader[0].set_value(("office.pcap", capture, "application/vnd.tcpdump.pcap"))
    app.run()
    assert not app.exception
    imported = app.session_state["packets"]
    assert len(imported) == 1
    assert app.session_state["data_source"] == "imported"
    assert app.session_state["source_name"] == "office.pcap"
    assert imported.iloc[0]["src_ip"] == "192.0.2.10"
    assert imported.iloc[0]["tcp_flags"] == "SYN"
    assert bool(imported.iloc[0]["is_simulated"]) is False
    visible = _visible_text(app)
    assert "Offline capture" in visible
    assert "Parsed 1 packets." in visible
    assert app.sidebar.metric[0].value == "1"

    app.switch_page("dashboard/network.py").run()
    assert not app.exception
    traffic = _visible_text(app)
    assert "Metadata from the uploaded capture" in traffic
    assert "192.0.2.10" in set(app.dataframe[0].value["Source IP"])

    restore = next(button for button in app.sidebar.button if button.label == "Use simulated data")
    restore.click()
    app.run()
    assert not app.exception
    assert len(app.session_state["packets"]) == 800
    assert app.session_state["data_source"] == "simulated"
    assert "Simulated data" in _visible_text(app)


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
