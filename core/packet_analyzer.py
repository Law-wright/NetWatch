"""Offline PCAP and PCAPNG parsing.

Reads a saved capture and returns packet metadata. This module does not open
a network interface, and it does not keep payload bytes.
"""

from __future__ import annotations

import hashlib
import io
import ipaddress
import logging
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

import pandas as pd

from core.models import PacketRecord
from core.sample_data import records_to_frame

logger = logging.getLogger(__name__)

# Streamlit's server.maxUploadSize is 50 MB. Enforce the same cap here.
MAX_PCAP_BYTES = 50 * 1024 * 1024
MAX_PCAP_PACKETS = 100_000

_PCAP_MAGICS = frozenset(
    {
        b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\xc3\xd4",
        b"\x4d\x3c\xb2\xa1",
        b"\xa1\xb2\x3c\x4d",
    }
)
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
_LABEL_LIMIT = 80
# Low bit to high bit, so common combinations read SYN-ACK, PSH-ACK, and FIN-ACK.
_TCP_FLAG_BITS = (
    (0x01, "F", "FIN"),
    (0x02, "S", "SYN"),
    (0x04, "R", "RST"),
    (0x08, "P", "PSH"),
    (0x10, "A", "ACK"),
    (0x20, "U", "URG"),
    (0x40, "E", "ECE"),
    (0x80, "C", "CWR"),
)


@dataclass(frozen=True)
class PcapImport:
    """Metadata extracted from one capture, without payload bytes."""

    frame: pd.DataFrame
    import_id: str
    accepted: int
    skipped: int
    truncated: bool
    incomplete: bool = False
    error: str | None = None


@dataclass(frozen=True)
class _Scapy:
    """Layers used to read a capture. Loaded only when a file is parsed."""

    reader: Any
    ip: type
    ipv6: type
    tcp: type
    udp: type
    icmp: type
    icmpv6: type
    extension: type
    no_payload: type


def capture_label(filename: str) -> str:
    """Return a single-line file label safe to show in the dashboard."""
    if not isinstance(filename, str):
        return "uploaded capture"
    cleaned: list[str] = []
    for character in Path(filename).name:
        if not character.isprintable() or unicodedata.category(character) == "Cf":
            continue
        if character in '\\/:*?"<>|':
            continue
        cleaned.append(character)
    label = "".join(cleaned).strip().strip(".")
    if not label:
        return "uploaded capture"
    return label[:_LABEL_LIMIT]


def describe_import(result: PcapImport) -> str:
    """Summarize a parse for the sidebar. The text contains counts, not packet contents."""
    if result.error:
        return result.error
    parts = [f"Parsed {result.accepted:,} packets."]
    if result.skipped:
        parts.append(
            f"Skipped {result.skipped:,} packets that did not contain usable IP metadata."
        )
    if result.truncated:
        parts.append(f"Only the first {result.accepted:,} packets were kept.")
    if result.incomplete:
        parts.append("Reading stopped before the end of the file.")
    return " ".join(parts)


def parse_pcap_bytes(
    data: bytes,
    *,
    max_bytes: int = MAX_PCAP_BYTES,
    max_packets: int = MAX_PCAP_PACKETS,
) -> PcapImport:
    """Parse IP metadata from PCAP or PCAPNG bytes.

    ``max_bytes`` rejects the upload before Scapy sees it. ``max_packets`` stops
    after that many accepted rows and reports the capture as truncated.
    """
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError("max_bytes must be an integer of at least 1.")
    if isinstance(max_packets, bool) or not isinstance(max_packets, int) or max_packets < 1:
        raise ValueError("max_packets must be an integer of at least 1.")

    payload = _as_bytes(data)
    if payload is None:
        return _failed("The capture must be provided as bytes.")
    if len(payload) == 0:
        return _failed("The file is empty.")
    if len(payload) > max_bytes:
        return _failed(_size_message(max_bytes))
    if payload[:4] not in _PCAP_MAGICS and payload[:4] != _PCAPNG_MAGIC:
        return _failed("The file is not a PCAP or PCAPNG capture.")

    layers = _scapy()
    import_id = "pcap-" + hashlib.sha256(payload).hexdigest()[:16]
    records: list[PacketRecord] = []
    reasons: dict[str, int] = {}
    truncated = False
    incomplete = False
    buffer = io.BytesIO(payload)
    reader = None
    try:
        try:
            reader = layers.reader(buffer)
        except Exception as exc:
            logger.warning("Capture rejected while opening: %s", type(exc).__name__)
            return _failed("The capture could not be read.")
        try:
            for packet in reader:
                if len(records) >= max_packets:
                    truncated = True
                    break
                record, reason = _record_from_packet(packet, import_id, layers)
                if reason:
                    reasons[reason] = reasons.get(reason, 0) + 1
                    continue
                records.append(record)
        except Exception as exc:
            logger.warning("Capture reading stopped: %s", type(exc).__name__)
            incomplete = True
    finally:
        if reader is not None:
            reader.close()
        else:
            buffer.close()

    skipped = sum(reasons.values())
    if incomplete and not records and skipped == 0:
        return _failed("The capture could not be read.")

    records.sort(key=lambda record: record.timestamp)
    if reasons:
        logger.info(
            "Capture skip counts: %s",
            " ".join(f"{name}={reasons[name]}" for name in sorted(reasons)),
        )
    logger.info(
        "Parsed capture accepted=%s skipped=%s truncated=%s incomplete=%s",
        len(records),
        skipped,
        truncated,
        incomplete,
    )
    return PcapImport(
        frame=records_to_frame(records),
        import_id=import_id,
        accepted=len(records),
        skipped=skipped,
        truncated=truncated,
        incomplete=incomplete,
    )


def _as_bytes(data: object) -> bytes | None:
    if isinstance(data, bytes):
        return data
    if isinstance(data, bytearray):
        return bytes(data)
    if isinstance(data, memoryview):
        return data.tobytes()
    return None


def _size_message(max_bytes: int) -> str:
    if max_bytes == MAX_PCAP_BYTES:
        return "The file is larger than 50 MB."
    return "The file is larger than the upload limit."


def _failed(message: str) -> PcapImport:
    logger.warning("Rejected capture: %s", message)
    return PcapImport(
        frame=records_to_frame([]),
        import_id="",
        accepted=0,
        skipped=0,
        truncated=False,
        incomplete=False,
        error=message,
    )


@lru_cache(maxsize=1)
def _scapy() -> _Scapy:
    """Import Scapy when a capture is parsed, not when the dashboard starts."""
    logging.getLogger("scapy").setLevel(logging.ERROR)
    from scapy.config import conf
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6, _ICMPv6, _IPv6ExtHdr
    from scapy.packet import NoPayload
    from scapy.utils import PcapReader

    conf.verb = 0
    logging.getLogger("scapy").setLevel(logging.ERROR)
    return _Scapy(
        reader=PcapReader,
        ip=IP,
        ipv6=IPv6,
        tcp=TCP,
        udp=UDP,
        icmp=ICMP,
        icmpv6=_ICMPv6,
        extension=_IPv6ExtHdr,
        no_payload=NoPayload,
    )


def _outer_ip(packet: Any, layers: _Scapy) -> tuple[Any, int] | None:
    layer = packet
    for _ in range(16):
        if layer is None or isinstance(layer, layers.no_payload):
            return None
        if isinstance(layer, layers.ip):
            return layer, 4
        if isinstance(layer, layers.ipv6):
            return layer, 6
        layer = layer.payload
    return None


def _upper_layer(ip_layer: Any, layers: _Scapy) -> Any | None:
    layer = ip_layer.payload
    for _ in range(8):
        if layer is None or isinstance(layer, layers.no_payload):
            return None
        if isinstance(layer, layers.extension):
            layer = layer.payload
            continue
        return layer
    return None


def _normalize_ip(value: object, version: int) -> str | None:
    text = value if isinstance(value, str) else str(value)
    try:
        address = ipaddress.ip_address(text.strip())
    except ValueError:
        return None
    if address.version != version:
        return None
    return str(address)


def _utc_timestamp(packet: Any) -> datetime | None:
    raw_time = getattr(packet, "time", None)
    if raw_time is None:
        return None
    try:
        timestamp = datetime.fromtimestamp(float(raw_time), tz=timezone.utc)
    except (TypeError, ValueError, OSError, OverflowError):
        return None
    return timestamp


def _valid_length(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 65535


def _packet_length(packet: Any) -> int | None:
    wirelen = getattr(packet, "wirelen", None)
    if _valid_length(wirelen):
        return int(wirelen)
    try:
        captured = len(packet)
    except (TypeError, ValueError):
        return None
    if _valid_length(captured):
        return int(captured)
    return None


def _port_number(value: object) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        port = value
    else:
        try:
            port = int(str(value))
        except (TypeError, ValueError):
            return None
    if 0 <= port <= 65535:
        return port
    return None


def _tcp_flag_token(flags: object) -> str | None:
    if flags is None:
        return None
    if isinstance(flags, int) and not isinstance(flags, bool):
        names = [name for bit, _letter, name in _TCP_FLAG_BITS if flags & bit]
    else:
        try:
            present = {str(letter) for letter in flags}  # type: ignore[union-attr]
        except TypeError:
            present = set(str(flags))
        names = [name for _bit, letter, name in _TCP_FLAG_BITS if letter in present]
    if not names:
        return None
    token = "-".join(names)
    if len(token) > 32:
        return None
    return token


def _transport(
    ip_layer: Any, layers: _Scapy
) -> tuple[str, int | None, int | None, str | None, bool]:
    """Return protocol, ports, TCP flags, and whether the ports are unusable."""
    upper = _upper_layer(ip_layer, layers)
    if isinstance(upper, layers.tcp):
        src_port = _port_number(getattr(upper, "sport", None))
        dst_port = _port_number(getattr(upper, "dport", None))
        if src_port is None or dst_port is None:
            return "TCP", None, None, None, True
        return "TCP", src_port, dst_port, _tcp_flag_token(getattr(upper, "flags", None)), False
    if isinstance(upper, layers.udp):
        src_port = _port_number(getattr(upper, "sport", None))
        dst_port = _port_number(getattr(upper, "dport", None))
        if src_port is None or dst_port is None:
            return "UDP", None, None, None, True
        return "UDP", src_port, dst_port, None, False
    if isinstance(upper, layers.icmp) or isinstance(upper, layers.icmpv6):
        return "ICMP", None, None, None, False
    return "OTHER", None, None, None, False


def _record_from_packet(
    packet: Any, import_id: str, layers: _Scapy
) -> tuple[PacketRecord | None, str | None]:
    found = _outer_ip(packet, layers)
    if found is None:
        return None, "not-ip"
    ip_layer, version = found
    source = _normalize_ip(getattr(ip_layer, "src", ""), version)
    destination = _normalize_ip(getattr(ip_layer, "dst", ""), version)
    if source is None or destination is None:
        return None, "address"
    timestamp = _utc_timestamp(packet)
    if timestamp is None:
        return None, "timestamp"
    length = _packet_length(packet)
    if length is None:
        return None, "length"
    protocol, src_port, dst_port, tcp_flags, broken_ports = _transport(ip_layer, layers)
    if broken_ports:
        return None, "metadata"
    try:
        record = PacketRecord(
            timestamp=timestamp,
            src_ip=source,
            dst_ip=destination,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            packet_length=length,
            ip_version=version,
            tcp_flags=tcp_flags,
            import_id=import_id,
            is_simulated=False,
        )
    except (TypeError, ValueError):
        return None, "metadata"
    return record, None
