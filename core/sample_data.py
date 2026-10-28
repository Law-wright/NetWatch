"""Deterministic fictional packet metadata for the local demonstration.

Addresses come from RFC 5737 documentation networks and RFC 1918 private
networks. The generator never reads a network interface. The full
demonstration set also includes a short TCP SYN burst and a one-minute
volume increase so detection rules have a pattern to describe.
"""

from __future__ import annotations

import logging
import random
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any

import pandas as pd

from core.models import PACKET_COLUMNS, PacketRecord

logger = logging.getLogger(__name__)

SAMPLE_SEED = 42
SAMPLE_PACKET_COUNT = 800
SAMPLE_WINDOW = timedelta(minutes=30)
SAMPLE_START = datetime(2026, 1, 15, 14, 0, tzinfo=timezone.utc)

# Fixed bursts inside the demonstration window. Small fixtures below this
# size stay purely random so tests can build a handful of ordinary packets.
SCAN_SOURCE = "10.0.0.18"
SCAN_DESTINATION = "203.0.113.80"
SCAN_PORT_START = 2000
SCAN_PORT_COUNT = 20
VOLUME_SOURCE = "192.168.1.10"
VOLUME_DESTINATION = "192.0.2.10"
VOLUME_PACKET_COUNT = 80
_BURST_ROWS = SCAN_PORT_COUNT + VOLUME_PACKET_COUNT

SOURCE_CHOICES: tuple[tuple[str, int], ...] = (
    ("192.168.1.10", 30),
    ("192.168.1.20", 22),
    ("192.168.1.35", 14),
    ("10.0.0.12", 14),
    ("10.0.0.18", 12),
    ("172.16.4.8", 8),
)
DESTINATION_CHOICES: tuple[tuple[str, int], ...] = (
    ("192.0.2.10", 18),
    ("192.0.2.25", 12),
    ("198.51.100.7", 16),
    ("198.51.100.40", 10),
    ("203.0.113.15", 14),
    ("203.0.113.80", 8),
    ("192.168.1.50", 14),
    ("10.0.0.5", 8),
)
TCP_PORT_CHOICES: tuple[tuple[int, int], ...] = (
    (443, 40),
    (80, 30),
    (22, 10),
    (445, 10),
    (3389, 10),
)
UDP_PORT_CHOICES: tuple[tuple[int, int], ...] = (
    (53, 70),
    (443, 20),
    (80, 10),
)
TCP_FLAG_CHOICES: tuple[tuple[str, int], ...] = (
    ("ACK", 40),
    ("PSH-ACK", 25),
    ("SYN", 15),
    ("SYN-ACK", 10),
    ("FIN-ACK", 10),
)

_EPHEMERAL_MIN = 49152
_EPHEMERAL_MAX = 65535


def _weighted(rng: random.Random, choices: Sequence[tuple[Any, int]]) -> Any:
    total = sum(weight for _, weight in choices)
    pick = rng.randrange(total)
    cursor = 0
    for value, weight in choices:
        cursor += weight
        if pick < cursor:
            return value
    raise RuntimeError("Weighted choice failed to select a value.")


def _packet_mapping(rng: random.Random, import_id: str) -> dict[str, Any]:
    offset_seconds = rng.randrange(int(SAMPLE_WINDOW.total_seconds()))
    roll = rng.random()
    if roll < 0.72:
        protocol = "TCP"
    elif roll < 0.92:
        protocol = "UDP"
    else:
        protocol = "ICMP"

    if protocol == "TCP":
        src_port: int | None = rng.randrange(_EPHEMERAL_MIN, _EPHEMERAL_MAX + 1)
        dst_port: int | None = _weighted(rng, TCP_PORT_CHOICES)
        tcp_flags: str | None = _weighted(rng, TCP_FLAG_CHOICES)
        packet_length = rng.randint(60, 1500)
    elif protocol == "UDP":
        src_port = rng.randrange(_EPHEMERAL_MIN, _EPHEMERAL_MAX + 1)
        dst_port = _weighted(rng, UDP_PORT_CHOICES)
        tcp_flags = None
        packet_length = rng.randint(48, 512)
    else:
        src_port = None
        dst_port = None
        tcp_flags = None
        packet_length = rng.randint(60, 98)

    return {
        "timestamp": SAMPLE_START + timedelta(seconds=offset_seconds),
        "src_ip": _weighted(rng, SOURCE_CHOICES),
        "dst_ip": _weighted(rng, DESTINATION_CHOICES),
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "packet_length": packet_length,
        "ip_version": 4,
        "tcp_flags": tcp_flags,
        "import_id": import_id,
        "is_simulated": True,
    }


def packets_from_mappings(rows: Sequence[Mapping[str, Any]]) -> list[PacketRecord]:
    """Build packet records, skipping rows that fail validation.

    Invalid rows are logged by index and reason. The raw row is not logged.
    """
    records: list[PacketRecord] = []
    for index, row in enumerate(rows):
        try:
            records.append(PacketRecord(**row))
        except (TypeError, ValueError) as exc:
            logger.warning("Skipped packet row %s: %s", index, str(exc)[:200])
    return records


def _demonstration_bursts(import_id: str) -> list[dict[str, Any]]:
    """Return the SYN burst and the volume burst for a full demonstration set."""
    rows: list[dict[str, Any]] = []
    volume_start = SAMPLE_START + timedelta(minutes=6)
    for index in range(VOLUME_PACKET_COUNT):
        rows.append(
            {
                "timestamp": volume_start + timedelta(milliseconds=200 * index),
                "src_ip": VOLUME_SOURCE,
                "dst_ip": VOLUME_DESTINATION,
                "protocol": "TCP",
                "src_port": 50000 + (index % 1000),
                "dst_port": 443,
                "packet_length": 60,
                "ip_version": 4,
                "tcp_flags": "ACK",
                "import_id": import_id,
                "is_simulated": True,
            }
        )
    scan_start = SAMPLE_START + timedelta(minutes=18)
    for index in range(SCAN_PORT_COUNT):
        rows.append(
            {
                "timestamp": scan_start + timedelta(milliseconds=400 * index),
                "src_ip": SCAN_SOURCE,
                "dst_ip": SCAN_DESTINATION,
                "protocol": "TCP",
                "src_port": 52000 + index,
                "dst_port": SCAN_PORT_START + index,
                "packet_length": 60,
                "ip_version": 4,
                "tcp_flags": "SYN",
                "import_id": import_id,
                "is_simulated": True,
            }
        )
    return rows


def generate_packets(
    seed: int = SAMPLE_SEED,
    count: int = SAMPLE_PACKET_COUNT,
) -> list[PacketRecord]:
    """Return fictional packet metadata for a fixed 30-minute UTC window.

    Counts above the burst size reserve rows for a TCP SYN burst and a
    one-minute volume increase. Smaller counts are only the weighted sample.
    """
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed must be an integer.")
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        raise ValueError("count must be an integer of at least 1.")

    rng = random.Random(seed)
    import_id = f"simulated-seed-{seed}"
    if count > _BURST_ROWS:
        mappings = [_packet_mapping(rng, import_id) for _ in range(count - _BURST_ROWS)]
        mappings.extend(_demonstration_bursts(import_id))
    else:
        mappings = [_packet_mapping(rng, import_id) for _ in range(count)]
    records = packets_from_mappings(mappings)
    records.sort(key=lambda record: record.timestamp)
    if len(records) != count:
        logger.warning(
            "Simulated generator kept %s of %s rows after validation.",
            len(records),
            count,
        )
    return records


def records_to_frame(records: Sequence[PacketRecord]) -> pd.DataFrame:
    """Convert packet records into a dataframe ordered like ``PACKET_COLUMNS``."""
    rows = [
        {
            "timestamp": record.timestamp,
            "src_ip": record.src_ip,
            "dst_ip": record.dst_ip,
            "protocol": record.protocol,
            "src_port": record.src_port,
            "dst_port": record.dst_port,
            "packet_length": record.packet_length,
            "ip_version": record.ip_version,
            "tcp_flags": record.tcp_flags,
            "import_id": record.import_id,
            "is_simulated": record.is_simulated,
        }
        for record in records
    ]
    frame = pd.DataFrame(rows, columns=list(PACKET_COLUMNS))
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True)
    frame["src_port"] = frame["src_port"].astype("Int64")
    frame["dst_port"] = frame["dst_port"].astype("Int64")
    if not frame.empty:
        frame["packet_length"] = frame["packet_length"].astype("int64")
        frame["ip_version"] = frame["ip_version"].astype("int64")
        frame["is_simulated"] = frame["is_simulated"].astype(bool)
    return frame


def generate_packet_frame(
    seed: int = SAMPLE_SEED,
    count: int = SAMPLE_PACKET_COUNT,
) -> pd.DataFrame:
    """Return the seeded demonstration set used by the dashboard and tests."""
    return records_to_frame(generate_packets(seed=seed, count=count))
