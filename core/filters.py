"""Pure filters and summaries for packet metadata.

These functions do not read the network, the database, or Streamlit session
state. The dashboard and the tests both call them.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from datetime import datetime

import pandas as pd

from core.models import PACKET_COLUMNS, PROTOCOLS

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class FilterOutcome:
    """Filtered packet rows, plus a validation message when the request is unusable."""

    frame: pd.DataFrame
    error: str | None = None


@dataclass(frozen=True)
class PacketSummary:
    """Counts shown on the overview for one packet table."""

    total_packets: int
    unique_src_ips: int
    unique_dst_ips: int


def _empty_like(frame: pd.DataFrame) -> pd.DataFrame:
    if all(column in frame.columns for column in PACKET_COLUMNS):
        return frame.iloc[0:0].copy()
    return pd.DataFrame(columns=list(PACKET_COLUMNS))


def _parse_port(port: int | str | None) -> tuple[int | None, str | None]:
    if port is None:
        return None, None
    if isinstance(port, bool):
        return None, "Port must be an integer from 0 through 65535."
    if isinstance(port, int):
        if 0 <= port <= 65535:
            return port, None
        return None, "Port must be an integer from 0 through 65535."
    if isinstance(port, str):
        text = port.strip()
        if text == "":
            return None, None
        if not text.isdigit():
            return None, "Port must be an integer from 0 through 65535."
        value = int(text)
        if value > 65535:
            return None, "Port must be an integer from 0 through 65535."
        return value, None
    return None, "Port must be an integer from 0 through 65535."


def _parse_protocol(protocol: str | None) -> tuple[str | None, str | None]:
    if protocol is None:
        return None, None
    if not isinstance(protocol, str):
        return None, "Protocol must be TCP, UDP, ICMP, or OTHER."
    text = protocol.strip()
    if text == "":
        return None, None
    normalized = text.upper()
    if normalized not in PROTOCOLS:
        return None, "Protocol must be TCP, UDP, ICMP, or OTHER."
    return normalized, None


def _parse_ip(ip: str | None) -> tuple[str | None, str | None]:
    if ip is None:
        return None, None
    if not isinstance(ip, str):
        return None, "Enter a valid IPv4 or IPv6 address."
    text = ip.strip()
    if text == "":
        return None, None
    try:
        return str(ipaddress.ip_address(text)), None
    except ValueError:
        logger.warning("Rejected packet filter because the IP address was invalid.")
        return None, "Enter a valid IPv4 or IPv6 address."


def _parse_utc(value: datetime | None, label: str) -> tuple[pd.Timestamp | None, str | None]:
    if value is None:
        return None, None
    if not isinstance(value, datetime):
        return None, f"{label} must be a UTC datetime."
    offset = value.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        return None, f"{label} must be timezone-aware UTC."
    return pd.Timestamp(value), None


def filter_packets(
    frame: pd.DataFrame,
    *,
    ip: str | None = None,
    protocol: str | None = None,
    port: int | str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
) -> FilterOutcome:
    """Keep packets matching an IP, protocol, port, and inclusive UTC time range.

    An IP matches the source or the destination. A port matches either side.
    Invalid input returns an empty frame and an error message.
    """
    missing = [column for column in PACKET_COLUMNS if column not in frame.columns]
    if missing:
        logger.warning("Rejected packet filter because required columns were missing.")
        return FilterOutcome(
            pd.DataFrame(columns=list(PACKET_COLUMNS)),
            "Packet table is missing required columns.",
        )

    parsed_ip, ip_error = _parse_ip(ip)
    if ip_error:
        return FilterOutcome(_empty_like(frame), ip_error)
    parsed_protocol, protocol_error = _parse_protocol(protocol)
    if protocol_error:
        return FilterOutcome(_empty_like(frame), protocol_error)
    parsed_port, port_error = _parse_port(port)
    if port_error:
        return FilterOutcome(_empty_like(frame), port_error)
    start_ts, start_error = _parse_utc(start, "Start")
    if start_error:
        return FilterOutcome(_empty_like(frame), start_error)
    end_ts, end_error = _parse_utc(end, "End")
    if end_error:
        return FilterOutcome(_empty_like(frame), end_error)
    if start_ts is not None and end_ts is not None and start_ts > end_ts:
        logger.warning("Rejected packet filter because the time range was reversed.")
        return FilterOutcome(_empty_like(frame), "Start time must be earlier than or equal to the end time.")

    matched = frame
    if parsed_ip is not None:
        matched = matched[(matched["src_ip"] == parsed_ip) | (matched["dst_ip"] == parsed_ip)]
    if parsed_protocol is not None:
        matched = matched[matched["protocol"] == parsed_protocol]
    if parsed_port is not None:
        matched = matched[(matched["src_port"] == parsed_port) | (matched["dst_port"] == parsed_port)]
    if start_ts is not None:
        matched = matched[matched["timestamp"] >= start_ts]
    if end_ts is not None:
        matched = matched[matched["timestamp"] <= end_ts]
    return FilterOutcome(matched.copy())


def packet_summary(frame: pd.DataFrame) -> PacketSummary:
    """Count packets and distinct endpoint addresses."""
    if frame.empty or "src_ip" not in frame.columns or "dst_ip" not in frame.columns:
        return PacketSummary(total_packets=0, unique_src_ips=0, unique_dst_ips=0)
    return PacketSummary(
        total_packets=int(len(frame)),
        unique_src_ips=int(frame["src_ip"].nunique(dropna=True)),
        unique_dst_ips=int(frame["dst_ip"].nunique(dropna=True)),
    )


def protocol_counts(frame: pd.DataFrame) -> pd.DataFrame:
    """Return packet totals for each observed protocol."""
    if frame.empty or "protocol" not in frame.columns:
        return pd.DataFrame(columns=["protocol", "packets"])
    return (
        frame["protocol"]
        .value_counts()
        .rename_axis("protocol")
        .reset_index(name="packets")
    )


def packets_over_time(frame: pd.DataFrame) -> pd.DataFrame:
    """Count packets in one-minute UTC buckets."""
    if frame.empty or "timestamp" not in frame.columns:
        return pd.DataFrame(columns=["timestamp", "packets"])
    counted = (
        frame.set_index("timestamp")
        .sort_index()
        .resample("1min")
        .size()
        .rename("packets")
        .reset_index()
    )
    if "timestamp" not in counted.columns:
        counted = counted.rename(columns={counted.columns[0]: "timestamp"})
    return counted


def top_ips(frame: pd.DataFrame, column: str, limit: int = 8) -> pd.DataFrame:
    """Return the most common source or destination addresses."""
    if column not in {"src_ip", "dst_ip"}:
        raise ValueError("column must be src_ip or dst_ip.")
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("limit must be an integer of at least 1.")
    if frame.empty or column not in frame.columns:
        return pd.DataFrame(columns=[column, "packets"])
    return (
        frame[column]
        .value_counts()
        .head(limit)
        .rename_axis(column)
        .reset_index(name="packets")
    )


def top_ports(frame: pd.DataFrame, limit: int = 8) -> pd.DataFrame:
    """Return the ports seen most often on either side of a packet.

    Ephemeral source ports are included. Service ports still lead the chart
    because the same destination port repeats across many packets.
    """
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("limit must be an integer of at least 1.")
    columns = ["port", "packets"]
    if frame.empty or "src_port" not in frame.columns or "dst_port" not in frame.columns:
        return pd.DataFrame(columns=columns)
    observed = pd.concat([frame["src_port"], frame["dst_port"]], ignore_index=True).dropna()
    if observed.empty:
        return pd.DataFrame(columns=columns)
    return (
        observed.astype("int64")
        .value_counts()
        .head(limit)
        .rename_axis("port")
        .reset_index(name="packets")
    )
