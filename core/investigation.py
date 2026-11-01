"""Reconstruct related packet and event rows from a finding's evidence.

Helpers stay free of Streamlit and the database. They only filter the tables
already loaded for the dashboard. Evidence holds references (uids, addresses,
windows), not payloads or free-text messages.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import pandas as pd

from core.models import EVENT_COLUMNS, PACKET_COLUMNS, SecurityAlert

logger = logging.getLogger(__name__)

RELATED_ROW_LIMIT = 500


@dataclass(frozen=True)
class RelatedEvidence:
    """Packet and event rows that support one finding, capped for display."""

    packets: pd.DataFrame
    events: pd.DataFrame
    packet_total: int
    event_total: int
    note: str | None = None


def related_evidence(
    alert: SecurityAlert,
    packets: pd.DataFrame,
    events: pd.DataFrame,
    *,
    limit: int = RELATED_ROW_LIMIT,
) -> RelatedEvidence:
    """Return related rows for ``alert`` from the loaded packet and event sets."""
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("limit must be an integer of at least 1.")
    empty_packets = _empty_packets(packets)
    empty_events = _empty_events(events)
    rule_key = alert.rule_key
    try:
        if rule_key == "failed_auth":
            matched_events = _failed_auth_events(alert, events)
            return _pack(empty_packets, matched_events, limit)
        if rule_key == "possible_port_scan":
            matched_packets = _port_scan_packets(alert, packets)
            return _pack(matched_packets, empty_events, limit)
        if rule_key == "volume_change":
            matched_packets = _volume_packets(alert, packets)
            return _pack(matched_packets, empty_events, limit)
        if rule_key.startswith("watch_"):
            return _watch_related(alert, packets, events, limit)
    except (TypeError, ValueError) as exc:
        logger.warning("Could not rebuild evidence for %s: %s", alert.alert_uid, str(exc)[:200])
        return RelatedEvidence(
            packets=empty_packets,
            events=empty_events,
            packet_total=0,
            event_total=0,
            note="Related rows could not be rebuilt from this finding's evidence.",
        )
    return RelatedEvidence(
        packets=empty_packets,
        events=empty_events,
        packet_total=0,
        event_total=0,
        note="No related-row lookup is defined for this rule.",
    )


def _pack(packets: pd.DataFrame, events: pd.DataFrame, limit: int) -> RelatedEvidence:
    packet_total = int(len(packets))
    event_total = int(len(events))
    note = None
    if packet_total > limit or event_total > limit:
        note = f"Showing the first {limit:,} related rows of each kind."
    return RelatedEvidence(
        packets=packets.head(limit).copy(),
        events=events.head(limit).copy(),
        packet_total=packet_total,
        event_total=event_total,
        note=note,
    )


def _failed_auth_events(alert: SecurityAlert, events: pd.DataFrame) -> pd.DataFrame:
    if "event_uid" not in events.columns:
        return _empty_events(events)
    raw = alert.evidence.get("event_uids", [])
    if not isinstance(raw, list):
        return _empty_events(events)
    wanted = {str(item) for item in raw if item is not None and str(item)}
    if not wanted:
        return _empty_events(events)
    matched = events[events["event_uid"].astype(str).isin(wanted)]
    if "timestamp" in matched.columns:
        matched = matched.sort_values("timestamp")
    return matched.copy()


def _port_scan_packets(alert: SecurityAlert, packets: pd.DataFrame) -> pd.DataFrame:
    required = ("timestamp", "src_ip", "dst_ip", "protocol", "dst_port", "tcp_flags")
    if any(column not in packets.columns for column in required):
        return _empty_packets(packets)
    source = alert.evidence.get("src_ip") or alert.src_ip
    destination = alert.evidence.get("dst_ip") or alert.dst_ip
    if not isinstance(source, str) or not isinstance(destination, str):
        return _empty_packets(packets)
    ports_raw = alert.evidence.get("ports")
    port_set: set[int] | None = None
    if isinstance(ports_raw, list) and ports_raw:
        port_set = {int(port) for port in ports_raw}
    flags = packets["tcp_flags"].fillna("").map(_is_syn_probe)
    matched = packets[
        (packets["protocol"] == "TCP")
        & flags
        & (packets["src_ip"] == source)
        & (packets["dst_ip"] == destination)
    ]
    matched = _within_window(matched, alert.first_seen, alert.last_seen)
    if port_set is not None:
        matched = matched[matched["dst_port"].isin(port_set)]
    return matched.sort_values("timestamp").copy()


def _volume_packets(alert: SecurityAlert, packets: pd.DataFrame) -> pd.DataFrame:
    if "timestamp" not in packets.columns:
        return _empty_packets(packets)
    start_text = alert.evidence.get("bucket_start")
    bucket_seconds = alert.evidence.get("bucket_seconds")
    if not isinstance(start_text, str) or not isinstance(bucket_seconds, int) or bucket_seconds < 1:
        return _within_window(packets, alert.first_seen, alert.last_seen).copy()
    start = _parse_iso(start_text)
    end = start + timedelta(seconds=bucket_seconds)
    stamps = packets["timestamp"]
    matched = packets[(stamps >= start) & (stamps < end)]
    return matched.sort_values("timestamp").copy()


def _watch_related(
    alert: SecurityAlert,
    packets: pd.DataFrame,
    events: pd.DataFrame,
    limit: int,
) -> RelatedEvidence:
    subject = alert.evidence.get("subject")
    criteria = alert.evidence.get("criteria")
    if not isinstance(criteria, dict):
        return _pack(_empty_packets(packets), _empty_events(events), limit)
    if subject == "packet":
        matched = _match_criteria(packets, criteria)
        matched = _within_window(matched, alert.first_seen, alert.last_seen)
        if "timestamp" in matched.columns:
            matched = matched.sort_values("timestamp")
        return _pack(matched.copy(), _empty_events(events), limit)
    if subject == "event":
        matched = _match_criteria(events, criteria)
        matched = _within_window(matched, alert.first_seen, alert.last_seen)
        if "timestamp" in matched.columns:
            matched = matched.sort_values("timestamp")
        return _pack(_empty_packets(packets), matched.copy(), limit)
    return _pack(_empty_packets(packets), _empty_events(events), limit)


def _match_criteria(frame: pd.DataFrame, criteria: dict[str, Any]) -> pd.DataFrame:
    matched = frame
    for field, expected in criteria.items():
        if field not in matched.columns:
            return frame.iloc[0:0].copy()
        matched = matched[matched[field] == expected]
    return matched


def _within_window(frame: pd.DataFrame, first_seen: datetime, last_seen: datetime) -> pd.DataFrame:
    if frame.empty or "timestamp" not in frame.columns:
        return frame
    return frame[(frame["timestamp"] >= first_seen) & (frame["timestamp"] <= last_seen)]


def _is_syn_probe(flags: object) -> bool:
    if not isinstance(flags, str):
        return False
    parts = {part for part in flags.upper().split("-") if part}
    return "SYN" in parts and "ACK" not in parts


def _parse_iso(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    moment = datetime.fromisoformat(text)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def _empty_packets(frame: pd.DataFrame) -> pd.DataFrame:
    if all(column in frame.columns for column in PACKET_COLUMNS):
        return frame.iloc[0:0].copy()
    return pd.DataFrame(columns=list(PACKET_COLUMNS))


def _empty_events(frame: pd.DataFrame) -> pd.DataFrame:
    if all(column in frame.columns for column in EVENT_COLUMNS):
        return frame.iloc[0:0].copy()
    return pd.DataFrame(columns=list(EVENT_COLUMNS))
