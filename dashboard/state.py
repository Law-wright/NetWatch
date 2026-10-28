"""Load and replace the packet and event sets kept in the local database."""

from __future__ import annotations

import logging
from typing import Any

import pandas as pd
import streamlit as st

from core.database import NetWatchStore, resolve_database_path
from core.detection_engine import (
    default_rules,
    describe_watch,
    evaluate,
    next_watch_key,
    normalize_parameters,
)
from core.log_analyzer import LocalLogRead, events_to_frame, generate_security_events
from core.models import SEVERITIES, DetectionRule
from core.sample_data import generate_packet_frame

LOGGER = logging.getLogger("netwatch")

SIMULATED_SOURCE_NAME = "Fictional demonstration set"
LOCAL_EVENT_NAME = "Local Windows logs"


def _store() -> NetWatchStore:
    return NetWatchStore(resolve_database_path())


def _refresh_if_ready() -> None:
    """Recompute findings once both tables are in the session."""
    if "packets" not in st.session_state or "events" not in st.session_state:
        return
    refresh_alerts()


def refresh_alerts() -> None:
    """Run the stored rules against the loaded tables and save the findings."""
    store = _store()
    store.ensure_rules(default_rules())
    rules = store.load_rules()
    alerts = evaluate(st.session_state.packets, st.session_state.events, rules)
    store.replace_alerts(alerts)
    st.session_state.rules = rules
    st.session_state.alerts = store.load_alerts()


def save_detection_rule(rule: DetectionRule) -> None:
    """Validate parameters, store the rule, and run detection again."""
    normalized = normalize_parameters(rule.rule_key, dict(rule.parameters))
    stored = DetectionRule(
        rule_key=rule.rule_key,
        name=rule.name,
        description=rule.description,
        enabled=rule.enabled,
        severity=rule.severity,
        parameters=normalized,
    )
    _store().save_rule(stored)
    refresh_alerts()


def add_watch_rule(
    *,
    name: str,
    severity: str,
    subject: str,
    fields: dict[str, Any],
) -> None:
    """Install one watch and run detection again."""
    if severity not in SEVERITIES:
        raise ValueError("Severity is not a supported category.")
    existing = {rule.rule_key for rule in st.session_state.get("rules", [])}
    rule_key = next_watch_key(existing)
    parameters = normalize_parameters(rule_key, {"subject": subject, **fields})
    rule = DetectionRule(
        rule_key=rule_key,
        name=name,
        description=describe_watch(parameters),
        enabled=True,
        severity=severity,
        parameters=parameters,
    )
    _store().save_rule(rule)
    refresh_alerts()


def delete_watch_rule(rule_key: str) -> None:
    """Remove a watch and run detection again."""
    _store().delete_rule(rule_key)
    refresh_alerts()


def use_simulated_packets() -> None:
    """Replace the session and the database with the seeded fictional packets."""
    frame = generate_packet_frame()
    _store().replace_packets(
        frame,
        source_kind="simulated",
        source_name=SIMULATED_SOURCE_NAME,
        note=None,
    )
    st.session_state.packets = frame
    st.session_state.data_source = "simulated"
    st.session_state.source_name = SIMULATED_SOURCE_NAME
    st.session_state.import_note = None
    LOGGER.info("Loaded %s simulated packets", len(frame))
    _refresh_if_ready()


def save_imported_packets(frame: pd.DataFrame, source_name: str, note: str | None) -> None:
    """Replace the session and the database with metadata from an uploaded capture."""
    _store().replace_packets(
        frame,
        source_kind="imported",
        source_name=source_name,
        note=note,
    )
    st.session_state.packets = frame
    st.session_state.data_source = "imported"
    st.session_state.source_name = source_name
    st.session_state.import_note = note
    _refresh_if_ready()


def use_simulated_events() -> None:
    """Replace the session and the database with the seeded fictional events."""
    frame = events_to_frame(generate_security_events())
    _store().replace_events(
        frame,
        source_kind="simulated",
        source_name=SIMULATED_SOURCE_NAME,
        note=None,
    )
    st.session_state.events = frame
    st.session_state.event_source = "simulated"
    st.session_state.event_source_name = SIMULATED_SOURCE_NAME
    st.session_state.event_note = None
    st.session_state.event_channels = None
    LOGGER.info("Loaded %s simulated security events", len(frame))
    _refresh_if_ready()


def apply_log_read(result: LocalLogRead) -> None:
    """Store a local read when it kept events. Otherwise leave the current set in place."""
    channels: list[dict[str, Any]] = [
        {
            "channel": item.channel,
            "status": item.status,
            "kept": item.kept,
            "detail": item.detail,
        }
        for item in result.channels
    ]
    if not result.events:
        st.session_state.event_channels = channels
        st.session_state.event_note = (
            "No supported events were kept. The current event set is unchanged."
        )
        LOGGER.info("Local log read kept no events")
        return
    frame = events_to_frame(result.events)
    note = (
        f"Kept {len(frame):,} events from local Windows logs. "
        "Command lines and free-text messages were not stored."
    )
    _store().replace_events(
        frame,
        source_kind="local",
        source_name=LOCAL_EVENT_NAME,
        note=note,
    )
    st.session_state.events = frame
    st.session_state.event_source = "local"
    st.session_state.event_source_name = LOCAL_EVENT_NAME
    st.session_state.event_note = note
    st.session_state.event_channels = channels
    LOGGER.info("Loaded %s local security events", len(frame))
    _refresh_if_ready()


def _load_packets() -> None:
    store = _store()
    store.initialize()
    frame = store.load_packets()
    meta = store.load_meta("packets")
    if frame.empty:
        use_simulated_packets()
        return
    kind = "simulated"
    name = SIMULATED_SOURCE_NAME
    note = None
    if meta is not None and meta.source_kind in {"simulated", "imported"}:
        kind = meta.source_kind
        name = meta.source_name
        note = meta.note
    elif not bool(frame["is_simulated"].all()):
        kind = "imported"
        name = "Saved capture"
    st.session_state.packets = frame
    st.session_state.data_source = kind
    st.session_state.source_name = name
    st.session_state.import_note = note
    LOGGER.info("Loaded %s packets from the local database", len(frame))


def _load_events() -> None:
    store = _store()
    store.initialize()
    frame = store.load_events()
    meta = store.load_meta("events")
    if frame.empty:
        use_simulated_events()
        return
    kind = "simulated"
    name = SIMULATED_SOURCE_NAME
    note = None
    if meta is not None and meta.source_kind in {"simulated", "local"}:
        kind = meta.source_kind
        name = meta.source_name
        note = meta.note
    elif not bool(frame["is_simulated"].all()):
        kind = "local"
        name = LOCAL_EVENT_NAME
    st.session_state.events = frame
    st.session_state.event_source = kind
    st.session_state.event_source_name = name
    st.session_state.event_note = note
    LOGGER.info("Loaded %s events from the local database", len(frame))


def load_session() -> None:
    """Fill session state from the local database once per browser session."""
    if "packets" not in st.session_state:
        _load_packets()
    if "events" not in st.session_state:
        _load_events()
    st.session_state.setdefault("data_source", "simulated")
    st.session_state.setdefault("source_name", SIMULATED_SOURCE_NAME)
    st.session_state.setdefault("import_note", None)
    st.session_state.setdefault("upload_generation", 0)
    st.session_state.setdefault("pcap_file_id", None)
    st.session_state.setdefault("pcap_error", None)
    st.session_state.setdefault("event_source", "simulated")
    st.session_state.setdefault("event_source_name", SIMULATED_SOURCE_NAME)
    st.session_state.setdefault("event_note", None)
    st.session_state.setdefault("event_channels", None)
    st.session_state.setdefault("watch_generation", 0)
    if "alerts" not in st.session_state:
        refresh_alerts()
