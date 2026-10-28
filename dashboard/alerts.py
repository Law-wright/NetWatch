"""Detection findings and the rules that produced them."""

from __future__ import annotations

from typing import Any

import pandas as pd
import plotly.express as px
import streamlit as st

from core.detection_engine import is_builtin, normalize_parameters
from core.models import EVENT_OUTCOMES, PROTOCOLS, SEVERITIES, DetectionRule, SecurityAlert
from dashboard.common import (
    ALERT_BANNER,
    SEVERITY_COLORS,
    display_alerts,
    is_imported_capture,
    is_local_events,
    require_alerts,
    require_rules,
    style_chart,
)
from dashboard.state import add_watch_rule, delete_watch_rule, refresh_alerts, save_detection_rule

_EVIDENCE_LABELS = {
    "count": "Failed logons",
    "threshold": "Threshold",
    "window_seconds": "Window (seconds)",
    "event_uids": "Event records",
    "event_uids_omitted": "Event records omitted",
    "account_name": "Account",
    "src_ip": "Source IP",
    "dst_ip": "Destination IP",
    "distinct_ports": "Distinct destination ports",
    "packet_count": "Packets",
    "ports": "Destination ports",
    "ports_omitted": "Ports omitted",
    "bucket_start": "Bucket start (UTC)",
    "bucket_seconds": "Bucket (seconds)",
    "baseline_median": "Baseline median",
    "multiplier": "Multiplier",
    "minimum_packets": "Minimum packets",
    "subject": "Watched records",
    "match_count": "Matching rows",
    "criteria": "Watch fields",
}
_CRITERIA_LABELS = {
    "src_ip": "source",
    "dst_ip": "destination",
    "protocol": "protocol",
    "dst_port": "destination port",
    "account_name": "account",
    "event_id": "event id",
    "outcome": "outcome",
}


def _evidence_text(value: Any) -> str:
    if isinstance(value, dict):
        return ", ".join(
            f"{_CRITERIA_LABELS.get(key, key)} {item}" for key, item in value.items()
        )
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    if isinstance(value, float):
        return f"{value:g}"
    return str(value)


def _evidence_frame(alert: SecurityAlert) -> pd.DataFrame:
    rows = [
        {"Field": _EVIDENCE_LABELS.get(key, key), "Value": _evidence_text(alert.evidence[key])}
        for key in alert.evidence
    ]
    return pd.DataFrame(rows, columns=["Field", "Value"])


def _origin_caption() -> str:
    packets = "uploaded capture" if is_imported_capture() else "fictional packet set"
    events = "local Windows logs" if is_local_events() else "fictional event set"
    return f"Rules run against the {packets} and the {events}."


def _save_builtin(rule: DetectionRule, enabled: bool, severity: str, parameters: dict[str, Any]) -> None:
    updated = DetectionRule(
        rule_key=rule.rule_key,
        name=rule.name,
        description=rule.description,
        enabled=enabled,
        severity=severity,
        parameters=parameters,
    )
    save_detection_rule(updated)


def _builtin_editor(rule: DetectionRule) -> None:
    try:
        current = normalize_parameters(rule.rule_key, dict(rule.parameters))
    except ValueError as exc:
        st.warning(str(exc))
        return
    enabled = st.checkbox("Enabled", value=rule.enabled, key=f"enabled_{rule.rule_key}")
    severity = st.selectbox(
        "Severity",
        SEVERITIES,
        index=SEVERITIES.index(rule.severity),
        key=f"severity_{rule.rule_key}",
    )
    parameters: dict[str, Any]
    if rule.rule_key == "failed_auth":
        threshold = st.number_input(
            "Failed logons",
            min_value=2,
            max_value=1000,
            value=int(current["threshold"]),
            step=1,
            key=f"threshold_{rule.rule_key}",
        )
        window = st.number_input(
            "Window (seconds)",
            min_value=1,
            max_value=86400,
            value=int(current["window_seconds"]),
            step=1,
            key=f"window_{rule.rule_key}",
        )
        parameters = {"threshold": int(threshold), "window_seconds": int(window)}
    elif rule.rule_key == "possible_port_scan":
        distinct = st.number_input(
            "Distinct destination ports",
            min_value=2,
            max_value=1000,
            value=int(current["distinct_ports"]),
            step=1,
            key=f"ports_{rule.rule_key}",
        )
        window = st.number_input(
            "Window (seconds)",
            min_value=1,
            max_value=86400,
            value=int(current["window_seconds"]),
            step=1,
            key=f"window_{rule.rule_key}",
        )
        parameters = {"distinct_ports": int(distinct), "window_seconds": int(window)}
    elif rule.rule_key == "volume_change":
        bucket = st.number_input(
            "Bucket (seconds)",
            min_value=10,
            max_value=3600,
            value=int(current["bucket_seconds"]),
            step=1,
            key=f"bucket_{rule.rule_key}",
        )
        multiplier = st.number_input(
            "Multiplier",
            min_value=1.5,
            max_value=100.0,
            value=float(current["multiplier"]),
            step=0.5,
            key=f"multiplier_{rule.rule_key}",
        )
        minimum = st.number_input(
            "Minimum packets",
            min_value=1,
            max_value=100000,
            value=int(current["minimum_packets"]),
            step=1,
            key=f"minimum_{rule.rule_key}",
        )
        parameters = {
            "bucket_seconds": int(bucket),
            "multiplier": float(multiplier),
            "minimum_packets": int(minimum),
        }
    else:
        st.caption("This rule has no editor.")
        return
    if st.button("Save rule", key=f"save_{rule.rule_key}"):
        try:
            _save_builtin(rule, bool(enabled), str(severity), parameters)
        except ValueError as exc:
            st.error(str(exc))
        else:
            st.rerun()


def _optional_text(label: str, key: str) -> str:
    value = st.text_input(label, key=key)
    return value.strip()


def _watch_fields(subject: str, generation: int) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    if subject == "packet":
        source = _optional_text("Source IP", f"watch_src_{generation}")
        destination = _optional_text("Destination IP", f"watch_dst_{generation}")
        protocol = st.selectbox("Protocol", ["Any", *PROTOCOLS], key=f"watch_protocol_{generation}")
        port = _optional_text("Destination port", f"watch_port_{generation}")
        if source:
            fields["src_ip"] = source
        if destination:
            fields["dst_ip"] = destination
        if protocol != "Any":
            fields["protocol"] = protocol
        if port:
            fields["dst_port"] = port
        return fields
    account = _optional_text("Account", f"watch_account_{generation}")
    source = _optional_text("Source IP", f"watch_src_{generation}")
    destination = _optional_text("Destination IP", f"watch_dst_{generation}")
    event_id = _optional_text("Event ID", f"watch_event_{generation}")
    outcome = st.selectbox("Outcome", ["Any", *EVENT_OUTCOMES], key=f"watch_outcome_{generation}")
    if account:
        fields["account_name"] = account
    if source:
        fields["src_ip"] = source
    if destination:
        fields["dst_ip"] = destination
    if event_id:
        fields["event_id"] = event_id
    if outcome != "Any":
        fields["outcome"] = outcome
    return fields


st.markdown(
    f'<div class="netwatch-banner">{ALERT_BANNER}</div>',
    unsafe_allow_html=True,
)
st.header("Alerts")
st.caption(
    "Rules look for repeated failed logons, a spread of TCP SYN ports, a sharp "
    "change in packet volume, and watches you define. The wording describes the pattern."
)
st.caption(_origin_caption())
if st.button("Run detection"):
    refresh_alerts()
    st.rerun()

rules = require_rules()
alerts = require_alerts()
enabled_rules = sum(1 for rule in rules if rule.enabled)
high_alerts = sum(1 for alert in alerts if alert.severity in {"critical", "high"})
total_column, high_column, rule_column = st.columns(3)
total_column.metric("Alerts", f"{len(alerts):,}")
high_column.metric("High or critical", f"{high_alerts:,}")
rule_column.metric("Enabled rules", f"{enabled_rules:,}")

st.subheader("Findings")
if not alerts:
    st.info("No findings for the current rules and the loaded packet and event sets.")
else:
    present = [name for name in SEVERITIES if any(alert.severity == name for alert in alerts)]
    chart_frame = pd.DataFrame(
        {
            "severity": [name.title() for name in present],
            "alerts": [sum(1 for alert in alerts if alert.severity == name) for name in present],
        }
    )
    chart = px.bar(
        chart_frame,
        x="severity",
        y="alerts",
        color="severity",
        color_discrete_map={name.title(): color for name, color in SEVERITY_COLORS.items()},
        template="plotly_dark",
    )
    chart.update_xaxes(title="Severity")
    chart.update_yaxes(title="Alerts")
    st.plotly_chart(style_chart(chart, "Findings by severity"), width="stretch")
    st.dataframe(display_alerts(alerts), width="stretch", hide_index=True)
    for alert in alerts:
        with st.expander(f"{alert.severity.title()} — {alert.title}"):
            st.write(alert.description)
            st.caption(
                f"{alert.first_seen.strftime('%Y-%m-%d %H:%M:%S')} to "
                f"{alert.last_seen.strftime('%Y-%m-%d %H:%M:%S')} UTC. "
                f"Status: {alert.status}."
            )
            st.dataframe(_evidence_frame(alert), width="stretch", hide_index=True)

st.subheader("Built-in rules")
st.caption("Turn a rule off or change its numbers. The rule text stays fixed.")
for rule in rules:
    if not is_builtin(rule.rule_key):
        continue
    label = "on" if rule.enabled else "off"
    with st.expander(f"{rule.name} ({label})"):
        st.caption(rule.description)
        _builtin_editor(rule)

st.subheader("Watch rules")
st.caption(
    "A watch raises one finding when rows match every field you set. "
    "Set only the fields that should match."
)
generation = int(st.session_state.get("watch_generation", 0))
subject_label = st.selectbox("Watch", ["Packets", "Events"], key=f"watch_subject_{generation}")
subject = "packet" if subject_label == "Packets" else "event"
name = st.text_input("Name", key=f"watch_name_{generation}")
severity = st.selectbox(
    "Severity",
    SEVERITIES,
    index=SEVERITIES.index("medium"),
    key=f"watch_severity_{generation}",
)
fields = _watch_fields(subject, generation)
if st.button("Add watch"):
    try:
        add_watch_rule(name=name, severity=str(severity), subject=subject, fields=fields)
    except ValueError as exc:
        st.error(str(exc))
    else:
        st.session_state.watch_generation = generation + 1
        st.rerun()

watches = [rule for rule in rules if not is_builtin(rule.rule_key)]
if not watches:
    st.caption("No watch rules yet.")
for rule in watches:
    state_label = "on" if rule.enabled else "off"
    st.markdown(f"**{rule.name}**")
    st.caption(f"{rule.description} Severity {rule.severity}. {state_label.capitalize()}.")
    toggle_column, delete_column = st.columns(2)
    toggle_label = "Turn off" if rule.enabled else "Turn on"
    if toggle_column.button(toggle_label, key=f"toggle_{rule.rule_key}"):
        try:
            save_detection_rule(
                DetectionRule(
                    rule_key=rule.rule_key,
                    name=rule.name,
                    description=rule.description,
                    enabled=not rule.enabled,
                    severity=rule.severity,
                    parameters=dict(rule.parameters),
                )
            )
        except ValueError as exc:
            st.error(str(exc))
        else:
            st.rerun()
    if delete_column.button("Delete", key=f"delete_{rule.rule_key}"):
        try:
            delete_watch_rule(rule.rule_key)
        except ValueError as exc:
            st.error(str(exc))
        else:
            st.rerun()
