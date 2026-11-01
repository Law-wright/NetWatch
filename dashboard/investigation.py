"""Alert triage and evidence review against the loaded packet and event sets."""

from __future__ import annotations

import streamlit as st

from core.investigation import related_evidence
from core.models import ALERT_STATUSES, SEVERITIES, SecurityAlert
from dashboard.common import (
    INVESTIGATION_BANNER,
    display_alerts,
    display_events,
    display_packets,
    evidence_frame,
    is_imported_capture,
    is_local_events,
    require_alerts,
    require_events,
    require_packets,
)
from dashboard.state import set_alert_status


def _origin_caption() -> str:
    packets = "uploaded capture" if is_imported_capture() else "fictional packet set"
    events = "local Windows logs" if is_local_events() else "fictional event set"
    return f"Related rows come from the {packets} and the {events}."


def _status_counts(alerts: list[SecurityAlert]) -> dict[str, int]:
    return {name: sum(1 for alert in alerts if alert.status == name) for name in ALERT_STATUSES}


def _filter_alerts(
    alerts: list[SecurityAlert],
    *,
    severity: str,
    status: str,
) -> list[SecurityAlert]:
    matched = alerts
    if severity != "All":
        matched = [alert for alert in matched if alert.severity == severity]
    if status != "All":
        matched = [alert for alert in matched if alert.status == status]
    return matched


def _label(alert: SecurityAlert) -> str:
    short = alert.alert_uid[:10]
    return f"{alert.severity.title()} — {alert.title} ({short})"


st.markdown(
    f'<div class="netwatch-banner">{INVESTIGATION_BANNER}</div>',
    unsafe_allow_html=True,
)
st.header("Investigation")
st.caption(
    "Pick a finding, change its status, and review the related packet or event "
    "rows that support it. Severity and status are labels for review on this computer."
)
st.caption(_origin_caption())

alerts = require_alerts()
packets = require_packets()
events = require_events()
counts = _status_counts(alerts)
open_column, ack_column, dismissed_column, total_column = st.columns(4)
open_column.metric("Open", f"{counts['open']:,}")
ack_column.metric("Acknowledged", f"{counts['acknowledged']:,}")
dismissed_column.metric("Dismissed", f"{counts['dismissed']:,}")
total_column.metric("Findings", f"{len(alerts):,}")

if not alerts:
    st.info("No findings to investigate. Open Alerts and run detection first.")
    st.stop()

filter_columns = st.columns(2)
severity_choice = filter_columns[0].selectbox(
    "Severity",
    ["All", *SEVERITIES],
    key="investigation_severity",
)
status_choice = filter_columns[1].selectbox(
    "Status",
    ["All", *ALERT_STATUSES],
    key="investigation_status_filter",
)
filtered = _filter_alerts(alerts, severity=str(severity_choice), status=str(status_choice))
st.dataframe(display_alerts(filtered), width="stretch", hide_index=True)

if not filtered:
    st.info("No findings match these filters.")
    st.stop()

labels = [_label(alert) for alert in filtered]
by_label = dict(zip(labels, filtered, strict=True))
selected_label = st.selectbox("Finding", labels, key="investigation_finding")
alert = by_label[selected_label]

st.subheader(alert.title)
st.write(alert.description)
st.caption(
    f"Rule `{alert.rule_key}`. "
    f"{alert.first_seen.strftime('%Y-%m-%d %H:%M:%S')} to "
    f"{alert.last_seen.strftime('%Y-%m-%d %H:%M:%S')} UTC. "
    f"Severity {alert.severity}."
)
if alert.src_ip or alert.dst_ip:
    st.caption(
        f"Source {alert.src_ip or '—'} → destination {alert.dst_ip or '—'}."
    )

status_columns = st.columns([2, 1])
new_status = status_columns[0].selectbox(
    "Triage status",
    ALERT_STATUSES,
    index=ALERT_STATUSES.index(alert.status),
    key=f"investigation_status_{alert.alert_uid}",
)
if status_columns[1].button("Save status", key=f"save_status_{alert.alert_uid}"):
    try:
        set_alert_status(alert.alert_uid, str(new_status))
    except ValueError as exc:
        st.error(str(exc))
    else:
        st.rerun()

st.subheader("Evidence")
st.dataframe(evidence_frame(alert), width="stretch", hide_index=True)

related = related_evidence(alert, packets, events)
if related.note:
    st.caption(related.note)

st.subheader("Related events")
if related.event_total == 0:
    st.caption("No related security events for this finding.")
else:
    st.caption(f"{related.event_total:,} related event rows.")
    st.dataframe(display_events(related.events), width="stretch", hide_index=True)

st.subheader("Related packets")
if related.packet_total == 0:
    st.caption("No related packets for this finding.")
else:
    st.caption(f"{related.packet_total:,} related packet rows.")
    st.dataframe(display_packets(related.packets), width="stretch", hide_index=True)
