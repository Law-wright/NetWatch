"""Security-event view for the fictional set or an optional local Windows read."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import plotly.express as px
import streamlit as st

import core.log_analyzer as log_analyzer
from dashboard.common import (
    display_events,
    is_local_events,
    render_event_banner,
    require_events,
    style_chart,
)
from dashboard.state import apply_log_read, use_simulated_events

OUTCOME_COLORS = {
    "failure": "#E15A4A",
    "success": "#3DDC97",
    "unspecified": "#8B9BB4",
}


def _slider_bounds(frame: pd.DataFrame) -> tuple[datetime, datetime]:
    """Snap UTC timestamps outward to whole minutes so the slider step is valid."""
    earliest = frame["timestamp"].min().to_pydatetime().astimezone(timezone.utc).replace(tzinfo=None)
    latest = frame["timestamp"].max().to_pydatetime().astimezone(timezone.utc).replace(tzinfo=None)
    start = earliest.replace(second=0, microsecond=0)
    end = latest.replace(second=0, microsecond=0)
    if (latest.second, latest.microsecond) != (0, 0):
        end += timedelta(minutes=1)
    if start == end:
        end = start + timedelta(minutes=1)
    return start, end


render_event_banner()
st.header("Security Events")
if is_local_events():
    st.caption(
        "Rows come from Windows logs on this computer. "
        "The summary column is a fixed sentence, not the original message."
    )
else:
    st.caption(
        "Accounts and addresses are fictional, in the same UTC window as the packet set. "
        "A burst of failed logons is part of that fiction, not a record of this computer."
    )
note = st.session_state.get("event_note")
if isinstance(note, str) and note:
    st.caption(note)

source = require_events()
summary = log_analyzer.event_summary(source)
total_column, failure_column, account_column, channel_column = st.columns(4)
total_column.metric("Events", f"{summary.total_events:,}")
failure_column.metric("Failed outcomes", f"{summary.failures:,}")
account_column.metric("Accounts", f"{summary.unique_accounts:,}")
channel_column.metric("Channels", f"{summary.channels:,}")

st.subheader("Local Windows logs")
st.caption(
    "Reads the Security, System, Application, and Sysmon channels on this computer. "
    "A missing channel or an access denial is reported and skipped. "
    "Command lines and free-text messages are not stored."
)
if st.button("Read local Windows logs"):
    with st.spinner("Reading local Windows logs on this computer..."):
        read = log_analyzer.read_local_events()
    apply_log_read(read)
    st.rerun()
if is_local_events() and st.button("Use simulated events"):
    use_simulated_events()
    st.rerun()

channel_status = st.session_state.get("event_channels")
if isinstance(channel_status, list):
    for item in channel_status:
        if not isinstance(item, dict):
            continue
        channel_name = item.get("channel", "")
        detail = item.get("detail", "")
        kept = item.get("kept", 0)
        st.caption(f"{channel_name}: {detail} Kept {kept}.")

if source.empty:
    st.info("No security events are loaded.")
    st.stop()

minimum, maximum = _slider_bounds(source)
source_key = str(st.session_state.get("event_source", "simulated"))
filter_columns = st.columns(3)
channel_options = ["All", *sorted(str(value) for value in source["channel"].dropna().unique())]
outcome_choice = filter_columns[0].selectbox(
    "Outcome",
    ["All", "failure", "success", "unspecified"],
    key=f"event_outcome_{source_key}",
)
channel_choice = filter_columns[1].selectbox(
    "Channel",
    channel_options,
    key=f"event_channel_{source_key}",
)
event_id_options = ["All", *[str(int(value)) for value in sorted(source["event_id"].unique())]]
event_id_choice = filter_columns[2].selectbox(
    "Event ID",
    event_id_options,
    key=f"event_id_{source_key}",
)
text_columns = st.columns(2)
account_text = text_columns[0].text_input(
    "Account",
    placeholder="demo.user",
    key=f"event_account_{source_key}",
)
ip_text = text_columns[1].text_input(
    "IP address",
    placeholder="192.0.2.25",
    key=f"event_ip_{source_key}",
)
selected_start, selected_end = st.slider(
    "Time range (UTC)",
    min_value=minimum,
    max_value=maximum,
    value=(minimum, maximum),
    step=timedelta(minutes=1),
    key=f"event_time_{source_key}_{minimum.isoformat()}_{maximum.isoformat()}",
)

outcome = log_analyzer.filter_events(
    source,
    channel=None if channel_choice == "All" else channel_choice,
    outcome=None if outcome_choice == "All" else outcome_choice,
    event_id=None if event_id_choice == "All" else event_id_choice,
    account=account_text,
    ip=ip_text,
    start=selected_start.replace(tzinfo=timezone.utc),
    end=selected_end.replace(tzinfo=timezone.utc),
)
if outcome.error:
    st.error(outcome.error)
    st.stop()

st.caption(f"Showing {len(outcome.frame):,} of {len(source):,} events.")
filtered = outcome.frame

st.subheader("Events over time")
series = log_analyzer.events_over_time(filtered)
if series.empty:
    st.info("No events match these filters.")
else:
    chart = px.bar(
        series,
        x="timestamp",
        y="events",
        color="outcome",
        barmode="stack",
        color_discrete_map=OUTCOME_COLORS,
        template="plotly_dark",
    )
    chart.update_xaxes(title="Time (UTC)")
    chart.update_yaxes(title="Events")
    st.plotly_chart(
        style_chart(chart, "Events per minute (UTC)", show_legend=True),
        width="stretch",
    )

st.subheader("Event metadata")
if is_local_events():
    st.caption("Metadata from local Windows logs. Command lines are not stored.")
else:
    st.caption("Every row in this view is simulated. The summary is a fixed sentence.")
st.dataframe(display_events(filtered), width="stretch", hide_index=True)
