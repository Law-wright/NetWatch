"""Filterable network-traffic view for the loaded packet table."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pandas as pd
import plotly.express as px
import streamlit as st

from core.filters import filter_packets, protocol_counts, top_ips, top_ports
from core.models import PROTOCOLS
from dashboard.common import (
    PROTOCOL_COLORS,
    display_packets,
    is_imported_capture,
    render_banner,
    require_packets,
    style_chart,
)

render_banner()


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


st.header("Network Traffic")
if is_imported_capture():
    st.caption(
        "Filters apply to metadata from the uploaded capture. "
        "The table does not include payload bytes."
    )
else:
    st.caption(
        "Addresses are drawn from RFC 5737 documentation ranges and RFC 1918 private "
        "ranges. Destination ports such as 80, 443, 53, 22, 445, and 3389 are part of "
        "the fiction, along with a TCP SYN burst to ports 2000-2019 and a one-minute "
        "volume increase."
    )

source = require_packets()
if source.empty:
    st.info("No packets are loaded.")
    st.stop()

minimum, maximum = _slider_bounds(source)

filter_columns = st.columns(3)
ip_text = filter_columns[0].text_input("IP address", placeholder="192.0.2.10")
protocol_choice = filter_columns[1].selectbox("Protocol", ["All", *PROTOCOLS])
port_text = filter_columns[2].text_input("Port", placeholder="443")
selected_start, selected_end = st.slider(
    "Time range (UTC)",
    min_value=minimum,
    max_value=maximum,
    value=(minimum, maximum),
    step=timedelta(minutes=1),
)

outcome = filter_packets(
    source,
    ip=ip_text,
    protocol=None if protocol_choice == "All" else protocol_choice,
    port=port_text,
    start=selected_start.replace(tzinfo=timezone.utc),
    end=selected_end.replace(tzinfo=timezone.utc),
)

if outcome.error:
    st.error(outcome.error)
    st.stop()

st.caption(f"Showing {len(outcome.frame):,} of {len(source):,} packets.")
filtered = outcome.frame

if filtered.empty:
    st.info("No packets match these filters.")
else:
    protocol_column, port_column = st.columns(2)
    protocols = protocol_counts(filtered)
    protocol_chart = px.bar(
        protocols,
        x="protocol",
        y="packets",
        color="protocol",
        color_discrete_map=PROTOCOL_COLORS,
        template="plotly_dark",
    )
    protocol_chart.update_xaxes(title="Protocol")
    protocol_chart.update_yaxes(title="Packets")
    protocol_column.plotly_chart(
        style_chart(protocol_chart, "Traffic by protocol", show_legend=False),
        width="stretch",
    )

    ports = top_ports(filtered)
    port_chart = px.bar(
        ports,
        x="port",
        y="packets",
        template="plotly_dark",
        color_discrete_sequence=["#8B9BB4"],
    )
    port_chart.update_xaxes(title="Port", type="category")
    port_chart.update_yaxes(title="Observations")
    port_column.plotly_chart(
        style_chart(port_chart, "Most frequently observed ports"),
        width="stretch",
    )

    source_column, destination_column = st.columns(2)
    sources = top_ips(filtered, "src_ip")
    source_chart = px.bar(
        sources,
        x="packets",
        y="src_ip",
        orientation="h",
        template="plotly_dark",
        color_discrete_sequence=["#4C8DFF"],
    )
    source_chart.update_yaxes(title="", categoryorder="total ascending")
    source_chart.update_xaxes(title="Packets")
    source_column.plotly_chart(
        style_chart(source_chart, "Top source IP addresses"),
        width="stretch",
    )

    destinations = top_ips(filtered, "dst_ip")
    destination_chart = px.bar(
        destinations,
        x="packets",
        y="dst_ip",
        orientation="h",
        template="plotly_dark",
        color_discrete_sequence=["#3DDC97"],
    )
    destination_chart.update_yaxes(title="", categoryorder="total ascending")
    destination_chart.update_xaxes(title="Packets")
    destination_column.plotly_chart(
        style_chart(destination_chart, "Top destination IP addresses"),
        width="stretch",
    )

st.subheader("Packet metadata")
if is_imported_capture():
    st.caption("Metadata from the uploaded capture. Payload bytes are not stored.")
else:
    st.caption("Every row in this view is simulated. The table lists metadata only.")
st.dataframe(display_packets(filtered), width="stretch", hide_index=True)
