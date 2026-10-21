"""Overview of the full simulated packet set."""

from __future__ import annotations

import plotly.express as px
import streamlit as st

from core.filters import packet_summary, packets_over_time
from dashboard.common import require_packets, style_chart

st.header("Overview")
st.caption(
    "Counts describe the full fictional set. Network Traffic is where filters "
    "narrow that set. Windows events and detection alerts are not part of this phase."
)

frame = require_packets()
summary = packet_summary(frame)

total_column, source_column, destination_column = st.columns(3)
total_column.metric("Total packets analyzed", f"{summary.total_packets:,}")
source_column.metric("Unique source IP addresses", f"{summary.unique_src_ips:,}")
destination_column.metric("Unique destination IP addresses", f"{summary.unique_dst_ips:,}")

st.subheader("Packets over time")
series = packets_over_time(frame)
if series.empty:
    st.info("No packets to chart.")
else:
    chart = px.line(
        series,
        x="timestamp",
        y="packets",
        markers=True,
        template="plotly_dark",
        color_discrete_sequence=["#4C8DFF"],
    )
    chart.update_xaxes(title="Time (UTC)")
    chart.update_yaxes(title="Packets")
    st.plotly_chart(style_chart(chart, "Packets per minute (UTC)"), width="stretch")
