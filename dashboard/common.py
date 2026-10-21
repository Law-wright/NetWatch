"""Shared dashboard text, chart styling, and session-state access."""

from __future__ import annotations

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from core.models import PACKET_COLUMNS

SIMULATED_BANNER = (
    "Simulated data. These packets are fictional demonstration records, "
    "not a capture from this computer or any live network."
)
IMPORTED_BANNER = (
    "Offline capture. These rows are packet metadata parsed locally from a file "
    "you uploaded. Payloads are not stored, and NetWatch is not capturing live traffic."
)
SIMULATED_EVENT_BANNER = (
    "Simulated events. These rows are fictional demonstration records, "
    "not logs from this computer."
)
LOCAL_EVENT_BANNER = (
    "Local Windows logs. These rows were read on this computer from channels "
    "you asked NetWatch to open. Command lines and free-text messages are not stored."
)

PROTOCOL_COLORS = {
    "TCP": "#4C8DFF",
    "UDP": "#3DDC97",
    "ICMP": "#F0B429",
    "OTHER": "#8B9BB4",
}

EVENT_DISPLAY_COLUMNS: tuple[str, ...] = (
    "timestamp",
    "channel",
    "provider",
    "event_id",
    "outcome",
    "account_name",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "process_name",
    "parent_process",
    "process_id",
    "logon_type",
    "message",
    "is_simulated",
)

_DISPLAY_NAMES = {
    "timestamp": "Timestamp (UTC)",
    "src_ip": "Source IP",
    "dst_ip": "Destination IP",
    "protocol": "Protocol",
    "src_port": "Source port",
    "dst_port": "Destination port",
    "packet_length": "Length (bytes)",
    "ip_version": "IP version",
    "tcp_flags": "TCP flags",
    "import_id": "Import batch",
    "is_simulated": "Data origin",
    "channel": "Channel",
    "provider": "Provider",
    "event_id": "Event ID",
    "account_name": "Account",
    "process_name": "Process",
    "process_id": "Process ID",
    "parent_process": "Parent process",
    "logon_type": "Logon type",
    "outcome": "Outcome",
    "message": "Summary",
}


def inject_styles() -> None:
    """Apply a compact dark operations-console layout on top of the theme."""
    st.markdown(
        """
        <style>
            .netwatch-banner {
                border: 1px solid #31445c;
                background: #152033;
                color: #e6edf3;
                padding: 0.75rem 1rem;
                border-radius: 6px;
                margin-bottom: 1rem;
                line-height: 1.45;
            }
            div[data-testid="stMetric"] {
                background: #141a22;
                border: 1px solid #2a3646;
                padding: 0.7rem 0.85rem;
                border-radius: 6px;
            }
        </style>
        """,
        unsafe_allow_html=True,
    )


def is_imported_capture() -> bool:
    """True when the session table came from an uploaded capture."""
    return st.session_state.get("data_source") == "imported"


def active_banner() -> str:
    """Return the warning that matches the packet table currently loaded."""
    if is_imported_capture():
        return IMPORTED_BANNER
    return SIMULATED_BANNER


def render_banner() -> None:
    """Show the packet-origin warning at the top of a packet page."""
    st.markdown(
        f'<div class="netwatch-banner">{active_banner()}</div>',
        unsafe_allow_html=True,
    )


def is_local_events() -> bool:
    """True when the session event table was read from this computer."""
    return st.session_state.get("event_source") == "local"


def event_banner() -> str:
    """Return the warning that matches the event table currently loaded."""
    if is_local_events():
        return LOCAL_EVENT_BANNER
    return SIMULATED_EVENT_BANNER


def render_event_banner() -> None:
    """Show the event-origin warning at the top of the security-events page."""
    st.markdown(
        f'<div class="netwatch-banner">{event_banner()}</div>',
        unsafe_allow_html=True,
    )


def require_packets() -> pd.DataFrame:
    """Return the packet table loaded by the application entry point."""
    frame = st.session_state.get("packets")
    if not isinstance(frame, pd.DataFrame):
        st.error("Packet data is not loaded. Start NetWatch from app.py.")
        st.stop()
    return frame


def require_events() -> pd.DataFrame:
    """Return the event table loaded by the application entry point."""
    frame = st.session_state.get("events")
    if not isinstance(frame, pd.DataFrame):
        st.error("Security events are not loaded. Start NetWatch from app.py.")
        st.stop()
    return frame


def style_chart(figure: go.Figure, title: str, *, show_legend: bool = False) -> go.Figure:
    """Use the Plotly dark template with a transparent background."""
    figure.update_layout(
        title=dict(text=title, x=0, xanchor="left"),
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=16, r=16, t=56, b=16),
        height=360,
        showlegend=show_legend,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, x=0),
    )
    figure.update_xaxes(gridcolor="#243041", zerolinecolor="#243041")
    figure.update_yaxes(gridcolor="#243041", zerolinecolor="#243041")
    return figure


def display_packets(frame: pd.DataFrame) -> pd.DataFrame:
    """Format packet metadata for the on-screen table."""
    headers = [_DISPLAY_NAMES[column] for column in PACKET_COLUMNS]
    if frame.empty:
        return pd.DataFrame(columns=headers)

    view = frame.loc[:, list(PACKET_COLUMNS)].copy()
    view["timestamp"] = view["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    # Ports stay nullable integers. Empty strings make Arrow guess a numeric type and fail.
    view["is_simulated"] = view["is_simulated"].map({True: "Simulated", False: "Imported"})
    return view.rename(columns=_DISPLAY_NAMES)


def display_events(frame: pd.DataFrame) -> pd.DataFrame:
    """Format security events for the on-screen table."""
    headers = [_DISPLAY_NAMES[column] for column in EVENT_DISPLAY_COLUMNS]
    if frame.empty:
        return pd.DataFrame(columns=headers)

    view = frame.loc[:, list(EVENT_DISPLAY_COLUMNS)].copy()
    view["timestamp"] = view["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    for column in (
        "provider",
        "outcome",
        "account_name",
        "src_ip",
        "dst_ip",
        "process_name",
        "parent_process",
        "message",
    ):
        view[column] = view[column].fillna("")
    view["is_simulated"] = view["is_simulated"].map({True: "Simulated", False: "Local"})
    return view.rename(columns=_DISPLAY_NAMES)
