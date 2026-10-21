"""Local NetWatch dashboard. Bind address is loopback; see .streamlit/config.toml."""

from __future__ import annotations

import logging
from pathlib import Path

import streamlit as st

from core.filters import packet_summary
from core.sample_data import generate_packet_frame
from dashboard.common import SIMULATED_BANNER, inject_styles, render_banner

LOGGER = logging.getLogger("netwatch")


def configure_logging() -> None:
    """Log counts and validation events to the console and a local file."""
    log_directory = Path(__file__).resolve().parent / "logs"
    log_directory.mkdir(exist_ok=True)
    root = logging.getLogger()
    if root.handlers:
        return
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(log_directory / "netwatch.log", encoding="utf-8"),
        ],
    )


def load_packets() -> None:
    """Load the seeded fictional set once per browser session."""
    if "packets" in st.session_state:
        return
    frame = generate_packet_frame()
    st.session_state.packets = frame
    st.session_state.data_source = "simulated"
    LOGGER.info("Loaded %s simulated packets", len(frame))


def main() -> None:
    """Render the banner, sidebar, and page navigation."""
    st.set_page_config(
        page_title="NetWatch",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    configure_logging()
    load_packets()
    inject_styles()
    render_banner()

    summary = packet_summary(st.session_state.packets)
    with st.sidebar:
        st.markdown("### NetWatch")
        st.caption("Local-only security monitoring")
        st.metric("Packets loaded", f"{summary.total_packets:,}")
        st.caption("Source: fictional demonstration set")
        st.caption(SIMULATED_BANNER)
        st.caption(
            "Phase 1 shows simulated network traffic. "
            "Windows event monitoring and threat detection come in later phases."
        )

    pages = [
        st.Page("dashboard/overview.py", title="Overview", default=True),
        st.Page("dashboard/network.py", title="Network Traffic"),
    ]
    st.navigation(pages).run()


if __name__ == "__main__":
    main()
