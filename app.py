"""Local NetWatch dashboard. Bind address is loopback; see .streamlit/config.toml."""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any

import streamlit as st

from core.filters import packet_summary
from core.packet_analyzer import capture_label, describe_import, parse_pcap_bytes
from dashboard.common import active_banner, inject_styles, is_imported_capture
from dashboard.state import load_session, save_imported_packets, use_simulated_packets

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


def _ingest_capture(upload: Any) -> None:
    """Parse one uploaded capture when its contents have not been seen this session."""
    file_id = getattr(upload, "file_id", None)
    if isinstance(file_id, str) and file_id == st.session_state.get("pcap_file_id"):
        return
    raw = upload.getvalue()
    if isinstance(raw, memoryview):
        raw = raw.tobytes()
    elif isinstance(raw, bytearray):
        raw = bytes(raw)
    if not isinstance(raw, bytes):
        st.session_state.pcap_error = "The capture must be provided as bytes."
        if isinstance(file_id, str) and file_id:
            st.session_state.pcap_file_id = file_id
        LOGGER.info("Rejected uploaded capture: The capture must be provided as bytes.")
        return
    token = file_id if isinstance(file_id, str) and file_id else hashlib.sha256(raw).hexdigest()
    if token == st.session_state.get("pcap_file_id"):
        return
    result = parse_pcap_bytes(raw)
    st.session_state.pcap_file_id = token
    if result.error:
        st.session_state.pcap_error = result.error
        LOGGER.info("Rejected uploaded capture: %s", result.error)
        return
    st.session_state.pcap_error = None
    save_imported_packets(
        result.frame,
        capture_label(getattr(upload, "name", "")),
        describe_import(result),
    )
    LOGGER.info(
        "Imported capture accepted %s skipped %s truncated %s incomplete %s",
        result.accepted,
        result.skipped,
        result.truncated,
        result.incomplete,
    )


def _render_sidebar() -> None:
    """Show the packet source, the capture uploader, and the way back to fictional data."""
    with st.sidebar:
        st.markdown("### NetWatch")
        st.caption("Local-only security monitoring")
        st.caption(
            "Upload a saved PCAP or PCAPNG to inspect it here. "
            "Live capture is off. Security Events can read local Windows logs when you ask."
        )
        generation = int(st.session_state.get("upload_generation", 0))
        upload = st.file_uploader(
            "Offline capture",
            type=["pcap", "pcapng", "cap"],
            help=(
                "A saved PCAP or PCAPNG, up to 50 MB. "
                "Parsed on this computer. Payload bytes are discarded."
            ),
            key=f"pcap_upload_{generation}",
        )
        if upload is not None:
            _ingest_capture(upload)
        summary = packet_summary(st.session_state.packets)
        st.metric("Packets loaded", f"{summary.total_packets:,}")
        events = st.session_state.get("events")
        event_count = len(events) if events is not None else 0
        st.metric("Events loaded", f"{event_count:,}")
        if is_imported_capture():
            st.caption(f"Packets: {st.session_state.source_name}")
        else:
            st.caption("Packets: fictional demonstration set")
        if st.session_state.get("event_source") == "local":
            st.caption(f"Events: {st.session_state.get('event_source_name', 'Local Windows logs')}")
        else:
            st.caption("Events: fictional demonstration set")
        note = st.session_state.get("import_note")
        if isinstance(note, str) and note:
            st.caption(note)
        st.caption(active_banner())
        error = st.session_state.get("pcap_error")
        if isinstance(error, str) and error:
            st.error(error)
        if is_imported_capture() and st.button("Use simulated data"):
            use_simulated_packets()
            st.session_state.upload_generation = generation + 1
            st.session_state.pcap_file_id = None
            st.session_state.pcap_error = None
            st.rerun()


def main() -> None:
    """Render the sidebar and page navigation."""
    st.set_page_config(
        page_title="NetWatch",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    configure_logging()
    load_session()
    inject_styles()
    _render_sidebar()

    pages = [
        st.Page("dashboard/overview.py", title="Overview", default=True),
        st.Page("dashboard/network.py", title="Network Traffic"),
        st.Page("dashboard/security_events.py", title="Security Events"),
    ]
    st.navigation(pages).run()


if __name__ == "__main__":
    main()
