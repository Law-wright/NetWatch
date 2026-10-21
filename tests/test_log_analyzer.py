"""Tests for fictional security events and the read-only Windows log parser."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import pytest

from core import log_analyzer
from core.log_analyzer import (
    FAILED_BURST_ACCOUNT,
    FAILED_BURST_COUNT,
    FAILED_BURST_SOURCE,
    SAMPLE_EVENT_COUNT,
    CommandResult,
    classify_log_error,
    events_over_time,
    filter_events,
    generate_event_frame,
    generate_security_events,
    parse_event_xml,
    read_local_events,
    template_messages,
    windows_query_args,
)
from core.models import EVENT_CHANNELS, EVENT_COLUMNS
from core.sample_data import SAMPLE_START, SAMPLE_WINDOW

SECRET = "hunter2-not-stored"
_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
_INGESTED = datetime(2026, 1, 15, 15, 0, tzinfo=timezone.utc)

_DEMO_NETWORKS = (
    "192.0.2.0/24",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
)


def _in_demo_space(address: str) -> bool:
    import ipaddress

    parsed = ipaddress.ip_address(address)
    return any(parsed in ipaddress.ip_network(network) for network in _DEMO_NETWORKS)


def _event_xml(
    *,
    event_id: int,
    record_id: int,
    channel: str,
    body: str,
    when: str = "2026-01-15T14:05:00.1234567Z",
    provider: str = "Microsoft-Windows-Security-Auditing",
) -> str:
    return f"""
    <Event xmlns="{_NS}">
      <System>
        <Provider Name="{provider}"/>
        <EventID>{event_id}</EventID>
        <EventRecordID>{record_id}</EventRecordID>
        <Channel>{channel}</Channel>
        <TimeCreated SystemTime="{when}"/>
      </System>
      <EventData>
        {body}
      </EventData>
    </Event>
    """


def test_generator_contract() -> None:
    frame = generate_event_frame()

    assert list(frame.columns) == list(EVENT_COLUMNS)
    assert "command_line" not in frame.columns
    assert "payload" not in frame.columns
    assert len(frame) == SAMPLE_EVENT_COUNT
    assert frame["is_simulated"].all()
    assert frame["event_uid"].is_unique
    assert set(frame["channel"]) <= set(EVENT_CHANNELS)
    assert set(frame["message"]) <= template_messages()
    assert set(frame["account_name"].dropna()) <= {"demo.user", "svc.backup", "lab.admin"}
    assert "password" not in " ".join(frame["message"]).casefold()
    assert "command" not in " ".join(frame["message"]).casefold()

    window_end = SAMPLE_START + SAMPLE_WINDOW
    assert frame["timestamp"].min() >= pd.Timestamp(SAMPLE_START)
    assert frame["timestamp"].max() < pd.Timestamp(window_end)
    assert frame["timestamp"].is_monotonic_increasing

    addresses = pd.concat([frame["src_ip"], frame["dst_ip"]], ignore_index=True).dropna()
    assert addresses.map(_in_demo_space).all()
    processes = pd.concat([frame["process_name"], frame["parent_process"]], ignore_index=True).dropna()
    assert processes.map(lambda name: "\\" not in name and "/" not in name and " " not in name).all()

    failures = frame[frame["outcome"] == "failure"]
    assert len(failures) == FAILED_BURST_COUNT
    assert set(failures["account_name"]) == {FAILED_BURST_ACCOUNT}
    assert set(failures["src_ip"]) == {FAILED_BURST_SOURCE}
    assert set(failures["event_id"]) == {4625}


def test_generator_is_deterministic_and_rejects_bad_arguments() -> None:
    pd.testing.assert_frame_equal(generate_event_frame(), generate_event_frame())
    assert not generate_event_frame(seed=99).equals(generate_event_frame())
    with pytest.raises(ValueError):
        generate_security_events(count=FAILED_BURST_COUNT - 1)
    with pytest.raises(ValueError):
        generate_security_events(seed=True)  # type: ignore[arg-type]


def test_event_filters_and_time_buckets() -> None:
    frame = generate_event_frame()
    failed = filter_events(frame, ip=FAILED_BURST_SOURCE, outcome="failure")
    assert failed.error is None
    assert len(failed.frame) == FAILED_BURST_COUNT

    literal = filter_events(frame, account=".*")
    assert literal.error is None
    assert literal.frame.empty

    series = events_over_time(frame)
    assert int(series.loc[series["outcome"] == "failure", "events"].sum()) == FAILED_BURST_COUNT

    original = frame.copy()
    filter_events(frame, account="demo")
    pd.testing.assert_frame_equal(frame, original)


def test_event_filter_rejects_bad_input_without_echoing_it(caplog: pytest.LogCaptureFixture) -> None:
    frame = generate_event_frame()
    secret_ip = "999.1.1.1"
    with caplog.at_level(logging.WARNING, logger="core.log_analyzer"):
        outcome = filter_events(frame, ip=secret_ip)
    assert outcome.error == "Enter a valid IPv4 or IPv6 address."
    assert outcome.frame.empty
    assert secret_ip not in caplog.text

    reversed_range = filter_events(
        frame,
        start=SAMPLE_START + timedelta(minutes=5),
        end=SAMPLE_START,
    )
    assert reversed_range.error == "Start time must be earlier than or equal to the end time."


def test_parser_drops_command_lines_and_keeps_metadata() -> None:
    xml = _event_xml(
        event_id=4688,
        record_id=50,
        channel="Security",
        body=f"""
        <Data Name="SubjectUserName">LAB\\demo.user</Data>
        <Data Name="NewProcessName">C:\\Windows\\Temp\\demo-agent.exe</Data>
        <Data Name="CommandLine">demo-agent.exe --password {SECRET}</Data>
        <Data Name="NewProcessId">0x1092</Data>
        <Data Name="ParentProcessName">C:\\Program Files\\Demo\\demo-service.exe</Data>
        """,
    )
    events, skipped = parse_event_xml(xml, channel="Security", ingested_at=_INGESTED)
    assert skipped == 0
    assert len(events) == 1
    event = events[0]
    assert event.process_name == "demo-agent.exe"
    assert event.parent_process == "demo-service.exe"
    assert event.process_id == 4242
    assert event.account_name == "demo.user"
    assert event.message == "Process started."
    assert event.timestamp == datetime(2026, 1, 15, 14, 5, 0, 123456, tzinfo=timezone.utc)
    assert event.is_simulated is False
    rendered = " ".join(
        str(value) for value in (
            event.event_uid,
            event.account_name,
            event.process_name,
            event.parent_process,
            event.message,
        )
    )
    assert SECRET not in rendered
    assert "CommandLine" not in rendered


def test_parser_drops_a_command_line_stuffed_into_the_image_field() -> None:
    xml = _event_xml(
        event_id=4688,
        record_id=51,
        channel="Security",
        body=f'<Data Name="Image">C:\\Users\\Public\\demo-agent.exe --password {SECRET}</Data>',
    )
    events, skipped = parse_event_xml(xml, channel="Security", ingested_at=_INGESTED)
    assert len(events) == 1
    assert skipped == 0
    assert events[0].process_name is None
    assert SECRET not in events[0].message


def test_parser_reads_a_failed_logon_and_skips_other_ids() -> None:
    xml = _event_xml(
        event_id=4625,
        record_id=90,
        channel="Security",
        body="""
        <Data Name="TargetUserName">demo.user</Data>
        <Data Name="IpAddress">192.0.2.25</Data>
        <Data Name="IpPort">49152</Data>
        <Data Name="LogonType">3</Data>
        """,
    ) + _event_xml(event_id=1000, record_id=3, channel="Application", body="")
    events, skipped = parse_event_xml(xml, channel="Security", ingested_at=_INGESTED)
    assert len(events) == 1
    assert skipped == 1
    assert events[0].outcome == "failure"
    assert events[0].src_ip == "192.0.2.25"
    assert events[0].src_port == 49152
    assert events[0].logon_type == 3
    assert events[0].message == "Failed logon."


def test_query_args_are_a_fixed_read_only_list() -> None:
    assert windows_query_args("Sysmon", 10) == [
        "wevtutil",
        "qe",
        "Microsoft-Windows-Sysmon/Operational",
        "/c:10",
        "/rd:true",
        "/f:xml",
    ]
    with pytest.raises(ValueError):
        windows_query_args("Security & calc", 10)
    with pytest.raises(ValueError):
        windows_query_args("Security", True)  # type: ignore[arg-type]


def test_denied_or_missing_channels_are_skipped(caplog: pytest.LogCaptureFixture) -> None:
    calls: list[list[str]] = []

    def runner(args: list[str]) -> CommandResult:
        calls.append(args)
        if args[2] == "Security":
            return CommandResult(5, f"<Event>{SECRET}</Event>", "Access is denied.")
        if args[2].endswith("Operational"):
            return CommandResult(2, "", "The specified channel could not be found.")
        if args[2] == "Application":
            return CommandResult(
                0,
                _event_xml(event_id=1000, record_id=3, channel="Application", body=""),
                "",
            )
        return CommandResult(
            0,
            _event_xml(
                event_id=7045,
                record_id=42,
                channel="System",
                provider="Service Control Manager",
                body=f"<Data Name='Image'>backup-job.exe</Data><Data Name='CommandLine'>{SECRET}</Data>",
            ),
            "",
        )

    with caplog.at_level(logging.INFO, logger="core.log_analyzer"):
        result = read_local_events(runner=runner, ingested_at=_INGESTED)

    assert [args[2] for args in calls] == [
        "Security",
        "System",
        "Application",
        "Microsoft-Windows-Sysmon/Operational",
    ]
    by_channel = {item.channel: item for item in result.channels}
    assert by_channel["Security"].status == "access_denied"
    assert by_channel["Security"].events == ()
    assert by_channel["Sysmon"].status == "missing"
    assert by_channel["Application"].status == "ok"
    assert by_channel["Application"].kept == 0
    assert by_channel["Application"].skipped == 1
    assert by_channel["System"].status == "ok"
    assert by_channel["System"].kept == 1
    assert result.events[0].process_name == "backup-job.exe"
    assert result.events[0].message == "Service installed."
    assert SECRET not in caplog.text
    assert SECRET not in by_channel["Security"].detail
    assert all("/c:" in args[3] and args[1] == "qe" for args in calls)


def test_unknown_channel_is_rejected_before_the_runner() -> None:
    def runner(args: list[str]) -> CommandResult:
        raise AssertionError(args)

    with pytest.raises(ValueError, match="Channel"):
        read_local_events(["Security", "calc.exe"], runner=runner)


def test_missing_tool_stops_the_remaining_channels() -> None:
    calls: list[list[str]] = []

    def runner(args: list[str]) -> CommandResult:
        calls.append(args)
        return CommandResult(1, "", "wevtutil is not available.", missing_tool=True)

    result = read_local_events(runner=runner, ingested_at=_INGESTED)
    assert len(calls) == 1
    assert len(result.channels) == 4
    assert {item.status for item in result.channels} == {"error"}
    assert all(item.events == () for item in result.channels)


def test_unreadable_xml_does_not_raise() -> None:
    result = read_local_events(
        ["System"],
        runner=lambda args: CommandResult(0, "<not-xml", ""),
        ingested_at=_INGESTED,
    )
    assert result.channels[0].status == "error"
    assert result.channels[0].detail == "The channel returned data NetWatch could not parse."
    assert result.events == ()


def test_error_text_is_not_copied_into_the_detail(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO, logger="core.log_analyzer"):
        result = read_local_events(
            ["System"],
            runner=lambda args: CommandResult(1, "", f"boom {SECRET}"),
            ingested_at=_INGESTED,
        )
    assert result.channels[0].status == "error"
    assert result.channels[0].detail == "The channel could not be read."
    assert SECRET not in result.channels[0].detail
    assert SECRET not in caplog.text
    assert classify_log_error("Access is denied.", 5) == "access_denied"
    assert classify_log_error("The system cannot find the file specified.", 2) == "missing"


def test_reader_does_not_invoke_a_shell() -> None:
    source = Path(log_analyzer.__file__).read_text(encoding="utf-8")
    assert "shell=True" not in source
    assert "shell=False" in source
    assert log_analyzer._DATA_NAMES.isdisjoint(
        {"CommandLine", "ScriptBlockText", "Password", "Message", "QueryName", "TargetFilename"}
    )
