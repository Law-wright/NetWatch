"""Simulated security events and a read-only Windows log reader.

The fictional set uses the same UTC window and address ranges as the packet
generator. The local reader queries Windows channels with ``wevtutil`` and
keeps a short template summary. It does not copy command lines, free-text
messages, or authentication material, and it does not modify the logs.
"""

from __future__ import annotations

import ipaddress
import logging
import random
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import PureWindowsPath
from typing import Any

import pandas as pd

from core.models import EVENT_CHANNELS, EVENT_COLUMNS, EVENT_OUTCOMES, SecurityEvent
from core.sample_data import (
    DESTINATION_CHOICES,
    SAMPLE_SEED,
    SAMPLE_START,
    SAMPLE_WINDOW,
    SOURCE_CHOICES,
)

logger = logging.getLogger(__name__)

SAMPLE_EVENT_COUNT = 80
FAILED_BURST_COUNT = 8
FAILED_BURST_ACCOUNT = "demo.user"
FAILED_BURST_SOURCE = "192.0.2.25"
MAX_EVENTS_PER_CHANNEL = 200
_MAX_XML_CHARS = 8_000_000

WINDOWS_CHANNEL_NAMES: dict[str, str] = {
    "Security": "Security",
    "System": "System",
    "Application": "Application",
    "Sysmon": "Microsoft-Windows-Sysmon/Operational",
}

# Names copied out of event XML. Command lines, messages, passwords, file
# paths, and DNS queries are intentionally absent.
_DATA_NAMES = frozenset(
    {
        "TargetUserName",
        "SubjectUserName",
        "User",
        "IpAddress",
        "IpPort",
        "LogonType",
        "NewProcessName",
        "ProcessName",
        "ParentProcessName",
        "NewProcessId",
        "ProcessId",
        "Image",
        "ParentImage",
        "SourceIp",
        "DestinationIp",
        "SourcePort",
        "DestinationPort",
    }
)

_TEMPLATES: dict[tuple[str, int], str] = {
    ("Security", 4624): "Successful logon.",
    ("Security", 4625): "Failed logon.",
    ("Security", 4634): "Logoff.",
    ("Security", 4647): "User-initiated logoff.",
    ("Security", 4648): "Logon using explicit credentials.",
    ("Security", 4672): "Special privileges assigned to a new logon.",
    ("Security", 4688): "Process started.",
    ("Security", 4689): "Process exited.",
    ("Security", 4720): "User account created.",
    ("Security", 4726): "User account deleted.",
    ("Security", 1102): "Audit log was cleared.",
    ("System", 7045): "Service installed.",
    ("System", 7040): "Service start type changed.",
    ("Sysmon", 1): "Process created.",
    ("Sysmon", 3): "Network connection observed.",
    ("Sysmon", 5): "Process terminated.",
}
_OUTCOMES = {4624: "success", 4625: "failure", 4648: "success"}
_EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

_ACCOUNTS = ("demo.user", "svc.backup", "lab.admin")
_PROCESS_NAMES = ("demo-agent.exe", "backup-job.exe", "editor.exe")
_PARENT_NAMES = ("demo-service.exe", "demo-shell.exe")
_HOSTS = tuple(ip for ip, _weight in SOURCE_CHOICES)
_REMOTES = tuple(ip for ip, _weight in DESTINATION_CHOICES)
_KINDS = (
    ("logon_success", 40),
    ("logoff", 16),
    ("process", 20),
    ("network", 16),
    ("privileges", 4),
    ("service", 4),
)
_EPHEMERAL_MIN = 49152
_EPHEMERAL_MAX = 65535


@dataclass(frozen=True)
class EventFilter:
    """Filtered event rows, plus a validation message when the request is unusable."""

    frame: pd.DataFrame
    error: str | None = None


@dataclass(frozen=True)
class EventSummary:
    """Counts shown for one security-event table."""

    total_events: int
    failures: int
    unique_accounts: int
    channels: int


@dataclass(frozen=True)
class CommandResult:
    """Stdout and a short stderr excerpt from one log query."""

    returncode: int
    stdout: str
    stderr: str
    missing_tool: bool = False
    too_large: bool = False


@dataclass(frozen=True)
class ChannelRead:
    """The outcome of reading one Windows channel. Event bodies are not included."""

    channel: str
    status: str
    kept: int
    skipped: int
    detail: str
    events: tuple[SecurityEvent, ...] = ()


@dataclass(frozen=True)
class LocalLogRead:
    """Read-only results for the channels NetWatch was asked to open."""

    channels: tuple[ChannelRead, ...]

    @property
    def events(self) -> tuple[SecurityEvent, ...]:
        kept: list[SecurityEvent] = []
        for channel in self.channels:
            kept.extend(channel.events)
        return tuple(kept)


def template_messages() -> frozenset[str]:
    """Return the only summary sentences the reader and the generator emit."""
    return frozenset(_TEMPLATES.values())


def _weighted(rng: random.Random, choices: Sequence[tuple[Any, int]]) -> Any:
    total = sum(weight for _, weight in choices)
    pick = rng.randrange(total)
    cursor = 0
    for value, weight in choices:
        cursor += weight
        if pick < cursor:
            return value
    raise RuntimeError("Weighted choice failed to select a value.")


def _simulated_event(
    *,
    seed: int,
    number: int,
    moment: datetime,
    channel: str,
    provider: str,
    event_id: int,
    message: str,
    account_name: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    src_port: int | None = None,
    dst_port: int | None = None,
    process_name: str | None = None,
    process_id: int | None = None,
    parent_process: str | None = None,
    logon_type: int | None = None,
    outcome: str | None = None,
) -> SecurityEvent:
    return SecurityEvent(
        event_uid=f"sim-{seed}-{number:04d}",
        timestamp=moment,
        channel=channel,
        provider=provider,
        event_id=event_id,
        account_name=account_name,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        process_name=process_name,
        process_id=process_id,
        parent_process=parent_process,
        logon_type=logon_type,
        outcome=outcome,
        message=message,
        is_simulated=True,
        record_id=number,
        ingested_at=moment,
    )


def _background_event(rng: random.Random, seed: int, number: int) -> SecurityEvent:
    offset = rng.randrange(int(SAMPLE_WINDOW.total_seconds()))
    moment = SAMPLE_START + timedelta(seconds=offset)
    kind = _weighted(rng, _KINDS)
    account = _weighted(rng, tuple((name, 1) for name in _ACCOUNTS))
    if kind == "logon_success":
        return _simulated_event(
            seed=seed,
            number=number,
            moment=moment,
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
            event_id=4624,
            message=_TEMPLATES[("Security", 4624)],
            account_name=account,
            src_ip=_weighted(rng, tuple((ip, 1) for ip in _HOSTS)),
            logon_type=3 if rng.random() < 0.7 else 2,
            outcome="success",
        )
    if kind == "logoff":
        return _simulated_event(
            seed=seed,
            number=number,
            moment=moment,
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
            event_id=4634,
            message=_TEMPLATES[("Security", 4634)],
            account_name=account,
            src_ip=_weighted(rng, tuple((ip, 1) for ip in _HOSTS)),
        )
    if kind == "process":
        process_name = _weighted(rng, tuple((name, 1) for name in _PROCESS_NAMES))
        parent = _weighted(rng, tuple((name, 1) for name in _PARENT_NAMES))
        process_id = rng.randint(1000, 4000)
        if rng.random() < 0.5:
            return _simulated_event(
                seed=seed,
                number=number,
                moment=moment,
                channel="Sysmon",
                provider="Microsoft-Windows-Sysmon",
                event_id=1,
                message=_TEMPLATES[("Sysmon", 1)],
                account_name=account,
                process_name=process_name,
                process_id=process_id,
                parent_process=parent,
            )
        return _simulated_event(
            seed=seed,
            number=number,
            moment=moment,
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
            event_id=4688,
            message=_TEMPLATES[("Security", 4688)],
            account_name=account,
            process_name=process_name,
            process_id=process_id,
            parent_process=parent,
        )
    if kind == "network":
        return _simulated_event(
            seed=seed,
            number=number,
            moment=moment,
            channel="Sysmon",
            provider="Microsoft-Windows-Sysmon",
            event_id=3,
            message=_TEMPLATES[("Sysmon", 3)],
            account_name=account,
            src_ip=_weighted(rng, tuple((ip, 1) for ip in _HOSTS)),
            dst_ip=_weighted(rng, tuple((ip, 1) for ip in _REMOTES)),
            src_port=rng.randrange(_EPHEMERAL_MIN, _EPHEMERAL_MAX + 1),
            dst_port=443 if rng.random() < 0.75 else 53,
            process_name="demo-agent.exe",
            process_id=rng.randint(1000, 4000),
        )
    if kind == "privileges":
        return _simulated_event(
            seed=seed,
            number=number,
            moment=moment,
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
            event_id=4672,
            message=_TEMPLATES[("Security", 4672)],
            account_name=account,
        )
    return _simulated_event(
        seed=seed,
        number=number,
        moment=moment,
        channel="System",
        provider="Service Control Manager",
        event_id=7045,
        message=_TEMPLATES[("System", 7045)],
        account_name="svc.backup",
        process_name="backup-job.exe",
    )


def _failed_logon_burst(seed: int, start_number: int) -> list[SecurityEvent]:
    events: list[SecurityEvent] = []
    for offset in range(FAILED_BURST_COUNT):
        events.append(
            _simulated_event(
                seed=seed,
                number=start_number + offset,
                moment=SAMPLE_START + timedelta(minutes=12, seconds=20 * offset),
                channel="Security",
                provider="Microsoft-Windows-Security-Auditing",
                event_id=4625,
                message=_TEMPLATES[("Security", 4625)],
                account_name=FAILED_BURST_ACCOUNT,
                src_ip=FAILED_BURST_SOURCE,
                logon_type=3,
                outcome="failure",
            )
        )
    return events


def generate_security_events(
    seed: int = SAMPLE_SEED,
    count: int = SAMPLE_EVENT_COUNT,
) -> list[SecurityEvent]:
    """Return fictional security events for the same 30-minute UTC window as the packets.

    Eight of the rows are a fixed failed-logon burst. The rest follow ``seed``.
    """
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed must be an integer.")
    if isinstance(count, bool) or not isinstance(count, int) or count < FAILED_BURST_COUNT:
        raise ValueError(f"count must be an integer of at least {FAILED_BURST_COUNT}.")

    rng = random.Random(seed)
    background_count = count - FAILED_BURST_COUNT
    events = [
        _background_event(rng, seed, number)
        for number in range(1, background_count + 1)
    ]
    events.extend(_failed_logon_burst(seed, background_count + 1))
    events.sort(key=lambda event: (event.timestamp, event.event_uid))
    return events


def events_to_frame(events: Sequence[SecurityEvent]) -> pd.DataFrame:
    """Convert security events into a dataframe ordered like ``EVENT_COLUMNS``."""
    rows = [
        {
            "event_uid": event.event_uid,
            "timestamp": event.timestamp,
            "channel": event.channel,
            "provider": event.provider,
            "event_id": event.event_id,
            "account_name": event.account_name,
            "src_ip": event.src_ip,
            "dst_ip": event.dst_ip,
            "src_port": event.src_port,
            "dst_port": event.dst_port,
            "process_name": event.process_name,
            "process_id": event.process_id,
            "parent_process": event.parent_process,
            "logon_type": event.logon_type,
            "outcome": event.outcome,
            "message": event.message,
            "is_simulated": event.is_simulated,
            "record_id": event.record_id,
            "ingested_at": event.ingested_at,
        }
        for event in events
    ]
    frame = pd.DataFrame(rows, columns=list(EVENT_COLUMNS))
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True)
    frame["ingested_at"] = pd.to_datetime(frame["ingested_at"], utc=True)
    for column in ("src_port", "dst_port", "process_id", "logon_type", "record_id"):
        frame[column] = frame[column].astype("Int64")
    if not frame.empty:
        frame["event_id"] = frame["event_id"].astype("int64")
        frame["is_simulated"] = frame["is_simulated"].astype(bool)
        frame = frame.sort_values(["timestamp", "event_uid"]).reset_index(drop=True)
    return frame


def generate_event_frame(
    seed: int = SAMPLE_SEED,
    count: int = SAMPLE_EVENT_COUNT,
) -> pd.DataFrame:
    """Return the seeded demonstration events used by the dashboard and tests."""
    return events_to_frame(generate_security_events(seed=seed, count=count))


def event_summary(frame: pd.DataFrame) -> EventSummary:
    """Count events, failed outcomes, accounts, and channels."""
    if frame.empty:
        return EventSummary(0, 0, 0, 0)
    failures = int((frame["outcome"] == "failure").sum()) if "outcome" in frame.columns else 0
    accounts = (
        int(frame["account_name"].nunique(dropna=True)) if "account_name" in frame.columns else 0
    )
    channels = int(frame["channel"].nunique(dropna=True)) if "channel" in frame.columns else 0
    return EventSummary(int(len(frame)), failures, accounts, channels)


def events_over_time(frame: pd.DataFrame) -> pd.DataFrame:
    """Count events in one-minute UTC buckets, split by outcome."""
    columns = ["timestamp", "outcome", "events"]
    if frame.empty or "timestamp" not in frame.columns:
        return pd.DataFrame(columns=columns)
    working = pd.DataFrame(
        {
            "timestamp": frame["timestamp"].dt.floor("min"),
            "outcome": (
                frame["outcome"].fillna("unspecified")
                if "outcome" in frame.columns
                else "unspecified"
            ),
        }
    )
    counted = (
        working.groupby(["timestamp", "outcome"])
        .size()
        .rename("events")
        .reset_index()
    )
    return counted.sort_values(["timestamp", "outcome"]).reset_index(drop=True)


def _empty_events(frame: pd.DataFrame) -> pd.DataFrame:
    if all(column in frame.columns for column in EVENT_COLUMNS):
        return frame.iloc[0:0].copy()
    return pd.DataFrame(columns=list(EVENT_COLUMNS))


def _parse_channel(channel: str | None) -> tuple[str | None, str | None]:
    if channel is None:
        return None, None
    if not isinstance(channel, str):
        return None, "Channel is not a supported event source."
    text = channel.strip()
    if text == "":
        return None, None
    for known in EVENT_CHANNELS:
        if known.casefold() == text.casefold():
            return known, None
    return None, "Channel is not a supported event source."


def _parse_outcome(outcome: str | None) -> tuple[str | None, str | None]:
    if outcome is None:
        return None, None
    if not isinstance(outcome, str):
        return None, "Outcome must be success, failure, or unspecified."
    text = outcome.strip().casefold()
    if text == "":
        return None, None
    if text == "unspecified" or text in EVENT_OUTCOMES:
        return text, None
    return None, "Outcome must be success, failure, or unspecified."


def _parse_event_id(event_id: int | str | None) -> tuple[int | None, str | None]:
    if event_id is None:
        return None, None
    if isinstance(event_id, bool):
        return None, "Event ID must be a non-negative integer."
    if isinstance(event_id, int):
        if 0 <= event_id <= 1_000_000:
            return event_id, None
        return None, "Event ID must be a non-negative integer."
    if isinstance(event_id, str):
        text = event_id.strip()
        if text == "":
            return None, None
        if not text.isdigit():
            return None, "Event ID must be a non-negative integer."
        value = int(text)
        if value > 1_000_000:
            return None, "Event ID must be a non-negative integer."
        return value, None
    return None, "Event ID must be a non-negative integer."


def _parse_account(account: str | None) -> tuple[str | None, str | None]:
    if account is None:
        return None, None
    if not isinstance(account, str):
        return None, "Account filter must be a single line of text."
    text = account.strip()
    if text == "":
        return None, None
    if len(text) > 128 or any(ord(character) < 32 for character in text):
        logger.warning("Rejected event filter because the account text was unusable.")
        return None, "Account filter must be a single line of text."
    return text, None


def _parse_ip(ip: str | None) -> tuple[str | None, str | None]:
    if ip is None:
        return None, None
    if not isinstance(ip, str):
        return None, "Enter a valid IPv4 or IPv6 address."
    text = ip.strip()
    if text == "":
        return None, None
    try:
        return str(ipaddress.ip_address(text)), None
    except ValueError:
        logger.warning("Rejected event filter because the IP address was invalid.")
        return None, "Enter a valid IPv4 or IPv6 address."


def _parse_utc(value: datetime | None, label: str) -> tuple[pd.Timestamp | None, str | None]:
    if value is None:
        return None, None
    if not isinstance(value, datetime):
        return None, f"{label} must be a UTC datetime."
    offset = value.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        return None, f"{label} must be timezone-aware UTC."
    return pd.Timestamp(value), None


def filter_events(
    frame: pd.DataFrame,
    *,
    channel: str | None = None,
    outcome: str | None = None,
    event_id: int | str | None = None,
    account: str | None = None,
    ip: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
) -> EventFilter:
    """Keep events matching channel, outcome, id, account text, IP, and UTC time.

    Account text is a literal substring. An IP matches the source or the destination.
    Invalid input returns an empty frame and an error message.
    """
    missing = [column for column in EVENT_COLUMNS if column not in frame.columns]
    if missing:
        logger.warning("Rejected event filter because required columns were missing.")
        return EventFilter(
            pd.DataFrame(columns=list(EVENT_COLUMNS)),
            "Event table is missing required columns.",
        )

    parsed_channel, channel_error = _parse_channel(channel)
    if channel_error:
        return EventFilter(_empty_events(frame), channel_error)
    parsed_outcome, outcome_error = _parse_outcome(outcome)
    if outcome_error:
        return EventFilter(_empty_events(frame), outcome_error)
    parsed_id, id_error = _parse_event_id(event_id)
    if id_error:
        return EventFilter(_empty_events(frame), id_error)
    parsed_account, account_error = _parse_account(account)
    if account_error:
        return EventFilter(_empty_events(frame), account_error)
    parsed_ip, ip_error = _parse_ip(ip)
    if ip_error:
        return EventFilter(_empty_events(frame), ip_error)
    start_ts, start_error = _parse_utc(start, "Start")
    if start_error:
        return EventFilter(_empty_events(frame), start_error)
    end_ts, end_error = _parse_utc(end, "End")
    if end_error:
        return EventFilter(_empty_events(frame), end_error)
    if start_ts is not None and end_ts is not None and start_ts > end_ts:
        logger.warning("Rejected event filter because the time range was reversed.")
        return EventFilter(
            _empty_events(frame),
            "Start time must be earlier than or equal to the end time.",
        )

    matched = frame
    if parsed_channel is not None:
        matched = matched[matched["channel"] == parsed_channel]
    if parsed_outcome == "unspecified":
        matched = matched[matched["outcome"].isna()]
    elif parsed_outcome is not None:
        matched = matched[matched["outcome"] == parsed_outcome]
    if parsed_id is not None:
        matched = matched[matched["event_id"] == parsed_id]
    if parsed_account is not None:
        needle = parsed_account.casefold()
        accounts = matched["account_name"].fillna("").astype(str).str.casefold()
        matched = matched[accounts.str.contains(needle, regex=False)]
    if parsed_ip is not None:
        matched = matched[(matched["src_ip"] == parsed_ip) | (matched["dst_ip"] == parsed_ip)]
    if start_ts is not None:
        matched = matched[matched["timestamp"] >= start_ts]
    if end_ts is not None:
        matched = matched[matched["timestamp"] <= end_ts]
    return EventFilter(matched.copy())


def _qualified(tag: str) -> str:
    return f"{{{_EVENT_NS}}}{tag}"


def _find_child(parent: ET.Element, tag: str) -> ET.Element | None:
    child = parent.find(_qualified(tag))
    if child is None:
        child = parent.find(tag)
    return child


def _parse_system_time(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    if "." in text:
        head, tail = text.split(".", 1)
        zone_index = max(tail.find("+"), tail.find("-"))
        if zone_index == -1:
            fraction, zone = tail, ""
        else:
            fraction, zone = tail[:zone_index], tail[zone_index:]
        fraction = (fraction + "000000")[:6]
        text = f"{head}.{fraction}{zone}"
    parsed = datetime.fromisoformat(text)
    if parsed.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware UTC.")
    return parsed.astimezone(timezone.utc)


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _section_values(event: ET.Element) -> dict[str, str]:
    values: dict[str, str] = {}
    for section_name in ("EventData", "UserData"):
        section = _find_child(event, section_name)
        if section is None:
            continue
        for element in section.iter():
            name = element.attrib.get("Name") or _local_name(element.tag)
            if name not in _DATA_NAMES or name in values:
                continue
            if list(element):
                continue
            if element.text is None:
                continue
            text = element.text.strip()
            if text:
                values[name] = text
    return values


def _first(values: Mapping[str, str], names: Sequence[str]) -> str | None:
    for name in names:
        if name in values:
            return values[name]
    return None


def _account(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    if not text or text == "-":
        return None
    if "\\" in text:
        text = text.rsplit("\\", 1)[-1].strip()
    if not text or any(character.isspace() for character in text):
        return None
    if len(text) > 128:
        return None
    return text


def _basename(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip().strip('"')
    if not text or text == "-":
        return None
    name = PureWindowsPath(text).name
    if not name or name in {".", ".."}:
        return None
    if any(character.isspace() for character in name):
        return None
    if any(character in '<>:"|?*' for character in name):
        return None
    if len(name) > 128:
        return None
    return name


def _clean_ip(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    if text in {"", "-", "local", "::", "0.0.0.0"}:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _parse_int(value: str | None) -> int | None:
    if value is None:
        return None
    text = value.strip()
    if not text or text == "-":
        return None
    try:
        if text.lower().startswith("0x"):
            number = int(text, 16)
        elif text.isdigit():
            number = int(text)
        else:
            return None
    except ValueError:
        return None
    if number < 0:
        return None
    return number


def _event_from_xml(
    event: ET.Element,
    *,
    channel: str,
    ingested_at: datetime,
    seen: set[str],
) -> SecurityEvent | None:
    system = _find_child(event, "System")
    if system is None:
        return None
    event_text = None
    event_id_node = _find_child(system, "EventID")
    if event_id_node is not None and event_id_node.text:
        event_text = event_id_node.text.strip()
    if event_text is None or not event_text.isdigit():
        return None
    event_id = int(event_text)
    message = _TEMPLATES.get((channel, event_id))
    if message is None:
        return None
    record_text = None
    record_node = _find_child(system, "EventRecordID")
    if record_node is not None and record_node.text:
        record_text = record_node.text.strip()
    record_id = _parse_int(record_text)
    if record_id is None:
        return None
    event_uid = f"{channel.lower()}-{record_id}"
    if event_uid in seen:
        return None
    created = _find_child(system, "TimeCreated")
    raw_time = created.get("SystemTime") if created is not None else None
    if not raw_time:
        return None
    timestamp = _parse_system_time(raw_time)
    provider_node = _find_child(system, "Provider")
    provider = "Unknown"
    if provider_node is not None:
        provider_name = provider_node.get("Name")
        if isinstance(provider_name, str) and provider_name.strip():
            provider = provider_name.strip()

    values = _section_values(event)
    record = SecurityEvent(
        event_uid=event_uid,
        timestamp=timestamp,
        channel=channel,
        provider=provider,
        event_id=event_id,
        account_name=_account(_first(values, ("TargetUserName", "SubjectUserName", "User"))),
        src_ip=_clean_ip(_first(values, ("SourceIp", "IpAddress"))),
        dst_ip=_clean_ip(_first(values, ("DestinationIp",))),
        src_port=_parse_int(_first(values, ("SourcePort", "IpPort"))),
        dst_port=_parse_int(_first(values, ("DestinationPort",))),
        process_name=_basename(_first(values, ("NewProcessName", "Image", "ProcessName"))),
        process_id=_parse_int(_first(values, ("NewProcessId", "ProcessId"))),
        parent_process=_basename(_first(values, ("ParentProcessName", "ParentImage"))),
        logon_type=_parse_int(_first(values, ("LogonType",))),
        outcome=_OUTCOMES.get(event_id),
        message=message,
        is_simulated=False,
        record_id=record_id,
        ingested_at=ingested_at,
    )
    seen.add(event_uid)
    return record


def parse_event_xml(
    xml_text: str,
    *,
    channel: str,
    ingested_at: datetime,
    max_events: int = MAX_EVENTS_PER_CHANNEL,
) -> tuple[tuple[SecurityEvent, ...], int]:
    """Parse one channel's XML into security events and a skipped-row count.

    Summaries come from ``_TEMPLATES``. Data fields outside ``_DATA_NAMES``
    are ignored, so a command line in the XML is not stored.
    """
    if channel not in WINDOWS_CHANNEL_NAMES:
        raise ValueError("Channel is not a supported event source.")
    if isinstance(max_events, bool) or not isinstance(max_events, int) or max_events < 1:
        raise ValueError("max_events must be an integer of at least 1.")
    if not isinstance(xml_text, str):
        raise ValueError("Event XML could not be parsed.")
    if not xml_text.strip():
        return (), 0

    stripped = xml_text.replace("\ufeff", "")
    while "<?xml" in stripped:
        start = stripped.find("<?xml")
        end = stripped.find("?>", start)
        if end == -1:
            break
        stripped = stripped[:start] + stripped[end + 2 :]
    try:
        root = ET.fromstring(f"<Events>{stripped}</Events>")
    except ET.ParseError as exc:
        raise ValueError("Event XML could not be parsed.") from exc

    nodes = root.findall(_qualified("Event"))
    if not nodes:
        nodes = root.findall("Event")
    kept: list[SecurityEvent] = []
    skipped = 0
    seen: set[str] = set()
    for node in nodes:
        if len(kept) >= max_events:
            skipped += 1
            continue
        try:
            event = _event_from_xml(node, channel=channel, ingested_at=ingested_at, seen=seen)
        except (TypeError, ValueError) as exc:
            skipped += 1
            logger.warning("Skipped %s event: %s", channel, str(exc)[:200])
            continue
        if event is None:
            skipped += 1
            continue
        kept.append(event)
    return tuple(kept), skipped


def windows_query_args(channel_key: str, max_events: int) -> list[str]:
    """Build a read-only ``wevtutil`` query. The channel must be one of the known keys."""
    if channel_key not in WINDOWS_CHANNEL_NAMES:
        raise ValueError("Channel is not a supported event source.")
    if (
        isinstance(max_events, bool)
        or not isinstance(max_events, int)
        or not 1 <= max_events <= MAX_EVENTS_PER_CHANNEL
    ):
        raise ValueError(
            f"max_events must be an integer from 1 through {MAX_EVENTS_PER_CHANNEL}."
        )
    windows_name = WINDOWS_CHANNEL_NAMES[channel_key]
    return ["wevtutil", "qe", windows_name, f"/c:{max_events}", "/rd:true", "/f:xml"]


def classify_log_error(stderr: str, returncode: int) -> str:
    """Map a failed log query to missing, access_denied, or error.

    The returned word is safe to show. The raw stderr is not.
    """
    if returncode == 0:
        return "ok"
    text = stderr.casefold() if isinstance(stderr, str) else ""
    if "access is denied" in text or "access denied" in text:
        return "access_denied"
    if (
        "could not be found" in text
        or "cannot find the file" in text
        or "does not exist" in text
    ):
        return "missing"
    return "error"


def _status_detail(status: str, skipped: int) -> str:
    if status == "access_denied":
        return "Access was denied. This channel was left unread."
    if status == "missing":
        return "This channel is not available on this computer."
    if status == "error":
        return "The channel could not be read."
    if skipped:
        return f"Read completed. Skipped {skipped} events outside the supported set."
    return "Read completed."


def run_wevtutil(args: list[str]) -> CommandResult:
    """Run one allowlisted query. A missing tool or a huge response is reported, not raised."""
    if (
        not isinstance(args, list)
        or args[:2] != ["wevtutil", "qe"]
        or len(args) != 6
        or args[2] not in WINDOWS_CHANNEL_NAMES.values()
    ):
        raise ValueError("Unexpected log query.")
    creationflags = 0
    if sys.platform == "win32":
        creationflags = subprocess.CREATE_NO_WINDOW
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            check=False,
            shell=False,
            creationflags=creationflags,
        )
    except FileNotFoundError:
        return CommandResult(1, "", "wevtutil is not available.", missing_tool=True)
    except subprocess.TimeoutExpired:
        return CommandResult(1, "", "The log query timed out.")
    stdout = completed.stdout or ""
    stderr = (completed.stderr or "")[:2000]
    if len(stdout) > _MAX_XML_CHARS:
        return CommandResult(1, "", stderr, too_large=True)
    return CommandResult(completed.returncode, stdout, stderr)


def read_local_events(
    channels: Sequence[str] | None = None,
    *,
    max_events: int = MAX_EVENTS_PER_CHANNEL,
    runner: Callable[[list[str]], CommandResult] | None = None,
    ingested_at: datetime | None = None,
) -> LocalLogRead:
    """Read the requested Windows channels. Missing and denied channels are skipped.

    ``channels`` accepts only the keys in ``WINDOWS_CHANNEL_NAMES``. The default
    runner shells out to ``wevtutil`` with a fixed argument list.
    """
    selected = tuple(WINDOWS_CHANNEL_NAMES) if channels is None else tuple(channels)
    for channel in selected:
        if channel not in WINDOWS_CHANNEL_NAMES:
            raise ValueError("Channel is not a supported event source.")
    query = runner if runner is not None else run_wevtutil
    moment = ingested_at if ingested_at is not None else datetime.now(timezone.utc)
    if moment.utcoffset() is None or moment.utcoffset().total_seconds() != 0:
        raise ValueError("ingested_at must be timezone-aware UTC.")

    results: list[ChannelRead] = []
    tool_missing = False
    for channel in selected:
        if tool_missing:
            results.append(
                ChannelRead(
                    channel=channel,
                    status="error",
                    kept=0,
                    skipped=0,
                    detail="The Windows log tool is not available.",
                )
            )
            continue
        args = windows_query_args(channel, max_events)
        completed = query(args)
        if completed.missing_tool:
            tool_missing = True
            results.append(
                ChannelRead(
                    channel=channel,
                    status="error",
                    kept=0,
                    skipped=0,
                    detail="The Windows log tool is not available.",
                )
            )
            logger.info("Channel %s status error kept 0 skipped 0", channel)
            continue
        if completed.too_large:
            results.append(
                ChannelRead(
                    channel=channel,
                    status="error",
                    kept=0,
                    skipped=0,
                    detail="The log response was too large to read.",
                )
            )
            logger.info("Channel %s status error kept 0 skipped 0", channel)
            continue
        if completed.returncode != 0:
            status = classify_log_error(completed.stderr, completed.returncode)
            detail = _status_detail(status, 0)
            if status == "error" and "timed out" in completed.stderr.casefold():
                detail = "The log query timed out."
            results.append(
                ChannelRead(channel=channel, status=status, kept=0, skipped=0, detail=detail)
            )
            logger.info("Channel %s status %s kept 0 skipped 0", channel, status)
            continue
        try:
            events, skipped = parse_event_xml(
                completed.stdout,
                channel=channel,
                ingested_at=moment,
                max_events=max_events,
            )
        except ValueError:
            results.append(
                ChannelRead(
                    channel=channel,
                    status="error",
                    kept=0,
                    skipped=0,
                    detail="The channel returned data NetWatch could not parse.",
                )
            )
            logger.info("Channel %s status error kept 0 skipped 0", channel)
            continue
        results.append(
            ChannelRead(
                channel=channel,
                status="ok",
                kept=len(events),
                skipped=skipped,
                detail=_status_detail("ok", skipped),
                events=events,
            )
        )
        logger.info(
            "Channel %s status ok kept %s skipped %s",
            channel,
            len(events),
            skipped,
        )
    return LocalLogRead(channels=tuple(results))
