"""Shared records exchanged by analysis, storage, and the dashboard.

Packets, security events, detection rules, and alerts are stored in the
local SQLite database. None of these records store packet payloads,
passwords, command lines, or other authentication material.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Any, Mapping

SEVERITIES: tuple[str, ...] = (
    "critical",
    "high",
    "medium",
    "low",
    "informational",
)
PROTOCOLS: tuple[str, ...] = ("TCP", "UDP", "ICMP", "OTHER")
ALERT_STATUSES: tuple[str, ...] = ("open", "acknowledged", "dismissed")
EVENT_CHANNELS: tuple[str, ...] = (
    "Security",
    "System",
    "Application",
    "Sysmon",
    "simulated",
)
EVENT_OUTCOMES: tuple[str, ...] = ("success", "failure")

PACKET_COLUMNS: tuple[str, ...] = (
    "timestamp",
    "src_ip",
    "dst_ip",
    "protocol",
    "src_port",
    "dst_port",
    "packet_length",
    "ip_version",
    "tcp_flags",
    "import_id",
    "is_simulated",
)
EVENT_COLUMNS: tuple[str, ...] = (
    "event_uid",
    "timestamp",
    "channel",
    "provider",
    "event_id",
    "account_name",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "process_name",
    "process_id",
    "parent_process",
    "logon_type",
    "outcome",
    "message",
    "is_simulated",
    "record_id",
    "ingested_at",
)

_PORT_PROTOCOLS = frozenset({"TCP", "UDP"})
_RULE_KEY = re.compile(r"[a-z0-9_]{1,64}")
_MIN_PACKET_LENGTH = 1
_MAX_PACKET_LENGTH = 65535


def _require_utc(value: datetime, field_name: str) -> None:
    if not isinstance(value, datetime):
        raise ValueError(f"{field_name} must be a datetime.")
    offset = value.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        raise ValueError(f"{field_name} must be timezone-aware UTC.")


def _single_line(value: str, field_name: str, max_length: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be text.")
    stripped = value.strip()
    if not stripped:
        raise ValueError(f"{field_name} is required.")
    if len(stripped) > max_length:
        raise ValueError(f"{field_name} is too long.")
    if any(ord(character) < 32 for character in stripped):
        raise ValueError(f"{field_name} must be a single line of text.")
    return stripped


def _optional_text(value: str | None, field_name: str, max_length: int) -> str | None:
    if value is None:
        return None
    return _single_line(value, field_name, max_length)


def _check_port(port: int | None, field_name: str, *, required: bool) -> str | None:
    if port is None:
        if required:
            return f"{field_name} is required for this protocol."
        return None
    if isinstance(port, bool) or not isinstance(port, int):
        return f"{field_name} must be an integer."
    if port < 0 or port > 65535:
        return f"{field_name} must be between 0 and 65535."
    return None


def _check_ip(value: str, field_name: str, ip_version: int) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return f"{field_name} is required."
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return f"{field_name} is not a valid IP address."
    if address.version != ip_version:
        return f"{field_name} does not match IP version {ip_version}."
    return None


def _optional_ip(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} is not a valid IP address.")
    try:
        ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValueError(f"{field_name} is not a valid IP address.") from exc
    return value.strip()


def _json_mapping(value: Mapping[str, Any] | None, field_name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or isinstance(value, (str, bytes)):
        raise ValueError(f"{field_name} must be a mapping.")
    try:
        encoded = json.dumps(dict(value))
        copied = json.loads(encoded)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be JSON-compatible.") from exc
    if not isinstance(copied, dict):
        raise ValueError(f"{field_name} must be a mapping.")
    return MappingProxyType(copied)


def validate_packet_fields(
    *,
    timestamp: datetime,
    src_ip: str,
    dst_ip: str,
    protocol: str,
    src_port: int | None,
    dst_port: int | None,
    packet_length: int,
    ip_version: int,
    tcp_flags: str | None,
    import_id: str,
    is_simulated: bool,
) -> str | None:
    """Return why packet metadata cannot be stored, or None when it is usable.

    The reason is safe to log: it names the field and does not echo the
    supplied address or any packet contents.
    """
    try:
        _require_utc(timestamp, "timestamp")
    except ValueError as exc:
        return str(exc)

    if not isinstance(protocol, str) or protocol.strip().upper() not in PROTOCOLS:
        return "Protocol must be TCP, UDP, ICMP, or OTHER."
    normalized_protocol = protocol.strip().upper()

    if ip_version not in (4, 6):
        return "IP version must be 4 or 6."
    source_issue = _check_ip(src_ip, "src_ip", ip_version)
    if source_issue:
        return source_issue
    destination_issue = _check_ip(dst_ip, "dst_ip", ip_version)
    if destination_issue:
        return destination_issue

    ports_required = normalized_protocol in _PORT_PROTOCOLS
    for issue in (
        _check_port(src_port, "src_port", required=ports_required),
        _check_port(dst_port, "dst_port", required=ports_required),
    ):
        if issue:
            return issue
    if not ports_required and (src_port is not None or dst_port is not None):
        return "Ports apply only to TCP and UDP packets."

    if isinstance(packet_length, bool) or not isinstance(packet_length, int):
        return "Packet length must be an integer."
    if not _MIN_PACKET_LENGTH <= packet_length <= _MAX_PACKET_LENGTH:
        return "Packet length is outside the supported range."

    if normalized_protocol != "TCP" and tcp_flags is not None:
        return "TCP flags apply only to TCP packets."
    if tcp_flags is not None:
        if not isinstance(tcp_flags, str) or not tcp_flags.strip():
            return "TCP flags must be a non-empty string when present."
        token = tcp_flags.strip().upper()
        if len(token) > 32 or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ-" for character in token):
            return "TCP flags contain unsupported characters."

    if not isinstance(import_id, str) or not import_id.strip():
        return "Import id is required."
    if len(import_id.strip()) > 128 or any(ord(character) < 32 for character in import_id):
        return "Import id must be a single line of text."
    if not isinstance(is_simulated, bool):
        return "is_simulated must be true or false."
    return None


@dataclass(frozen=True)
class PacketRecord:
    """Metadata for one observed packet. Payload bytes are intentionally absent."""

    timestamp: datetime
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int | None
    dst_port: int | None
    packet_length: int
    ip_version: int
    tcp_flags: str | None
    import_id: str
    is_simulated: bool

    def __post_init__(self) -> None:
        protocol = self.protocol.strip().upper() if isinstance(self.protocol, str) else self.protocol
        flags = self.tcp_flags.strip().upper() if isinstance(self.tcp_flags, str) else self.tcp_flags
        source = self.src_ip.strip() if isinstance(self.src_ip, str) else self.src_ip
        destination = self.dst_ip.strip() if isinstance(self.dst_ip, str) else self.dst_ip
        import_id = self.import_id.strip() if isinstance(self.import_id, str) else self.import_id
        reason = validate_packet_fields(
            timestamp=self.timestamp,
            src_ip=source,
            dst_ip=destination,
            protocol=protocol if isinstance(protocol, str) else "",
            src_port=self.src_port,
            dst_port=self.dst_port,
            packet_length=self.packet_length,
            ip_version=self.ip_version,
            tcp_flags=flags,
            import_id=import_id if isinstance(import_id, str) else "",
            is_simulated=self.is_simulated,
        )
        if reason:
            raise ValueError(reason)
        object.__setattr__(self, "protocol", protocol)
        object.__setattr__(self, "tcp_flags", flags)
        object.__setattr__(self, "src_ip", source)
        object.__setattr__(self, "dst_ip", destination)
        object.__setattr__(self, "import_id", import_id)


@dataclass(frozen=True)
class SecurityEvent:
    """Normalized Windows or simulated security event, without secrets or command lines."""

    event_uid: str
    timestamp: datetime
    channel: str
    provider: str
    event_id: int
    account_name: str | None
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    process_name: str | None
    process_id: int | None
    parent_process: str | None
    logon_type: int | None
    outcome: str | None
    message: str
    is_simulated: bool
    record_id: int | None = None
    ingested_at: datetime | None = None

    def __post_init__(self) -> None:
        _require_utc(self.timestamp, "timestamp")
        if self.ingested_at is not None:
            _require_utc(self.ingested_at, "ingested_at")
        if self.channel not in EVENT_CHANNELS:
            raise ValueError("Channel is not a supported event source.")
        object.__setattr__(self, "provider", _single_line(self.provider, "provider", 128))
        object.__setattr__(self, "event_uid", _single_line(self.event_uid, "event_uid", 64))
        object.__setattr__(self, "message", _single_line(self.message, "message", 500))
        if isinstance(self.event_id, bool) or not isinstance(self.event_id, int) or self.event_id < 0:
            raise ValueError("Event id must be a non-negative integer.")
        if self.outcome is not None and self.outcome not in EVENT_OUTCOMES:
            raise ValueError("Outcome must be success or failure.")
        if not isinstance(self.is_simulated, bool):
            raise ValueError("is_simulated must be true or false.")
        for field_name, value in (
            ("src_port", self.src_port),
            ("dst_port", self.dst_port),
        ):
            issue = _check_port(value, field_name, required=False)
            if issue:
                raise ValueError(issue)
        object.__setattr__(self, "src_ip", _optional_ip(self.src_ip, "src_ip"))
        object.__setattr__(self, "dst_ip", _optional_ip(self.dst_ip, "dst_ip"))
        object.__setattr__(
            self, "account_name", _optional_text(self.account_name, "account_name", 128)
        )
        object.__setattr__(
            self, "process_name", _optional_text(self.process_name, "process_name", 260)
        )
        object.__setattr__(
            self, "parent_process", _optional_text(self.parent_process, "parent_process", 260)
        )
        if self.process_id is not None and (
            isinstance(self.process_id, bool) or not isinstance(self.process_id, int) or self.process_id < 0
        ):
            raise ValueError("Process id must be a non-negative integer.")
        if self.logon_type is not None and (
            isinstance(self.logon_type, bool) or not isinstance(self.logon_type, int) or self.logon_type < 0
        ):
            raise ValueError("Logon type must be a non-negative integer.")
        if self.record_id is not None and (
            isinstance(self.record_id, bool) or not isinstance(self.record_id, int) or self.record_id < 0
        ):
            raise ValueError("Record id must be a non-negative integer.")


@dataclass(frozen=True)
class DetectionRule:
    """Configurable detection definition. Parameters are JSON, not executable code."""

    rule_key: str
    name: str
    description: str
    enabled: bool
    severity: str
    parameters: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not isinstance(self.rule_key, str) or _RULE_KEY.fullmatch(self.rule_key) is None:
            raise ValueError("Rule key must use lowercase letters, digits, and underscores.")
        object.__setattr__(self, "name", _single_line(self.name, "name", 120))
        object.__setattr__(self, "description", _single_line(self.description, "description", 500))
        if not isinstance(self.enabled, bool):
            raise ValueError("enabled must be true or false.")
        if self.severity not in SEVERITIES:
            raise ValueError("Severity is not a supported category.")
        object.__setattr__(self, "parameters", _json_mapping(self.parameters, "parameters"))


@dataclass(frozen=True)
class SecurityAlert:
    """A hypothesis raised by a detection rule, with evidence references rather than payloads."""

    alert_uid: str
    created_at: datetime
    rule_key: str
    severity: str
    status: str
    src_ip: str | None
    dst_ip: str | None
    title: str
    description: str
    first_seen: datetime
    last_seen: datetime
    evidence: Mapping[str, Any]

    def __post_init__(self) -> None:
        _require_utc(self.created_at, "created_at")
        _require_utc(self.first_seen, "first_seen")
        _require_utc(self.last_seen, "last_seen")
        if self.first_seen > self.last_seen:
            raise ValueError("first_seen cannot be later than last_seen.")
        object.__setattr__(self, "alert_uid", _single_line(self.alert_uid, "alert_uid", 64))
        if not isinstance(self.rule_key, str) or _RULE_KEY.fullmatch(self.rule_key) is None:
            raise ValueError("Rule key must use lowercase letters, digits, and underscores.")
        if self.severity not in SEVERITIES:
            raise ValueError("Severity is not a supported category.")
        if self.status not in ALERT_STATUSES:
            raise ValueError("Alert status is not supported.")
        object.__setattr__(self, "src_ip", _optional_ip(self.src_ip, "src_ip"))
        object.__setattr__(self, "dst_ip", _optional_ip(self.dst_ip, "dst_ip"))
        object.__setattr__(self, "title", _single_line(self.title, "title", 160))
        object.__setattr__(self, "description", _single_line(self.description, "description", 500))
        object.__setattr__(self, "evidence", _json_mapping(self.evidence, "evidence"))
