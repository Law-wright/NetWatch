"""Rule checks over stored packet metadata and security events.

The built-in rules describe repeated failed logons, a spread of TCP SYN
ports, and a sharp change in packet volume. Watch rules match the fields
you set. Findings name counts, windows, and addresses. They do not carry
payloads, command lines, or an intrusion verdict.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import statistics
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any

import pandas as pd

from core.models import (
    EVENT_OUTCOMES,
    PROTOCOLS,
    SEVERITIES,
    DetectionRule,
    SecurityAlert,
)

logger = logging.getLogger(__name__)

BUILTIN_RULE_KEYS: tuple[str, ...] = (
    "failed_auth",
    "possible_port_scan",
    "volume_change",
)
_EVIDENCE_LIST_LIMIT = 50
_WATCH_PREFIX = "watch_"
_PACKET_WATCH_FIELDS = ("src_ip", "dst_ip", "protocol", "dst_port")
_EVENT_WATCH_FIELDS = ("src_ip", "dst_ip", "account_name", "event_id", "outcome")
_SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}

DEFAULT_RULES: tuple[DetectionRule, ...] = (
    DetectionRule(
        rule_key="failed_auth",
        name="Repeated failed authentication",
        description="Counts failed logons for the same account and source address inside a time window.",
        enabled=True,
        severity="high",
        parameters={"threshold": 5, "window_seconds": 300},
    ),
    DetectionRule(
        rule_key="possible_port_scan",
        name="Possible port scanning",
        description="Counts distinct destination ports in TCP SYN packets from one source to one host.",
        enabled=True,
        severity="medium",
        parameters={"distinct_ports": 15, "window_seconds": 60},
    ),
    DetectionRule(
        rule_key="volume_change",
        name="Packet volume change",
        description="Compares each time bucket with the median packet count of the other buckets.",
        enabled=True,
        severity="low",
        parameters={"bucket_seconds": 60, "multiplier": 3.0, "minimum_packets": 40},
    ),
)


def default_rules() -> tuple[DetectionRule, ...]:
    """Return the rules installed into a new database."""
    return DEFAULT_RULES


def is_builtin(rule_key: str) -> bool:
    """True when ``rule_key`` is one of the rules shipped with NetWatch."""
    return rule_key in BUILTIN_RULE_KEYS


def next_watch_key(existing: set[str]) -> str:
    """Return the next unused ``watch_###`` key."""
    for number in range(1, 1000):
        candidate = f"{_WATCH_PREFIX}{number:03d}"
        if candidate not in existing:
            return candidate
    raise ValueError("The watch list is full.")


def normalize_parameters(rule_key: str, parameters: Mapping[str, Any]) -> dict[str, Any]:
    """Return canonical parameters for ``rule_key`` or raise ``ValueError``.

    Messages name the field. They do not repeat the rejected address or text.
    """
    if not isinstance(parameters, Mapping) or isinstance(parameters, (str, bytes)):
        raise ValueError("parameters must be a mapping.")
    if is_builtin(rule_key):
        return _builtin_parameters(rule_key, parameters)
    if isinstance(rule_key, str) and rule_key.startswith(_WATCH_PREFIX):
        return _watch_parameters(parameters)
    raise ValueError("Custom rules use a watch_ key.")


def evaluate(
    packets: pd.DataFrame,
    events: pd.DataFrame,
    rules: Sequence[DetectionRule],
    *,
    evaluated_at: datetime | None = None,
) -> list[SecurityAlert]:
    """Run enabled rules and return findings ordered by severity."""
    if not isinstance(packets, pd.DataFrame) or not isinstance(events, pd.DataFrame):
        raise TypeError("Detection expects packet and event tables.")
    if isinstance(rules, (str, bytes)) or not isinstance(rules, Sequence):
        raise TypeError("rules must be a sequence of detection rules.")
    moment = _require_evaluated_at(evaluated_at)
    alerts: list[SecurityAlert] = []
    enabled = 0
    for rule in rules:
        if not isinstance(rule, DetectionRule):
            raise TypeError("rules must contain detection rules.")
        if not rule.enabled:
            continue
        enabled += 1
        try:
            parameters = normalize_parameters(rule.rule_key, dict(rule.parameters))
        except ValueError as exc:
            logger.warning("Skipped rule %s: %s", rule.rule_key, exc)
            continue
        alerts.extend(_run_rule(rule, parameters, packets, events, moment))
    alerts.sort(key=lambda alert: (_SEVERITY_RANK[alert.severity], -alert.last_seen.timestamp(), alert.alert_uid))
    logger.info("Detection evaluated %s rules and produced %s alerts", enabled, len(alerts))
    return alerts


def _builtin_parameters(rule_key: str, parameters: Mapping[str, Any]) -> dict[str, Any]:
    if rule_key == "failed_auth":
        return {
            "threshold": _bounded_int(parameters.get("threshold"), "threshold", 2, 1000),
            "window_seconds": _bounded_int(parameters.get("window_seconds"), "window_seconds", 1, 86400),
        }
    if rule_key == "possible_port_scan":
        return {
            "distinct_ports": _bounded_int(parameters.get("distinct_ports"), "distinct_ports", 2, 1000),
            "window_seconds": _bounded_int(parameters.get("window_seconds"), "window_seconds", 1, 86400),
        }
    if rule_key == "volume_change":
        return {
            "bucket_seconds": _bounded_int(parameters.get("bucket_seconds"), "bucket_seconds", 10, 3600),
            "multiplier": _bounded_multiplier(parameters.get("multiplier")),
            "minimum_packets": _bounded_int(
                parameters.get("minimum_packets"), "minimum_packets", 1, 100_000
            ),
        }
    raise ValueError("Rule key is not a built-in rule.")


def _watch_parameters(parameters: Mapping[str, Any]) -> dict[str, Any]:
    subject = parameters.get("subject")
    if subject == "packet":
        allowed = _PACKET_WATCH_FIELDS
    elif subject == "event":
        allowed = _EVENT_WATCH_FIELDS
    else:
        raise ValueError("Watch subject must be packet or event.")
    unknown = set(parameters) - {"subject", *allowed}
    if unknown:
        raise ValueError("Watch parameters include a field this subject does not use.")
    normalized: dict[str, Any] = {"subject": subject}
    for field in allowed:
        if field not in parameters or parameters[field] is None:
            continue
        normalized[field] = _watch_field(field, parameters[field])
    if len(normalized) == 1:
        raise ValueError("A watch needs at least one field to match.")
    return normalized


def _watch_field(field: str, value: Any) -> Any:
    if field in {"src_ip", "dst_ip"}:
        return _watch_ip(value, field)
    if field == "protocol":
        if not isinstance(value, str) or value.strip().upper() not in PROTOCOLS:
            raise ValueError("Protocol must be TCP, UDP, ICMP, or OTHER.")
        return value.strip().upper()
    if field == "outcome":
        if not isinstance(value, str) or value not in EVENT_OUTCOMES:
            raise ValueError("Outcome must be success or failure.")
        return value
    if field == "account_name":
        return _watch_text(value, "account_name", 128)
    if field in {"dst_port", "event_id"}:
        return _bounded_int(value, field, 0, 65535 if field == "dst_port" else 2_000_000_000)
    raise ValueError("Watch field is not supported.")


def _watch_ip(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} is not a valid IP address.")
    text = value.strip()
    try:
        ipaddress.ip_address(text)
    except ValueError as exc:
        raise ValueError(f"{field} is not a valid IP address.") from exc
    return text


def _watch_text(value: Any, field: str, limit: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be text.")
    stripped = value.strip()
    if not stripped or len(stripped) > limit or any(ord(character) < 32 for character in stripped):
        raise ValueError(f"{field} must be a single line of text.")
    return stripped


def _bounded_int(value: Any, field: str, low: int, high: int) -> int:
    if isinstance(value, str):
        text = value.strip()
        if not text.isdigit():
            raise ValueError(f"{field} must be an integer from {low} through {high}.")
        number = int(text)
    elif isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be an integer from {low} through {high}.")
    elif isinstance(value, float) and not value.is_integer():
        raise ValueError(f"{field} must be an integer from {low} through {high}.")
    else:
        number = int(value)
    if number < low or number > high:
        raise ValueError(f"{field} must be an integer from {low} through {high}.")
    return number


def _bounded_multiplier(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("multiplier must be a number from 1.5 through 100.")
    number = float(value)
    if number < 1.5 or number > 100:
        raise ValueError("multiplier must be a number from 1.5 through 100.")
    return number


def _require_evaluated_at(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if not isinstance(value, datetime):
        raise ValueError("evaluated_at must be a datetime.")
    offset = value.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        raise ValueError("evaluated_at must be timezone-aware UTC.")
    return value.astimezone(timezone.utc)


def _run_rule(
    rule: DetectionRule,
    parameters: Mapping[str, Any],
    packets: pd.DataFrame,
    events: pd.DataFrame,
    evaluated_at: datetime,
) -> list[SecurityAlert]:
    if rule.rule_key == "failed_auth":
        return _failed_auth(rule, parameters, events, evaluated_at)
    if rule.rule_key == "possible_port_scan":
        return _possible_port_scan(rule, parameters, packets, evaluated_at)
    if rule.rule_key == "volume_change":
        return _volume_change(rule, parameters, packets, evaluated_at)
    if rule.rule_key.startswith(_WATCH_PREFIX):
        return _watch(rule, parameters, packets, events, evaluated_at)
    logger.warning("Skipped rule %s: no evaluator", rule.rule_key)
    return []


def _failed_auth(
    rule: DetectionRule,
    parameters: Mapping[str, Any],
    events: pd.DataFrame,
    evaluated_at: datetime,
) -> list[SecurityAlert]:
    required = ("timestamp", "event_uid", "event_id", "account_name", "src_ip")
    if not _has_columns(events, required):
        logger.warning("Skipped rule %s: event table is missing required columns.", rule.rule_key)
        return []
    if events.empty:
        return []
    threshold = int(parameters["threshold"])
    window = timedelta(seconds=int(parameters["window_seconds"]))
    failed = events[events["event_id"] == 4625].copy()
    if failed.empty:
        return []
    failed["account_name"] = failed["account_name"].fillna("")
    failed["src_ip"] = failed["src_ip"].fillna("")
    alerts: list[SecurityAlert] = []
    for (account, source), group in failed.groupby(["account_name", "src_ip"], dropna=False):
        ordered = group.sort_values("timestamp")
        times = _python_times(ordered["timestamp"])
        if len(times) != len(ordered):
            continue
        found = _best_count_window(times, window, threshold)
        if found is None:
            continue
        count, left, right = found
        identifiers = [str(value) for value in ordered["event_uid"].iloc[left : right + 1].tolist()]
        listed = identifiers[:_EVIDENCE_LIST_LIMIT]
        account_text = str(account).strip()
        source_text = str(source).strip()
        evidence: dict[str, Any] = {
            "count": count,
            "threshold": threshold,
            "window_seconds": int(parameters["window_seconds"]),
            "event_uids": listed,
        }
        if len(identifiers) > len(listed):
            evidence["event_uids_omitted"] = len(identifiers) - len(listed)
        if account_text:
            evidence["account_name"] = account_text
        if source_text:
            evidence["src_ip"] = source_text
        alerts.append(
            _make_alert(
                rule=rule,
                group=f"{account_text}|{source_text}",
                evaluated_at=evaluated_at,
                src_ip=source_text or None,
                dst_ip=None,
                title=rule.name,
                description=_failed_auth_text(
                    count, account_text, source_text, int(parameters["window_seconds"])
                ),
                first_seen=times[left],
                last_seen=times[right],
                evidence=evidence,
            )
        )
    return alerts


def _failed_auth_text(count: int, account: str, source: str, window_seconds: int) -> str:
    window = f"{window_seconds} seconds"
    if account and source:
        return (
            f"{count} failed logons for {account} from {source} fell inside {window}."
        )
    if account:
        return f"{count} failed logons for {account} fell inside {window}."
    if source:
        return f"{count} failed logons from {source} fell inside {window}."
    return f"{count} failed logons fell inside {window}."


def _possible_port_scan(
    rule: DetectionRule,
    parameters: Mapping[str, Any],
    packets: pd.DataFrame,
    evaluated_at: datetime,
) -> list[SecurityAlert]:
    required = ("timestamp", "src_ip", "dst_ip", "protocol", "dst_port", "tcp_flags")
    if not _has_columns(packets, required):
        logger.warning("Skipped rule %s: packet table is missing required columns.", rule.rule_key)
        return []
    if packets.empty:
        return []
    distinct_needed = int(parameters["distinct_ports"])
    window = timedelta(seconds=int(parameters["window_seconds"]))
    flags = packets["tcp_flags"].fillna("").map(_is_syn_probe)
    probes = packets[(packets["protocol"] == "TCP") & flags & packets["dst_port"].notna()]
    if probes.empty:
        return []
    alerts: list[SecurityAlert] = []
    for (source, destination), group in probes.groupby(["src_ip", "dst_ip"], dropna=False):
        ordered = group.sort_values("timestamp")
        times = _python_times(ordered["timestamp"])
        if len(times) != len(ordered):
            continue
        ports = [int(value) for value in ordered["dst_port"].tolist()]
        found = _best_port_window(times, ports, window, distinct_needed)
        if found is None:
            continue
        distinct, left, right = found
        window_ports = ports[left : right + 1]
        unique_ports = sorted(set(window_ports))
        listed = unique_ports[:_EVIDENCE_LIST_LIMIT]
        evidence: dict[str, Any] = {
            "distinct_ports": distinct,
            "packet_count": right - left + 1,
            "ports": listed,
            "window_seconds": int(parameters["window_seconds"]),
            "src_ip": str(source),
            "dst_ip": str(destination),
        }
        if len(unique_ports) > len(listed):
            evidence["ports_omitted"] = len(unique_ports) - len(listed)
        alerts.append(
            _make_alert(
                rule=rule,
                group=f"{source}|{destination}",
                evaluated_at=evaluated_at,
                src_ip=str(source),
                dst_ip=str(destination),
                title=rule.name,
                description=(
                    f"TCP SYN packets from {source} reached {distinct} distinct "
                    f"destination ports on {destination} inside {int(parameters['window_seconds'])} seconds."
                ),
                first_seen=times[left],
                last_seen=times[right],
                evidence=evidence,
            )
        )
    return alerts


def _volume_change(
    rule: DetectionRule,
    parameters: Mapping[str, Any],
    packets: pd.DataFrame,
    evaluated_at: datetime,
) -> list[SecurityAlert]:
    if not _has_columns(packets, ("timestamp",)):
        logger.warning("Skipped rule %s: packet table is missing required columns.", rule.rule_key)
        return []
    if packets.empty:
        return []
    bucket_seconds = int(parameters["bucket_seconds"])
    multiplier = float(parameters["multiplier"])
    minimum = int(parameters["minimum_packets"])
    moments = _python_times(packets["timestamp"])
    if len(moments) != len(packets):
        usable = packets.loc[packets["timestamp"].notna()].copy()
    else:
        usable = packets
    if usable.empty:
        return []
    stamps = usable["timestamp"].map(lambda value: _bucket_floor(_as_utc(value), bucket_seconds))
    counts = stamps.value_counts().to_dict()
    if len(counts) < 3:
        return []
    alerts: list[SecurityAlert] = []
    for bucket, count in sorted(counts.items()):
        others = [value for key, value in counts.items() if key != bucket]
        baseline = float(statistics.median(others))
        if baseline <= 0 or count < minimum or count < multiplier * baseline:
            continue
        in_bucket = usable.loc[stamps == bucket, "timestamp"]
        first_seen = _as_utc(in_bucket.min())
        last_seen = _as_utc(in_bucket.max())
        baseline_number = int(baseline) if baseline.is_integer() else round(baseline, 2)
        alerts.append(
            _make_alert(
                rule=rule,
                group=bucket.isoformat(),
                evaluated_at=evaluated_at,
                src_ip=None,
                dst_ip=None,
                title=rule.name,
                description=(
                    f"A {bucket_seconds}-second bucket contained {int(count)} packets, "
                    f"at least {multiplier:g} times the median of the other buckets ({baseline_number:g})."
                ),
                first_seen=first_seen,
                last_seen=last_seen,
                evidence={
                    "bucket_start": bucket.isoformat(),
                    "bucket_seconds": bucket_seconds,
                    "packet_count": int(count),
                    "baseline_median": baseline_number,
                    "multiplier": multiplier,
                    "minimum_packets": minimum,
                },
            )
        )
    return alerts


def _watch(
    rule: DetectionRule,
    parameters: Mapping[str, Any],
    packets: pd.DataFrame,
    events: pd.DataFrame,
    evaluated_at: datetime,
) -> list[SecurityAlert]:
    subject = str(parameters["subject"])
    frame = packets if subject == "packet" else events
    criteria = {key: value for key, value in parameters.items() if key != "subject"}
    if "timestamp" not in frame.columns:
        logger.warning("Skipped rule %s: table is missing required columns.", rule.rule_key)
        return []
    matched = frame
    for field, expected in criteria.items():
        if field not in matched.columns:
            logger.warning("Skipped rule %s: table is missing required columns.", rule.rule_key)
            return []
        matched = matched[matched[field] == expected]
    if matched.empty:
        return []
    times = _python_times(matched["timestamp"])
    if not times:
        return []
    kind = "packets" if subject == "packet" else "events"
    return [
        _make_alert(
            rule=rule,
            group="matches",
            evaluated_at=evaluated_at,
            src_ip=_optional_str(criteria.get("src_ip")),
            dst_ip=_optional_str(criteria.get("dst_ip")),
            title=rule.name,
            description=f"{len(matched)} {kind} matched this watch.",
            first_seen=min(times),
            last_seen=max(times),
            evidence={
                "subject": subject,
                "match_count": int(len(matched)),
                "criteria": criteria,
            },
        )
    ]


def _make_alert(
    *,
    rule: DetectionRule,
    group: str,
    evaluated_at: datetime,
    src_ip: str | None,
    dst_ip: str | None,
    title: str,
    description: str,
    first_seen: datetime,
    last_seen: datetime,
    evidence: Mapping[str, Any],
) -> SecurityAlert:
    return SecurityAlert(
        alert_uid=_alert_uid(rule.rule_key, group),
        created_at=evaluated_at,
        rule_key=rule.rule_key,
        severity=rule.severity,
        status="open",
        src_ip=src_ip,
        dst_ip=dst_ip,
        title=title,
        description=description,
        first_seen=first_seen,
        last_seen=last_seen,
        evidence=evidence,
    )


def _alert_uid(rule_key: str, group: str) -> str:
    digest = hashlib.sha256(f"{rule_key}\n{group}".encode()).hexdigest()[:32]
    return f"a{digest}"


def _best_count_window(
    times: Sequence[datetime],
    window: timedelta,
    threshold: int,
) -> tuple[int, int, int] | None:
    best: tuple[int, int, int] | None = None
    left = 0
    for right, moment in enumerate(times):
        while moment - times[left] > window:
            left += 1
        count = right - left + 1
        if count >= threshold and (best is None or count > best[0]):
            best = (count, left, right)
    return best


def _best_port_window(
    times: Sequence[datetime],
    ports: Sequence[int],
    window: timedelta,
    threshold: int,
) -> tuple[int, int, int] | None:
    counts: Counter[int] = Counter()
    unique = 0
    left = 0
    best: tuple[int, int, int] | None = None
    for right, moment in enumerate(times):
        port = ports[right]
        counts[port] += 1
        if counts[port] == 1:
            unique += 1
        while moment - times[left] > window:
            old = ports[left]
            counts[old] -= 1
            if counts[old] == 0:
                unique -= 1
                del counts[old]
            left += 1
        if unique >= threshold and (best is None or unique > best[0]):
            best = (unique, left, right)
    return best


def _is_syn_probe(flags: object) -> bool:
    if not isinstance(flags, str):
        return False
    parts = {part for part in flags.upper().split("-") if part}
    return "SYN" in parts and "ACK" not in parts


def _bucket_floor(moment: datetime, bucket_seconds: int) -> datetime:
    epoch = int(moment.timestamp())
    floored = epoch - (epoch % bucket_seconds)
    return datetime.fromtimestamp(floored, tz=timezone.utc)


def _python_times(series: pd.Series) -> list[datetime]:
    moments: list[datetime] = []
    for value in series.tolist():
        if _missing(value):
            continue
        moments.append(_as_utc(value))
    return moments


def _as_utc(value: Any) -> datetime:
    if isinstance(value, pd.Timestamp):
        value = value.to_pydatetime()
    if not isinstance(value, datetime):
        raise ValueError("timestamp must be a datetime.")
    if value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware UTC.")
    return value.astimezone(timezone.utc)


def _missing(value: Any) -> bool:
    try:
        return bool(pd.isna(value))
    except TypeError:
        return False


def _has_columns(frame: pd.DataFrame, columns: Sequence[str]) -> bool:
    return all(column in frame.columns for column in columns)


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def describe_watch(parameters: Mapping[str, Any]) -> str:
    """Return a one-line description of the fields a watch matches."""
    subject = "packets" if parameters.get("subject") == "packet" else "events"
    labels = {
        "src_ip": "source",
        "dst_ip": "destination",
        "protocol": "protocol",
        "dst_port": "destination port",
        "account_name": "account",
        "event_id": "event id",
        "outcome": "outcome",
    }
    parts = [
        f"{label} {parameters[key]}"
        for key, label in labels.items()
        if key in parameters
    ]
    if not parts:
        return f"Matching {subject}."
    return f"Matching {subject} where " + ", ".join(parts) + "."
