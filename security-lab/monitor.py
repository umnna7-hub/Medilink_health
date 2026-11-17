import json
import os
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote_plus

LAB_DIR = Path(__file__).resolve().parent
BACKEND_DIR = LAB_DIR.parent / "backend"
DEFAULT_LOG_FILE = BACKEND_DIR / "app.log"
AUDIT_FILE = LAB_DIR / "vendor_audit_log.jsonl"
ALERTS_FILE = LAB_DIR / "alerts.jsonl"
FAILED_LOGIN_THRESHOLD = 5
FAILED_LOGIN_WINDOW = timedelta(minutes=5)
HTTP_429_THRESHOLD = 20
HTTP_429_WINDOW = timedelta(minutes=1)
SQL_URL_THRESHOLD = 1
SQL_URL_WINDOW = timedelta(minutes=1)
PRIVILEGED_DENIED_THRESHOLD = 3
PRIVILEGED_DENIED_WINDOW = timedelta(minutes=10)

# This rule-based prototype is a lab aid, not a SIEM.
SQL_META_PATTERN = re.compile(r"('|--|\bunion\b)", re.IGNORECASE)
AUTH_FAILURE_PATTERN = re.compile(
    r'\bAUTH_FAILURE email=("(?:\\.|[^"\\])*")'
)
HTTP_429_PATTERN = re.compile(r"\bHTTP_429 ip=(\S+)")
SQL_EVENT_PATTERN = re.compile(
    r"\bSQL_META_REQUEST ip=(\S+)\s+method=(\S+)\s+marker=(quote|comment|union)"
)
ACCESS_LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+).*?\[(?P<date>[^\]]+)\]\s+"'
    r'(?P<method>[A-Z]+)\s+(?P<target>\S+)\s+HTTP/[^"]+"\s+'
    r"(?P<status>\d{3})\b"
)
TIMESTAMP_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}"
    r"(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)
PRIVILEGED_ACTION_PATTERN = re.compile(
    r"\b(admin|database|server|privileged|configuration|credential|"
    r"permission|role|grant|revoke)\b",
    re.IGNORECASE,
)


def _as_utc(value):
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _parse_timestamp(value):
    timestamp = value.strip().replace(",", ".")
    if timestamp.endswith("Z"):
        timestamp = timestamp[:-1] + "+00:00"
    try:
        return _as_utc(datetime.fromisoformat(timestamp))
    except ValueError:
        for date_format in (
            "%d/%b/%Y:%H:%M:%S %z",
            "%d/%b/%Y %H:%M:%S",
        ):
            try:
                return _as_utc(datetime.strptime(value.strip(), date_format))
            except ValueError:
                continue
    return None


def _log_timestamp(line):
    match = TIMESTAMP_PATTERN.search(line)
    if match:
        timestamp = _parse_timestamp(match.group("timestamp"))
        if timestamp:
            return timestamp

    access_match = ACCESS_LOG_PATTERN.search(line)
    if access_match:
        return _parse_timestamp(access_match.group("date"))
    return None


def _sql_marker(target):
    match = SQL_META_PATTERN.search(unquote_plus(target))
    if not match:
        return None
    marker = match.group(0).lower()
    return {"'": "quote", "--": "comment"}.get(marker, marker)


def _read_flask_events(log_file):
    failed_logins = []
    rate_limits = []
    sql_requests = []

    with log_file.open("r", encoding="utf-8") as file:
        for line in file:
            timestamp = _log_timestamp(line)
            if timestamp is None:
                continue

            auth_match = AUTH_FAILURE_PATTERN.search(line)
            if auth_match:
                email = json.loads(auth_match.group(1))
                if isinstance(email, str):
                    failed_logins.append((timestamp, email))

            rate_match = HTTP_429_PATTERN.search(line)
            if rate_match:
                rate_limits.append((timestamp, rate_match.group(1)))

            sql_match = SQL_EVENT_PATTERN.search(line)
            if sql_match:
                sql_requests.append(
                    (
                        timestamp,
                        sql_match.group(1),
                        sql_match.group(2),
                        sql_match.group(3),
                    )
                )

            access_match = ACCESS_LOG_PATTERN.search(line)
            if access_match:
                ip = access_match.group("ip")
                if access_match.group("status") == "429":
                    rate_limits.append((timestamp, ip))
                marker = _sql_marker(access_match.group("target"))
                if marker:
                    sql_requests.append(
                        (
                            timestamp,
                            ip,
                            access_match.group("method"),
                            marker,
                        )
                    )

    return failed_logins, rate_limits, sql_requests


def _read_audit_events(audit_file):
    events = []
    with audit_file.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"Invalid audit JSON at {audit_file}:{line_number}"
                ) from error

            if not isinstance(record, dict):
                raise ValueError(
                    f"Invalid audit record at {audit_file}:{line_number}"
                )
            timestamp_value = record.get("timestamp")
            action = record.get("action")
            decision = record.get("decision")
            vendor_id = record.get("vendor_id")
            timestamp = (
                _parse_timestamp(timestamp_value)
                if isinstance(timestamp_value, str)
                else None
            )
            if (
                timestamp is None
                or not isinstance(action, str)
                or not isinstance(decision, str)
                or not isinstance(vendor_id, str)
            ):
                raise ValueError(
                    f"Incomplete audit record at {audit_file}:{line_number}"
                )
            events.append((timestamp, vendor_id, action, decision))
    return events


def _recent_events(events, now, window):
    start = now - window
    return [
        event for event in events
        if start <= event[0] <= now
    ]


def _alert(timestamp, rule, source, detail):
    return {
        "timestamp": timestamp.isoformat(),
        "rule": rule,
        "source": source,
        "detail": detail,
    }


def monitor_files(log_file=None, audit_file=None, alerts_file=None, now=None):
    log_file = Path(log_file) if log_file else _configured_log_file()
    audit_file = Path(audit_file) if audit_file else AUDIT_FILE
    alerts_file = Path(alerts_file) if alerts_file else ALERTS_FILE

    if not log_file.is_file():
        raise FileNotFoundError(
            f"Flask log not found: {log_file}. Set LOG_FILE to its path."
        )
    if not audit_file.is_file():
        raise FileNotFoundError(f"Vendor audit log not found: {audit_file}")

    now = _as_utc(now or datetime.now(timezone.utc))
    failed_logins, rate_limits, sql_requests = _read_flask_events(log_file)
    audit_events = _read_audit_events(audit_file)
    alerts = []

    recent_logins = _recent_events(
        failed_logins, now, FAILED_LOGIN_WINDOW
    )
    login_counts = defaultdict(int)
    for _, email in recent_logins:
        login_counts[email] += 1
    for email, count in sorted(login_counts.items()):
        if count >= FAILED_LOGIN_THRESHOLD:
            alerts.append(
                _alert(
                    now,
                    "failed_login_burst",
                    "flask_log",
                    f"{count} failed logins for {email} within 5 minutes.",
                )
            )

    recent_rate_limits = _recent_events(
        rate_limits, now, HTTP_429_WINDOW
    )
    rate_counts = defaultdict(int)
    for _, ip in recent_rate_limits:
        rate_counts[ip] += 1
    for ip, count in sorted(rate_counts.items()):
        if count >= HTTP_429_THRESHOLD:
            alerts.append(
                _alert(
                    now,
                    "http_429_burst",
                    "flask_log",
                    f"{count} HTTP 429 responses from IP {ip} within 1 minute.",
                )
            )

    recent_sql_requests = _recent_events(sql_requests, now, SQL_URL_WINDOW)
    if len(recent_sql_requests) >= SQL_URL_THRESHOLD:
        for _, ip, method, marker in recent_sql_requests:
            # One matching request is sufficient; do not retain its raw URL.
            alerts.append(
                _alert(
                    now,
                    "sql_metacharacter_url",
                    "flask_log",
                    f"{method} request from IP {ip} contained SQL marker {marker}.",
                )
            )

    recent_audit_events = _recent_events(
        audit_events, now, PRIVILEGED_DENIED_WINDOW
    )
    denied_counts = defaultdict(int)
    for _, vendor_id, action, decision in recent_audit_events:
        if (
            decision == "Denied"
            and PRIVILEGED_ACTION_PATTERN.search(action)
        ):
            denied_counts[(vendor_id, action)] += 1
    for (vendor_id, action), count in sorted(denied_counts.items()):
        if count > PRIVILEGED_DENIED_THRESHOLD:
            alerts.append(
                _alert(
                    now,
                    "repeated_denied_privileged_action",
                    "vendor_audit_log",
                    f"{count} denied privileged actions for vendor "
                    f"{vendor_id}: {action} within 10 minutes.",
                )
            )

    if alerts:
        alerts_file.parent.mkdir(parents=True, exist_ok=True)
        with alerts_file.open("a", encoding="utf-8") as file:
            for alert in alerts:
                file.write(json.dumps(alert, sort_keys=True) + "\n")
    return alerts


def _configured_log_file():
    configured_path = os.environ.get("LOG_FILE")
    path = Path(configured_path).expanduser() if configured_path else DEFAULT_LOG_FILE
    if not path.is_absolute():
        path = BACKEND_DIR / path
    return path


def main():
    try:
        alerts = monitor_files()
    except FileNotFoundError as error:
        print(f"ERROR: {error}")
        return 1

    print(f"Wrote {len(alerts)} alert(s) to {ALERTS_FILE}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
