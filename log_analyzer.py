#!/usr/bin/env python3
"""Offline SSH / JSONL login analyzer. Python standard library only."""
import argparse
import csv
import hashlib
import html
import ipaddress
import json
import re
import sqlite3
import sys
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

UTC = timezone.utc
SSH = re.compile(r'\bsshd(?:-session)?(?:\[\d+\])?: (?P<status>Failed|Accepted) (?P<method>password|publickey|keyboard-interactive(?:/pam)?) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+\b')
LEGACY = re.compile(r'^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+')
FIELDS = ['id', 'time', 'severity', 'rule', 'host', 'ip', 'user', 'count', 'message']

@dataclass(frozen=True)
class Event:
    time: datetime
    host: str
    ip: str
    user: str
    status: str


def clean_text(value):
    if not isinstance(value, str) or not value or len(value) > 255 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('invalid text field')
    return value


def parse_line(line, year, tz):
    """None means unrelated; ValueError means malformed supported login record."""
    line = line.strip()
    if not line:
        return None
    if line.startswith('{'):
        obj = json.loads(line)
        if not isinstance(obj, dict):
            raise ValueError('JSON object required')
        stamp = datetime.fromisoformat(clean_text(obj['timestamp']).replace('Z', '+00:00'))
        host, ip, user, status = (obj[k] for k in ('host', 'ip', 'user', 'status'))
    else:
        match = SSH.search(line)
        if not match:
            return None
        legacy = LEGACY.match(line)
        if legacy:
            stamp = datetime.strptime(str(year) + ' ' + legacy['ts'], '%Y %b %d %H:%M:%S')
            host = legacy['host']
        else:
            parts = line.split(maxsplit=2)
            stamp = datetime.fromisoformat(parts[0].replace('Z', '+00:00'))
            host = parts[1]
        ip, user = match['ip'], match['user']
        status = 'failure' if match['status'] == 'Failed' else 'success'
    if status not in ('failure', 'success'):
        raise ValueError('status must be failure or success')
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=tz)
    # Validate/canonicalize both IPv4 and IPv6; scoped addresses are not accepted.
    if not isinstance(ip, str) or '%' in ip:
        raise ValueError('invalid IP')
    return Event(stamp.astimezone(UTC), clean_text(host), str(ipaddress.ip_address(ip)), clean_text(user), status)


def load_events(paths, year, tz):
    events = []
    stats = {'lines': 0, 'parsed': 0, 'ignored': 0, 'malformed': 0}
    for path in paths:
        with Path(path).open(encoding='utf-8', errors='replace') as source:
            for line in source:
                stats['lines'] += 1
                try:
                    event = parse_line(line, year, tz)
                except (ValueError, KeyError, TypeError, IndexError, OverflowError):
                    stats['malformed'] += 1
                    continue
                if event is None:
                    stats['ignored'] += 1
                else:
                    events.append(event)
                    stats['parsed'] += 1
    return sorted(events, key=lambda e: e.time), stats


def analyze(events, threshold=5, window=300, spray_users=5):
    if min(threshold, window, spray_users) < 1:
        raise ValueError('thresholds must be positive')
    failures = defaultdict(deque)
    active = {}
    alerts = []

    def emit(e, severity, rule, count, message):
        alert = dict(time=e.time.isoformat(), severity=severity, rule=rule,
                     host=e.host, ip=e.ip, user=e.user, count=count, message=message)
        alert['id'] = hashlib.sha256(json.dumps(alert, sort_keys=True).encode()).hexdigest()
        alerts.append(alert)

    for e in sorted(events, key=lambda x: x.time):
        key = (e.host, e.ip)
        queue = failures[key]
        try:
            cutoff = e.time - timedelta(seconds=window)
        except OverflowError:
            cutoff = datetime.min.replace(tzinfo=UTC)
        while queue and queue[0].time < cutoff:
            queue.popleft()
        brute, spray = active.get(key, (False, False))
        if len(queue) < threshold:
            brute = False
        if len({v.user for v in queue}) < spray_users:
            spray = False
        if e.status == 'failure':
            queue.append(e)
            if len(queue) >= threshold and not brute:
                emit(e, 'HIGH', 'repeated_failures', len(queue), f'{len(queue)} failed logins within {window} seconds.')
                brute = True
            distinct = len({v.user for v in queue})
            if distinct >= spray_users and not spray:
                emit(e, 'HIGH', 'multiple_accounts', distinct, f'Failed logins for {distinct} distinct users within {window} seconds; possible password spraying.')
                spray = True
        else:
            matching = sum(v.user == e.user for v in queue)
            if matching >= threshold:
                emit(e, 'CRITICAL', 'success_after_failures', matching, f'Success after {matching} failures for the same host, IP and user within {window} seconds; investigate.')
            if e.user == 'root':
                emit(e, 'MEDIUM', 'root_login', 1, 'Successful root login; review whether expected.')
            # A successful login ends this account's failure sequence only.
            queue = deque(v for v in queue if v.user != e.user)
            failures[key] = queue
            brute = brute and len(queue) >= threshold
            spray = spray and len({v.user for v in queue}) >= spray_users
        active[key] = (brute, spray)
    return alerts


def csv_safe(value):
    text = str(value)
    return "'" + text if text.lstrip().startswith(('=', '+', '-', '@')) else text


def save_report(out, alerts, stats, settings):
    out.mkdir(parents=True, exist_ok=False)
    payload = dict(summary=stats, settings=settings, alerts=alerts)
    (out / 'alerts.json').write_text(json.dumps(payload, indent=2), encoding='utf-8')
    with (out / 'alerts.csv').open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows({k: csv_safe(a[k]) for k in FIELDS} for a in alerts)
    with sqlite3.connect(out / 'alerts.db') as db:
        db.execute('CREATE TABLE alerts (id TEXT PRIMARY KEY, time TEXT, severity TEXT, rule TEXT, host TEXT, ip TEXT, user TEXT, count INTEGER, message TEXT)')
        db.executemany('INSERT OR IGNORE INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', [tuple(a[k] for k in FIELDS) for a in alerts])
    cols = FIELDS[1:]
    rows = ''.join('<tr>' + ''.join('<td>' + html.escape(str(a[k])) + '</td>' for k in cols) + '</tr>' for a in alerts)
    summary = html.escape(json.dumps(stats))
    settings_html = html.escape(json.dumps(settings))
    document = '''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>Log Analyzer Report</title><style>body{font:16px system-ui;margin:40px;background:#0b1220;color:#e2e8f0}h1{color:#60a5fa}table{border-collapse:collapse;width:100%;background:#172033}td,th{padding:12px;text-align:left;border-bottom:1px solid #334155;overflow-wrap:anywhere}th{color:#93c5fd}.scroll{overflow-x:auto}p{line-height:1.6}code{white-space:pre-wrap}</style><h1>Log Analyzer &amp; Alert Tool</h1><p>Offline login activity report · All event times are UTC.</p>'''
    document += f'<p><strong>{len(alerts)} alerts</strong></p><p>Input summary: <code>{summary}</code></p><p>Settings: <code>{settings_html}</code></p>'
    document += '<div class="scroll"><table><thead><tr>' + ''.join('<th>' + k.title() + '</th>' for k in cols) + '</tr></thead><tbody>' + rows + '</tbody></table></div>'
    document += '<p>Alerts are investigation leads, not proof of compromise. Ignored or malformed records were not analyzed. This report may contain sensitive usernames and IP addresses.</p></html>'
    (out / 'report.html').write_text(document, encoding='utf-8')


def positive(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError('must be positive')
    return number


def offset(value):
    if not re.fullmatch(r'[+-]\d{2}:\d{2}', value):
        raise argparse.ArgumentTypeError('use +05:30 or +00:00')
    hours, minutes = map(int, value[1:].split(':'))
    if hours > 23 or minutes > 59:
        raise argparse.ArgumentTypeError('invalid UTC offset')
    return timezone((1 if value[0] == '+' else -1) * timedelta(hours=hours, minutes=minutes))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('logs', nargs='+', type=Path, help='SSH text logs or application JSONL files')
    parser.add_argument('--threshold', type=positive, default=5, help='failure count (default 5)')
    parser.add_argument('--window', type=positive, default=300, help='window in seconds (default 300)')
    parser.add_argument('--spray-users', type=positive, default=5, help='distinct failed users (default 5)')
    parser.add_argument('--year', type=int, default=datetime.now(UTC).year, help='year for legacy syslog; default current UTC year')
    parser.add_argument('--utc-offset', type=offset, default=UTC, help='timezone for timestamps without offset; default +00:00')
    parser.add_argument('--output', type=Path, default=None, help='NEW output directory; existing directories are refused')
    parser.add_argument('--fail-on-alert', action='store_true', help='exit 1 when alerts exist')
    args = parser.parse_args(argv)
    if not 1 <= args.year <= 9999:
        parser.error('--year must be between 1 and 9999')
    paths = [p.resolve() for p in args.logs]
    if len(paths) != len(set(paths)):
        parser.error('the same input path was supplied more than once')
    out = args.output or Path('reports') / datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')
    try:
        events, stats = load_events(paths, args.year, args.utc_offset)
        alerts = analyze(events, args.threshold, args.window, args.spray_users)
        settings = dict(threshold=args.threshold, window_seconds=args.window, spray_users=args.spray_users, legacy_year=args.year, naive_timezone=str(args.utc_offset))
        save_report(out, alerts, stats, settings)
    except (OSError, sqlite3.Error) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 2
    print(f"Parsed: {stats['parsed']} | Ignored: {stats['ignored']} | Malformed: {stats['malformed']} | Alerts: {len(alerts)}")
    for alert in alerts:
        # JSON escaping prevents terminal control sequences from untrusted fields.
        print(json.dumps({k: alert[k] for k in ('severity', 'rule', 'ip', 'user', 'message')}, ensure_ascii=True))
    print(f'Report: {out.resolve() / "report.html"}')
    if not events:
        print('No supported login events found. Review input format; no security conclusion can be drawn.', file=sys.stderr)
        return 2
    return 1 if alerts and args.fail_on_alert else 0


if __name__ == '__main__':
    sys.exit(main())
