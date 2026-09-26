import csv
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from log_analyzer import Event, analyze, load_events, main, offset, parse_line, save_report

T = datetime(2026, 9, 26, tzinfo=timezone.utc)

def event(seconds=0, user='alice', status='failure', host='lab', ip='192.0.2.10'):
    return Event(T + timedelta(seconds=seconds), host, ip, user, status)

class DetectionTests(unittest.TestCase):
    def test_threshold(self):
        self.assertEqual(analyze([event(i) for i in range(4)]), [])
        self.assertEqual([a['rule'] for a in analyze([event(i) for i in range(5)])], ['repeated_failures'])

    def test_window_boundary(self):
        self.assertEqual(len(analyze([event(0), event(300)], threshold=2)), 1)
        self.assertEqual(analyze([event(0), event(301)], threshold=2), [])

    def test_success_correlation(self):
        events = [event(i) for i in range(5)]
        self.assertEqual(analyze(events + [event(6, status='success')])[-1]['rule'], 'success_after_failures')
        self.assertFalse(any(a['rule'] == 'success_after_failures' for a in analyze(events + [event(6, user='bob', status='success')])))

    def test_host_and_ip_isolation(self):
        for change in ({'host': 'other'}, {'ip': '192.0.2.11'}):
            self.assertEqual(analyze([event(i) for i in range(4)] + [event(5, **change)]), [])

    def test_spray_and_suppression(self):
        alerts = analyze([event(i, user=f'user{i}') for i in range(10)])
        self.assertEqual([a['rule'] for a in alerts], ['repeated_failures', 'multiple_accounts'])

    def test_rearm(self):
        alerts = analyze([event(i) for i in range(5)] + [event(400+i) for i in range(5)])
        self.assertEqual(len(alerts), 2)

    def test_sort(self):
        events = [event(i) for i in range(5)] + [event(6, status='success')]
        self.assertEqual(analyze(events), analyze(list(reversed(events))))

    def test_root_and_reset(self):
        events = [event(i, user='root') for i in range(5)] + [event(6, user='root', status='success'), event(7, user='root', status='success')]
        rules = [a['rule'] for a in analyze(events)]
        self.assertEqual(rules.count('success_after_failures'), 1)
        self.assertEqual(rules.count('root_login'), 2)

class ParserTests(unittest.TestCase):
    def test_legacy(self):
        e = parse_line('Sep 26 05:30:00 lab sshd[42]: Failed password for invalid user alice from 192.0.2.10 port 22 ssh2', 2026, offset('+05:30'))
        self.assertEqual(e.time, T)
        self.assertEqual(e.user, 'alice')

    def test_iso_ipv6(self):
        e = parse_line('2026-09-26T00:00:00Z lab sshd[42]: Accepted publickey for bob from 2001:db8::1 port 22 ssh2', 2026, timezone.utc)
        self.assertEqual(e.ip, '2001:db8::1')
        self.assertEqual(e.status, 'success')

    def test_json_and_invalid(self):
        row = dict(timestamp=T.isoformat(), host='lab', ip='192.0.2.10', user='alice', status='failure')
        self.assertEqual(parse_line(json.dumps(row), 2026, timezone.utc), event())
        row['ip'] = '999.1.1.1'
        with self.assertRaises(ValueError):
            parse_line(json.dumps(row), 2026, timezone.utc)

    def test_statistics(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'input.log'
            p.write_text('unrelated\n{broken\n', encoding='utf-8')
            events, stats = load_events([p], 2026, timezone.utc)
            self.assertEqual(events, [])
            self.assertEqual(stats, dict(lines=2, parsed=0, ignored=1, malformed=1))

    def test_bad_timestamp_types(self):
        for stamp in (None, 123, [], {}):
            row = dict(timestamp=stamp, host='lab', ip='192.0.2.10', user='alice', status='failure')
            with self.assertRaises(ValueError):
                parse_line(json.dumps(row), 2026, timezone.utc)

class ReportTests(unittest.TestCase):
    def test_escaping_and_database(self):
        user = '=1+1<script>alert(1)</script>'
        alerts = analyze([event(i, user=user) for i in range(5)])
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / 'report'
            save_report(out, alerts, {}, {})
            page = (out / 'report.html').read_text()
            self.assertNotIn('<script>', page)
            self.assertIn('&lt;script&gt;', page)
            with (out / 'alerts.csv').open(newline='') as f:
                self.assertTrue(next(csv.DictReader(f))['user'].startswith("'="))
            with sqlite3.connect(out / 'alerts.db') as db:
                self.assertEqual(db.execute('SELECT user FROM alerts').fetchone()[0], user)
            with self.assertRaises(FileExistsError):
                save_report(out, alerts, {}, {})

    def test_cli_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(main(['samples/auth.log', '--year', '2026', '--output', str(Path(d)/'one'), '--fail-on-alert']), 1)
            self.assertEqual(main(['samples/auth.log', '--output', str(Path(d)/'one')]), 2)
            self.assertEqual(main([str(Path(d)/'absent')]), 2)

if __name__ == '__main__':
    unittest.main()
