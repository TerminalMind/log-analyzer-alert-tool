# Log Analyzer & Alert Tool

An offline Python cybersecurity project that finds suspicious login patterns and creates a browser-readable report. Works on Windows, Linux and macOS with Python 3.10 or newer. Uses only the Python standard library: **no pip installs required**.

## Quick start

Extract the ZIP, open a terminal in the `log-analyzer` folder, then run:

```sh
python log_analyzer.py samples/auth.log --year 2026 --output demo-report
```

On Windows you can use `py` instead of `python`; on Linux/macOS use `python3` if needed. Open `demo-report/report.html` in your browser. The sample produces **5 alerts** from 12 login events; one unrelated line is ignored. It uses documentation-only example IP addresses.

Output directories must be new to prevent accidental overwrites. For another run, omit `--output` for an automatically named folder under `reports`, or choose another name.

## Detection rules

| Rule | Default trigger | Severity |
|---|---|---|
| Repeated failures | 5 failures from the same IP against the same host within 300 seconds, across any usernames | HIGH |
| Multiple accounts | Failures for 5 distinct usernames from the same IP against the same host within 300 seconds | HIGH |
| Success after failures | Success after at least 5 failures for the exact same host, IP and username within 300 seconds | CRITICAL |
| Root login | Any successful login as `root` | MEDIUM |

Windows are inclusive: an event exactly 300 seconds earlier is included. Repeated-failure and multiple-account alerts fire when their threshold is crossed, then rearm after the active window drops below it. A success clears prior failures for that account at that host and IP. A root success can produce both a root alert and a success-after-failures alert. Severity expresses review priority, not confirmed compromise.

## Your logs

Copy an SSH authentication log that you have permission to read into this folder:

```sh
python log_analyzer.py auth.log --year 2026 --utc-offset=+05:30
```

For Linux SSH text logs, commonly named `auth.log` or `secure`, supported messages are `Failed` or `Accepted` for password, publickey, or keyboard-interactive authentication. Prefixes may use `Sep 26 10:00:00 server sshd[123]:` or an ISO timestamp such as `2026-09-26T10:00:00+05:30 server sshd[123]:`. IPv4 and IPv6 are supported. Other SSH/PAM formats, web access logs and Windows Event Logs are not currently supported. Unsupported text lines are counted as ignored; malformed supported records are counted separately.

Legacy syslog does not contain a year or timezone. Set `--year` and `--utc-offset` correctly. Defaults are current UTC year and UTC. A single invocation uses one supplied year and offset for all timestamps missing that information. For logs spanning New Year or daylight-saving changes, convert timestamps to ISO with explicit offsets before analysis. Reports normalize timestamps to UTC.

Analyze multiple non-overlapping files together:

```sh
python log_analyzer.py auth-part1.log auth-part2.log --year 2026
```

Events are sorted by timestamp; equal timestamps retain input order. Duplicate input paths are rejected, but overlapping file contents are not deduplicated because identical log messages can represent separate attempts. Avoid combining duplicate exports. Events are stored in memory; split very large datasets into sensible batches with enough overlap to cover the detection window, reviewing overlap alerts accordingly.

## Application JSONL format

One JSON object per line, with all five fields required:

```json
{"timestamp":"2026-09-26T10:00:00+05:30","host":"my-app","ip":"192.0.2.50","user":"shivam","status":"failure"}
```

`status` must be `failure` or `success`. IP must be a valid address. Host/user must be nonempty strings of up to 255 characters without ASCII control characters. Do not log passwords, tokens, session cookies, or 2FA codes.

Try the application sample with a lower threshold:

```sh
python log_analyzer.py samples/application.jsonl --threshold 2
```

## Customize

```sh
python log_analyzer.py samples/auth.log --year 2026 --threshold 3 --window 120 --spray-users 3
python log_analyzer.py --help
```

`--window` is in seconds. All detection thresholds must be positive integers.

## Generated files

- `report.html`: static report; open locally in a browser, no server required.
- `alerts.json`: alerts, parsing summary and analysis settings.
- `alerts.csv`: alerts for a spreadsheet; potentially formula-like values are prefixed with an apostrophe.
- `alerts.db`: SQLite `alerts` table, with parameterized inserts and deterministic alert IDs.

SQLite is a per-run snapshot, not a continuously updated history database. Existing report folders are refused. HTML fields are escaped, and console alert data is JSON-escaped. Files can contain sensitive usernames/IPs: keep reports in a private folder. No network traffic or email is sent; alerts appear in the terminal and saved reports. This version is a batch analyzer, without live file watching, automatic IP blocking, or a web server.

Exit codes: `0` completed; `1` alerts found when `--fail-on-alert` is used; `2` input/output/argument error or no supported events. Malformed lines do not stop a run; always inspect coverage counts. If report writing fails, the partially created output folder may remain; inspect it and choose a new output folder for the retry.

## Run the tests

From the project folder:

```sh
python -m unittest discover -s tests -v
```

Tests cover time boundaries, correlation, host/IP separation, suppression and rearming, parsing, malformed records, HTML/CSV output safety, SQLite storage and CLI behavior.

## Interpretation and limitations

Use only logs you own or are authorized to analyze. An alert is a reason to investigate, not proof of an attack. Shared IP addresses, mistyped passwords and normal administrator logins can cause alerts. Slow or distributed attacks may stay below thresholds. Forged, missing or unsupported log lines can hide activity; this tool does not verify log authenticity. It is an educational/portfolio tool, not a replacement for a production SIEM.

Possible next additions: streaming detection with rotation handling, additional parsers, an authenticated dashboard, and optional notifications configured by the operator.
