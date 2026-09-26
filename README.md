# Log Analyzer & Alert Tool

A Python cybersecurity tool that analyzes login logs, detects suspicious activity, and generates detailed reports.

Built using Python’s standard library—no extra packages required.

## Features

- Detect repeated failed login attempts.
- Identify failed logins targeting multiple accounts.
- Flag successful logins after repeated failures.
- Detect successful root logins.
- Support Linux SSH logs and application JSONL logs.
- Support IPv4 and IPv6 addresses.
- Generate HTML, CSV, JSON, and SQLite reports.
- Customize detection thresholds and time windows.

## Technologies Used

- **Python** — parsing, analysis, and command-line interface
- **Regular Expressions** — SSH log pattern matching
- **SQLite** — storing alerts
- **HTML** — browser-readable reports
- **JSON and CSV** — exporting results
- **unittest** — automated testing

## Requirements

- Python **3.10 or newer**
- Windows, Linux, or macOS

No third-party dependencies or `pip install` commands are needed.

## Project Structure

```text
log-analyzer/
├── log_analyzer.py
├── README.md
├── .gitignore
├── samples/
│   ├── auth.log
│   └── application.jsonl
└── tests/
    └── test_analyzer.py
```

## Getting Started

Download or clone the repository. Open a terminal in the folder containing `log_analyzer.py`.

### Windows

```powershell
py log_analyzer.py samples/auth.log --year 2026 --output demo-report
```

### Linux / macOS

```bash
python3 log_analyzer.py samples/auth.log --year 2026 --output demo-report
```

Open the generated report:

```text
demo-report/report.html
```

Expected sample summary:

```text
Parsed: 12 | Ignored: 1 | Malformed: 0 | Alerts: 5
```

**Note:** The output directory must not already exist. For another run, use a different directory name or omit `--output` to generate a timestamped folder.

The following examples use `python`. Replace it with `py` or `python3` if required.

## Detection Rules

| Rule | Default Trigger | Severity |
|---|---|---|
| Repeated failures | 5 failures from the same IP against the same host within 300 seconds | HIGH |
| Multiple accounts | Failures for 5 distinct usernames from the same IP against the same host within 300 seconds | HIGH |
| Success after failures | Successful login after 5 failures for the same host, IP, and username within 300 seconds | CRITICAL |
| Root login | Any successful login as `root` | MEDIUM |

Repeated-failure detection counts failures across usernames.

Time-window boundaries are inclusive. Repeated-failure and multiple-account alerts are suppressed while their thresholds remain met. They can trigger again after the counts drop below their thresholds.

A successful login clears the previous failures for that account at the same host and IP.

Alerts indicate activity to investigate, not proof of compromise.

## Usage Examples

### Analyze an SSH Log

```bash
python log_analyzer.py auth.log --year 2026 --utc-offset=+05:30
```

Set the year and UTC offset to match the log. The example offset is India Standard Time.

### Customize Detection Settings

```bash
python log_analyzer.py samples/auth.log --year 2026 --threshold 3 --window 120 --spray-users 3
```

This uses:

- 3 failed attempts as the failure threshold.
- A 120-second detection window.
- 3 distinct usernames as the multiple-account threshold.

### Analyze Multiple Files

```bash
python log_analyzer.py auth-part1.log auth-part2.log --year 2026
```

Events are sorted by timestamp. Avoid overlapping files because duplicate contents are not removed.

### Analyze Application Logs

```bash
python log_analyzer.py samples/application.jsonl --threshold 2
```

### Return Exit Code 1 When Alerts Are Found

```bash
python log_analyzer.py samples/auth.log --year 2026 --fail-on-alert
```

### View Help

```bash
python log_analyzer.py --help
```

## Command-Line Options

| Option | Description | Default |
|---|---|---|
| `logs` | One or more input files | Required |
| `--threshold` | Failed-login threshold | `5` |
| `--window` | Detection window in seconds | `300` |
| `--spray-users` | Distinct failed-user threshold | `5` |
| `--year` | Year for legacy syslog timestamps | Current UTC year |
| `--utc-offset` | Offset for timestamps without timezone information | `+00:00` |
| `--output` | New output directory | Timestamped folder under `reports/` |
| `--fail-on-alert` | Exit with code `1` when alerts exist | Disabled |

Detection thresholds must be positive integers.

## Supported Log Formats

### SSH Text Logs

Example:

```text
Sep 26 10:00:00 lab sshd[100]: Failed password for alice from 192.0.2.10 port 51001 ssh2
Sep 26 10:02:30 lab sshd[105]: Accepted publickey for alice from 192.0.2.10 port 51006 ssh2
```

ISO timestamps are also supported:

```text
2026-09-26T10:02:30+05:30 lab sshd[105]: Accepted publickey for alice from 192.0.2.10 port 51006 ssh2
```

The parser recognizes supported `Failed` and `Accepted` messages for password, publickey, and keyboard-interactive authentication.

Other SSH/PAM formats, web access logs, and Windows Event Logs are not currently supported.

### Application JSONL Logs

Each line must contain a JSON object:

```json
{"timestamp":"2026-09-26T10:00:00+05:30","host":"my-app","ip":"192.0.2.50","user":"shivam","status":"failure"}
```

Required fields:

| Field | Description |
|---|---|
| `timestamp` | ISO-format timestamp; include an explicit timezone offset when possible |
| `host` | Host or application name |
| `ip` | Valid IPv4 or IPv6 address |
| `user` | Username |
| `status` | `failure` or `success` |

Host and user values must be nonempty strings of up to 255 characters without ASCII control characters.

Never log passwords, tokens, session cookies, or 2FA codes.

## Timestamp Handling

Reports display event times in UTC.

Legacy syslog timestamps do not include a year or timezone. Set `--year` and `--utc-offset` correctly.

For logs spanning New Year or daylight-saving changes, convert timestamps to ISO format with explicit offsets before analysis.

## Generated Reports

```text
demo-report/
├── report.html
├── alerts.csv
├── alerts.json
└── alerts.db
```

| File | Purpose |
|---|---|
| `report.html` | View alerts in a browser |
| `alerts.csv` | Open alerts in a spreadsheet |
| `alerts.json` | Read alerts, analysis settings, and parsing counts |
| `alerts.db` | Query alerts using SQLite |

The database is a separate snapshot for each run. It does not maintain a continuous alert history.

## Running Tests

Run from the project folder:

```bash
python -m unittest discover -s tests -v
```

The included suite contains **15 tests** covering:

- Detection thresholds and time-window boundaries
- Host and IP separation
- Successful login correlation
- Alert suppression and rearming
- Log parsing and malformed input
- HTML escaping and CSV formula protection
- SQLite storage
- Command-line behavior

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Analysis completed successfully |
| `1` | Alerts found with `--fail-on-alert` enabled |
| `2` | Input, output, or argument error, or no supported events found |

Malformed records do not stop analysis. Always check the ignored and malformed line counts.

## Security and Privacy

- Analyze only logs you own or are authorized to access.
- Keep real logs and reports private.
- Do not upload real authentication logs to GitHub.
- The bundled samples contain fictional data.
- HTML report values are escaped.
- Potential CSV formulas are prefixed with an apostrophe.
- SQLite inserts use parameterized queries.
- Console alert fields are JSON-escaped.
- Existing output directories are refused to prevent accidental overwrites.

The tool runs locally and sends no emails or network requests.

Review files before committing: `.gitignore` does not automatically exclude every custom report directory or application log filename.

## Limitations

This is an educational and portfolio project, not a replacement for a production SIEM.

- Analyzes saved files; live monitoring is not implemented.
- Does not automatically block IP addresses.
- Does not send email or webhook notifications.
- Legitimate activity can trigger alerts.
- Slow or distributed attacks may remain below detection thresholds.
- Does not verify log authenticity.
- Holds parsed events in memory.
- Does not preserve detection state between separate runs.

## Future Improvements

- Live log monitoring
- Log rotation support
- Additional log formats
- Optional email and webhook alerts
- Authenticated dashboard
- Persistent detection state

## Contributing

Bug reports and improvements are welcome.

When reporting an issue, include:

- The command you ran
- The expected and actual results
- A sanitized example log line, if relevant

Remove personal information and secrets before sharing logs. Run the test suite before submitting changes.
