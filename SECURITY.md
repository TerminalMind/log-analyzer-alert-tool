# Security Policy

## Project Scope

Log Analyzer & Alert Tool is an educational Python project that analyzes saved login logs and reports suspicious activity.

It is not a replacement for a production security monitoring system. Alerts are investigation leads, not proof of compromise.

## Supported Code

Please check whether a suspected vulnerability affects the latest code on the repository’s default branch.

Older snapshots do not have a guaranteed security backport policy.

## Reporting a Vulnerability

Please do not report security vulnerabilities through public issues or pull requests.

Use the repository’s **Report a vulnerability** option under the **Security** tab if private vulnerability reporting is enabled.

If that option is unavailable, ask the maintainer for a private reporting channel. Do not include vulnerability details in that public request.

Never include passwords, API keys, session tokens, or private authentication logs.

### What to Include

A useful report includes:

- A description of the vulnerability
- The affected file or function
- The commit or version you tested
- Your operating system and Python version
- Steps to reproduce the issue
- A minimal example using fictional or sanitized data
- The potential impact
- A suggested fix, if available

## Response and Disclosure

Reports will be reviewed as maintainer availability allows. No fixed response or resolution time is guaranteed.

Please coordinate public disclosure with the maintainer so the issue can be investigated and, where appropriate, fixed before technical details are published.

## Security Issues in Scope

Examples include:

- Code execution caused by processing crafted logs
- SQL injection in database operations
- HTML or script injection in generated reports
- CSV formula injection
- Unintended file overwrites or writes outside the intended output location
- Exposure of sensitive data through unexpected behavior
- Crashes or excessive resource consumption caused by crafted input

A detection bypass may also be security-relevant when supported, valid input causes a documented rule to fail.

## Known Limitations

The following are documented limitations and do not, by themselves, establish a vulnerability:

- Unsupported log formats are not analyzed.
- Malformed records may be skipped and counted.
- Slow or distributed attacks may remain below thresholds.
- Incorrect timestamp settings can affect detection.
- Log authenticity is not verified.
- Missing or forged logs can hide activity.
- Events are held in memory, so large inputs can use substantial memory.
- Detection state is not preserved between separate runs.
- The tool does not block IP addresses or provide live monitoring.

Unexpected behavior beyond these limitations is still worth reporting.

## Safe Usage

- Analyze only logs you own or are authorized to access.
- Run with the minimum permissions needed to read the input and write reports.
- Use a private output directory.
- Keep Python updated with security fixes.
- Review parsed, ignored, and malformed line counts.
- Investigate alerts before taking action.
- Avoid running the tool with administrator or root privileges unless necessary.

## Data Privacy

Logs and reports may contain usernames, hostnames, IP addresses, and login timestamps.

- Do not upload real authentication logs or reports to public repositories.
- Never record passwords, tokens, session cookies, or 2FA codes.
- Use fictional or sanitized data when reporting issues.
- Protect and delete reports according to your own retention requirements.

The tool operates locally and does not send logs or alerts over the network. Generated reports are not encrypted by the tool; their protection depends on your operating system and storage settings.

## Security Controls

The project includes:

- Parameterized SQLite inserts
- HTML escaping for report content
- CSV formula protection
- JSON-escaped console alert fields
- Input validation for supported records
- Refusal to reuse an existing output directory

These controls reduce specific risks but do not guarantee that all vulnerabilities have been eliminated.
