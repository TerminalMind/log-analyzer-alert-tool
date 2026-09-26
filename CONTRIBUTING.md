# Contributing to Log Analyzer & Alert Tool

Contributions are welcome! You can help by fixing bugs, improving detection rules, adding log formats, writing tests, or updating documentation.

## Development Setup

1. Fork the repository.
2. Clone your fork.
3. Open a terminal in the folder containing `log_analyzer.py`.
4. Create a branch:

   ```bash
   git checkout -b feature/your-feature-name
   ```

### Requirements

- Python 3.10 or newer
- No third-party packages required

## Making Changes

- Keep each contribution focused on one improvement.
- Follow the existing code style.
- Use clear function and variable names.
- Explain complex logic with short comments.
- Update documentation when changing commands or behavior.
- Add relevant tests for bug fixes and new features.
- Discuss major changes in an issue before starting work.

## Run Tests

From the project folder, run:

```bash
python -m unittest discover -s tests -v
```

Use `py` instead of `python` on Windows, or `python3` on Linux/macOS if needed.

Also check the sample analysis:

```bash
python log_analyzer.py samples/auth.log --year 2026
```

The bundled SSH sample produces **5 alerts** with the default detection settings.

If your change intentionally affects this result, explain why and update the tests and documentation.

## Reporting Bugs

Open an issue with:

- A short, clear title
- Your operating system and Python version
- Steps to reproduce the problem
- The command you used
- Expected and actual results
- A small, sanitized log sample, when relevant

Never share passwords, tokens, session cookies, or private authentication logs.

## Suggesting Features

Describe:

- The problem you want to solve
- Your proposed feature
- An example of how it would work
- Any changes to dependencies or existing behavior

## Submitting a Pull Request

1. Make your changes.
2. Run the tests.
3. Review your changes:

   ```bash
   git status
   git diff
   ```

4. Stage only the files relevant to your contribution.
5. Commit your changes:

   ```bash
   git commit -m "Describe your change"
   ```

6. Push your branch:

   ```bash
   git push origin feature/your-feature-name
   ```

7. Open a pull request against the repository’s default branch.

Include a short explanation of:

- What changed
- Why the change is needed
- How you tested it
- Any related issue numbers

## Security Guidelines

Treat log content as untrusted input.

- Preserve HTML escaping in reports.
- Keep CSV formula protection.
- Use parameterized SQLite queries.
- Do not execute commands taken from log content.
- Validate input and handle malformed records safely.
- Use fictional data in tests and examples.

Do not commit:

- Real authentication logs
- Generated reports or databases
- Passwords, API keys, or tokens
- Virtual environments or Python cache files

Review staged files before committing. The `.gitignore` file may not cover custom report folders or every log filename.

## Reporting Vulnerabilities

Do not disclose security vulnerabilities in public issues or pull requests.

Use private vulnerability reporting if it is enabled for the repository. Otherwise, ask the maintainer for a private reporting channel without posting sensitive details.

## Community Expectations

Be respectful and constructive. Explain your suggestions clearly, welcome feedback, and keep discussions focused on improving the project.
