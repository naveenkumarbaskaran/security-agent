# security-agent-ai

An AI-powered security scanner that uses Claude (via the Anthropic SDK) to detect
OWASP Top 10 vulnerabilities, hard-coded secrets, and insecure dependencies in
Python projects.

## Features

- **OWASP Top 10 analysis** — Claude reads your source files and identifies injection
  flaws, broken authentication, sensitive data exposure, IDOR, security misconfiguration,
  XSS, insecure deserialization, vulnerable components, and more.
- **Secret / credential scanning** — 25+ regex patterns covering AWS keys, GitHub tokens,
  Stripe keys, Google API keys, private SSH/RSA keys, hard-coded passwords, JWT secrets,
  and database connection strings.
- **Dependency auditing** — checks `requirements.txt` and `pyproject.toml` against a
  curated CVE list and the PyPI JSON API to flag outdated or vulnerable packages.
- **Structured findings** — every issue includes severity, file path, line number,
  description, and a concrete fix recommendation.
- **Rich CLI** — colour-coded findings table, Markdown report output, and a
  `--fail-on` flag for CI/CD pipelines.

## Installation

```bash
pip install security-agent-ai
```

Or install from source:

```bash
git clone https://github.com/example/security-agent-ai
cd security-agent-ai
pip install -e .
```

## Prerequisites

You need an [Anthropic API key](https://console.anthropic.com/):

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

## Usage

### Command-line interface

```bash
# Basic scan
security-agent scan /path/to/your/project

# Write a Markdown report
security-agent scan /path/to/your/project --report report.md

# Fail (exit code 1) if any HIGH or CRITICAL findings exist
security-agent scan /path/to/your/project --fail-on high

# Fail only on CRITICAL
security-agent scan /path/to/your/project --fail-on critical

# Never fail regardless of findings
security-agent scan /path/to/your/project --fail-on none
```

### Python API

```python
from security_agent import SecurityAgent

agent = SecurityAgent()  # reads ANTHROPIC_API_KEY from environment
findings = agent.scan("/path/to/your/project")

for f in findings:
    print(f"{f.severity.upper():8} {f.file}:{f.line} — {f.description}")
    print(f"         Fix: {f.fix}")
    print()
```

#### Finding schema

```python
@dataclass
class Finding:
    severity: str      # "critical" | "high" | "medium" | "low" | "info"
    file: str          # relative or absolute file path
    line: int | None   # line number, or None if not applicable
    description: str   # what the issue is
    fix: str           # concrete remediation advice
```

### Running in CI/CD

**GitHub Actions example:**

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install security-agent-ai
      - run: security-agent scan . --report security-report.md --fail-on high
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-report
          path: security-report.md
```

## Architecture

```
security_agent/
├── __init__.py     — public API surface
├── agent.py        — SecurityAgent class + agentic Claude loop
├── scanners.py     — SecretScanner (regex) + DepScanner (PyPI)
└── cli.py          — Click CLI + Rich output + Markdown report
```

### How the agent works

1. The `SecurityAgent` sends a task description to Claude `claude-sonnet-4-6` with three
   tools defined:
   - `scan_file(path)` — reads a source file and returns its content for analysis
   - `grep_secrets(directory)` — runs the regex scanner and returns hits
   - `check_dependencies(requirements_file)` — audits a requirements file
2. Claude decides which tools to call, in what order, iterating through all source
   files in the target directory.
3. The agentic loop continues until Claude produces a final message containing a
   consolidated JSON array of findings.
4. Findings are parsed, sorted by severity, and returned to the caller.

## Secret patterns detected

| Category | Patterns |
|---|---|
| Cloud credentials | AWS Access Key ID/Secret, Google API Key, Google OAuth Client Secret |
| Source control | GitHub PAT, GitHub OAuth, GitHub App tokens |
| Communication | Slack bot tokens, Slack webhook URLs, Twilio SID/Auth |
| Payments | Stripe secret/publishable keys |
| Email | SendGrid API keys, Mailgun API keys |
| Private keys | RSA, EC, OpenSSH, PKCS#8 private keys |
| Database | MongoDB, PostgreSQL, MySQL, Redis connection strings |
| Auth | Bearer tokens, JWT secrets, generic passwords |
| AI/ML | Anthropic API keys, OpenAI API keys |

## Dependency CVEs tracked

The built-in advisory list includes CVEs for: Django, Flask, Pillow, cryptography,
requests, urllib3, PyYAML, SQLAlchemy, setuptools, paramiko, aiohttp, Werkzeug,
Jinja2, and certifi. The scanner also queries the PyPI JSON API to flag outdated
packages even when no specific CVE is tracked.

## Development

```bash
pip install -e '.[dev]'
pytest
```

## License

MIT
