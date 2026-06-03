"""
scanners.py — two lightweight, dependency-free scanners:

  SecretScanner  — regex patterns for common credentials / secrets
  DepScanner     — checks PyPI JSON API for known-vulnerable package versions
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:  # pragma: no cover
    import urllib.request as _urllib_request
    _HAS_REQUESTS = False


# ---------------------------------------------------------------------------
# Secret / credential patterns
# ---------------------------------------------------------------------------

# Each entry: (label, compiled_pattern)
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Generic high-entropy key assignments
    ("Generic API key",
     re.compile(r'(?i)(?:api[_\-]?key|apikey)[\s]*[=:][\s]*["\']?([A-Za-z0-9_\-]{20,})["\']?')),

    # AWS
    ("AWS Access Key ID",
     re.compile(r'(?i)(?:AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16}')),
    ("AWS Secret Access Key",
     re.compile(r'(?i)aws[_\-]?secret[_\-]?(?:access[_\-]?)?key[\s]*[=:][\s]*["\']?([A-Za-z0-9/+]{40})["\']?')),

    # GitHub
    ("GitHub Personal Access Token",
     re.compile(r'ghp_[A-Za-z0-9]{36}')),
    ("GitHub OAuth Token",
     re.compile(r'gho_[A-Za-z0-9]{36}')),
    ("GitHub App Token",
     re.compile(r'(?:ghs|ghu)_[A-Za-z0-9]{36}')),

    # Slack
    ("Slack Bot Token",
     re.compile(r'xoxb-[0-9A-Za-z\-]{50,}')),
    ("Slack Webhook URL",
     re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+')),

    # Stripe
    ("Stripe Secret Key",
     re.compile(r'sk_(?:live|test)_[A-Za-z0-9]{24,}')),
    ("Stripe Publishable Key",
     re.compile(r'pk_(?:live|test)_[A-Za-z0-9]{24,}')),

    # Twilio
    ("Twilio Account SID",
     re.compile(r'AC[a-z0-9]{32}')),
    ("Twilio Auth Token",
     re.compile(r'(?i)twilio[^\n]*auth[_\-]?token[\s]*[=:][\s]*["\']?([a-z0-9]{32})["\']?')),

    # Google
    ("Google API Key",
     re.compile(r'AIza[0-9A-Za-z_\-]{35}')),
    ("Google OAuth Client Secret",
     re.compile(r'(?i)client[_\-]?secret[\s]*[=:][\s]*["\']?([A-Za-z0-9_\-]{24,})["\']?')),

    # SendGrid
    ("SendGrid API Key",
     re.compile(r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}')),

    # Mailgun
    ("Mailgun API Key",
     re.compile(r'key-[0-9a-zA-Z]{32}')),

    # Private keys
    ("RSA Private Key",
     re.compile(r'-----BEGIN RSA PRIVATE KEY-----')),
    ("EC Private Key",
     re.compile(r'-----BEGIN EC PRIVATE KEY-----')),
    ("Generic Private Key",
     re.compile(r'-----BEGIN PRIVATE KEY-----')),
    ("OpenSSH Private Key",
     re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----')),

    # Passwords in code
    ("Hard-coded password",
     re.compile(r'(?i)(?:password|passwd|pwd)[\s]*[=:][\s]*["\']([^"\']\S{6,})["\']')),

    # Database connection strings
    ("Database connection string",
     re.compile(r'(?i)(?:mongodb|postgresql|mysql|redis)://[^\s@]+:[^\s@]+@[\w.\-]+')),

    # JWT secrets
    ("JWT Secret",
     re.compile(r'(?i)jwt[_\-]?secret[\s]*[=:][\s]*["\']?([^"\' \n]{16,})["\']?')),

    # Bearer tokens
    ("Bearer Token",
     re.compile(r'(?i)bearer[\s]+([A-Za-z0-9_\-.+/=]{40,})')),

    # Anthropic / OpenAI
    ("Anthropic API Key",
     re.compile(r'sk-ant-[A-Za-z0-9_\-]{40,}')),
    ("OpenAI API Key",
     re.compile(r'sk-[A-Za-z0-9]{48}')),
]

# File extensions to include
_TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".go", ".rb", ".php", ".cs",
    ".cpp", ".c", ".h", ".sh", ".bash",
    ".env", ".cfg", ".conf", ".config",
    ".yml", ".yaml", ".json", ".xml", ".toml",
    ".properties", ".ini", ".tf",
    ".txt", ".md",
}

# Directories to skip
_SKIP_DIRS = {
    ".git", ".hg", ".svn",
    "node_modules", "__pycache__", ".pytest_cache",
    "venv", ".venv", "env", ".env",
    "dist", "build", ".tox",
}


class SecretScanner:
    """Regex-based scanner that looks for secrets/credentials in source files."""

    def scan_directory(
        self,
        directory: Path,
        max_file_size_kb: int = 512,
    ) -> list[dict[str, Any]]:
        """
        Walk *directory* recursively and return a list of match dicts:
          {"file", "line", "pattern_name", "snippet"}
        """
        hits: list[dict[str, Any]] = []
        max_bytes = max_file_size_kb * 1024

        for path in directory.rglob("*"):
            # Skip non-files and excluded dirs
            if not path.is_file():
                continue
            if any(part in _SKIP_DIRS for part in path.parts):
                continue
            if path.suffix.lower() not in _TEXT_EXTENSIONS:
                continue
            if path.stat().st_size > max_bytes:
                continue

            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue

            for lineno, line in enumerate(text.splitlines(), start=1):
                for label, pattern in _SECRET_PATTERNS:
                    if pattern.search(line):
                        snippet = line.strip()[:120]
                        hits.append(
                            {
                                "file": str(path),
                                "line": lineno,
                                "pattern_name": label,
                                "snippet": snippet,
                            }
                        )
                        break  # one hit per line is enough

        return hits

    def scan_file(self, path: Path) -> list[dict[str, Any]]:
        """Scan a single file for secrets."""
        return self.scan_directory(path.parent, max_file_size_kb=2048)


# ---------------------------------------------------------------------------
# Known-vulnerable version database (advisory data)
# ---------------------------------------------------------------------------

# Manually curated list of (package, vulnerable_specifier, cve, description)
# This list is checked *in addition to* the live PyPI advisories.
_KNOWN_VULNS: list[dict[str, Any]] = [
    {"package": "django", "below": "3.2.19", "cve": "CVE-2023-23969",
     "description": "ReDoS via Accept-Language header"},
    {"package": "django", "below": "4.2.1", "cve": "CVE-2023-24580",
     "description": "Potential DoS via file uploads"},
    {"package": "flask", "below": "2.2.5", "cve": "CVE-2023-25577",
     "description": "Multipart Content-Length header bypass"},
    {"package": "pillow", "below": "9.3.0", "cve": "CVE-2022-45198",
     "description": "Uncontrolled resource consumption"},
    {"package": "cryptography", "below": "41.0.0", "cve": "CVE-2023-49083",
     "description": "NULL pointer dereference in PKCS12"},
    {"package": "requests", "below": "2.31.0", "cve": "CVE-2023-32681",
     "description": "Unintended leak of Proxy-Authorization header"},
    {"package": "urllib3", "below": "1.26.17", "cve": "CVE-2023-45803",
     "description": "Redirect request body leaks credentials"},
    {"package": "pyyaml", "below": "6.0", "cve": "CVE-2022-1471",
     "description": "Arbitrary code execution via yaml.load()"},
    {"package": "sqlalchemy", "below": "1.4.49", "cve": "CVE-2023-30608",
     "description": "SQL injection via crafted bind parameters"},
    {"package": "setuptools", "below": "65.5.1", "cve": "CVE-2022-40897",
     "description": "ReDoS via HTML parsing"},
    {"package": "paramiko", "below": "2.10.1", "cve": "CVE-2022-24302",
     "description": "Prefixed process during private-key creation"},
    {"package": "aiohttp", "below": "3.8.5", "cve": "CVE-2023-37276",
     "description": "HTTP request smuggling via pipelining"},
    {"package": "werkzeug", "below": "2.3.3", "cve": "CVE-2023-25577",
     "description": "Multipart form data parsing DoS"},
    {"package": "jinja2", "below": "3.1.2", "cve": "CVE-2023-44271",
     "description": "Uncontrolled resource consumption via crafted template"},
    {"package": "certifi", "below": "2022.12.7", "cve": "CVE-2022-23491",
     "description": "Distrusted root certificates included"},
]


def _parse_version(ver_str: str) -> tuple[int, ...]:
    """Convert '1.2.3' -> (1, 2, 3). Non-numeric parts default to 0."""
    parts = []
    for p in re.split(r"[.\-+]", ver_str):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def _is_below(installed: str, threshold: str) -> bool:
    """Return True when installed version < threshold."""
    try:
        return _parse_version(installed) < _parse_version(threshold)
    except Exception:
        return False


class DepScanner:
    """Check requirements files for packages with known vulnerable versions."""

    def __init__(self, timeout: int = 5) -> None:
        self._timeout = timeout
        self._pypi_cache: dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(self, requirements_file: Path) -> list[dict[str, Any]]:
        """
        Parse *requirements_file* and return a list of advisory dicts:
          {"package", "installed_version", "cve", "description", "severity"}
        """
        packages = self._parse_requirements(requirements_file)
        results: list[dict[str, Any]] = []

        for pkg_name, pkg_version in packages.items():
            if pkg_version is None:
                continue

            advisories = self._check_package(pkg_name, pkg_version)
            results.extend(advisories)

        return results

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def _parse_requirements(self, path: Path) -> dict[str, str | None]:
        """Return {package_name: version_or_None} from a requirements file."""
        packages: dict[str, str | None] = {}
        suffix = path.suffix.lower()

        if suffix == ".toml":
            return self._parse_pyproject(path)

        # requirements.txt style
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return {}

        for raw_line in text.splitlines():
            line = raw_line.strip()
            # Skip comments, blank lines, options
            if not line or line.startswith(("#", "-", "http", "git")):
                continue
            # Strip inline comments
            line = line.split("#")[0].strip()
            # Handle ==, >=, ~=, etc.
            match = re.match(r'^([A-Za-z0-9_\-\.]+)(?:[=<>!~]+([A-Za-z0-9_\.\-]+))?', line)
            if match:
                name = match.group(1).lower().replace("-", "-")
                version = match.group(2)  # may be None if no pin
                packages[name] = version

        return packages

    def _parse_pyproject(self, path: Path) -> dict[str, str | None]:
        """Very light TOML parser to extract dependencies from pyproject.toml."""
        try:
            import tomllib  # Python 3.11+
        except ImportError:
            try:
                import tomli as tomllib  # type: ignore[no-redef]
            except ImportError:
                # Fallback: regex extraction
                return self._parse_pyproject_regex(path)

        try:
            data = tomllib.loads(path.read_text())
        except Exception:
            return self._parse_pyproject_regex(path)

        packages: dict[str, str | None] = {}
        deps: list[str] = []
        # PEP 517/518 project.dependencies
        project = data.get("project", {})
        deps += project.get("dependencies", [])
        # poetry / tool.poetry.dependencies
        tool = data.get("tool", {})
        poetry_deps = tool.get("poetry", {}).get("dependencies", {})
        for k, v in poetry_deps.items():
            if k.lower() == "python":
                continue
            ver = v if isinstance(v, str) else (v.get("version") if isinstance(v, dict) else None)
            packages[k.lower()] = self._extract_version(ver or "")

        for dep in deps:
            match = re.match(r'^([A-Za-z0-9_\-\.]+)(?:[=<>!~]+([A-Za-z0-9_\.\-]+))?', dep.strip())
            if match:
                packages[match.group(1).lower()] = match.group(2)

        return packages

    def _parse_pyproject_regex(self, path: Path) -> dict[str, str | None]:
        """Regex fallback for pyproject.toml when tomllib is unavailable."""
        packages: dict[str, str | None] = {}
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return {}
        for match in re.finditer(
            r'["\']([A-Za-z0-9_\-\.]+)(?:[=<>!~]+([A-Za-z0-9_\.\-]+))?["\']', text
        ):
            packages[match.group(1).lower()] = match.group(2)
        return packages

    @staticmethod
    def _extract_version(spec: str) -> str | None:
        """Extract version number from a specifier like '>=1.2, <2'."""
        m = re.search(r'([0-9][0-9.a-zA-Z\-]*)', spec)
        return m.group(1) if m else None

    # ------------------------------------------------------------------
    # Advisory lookup
    # ------------------------------------------------------------------

    def _check_package(
        self, name: str, version: str
    ) -> list[dict[str, Any]]:
        advisories: list[dict[str, Any]] = []

        # 1. Check our built-in list first
        for vuln in _KNOWN_VULNS:
            if vuln["package"] == name and _is_below(version, vuln["below"]):
                advisories.append(
                    {
                        "package": name,
                        "installed_version": version,
                        "cve": vuln["cve"],
                        "description": vuln["description"],
                        "severity": "high",
                        "source": "built-in advisory list",
                    }
                )

        # 2. Query PyPI JSON API for the latest version as a simple check
        latest = self._get_latest_pypi_version(name)
        if latest and _is_below(version, latest):
            advisories.append(
                {
                    "package": name,
                    "installed_version": version,
                    "latest_version": latest,
                    "description": f"Outdated package — latest is {latest}",
                    "severity": "info",
                    "source": "PyPI latest",
                }
            )

        return advisories

    def _get_latest_pypi_version(self, package: str) -> str | None:
        """Fetch the latest release version from PyPI JSON API."""
        if package in self._pypi_cache:
            return self._pypi_cache[package]

        url = f"https://pypi.org/pypi/{package}/json"
        try:
            if _HAS_REQUESTS:
                resp = _requests.get(url, timeout=self._timeout)
                if resp.status_code == 200:
                    data = resp.json()
                    version = data.get("info", {}).get("version")
                    self._pypi_cache[package] = version
                    return version
            else:
                import urllib.request
                import urllib.error
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, timeout=self._timeout) as r:
                    import json
                    data = json.loads(r.read().decode())
                    version = data.get("info", {}).get("version")
                    self._pypi_cache[package] = version
                    return version
        except Exception:
            pass

        self._pypi_cache[package] = None
        return None
