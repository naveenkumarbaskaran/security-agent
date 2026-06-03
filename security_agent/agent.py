"""
SecurityAgent — drives Claude claude-sonnet-4-6 with three tools:
  scan_file          : static OWASP / code-quality scan of a single file
  grep_secrets       : regex-based secret / credential leakage scan
  check_dependencies : PyPI advisory lookup for requirements files

Produces structured Finding objects (severity, file, line, description, fix).
"""

from __future__ import annotations

import json
import os
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import anthropic

from .scanners import DepScanner, SecretScanner

MODEL = "claude-sonnet-4-6"

SYSTEM_PROMPT = textwrap.dedent("""
    You are a senior application-security engineer.
    Your job is to scan source-code for security vulnerabilities.

    You have three tools:
      1. scan_file(path)              — analyse a single source file for OWASP Top 10
                                        vulnerabilities and insecure coding patterns.
      2. grep_secrets(directory)      — search a directory tree for hard-coded secrets,
                                        API keys, passwords, and tokens.
      3. check_dependencies(req_file) — check a requirements.txt / pyproject.toml for
                                        packages with known vulnerable versions.

    For every issue you find, return a JSON array of findings with this exact shape:
    [
      {
        "severity":    "critical" | "high" | "medium" | "low" | "info",
        "file":        "<relative path>",
        "line":        <int or null>,
        "description": "<what the issue is>",
        "fix":         "<concrete remediation advice>"
      }
    ]

    Be thorough but precise — avoid false positives.
    Group your final answer as one consolidated JSON array of all findings.
""").strip()


@dataclass
class Finding:
    severity: str
    file: str
    line: int | None
    description: str
    fix: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "description": self.description,
            "fix": self.fix,
        }


class SecurityAgent:
    """Orchestrates Claude + the three scanning tools."""

    def __init__(self, api_key: str | None = None) -> None:
        self._client = anthropic.Anthropic(
            api_key=api_key or os.environ.get("ANTHROPIC_API_KEY")
        )
        self._secret_scanner = SecretScanner()
        self._dep_scanner = DepScanner()

    # ------------------------------------------------------------------
    # Tool implementations
    # ------------------------------------------------------------------

    def _scan_file(self, path: str) -> str:
        """Read a file and ask Claude to identify OWASP vulnerabilities."""
        p = Path(path)
        if not p.is_file():
            return json.dumps({"error": f"File not found: {path}"})
        try:
            content = p.read_text(errors="replace")
        except OSError as exc:
            return json.dumps({"error": str(exc)})

        # Return the file content so the outer Claude session can analyse it.
        # The outer model already has instructions; we just feed it the raw code.
        return json.dumps(
            {
                "path": str(p),
                "lines": content.count("\n") + 1,
                "content": content[:50_000],  # safety cap
            }
        )

    def _grep_secrets(self, directory: str) -> str:
        """Run the regex-based secret scanner over a directory."""
        d = Path(directory)
        if not d.is_dir():
            return json.dumps({"error": f"Directory not found: {directory}"})
        hits = self._secret_scanner.scan_directory(d)
        return json.dumps({"directory": str(d), "matches": hits})

    def _check_dependencies(self, requirements_file: str) -> str:
        """Check a requirements file for known-vulnerable versions."""
        p = Path(requirements_file)
        if not p.is_file():
            return json.dumps({"error": f"File not found: {requirements_file}"})
        results = self._dep_scanner.check(p)
        return json.dumps({"file": str(p), "results": results})

    # ------------------------------------------------------------------
    # Tool dispatch
    # ------------------------------------------------------------------

    _TOOL_DEFINITIONS: list[dict[str, Any]] = [
        {
            "name": "scan_file",
            "description": (
                "Read a single source-code file and return its content for "
                "OWASP Top 10 vulnerability analysis. Use this for every "
                "relevant source file in the target directory."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute or relative path to the file.",
                    }
                },
                "required": ["path"],
            },
        },
        {
            "name": "grep_secrets",
            "description": (
                "Scan a directory tree with regex patterns to find hard-coded "
                "secrets, API keys, tokens, and passwords in source files."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "directory": {
                        "type": "string",
                        "description": "Path to the directory to scan recursively.",
                    }
                },
                "required": ["directory"],
            },
        },
        {
            "name": "check_dependencies",
            "description": (
                "Check a requirements.txt or pyproject.toml file for packages "
                "with known vulnerable versions via PyPI advisories."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "requirements_file": {
                        "type": "string",
                        "description": "Path to the requirements file.",
                    }
                },
                "required": ["requirements_file"],
            },
        },
    ]

    def _dispatch(self, name: str, tool_input: dict[str, Any]) -> str:
        if name == "scan_file":
            return self._scan_file(tool_input["path"])
        if name == "grep_secrets":
            return self._grep_secrets(tool_input["directory"])
        if name == "check_dependencies":
            return self._check_dependencies(tool_input["requirements_file"])
        return json.dumps({"error": f"Unknown tool: {name}"})

    # ------------------------------------------------------------------
    # Main scan entry-point
    # ------------------------------------------------------------------

    def scan(self, directory: str) -> list[Finding]:
        """
        Scan *directory* for security issues.

        Returns a list of Finding objects, sorted by severity.
        """
        target = Path(directory).resolve()
        user_message = (
            f"Please perform a comprehensive security scan of the project at: {target}\n\n"
            "Steps to follow:\n"
            "1. Use grep_secrets to scan for hard-coded credentials in the whole directory.\n"
            "2. Enumerate all Python source files (.py) and scan each with scan_file.\n"
            "3. If a requirements.txt or pyproject.toml exists, run check_dependencies on it.\n"
            "4. Consolidate every issue into a single JSON array of findings using the schema "
            "described in your instructions. Output ONLY the JSON array as your final message."
        )

        messages: list[dict[str, Any]] = [{"role": "user", "content": user_message}]

        # Agentic loop — keep going until Claude stops requesting tools.
        while True:
            response = self._client.messages.create(
                model=MODEL,
                max_tokens=8192,
                system=SYSTEM_PROMPT,
                tools=self._TOOL_DEFINITIONS,
                messages=messages,
            )

            # Append assistant's full response to history.
            messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason == "end_turn":
                # Extract the final JSON answer.
                return self._parse_findings(response)

            if response.stop_reason != "tool_use":
                # Unexpected stop — return whatever we can parse.
                return self._parse_findings(response)

            # Execute all requested tools and feed results back.
            tool_results: list[dict[str, Any]] = []
            for block in response.content:
                if block.type == "tool_use":
                    result_text = self._dispatch(block.name, block.input)
                    tool_results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": result_text,
                        }
                    )

            messages.append({"role": "user", "content": tool_results})

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_findings(response: anthropic.types.Message) -> list[Finding]:
        """Extract and parse the JSON findings array from the final message."""
        text = ""
        for block in response.content:
            if block.type == "text":
                text += block.text

        # Try to locate a JSON array in the text.
        start = text.find("[")
        end = text.rfind("]")
        if start == -1 or end == -1:
            return []

        try:
            raw = json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return []

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings: list[Finding] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            findings.append(
                Finding(
                    severity=str(item.get("severity", "info")).lower(),
                    file=str(item.get("file", "unknown")),
                    line=item.get("line"),
                    description=str(item.get("description", "")),
                    fix=str(item.get("fix", "")),
                )
            )

        findings.sort(key=lambda f: severity_order.get(f.severity, 99))
        return findings
