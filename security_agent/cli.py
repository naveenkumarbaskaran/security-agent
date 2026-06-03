"""
CLI entry-point for security-agent-ai.

Usage:
    security-agent scan <directory> [--report report.md] [--fail-on high]
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich import box
from rich.markup import escape

from .agent import Finding, SecurityAgent

console = Console()

SEVERITY_COLOURS: dict[str, str] = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}

SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


@click.group()
def cli() -> None:
    """Security Agent AI — scan source code for vulnerabilities."""


@cli.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False, resolve_path=True))
@click.option(
    "--report",
    default=None,
    type=click.Path(writable=True),
    help="Write a Markdown report to this file.",
)
@click.option(
    "--fail-on",
    "fail_on",
    default="high",
    type=click.Choice(["critical", "high", "medium", "low", "info", "none"]),
    show_default=True,
    help="Exit with code 1 if any finding meets or exceeds this severity.",
)
def scan(
    directory: str,
    report: Optional[str],
    fail_on: str,
) -> None:
    """Scan DIRECTORY for OWASP Top 10 vulnerabilities, secrets, and insecure deps."""
    target = Path(directory)
    console.print(f"[bold blue]Security Agent AI[/bold blue] scanning [bold]{target}[/bold] ...\n")

    agent = SecurityAgent()

    with console.status("[yellow]Running AI-powered security scan...[/yellow]", spinner="dots"):
        try:
            findings = agent.scan(str(target))
        except Exception as exc:
            console.print(f"[bold red]Error:[/bold red] {escape(str(exc))}")
            sys.exit(2)

    if not findings:
        console.print("[bold green]No security issues found.[/bold green]")
    else:
        _print_table(findings)

    if report:
        _write_report(findings, Path(report), target)
        console.print(f"\n[bold]Report written to:[/bold] {report}")

    # Determine exit code
    if fail_on != "none":
        fail_threshold = SEVERITY_ORDER.get(fail_on, 99)
        for f in findings:
            if SEVERITY_ORDER.get(f.severity, 99) <= fail_threshold:
                console.print(
                    f"\n[bold red]FAIL:[/bold red] Found findings at or above "
                    f"[bold]{fail_on}[/bold] severity."
                )
                sys.exit(1)

    console.print("\n[bold green]Scan complete.[/bold green]")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _print_table(findings: list[Finding]) -> None:
    table = Table(
        title="Security Findings",
        box=box.ROUNDED,
        show_lines=True,
        expand=True,
    )
    table.add_column("#", style="dim", width=4, no_wrap=True)
    table.add_column("Severity", width=10, no_wrap=True)
    table.add_column("File", style="bold", overflow="fold")
    table.add_column("Line", width=6, no_wrap=True)
    table.add_column("Description", overflow="fold")
    table.add_column("Fix", overflow="fold")

    for idx, f in enumerate(findings, start=1):
        colour = SEVERITY_COLOURS.get(f.severity, "white")
        table.add_row(
            str(idx),
            f"[{colour}]{f.severity.upper()}[/{colour}]",
            escape(f.file),
            str(f.line) if f.line else "-",
            escape(f.description),
            escape(f.fix),
        )

    console.print(table)

    # Summary line
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    parts = []
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev in counts:
            colour = SEVERITY_COLOURS[sev]
            parts.append(f"[{colour}]{counts[sev]} {sev}[/{colour}]")

    console.print("\nSummary: " + "  ".join(parts))


def _write_report(
    findings: list[Finding],
    output: Path,
    target: Path,
) -> None:
    """Write a Markdown report file."""
    from datetime import datetime, timezone

    lines: list[str] = [
        "# Security Scan Report",
        "",
        f"**Target:** `{target}`",
        f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Total findings:** {len(findings)}",
        "",
    ]

    if not findings:
        lines += ["*No security issues found.*", ""]
    else:
        # Summary table
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        lines += ["## Summary", "", "| Severity | Count |", "|----------|-------|"]
        for sev in ("critical", "high", "medium", "low", "info"):
            if sev in counts:
                lines.append(f"| {sev.capitalize()} | {counts[sev]} |")
        lines += ["", "## Findings", ""]

        for idx, f in enumerate(findings, start=1):
            lines += [
                f"### {idx}. [{f.severity.upper()}] {f.description}",
                "",
                f"- **File:** `{f.file}`",
                f"- **Line:** {f.line if f.line else 'N/A'}",
                f"- **Severity:** {f.severity}",
                "",
                f"**Description:** {f.description}",
                "",
                f"**Recommended Fix:** {f.fix}",
                "",
                "---",
                "",
            ]

    output.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:  # pragma: no cover
    cli()


if __name__ == "__main__":  # pragma: no cover
    main()
