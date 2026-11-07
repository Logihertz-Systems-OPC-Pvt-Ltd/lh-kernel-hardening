# ==============================================================================
# Product:       lh-kernel-hardening (lh-kernel)
# Module:        src.lh_kernel_hardening.cli
# Role:          CLI Interface & Execution Controller
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Command-line interface for lh-kernel-hardening.

Implements CLI commands:
- lh-kernel scan <path> [--format table|json|sarif] [--output <path>]
                        [--min-severity <level>] [--fail-on <level>]
- lh-kernel rules
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from lh_kernel_hardening.exporters import (
    OutputFormat,
    export_json,
    export_sarif,
    render_table_report,
)
from lh_kernel_hardening.models import (
    RULES_REGISTRY,
    AuditReport,
    FindingSeverity,
    ScanTargetResult,
)
from lh_kernel_hardening.modprobe_scanner import scan_modprobe
from lh_kernel_hardening.sysctl_scanner import scan_sysctl

# --- Exit Code Semantics ---
# Exit Code 0: Audit passed successfully with zero policy violations.
# Exit Code 1: Security findings detected meeting or exceeding failure threshold (--fail-on).
# Exit Code 2: Command execution error, invalid arguments, or unparseable input target.

app = typer.Typer(
    name="lh-kernel",
    help=(
        "Enterprise Linux kernel sysctl, modprobe, and security posture auditor.\n"
        "Developed by Logihertz Systems (OPC) Private Limited."
    ),
    no_args_is_help=True,
    rich_markup_mode=None,
)
console = Console()


def _is_modprobe_target(path: Path) -> bool:
    """Check if target path represents a modprobe configuration or directory."""
    name = path.name.lower()
    path_str = str(path).lower()
    return "modprobe" in name or "modprobe" in path_str


def _discover_and_scan(target_path: Path) -> list[ScanTargetResult]:
    """Scan target path (file or directory)."""
    results: list[ScanTargetResult] = []

    if target_path.is_file():
        if _is_modprobe_target(target_path):
            results.append(scan_modprobe(target_path))
        else:
            results.append(scan_sysctl(target_path))
        return results

    if _is_modprobe_target(target_path):
        results.append(scan_modprobe(target_path))
        return results

    if target_path.name == "sys" and target_path.parent.name == "proc":
        results.append(scan_sysctl(target_path))
        return results

    found_targets = False

    modprobe_files = list(target_path.rglob("modprobe.d/*.conf"))
    if modprobe_files:
        for mf in sorted(set(modprobe_files)):
            results.append(scan_modprobe(mf))
            found_targets = True

    sysctl_files = (
        list(target_path.rglob("*.conf"))
        + list(target_path.rglob("sysctl.conf"))
        + list(target_path.rglob("sysctl.d/*.conf"))
    )
    for sf in sorted(set(sysctl_files)):
        if sf.is_file() and not _is_modprobe_target(sf):
            results.append(scan_sysctl(sf))
            found_targets = True

    if not found_targets:
        results.append(scan_sysctl(target_path))

    return results


def _output_report(
    report: AuditReport,
    fmt: OutputFormat,
    output_path: Path | None,
) -> None:
    """Format and write or print the audit report according to format and destination."""
    report.compute_summary()

    if fmt == OutputFormat.JSON:
        rendered = export_json(report)
    elif fmt == OutputFormat.SARIF:
        rendered = export_sarif(report)
    else:
        if output_path:
            file_console = Console(record=True, width=120, color_system=None)
            render_table_report(report, console=file_console)
            rendered = file_console.export_text()
        else:
            render_table_report(report, console=console)
            rendered = ""

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
        console.print(f"[bold green]Report successfully written to {output_path}[/bold green]")
    elif rendered:
        print(rendered)


@app.command(name="scan")
def scan(
    path: Annotated[
        str,
        typer.Argument(help="Path to sysctl config, modprobe blacklist, /proc/sys, or directory."),
    ],
    format: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Output format: table, json, or sarif."),
    ] = OutputFormat.TABLE,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Path to write output report file."),
    ] = None,
    min_severity: Annotated[
        FindingSeverity | None,
        typer.Option("--min-severity", "-s", help="Filter findings below this severity."),
    ] = None,
    fail_on: Annotated[
        FindingSeverity | None,
        typer.Option(
            "--fail-on",
            help="Severity threshold for failure exit (CRITICAL, HIGH, MEDIUM, LOW).",
        ),
    ] = FindingSeverity.HIGH,
) -> None:
    """Scan Linux kernel parameters and module blacklists for security hardening."""
    target_path = Path(path)
    if not target_path.exists():
        console.print(f"[bold red]Error: Target path '{path}' does not exist.[/bold red]")
        raise typer.Exit(code=2)

    results = _discover_and_scan(target_path)

    report = AuditReport(
        report_type="kernel_hardening_audit",
        generated_at=datetime.now(UTC),
        parameters={
            "path": path,
            "format": format.value,
            "min_severity": min_severity.value if min_severity else None,
            "fail_on": fail_on.value if fail_on else None,
        },
        results=results,
    )

    if min_severity is not None:
        report.filter_min_severity(min_severity)

    _output_report(report, format, output)

    if report.has_failures(fail_on):
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


@app.command(name="rules")
def rules() -> None:
    """List all supported LH-KERN security posture detection rules."""
    table = Table(
        title="LH-KERN Kernel Hardening Detection Rules",
        border_style="blue",
    )
    table.add_column("Rule ID", style="bold magenta", no_wrap=True)
    table.add_column("Severity", justify="center")
    table.add_column("Category", style="cyan")
    table.add_column("Rule Title", style="bold white")
    table.add_column("Targets")
    table.add_column("Description")

    sev_styles = {
        FindingSeverity.CRITICAL: "bold white on red",
        FindingSeverity.HIGH: "bold red",
        FindingSeverity.MEDIUM: "bold yellow",
        FindingSeverity.LOW: "bold cyan",
    }

    for rule_id, rule_def in sorted(RULES_REGISTRY.items()):
        badge = Text(rule_def.severity.value, style=sev_styles.get(rule_def.severity, "bold"))
        targets_str = ", ".join(t.value for t in rule_def.targets)
        table.add_row(
            rule_id,
            badge,
            rule_def.category.value,
            rule_def.title,
            targets_str,
            rule_def.description,
        )

    console.print(table)


if __name__ == "__main__":
    app()
