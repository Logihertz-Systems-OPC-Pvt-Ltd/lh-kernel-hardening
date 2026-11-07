# ==============================================================================
# Product:       lh-kernel-hardening (lh-kernel)
# Module:        tests.test_cli
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for the CLI interface using Typer CliRunner."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from lh_kernel_hardening.cli import app

runner = CliRunner()
CLI_ENV = {"COLUMNS": "160", "NO_COLOR": "1", "TERM": "dumb"}


def test_cli_help() -> None:
    """Test CLI top-level and subcommand help commands."""
    res = runner.invoke(app, ["--help"], env=CLI_ENV)
    assert res.exit_code == 0
    assert "Enterprise Linux kernel sysctl, modprobe" in res.stdout

    res_scan = runner.invoke(app, ["scan", "--help"], env=CLI_ENV)
    assert res_scan.exit_code == 0
    assert "--format" in res_scan.stdout
    assert "--min-severity" in res_scan.stdout
    assert "--fail-on" in res_scan.stdout

    res_rules = runner.invoke(app, ["rules", "--help"], env=CLI_ENV)
    assert res_rules.exit_code == 0
    assert "List all supported LH-KERN security posture detection rules" in res_rules.stdout


def test_cli_rules_list() -> None:
    """Test listing all 10 LH-KERN detection rules."""
    res = runner.invoke(app, ["rules"], env=CLI_ENV)
    assert res.exit_code == 0
    for i in range(1, 11):
        rule_id = f"LH-KERN-{i:03d}"
        assert rule_id in res.stdout


def test_cli_scan_clean_sysctl(tmp_path: Path, sample_hardened_sysctl: str) -> None:
    """Test scanning a hardened sysctl configuration file produces exit code 0."""
    conf_file = tmp_path / "sysctl.conf"
    conf_file.write_text(sample_hardened_sysctl, encoding="utf-8")

    res = runner.invoke(app, ["scan", str(conf_file)], env=CLI_ENV)
    assert res.exit_code == 0
    assert "Clean Audit" in res.stdout


def test_cli_scan_violations_sysctl(tmp_path: Path) -> None:
    """Test scanning an unhardened sysctl configuration produces exit code 1."""
    vuln_conf = tmp_path / "sysctl.conf"
    vuln_conf.write_text(
        "kernel.randomize_va_space = 0\nkernel.kptr_restrict = 0\n",
        encoding="utf-8",
    )

    res = runner.invoke(app, ["scan", str(vuln_conf)], env=CLI_ENV)
    assert res.exit_code == 1
    assert "LH-KERN-001" in res.stdout
    assert "LH-KERN-002" in res.stdout


def test_cli_scan_clean_modprobe(tmp_path: Path, sample_hardened_modprobe: str) -> None:
    """Test scanning a hardened modprobe file produces exit code 0."""
    mod_file = tmp_path / "modprobe.d" / "security.conf"
    mod_file.parent.mkdir(parents=True)
    mod_file.write_text(sample_hardened_modprobe, encoding="utf-8")

    res = runner.invoke(app, ["scan", str(mod_file)], env=CLI_ENV)
    assert res.exit_code == 0
    assert "Clean Audit" in res.stdout


def test_cli_scan_violations_modprobe(tmp_path: Path) -> None:
    """Test scanning an unhardened modprobe file produces exit code 1."""
    mod_file = tmp_path / "modprobe.d" / "security.conf"
    mod_file.parent.mkdir(parents=True)
    mod_file.write_text("# Empty modprobe blacklist\n", encoding="utf-8")

    res = runner.invoke(app, ["scan", str(mod_file)], env=CLI_ENV)
    assert res.exit_code == 1
    assert "LH-KERN-009" in res.stdout


def test_cli_scan_json_output(tmp_path: Path) -> None:
    """Test CLI output in JSON format."""
    conf = tmp_path / "sysctl.conf"
    conf.write_text("kernel.randomize_va_space = 2\n", encoding="utf-8")

    res = runner.invoke(app, ["scan", str(conf), "--format", "json"], env=CLI_ENV)
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["report_type"] == "kernel_hardening_audit"
    assert "summary" in data


def test_cli_scan_sarif_output(tmp_path: Path) -> None:
    """Test CLI output in SARIF format."""
    conf = tmp_path / "sysctl.conf"
    conf.write_text("kernel.randomize_va_space = 0\n", encoding="utf-8")

    res = runner.invoke(
        app,
        ["scan", str(conf), "--format", "sarif", "--fail-on", "CRITICAL"],
        env=CLI_ENV,
    )
    assert res.exit_code == 1
    data = json.loads(res.stdout)
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1


def test_cli_scan_output_file(tmp_path: Path) -> None:
    """Test writing scan results to an output file."""
    conf = tmp_path / "sysctl.conf"
    conf.write_text("kernel.randomize_va_space = 2\n", encoding="utf-8")
    out_file = tmp_path / "report.json"

    res = runner.invoke(
        app,
        ["scan", str(conf), "--format", "json", "--output", str(out_file)],
        env=CLI_ENV,
    )
    assert res.exit_code == 0
    assert out_file.exists()
    content = json.loads(out_file.read_text(encoding="utf-8"))
    assert content["report_type"] == "kernel_hardening_audit"


def test_cli_scan_fail_on_threshold(tmp_path: Path) -> None:
    """Test --fail-on threshold logic."""
    conf = tmp_path / "sysctl.conf"
    # kernel.sysrq = 1 is MEDIUM severity (LH-KERN-004)
    conf.write_text("kernel.sysrq = 1\n", encoding="utf-8")

    # Fail on HIGH should exit 0
    res_high = runner.invoke(
        app,
        ["scan", str(conf), "--fail-on", "HIGH"],
        env=CLI_ENV,
    )
    assert res_high.exit_code == 0

    # Fail on MEDIUM should exit 1
    res_med = runner.invoke(
        app,
        ["scan", str(conf), "--fail-on", "MEDIUM"],
        env=CLI_ENV,
    )
    assert res_med.exit_code == 1


def test_cli_scan_min_severity_filter(tmp_path: Path) -> None:
    """Test --min-severity filtering out lower severity findings."""
    conf = tmp_path / "sysctl.conf"
    conf.write_text("kernel.sysrq = 1\n", encoding="utf-8")

    res = runner.invoke(
        app,
        ["scan", str(conf), "--min-severity", "CRITICAL", "--format", "json"],
        env=CLI_ENV,
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["summary"]["total_findings"] == 0


def test_cli_scan_directory(tmp_path: Path) -> None:
    """Test directory scanning finds sysctl and modprobe configurations."""
    dir_path = tmp_path / "etc"
    dir_path.mkdir()

    f1 = dir_path / "sysctl.conf"
    f1.write_text("kernel.randomize_va_space = 2\n", encoding="utf-8")

    f2 = dir_path / "modprobe.d" / "security.conf"
    f2.parent.mkdir(parents=True)
    f2.write_text("install cramfs /bin/true\n", encoding="utf-8")

    res = runner.invoke(app, ["scan", str(dir_path), "--format", "json"], env=CLI_ENV)
    assert res.exit_code == 1  # f2 is missing other blacklists
    data = json.loads(res.stdout)
    assert data["summary"]["total_targets"] >= 2


def test_cli_scan_nonexistent_target() -> None:
    """Test CLI error exit on missing file or directory."""
    res = runner.invoke(app, ["scan", "/nonexistent/path/sysctl.conf"], env=CLI_ENV)
    assert res.exit_code == 2
    assert "does not exist" in res.stdout
