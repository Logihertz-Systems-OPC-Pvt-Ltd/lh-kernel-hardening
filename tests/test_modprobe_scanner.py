# ==============================================================================
# Product:       lh-kernel-hardening (lh-kernel)
# Module:        tests.test_modprobe_scanner
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for ModprobeScanner."""

from __future__ import annotations

from pathlib import Path

from lh_kernel_hardening.models import FindingSeverity
from lh_kernel_hardening.modprobe_scanner import ModprobeScanner, scan_modprobe


def test_modprobe_clean_config(sample_hardened_modprobe: str) -> None:
    """Test that a compliant modprobe blacklist produces zero findings."""
    scanner = ModprobeScanner(sample_hardened_modprobe, "/etc/modprobe.d/hardened.conf")
    res = scanner.scan()
    assert not res.has_error
    assert len(res.findings) == 0
    # --------------------------------------------------------------------------
    # --- Rule LH-KERN-009: Kexec System Call Unrestricted (CRITICAL) ---
    # Evaluates security posture against kexec system call unrestricted.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_modprobe_missing_blacklists() -> None:
    """Test LH-KERN-009: Missing blacklists for risky filesystems and protocols."""
    conf = """
    # Only blacklists cramfs
    install cramfs /bin/true
    """
    scanner = ModprobeScanner(conf, check_baseline=True)
    res = scanner.scan()
    findings_009 = [f for f in res.findings if f.rule_id == "LH-KERN-009"]
    # 5 missing modules: squashfs, udf, rds, sctp, dccp
    assert len(findings_009) == 5
    for f in findings_009:
        assert f.severity == FindingSeverity.HIGH


def test_modprobe_insecure_alias() -> None:
    """Test LH-KERN-009: Insecure alias directive enabling risky module."""
    conf = """
    install cramfs /bin/true
    install squashfs /bin/true
    install udf /bin/true
    install sctp /bin/true
    install dccp /bin/true
    alias net-pf-27 rds
    """
    scanner = ModprobeScanner(conf, check_baseline=False)
    res = scanner.scan()
    findings_009 = [f for f in res.findings if f.rule_id == "LH-KERN-009"]
    assert len(findings_009) == 1
    assert "aliased for auto-loading" in findings_009[0].message


def test_modprobe_directory_scan(tmp_path: Path) -> None:
    """Test scanning a directory of modprobe configuration files."""
    mod_dir = tmp_path / "modprobe.d"
    mod_dir.mkdir()

    f1 = mod_dir / "filesystems.conf"
    f1.write_text(
        "install cramfs /bin/true\ninstall squashfs /bin/true\ninstall udf /bin/true\n",
        encoding="utf-8",
    )

    f2 = mod_dir / "protocols.conf"
    f2.write_text(
        "install rds /bin/true\ninstall sctp /bin/true\ninstall dccp /bin/true\n",
        encoding="utf-8",
    )

    res = scan_modprobe(mod_dir, check_baseline=True)
    assert not res.has_error
    assert len(res.findings) == 0


def test_modprobe_error_handling(tmp_path: Path) -> None:
    """Test error handling when target file does not exist."""
    missing = tmp_path / "missing.conf"
    res = scan_modprobe(missing)
    assert res.has_error
    assert "does not exist" in (res.error_message or "").lower()
