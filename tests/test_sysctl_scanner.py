# ==============================================================================
# Product:       lh-kernel-hardening (lh-kernel)
# Module:        tests.test_sysctl_scanner
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for SysctlScanner."""

from __future__ import annotations

from pathlib import Path

from lh_kernel_hardening.models import FindingSeverity
from lh_kernel_hardening.sysctl_scanner import SysctlScanner, scan_sysctl


def test_sysctl_clean_config(sample_hardened_sysctl: str) -> None:
    """Test that a compliant, hardened sysctl configuration yields zero findings."""
    scanner = SysctlScanner(sample_hardened_sysctl, "/etc/sysctl.conf")
    res = scanner.scan()
    assert not res.has_error
    assert len(res.findings) == 0
    # --------------------------------------------------------------------------
    # --- Rule LH-KERN-001 (CRITICAL):
    #     ASLR Disabled: kernel.randomize_va_space is Not Set to 2
    # ---
    # Evaluates security posture against aslr disabled: kernel.randomize_va_space is
    # not set to 2.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_sysctl_weak_aslr() -> None:
    """Test LH-KERN-001: ASLR disabled or set below 2."""
    conf = "kernel.randomize_va_space = 0\n"
    scanner = SysctlScanner(conf)
    res = scanner.scan()
    findings_001 = [f for f in res.findings if f.rule_id == "LH-KERN-001"]
    assert len(findings_001) == 1
    assert findings_001[0].severity == FindingSeverity.CRITICAL
    # --------------------------------------------------------------------------
    # --- Rule LH-KERN-002 (CRITICAL):
    #     Unrestricted eBPF: kernel.unprivileged_bpf_disabled is 0
    # ---
    # Evaluates security posture against unrestricted ebpf:
    # kernel.unprivileged_bpf_disabled is 0.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_sysctl_kptr_and_dmesg_restrict() -> None:
    """Test LH-KERN-002: Kernel pointer exposure and unprivileged dmesg access."""
    conf = "kernel.kptr_restrict = 0\nkernel.dmesg_restrict = 0\n"
    scanner = SysctlScanner(conf)
    res = scanner.scan()
    findings_002 = [f for f in res.findings if f.rule_id == "LH-KERN-002"]
    assert len(findings_002) == 2
    for f in findings_002:
        assert f.severity == FindingSeverity.HIGH
    # --------------------------------------------------------------------------
    # --- Rule LH-KERN-003 (HIGH):
    #     Permissive Ptrace: kernel.yama.ptrace_scope is Set to 0
    # ---
    # Evaluates security posture against permissive ptrace: kernel.yama.ptrace_scope
    # is set to 0.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_sysctl_ptrace_and_bpf() -> None:
    """Test LH-KERN-003: Unrestricted ptrace and unprivileged eBPF execution."""
    conf = "kernel.yama.ptrace_scope = 0\nkernel.unprivileged_bpf_disabled = 0\n"
    scanner = SysctlScanner(conf)
    res = scanner.scan()
    findings_003 = [f for f in res.findings if f.rule_id == "LH-KERN-003"]
    assert len(findings_003) == 2
    for f in findings_003:
        assert f.severity == FindingSeverity.HIGH
    # --------------------------------------------------------------------------
    # --- Rule LH-KERN-004: IP Forwarding Enabled on Non-Router Host (HIGH) ---
    # Evaluates security posture against ip forwarding enabled on non-router host.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_sysctl_sysrq_and_suid_dumpable() -> None:
    """Test LH-KERN-004: Magic SysRq enabled and SUID core dumps permitted."""
    conf = "kernel.sysrq = 1\nfs.suid_dumpable = 1\n"
    scanner = SysctlScanner(conf)
    res = scanner.scan()
    findings_004 = [f for f in res.findings if f.rule_id == "LH-KERN-004"]
    assert len(findings_004) == 2
    for f in findings_004:
        assert f.severity == FindingSeverity.MEDIUM
    # --------------------------------------------------------------------------
    # --- Rule LH-KERN-005: SYN Flood Protection Disabled (HIGH) ---
    # Evaluates security posture against syn flood protection disabled.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_sysctl_filesystem_link_protections() -> None:
    """Test LH-KERN-005: Missing symlink, hardlink, and FIFO protections."""
    conf = """
    fs.protected_symlinks = 0
    fs.protected_hardlinks = 0
    fs.protected_fifos = 0
    fs.protected_regular = 0
    """
    scanner = SysctlScanner(conf)
    res = scanner.scan()
    findings_005 = [f for f in res.findings if f.rule_id == "LH-KERN-005"]
    assert len(findings_005) == 4
    for f in findings_005:
        assert f.severity == FindingSeverity.HIGH
    # --------------------------------------------------------------------------
    # --- Rule LH-KERN-006: ICMP Redirect Acceptance Enabled (MEDIUM) ---
    # Evaluates security posture against icmp redirect acceptance enabled.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_sysctl_syn_flood_and_rp_filter() -> None:
    """Test LH-KERN-006: Missing SYN flood protection and Reverse Path Filtering."""
    conf = """
    net.ipv4.tcp_syncookies = 0
    net.ipv4.conf.all.rp_filter = 0
    net.ipv4.conf.default.rp_filter = 0
    """
    scanner = SysctlScanner(conf)
    res = scanner.scan()
    findings_006 = [f for f in res.findings if f.rule_id == "LH-KERN-006"]
    assert len(findings_006) == 3
    for f in findings_006:
        assert f.severity == FindingSeverity.HIGH
    # --------------------------------------------------------------------------
    # --- Rule LH-KERN-007: Source Routed Packet Acceptance Enabled (MEDIUM) ---
    # Evaluates security posture against source routed packet acceptance enabled.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_sysctl_icmp_and_source_routing() -> None:
    """Test LH-KERN-007: ICMP redirects and source-routed packets accepted or sent."""
    conf = """
    net.ipv4.conf.all.accept_redirects = 1
    net.ipv4.conf.all.send_redirects = 1
    net.ipv4.conf.all.accept_source_route = 1
    net.ipv6.conf.all.accept_redirects = 1
    """
    scanner = SysctlScanner(conf)
    res = scanner.scan()
    findings_007 = [f for f in res.findings if f.rule_id == "LH-KERN-007"]
    assert len(findings_007) == 4
    for f in findings_007:
        assert f.severity == FindingSeverity.MEDIUM
    # --------------------------------------------------------------------------
    # --- Rule LH-KERN-008 (HIGH):
    #     Missing Blacklist for Legacy/Uncommon Network Protocols
    # ---
    # Evaluates security posture against missing blacklist for legacy/uncommon
    # network protocols.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_sysctl_ip_forwarding_and_martians() -> None:
    """Test LH-KERN-008: Packet forwarding enabled and unlogged martian packets."""
    conf = """
    net.ipv4.ip_forward = 1
    net.ipv6.conf.all.forwarding = 1
    net.ipv4.conf.all.log_martians = 0
    """
    scanner = SysctlScanner(conf)
    res = scanner.scan()
    findings_008 = [f for f in res.findings if f.rule_id == "LH-KERN-008"]
    assert len(findings_008) == 3
    # --------------------------------------------------------------------------
    # --- Rule LH-KERN-010: Kernel Dmesg Restriction Disabled (LOW) ---
    # Evaluates security posture against kernel dmesg restriction disabled.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_sysctl_userns_and_bpf_jit() -> None:
    """Test LH-KERN-010: Unprivileged user namespaces and BPF JIT blinding."""
    conf = """
    kernel.unprivileged_userns_clone = 1
    net.core.bpf_jit_harden = 0
    """
    scanner = SysctlScanner(conf)
    res = scanner.scan()
    findings_010 = [f for f in res.findings if f.rule_id == "LH-KERN-010"]
    assert len(findings_010) == 2


def test_sysctl_proc_sys_snapshot(tmp_path: Path) -> None:
    """Test auditing a simulated /proc/sys snapshot directory."""
    proc_sys = tmp_path / "proc" / "sys"
    aslr_file = proc_sys / "kernel" / "randomize_va_space"
    aslr_file.parent.mkdir(parents=True)
    aslr_file.write_text("0\n", encoding="utf-8")

    res = scan_sysctl(proc_sys)
    assert not res.has_error
    findings_001 = [f for f in res.findings if f.rule_id == "LH-KERN-001"]
    assert len(findings_001) == 1
    assert findings_001[0].actual == "0"


def test_sysctl_error_handling(tmp_path: Path) -> None:
    """Test scanner error reporting on missing files."""
    missing = tmp_path / "missing.conf"
    res = scan_sysctl(missing)
    assert res.has_error
    assert "does not exist" in (res.error_message or "").lower()
