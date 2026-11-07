# ==============================================================================
# Product:       lh-kernel-hardening (lh-kernel)
# Module:        src.lh_kernel_hardening.sysctl_scanner
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Linux sysctl configuration static analysis scanner for lh-kernel-hardening.

Inspects sysctl files (/etc/sysctl.conf, /etc/sysctl.d/*.conf) and /proc/sys snapshots
for ASLR, pointer/dmesg restrictions, ptrace scope, SUID dumps, filesystem link protections,
TCP SYN cookies, Reverse Path Filtering, ICMP redirects, IP forwarding, and BPF JIT hardening.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from lh_kernel_hardening.models import (
    Finding,
    ScanTargetResult,
    TargetType,
    create_finding,
)

SYSCTL_RULES: list[dict[str, Any]] = [
    {
        "rule_id": "LH-KERN-001",
        "param": "kernel.randomize_va_space",
        "expected": "2",
        "check": lambda val: val == 2,
        "message": (
            "ASLR is disabled or incomplete (kernel.randomize_va_space = {actual}, expected 2)."
        ),
    },
    {
        "rule_id": "LH-KERN-002",
        "param": "kernel.kptr_restrict",
        "expected": ">= 1 (recommended 2)",
        "check": lambda val: val >= 1,
        "message": (
            "Kernel pointers are exposed to unprivileged users "
            "(kernel.kptr_restrict = {actual}, expected >= 1)."
        ),
    },
    {
        "rule_id": "LH-KERN-002",
        "param": "kernel.dmesg_restrict",
        "expected": "1",
        "check": lambda val: val == 1,
        "message": (
            "Unprivileged users can view the kernel syslog "
            "(kernel.dmesg_restrict = {actual}, expected 1)."
        ),
    },
    {
        "rule_id": "LH-KERN-003",
        "param": "kernel.yama.ptrace_scope",
        "expected": ">= 1",
        "check": lambda val: val >= 1,
        "message": (
            "Yama ptrace scope is unrestricted "
            "(kernel.yama.ptrace_scope = {actual}, expected >= 1)."
        ),
    },
    {
        "rule_id": "LH-KERN-003",
        "param": "kernel.unprivileged_bpf_disabled",
        "expected": "1",
        "check": lambda val: val == 1,
        "message": (
            "Unprivileged eBPF execution is allowed "
            "(kernel.unprivileged_bpf_disabled = {actual}, expected 1)."
        ),
    },
    {
        "rule_id": "LH-KERN-004",
        "param": "kernel.sysrq",
        "expected": "0",
        "check": lambda val: val == 0,
        "message": ("Magic SysRq key is enabled (kernel.sysrq = {actual}, expected 0)."),
    },
    {
        "rule_id": "LH-KERN-004",
        "param": "fs.suid_dumpable",
        "expected": "0",
        "check": lambda val: val == 0,
        "message": (
            "SUID binaries are allowed to produce core dumps "
            "(fs.suid_dumpable = {actual}, expected 0)."
        ),
    },
    {
        "rule_id": "LH-KERN-005",
        "param": "fs.protected_symlinks",
        "expected": "1",
        "check": lambda val: val == 1,
        "message": (
            "Symlink traversal protection is disabled "
            "(fs.protected_symlinks = {actual}, expected 1)."
        ),
    },
    {
        "rule_id": "LH-KERN-005",
        "param": "fs.protected_hardlinks",
        "expected": "1",
        "check": lambda val: val == 1,
        "message": (
            "Hardlink creation protection is disabled "
            "(fs.protected_hardlinks = {actual}, expected 1)."
        ),
    },
    {
        "rule_id": "LH-KERN-005",
        "param": "fs.protected_fifos",
        "expected": ">= 1 (recommended 2)",
        "check": lambda val: val >= 1,
        "message": (
            "FIFO protection in world-writable directories is disabled "
            "(fs.protected_fifos = {actual}, expected >= 1)."
        ),
    },
    {
        "rule_id": "LH-KERN-005",
        "param": "fs.protected_regular",
        "expected": ">= 1 (recommended 2)",
        "check": lambda val: val >= 1,
        "message": (
            "Regular file protection in world-writable directories is disabled "
            "(fs.protected_regular = {actual}, expected >= 1)."
        ),
    },
    {
        "rule_id": "LH-KERN-006",
        "param": "net.ipv4.tcp_syncookies",
        "expected": "1",
        "check": lambda val: val == 1,
        "message": (
            "TCP SYN cookies protection is disabled "
            "(net.ipv4.tcp_syncookies = {actual}, expected 1)."
        ),
    },
    {
        "rule_id": "LH-KERN-006",
        "param": "net.ipv4.conf.all.rp_filter",
        "expected": "1",
        "check": lambda val: val == 1,
        "message": (
            "Reverse Path Filtering is disabled on all interfaces "
            "(net.ipv4.conf.all.rp_filter = {actual}, expected 1)."
        ),
    },
    {
        "rule_id": "LH-KERN-006",
        "param": "net.ipv4.conf.default.rp_filter",
        "expected": "1",
        "check": lambda val: val == 1,
        "message": (
            "Reverse Path Filtering is disabled on default interfaces "
            "(net.ipv4.conf.default.rp_filter = {actual}, expected 1)."
        ),
    },
    {
        "rule_id": "LH-KERN-007",
        "param": "net.ipv4.conf.all.accept_redirects",
        "expected": "0",
        "check": lambda val: val == 0,
        "message": (
            "ICMP redirects accepted on all interfaces "
            "(net.ipv4.conf.all.accept_redirects = {actual}, expected 0)."
        ),
    },
    {
        "rule_id": "LH-KERN-007",
        "param": "net.ipv4.conf.default.accept_redirects",
        "expected": "0",
        "check": lambda val: val == 0,
        "message": (
            "ICMP redirects accepted on default interfaces "
            "(net.ipv4.conf.default.accept_redirects = {actual}, expected 0)."
        ),
    },
    {
        "rule_id": "LH-KERN-007",
        "param": "net.ipv4.conf.all.send_redirects",
        "expected": "0",
        "check": lambda val: val == 0,
        "message": (
            "ICMP redirects sent on all interfaces "
            "(net.ipv4.conf.all.send_redirects = {actual}, expected 0)."
        ),
    },
    {
        "rule_id": "LH-KERN-007",
        "param": "net.ipv4.conf.default.send_redirects",
        "expected": "0",
        "check": lambda val: val == 0,
        "message": (
            "ICMP redirects sent on default interfaces "
            "(net.ipv4.conf.default.send_redirects = {actual}, expected 0)."
        ),
    },
    {
        "rule_id": "LH-KERN-007",
        "param": "net.ipv4.conf.all.accept_source_route",
        "expected": "0",
        "check": lambda val: val == 0,
        "message": (
            "IP source routing accepted on all interfaces "
            "(net.ipv4.conf.all.accept_source_route = {actual}, expected 0)."
        ),
    },
    {
        "rule_id": "LH-KERN-007",
        "param": "net.ipv4.conf.default.accept_source_route",
        "expected": "0",
        "check": lambda val: val == 0,
        "message": (
            "IP source routing accepted on default interfaces "
            "(net.ipv4.conf.default.accept_source_route = {actual}, expected 0)."
        ),
    },
    {
        "rule_id": "LH-KERN-007",
        "param": "net.ipv6.conf.all.accept_redirects",
        "expected": "0",
        "check": lambda val: val == 0,
        "message": (
            "IPv6 ICMP redirects accepted on all interfaces "
            "(net.ipv6.conf.all.accept_redirects = {actual}, expected 0)."
        ),
    },
    {
        "rule_id": "LH-KERN-007",
        "param": "net.ipv6.conf.default.accept_redirects",
        "expected": "0",
        "check": lambda val: val == 0,
        "message": (
            "IPv6 ICMP redirects accepted on default interfaces "
            "(net.ipv6.conf.default.accept_redirects = {actual}, expected 0)."
        ),
    },
    {
        "rule_id": "LH-KERN-007",
        "param": "net.ipv6.conf.all.accept_source_route",
        "expected": "0",
        "check": lambda val: val == 0,
        "message": (
            "IPv6 source routing accepted on all interfaces "
            "(net.ipv6.conf.all.accept_source_route = {actual}, expected 0)."
        ),
    },
    {
        "rule_id": "LH-KERN-008",
        "param": "net.ipv4.ip_forward",
        "expected": "0",
        "check": lambda val: val == 0,
        "message": (
            "IPv4 packet forwarding is enabled (net.ipv4.ip_forward = {actual}, expected 0)."
        ),
    },
    {
        "rule_id": "LH-KERN-008",
        "param": "net.ipv6.conf.all.forwarding",
        "expected": "0",
        "check": lambda val: val == 0,
        "message": (
            "IPv6 packet forwarding is enabled "
            "(net.ipv6.conf.all.forwarding = {actual}, expected 0)."
        ),
    },
    {
        "rule_id": "LH-KERN-008",
        "param": "net.ipv4.conf.all.log_martians",
        "expected": "1",
        "check": lambda val: val == 1,
        "message": (
            "Martian packet logging is disabled on all interfaces "
            "(net.ipv4.conf.all.log_martians = {actual}, expected 1)."
        ),
    },
    {
        "rule_id": "LH-KERN-008",
        "param": "net.ipv4.conf.default.log_martians",
        "expected": "1",
        "check": lambda val: val == 1,
        "message": (
            "Martian packet logging is disabled on default interfaces "
            "(net.ipv4.conf.default.log_martians = {actual}, expected 1)."
        ),
    },
    {
        "rule_id": "LH-KERN-009",
        "param": "kernel.modules_disabled",
        "expected": "1",
        "check": lambda val: val == 1,
        "message": (
            "Kernel module loading is not disabled "
            "(kernel.modules_disabled = {actual}, expected 1)."
        ),
    },
    {
        "rule_id": "LH-KERN-010",
        "param": "kernel.unprivileged_userns_clone",
        "expected": "0",
        "check": lambda val: val == 0,
        "message": (
            "Unprivileged user namespaces clone is permitted "
            "(kernel.unprivileged_userns_clone = {actual}, expected 0)."
        ),
    },
    {
        "rule_id": "LH-KERN-010",
        "param": "net.core.bpf_jit_harden",
        "expected": "2",
        "check": lambda val: val >= 2,
        "message": (
            "BPF JIT blinding hardening is insufficient "
            "(net.core.bpf_jit_harden = {actual}, expected 2)."
        ),
    },
]


class SysctlScanner:
    """Audits Linux sysctl configuration text or parsed parameters."""

    def __init__(self, content: str, target_path: str = "/etc/sysctl.conf") -> None:
        self.content = content
        self.target_path = target_path
        self.lines = content.splitlines()

    def scan(self) -> ScanTargetResult:
        """Parse sysctl lines and evaluate hardening compliance rules."""
        findings: list[Finding] = []
        parsed_params: dict[str, tuple[Any, int]] = {}

        for idx, line in enumerate(self.lines):
            line_str = line.strip()
            if not line_str or line_str.startswith("#") or line_str.startswith(";"):
                continue

            match = re.match(r"^([A-Za-z0-9_.-]+)\s*=\s*(.+)$", line_str)
            if not match:
                continue

            param_name = match.group(1).strip()
            raw_val = match.group(2).strip()

            val: Any
            try:
                val = int(raw_val)
            except ValueError:
                val = raw_val

            parsed_params[param_name] = (val, idx + 1)

        for rule in SYSCTL_RULES:
            param = rule["param"]
            if param in parsed_params:
                val, line_num = parsed_params[param]
                check_fn = rule["check"]
                if not check_fn(val):
                    msg = rule["message"].format(actual=val)
                    findings.append(
                        create_finding(
                            rule_id=rule["rule_id"],
                            target=self.target_path,
                            line_number=line_num,
                            parameter=param,
                            expected=rule["expected"],
                            actual=str(val),
                            message=msg,
                            details={"parameter": param, "value": val},
                        )
                    )

        return ScanTargetResult(
            target=self.target_path,
            target_type=TargetType.SYSCTL,
            findings=findings,
        )


def scan_sysctl(path: Path | str) -> ScanTargetResult:
    """Audit a sysctl configuration file or a /proc/sys snapshot directory.

    Args:
        path: Path to sysctl file or /proc/sys directory.

    Returns:
        ScanTargetResult containing all detected findings.
    """
    target = Path(path)
    if not target.exists():
        return ScanTargetResult(
            target=str(target),
            target_type=TargetType.SYSCTL,
            findings=[],
            error_message=f"Target path '{target}' does not exist.",
        )

    if target.is_dir():
        return _scan_proc_sys_directory(target)

    try:
        content = target.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        return ScanTargetResult(
            target=str(target),
            target_type=TargetType.SYSCTL,
            findings=[],
            error_message=f"Failed to read sysctl file: {e}",
        )

    scanner = SysctlScanner(content=content, target_path=str(target))
    return scanner.scan()


def _scan_proc_sys_directory(proc_dir: Path) -> ScanTargetResult:
    """Read kernel parameter files under /proc/sys snapshot directory."""
    findings: list[Finding] = []

    for rule in SYSCTL_RULES:
        param = rule["param"]
        rel_path = param.replace(".", "/")
        param_file = proc_dir / rel_path

        if param_file.is_file():
            try:
                raw = param_file.read_text(encoding="utf-8").strip()
                val: Any
                try:
                    val = int(raw)
                except ValueError:
                    val = raw

                if not rule["check"](val):
                    findings.append(
                        create_finding(
                            rule_id=rule["rule_id"],
                            target=str(param_file),
                            parameter=param,
                            expected=rule["expected"],
                            actual=str(val),
                            message=rule["message"].format(actual=val),
                            details={"parameter": param, "value": val},
                        )
                    )
            except (OSError, UnicodeDecodeError):
                continue

    return ScanTargetResult(
        target=str(proc_dir),
        target_type=TargetType.PROC_SYS,
        findings=findings,
    )
