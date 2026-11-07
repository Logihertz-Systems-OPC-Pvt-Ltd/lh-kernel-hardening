# ==============================================================================
# Product:       lh-kernel-hardening (lh-kernel)
# Module:        src.lh_kernel_hardening.models
# Role:          Data Models & Rule Definitions
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Data models and findings representations for lh-kernel-hardening.

Provides structured types for Linux sysctl and modprobe targets, security findings,
severity classifications, detection rule definitions, and audit reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class FindingSeverity(StrEnum):
    # --- Severity Rank & Weighting Structure ---
    # Defines discrete security tiers for findings and threshold gating.
    # Higher ordinal rankings enforce stricter build break / fail-on gates.
    """Severity classification for kernel security posture findings."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def level(self) -> int:
        """Numeric rank for threshold comparisons."""
        order = {
            FindingSeverity.LOW: 1,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.HIGH: 3,
            FindingSeverity.CRITICAL: 4,
        }
        return order[self]

    def meets_threshold(self, threshold: FindingSeverity) -> bool:
        """Return True if this severity meets or exceeds threshold."""
        return self.level >= threshold.level


class FindingCategory(StrEnum):
    """Categories aligning with Linux kernel hardening domains."""

    MEMORY_PROTECTION = "MEMORY_PROTECTION"
    INFO_DISCLOSURE = "INFO_DISCLOSURE"
    PROCESS_ISOLATION = "PROCESS_ISOLATION"
    SYSTEM_INTEGRITY = "SYSTEM_INTEGRITY"
    FILESYSTEM_SECURITY = "FILESYSTEM_SECURITY"
    NETWORK_HARDENING = "NETWORK_HARDENING"
    MODULE_SECURITY = "MODULE_SECURITY"
    PRIVILEGE_CONTROL = "PRIVILEGE_CONTROL"


class TargetType(StrEnum):
    """Configuration artifact dialect or inspection target."""

    SYSCTL = "SYSCTL"
    MODPROBE = "MODPROBE"
    PROC_SYS = "PROC_SYS"
    UNKNOWN = "UNKNOWN"


@dataclass
class RuleDefinition:
    """Metadata definition for a built-in LH-KERN posture audit rule."""

    rule_id: str
    title: str
    severity: FindingSeverity
    category: FindingCategory
    description: str
    remediation: str
    targets: list[TargetType]


@dataclass
class Finding:
    """Represents a specific Linux kernel security misconfiguration or flaw."""

    rule_id: str
    title: str
    category: FindingCategory
    severity: FindingSeverity
    target: str
    message: str
    line_number: int | None = None
    parameter: str | None = None
    expected: str | None = None
    actual: str | None = None
    resource: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary representation."""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity.value,
            "target": self.target,
            "line_number": self.line_number,
            "parameter": self.parameter or self.resource,
            "expected": self.expected,
            "actual": self.actual,
            "resource": self.resource or self.parameter,
            "message": self.message,
            "details": self.details,
        }


@dataclass
class ScanTargetResult:
    """Analysis results for a single target file or directory."""

    target: str
    target_type: TargetType
    findings: list[Finding] = field(default_factory=list)
    error_message: str | None = None

    @property
    def has_error(self) -> bool:
        """Whether target analysis encountered an execution error."""
        return self.error_message is not None

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary representation."""
        return {
            "target": self.target,
            "target_type": self.target_type.value,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "error_message": self.error_message,
        }


@dataclass
class AuditReport:
    """Complete aggregated audit report across all analyzed targets."""

    report_type: str = "kernel_hardening_audit"
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    parameters: dict[str, Any] = field(default_factory=dict)
    results: list[ScanTargetResult] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)

    def compute_summary(self) -> None:
        """Recalculate summary totals from all scanned target results."""
        all_findings = [f for r in self.results for f in r.findings]
        self.summary = {
            "total_targets": len(self.results),
            "total_findings": len(all_findings),
            "critical": sum(1 for f in all_findings if f.severity == FindingSeverity.CRITICAL),
            "high": sum(1 for f in all_findings if f.severity == FindingSeverity.HIGH),
            "medium": sum(1 for f in all_findings if f.severity == FindingSeverity.MEDIUM),
            "low": sum(1 for f in all_findings if f.severity == FindingSeverity.LOW),
        }

    def filter_min_severity(self, min_severity: FindingSeverity | None) -> None:
        """Filter out findings with severity lower than min_severity."""
        if min_severity is None:
            return
        for r in self.results:
            r.findings = [f for f in r.findings if f.severity.meets_threshold(min_severity)]
        self.compute_summary()

    def has_failures(self, fail_on: FindingSeverity | None) -> bool:
        """Check if any finding meets or exceeds the fail_on threshold."""
        if fail_on is None:
            return False
        for r in self.results:
            if r.error_message:
                return True
            for f in r.findings:
                if f.severity.meets_threshold(fail_on):
                    return True
        return False

    def to_dict(self) -> dict[str, Any]:
        """Serialize complete audit report to dictionary."""
        self.compute_summary()
        return {
            "report_type": self.report_type,
            "generated_at": self.generated_at.isoformat(),
            "parameters": self.parameters,
            "summary": self.summary,
            "results": [r.to_dict() for r in self.results],
        }


RULES_REGISTRY: dict[str, RuleDefinition] = {
    "LH-KERN-001": RuleDefinition(
        rule_id="LH-KERN-001",
        title="Weak or disabled Address Space Layout Randomization",
        severity=FindingSeverity.CRITICAL,
        category=FindingCategory.MEMORY_PROTECTION,
        description=(
            "Address Space Layout Randomization (ASLR) is disabled or partially applied "
            "(kernel.randomize_va_space != 2), allowing memory corruption and ROP exploits."
        ),
        remediation="Set 'kernel.randomize_va_space = 2' in /etc/sysctl.d/99-security.conf.",
        targets=[TargetType.SYSCTL, TargetType.PROC_SYS],
    ),
    "LH-KERN-002": RuleDefinition(
        rule_id="LH-KERN-002",
        title="Exposed kernel pointers or unprivileged dmesg access",
        severity=FindingSeverity.HIGH,
        category=FindingCategory.INFO_DISCLOSURE,
        description=(
            "Kernel pointers are exposed via /proc and format strings (kernel.kptr_restrict < 1) "
            "or unprivileged users can read the kernel ring buffer (kernel.dmesg_restrict != 1)."
        ),
        remediation=("Set 'kernel.kptr_restrict = 2' and 'kernel.dmesg_restrict = 1' in sysctl."),
        targets=[TargetType.SYSCTL, TargetType.PROC_SYS],
    ),
    "LH-KERN-003": RuleDefinition(
        rule_id="LH-KERN-003",
        title="Unrestricted ptrace scope or unprivileged BPF execution",
        severity=FindingSeverity.HIGH,
        category=FindingCategory.PROCESS_ISOLATION,
        description=(
            "Yama ptrace scope is unrestricted (kernel.yama.ptrace_scope < 1) or unprivileged "
            "users are allowed to load eBPF programs (kernel.unprivileged_bpf_disabled != 1)."
        ),
        remediation=(
            "Set 'kernel.yama.ptrace_scope = 1' (or 2) and 'kernel.unprivileged_bpf_disabled = 1'."
        ),
        targets=[TargetType.SYSCTL, TargetType.PROC_SYS],
    ),
    "LH-KERN-004": RuleDefinition(
        rule_id="LH-KERN-004",
        title="Enabled Magic SysRq key or SUID core dumps enabled",
        severity=FindingSeverity.MEDIUM,
        category=FindingCategory.SYSTEM_INTEGRITY,
        description=(
            "Magic SysRq key is enabled (kernel.sysrq != 0) allowing console control, "
            "or SUID programs are allowed to produce core dumps (fs.suid_dumpable != 0)."
        ),
        remediation="Set 'kernel.sysrq = 0' and 'fs.suid_dumpable = 0' in sysctl configuration.",
        targets=[TargetType.SYSCTL, TargetType.PROC_SYS],
    ),
    "LH-KERN-005": RuleDefinition(
        rule_id="LH-KERN-005",
        title="Missing symlink, hardlink, FIFO, or regular file link protections",
        severity=FindingSeverity.HIGH,
        category=FindingCategory.FILESYSTEM_SECURITY,
        description=(
            "VFS link protections are disabled (fs.protected_symlinks != 1, "
            "fs.protected_hardlinks != 1, fs.protected_fifos < 1, or fs.protected_regular < 1), "
            "permitting arbitrary file overwrites and symlink traversal in /tmp."
        ),
        remediation=(
            "Set fs.protected_symlinks = 1, fs.protected_hardlinks = 1, "
            "fs.protected_fifos = 2, and fs.protected_regular = 2."
        ),
        targets=[TargetType.SYSCTL, TargetType.PROC_SYS],
    ),
    "LH-KERN-006": RuleDefinition(
        rule_id="LH-KERN-006",
        title="Missing TCP SYN flood protection or Reverse Path Filtering disabled",
        severity=FindingSeverity.HIGH,
        category=FindingCategory.NETWORK_HARDENING,
        description=(
            "TCP SYN cookies are disabled (net.ipv4.tcp_syncookies != 1) or Reverse Path "
            "Filtering is disabled (net.ipv4.conf.all.rp_filter != 1), risking IP spoofing."
        ),
        remediation=(
            "Set 'net.ipv4.tcp_syncookies = 1' and 'net.ipv4.conf.all.rp_filter = 1' and "
            "'net.ipv4.conf.default.rp_filter = 1'."
        ),
        targets=[TargetType.SYSCTL, TargetType.PROC_SYS],
    ),
    "LH-KERN-007": RuleDefinition(
        rule_id="LH-KERN-007",
        title="ICMP redirects or source-routed packets accepted or sent",
        severity=FindingSeverity.MEDIUM,
        category=FindingCategory.NETWORK_HARDENING,
        description=(
            "Kernel accepts ICMP redirects (accept_redirects != 0), sends ICMP redirects "
            "(send_redirects != 0), or accepts source-routed packets (accept_source_route != 0)."
        ),
        remediation=(
            "Set accept_redirects = 0, send_redirects = 0, and accept_source_route = 0 "
            "for both net.ipv4.conf.all and net.ipv4.conf.default."
        ),
        targets=[TargetType.SYSCTL, TargetType.PROC_SYS],
    ),
    "LH-KERN-008": RuleDefinition(
        rule_id="LH-KERN-008",
        title="Unintended IPv4/IPv6 packet forwarding enabled or unlogged martian packets",
        severity=FindingSeverity.MEDIUM,
        category=FindingCategory.NETWORK_HARDENING,
        description=(
            "IP forwarding is enabled on non-router host (net.ipv4.ip_forward == 1 or "
            "net.ipv6.conf.all.forwarding == 1) or martian packets are not logged."
        ),
        remediation=(
            "Disable packet forwarding (ip_forward = 0, forwarding = 0) and enable "
            "'net.ipv4.conf.all.log_martians = 1'."
        ),
        targets=[TargetType.SYSCTL, TargetType.PROC_SYS],
    ),
    "LH-KERN-009": RuleDefinition(
        rule_id="LH-KERN-009",
        title="Unpinned module loading or legacy filesystems unblocked",
        severity=FindingSeverity.HIGH,
        category=FindingCategory.MODULE_SECURITY,
        description=(
            "Kernel module loading is unpinned or risky legacy filesystems/protocols (cramfs, "
            "squashfs, udf, rds, sctp, dccp) are not blacklisted in /etc/modprobe.d/."
        ),
        remediation=(
            "Add 'install <module> /bin/true' and 'blacklist <module>' in /etc/modprobe.d/ "
            "for unused filesystems and uncommon network protocols."
        ),
        targets=[TargetType.MODPROBE, TargetType.SYSCTL, TargetType.PROC_SYS],
    ),
    "LH-KERN-010": RuleDefinition(
        rule_id="LH-KERN-010",
        title="Unprivileged user namespaces enabled or BPF JIT hardening missing",
        severity=FindingSeverity.HIGH,
        category=FindingCategory.PRIVILEGE_CONTROL,
        description=(
            "Unprivileged user namespaces are enabled (kernel.unprivileged_userns_clone == 1) "
            "or BPF JIT constant blinding is disabled (net.core.bpf_jit_harden < 2)."
        ),
        remediation=(
            "Set 'kernel.unprivileged_userns_clone = 0' and 'net.core.bpf_jit_harden = 2' "
            "to prevent privilege escalation and JIT spraying attacks."
        ),
        targets=[TargetType.SYSCTL, TargetType.PROC_SYS],
    ),
}


def create_finding(
    rule_id: str,
    target: str,
    message: str,
    line_number: int | None = None,
    parameter: str | None = None,
    expected: str | None = None,
    actual: str | None = None,
    resource: str | None = None,
    details: dict[str, Any] | None = None,
) -> Finding:
    """Construct a Finding instance with metadata populated from RULES_REGISTRY."""
    rule = RULES_REGISTRY[rule_id]
    param = parameter or resource
    res = resource or parameter
    return Finding(
        rule_id=rule.rule_id,
        title=rule.title,
        category=rule.category,
        severity=rule.severity,
        target=target,
        message=message,
        line_number=line_number,
        parameter=param,
        expected=expected,
        actual=actual,
        resource=res,
        details=details or {},
    )
