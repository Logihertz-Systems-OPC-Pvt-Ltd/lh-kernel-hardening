# ==============================================================================
# Product:       lh-kernel-hardening (lh-kernel)
# Module:        src.lh_kernel_hardening.__init__
# Role:          Package Initialization & Public API Declarations
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""lh-kernel-hardening: Enterprise Linux kernel sysctl and modprobe security auditor.

Audits Linux kernel sysctl configurations, modprobe blacklists, and /proc/sys runtime
parameters for memory protections, ASLR, pointer restrictions, filesystem link defenses,
network stack hardening, and risky kernel module blacklisting.

Developed by Logihertz Systems (OPC) Private Limited.
"""

from __future__ import annotations

from lh_kernel_hardening.exporters import (
    OutputFormat,
    export_json,
    export_sarif,
    render_table_report,
)
from lh_kernel_hardening.models import (
    RULES_REGISTRY,
    AuditReport,
    Finding,
    FindingCategory,
    FindingSeverity,
    RuleDefinition,
    ScanTargetResult,
    TargetType,
    create_finding,
)
from lh_kernel_hardening.modprobe_scanner import ModprobeScanner, scan_modprobe
from lh_kernel_hardening.sysctl_scanner import SysctlScanner, scan_sysctl

__version__ = "0.1.0"

__all__ = [
    "RULES_REGISTRY",
    "AuditReport",
    "Finding",
    "FindingCategory",
    "FindingSeverity",
    "ModprobeScanner",
    "OutputFormat",
    "RuleDefinition",
    "ScanTargetResult",
    "SysctlScanner",
    "TargetType",
    "__version__",
    "create_finding",
    "export_json",
    "export_sarif",
    "render_table_report",
    "scan_modprobe",
    "scan_sysctl",
]
