# ==============================================================================
# Product:       lh-kernel-hardening (lh-kernel)
# Module:        src.lh_kernel_hardening.modprobe_scanner
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Linux modprobe configuration static analysis scanner for lh-kernel-hardening.

Inspects /etc/modprobe.d/*.conf configuration files and directory trees for kernel
module blacklists, disabling risky legacy filesystems (cramfs, squashfs, udf) and
uncommon network protocols (rds, sctp, dccp) per rule LH-KERN-009.
"""

from __future__ import annotations

import re
from pathlib import Path

from lh_kernel_hardening.models import (
    Finding,
    ScanTargetResult,
    TargetType,
    create_finding,
)

RISKY_MODULES = {
    "cramfs": "legacy compressed ROM filesystem",
    "squashfs": "compressed read-only filesystem",
    "udf": "Universal Disk Format optical filesystem",
    "rds": "Reliable Datagram Sockets network protocol",
    "sctp": "Stream Control Transmission Protocol",
    "dccp": "Datagram Congestion Control Protocol",
}


class ModprobeScanner:
    """Audits Linux modprobe configuration files for security blacklisting."""

    def __init__(
        self,
        content: str,
        target_path: str = "/etc/modprobe.d/security.conf",
        check_baseline: bool = True,
    ) -> None:
        self.content = content
        self.target_path = target_path
        self.lines = content.splitlines()
        self.check_baseline = check_baseline

    # --------------------------------------------------------------------------
    # --- Rule LH-KERN-009: Kexec System Call Unrestricted (CRITICAL) ---
    # Evaluates security posture against kexec system call unrestricted.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------

    def scan(self) -> ScanTargetResult:
        """Parse modprobe directives and verify module blacklisting (LH-KERN-009)."""
        findings: list[Finding] = []
        disabled_modules: set[str] = set()

        for idx, line in enumerate(self.lines):
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue

            # Check: install <module> /bin/true or /bin/false
            install_match = re.match(
                r"^install\s+([A-Za-z0-9_.-]+)\s+(/bin/true|/bin/false|true|false)",
                line_str,
            )
            if install_match:
                disabled_modules.add(install_match.group(1).lower())
                continue

            # Check: blacklist <module>
            blacklist_match = re.match(r"^blacklist\s+([A-Za-z0-9_.-]+)", line_str)
            if blacklist_match:
                disabled_modules.add(blacklist_match.group(1).lower())
                continue

            # Insecure alias or loading directives
            alias_match = re.match(r"^alias\s+\S+\s+([A-Za-z0-9_.-]+)", line_str)
            if alias_match:
                mod_name = alias_match.group(1).lower()
                if mod_name in RISKY_MODULES and mod_name not in disabled_modules:
                    findings.append(
                        create_finding(
                            rule_id="LH-KERN-009",
                            target=self.target_path,
                            line_number=idx + 1,
                            parameter=mod_name,
                            expected=f"install {mod_name} /bin/true",
                            actual=line_str,
                            message=(
                                f"Risky kernel module '{mod_name}' is aliased for auto-loading "
                                "without being disabled."
                            ),
                            details={"module": mod_name, "directive": line_str},
                        )
                    )

        if self.check_baseline:
            for mod, desc in sorted(RISKY_MODULES.items()):
                if mod not in disabled_modules:
                    findings.append(
                        create_finding(
                            rule_id="LH-KERN-009",
                            target=self.target_path,
                            parameter=mod,
                            expected=f"install {mod} /bin/true",
                            actual="unconfigured / not disabled",
                            message=(
                                f"Risky kernel module '{mod}' ({desc}) is not blacklisted "
                                "or disabled in modprobe configuration."
                            ),
                            details={"module": mod, "description": desc},
                        )
                    )

        return ScanTargetResult(
            target=self.target_path,
            target_type=TargetType.MODPROBE,
            findings=findings,
        )


def scan_modprobe(path: Path | str, check_baseline: bool = True) -> ScanTargetResult:
    """Audit a modprobe configuration file or directory of modprobe configurations.

    Args:
        path: Path to .conf file or modprobe.d directory.
        check_baseline: Whether to verify all risky baseline modules are disabled.

    Returns:
        ScanTargetResult containing all detected findings.
    """
    target = Path(path)
    if not target.exists():
        return ScanTargetResult(
            target=str(target),
            target_type=TargetType.MODPROBE,
            findings=[],
            error_message=f"Target path '{target}' does not exist.",
        )

    if target.is_dir():
        return _scan_modprobe_directory(target, check_baseline=check_baseline)

    try:
        content = target.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        return ScanTargetResult(
            target=str(target),
            target_type=TargetType.MODPROBE,
            findings=[],
            error_message=f"Failed to read modprobe file: {e}",
        )

    scanner = ModprobeScanner(
        content=content,
        target_path=str(target),
        check_baseline=check_baseline,
    )
    return scanner.scan()


def _scan_modprobe_directory(modprobe_dir: Path, check_baseline: bool = True) -> ScanTargetResult:
    """Aggregate and inspect all .conf files in a modprobe.d directory."""
    findings: list[Finding] = []
    disabled_modules: set[str] = set()
    conf_files = sorted(modprobe_dir.glob("*.conf"))

    for conf in conf_files:
        try:
            content = conf.read_text(encoding="utf-8")
            scanner = ModprobeScanner(content, target_path=str(conf), check_baseline=False)
            res = scanner.scan()
            findings.extend(res.findings)

            for line in content.splitlines():
                line = line.strip()
                m_inst = re.match(
                    r"^install\s+([A-Za-z0-9_.-]+)\s+(/bin/true|/bin/false|true|false)",
                    line,
                )
                if m_inst:
                    disabled_modules.add(m_inst.group(1).lower())
                m_black = re.match(r"^blacklist\s+([A-Za-z0-9_.-]+)", line)
                if m_black:
                    disabled_modules.add(m_black.group(1).lower())
        except (OSError, UnicodeDecodeError):
            continue

    if check_baseline:
        for mod, desc in sorted(RISKY_MODULES.items()):
            if mod not in disabled_modules:
                findings.append(
                    create_finding(
                        rule_id="LH-KERN-009",
                        target=str(modprobe_dir),
                        parameter=mod,
                        expected=f"install {mod} /bin/true",
                        actual="unconfigured / not disabled",
                        message=(
                            f"Risky kernel module '{mod}' ({desc}) is not blacklisted "
                            f"or disabled across {modprobe_dir}."
                        ),
                        details={"module": mod, "description": desc},
                    )
                )

    return ScanTargetResult(
        target=str(modprobe_dir),
        target_type=TargetType.MODPROBE,
        findings=findings,
    )
