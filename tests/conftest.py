# ==============================================================================
# Product:       lh-kernel-hardening (lh-kernel)
# Module:        tests.conftest
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Shared test fixtures for lh-kernel-hardening."""

from __future__ import annotations

import pytest


@pytest.fixture
def sample_hardened_sysctl() -> str:
    """Return a hardened, fully compliant sysctl configuration."""
    return """
    # Memory & Process Protections
    kernel.randomize_va_space = 2
    kernel.kptr_restrict = 2
    kernel.dmesg_restrict = 1
    kernel.yama.ptrace_scope = 1
    kernel.unprivileged_bpf_disabled = 1
    kernel.sysrq = 0
    fs.suid_dumpable = 0

    # Filesystem Protections
    fs.protected_symlinks = 1
    fs.protected_hardlinks = 1
    fs.protected_fifos = 2
    fs.protected_regular = 2

    # Network Stack Hardening
    net.ipv4.tcp_syncookies = 1
    net.ipv4.conf.all.rp_filter = 1
    net.ipv4.conf.default.rp_filter = 1
    net.ipv4.conf.all.accept_redirects = 0
    net.ipv4.conf.default.accept_redirects = 0
    net.ipv4.conf.all.send_redirects = 0
    net.ipv4.conf.default.send_redirects = 0
    net.ipv4.conf.all.accept_source_route = 0
    net.ipv4.conf.default.accept_source_route = 0
    net.ipv6.conf.all.accept_redirects = 0
    net.ipv6.conf.default.accept_redirects = 0
    net.ipv6.conf.all.accept_source_route = 0

    # IP Routing and Logging
    net.ipv4.ip_forward = 0
    net.ipv6.conf.all.forwarding = 0
    net.ipv4.conf.all.log_martians = 1
    net.ipv4.conf.default.log_martians = 1

    # Privilege and BPF
    kernel.modules_disabled = 1
    kernel.unprivileged_userns_clone = 0
    net.core.bpf_jit_harden = 2
    """


@pytest.fixture
def sample_hardened_modprobe() -> str:
    """Return a hardened modprobe blacklist configuration."""
    return """
    # Disable unneeded legacy filesystems
    install cramfs /bin/true
    install squashfs /bin/true
    install udf /bin/true

    # Disable risky and unused network protocols
    install rds /bin/true
    install sctp /bin/true
    install dccp /bin/true
    """
