# Security Rules Reference: lh-kernel-hardening

An enterprise linux kernel posture & sysctl hardening auditor developed by **Logihertz Systems (OPC) Private Limited**.

This reference manual documents the complete 10-rule security detection registry enforced by `lh-kernel-hardening`.

---

## Detection Catalog Overview

| Rule ID | Severity | Category | Title |
|:---|:---:|:---|:---|
| `LH-KERN-001` | `CRITICAL` | Memory Protection | ASLR Disabled: kernel.randomize_va_space is Not Set to 2 |
| `LH-KERN-002` | `CRITICAL` | Privilege Isolation | Unrestricted eBPF: kernel.unprivileged_bpf_disabled is 0 |
| `LH-KERN-003` | `HIGH` | Process Isolation | Permissive Ptrace: kernel.yama.ptrace_scope is Set to 0 |
| `LH-KERN-004` | `HIGH` | Network Hardening | IP Forwarding Enabled on Non-Router Host |
| `LH-KERN-005` | `HIGH` | Network Resilience | SYN Flood Protection Disabled |
| `LH-KERN-006` | `MEDIUM` | Network Hardening | ICMP Redirect Acceptance Enabled |
| `LH-KERN-007` | `MEDIUM` | Network Hardening | Source Routed Packet Acceptance Enabled |
| `LH-KERN-008` | `HIGH` | Module Hardening | Missing Blacklist for Legacy/Uncommon Network Protocols |
| `LH-KERN-009` | `CRITICAL` | Kernel Integrity | Kexec System Call Unrestricted |
| `LH-KERN-010` | `LOW` | Information Disclosure | Kernel Dmesg Restriction Disabled |

---

## Granular Rule Specifications

### `LH-KERN-001`: ASLR Disabled: kernel.randomize_va_space is Not Set to 2

- **Severity**: `CRITICAL`
- **Category**: `Memory Protection`
- **Description**: Address Space Layout Randomization (ASLR) disabled or partial, simplifying memory corruption exploits.
- **Remediation**: Set kernel.randomize_va_space = 2 in /etc/sysctl.d/99-security.conf to enforce full ASLR.

---

### `LH-KERN-002`: Unrestricted eBPF: kernel.unprivileged_bpf_disabled is 0

- **Severity**: `CRITICAL`
- **Category**: `Privilege Isolation`
- **Description**: Unprivileged users allowed to load eBPF programs, risking kernel privilege escalation.
- **Remediation**: Set kernel.unprivileged_bpf_disabled = 1 to restrict eBPF loading to CAP_BPF / root.

---

### `LH-KERN-003`: Permissive Ptrace: kernel.yama.ptrace_scope is Set to 0

- **Severity**: `HIGH`
- **Category**: `Process Isolation`
- **Description**: Yama ptrace scope allows non-child process memory inspection and code injection.
- **Remediation**: Set kernel.yama.ptrace_scope = 1 or 2 to restrict ptrace to parent processes.

---

### `LH-KERN-004`: IP Forwarding Enabled on Non-Router Host

- **Severity**: `HIGH`
- **Category**: `Network Hardening`
- **Description**: net.ipv4.ip_forward is set to 1 on a standard endpoint, permitting packet routing.
- **Remediation**: Set net.ipv4.ip_forward = 0 unless host operates as an intentional network router.

---

### `LH-KERN-005`: SYN Flood Protection Disabled

- **Severity**: `HIGH`
- **Category**: `Network Resilience`
- **Description**: net.ipv4.tcp_syncookies is disabled, leaving system vulnerable to TCP SYN flood DoS.
- **Remediation**: Set net.ipv4.tcp_syncookies = 1 in /etc/sysctl.d/99-security.conf.

---

### `LH-KERN-006`: ICMP Redirect Acceptance Enabled

- **Severity**: `MEDIUM`
- **Category**: `Network Hardening`
- **Description**: net.ipv4.conf.all.accept_redirects is enabled, allowing malicious routing modifications.
- **Remediation**: Set net.ipv4.conf.all.accept_redirects = 0 and net.ipv6.conf.all.accept_redirects = 0.

---

### `LH-KERN-007`: Source Routed Packet Acceptance Enabled

- **Severity**: `MEDIUM`
- **Category**: `Network Hardening`
- **Description**: net.ipv4.conf.all.accept_source_route is enabled, allowing attacker-specified packet routes.
- **Remediation**: Set net.ipv4.conf.all.accept_source_route = 0 across all network interfaces.

---

### `LH-KERN-008`: Missing Blacklist for Legacy/Uncommon Network Protocols

- **Severity**: `HIGH`
- **Category**: `Module Hardening`
- **Description**: Obsolete network protocols (dccp, sctp, rds, tipc) not blacklisted in /etc/modprobe.d/.
- **Remediation**: Blacklist unused protocols using install <proto> /bin/true in /etc/modprobe.d/blacklist.conf.

---

### `LH-KERN-009`: Kexec System Call Unrestricted

- **Severity**: `CRITICAL`
- **Category**: `Kernel Integrity`
- **Description**: kernel.kexec_load_disabled is set to 0, permitting live reboot into unsigned kernels.
- **Remediation**: Set kernel.kexec_load_disabled = 1 to prevent unauthorized kernel replacement.

---

### `LH-KERN-010`: Kernel Dmesg Restriction Disabled

- **Severity**: `LOW`
- **Category**: `Information Disclosure`
- **Description**: kernel.dmesg_restrict is set to 0, allowing unprivileged users to read kernel logs.
- **Remediation**: Set kernel.dmesg_restrict = 1 to restrict dmesg buffer access to CAP_SYSLOG.

---
