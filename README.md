# lh-kernel-hardening

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-kernel-hardening/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-kernel-hardening/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

An enterprise linux kernel & sysctl posture auditor developed by **Logihertz Systems (OPC) Private Limited**.

Evaluates /etc/sysctl.conf, /proc/sys runtime snapshots, kernel boot parameters, and /etc/modprobe.d blacklists against KSPP and CIS benchmarks for ASLR, kptr_restrict, eBPF restrictions, and SYN flood defenses.

---

## Key Features

- **Comprehensive Kernel Parameter Auditing**: Evaluates memory protections, network stack flags, process tracing, and eBPF restrictions against CIS benchmarks.
- **Module Blacklist Inspection**: Checks `/etc/modprobe.d/` for blacklisting of obsolete, unmaintained, or dangerous filesystem protocols (cramfs, freevxfs, jffs2, dccp).
- **Security Subsystem Verification**: Audits the status of ASLR, AppArmor, SELinux, and Yama ptrace scope restrictions.
- **Offline & Live Auditing**: Supports live kernel parameter inspection and static auditing of configuration directories on offline system images.
- **Multi-Format Reporting**: Outputs rich terminal tables, structured JSON, and OASIS SARIF v2.1.0.

---

## Core Detection Rules

| Rule ID | Severity | Description |
|:---|:---:|:---|
| `LH-KERN-001` | `CRITICAL` | ASLR Disabled: kernel.randomize_va_space is not set to 2 (full ASLR) |
| `LH-KERN-002` | `CRITICAL` | Unrestricted eBPF: kernel.unprivileged_bpf_disabled is set to 0 allowing unprivileged eBPF |
| `LH-KERN-003` | `HIGH` | Permissive Ptrace: kernel.yama.ptrace_scope is set to 0 allowing non-child process debugging |
| `LH-KERN-004` | `HIGH` | IP Forwarding Enabled: net.ipv4.ip_forward is enabled on non-router host |
| `LH-KERN-005` | `HIGH` | SYN Flood Protection Disabled: net.ipv4.tcp_syncookies is disabled |
| `LH-KERN-006` | `MEDIUM` | ICMP Redirect Acceptance Enabled: net.ipv4.conf.all.accept_redirects is enabled |
| `LH-KERN-007` | `MEDIUM` | Source Routed Packet Acceptance: net.ipv4.conf.all.accept_source_route is enabled |
| `LH-KERN-008` | `HIGH` | Missing Blacklist for Legacy/Uncommon Protocols (dccp, sctp, rds, tipc) in modprobe configs |
| `LH-KERN-009` | `CRITICAL` | Kexec System Call Unrestricted: kernel.kexec_load_disabled is set to 0 |
| `LH-KERN-010` | `LOW` | Missing or Permissive Kernel Dmesg Restriction: kernel.dmesg_restrict is set to 0 |

---

## Installation

### Using `uv` (Recommended)

```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-kernel-hardening.git
cd lh-kernel-hardening

# Create virtual environment and install in editable mode with development tools
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Using standard `pip`

```bash
pip install -e .
```

---

## CLI Usage

The primary executable entrypoint is `lh-kernel` (also accessible via `lh-kernel`, `lh-kernel-hardening`).

```bash
# Scan live host kernel parameters
lh-kernel scan /proc/sys/

# Audit a sysctl configuration file or directory
lh-kernel scan /etc/sysctl.d/ --format json

# Export findings to OASIS SARIF v2.1.0
lh-kernel scan /etc/sysctl.conf --format sarif --output kernel.sarif

# List all kernel hardening detection rules
lh-kernel rules
```

---

## Exit Codes

| Exit Code | Meaning |
|:---:|:---|
| `0` | All audits and security checks passed; no policy violations detected. |
| `1` | One or more security findings, policy violations, or compliance failures detected. |
| `2` | Execution error (invalid arguments, missing input files, malformed syntax). |

---

## Documentation

Comprehensive enterprise documentation is available in the [`docs/`](docs/) directory and repository root:

- **[Architecture & Design](docs/ARCHITECTURE.md)**: Zero-daemon clean-room architecture, module responsibilities, domain models, and 0–100 risk score calculation formula.
- **[Security Rules Reference](docs/RULES.md)**: Exhaustive catalog of all 10 detection rules with threat models, severities, and remediation guides.
- **[CLI Usage Guide](docs/USAGE.md)**: Complete command-line manual, flags, exit codes, CI/CD SARIF upload workflows, and JSON pipelines.
- **[Test & Verification Declaration](docs/TESTING.md)**: Audited test inventory, AST security verification, SAST audit results, and per-module code coverage metrics.
- **[Changelog](CHANGELOG.md)**: Semantic release history and detailed changelog entries.
- **[Contributing Guidelines](CONTRIBUTING.md)**: Developer setup, coding standards, line length, typing, and PR requirements.
- **[Security Policy](SECURITY.md)**: Vulnerability disclosure procedure, reporting email, and 48-hour response SLA.
- **[Legal Notice & Attributions](NOTICE)**: Apache-2.0 Section 4 legal notice, trademark reservations, and third-party software attributions.

## Development & Testing

Run all project linters, security audits, and test suites:

```bash
# Run code style and lint checks
uv run ruff check src/ tests/

# Run static application security testing (SAST)
uv run bandit -r src/

# Run unit and integration tests with coverage
uv run pytest
```

---

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) and [NOTICE](NOTICE) files for details.

Developed with precision by **Logihertz Systems (OPC) Private Limited** (`logihertzsystems`).  
Created, architected, and engineered by **Sameer Tawade** (Creator, Founder, Director & Whole and Sole Developer — `ops@logihertz.com`).
