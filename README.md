# StealthWizard

**StealthWizard** is a military-grade penetration testing tool engineered for covert operations against Active Directory (AD) environments and Microsoft 365 (M365) cloud tenants. Designed for red team engagements, it executes reconnaissance, credential harvesting, spraying, and cloud privilege escalation with ruthless efficiency, prioritizing stealth, security, and operational control. Leveraging asynchronous operations, robust encryption, and stringent OPSEC, StealthWizard ensures minimal detection risk while maximizing breach impact.

> **WARNING**: This tool is intended for authorized security testing only. Unauthorized use violates legal and ethical boundaries. Ensure you have explicit permission (e.g., a signed engagement letter) before deployment.

## Table of Contents
- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Operational Security (OPSEC)](#operational-security-opsec)
- [Error Handling](#error-handling)
- [Extending the Tool](#extending-the-tool)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)

## Features

StealthWizard delivers a surgical strike against target environments with the following capabilities:

- **Covert Reconnaissance**:
  - Passive asset discovery via crt.sh and Hunter.io for domain and email enumeration.
  - Active scanning with Masscan and Nmap, optimized for low-and-slow evasion.
  - Active Directory (AD) indicator scoring to pinpoint domain controllers and critical hosts.
  - Cloud tenant validation using GetUserRealm and autodiscover endpoint probing for M365.

- **Credential Harvesting and Spraying**:
  - Username enumeration via Hunter.io, LDAP anonymous binds, and pattern-based generation (e.g., `{first}.{last}@{domain}`).
  - Password spraying across LDAP and M365 services with lockout prevention.
  - Password policy discovery using cracked credentials for strategic escalation.
  - Support for NTLM hash-based authentication to exploit weak credentials.

- **Cloud Tenant Infiltration**:
  - Microsoft 365 role enumeration and privilege escalation (e.g., Global Administrator) with compromised credentials.
  - Autodiscover endpoint discovery for M365 service mapping.
  - Seamless pivot from on-premises AD to cloud environments.

- **Stealth and Evasion**:
  - Asynchronous I/O with `aiohttp`, `aiofiles`, and `aiodns` for minimal footprint.
  - DNS over HTTPS (DoH) with multiple resolvers (Cloudflare, Google, OpenDNS) for private resolution.
  - Proxy chain support with randomized selection for traffic obfuscation.
  - User-Agent rotation and HTTP header manipulation (e.g., X-Forwarded-For) to mimic legitimate traffic.
  - Scan signature profiling to evade intrusion detection systems (IDS).

- **Security and OPSEC**:
  - AES-256-CBC encryption for audit logs and temporary files with unique IVs.
  - Sensitive data redaction using regex patterns for logs and outputs.
  - Secure file shredding with multiple overwrite passes to eliminate traces.
  - Detection threshold monitoring with immediate abort on exposure risk (e.g., WAF, rate limits).
  - External key management for audit logs and temp files to prevent key exposure.

- **Audit and Compliance**:
  - Immutable, encrypted audit logs for all actions with timestamped events.
  - Engagement letter validation (PDF text extraction) to enforce legal scope.
  - Detailed logging with redacted sensitive data (e.g., passwords, API keys).

## Architecture

StealthWizard is structured as a modular, asynchronous Python script, leveraging a class-based design for extensibility and control. Key components include:

- **Data Classes**:
  - `Credential`: Manages username, password, NTLM hashes, and privilege levels (e.g., user, global_admin).
  - `TargetInfo`: Stores domain, cloud tenant, IP ranges, and AD details (e.g., domain SID, functional level).
  - `Job`: Tracks operation state, reconnaissance results, credential harvest, audit logs, and OPSEC settings.

- **Core Class**:
  - `StealthWizard`: Orchestrates the attack pipeline with methods for each stage:
    - `gatekeeper`: Validates engagement letter and initializes operation.
    - `target_definition`: Maps domains, IPs, and cloud tenants.
    - `recon_surface_mapping`: Performs passive and active reconnaissance.
    - `credential_harvest_spray`: Harvests and sprays credentials.
    - `cloud_pivot`: Escalates access in M365 tenants.

- **Utilities**:
  - Encryption (`encrypt_data`, `decrypt_data`) for secure data handling.
  - File shredding (`shred_file_async`) for trace elimination.
  - Command execution (`_execute_command`) with sandboxing support (e.g., firejail).
  - HTTP requests (`_execute_async_request`) with stealth headers and proxy support.

- **OPSEC**:
  - Configurable settings (`OPSEC_CONFIG`) for jitter, proxies, detection thresholds, and more.
  - Signal handling (`SIGINT`, `SIGTERM`) for graceful shutdown.
  - Redaction (`StealthFormatter`) for log security, masking sensitive data.

## Prerequisites

### System Requirements
- **Operating System**: Linux (Ubuntu recommended) or Windows with WSL2.
- **Python**: 3.8+ (tested with 3.11).
- **CPU**: Multi-core recommended for async performance.
- **Memory**: 4GB minimum, 8GB+ for large-scale scans.
- **Network**: Stable internet with egress to target networks (port 443 for DoH, scanning ports).

### Dependencies
Install Python packages via pip:
```bash
pip install pycryptodome aiohttp aiodns async-timeout aiofiles pypdf
