# StealthWizard README

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
```

### External Tools
The following tools must be installed and accessible in the system PATH or specified in the config:
- **certsh.py**: Custom script for crt.sh queries (placeholder; replace with actual tool).
- **hunterio_tool**: Hunter.io email enumeration tool (requires API key).
- **ldap_tool**: LDAP enumeration and authentication tool.
- **aad_spray_tool**: M365 credential spraying and role enumeration tool.
- **masscan**: High-speed port scanner.
- **nmap**: Network exploration tool with scripting engine.
- **pdftotext**: PDF text extraction utility (part of `poppler-utils`).

Install tools on Ubuntu:
```bash
sudo apt update
sudo apt install masscan nmap poppler-utils
# Install custom tools (certsh.py, hunterio_tool, ldap_tool, aad_spray_tool) manually
```

### Permissions
- **Root Privileges**: Required for Masscan and some Nmap scripts (e.g., SMB enumeration).
- **File Permissions**: Write access to results directory (default: `./results`).
- **Network Permissions**: Egress on ports 80, 443, and target-specific ports (e.g., 88, 389, 445).

## Installation

1. **Clone or Download the Repository**:
   ```bash
   git clone https://github.com/your-repo/stealth-wizard.git
   cd stealth-wizard
   ```

2. **Install Python Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
   Create a `requirements.txt` with:
   ```text
   pycryptodome
   aiohttp
   aiodns
   async-timeout
   aiofiles
   pypdf
   ```

3. **Install External Tools**:
   - Ensure `masscan`, `nmap`, and `pdftotext` are installed via package manager or manually.
   - Place custom tools (`certsh.py`, `hunterio_tool`, `ldap_tool`, `aad_spray_tool`) in `/usr/bin/` or a custom path.
   - Verify tools are executable:
     ```bash
     chmod +x /path/to/certsh.py
     ```

4. **Configure the Tool**:
   - Create a `config.yaml` file (see [Configuration](#configuration)).
   - Securely store API keys and tool paths.
   - Restrict `config.yaml` permissions:
     ```bash
     chmod 600 config.yaml
     ```

## Configuration

StealthWizard uses a YAML configuration file to define operational parameters, tool paths, and target details. Below is a sample `config.yaml`:

```yaml
results_directory: results
tool_paths:
  certsh.py: /usr/bin/certsh.py
  hunterio_tool: /usr/bin/hunterio_tool
  ldap_tool: /usr/bin/ldap_tool
  aad_spray_tool: /usr/bin/aad_spray_tool
  masscan: /usr/bin/masscan
  nmap: /usr/bin/nmap
  pdftotext: /usr/bin/pdftotext
api_keys:
  hunterio: your_hunterio_api_key
opsec:
  jitter_seconds: [0.5, 2.0]
  low_and_slow: true
  low_and_slow_factor: 2.0
  proxy_chain: []
  exit_on_detection: true
  detection_threshold: 2
  dns_over_https: true
  doh_resolvers:
    - https://cloudflare-dns.com/dns-query
    - https://dns.google/dns-query
    - https://doh.opendns.com/dns-query
  network_timeout: 15.0
  connect_timeout: 7.0
  min_password_spray_attempts: 2
  lockout_wait_multiplier: 1.5
  scan_signature_profiling: true
target_definition:
  root_domains: example.com,contoso.com
  suspected_cloud_tenant: contoso.onmicrosoft.com
  optional_targets: 192.168.1.0/24,dc1.example.com
recon_surface_mapping:
  passive_recon:
    enabled: true
    hunterio:
      enabled: true
      timeout: 120
    timeout: 180
  active_scan:
    enabled: true
    scan_ports: 88,135,139,389,445,636,3268,3269,443
    masscan_rate: 100
    masscan_timeout: 600
    nmap_timeout: 1200
    cidr_expansion_limit: 65536
    ad_likelihood_threshold: 70
credential_harvest_spray:
  username_generation:
    enabled: true
    hunterio:
      enabled: true
      timeout: 120
    ldap_anon_enum:
      enabled: true
      timeout: 120
    common_names:
      - john.doe
      - jane.smith
    email_patterns:
      - "{first}.{last}@{domain}"
  password_spray:
    enabled: true
    common_weak_passwords:
      - Password1!
      - Welcome1!
      - Summer2025!
    target_services:
      - ldap
      - m365
    attempt_timeout: 45
    lockout_threshold: 5
```

### Configuration Fields
- **results_directory**: Directory for results, audit logs, and temporary files (default: `results`).
- **tool_paths**: Absolute paths to external tools or their names if in PATH.
- **api_keys**: API keys for services like Hunter.io (securely store and restrict access).
- **opsec**: Stealth settings controlling jitter, proxies, detection thresholds, and more (see script’s `OPSEC_CONFIG` for defaults).
- **target_definition**:
  - `root_domains`: Comma-separated list of target domains (e.g., `example.com,contoso.com`).
  - `suspected_cloud_tenant`: M365 tenant domain (e.g., `contoso.onmicrosoft.com`).
  - `optional_targets`: IPs, CIDRs, or hostnames for scanning (e.g., `192.168.1.0/24,dc1.example.com`).
- **recon_surface_mapping**:
  - `passive_recon`: Configures crt.sh and Hunter.io for passive enumeration.
  - `active_scan`: Controls Masscan and Nmap scanning parameters (ports, rates, timeouts).
- **credential_harvest_spray**:
  - `username_generation`: Defines sources (Hunter.io, LDAP, patterns) and common names.
  - `password_spray`: Specifies weak passwords, target services, and spraying parameters.

### Security Notes
- **Config File**: Store `config.yaml` with restrictive permissions (`chmod 600`) to protect API keys.
- **API Keys**: Never commit keys to version control; use environment variables or a secure vault if possible.
- **Results Directory**: Ensure the results directory is writeable and restricted to the operator.

## Usage

StealthWizard is executed via the command line with required arguments for configuration and engagement details.

### Command Syntax
```bash
python stealth_wizard.py --config <config.yaml> --engagement-letter <letter.pdf> --company-name <company> --testing-window <window> --run-uuid <uuid>
```

### Arguments
- `--config`: Path to the YAML configuration file (e.g., `config.yaml`).
- `--engagement-letter`: Path to the signed engagement letter PDF (mandatory for legal compliance).
- `--company-name`: Name of the target company (must match engagement letter).
- `--testing-window`: Testing period (e.g., `2025-06-01 to 2025-06-30`).
- `--run-uuid`: Unique identifier for the operation (use `uuidgen` or similar).

### Example
```bash
python stealth_wizard.py --config config.yaml --engagement-letter letter.pdf --company-name Contoso --testing-window "2025-06-01 to 2025-06-30" --run-uuid $(uuidgen)
```

### Operation Stages
1. **Gatekeeper**:
   - Validates the engagement letter PDF for company name and readable text.
   - Initializes secure directories and audit logging.
   - Aborts if validation fails.

2. **Target Definition**:
   - Resolves domains to IPs using DoH or system DNS.
   - Validates WHOIS records for company ownership.
   - Confirms M365 tenant status via GetUserRealm and autodiscover checks.

3. **Reconnaissance and Surface Mapping**:
   - Passive: Queries crt.sh for subdomains and Hunter.io for emails.
   - Active: Scans with Masscan for open ports, followed by Nmap for service details.
   - Scores AD likelihood to prioritize targets.

4. **Credential Harvesting and Spraying**:
   - Harvests usernames from Hunter.io, LDAP, and patterns.
   - Sprays weak passwords against LDAP and M365 services.
   - Discovers password policies with cracked credentials.

5. **Cloud Pivot**:
   - Enumerates M365 roles (e.g., Global Administrator) using cracked credentials.
   - Maps cloud services via autodiscover endpoints.
   - Escalates privileges for deeper access.

### Output
- **Results Directory**: `./results/<run_uuid>/`
  - `audit_logs/<run_uuid>.audit.log.enc`: Encrypted audit log (requires `audit_log_key` for decryption).
  - `output/`: Scan results, credential data (encrypted).
  - `temp/`: Temporary files (shredded post-operation).
- **Console Logs**: Detailed progress, warnings, and critical errors with redacted sensitive data.

### Audit Log Decryption
To decrypt the audit log, use the `audit_log_key` (managed externally):
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
key = b'your_audit_log_key'  # Retrieve securely
with open('audit.log.enc', 'rb') as f:
    encrypted = f.read()
iv = encrypted[:16]
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = unpad(cipher.decrypt(encrypted[16:]), AES.block_size)
print(plaintext.decode('utf-8'))
```

## Operational Security (OPSEC)

StealthWizard is designed for maximum stealth and minimal exposure. Key OPSEC features include:

- **Detection Monitoring**:
  - Tracks indicators (e.g., "block", "captcha", "rate limit") in command outputs and HTTP responses.
  - Aborts if `detection_threshold` (default: 2) is exceeded (`exit_on_detection: true`).

- **Low-and-Slow**:
  - Applies `low_and_slow_factor` (default: 2.0) to delay operations, reducing detection risk.
  - Random jitter (`jitter_seconds: [0.5, 2.0]`) for unpredictable timing.

- **Network Stealth**:
  - DoH resolvers obscure DNS queries.
  - Proxy chains (if configured) route traffic through anonymized paths.
  - Randomized User-Agents and X-Forwarded-For headers mimic legitimate clients.

- **Data Protection**:
  - All temporary files and audit logs are encrypted with AES-256-CBC.
  - Sensitive data (passwords, keys) is redacted from logs.
  - Files are shredded with multiple passes (`temp_file_cleanup_policy: shred`).

- **Sandboxing**:
  - Optional command execution sandboxing with firejail (`command_execution_sandbox: true`).
  - Requires firejail installation and configuration.

### OPSEC Recommendations
- **Engagement Letter**: Always validate the engagement letter to ensure legal scope.
- **Key Management**: Store `audit_log_key` and `temp_file_key` in a secure vault, not on disk.
- **Network Isolation**: Run from a dedicated, firewalled VM or container to limit exposure.
- **Proxy Chains**: Configure multiple proxies for traffic routing (e.g., SOCKS5, HTTP).
- **Logging**: Review audit logs post-operation for detection indicators.
- **Testing Window**: Adhere strictly to the specified testing period to avoid legal issues.

## Error Handling

StealthWizard employs a robust exception hierarchy and logging to handle errors aggressively:

- **Custom Exceptions**:
  - `StealthToolError`: Base exception for all tool errors.
  - `ConfigurationError`: Invalid or missing configuration.
  - `ToolExecutionError`: Failed external tool execution.
  - `NetworkError`: Network connectivity issues.
  - `DetectionError`: Suspected detection by target defenses.
  - `EncryptionError`: Encryption/decryption failures.
  - `EngagementScopeError`: Violations of engagement scope.

- **Error Behavior**:
  - Critical errors (e.g., missing tools, invalid engagement letter) trigger immediate abort (`_abort_wizard`).
  - Non-critical errors (e.g., failed crt.sh query) are logged and bypassed if possible.
  - Detection indicators exceeding `detection_threshold` cause operation termination.

- **Logging**:
  - All errors are logged with `stealth_logger` at appropriate levels (`INFO`, `WARNING`, `ERROR`, `CRITICAL`).
  - Sensitive data in logs is redacted using `StealthFormatter`.
  - Audit logs capture all events, including failures, in encrypted form.

### Common Errors
- **Tool Not Found**:
  - **Cause**: Missing or misconfigured tool path in `config.yaml`.
  - **Fix**: Verify `tool_paths` and ensure tools are executable.
- **Engagement Letter Failure**:
  - **Cause**: Invalid PDF or missing company name.
  - **Fix**: Provide a valid PDF with the company name in extractable text.
- **Network Timeout**:
  - **Cause**: Target unreachable or proxy misconfigured.
  - **Fix**: Check network connectivity, increase `network_timeout`, or validate proxy settings.
- **Audit Log Decryption Fails**:
  - **Cause**: Incorrect `audit_log_key` or corrupted log.
  - **Fix**: Verify key and log integrity.

## Extending the Tool

StealthWizard is modular, allowing extensions for new attack vectors or tools. To extend:

1. **Add New Stages**:
   - Create a new method in `StealthWizard` (e.g., `kerberos_attack`).
   - Call it in `run` after existing stages.
   - Example:
     ```python
     async def kerberos_attack(self) -> bool:
         stealth_logger.info("[STEALTH] --- Kerberos Attack ---")
         # Implement attack logic
         return True
     ```

2. **Integrate New Tools**:
   - Add tool paths to `config.yaml` under `tool_paths`.
   - Update `_execute_command` to handle new tool outputs.
   - Example: Add John the Ripper for hash cracking.

3. **Enhance OPSEC**:
   - Add new detection keywords to `SENSITIVE_PATTERNS`.
   - Implement advanced TLS fingerprinting (requires external library).
   - Example: Add `tls_fingerprinting: true` to `OPSEC_CONFIG`.

4. **Cloud Enhancements**:
   - Extend `cloud_pivot` for Azure AD, AWS, or GCP enumeration.
   - Add new M365 attack modules (e.g., Teams data exfiltration).

5. **Custom Logging**:
   - Modify `StealthFormatter` to include additional redaction patterns.
   - Add new audit events in `_log_audit`.

## Troubleshooting

### Tool Fails to Start
- **Symptom**: `Tool 'xyz' not found` error.
- **Solution**:
  - Check `tool_paths` in `config.yaml`.
  - Run `which xyz` to verify tool availability.
  - Install missing tools (e.g., `sudo apt install masscan`).

### Operation Aborts Early
- **Symptom**: `Detection threshold exceeded` or `Invalid engagement letter`.
- **Solution**:
  - **Detection**: Review audit logs for indicators (e.g., WAF, rate limits). Increase `detection_threshold` or enable proxies.
  - **Engagement Letter**: Ensure PDF contains the company name in extractable text. Test with `pdftotext letter.pdf -`.

### Network Errors
- **Symptom**: `HTTP request timed out` or `DNS lookup failed`.
- **Solution**:
  - Verify internet connectivity and firewall rules.
  - Increase `network_timeout` or `connect_timeout` in `config.yaml`.
  - Check DoH resolvers (`doh_resolvers`) or disable `dns_over_https`.

### Audit Log Decryption Fails
- **Symptom**: `Padding error` or unreadable log.
- **Solution**:
  - Ensure correct `audit_log_key` is used.
  - Verify log integrity (no truncation or corruption).
  - Use the decryption script provided in [Usage](#usage).

### Performance Issues
- **Symptom**: Slow scans or high CPU usage.
- **Solution**:
  - Reduce `masscan_rate` or increase `low_and_slow_factor`.
  - Run on a system with more CPU/memory.
  - Limit CIDR ranges (`cidr_expansion_limit`) to avoid large scans.

## Contributing

Contributions are welcome to enhance StealthWizard’s capabilities or fix issues. To contribute:

1. **Fork the Repository**:
   ```bash
   git clone https://github.com/your-repo/stealth-wizard.git
   cd stealth-wizard
   ```

2. **Create a Branch**:
   ```bash
   git checkout -b feature/your-feature
   ```

3. **Make Changes**:
   - Follow PEP 8 coding standards.
   - Add tests for new features (use `pytest`).
   - Update this README for new functionality.

4. **Submit a Pull Request**:
   - Push your branch:
     ```bash
     git push origin feature/your-feature
     ```
   - Open a PR with a detailed description of changes.

5. **Code Review**:
   - Ensure changes maintain stealth and security.
   - Address reviewer feedback promptly.

## License

StealthWizard is licensed under the MIT License. See `LICENSE` for details.

## Disclaimer

StealthWizard is a security testing tool for authorized use only. The developers are not responsible for misuse or illegal activities. Always obtain explicit permission from the target organization before use. By using this tool, you agree to comply with all applicable laws and ethical guidelines.
