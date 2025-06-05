# Stealth AD Takeover Wizard

The **Stealth AD Takeover Wizard** (`stealth_wizard.py`) is an advanced Python-based tool designed for authorized penetration testing to simulate the initial stages of an Active Directory (AD) compromise in a controlled environment. Integrated with the **Canvas** penetration testing framework, it automates legal validation, target definition, stealth reconnaissance, and credential harvesting/spraying, producing encrypted audit logs and results for security assessments. This tool is intended exclusively for use with explicit permission from the target organization, as unauthorized use is illegal and unethical.

## Purpose

The Stealth AD Takeover Wizard facilitates red team engagements by simulating attacker workflows with a focus on operational security (opsec) and stealth, including:
- **Legal Validation**: Verifies testing authorization via an engagement letter PDF, ensuring compliance with scope.
- **Target Definition**: Validates domains, IP ranges, and cloud tenants (e.g., Microsoft 365) using secure DNS resolution.
- **Reconnaissance**: Performs passive (e.g., Hunter.io) and active (e.g., masscan, nmap) scanning to identify AD assets with minimal detection risk.
- **Credential Harvesting/Spraying**: Generates usernames and tests credentials against services like Microsoft 365, with lockout avoidance mechanisms.

**Note**: Advanced modules for cloud pivoting, internal reconnaissance, lateral movement, and privilege escalation are placeholders and not implemented in this version. The tool halts after reconnaissance if the AD likelihood score is below the configured threshold, unless overridden.

## Features

- **Encrypted Audit Logging**: Produces AES-256-CBC encrypted logs (`<uuid>.audit.log.enc`) with redacted sensitive data (e.g., passwords, tokens).
- **Stealth Operations**: Implements proxy chaining, DNS over HTTPS (DoH), User-Agent rotation, jitter, and low-and-slow techniques to evade detection.
- **Secure Data Handling**: Encrypts temporary files and results, with secure deletion (shredding) to minimize forensic artifacts.
- **Detection Avoidance**: Monitors for detection indicators (e.g., WAF headers, lockouts) and can abort operations to protect opsec.
- **Canvas Integration**: Executes within Canvas’s script runner, leveraging its secure C2 channels for red team workflows.
- **Configurable Workflow**: YAML-based configuration (`stealth_wizard.yaml`) for tool paths, timeouts, and opsec settings.
- **Robust Error Handling**: Gracefully handles missing tools and network errors, logging issues without crashing.
- **Signal Handling**: Supports graceful shutdown via SIGINT/SIGTERM (Ctrl+C) with secure cleanup.

## Prerequisites

### System Requirements
- **Operating System**: Linux (preferred, e.g., Kali Linux 2025), macOS, or Windows (Linux recommended for tool compatibility).
- **Python**: Version 3.8 or higher (3.11+ recommended for full feature support, e.g., `encoding='utf-8'` in `subprocess.run`).
- **Canvas**: A licensed instance of the Canvas penetration testing framework with Python script execution support (e.g., via a Canvas agent or script runner).
- **Disk Space**: At least 2 GB for encrypted logs and results (more for large-scale scans).
- **Network Access**: Internet access for passive reconnaissance (e.g., Hunter.io) and target connectivity for active scans and credential spraying.

### Python Dependencies
Install required Python packages using `pip`:
```bash
pip install pycryptodome httpx pypdf pyyaml dnspython
```

- `pycryptodome`: For AES-256-CBC encryption of logs and temporary files.
- `httpx`: For stealth HTTP requests with proxy support and TLS fingerprinting evasion.
- `pypdf`: For parsing engagement letter PDFs.
- `pyyaml`: For YAML configuration parsing.
- `dnspython`: For DNS resolution, including fallback for DoH.

Optional:
- `xml.etree.ElementTree`: Included in Python’s standard library for Nmap XML parsing; verify availability.

### External Tools
The script uses external tools for specific functions. Install these or disable their features in `stealth_wizard.yaml` to skip them:
- **`masscan`**: High-speed port scanner for active reconnaissance.
  ```bash
  sudo apt-get install masscan  # Debian/Ubuntu
  ```
- **`nmap`**: Detailed service enumeration for AD detection.
  ```bash
  sudo apt-get install nmap  # Debian/Ubuntu
  ```
- **`pdftotext`**: Fallback for PDF parsing if `pypdf` is unavailable.
  ```bash
  sudo apt-get install poppler-utils  # Debian/Ubuntu
  ```
- **`theHarvester`**: Email harvesting for passive reconnaissance (replaces `hunterio_tool`).
  ```bash
  sudo apt-get install theharvester  # Debian/Ubuntu
  ```
- **`firejail`**: Optional sandboxing for tool execution.
  ```bash
  sudo apt-get install firejail  # Debian/Ubuntu
  ```
- **Placeholder Tools** (custom or third-party, not included):
  - `aad_spray_tool`: Performs Microsoft 365 credential spraying. Expected interface: `aad_spray_tool --domain <domain> --username <user> --password <pass>`.
  - `get_ad_policy`: Retrieves AD password policies. Expected interface: `get_ad_policy --target <host> --username <user> --password <pass>`.

**Note**: Missing tools are logged gracefully, and affected features are skipped. Ensure tool paths are specified in `stealth_wizard.yaml`.

### Canvas Setup
- **Canvas License**: Verify a valid Canvas license with Python script execution support.
- **Agent Configuration**: Deploy a Canvas agent on a Linux system with network access to the target and Python 3.8+ installed.
- **Script Runner**: Configure Canvas’s script execution module to run `stealth_wizard.py`, passing command-line arguments dynamically.
- **Dependencies**: Install Python dependencies and external tools on the Canvas agent.

### Engagement Letter
Obtain a signed engagement letter in PDF format from the target organization, detailing the scope (e.g., company name, testing window). Place it in an accessible directory (e.g., `./engagement/letter.pdf`).

## Installation

Follow these steps to set up the Stealth AD Takeover Wizard:

1. **Clone or Download the Script**
   Copy `stealth_wizard.py` and `stealth_wizard.yaml` to your Canvas agent’s working directory or a testing system:
   ```bash
   git clone <repository-url>  # If hosted in a Git repository
   cd stealth-ad-takeover-wizard
   ```
   Alternatively, download the files directly.

2. **Install Python Dependencies**
   Create a virtual environment (recommended) and install packages:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # Linux/macOS
   venv\Scripts\activate     # Windows
   pip install pycryptodome httpx pypdf pyyaml dnspython
   ```

3. **Install External Tools**
   Install required tools on the Canvas agent or testing system:
   ```bash
   sudo apt-get update
   sudo apt-get install masscan nmap poppler-utils theharvester firejail  # Debian/Ubuntu
   ```
   For placeholder tools (`aad_spray_tool`, `get_ad_policy`), provide implementations or disable their features in `stealth_wizard.yaml`:
   ```yaml
   credential_harvest_spray:
     password_spray:
       enabled: false
   ```

4. **Configure Canvas**
   - Upload `stealth_wizard.py` and `stealth_wizard.yaml` to the Canvas agent’s working directory.
   - Verify Python 3.8+ is installed on the agent:
     ```bash
     python3 --version
     ```
   - Configure Canvas’s script runner to execute Python scripts, passing command-line arguments as needed.

5. **Set Up Encryption Keys**
   - Generate AES-256 keys for audit logs and temporary files using a secure method (e.g., OpenSSL):
     ```bash
     openssl rand -base64 32 > audit_key.bin
     openssl rand -base64 32 > temp_key.bin
     ```
   - Store keys securely (e.g., in a Hardware Security Module, HSM, or encrypted vault) and pass them via environment variables:
     ```bash
     export AUDIT_LOG_KEY=$(cat audit_key.bin)
     export TEMP_FILE_KEY=$(cat temp_key.bin)
     ```
   - Ensure the Canvas agent has access to these keys during execution.

6. **Customize Configuration**
   Copy the sample `stealth_wizard.yaml` (provided below) and edit it to match your environment:
   ```bash
   cp stealth_wizard.yaml.sample stealth_wizard.yaml
   nano stealth_wizard.yaml
   ```
   Update tool paths, target details, opsec settings, and API keys as required.

## Configuration

The `stealth_wizard.yaml` file controls the wizard’s behavior. Key sections include:

- **Results Storage**:
  ```yaml
  results_directory: "results"
  audit_log_subdir: "audit_logs"
  results_subdir: "results"
  ```
  Defines paths for encrypted logs and outputs (e.g., `results/<uuid>/audit_logs/<uuid>.audit.log.enc`).

- **Tool Paths**:
  ```yaml
  tool_paths:
    masscan: "/usr/bin/masscan"
    nmap: "/usr/bin/nmap"
    pdftotext: "/usr/bin/pdftotext"
    theHarvester: "/usr/bin/theHarvester"
    aad_spray_tool: "/usr/local/bin/aad_spray_tool"
    get_ad_policy: "/usr/local/bin/get_ad_policy"
  ```
  Specifies paths to external tools. Update to match your system.

- **Timeouts**:
  ```yaml
  timeouts:
    dns_resolve: 5
    getuserrealm: 15
  ```
  Sets timeouts for DNS and HTTP operations (in seconds).

- **Gatekeeper**:
  ```yaml
  gatekeeper:
    engagement_checksum: null  # Optional SHA256 checksum
  ```
  Validates the engagement letter PDF (optional checksum).

- **Target Definition**:
  ```yaml
  target_definition:
    root_domains: "example.com,example.org"
    suspected_cloud_tenant: "example.onmicrosoft.com"
    optional_targets: "192.168.1.0/24"
  ```
  Specifies domains, cloud tenants, and IP ranges/CIDRs.

- **Reconnaissance**:
  ```yaml
  recon_surface_mapping:
    passive_recon:
      enabled: true
      hunterio:
        enabled: true
        timeout: 120
    active_scan:
      enabled: true
      cidr_expansion_limit: 65536
      masscan_rate: 50
      scan_ports: "88,135,139,389,445,593,636,3268,3269,53,587,443"
      ad_likelihood_threshold: 70
  ```
  Configures passive (Hunter.io) and active (masscan, nmap) scanning.

- **Credential Harvesting/Spraying**:
  ```yaml
  credential_harvest_spray:
    username_generation:
      hunterio:
        enabled: true
      email_patterns:
        - "{first}.{last}@{domain}"
        - "{f}{last}@{domain}"
    password_spray:
      enabled: true
      target_services:
        - "m365"
      rate_per_minute: 1
      attempt_timeout: 30
      lockout_threshold: 5
  ```
  Controls username generation and credential spraying.

- **Opsec Settings**:
  ```yaml
  opsec:
    jitter_seconds: [0.5, 2.0]
    low_and_slow: true
    proxy_chain:
      - "http://proxy1:8080"
      - "socks5://proxy2:1080"
    exit_on_detection: true
  ```
  Configures stealth parameters like jitter, proxies, and detection handling.

A complete sample `stealth_wizard.yaml` is provided at the end of this README.

## Usage

### Command-Line Execution
Run the wizard standalone for testing or debugging:
```bash
python3 stealth_wizard.py \
  --engagement-letter ./engagement/letter.pdf \
  --company-name "ACME Corp" \
  --testing-window "2025-06-10 to 2025-06-12" \
  --config stealth_wizard.yaml \
  --run-uuid "$(uuidgen)" \
  --debug
```

**Arguments**:
- `--engagement-letter`: Path to the engagement letter PDF (required).
- `--company-name`: Target company name for validation (required).
- `--testing-window`: Testing period (e.g., "YYYY-MM-DD to YYYY-MM-DD") (required).
- `--config`: Path to `stealth_wizard.yaml` (default: `stealth_wizard.yaml`).
- `--run-uuid`: Unique run identifier (default: auto-generated UUID).
- `--debug`: Enables verbose logging for troubleshooting.

**Example Output**:
```
[StealthWizard] Stealth AD Takeover Wizard (Operational Mode - AUTHORIZED USE ONLY)
--- Gatekeeper Screen ---
INFO: Audit log initialized: results/<uuid>/audit_logs/<uuid>.audit.log.enc
INFO: Results directory: results/<uuid>
INFO: Gatekeeper passed for UUID: <uuid>
--- Target Definition ---
INFO: Target definition complete.
--- Recon & Surface Mapping ---
INFO: Reconnaissance complete.
--- Credential Harvest & Spray ---
INFO: Cracked credentials found: 0
INFO: --- Wizard Execution Finished ---
UUID: <uuid>
Audit log (encrypted): results/<uuid>/audit_logs/<uuid>.audit.log.enc
Results directory: results/<uuid>
Status: completed
```

### Canvas Integration
To execute within Canvas:
1. **Upload Files**: Transfer `stealth_wizard.py` and `stealth_wizard.yaml` to the Canvas agent’s working directory.
2. **Set Environment Variables**: Provide encryption keys:
   ```bash
   export AUDIT_LOG_KEY=$(cat audit_key.bin)
   export TEMP_FILE_KEY=$(cat temp_key.bin)
   ```
3. **Configure Script Runner**: Use Canvas’s Python script runner to execute:
   ```bash
   python3 stealth_wizard.py --engagement-letter /path/to/letter.pdf --company-name "ACME Corp" --testing-window "2025-06-10 to 2025-06-12" --debug
   ```
4. **Monitor Output**: View logs in Canvas’s console or retrieve encrypted results from `results/<uuid>`.

**Example Canvas Wrapper Script** (`run_stealth_wizard.py`):
```python
import os
os.system('python3 stealth_wizard.py --engagement-letter /path/to/letter.pdf --company-name "ACME Corp" --testing-window "2025-06-10 to 2025-06-12" --debug')
```
Upload and execute via Canvas’s script runner.

### Common Scenarios

1. **Minimal Run (No Active Recon)**:
   Disable active scanning for stealth:
   ```yaml
   recon_surface_mapping:
     active_scan:
       enabled: false
   ```
   ```bash
   python3 stealth_wizard.py --engagement-letter letter.pdf --company-name "Test Corp" --testing-window "2025-06-10 to 2025-06-12"
   ```

2. **Full Recon and Spraying**:
   Ensure all tools are installed and configured:
   ```bash
   python3 stealth_wizard.py --engagement-letter letter.pdf --company-name "ACME Corp" --testing-window "2025-06-10 to 2025-06-12" --debug
   ```

3. **Override Low AD Score**:
   Proceed despite a low AD likelihood score:
   ```yaml
   recon_surface_mapping:
     override_threshold_on_low_score: true
   ```
   ```bash
   python3 stealth_wizard.py --engagement-letter letter.pdf --company-name "ACME Corp" --testing-window "2025-06-10 to 2025-06-12"
   ```

## Output

- **Encrypted Audit Logs**: Stored in `results/<uuid>/audit_logs/<uuid>.audit.log.enc`. Contains timestamped, encrypted events (e.g., tool execution, errors). Decrypt using the audit log key:
  ```bash
  # Example decryption script (not provided)
  python3 decrypt_log.py --key audit_key.bin --input results/<uuid>/audit_logs/<uuid>.audit.log.enc
  ```
- **Results**: Saved in `results/<uuid>/results/`, including:
  - `<uuid>_nmap.xml`: Nmap XML output (if generated).
  - Temporary encrypted files (e.g., `<uuid>_masscan_targets.txt`, `<uuid>_nmap_targets.txt`) are shredded on completion.
- **Console Output**: Summarizes progress, errors, and credential findings (e.g., `Cracked credentials found: 2`).

## Operational Security (Opsec)

- **Engagement Validation**: Aborts if the company name is not found in the engagement letter, ensuring legal compliance.
- **Password Handling**: Plaintext passwords are hashed and cleared immediately after use, minimizing memory exposure.
- **Rate Limiting and Jitter**: Configurable `rate_per_minute` and `jitter_seconds` reduce detection risk during spraying.
- **Data Encryption**: All logs and temporary files are encrypted with AES-256-CBC, using unique IVs per operation.
- **Secure Cleanup**: Temporary files are shredded (`shred` policy) on exit or interrupt, reducing forensic traces.
- **Detection Monitoring**: Aborts on detection indicators (e.g., WAF blocks, lockouts) if `exit_on_detection` is enabled.
- **Proxy Chaining**: Supports HTTP/SOCKS proxies to obfuscate traffic, configurable via `proxy_chain`.

**Recommendations**:
- Operate in an isolated, dedicated environment to prevent accidental exposure.
- Use residential proxies or Tor for `proxy_chain` to blend with legitimate traffic.
- Test spraying rates and scan parameters in a lab to optimize evasion.
- Store encryption keys in a secure vault (e.g., HashiCorp Vault) and restrict access.
- Regularly review audit logs for detection indicators post-engagement.

## Troubleshooting

- **Error: Tool '<tool_name>' not found**
  - Verify the tool is installed and its path is correct in `stealth_wizard.yaml`.
  - Disable the feature if the tool is unavailable:
    ```yaml
    recon_surface_mapping:
      active_scan:
        enabled: false
    ```
  ```bash
  sudo apt-get install <tool_name>  # Install missing tool
  ```

- **Error: Invalid engagement letter PDF**
  - Ensure the PDF path is correct and the file is accessible.
  - Check that `--company-name` matches text in the PDF (case-insensitive).
  ```bash
  pdftotext letter.pdf - | grep "ACME Corp"
  ```

- **Audit log decryption fails**
  - Verify the correct `AUDIT_LOG_KEY` is provided.
  - Check for file corruption or incorrect IV handling.
  ```bash
  ls -l results/<uuid>/audit_logs/<uuid>.audit.log.enc  # Verify file exists
  ```

- **No credentials found during spraying**
  - Confirm `target_services` and `suspected_cloud_tenant` are correct in `stealth_wizard.yaml`.
  - Check network connectivity and rate limits:
  ```bash
  ping login.microsoftonline.com
  ```

- **Canvas execution errors**
  - Ensure Python 3.8+ and dependencies are installed on the Canvas agent.
  - Review Canvas logs for Python errors.
  ```bash
  python3 --version
  pip install pycryptodome httpx pypdf pyyaml dnspython
  ```

## Sample `stealth_wizard.yaml`

```yaml
# Stealth AD Takeover Wizard Configuration
results_directory: "results"
audit_log_subdir: "audit_logs"
results_subdir: "results"
tool_paths:
  masscan: "/usr/bin/masscan"
  nmap: "/usr/bin/nmap"
  pdftotext: "/usr/bin/pdftotext"
  theHarvester: "/usr/bin/theHarvester"
  aad_spray_tool: "/usr/local/bin/aad_spray_tool"
  get_ad_policy: "/usr/local/bin/get_ad_policy"
timeouts:
  dns_resolve: 5
  getuserrealm: 15
gatekeeper:
  engagement_checksum: null
target_definition:
  root_domains: "example.com,example.org"
  suspected_cloud_tenant: "example.onmicrosoft.com"
  optional_targets: "192.168.1.0/24"
recon_surface_mapping:
  passive_recon:
    enabled: true
    hunterio:
      enabled: true
      timeout: 120
  active_scan:
    enabled: true
    cidr_expansion_limit: 65536
    masscan_rate: 50
    masscan_timeout: 600
    scan_ports: "88,135,139,389,445,593,636,3268,3269,53,587,443"
    nmap_script_set: "default,auth,vuln,ldap*"
    nmap_timeout: 1200
    nmap_max_rate: 20
    nmap_script_timeout: 60
    exclusion_list: []
    ad_likelihood_threshold: 70
    override_threshold_on_low_score: false
credential_harvest_spray:
  username_generation:
    hunterio:
      enabled: true
    email_patterns:
      - "{first}.{last}@{domain}"
      - "{f}{last}@{domain}"
    common_names:
      - "john.doe"
      - "jane.smith"
    manual_list_path: ""
  password_spray:
    enabled: true
    regional_seasons:
      - "Winter"
      - "Summer"
    company_mottos:
      - "Innovate"
    sport_teams:
      - "Eagles"
    common_patterns:
      - "{word}{year}{ending}"
    common_endings:
      - "!"
      - "1"
    past_years_count: 3
    common_weak_passwords:
      - "Password123"
    policy_check_timeout: 60
    target_services:
      - "m365"
    rate_per_minute: 1
    attempt_timeout: 30
    lockout_threshold: 5
opsec:
  jitter_seconds: [0.5, 2.0]
  low_and_slow: true
  proxy_chain:
    - "http://proxy1:8080"
    - "socks5://proxy2:1080"
  user_agents:
    - "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
  exit_on_detection: true
  temp_file_cleanup_policy: shred
  dns_over_https: false
  doh_resolvers:
    - "https://cloudflare-dns.com/dns-query"
```

## Contributing

Contributions are welcome to enhance the tool’s functionality, such as implementing placeholder modules or adding unit tests. To contribute:
1. Fork the repository (if hosted).
2. Create a feature branch (`git checkout -b feature/cloud-pivot`).
3. Submit a pull request with detailed changes.

**Requested Enhancements**:
- Implement cloud pivot, internal reconnaissance, and lateral movement modules.
- Add unit tests for tool stubs and scan outputs.
- Integrate advanced TLS fingerprinting for HTTP requests.
- Develop a decryption utility for audit logs and results.

## Legal Disclaimer

This tool is provided for **authorized security testing only**. Unauthorized use against systems without explicit permission is illegal and may result in criminal prosecution. Always obtain written consent (e.g., an engagement letter) before testing. The authors are not responsible for misuse or damages caused by this tool.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details (if included).

## Contact

For issues, feature requests, or questions, contact the project maintainer via GitHub Issues (if hosted) or your organization’s security team.

**Last Updated**: June 5, 2025
