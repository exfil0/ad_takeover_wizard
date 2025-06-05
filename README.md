# AD Remote Takeover Wizard

The **AD Remote Takeover Wizard** is a Python-based tool designed for authorized penetration testing to simulate the initial stages of an Active Directory (AD) compromise in a controlled environment. Integrated with the **Canvas** penetration testing framework, it automates legal validation, target definition, reconnaissance, and credential harvesting/spraying, producing detailed audit logs and results for security assessments. This tool must only be used with explicit permission from the target organization, as unauthorized use is illegal and unethical.

## Purpose

The wizard facilitates red team engagements by simulating attacker workflows, focusing on:
- **Legal Validation**: Verifies authorization via an engagement letter PDF.
- **Target Definition**: Validates domains, IP ranges, and cloud tenants (e.g., Microsoft 365).
- **Reconnaissance**: Conducts passive (e.g., crt.sh, Hunter.io) and active (e.g., masscan, nmap) scanning to identify AD assets.
- **Credential Harvesting/Spraying**: Generates usernames and tests credentials against services like Microsoft 365.

**Note**: Cloud pivoting, remote code execution (RCE), and privilege escalation modules are placeholders and not implemented in this version. The tool halts after reconnaissance if the AD likelihood score is below the configured threshold, unless overridden.

## Features

- **Immutable Audit Logging**: Generates gzipped logs with redacted sensitive data (e.g., passwords, tokens).
- **Opsec-Safe Design**: Implements rate limiting, jitter, and immediate plaintext password clearing to minimize detection.
- **Canvas Integration**: Executes within Canvas for seamless integration with existing pentest workflows.
- **Configurable Workflow**: YAML-based configuration for tool paths, timeouts, and module settings.
- **Graceful Error Handling**: Skips missing tools and logs errors without crashing.
- **Signal Handling**: Supports graceful shutdown via SIGINT/SIGTERM (Ctrl+C).

## Prerequisites

### System Requirements
- **Operating System**: Linux (preferred, e.g., Kali Linux), macOS, or Windows (Linux recommended for tool compatibility).
- **Python**: Version 3.8 or higher (3.11+ recommended for full feature support, e.g., `encoding='utf-8'` in `subprocess.run`).
- **Canvas**: A licensed instance of the Canvas penetration testing framework with Python script execution capabilities (e.g., via a Canvas agent or script runner).
- **Disk Space**: At least 1 GB for logs and results (more for large scans).
- **Network Access**: Internet access for passive recon (e.g., crt.sh, Hunter.io) and target connectivity for active scans and spraying.

### Python Dependencies
Install required Python packages using `pip`:
```bash
pip install pypdf pywhois dnspython requests pyyaml
```

- `pypdf`: For parsing engagement letter PDFs.
- `pywhois`: For WHOIS lookups.
- `dnspython`: For DNS resolution.
- `requests`: For HTTP requests (e.g., Microsoft 365 tenant checks).
- `pyyaml`: For YAML configuration parsing.

Optional:
- `xml.etree.ElementTree`: Included in Python’s standard library for Nmap XML parsing; verify availability.

### External Tools
The script relies on external tools for certain functions. Install these or disable their features in `wizard.yaml` to skip them:
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
- **Placeholder Tools** (custom or third-party, not included):
  - `certsh.py`: Scrapes crt.sh certificates for passive domain discovery.
  - `hunterio_tool`: Harvests emails from Hunter.io.
  - `linkedin_scraper`: Scrapes usernames from LinkedIn.
  - `aad_spray_tool`: Performs Microsoft 365 credential spraying.
  - `get_ad_policy`: Retrieves AD password policies.

**Note**: Without these tools, the script will log errors and skip affected features gracefully. Ensure tool paths are correctly specified in `wizard.yaml`.

### Canvas Setup
- **Canvas License**: Ensure a valid Canvas license with Python script execution support.
- **Agent Configuration**: Deploy a Canvas agent on a compatible system (e.g., Linux) with network access to the target.
- **Script Runner**: Use Canvas’s script execution module to run `ad_takeover_wizard.py` within the framework, passing command-line arguments as needed.

## Installation

Follow these steps to set up the AD Remote Takeover Wizard:

1. **Clone or Download the Repository**
   Download the script and associated files (e.g., `wizard.yaml`) to your Canvas agent or testing system:
   ```bash
   git clone <repository-url>  # If hosted in a Git repo
   cd ad-takeover-wizard
   ```
   Alternatively, copy `ad_takeover_wizard.py` and `wizard.yaml` to your working directory.

2. **Install Python Dependencies**
   Create a virtual environment (optional but recommended) and install packages:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # Linux/macOS
   venv\Scripts\activate     # Windows
   pip install pypdf pywhois dnspython requests pyyaml
   ```

3. **Install External Tools**
   Install required tools based on your operating system:
   ```bash
   sudo apt-get update
   sudo apt-get install masscan nmap poppler-utils  # Debian/Ubuntu
   ```
   For placeholder tools (`certsh.py`, `hunterio_tool`, etc.), ensure they are installed and accessible, or disable their features in `wizard.yaml`:
   ```yaml
   recon_surface_mapping:
     passive_recon:
       enabled: false
   ```

4. **Configure Canvas**
   - Upload `ad_takeover_wizard.py` and `wizard.yaml` to your Canvas agent’s working directory.
   - Verify Python 3.8+ is available on the Canvas agent (e.g., via `python3 --version`).
   - Configure Canvas to execute Python scripts, typically via the script runner module or a custom command.

5. **Prepare Engagement Letter**
   Obtain a signed engagement letter in PDF format from the target organization, specifying the scope of testing (e.g., company name, testing window). Place it in an accessible directory (e.g., `./demo/letter.pdf`).

6. **Customize Configuration**
   Copy the sample `wizard.yaml` (provided below) to your working directory and edit it to match your environment:
   ```bash
   cp wizard.yaml.sample wizard.yaml
   nano wizard.yaml
   ```
   Update tool paths, target details, and module settings as needed. A sample `wizard.yaml` is included at the end of this README.

## Configuration

The `wizard.yaml` file controls the wizard’s behavior. Key sections include:

- **Results Storage**:
  ```yaml
  results_directory: "results"
  audit_log_subdir: "audit_logs"
  results_subdir: "results"
  ```
  Specifies where logs and outputs are saved (e.g., `results/<uuid>/audit_logs/<uuid>.audit.log.gz`).

- **Tool Paths**:
  ```yaml
  tool_paths:
    masscan: "/usr/bin/masscan"
    nmap: "/usr/bin/nmap"
    pdftotext: "/usr/bin/pdftotext"
    certsh.py: "/usr/local/bin/certsh.py"
    hunterio_tool: "/usr/local/bin/hunterio_tool"
    linkedin_scraper: "/usr/local/bin/linkedin_scraper"
    aad_spray_tool: "/usr/local/bin/aad_spray_tool"
    get_ad_policy: "/usr/local/bin/get_ad_policy"
  ```
  Defines paths to external tools. Update to match your system.

- **Timeouts**:
  ```yaml
  timeouts:
    dns_resolve: 5
    getuserrealm: 15
  ```
  Sets timeouts for DNS queries and HTTP requests (in seconds).

- **Gatekeeper**:
  ```yaml
  gatekeeper:
    engagement_checksum: null  # Optional SHA256 checksum
  ```
  Validates the engagement letter PDF (optional checksum for integrity).

- **Target Definition**:
  ```yaml
  target_definition:
    root_domains: "example.com,example.org"
    suspected_cloud_tenant: "example.onmicrosoft.com"
    optional_targets: "192.168.1.0/24"
  ```
  Specifies target domains, cloud tenants, and IP ranges/CIDRs.

- **Reconnaissance**:
  ```yaml
  recon_surface_mapping:
    passive_recon:
      enabled: true
      crtsh:
        enabled: true
        timeout: 180
      hunterio:
        enabled: true
        timeout: 120
    active_scan:
      enabled: true
      cidr_expansion_limit: 65536
      masscan_rate: 1000
      scan_ports: "88,135,139,389,445,593,636,3268,3269,53,587,443"
      ad_likelihood_threshold: 70
  ```
  Configures passive (crt.sh, Hunter.io) and active (masscan, nmap) scanning.

- **Credential Harvesting/Spraying**:
  ```yaml
  credential_harvest_spray:
    username_generation:
      linkedin_scrape:
        enabled: true
        timeout: 300
      hunterio:
        enabled: true
    password_spray:
      enabled: true
      target_services:
        - "m365"
      rate_per_minute: 1
      attempt_timeout: 30
  ```
  Controls username generation and credential spraying (e.g., Microsoft 365).

- **Opsec**:
  ```yaml
  opsec:
    jitter_seconds: 0.5
  ```
  Adds random delays to spray attempts to evade detection.

See the sample `wizard.yaml` at the end for a complete example.

## Usage

### Command-Line Execution
Run the wizard directly from the command line for standalone testing or debugging:
```bash
python3 ad_takeover_wizard.py \
  --engagement-letter ./demo/letter.pdf \
  --company-name "ACME Corp" \
  --testing-window "2025-06-10 to 2025-06-12" \
  --config wizard.yaml \
  --run-uuid "$(uuidgen)"
```

**Arguments**:
- `--engagement-letter`: Path to the engagement letter PDF (required).
- `--company-name`: Target company name for validation (required).
- `--testing-window`: Testing period (e.g., "YYYY-MM-DD to YYYY-MM-DD") (required).
- `--config`: Path to `wizard.yaml` (default: `wizard.yaml`).
- `--run-uuid`: Unique run identifier (default: auto-generated UUID).

**Example Output**:
```
AD Remote Takeover Wizard (Simulation Mode - Authorized Use Only)
--- 0 - Gatekeeper Screen (Legal & Scope) ---
Audit log: results/<uuid>/audit_logs/<uuid>.audit.log.gz
Results dir: results/<uuid>
Gatekeeper validation successful for UUID: <uuid>
--- 1 - Target Definition ---
Validating domain: example.com
Target definition complete.
--- 2 - Recon & Surface Mapping ---
Performing passive reconnaissance...
Error: Required tool 'certsh.py' not found or not executable.
AD Likelihood Score: 0%
AD likelihood score (0%) below threshold (70%). Halting.
--- Wizard Complete ---
UUID: <uuid>
Audit log: results/<uuid>/audit_logs/<uuid>.audit.log.gz
Results: results/<uuid>
Status: halted_after_recon
```

### Canvas Integration
To run within Canvas:
1. **Upload Files**: Transfer `ad_takeover_wizard.py` and `wizard.yaml` to the Canvas agent’s working directory.
2. **Configure Script Runner**: Use Canvas’s script execution module (e.g., Python Script Runner) to invoke the command:
   ```bash
   python3 ad_takeover_wizard.py --engagement-letter /path/to/letter.pdf --company-name "ACME Corp" --testing-window "2025-06-10 to 2025-06-12"
   ```
3. **Pass Arguments**: Configure Canvas to pass command-line arguments or hardcode them in a wrapper script.
4. **Monitor Output**: View results in Canvas’s console or retrieve logs/results from `results/<uuid>` on the agent.

**Example Canvas Wrapper Script** (`run_wizard.py`):
```python
import os
os.system('python3 ad_takeover_wizard.py --engagement-letter /path/to/letter.pdf --company-name "ACME Corp" --testing-window "2025-06-10 to 2025-06-12"')
```
Upload and execute `run_wizard.py` via Canvas.

### Common Scenarios

1. **Run with Minimal Config (No External Tools)**:
   Disable passive and active recon to test basic functionality:
   ```yaml
   recon_surface_mapping:
     passive_recon:
       enabled: false
     active_scan:
       enabled: false
   ```
   ```bash
   python3 ad_takeover_wizard.py --engagement-letter letter.pdf --company-name "Test Corp" --testing-window "2025-06-10 to 2025-06-12"
   ```

2. **Perform Full Recon and Spraying**:
   Ensure all tools are installed and configured in `wizard.yaml`:
   ```bash
   python3 ad_takeover_wizard.py --engagement-letter letter.pdf --company-name "ACME Corp" --testing-window "2025-06-10 to 2025-06-12"
   ```

3. **Override Low AD Likelihood Score**:
   Allow the wizard to proceed despite a low AD score:
   ```yaml
   recon_surface_mapping:
     override_threshold_on_low_score: true
   ```
   ```bash
   python3 ad_takeover_wizard.py --engagement-letter letter.pdf --company-name "ACME Corp" --testing-window "2025-06-10 to 2025-06-12"
   ```

## Output

- **Audit Logs**: Stored in `results/<uuid>/audit_logs/<uuid>.audit.log.gz`. Contains timestamped events (e.g., tool execution, errors) with sensitive data redacted.
- **Results**: Saved in `results/<uuid>/results/`, including:
  - `<uuid>_passive_recon.csv`: Passive reconnaissance assets (if enabled).
  - `<uuid>_masscan_targets.txt`: IPs for masscan (temporary).
  - `<uuid>_masscan_raw.txt`: Masscan output (if generated).
  - `<uuid>_nmap_targets.txt`: IPs for nmap (temporary).
  - `<uuid>_nmap_scripted.xml`: Nmap XML output (if generated).
- **Console Output**: Summarizes progress, errors, and credential findings (e.g., `Found: user@example.com for m365`).

## Operational Security (Opsec)

- **Engagement Letter Validation**: Ensures testing is authorized, aborting if the company name is not found in the PDF.
- **Password Handling**: Plaintext passwords are hashed immediately and cleared from memory after use (e.g., post-policy check).
- **Rate Limiting**: Configurable rate limits (`rate_per_minute`) and jitter (`jitter_seconds`) reduce detection risk during spraying.
- **Sensitive Data Redaction**: Passwords, tokens, and hashes are redacted in logs using regex patterns.
- **Temporary Files**: Automatically deleted on exit or interrupt (SIGINT/SIGTERM).
- **Canvas Context**: Running within Canvas leverages its stealth features (e.g., encrypted C2 channels).

**Recommendations**:
- Use a dedicated, isolated testing environment to avoid accidental exposure.
- Minimize active scanning (`masscan`, `nmap`) to reduce network noise.
- Test spraying rates in a lab environment to optimize evasion.
- Verify log storage security to prevent unauthorized access.

## Troubleshooting

- **Error: Tool '<tool_name>' not found**
  - Ensure the tool is installed and its path is correct in `wizard.yaml`.
  - Disable the feature (e.g., `crtsh.enabled: false`) if the tool is unavailable.
  ```bash
  sudo apt-get install <tool_name>  # Install missing tool
  ```

- **Error: Invalid or missing engagement letter PDF**
  - Verify the PDF path is correct and the file is accessible.
  - Ensure the company name (`--company-name`) matches text in the PDF (case-insensitive).
  ```bash
  pdftotext letter.pdf - | grep "ACME Corp"
  ```

- **JSONDecodeError in audit logs**
  - If logs fail to write, check disk space and permissions for `results/<uuid>/audit_logs`.
  - Verify `wizard.yaml` does not introduce non-serializable objects.
  ```bash
  df -h  # Check disk space
  chmod -R 755 results  # Fix permissions
  ```

- **No credentials found during spraying**
  - Confirm `target_services` (e.g., `m365`) and `target_domain` are correct in `wizard.yaml`.
  - Check rate limiting (`rate_per_minute`) and network connectivity.
  ```bash
  ping login.microsoftonline.com  # Verify connectivity
  ```

- **Canvas execution fails**
  - Ensure Python 3.8+ is installed on the Canvas agent.
  - Check Canvas logs for Python errors or missing dependencies.
  ```bash
  python3 --version  # Verify Python version
  pip install pypdf pywhois dnspython requests pyyaml  # Reinstall dependencies
  ```

## Sample `wizard.yaml`

```yaml
# AD Remote Takeover Wizard Configuration
results_directory: "results"
audit_log_subdir: "audit_logs"
results_subdir: "results"
tool_paths:
  certsh.py: "/usr/local/bin/certsh.py"
  hunterio_tool: "/usr/local/bin/hunterio_tool"
  linkedin_scraper: "/usr/local/bin/linkedin_scraper"
  aad_spray_tool: "/usr/local/bin/aad_spray_tool"
  get_ad_policy: "/usr/local/bin/get_ad_policy"
  masscan: "/usr/bin/masscan"
  nmap: "/usr/bin/nmap"
  pdftotext: "/usr/bin/pdftotext"
timeouts:
  dns_resolve: 5
  getuserrealm: 15
gatekeeper:
  engagement_checksum: null  # Optional SHA256 checksum
target_definition:
  root_domains: "example.com,example.org"
  suspected_cloud_tenant: "example.onmicrosoft.com"
  optional_targets: "192.168.1.0/24"
recon_surface_mapping:
  passive_recon:
    enabled: true
    crtsh:
      enabled: true
      timeout: 180
    hunterio:
      enabled: true
      timeout: 120
  active_scan:
    enabled: true
    cidr_expansion_limit: 65536
    masscan_rate: 1000
    masscan_timeout: 300
    scan_ports: "88,135,139,389,445,593,636,3268,3269,53,587,443"
    nmap_script_set: "default,auth,vuln,ldap*"
    nmap_timeout: 600
    nmap_max_rate: 100
    nmap_script_timeout: 60
    nmap_max_ports: 25
    exclusion_list: []
    ad_likelihood_threshold: 70
    override_threshold_on_low_score: false
credential_harvest_spray:
  username_generation:
    linkedin_scrape:
      enabled: true
      timeout: 300
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
opsec:
  jitter_seconds: 0.5
```

## Contributing

This tool is a proof-of-concept for educational and authorized testing purposes. Contributions are welcome to enhance functionality (e.g., implementing placeholder modules, adding tests). To contribute:
1. Fork the repository (if hosted).
2. Create a feature branch (`git checkout -b feature/new-module`).
3. Submit a pull request with detailed changes.

**Requested Enhancements**:
- Unit tests for tool output simulation.
- Config validation to detect missing tools/settings.
- Implementation of cloud pivot, RCE, and privilege escalation modules.
- Support for additional credential spraying services (e.g., OWA, VPN).

## Legal Disclaimer

This tool is provided for **authorized security testing only**. Unauthorized use against systems without explicit permission is illegal and may result in criminal prosecution. Always obtain written consent (e.g., an engagement letter) before testing. The authors are not responsible for misuse or damages caused by this tool.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details (if included in the repository).

## Contact

For issues, feature requests, or questions, contact the project maintainer via GitHub Issues (if hosted) or your organization’s security team.

**Last Updated**: June 5, 2025
