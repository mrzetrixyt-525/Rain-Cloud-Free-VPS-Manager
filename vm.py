from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import hmac
import html
import ipaddress
import json
import logging
import os
import re
import secrets
import shlex
import signal
import socket
import sqlite3
import ssl
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote

try:
    import aiohttp
    from aiohttp import web
except ImportError:  # pragma: no cover
    aiohttp = None
    web = None

try:
    import discord
    from discord import app_commands
    from discord.ext import commands
except ImportError:  # pragma: no cover
    discord = None
    app_commands = None
    commands = None

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    def load_dotenv() -> None:
        return None

load_dotenv()

# ============================================================================
# RGNODES™ VM Manager — hardened KVM/QEMU + Docker/Pterodactyl compatible build
# ============================================================================
# Notes:
# - KVM/libvirt is preferred when available. QEMU without KVM is supported as a
#   safe fallback, but is much slower.
# - The Python service itself is cross-platform. The KVM backend requires a
#   Linux host with libvirt/virsh, qemu-img, and suitable QEMU binaries.
# - Guest OS images are intentionally supplied by the operator via local paths.
#   This avoids silently downloading or trusting arbitrary disk images.
# - Dashboard listens on WEB_PORT (default 3399) and requires authentication.
# - No web endpoint executes arbitrary host shell commands.

APP_NAME = "RGNODES™ VM Manager"
BUILD = "2026.09.10-kvm-dashboard-deepfix"
PREFIX = os.getenv("PREFIX", "-").strip() or "-"
DATABASE_FILE = os.getenv("DATABASE_FILE", "rgnodes_vm.db").strip() or "rgnodes_vm.db"
LOG_FILE = os.getenv("LOG_FILE", "rgnodes_vm.log").strip() or "rgnodes_vm.log"
WEB_HOST = os.getenv("WEB_HOST", "0.0.0.0").strip() or "0.0.0.0"
WEB_PORT = max(1, min(65535, int(os.getenv("WEB_PORT", "3399"))))
WEB_PUBLIC_URL = os.getenv("WEB_PUBLIC_URL", "").strip().rstrip("/")
SESSION_TTL = max(300, int(os.getenv("SESSION_TTL", "28800")))
LOGIN_WINDOW = max(30, int(os.getenv("LOGIN_WINDOW", "300")))
LOGIN_MAX_FAILURES = max(3, int(os.getenv("LOGIN_MAX_FAILURES", "8")))
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "0").strip().lower() in {"1", "true", "yes", "on"}
ADMIN_ID = int(os.getenv("ADMIN_ID", "0"))
DISCORD_TOKEN = (os.getenv("DISCORD_TOKEN") or os.getenv("TOKEN") or os.getenv("BOT_TOKEN") or "").strip().strip('"\'')
DISCORD_GUILD_ID = int(os.getenv("DISCORD_GUILD_ID", "0"))

BACKEND = os.getenv("VPS_BACKEND", "auto").strip().lower() or "auto"
if BACKEND not in {"auto", "kvm", "qemu", "docker", "pterodactyl"}:
    BACKEND = "auto"
KVM_STORAGE = Path(os.getenv("KVM_STORAGE", "/var/lib/rgnodes/vms")).expanduser()
KVM_NETWORK = os.getenv("KVM_NETWORK", "default").strip() or "default"
KVM_BRIDGE = os.getenv("KVM_BRIDGE", "").strip()
KVM_ARCH = os.getenv("KVM_ARCH", "x86_64").strip() or "x86_64"
KVM_MACHINE = os.getenv("KVM_MACHINE", "q35").strip() or "q35"
KVM_FIRMWARE = os.getenv("KVM_FIRMWARE", "bios").strip().lower() or "bios"
KVM_DISK_FORMAT = os.getenv("KVM_DISK_FORMAT", "qcow2").strip().lower() or "qcow2"
KVM_VCPUS_MAX = max(1, min(256, int(os.getenv("KVM_VCPUS_MAX", "64"))))
KVM_RAM_MAX_GB = max(1, min(1024, int(os.getenv("KVM_RAM_MAX_GB", "256"))))
KVM_DISK_MAX_GB = max(1, min(10000, int(os.getenv("KVM_DISK_MAX_GB", "1000"))))
KVM_AUTOSTART = os.getenv("KVM_AUTOSTART", "1").strip().lower() in {"1", "true", "yes", "on"}
KVM_REQUIRE_KVM = os.getenv("KVM_REQUIRE_KVM", "0").strip().lower() in {"1", "true", "yes", "on"}
GUEST_BOOTSTRAP = os.getenv("GUEST_BOOTSTRAP", "1").strip().lower() in {"1", "true", "yes", "on"}
GUEST_BOOTSTRAP_TIMEOUT = max(60, min(1800, int(os.getenv("GUEST_BOOTSTRAP_TIMEOUT", "900"))))
GUEST_INSTALL_KVM_TOOLS = os.getenv("GUEST_INSTALL_KVM_TOOLS", "1").strip().lower() in {"1", "true", "yes", "on"}
GUEST_INSTALL_SSHX = os.getenv("GUEST_INSTALL_SSHX", "1").strip().lower() in {"1", "true", "yes", "on"}
GUEST_INSTALL_PHP_STACK = os.getenv("GUEST_INSTALL_PHP_STACK", "1").strip().lower() in {"1", "true", "yes", "on"}
GUEST_RUN_FULL_UPGRADE = os.getenv("GUEST_RUN_FULL_UPGRADE", "1").strip().lower() in {"1", "true", "yes", "on"}

DEFAULT_RAM = os.getenv("DEFAULT_RAM", "4G").strip() or "4G"
DEFAULT_CPU = os.getenv("DEFAULT_CPU", "2").strip() or "2"
DEFAULT_DISK = os.getenv("DEFAULT_DISK", "20G").strip() or "20G"
SERVER_LIMIT = max(1, min(100, int(os.getenv("SERVER_LIMIT", "2"))))
TOTAL_RUNNING_LIMIT = max(1, min(10000, int(os.getenv("TOTAL_RUNNING_LIMIT", "50"))))

# Abuse guard. It is deliberately conservative: a single weak signal only
# quarantines; repeated/high-confidence signals can delete automatically.
ABUSE_ENABLED = os.getenv("ABUSE_ENABLED", "1").strip().lower() in {"1", "true", "yes", "on"}
ABUSE_AUTO_SUSPEND = os.getenv("ABUSE_AUTO_SUSPEND", "1").strip().lower() in {"1", "true", "yes", "on"}
ABUSE_AUTO_DELETE = os.getenv("ABUSE_AUTO_DELETE", "1").strip().lower() in {"1", "true", "yes", "on"}
ABUSE_SCAN_INTERVAL = max(15, min(600, int(os.getenv("ABUSE_SCAN_INTERVAL", "30"))))
ABUSE_CONN_THRESHOLD = max(20, min(100000, int(os.getenv("ABUSE_CONN_THRESHOLD", "800"))))
ABUSE_DEST_THRESHOLD = max(10, min(10000, int(os.getenv("ABUSE_DEST_THRESHOLD", "120"))))
ABUSE_CONFIRMATIONS_TO_DELETE = max(2, min(10, int(os.getenv("ABUSE_CONFIRMATIONS_TO_DELETE", "3"))))
ABUSE_TERMS = tuple(
    x.strip().lower()
    for x in os.getenv(
        "ABUSE_TERMS",
        "xmrig,minerd,masscan,zmap,hydra,medusa,sqlmap,nikto,msfconsole,metasploit,cobaltstrike,sliver",
    ).split(",")
    if x.strip()
)

PTERO_URL = os.getenv("PTERO_URL", "").strip().rstrip("/")
PTERO_API_KEY = (os.getenv("PTERO_API_KEY") or os.getenv("PTERODACTYL_APPLICATION_API_KEY") or "").strip()
PTERO_CLIENT_API_KEY = (os.getenv("PTERO_CLIENT_API_KEY") or os.getenv("PTERODACTYL_CLIENT_API_KEY") or "").strip()
PTERO_NODE_ID = int(os.getenv("PTERO_NODE_ID", "0"))
PTERO_NEST_ID = int(os.getenv("PTERO_NEST_ID", "0"))
PTERO_EGG_ID = int(os.getenv("PTERO_EGG_ID", "0"))
PTERO_ALLOCATION_ID = int(os.getenv("PTERO_ALLOCATION_ID", "0"))
PTERO_DEFAULT_USER_ID = int(os.getenv("PTERO_DEFAULT_USER_ID", "0"))

WEB_ADMIN_USER = os.getenv("WEB_ADMIN_USER", "admin").strip() or "admin"
WEB_ADMIN_PASSWORD = os.getenv("WEB_ADMIN_PASSWORD", "").strip()
WEB_ADMIN_PASSWORD_HASH = os.getenv("WEB_ADMIN_PASSWORD_HASH", "").strip()

# Optional guest image mapping. Example:
# KVM_BASE_IMAGES_JSON='{"ubuntu-24.04":"/var/lib/rgnodes/images/ubuntu-24.04.qcow2"}'
try:
    KVM_BASE_IMAGES: dict[str, str] = json.loads(os.getenv("KVM_BASE_IMAGES_JSON", "{}"))
    if not isinstance(KVM_BASE_IMAGES, dict):
        KVM_BASE_IMAGES = {}
except json.JSONDecodeError:
    KVM_BASE_IMAGES = {}

OS_ALIASES = {
    "ubuntu": "ubuntu-24.04",
    "ubuntu24": "ubuntu-24.04",
    "ubuntu24.04": "ubuntu-24.04",
    "ubuntu22": "ubuntu-22.04",
    "ubuntu22.04": "ubuntu-22.04",
    "debian": "debian-12",
    "debian12": "debian-12",
    "debian11": "debian-11",
    "rocky": "rocky-9",
    "rocky9": "rocky-9",
    "alma": "alma-9",
    "alma9": "alma-9",
    "windows": "windows",
    "windows11": "windows-11",
    "windows-11": "windows-11",
}
OS_LABELS = {
    "ubuntu-24.04": "Ubuntu 24.04 LTS",
    "ubuntu-22.04": "Ubuntu 22.04 LTS",
    "debian-12": "Debian 12",
    "debian-11": "Debian 11",
    "rocky-9": "Rocky Linux 9",
    "alma-9": "AlmaLinux 9",
    "windows-11": "Windows 11",
    "windows": "Windows (configured image)",
}

logger = logging.getLogger("rgnodes")
Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    handlers=[logging.FileHandler(LOG_FILE, encoding="utf-8"), logging.StreamHandler(sys.stdout)],
)

# ============================================================================
# Generic helpers
# ============================================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def clean(value: Any, limit: int = 500) -> str:
    return str(value if value is not None else "").replace("`", "'").replace("\x00", "")[:limit]


def env_secret_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return "pbkdf2$sha256$310000$%s$%s" % (
        base64.urlsafe_b64encode(salt).decode().rstrip("="),
        base64.urlsafe_b64encode(digest).decode().rstrip("="),
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, algo, iterations, salt_b64, digest_b64 = encoded.split("$", 4)
        if scheme != "pbkdf2" or algo != "sha256":
            return False
        salt = base64.urlsafe_b64decode(salt_b64 + "===")
        expected = base64.urlsafe_b64decode(digest_b64 + "===")
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iterations))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def password_configured() -> bool:
    return bool(WEB_ADMIN_PASSWORD_HASH or WEB_ADMIN_PASSWORD)


def verify_web_credentials(username: str, password: str) -> bool:
    if not hmac.compare_digest(username, WEB_ADMIN_USER):
        return False
    if WEB_ADMIN_PASSWORD_HASH:
        return verify_password(password, WEB_ADMIN_PASSWORD_HASH)
    if WEB_ADMIN_PASSWORD:
        return hmac.compare_digest(password, WEB_ADMIN_PASSWORD)
    return False


def normalize_os(value: str | None) -> str | None:
    raw = (value or "").strip().lower()
    return OS_ALIASES.get(raw, raw if raw in OS_LABELS else None)


def os_label(value: str | None) -> str:
    key = normalize_os(value) or (value or "Unknown")
    return OS_LABELS.get(key, key)


def parse_size_bytes(value: str | int | float) -> int:
    text = str(value).strip().lower().replace(" ", "")
    m = re.fullmatch(r"(\d+(?:\.\d+)?)(b|kb|kib|mb|mib|gb|gib|tb|tib|k|m|g|t)?", text)
    if not m:
        raise ValueError(f"Invalid size: {value}")
    amount = float(m.group(1))
    unit = m.group(2) or "g"
    factors = {
        "b": 1,
        "k": 1024,
        "kb": 1000,
        "kib": 1024,
        "m": 1024**2,
        "mb": 1000**2,
        "mib": 1024**2,
        "g": 1024**3,
        "gb": 1000**3,
        "gib": 1024**3,
        "t": 1024**4,
        "tb": 1000**4,
        "tib": 1024**4,
    }
    return int(amount * factors[unit])


def format_bytes(value: int | float | None) -> str:
    try:
        n = max(0, int(value or 0))
    except (ValueError, TypeError):
        return "N/A"
    units = ("B", "KB", "MB", "GB", "TB", "PB")
    v = float(n)
    for unit in units:
        if v < 1024 or unit == units[-1]:
            return f"{v:.1f}{unit}" if unit != "B" else f"{int(v)}B"
        v /= 1024
    return "N/A"


def validate_resources(ram: str, cpu: str, disk: str) -> tuple[str, int, str, int]:
    ram_b = parse_size_bytes(ram)
    disk_b = parse_size_bytes(disk)
    cpu_n = int(float(cpu))
    if not 256 * 1024**2 <= ram_b <= KVM_RAM_MAX_GB * 1024**3:
        raise ValueError(f"RAM must be between 256MB and {KVM_RAM_MAX_GB}GB.")
    if not 1 * 1024**3 <= disk_b <= KVM_DISK_MAX_GB * 1024**3:
        raise ValueError(f"Disk must be between 1GB and {KVM_DISK_MAX_GB}GB.")
    if cpu_n < 1 or cpu_n > KVM_VCPUS_MAX:
        raise ValueError(f"CPU must be between 1 and {KVM_VCPUS_MAX} vCPU(s).")
    return str(ram).strip(), cpu_n, str(disk).strip(), disk_b


def safe_name(value: str, fallback: str = "vm") -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
    value = value.strip(".-_")[:56]
    return value or fallback


def command_available(name: str) -> bool:
    from shutil import which
    return which(name) is not None


def detect_kvm() -> bool:
    return sys.platform.startswith("linux") and os.path.exists("/dev/kvm")


def qemu_backend_available(prefer_kvm: bool = True) -> tuple[bool, str]:
    if not sys.platform.startswith("linux"):
        return False, "QEMU/libvirt backend currently requires a Linux host."
    missing = [x for x in ("virsh", "qemu-img") if not command_available(x)]
    if missing:
        return False, "Missing required binaries: " + ", ".join(missing)
    if prefer_kvm and KVM_REQUIRE_KVM and not detect_kvm():
        return False, "/dev/kvm is unavailable and KVM is required by configuration."
    return True, "KVM" if detect_kvm() and prefer_kvm else "QEMU"


def choose_backend(override: str | None = None) -> str:
    choice = (override or BACKEND).strip().lower()
    if choice in {"kvm", "qemu"}:
        return choice
    if choice == "docker":
        return "docker"
    if choice == "pterodactyl":
        return "pterodactyl"
    ok, mode = qemu_backend_available(True)
    if ok:
        return "kvm" if mode == "KVM" else "qemu"
    if PTERO_URL and PTERO_API_KEY:
        return "pterodactyl"
    if command_available("docker"):
        return "docker"
    return "kvm"


# ============================================================================
# Database
# ============================================================================

DB_LOCK = asyncio.Lock()


def db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE_FILE, timeout=30, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def db_init() -> None:
    conn = db_connect()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users(
                user_id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS vms(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                backend TEXT NOT NULL,
                domain TEXT UNIQUE NOT NULL,
                os_type TEXT NOT NULL,
                ram TEXT NOT NULL,
                vcpu INTEGER NOT NULL,
                disk TEXT NOT NULL,
                disk_path TEXT,
                ip_address TEXT,
                status TEXT NOT NULL DEFAULT 'stopped',
                suspended INTEGER NOT NULL DEFAULT 0,
                abuse_score INTEGER NOT NULL DEFAULT 0,
                abuse_reason TEXT,
                bootstrap_status TEXT NOT NULL DEFAULT 'pending',
                bootstrap_message TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                deleted_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_vms_owner ON vms(owner_id);
            CREATE INDEX IF NOT EXISTS idx_vms_status ON vms(status);
            CREATE TABLE IF NOT EXISTS bans(
                user_id INTEGER PRIMARY KEY,
                reason TEXT NOT NULL DEFAULT 'policy violation',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_logs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT,
                detail TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions(
                token_hash TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                expires_at REAL NOT NULL,
                csrf TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_seen REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS login_failures(
                source TEXT PRIMARY KEY,
                failures INTEGER NOT NULL DEFAULT 0,
                first_seen REAL NOT NULL,
                blocked_until REAL NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS abuse_events(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vm_id INTEGER NOT NULL,
                score INTEGER NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(vm_id) REFERENCES vms(id) ON DELETE CASCADE
            );
            """
        )
        cols = {row["name"] for row in conn.execute("PRAGMA table_info(vms)")}
        if "bootstrap_status" not in cols:
            conn.execute("ALTER TABLE vms ADD COLUMN bootstrap_status TEXT NOT NULL DEFAULT 'pending'")
        if "bootstrap_message" not in cols:
            conn.execute("ALTER TABLE vms ADD COLUMN bootstrap_message TEXT")
    finally:
        conn.close()


def db_audit(actor: str, action: str, target: str = "", detail: str = "") -> None:
    conn = db_connect()
    try:
        conn.execute(
            "INSERT INTO audit_logs(actor,action,target,detail,created_at) VALUES(?,?,?,?,?)",
            (clean(actor, 120), clean(action, 120), clean(target, 200), clean(detail, 1500), now_iso()),
        )
    finally:
        conn.close()


def db_upsert_user(user_id: int, username: str) -> None:
    conn = db_connect()
    try:
        now = now_iso()
        conn.execute(
            "INSERT INTO users(user_id,username,created_at,updated_at) VALUES(?,?,?,?) "
            "ON CONFLICT(user_id) DO UPDATE SET username=excluded.username,updated_at=excluded.updated_at",
            (int(user_id), clean(username, 200), now, now),
        )
    finally:
        conn.close()


def db_is_banned(user_id: int) -> tuple[bool, str]:
    conn = db_connect()
    try:
        row = conn.execute("SELECT reason FROM bans WHERE user_id=?", (int(user_id),)).fetchone()
        return (True, str(row[0])) if row else (False, "")
    finally:
        conn.close()


def db_set_ban(user_id: int, banned: bool, reason: str = "policy violation") -> None:
    conn = db_connect()
    try:
        if banned:
            conn.execute(
                "INSERT INTO bans(user_id,reason,created_at) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET reason=excluded.reason",
                (int(user_id), clean(reason, 500), now_iso()),
            )
        else:
            conn.execute("DELETE FROM bans WHERE user_id=?", (int(user_id),))
    finally:
        conn.close()


def db_insert_vm(**values: Any) -> int:
    fields = [
        "owner_id", "name", "backend", "domain", "os_type", "ram", "vcpu",
        "disk", "disk_path", "ip_address", "status", "suspended", "bootstrap_status", "bootstrap_message", "created_at", "updated_at",
    ]
    data = {k: values.get(k) for k in fields}
    data["created_at"] = data.get("created_at") or now_iso()
    data["updated_at"] = data.get("updated_at") or now_iso()
    cols = ",".join(fields)
    placeholders = ",".join("?" for _ in fields)
    conn = db_connect()
    try:
        cur = conn.execute(
            f"INSERT INTO vms({cols}) VALUES({placeholders})",
            tuple(data[x] for x in fields),
        )
        return int(cur.lastrowid)
    finally:
        conn.close()


def db_get_vm(vm_id: int) -> sqlite3.Row | None:
    conn = db_connect()
    try:
        return conn.execute("SELECT * FROM vms WHERE id=? AND deleted_at IS NULL", (int(vm_id),)).fetchone()
    finally:
        conn.close()


def db_get_vms(owner_id: int | None = None) -> list[sqlite3.Row]:
    conn = db_connect()
    try:
        if owner_id is None:
            return conn.execute("SELECT * FROM vms WHERE deleted_at IS NULL ORDER BY id DESC").fetchall()
        return conn.execute("SELECT * FROM vms WHERE owner_id=? AND deleted_at IS NULL ORDER BY id DESC", (int(owner_id),)).fetchall()
    finally:
        conn.close()


def db_update_vm(vm_id: int, **fields: Any) -> None:
    allowed = {
        "name", "status", "suspended", "abuse_score", "abuse_reason", "ip_address",
        "backend", "disk_path", "bootstrap_status", "bootstrap_message", "updated_at", "deleted_at",
    }
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return
    updates["updated_at"] = now_iso()
    assignments = ",".join(f"{k}=?" for k in updates)
    conn = db_connect()
    try:
        conn.execute(f"UPDATE vms SET {assignments} WHERE id=?", (*updates.values(), int(vm_id)))
    finally:
        conn.close()


def db_find_vm(identifier: str, owner_id: int | None = None) -> sqlite3.Row | None:
    needle = (identifier or "").strip().lower()
    rows = db_get_vms(owner_id)
    if not rows:
        return None
    if not needle:
        return rows[0]
    exact = [
        r for r in rows
        if needle in {str(r["id"]).lower(), str(r["domain"]).lower(), str(r["name"]).lower()}
    ]
    if exact:
        return exact[0]
    partial = [r for r in rows if needle in str(r["domain"]).lower() or needle in str(r["name"]).lower()]
    return partial[0] if len(partial) == 1 else None


def db_running_count() -> int:
    conn = db_connect()
    try:
        return int(conn.execute("SELECT COUNT(*) FROM vms WHERE status='running' AND suspended=0").fetchone()[0])
    finally:
        conn.close()


def db_log_abuse(vm_id: int, score: int, reason: str) -> None:
    conn = db_connect()
    try:
        conn.execute(
            "INSERT INTO abuse_events(vm_id,score,reason,created_at) VALUES(?,?,?,?)",
            (int(vm_id), int(score), clean(reason, 1000), now_iso()),
        )
    finally:
        conn.close()


# ============================================================================
# Safe process execution
# ============================================================================

async def run_process(*args: str, timeout: float = 60.0, env: dict[str, str] | None = None) -> tuple[int, str, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
            env=env,
        )
    except FileNotFoundError as exc:
        return 127, "", str(exc)
    except OSError as exc:
        return 126, "", str(exc)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode or 0, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")
    except asyncio.TimeoutError:
        with contextlib.suppress(Exception):
            os.killpg(proc.pid, signal.SIGKILL)
        with contextlib.suppress(Exception):
            await proc.wait()
        return 124, "", "process timeout"
    except asyncio.CancelledError:
        with contextlib.suppress(Exception):
            os.killpg(proc.pid, signal.SIGKILL)
        raise


async def virsh(*args: str, timeout: float = 60.0) -> tuple[int, str, str]:
    return await run_process("virsh", *args, timeout=timeout)


async def qemu_img(*args: str, timeout: float = 300.0) -> tuple[int, str, str]:
    return await run_process("qemu-img", *args, timeout=timeout)


# ============================================================================
# Guest bootstrap via cloud-init
# ============================================================================

GUEST_BOOTSTRAP_SCRIPT = r"""#!/bin/bash
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

log() { printf '[RGNODES bootstrap] %s\\n' "$*" | tee -a /var/log/rgnodes-bootstrap.log; }

if command -v apt-get >/dev/null 2>&1; then
  log "Refreshing APT metadata"
  apt-get update -y
  if [ "__FULL_UPGRADE__" = "1" ]; then
    log "Running full system upgrade"
    apt-get full-upgrade -y
  fi
  log "Installing requested base packages"
  apt-get install -y software-properties-common ca-certificates curl apt-transport-https gnupg tar unzip git mariadb-server redis-server nginx certbot python3-certbot-nginx cloud-init qemu-guest-agent systemd systemd-sysv dbus

  if [ "__PHP_STACK__" = "1" ]; then
    if apt-cache show php8.3 >/dev/null 2>&1; then
      apt-get install -y php8.3 php8.3-common php8.3-cli php8.3-gd php8.3-mysql php8.3-mbstring php8.3-bcmath php8.3-xml php8.3-fpm php8.3-curl php8.3-zip || true
    else
      log "php8.3 unavailable; installing distribution PHP packages"
      apt-get install -y php php-common php-cli php-gd php-mysql php-mbstring php-bcmath php-xml php-fpm php-curl php-zip || true
    fi
  fi

  log "Installing Docker"
  if ! command -v docker >/dev/null 2>&1; then
    curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
    sh /tmp/get-docker.sh
  fi
  systemctl enable --now docker 2>/dev/null || true

  log "Installing Docker Compose"
  docker compose version >/dev/null 2>&1 || apt-get install -y docker-compose-plugin || apt-get install -y docker-compose-v2 || true

  log "Installing Node.js 20"
  if ! command -v node >/dev/null 2>&1 || ! node -v | grep -q '^v20\\.'; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y nodejs
  fi

  log "Installing npm and Yarn"
  npm install -g npm@10 || true
  corepack enable || true
  corepack prepare yarn@stable --activate || npm install -g yarn || true

  log "Installing PM2"
  npm install -g pm2 || true

  if [ "__SSHX__" = "1" ]; then
    log "Installing SSHx"
    command -v sshx >/dev/null 2>&1 || curl -sSf https://sshx.io/get | sh || true
  fi

  if [ "__KVM_TOOLS__" = "1" ]; then
    log "Installing QEMU/KVM/libvirt tooling"
    apt-get install -y qemu-kvm qemu-utils libvirt-daemon-system libvirt-clients virtinst bridge-utils ovmf || true
    systemctl enable --now libvirtd 2>/dev/null || systemctl enable --now libvirt-daemon 2>/dev/null || true
    if [ -e /dev/kvm ]; then log "Nested KVM is available"; else log "Nested KVM is not exposed; QEMU software mode remains available"; fi
  fi

  log "Enabling requested services"
  for unit in mariadb redis-server nginx ssh sshd qemu-guest-agent php8.3-fpm; do
    systemctl enable --now "$unit" 2>/dev/null || true
  done
  mkdir -p /var/lib/rgnodes
  touch /var/lib/rgnodes/.bootstrap-complete
  log "Bootstrap complete"
  exit 0
fi

if command -v dnf >/dev/null 2>&1; then
  log "Detected RPM-based Linux"
  dnf -y update || true
  dnf -y install curl ca-certificates git tar unzip nginx mariadb-server redis openssh-server nodejs npm qemu-guest-agent cloud-init || true
  if [ "__KVM_TOOLS__" = "1" ]; then dnf -y install qemu-kvm qemu-img libvirt virt-install edk2-ovmf || true; fi
  npm install -g pm2 yarn || true
  systemctl enable --now docker 2>/dev/null || true
  systemctl enable --now libvirtd 2>/dev/null || true
  systemctl enable --now sshd 2>/dev/null || true
  systemctl enable --now qemu-guest-agent 2>/dev/null || true
  mkdir -p /var/lib/rgnodes
  touch /var/lib/rgnodes/.bootstrap-complete
  exit 0
fi

log "Unsupported package manager; bootstrap skipped"
exit 0
"""

def render_bootstrap(os_type: str) -> str:
    text=GUEST_BOOTSTRAP_SCRIPT
    text=text.replace('__FULL_UPGRADE__','1' if GUEST_RUN_FULL_UPGRADE else '0')
    text=text.replace('__PHP_STACK__','1' if GUEST_INSTALL_PHP_STACK else '0')
    text=text.replace('__KVM_TOOLS__','1' if GUEST_INSTALL_KVM_TOOLS else '0')
    text=text.replace('__SSHX__','1' if GUEST_INSTALL_SSHX else '0')
    return text

async def build_cloud_init_iso(vm_id: int, os_type: str) -> Path | None:
    if not GUEST_BOOTSTRAP or not sys.platform.startswith('linux'):
        return None
    d = KVM_STORAGE / f"rgnodes-vm-{int(vm_id)}"
    d.mkdir(parents=True, exist_ok=True)
    ud = d / 'user-data'
    md = d / 'meta-data'
    seed = d / 'cloud-init.iso'
    content = "#cloud-config\\nwrite_files:\\n  - path: /usr/local/sbin/rgnodes-bootstrap.sh\\n    permissions: '0755'\\n    content: |\\n" + "\\n".join("      " + line for line in render_bootstrap(os_type).splitlines()) + "\\nruncmd:\\n  - /usr/local/sbin/rgnodes-bootstrap.sh\\n"
    ud.write_text(content, encoding='utf-8')
    md.write_text(f"instance-id: rgnodes-{vm_id}\\nlocal-hostname: rgnodes-vm-{vm_id}\\n", encoding='utf-8')
    if command_available('cloud-localds'):
        rc, _, _ = await run_process('cloud-localds', str(seed), str(ud), str(md), timeout=90)
        if rc == 0 and seed.exists(): return seed
    if command_available('xorriso'):
        rc, _, _ = await run_process('xorriso', '-as', 'mkisofs', '-output', str(seed), '-volid', 'cidata', '-joliet', '-rock', str(ud), str(md), timeout=90)
        if rc == 0 and seed.exists(): return seed
    if command_available('genisoimage'):
        rc, _, _ = await run_process('genisoimage', '-output', str(seed), '-volid', 'cidata', '-joliet', '-rock', str(ud), str(md), timeout=90)
        if rc == 0 and seed.exists(): return seed
    return None

# ============================================================================
# KVM/QEMU backend
# ============================================================================

class KVMBackend:
    def __init__(self, use_kvm: bool = True) -> None:
        self.use_kvm = use_kvm
        self.locks: dict[int, asyncio.Lock] = {}

    def lock(self, vm_id: int) -> asyncio.Lock:
        return self.locks.setdefault(int(vm_id), asyncio.Lock())

    async def preflight(self) -> tuple[bool, str]:
        ok, detail = qemu_backend_available(self.use_kvm)
        if not ok:
            return False, detail
        if self.use_kvm and detect_kvm():
            return True, "KVM/libvirt ready."
        if self.use_kvm and KVM_REQUIRE_KVM:
            return False, "/dev/kvm is required but unavailable."
        return True, "QEMU/libvirt ready (software emulation)."

    def domain_name(self, vm_id: int) -> str:
        return f"rgnodes-vm-{int(vm_id)}"

    def vm_dir(self, vm_id: int) -> Path:
        return KVM_STORAGE / self.domain_name(vm_id)

    def disk_path(self, vm_id: int) -> Path:
        return self.vm_dir(vm_id) / f"{self.domain_name(vm_id)}.{KVM_DISK_FORMAT}"

    async def ensure_dirs(self, vm_id: int) -> None:
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            raise PermissionError("KVM storage setup normally requires root on the host.")
        self.vm_dir(vm_id).mkdir(parents=True, exist_ok=True)
        os.chmod(self.vm_dir(vm_id), 0o750)

    def base_image(self, os_type: str) -> Path:
        key = normalize_os(os_type) or os_type
        raw = KVM_BASE_IMAGES.get(key) or KVM_BASE_IMAGES.get("default")
        if not raw:
            env_key = "KVM_BASE_IMAGE_" + re.sub(r"[^A-Za-z0-9]", "_", key).upper()
            raw = os.getenv(env_key, "").strip()
        if not raw:
            raise FileNotFoundError(
                f"No trusted base image is configured for {key}. Set {env_key} or KVM_BASE_IMAGES_JSON."
            )
        path = Path(raw).expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Base image does not exist: {path}")
        return path

    async def create(self, vm_id: int, os_type: str, ram: str, vcpu: int, disk: str, name: str) -> tuple[bool, str, str | None]:
        ok, detail = await self.preflight()
        if not ok:
            return False, detail, None
        await self.ensure_dirs(vm_id)
        base = self.base_image(os_type)
        target = self.disk_path(vm_id)
        if target.exists():
            return False, "Target disk already exists; refusing to overwrite it.", None
        disk_gb = max(1, int(parse_size_bytes(disk) / 1024**3))
        rc_info, out_info, _ = await qemu_img("info", "--output=json", str(base), timeout=60)
        base_format = KVM_DISK_FORMAT
        base_virtual_size = 0
        if rc_info == 0:
            with contextlib.suppress(ValueError, TypeError, KeyError):
                info = json.loads(out_info)
                detected = str(info.get("format") or "").strip().lower()
                if detected:
                    base_format = detected
                base_virtual_size = int(info.get("virtual-size") or 0)
        if base_virtual_size and parse_size_bytes(disk) < base_virtual_size:
            return False, f"Requested disk {disk} is smaller than the trusted base image virtual size ({format_bytes(base_virtual_size)}).", None
        rc, _, err = await qemu_img("create", "-f", KVM_DISK_FORMAT, "-F", base_format, "-b", str(base), str(target), str(disk_gb) + "G")
        if rc != 0:
            # Some source formats are not qcow2. Fall back to a standalone copy.
            rc, _, err = await qemu_img("convert", "-p", "-O", KVM_DISK_FORMAT, str(base), str(target), timeout=900)
            if rc != 0:
                return False, f"qemu-img failed: {clean(err, 1200)}", None
            rc, _, err = await qemu_img("resize", str(target), str(disk_gb) + "G")
            if rc != 0:
                target.unlink(missing_ok=True)
                return False, f"qemu-img resize failed: {clean(err, 1000)}", None
        seed = await build_cloud_init_iso(vm_id, os_type)
        xml = self.domain_xml(vm_id, name, ram, vcpu, target, os_type, seed)
        xml_path = self.vm_dir(vm_id) / "domain.xml"
        xml_path.write_text(xml, encoding="utf-8")
        rc, _, err = await virsh("define", str(xml_path), timeout=60)
        if rc != 0:
            target.unlink(missing_ok=True)
            return False, f"libvirt define failed: {clean(err, 1500)}", None
        if KVM_AUTOSTART:
            await virsh("autostart", self.domain_name(vm_id), timeout=30)
        return True, f"{('KVM' if self.use_kvm and detect_kvm() else 'QEMU')} VM created.", str(target)

    def domain_xml(self, vm_id: int, name: str, ram: str, vcpu: int, disk: Path, os_type: str, seed: Path | None = None) -> str:
        memory_kib = int(parse_size_bytes(ram) / 1024)
        domain_type = "kvm" if self.use_kvm and detect_kvm() else "qemu"
        uuid_value = str(uuid.uuid4())
        boot = "<boot dev='hd'/>"
        firmware = ""
        if KVM_FIRMWARE == "uefi":
            firmware = "<loader readonly='yes' type='pflash'>/usr/share/OVMF/OVMF_CODE.fd</loader>"
        net = (
            f"<interface type='bridge'><source bridge='{html.escape(KVM_BRIDGE)}'/><model type='virtio'/></interface>"
            if KVM_BRIDGE
            else f"<interface type='network'><source network='{html.escape(KVM_NETWORK)}'/><model type='virtio'/></interface>"
        )
        graphics = "<graphics type='spice' autoport='yes'><listen type='address' address='127.0.0.1'/></graphics>"
        channel = "<channel type='unix'><target type='virtio' name='org.qemu.guest_agent.0'/></channel>"
        return f"""<domain type='{domain_type}'>
  <name>{html.escape(self.domain_name(vm_id))}</name>
  <uuid>{uuid_value}</uuid>
  <memory unit='KiB'>{memory_kib}</memory>
  <currentMemory unit='KiB'>{memory_kib}</currentMemory>
  <vcpu placement='static'>{int(vcpu)}</vcpu>
  <os>{firmware}<type arch='{html.escape(KVM_ARCH)}' machine='{html.escape(KVM_MACHINE)}'>hvm</type>{boot}</os>
  <features><acpi/><apic/></features>
  <cpu mode='host-model'/>
  <clock offset='utc'/>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>restart</on_crash>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='{html.escape(KVM_DISK_FORMAT)}' cache='none' discard='unmap'/>
      <source file='{html.escape(str(disk))}'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    {((f"<disk type='file' device='cdrom'><driver name='qemu' type='raw'/><source file='{html.escape(str(seed))}'/><target dev='sdb' bus='sata'/><readonly/></disk>") if seed else '')}
    {net}
    <serial type='pty'/>
    <console type='pty'/>
    {graphics}
    {channel}
    <memballoon model='virtio'/>
  </devices>
</domain>"""

    async def state(self, vm_id: int) -> str:
        rc, out, _ = await virsh("domstate", self.domain_name(vm_id), timeout=20)
        return out.strip().lower() if rc == 0 else "missing"

    async def start(self, vm_id: int) -> tuple[bool, str]:
        async with self.lock(vm_id):
            state = await self.state(vm_id)
            if state == "running":
                return True, "VM is already running."
            rc, _, err = await virsh("start", self.domain_name(vm_id), timeout=90)
            return rc == 0, "VM started." if rc == 0 else clean(err, 1200)

    async def stop(self, vm_id: int) -> tuple[bool, str]:
        async with self.lock(vm_id):
            state = await self.state(vm_id)
            if state in {"shut off", "missing"}:
                return True, "VM is already stopped."
            rc, _, err = await virsh("shutdown", self.domain_name(vm_id), timeout=60)
            if rc != 0:
                return False, clean(err, 1200)
            for _ in range(20):
                if await self.state(vm_id) == "shut off":
                    return True, "VM stopped gracefully."
                await asyncio.sleep(1)
            rc, _, err = await virsh("destroy", self.domain_name(vm_id), timeout=30)
            return rc == 0, "VM force-stopped." if rc == 0 else clean(err, 1200)

    async def restart(self, vm_id: int) -> tuple[bool, str]:
        async with self.lock(vm_id):
            state = await self.state(vm_id)
            if state == "missing":
                return False, "VM domain is missing."
            rc, _, err = await virsh("reboot", self.domain_name(vm_id), timeout=60)
            if rc == 0:
                return True, "VM reboot requested."
            rc, _, err = await virsh("destroy", self.domain_name(vm_id), timeout=30)
            if rc != 0:
                return False, clean(err, 1200)
            rc, _, err = await virsh("start", self.domain_name(vm_id), timeout=90)
            return rc == 0, "VM restarted." if rc == 0 else clean(err, 1200)

    async def delete(self, vm_id: int) -> tuple[bool, str]:
        async with self.lock(vm_id):
            domain = self.domain_name(vm_id)
            state = await self.state(vm_id)
            if state not in {"shut off", "missing"}:
                rc, _, err = await virsh("shutdown", domain, timeout=60)
                if rc != 0:
                    rc, _, err = await virsh("destroy", domain, timeout=30)
                    if rc != 0:
                        return False, clean(err, 1200)
                else:
                    for _ in range(20):
                        if await self.state(vm_id) == "shut off":
                            break
                        await asyncio.sleep(1)
                    else:
                        rc, _, err = await virsh("destroy", domain, timeout=30)
                        if rc != 0:
                            return False, clean(err, 1200)
            await virsh("undefine", domain, "--remove-all-storage", timeout=120)
            # --remove-all-storage can be unavailable or the disk may be a backing chain.
            path = self.vm_dir(vm_id)
            if path.exists():
                for child in sorted(path.rglob("*"), reverse=True):
                    if child.is_file() or child.is_symlink():
                        child.unlink(missing_ok=True)
                with contextlib.suppress(OSError):
                    path.rmdir()
            return True, "VM deleted."

    async def snapshot(self, vm_id: int, name: str) -> tuple[bool, str]:
        name = safe_name(name, "snapshot")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", name):
            return False, "Invalid snapshot name."
        async with self.lock(vm_id):
            if await self.state(vm_id) == "missing":
                return False, "VM domain is missing."
            rc, _, err = await virsh("snapshot-create-as", self.domain_name(vm_id), name, "--atomic", timeout=300)
            return rc == 0, "Snapshot created." if rc == 0 else clean(err, 1200)

    async def snapshot_list(self, vm_id: int) -> list[str]:
        rc, out, _ = await virsh("snapshot-list", self.domain_name(vm_id), "--name", timeout=60)
        if rc != 0:
            return []
        return [line.strip() for line in out.splitlines() if line.strip()]

    async def snapshot_restore(self, vm_id: int, name: str) -> tuple[bool, str]:
        name = safe_name(name, "snapshot")
        async with self.lock(vm_id):
            state = await self.state(vm_id)
            was_running = state == "running"
            if was_running:
                rc, _, err = await virsh("shutdown", self.domain_name(vm_id), timeout=60)
                if rc != 0:
                    return False, clean(err, 1200)
                for _ in range(30):
                    if await self.state(vm_id) == "shut off": break
                    await asyncio.sleep(1)
                else:
                    return False, "VM did not stop before snapshot restore."
            revert_args = ["snapshot-revert", self.domain_name(vm_id), name]
            if was_running:
                revert_args.append("--running")
            rc, _, err = await virsh(*revert_args, timeout=180)
            if rc != 0:
                return False, clean(err, 1200)
            return True, f"Snapshot `{name}` restored."

    async def ip(self, vm_id: int) -> str | None:
        domain = self.domain_name(vm_id)
        for source in ("lease", "arp", "agent"):
            rc, out, _ = await virsh("domifaddr", domain, "--source", source, timeout=15)
            if rc != 0:
                continue
            for line in out.splitlines():
                match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})/\d+\b", line)
                if match:
                    try:
                        addr = ipaddress.ip_address(match.group(1))
                        if isinstance(addr, ipaddress.IPv4Address) and not addr.is_loopback:
                            return str(addr)
                    except ValueError:
                        continue
        return None

    async def guest_bootstrap_complete(self, vm_id: int) -> bool:
        domain = self.domain_name(vm_id)
        cmd = json.dumps({"execute": "guest-exec", "arguments": {"path": "/bin/sh", "arg": ["-lc", "test -f /var/lib/rgnodes/.bootstrap-complete && echo READY"], "capture-output": True}})
        rc, out, _ = await virsh("qemu-agent-command", domain, cmd, timeout=20)
        if rc != 0 or not out.strip():
            return False
        try:
            pid = json.loads(out).get("return", {}).get("pid")
            if pid is None: return False
            await asyncio.sleep(0.2)
            status_cmd = json.dumps({"execute": "guest-exec-status", "arguments": {"pid": pid, "capture-output": True}})
            rc2, out2, _ = await virsh("qemu-agent-command", domain, status_cmd, timeout=20)
            if rc2 != 0: return False
            encoded = json.loads(out2).get("return", {}).get("out-data")
            if not encoded: return False
            return "READY" in base64.b64decode(encoded).decode("utf-8", "replace")
        except (ValueError, TypeError, KeyError):
            return False

    async def stats(self, vm_id: int) -> dict[str, str]:
        domain = self.domain_name(vm_id)
        state = await self.state(vm_id)
        rc, out, _ = await virsh("domstats", domain, "--balloon", "--vcpu", "--state", timeout=30)
        data: dict[str, str] = {"state": state}
        if rc == 0:
            for line in out.splitlines():
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                data[key.strip()] = value.strip()
        data["ip"] = (await self.ip(vm_id)) or "N/A"
        return data

    async def logs(self, vm_id: int, lines: int = 80) -> str:
        path = self.vm_dir(vm_id) / "domain.xml"
        if path.exists():
            text = path.read_text(encoding="utf-8", errors="replace")
            return "Domain XML:\n" + text[-min(3800, max(500, lines * 120)):]
        return "No local VM metadata found."

    async def guest_process_text(self, vm_id: int) -> str | None:
        # Uses the QEMU guest agent when available. No arbitrary host command is
        # accepted here; only a fixed read-only `ps` query is requested.
        domain = self.domain_name(vm_id)
        cmd = json.dumps({
            "execute": "guest-exec",
            "arguments": {
                "path": "/usr/bin/ps",
                "arg": ["-eo", "comm,args"],
                "capture-output": True,
            },
        })
        rc, out, _ = await virsh("qemu-agent-command", domain, cmd, timeout=20)
        if rc != 0 or not out.strip():
            return None
        try:
            payload = json.loads(out)
            pid = payload.get("return", {}).get("pid")
            if pid is None:
                return None
            await asyncio.sleep(0.25)
            read_cmd = json.dumps({
                "execute": "guest-exec-status",
                "arguments": {"pid": pid, "capture-output": True},
            })
            rc2, out2, _ = await virsh("qemu-agent-command", domain, read_cmd, timeout=20)
            if rc2 != 0:
                return None
            status = json.loads(out2).get("return", {})
            encoded = status.get("out-data")
            if encoded:
                return base64.b64decode(encoded).decode("utf-8", "replace")
        except (ValueError, KeyError, TypeError, UnicodeError):
            return None
        return None


KVM = KVMBackend(use_kvm=True)
QEMU = KVMBackend(use_kvm=False)


# ============================================================================
# Docker compatibility backend (kept intentionally non-privileged)
# ============================================================================

async def docker_available() -> bool:
    rc, _, _ = await run_process("docker", "info", timeout=20)
    return rc == 0


async def docker_state(name: str) -> str:
    rc, out, _ = await run_process("docker", "inspect", "-f", "{{.State.Status}}", name, timeout=20)
    return out.strip().lower() if rc == 0 else "missing"


async def docker_create(vm_id: int, os_type: str, ram: str, cpu: int, disk: str, name: str) -> tuple[bool, str]:
    if not await docker_available():
        return False, "Docker daemon is not reachable."
    image = {
        "ubuntu-24.04": "ubuntu:24.04",
        "ubuntu-22.04": "ubuntu:22.04",
        "debian-12": "debian:12",
        "debian-11": "debian:11",
    }.get(normalize_os(os_type) or "", "")
    if not image:
        return False, "Docker mode supports only the configured Linux container images. Use KVM for full VM isolation."
    ram_b = parse_size_bytes(ram)
    # Disk quota is intentionally not emulated with privileged/storage-driver tricks.
    cmd = [
        "docker", "run", "-d", "--name", name,
        "--hostname", name,
        "--memory", str(ram_b),
        "--cpus", str(cpu),
        "--pids-limit", "1024",
        "--restart", "unless-stopped",
        "--security-opt", "no-new-privileges:true",
        "--cap-drop", "ALL",
        "--label", "com.rgnodes.managed=true",
        image,
        "sh", "-lc", "while :; do sleep 3600; done",
    ]
    rc, out, err = await run_process(*cmd, timeout=180)
    return (True, "Docker container created.") if rc == 0 else (False, clean(err, 1400))


async def docker_action(name: str, action: str) -> tuple[bool, str]:
    verb = {"start": "start", "stop": "stop", "restart": "restart", "delete": "rm"}.get(action)
    if not verb:
        return False, "Unsupported Docker action."
    args = ["docker", verb]
    if action == "delete":
        args += ["-f"]
    args.append(name)
    rc, _, err = await run_process(*args, timeout=90)
    return rc == 0, ("Done." if rc == 0 else clean(err, 1400))


# ============================================================================
# Pterodactyl minimal compatibility helpers
# ============================================================================

async def ptero_request(method: str, path: str, payload: dict[str, Any] | None = None, client: bool = False) -> tuple[int, dict[str, Any] | str]:
    if aiohttp is None:
        return 503, "aiohttp is not installed."
    key = PTERO_CLIENT_API_KEY if client else PTERO_API_KEY
    if not PTERO_URL or not key:
        return 503, "Pterodactyl is not configured."
    headers = {
        "Authorization": f"Bearer {key}",
        "Accept": "Application/vnd.pterodactyl.v1+json",
        "Content-Type": "application/json",
        "User-Agent": "RGNODES-VM-Manager/3.0",
    }
    try:
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            async with session.request(method.upper(), f"{PTERO_URL}/api/{path.lstrip('/')}", json=payload) as resp:
                text = await resp.text()
                try:
                    body: dict[str, Any] | str = json.loads(text) if text else {}
                except json.JSONDecodeError:
                    body = text
                return resp.status, body
    except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
        return 599, str(exc)


# ============================================================================
# VM service
# ============================================================================

@dataclass(slots=True)
class ActionResult:
    ok: bool
    message: str
    vm: sqlite3.Row | None = None


class VMService:
    def __init__(self) -> None:
        self.create_lock = asyncio.Lock()
        self.vm_locks: dict[int, asyncio.Lock] = {}

    def lock(self, vm_id: int) -> asyncio.Lock:
        return self.vm_locks.setdefault(int(vm_id), asyncio.Lock())

    def backend_for(self, backend: str) -> KVMBackend | None:
        if backend == "kvm":
            return KVM
        if backend == "qemu":
            return QEMU
        return None

    async def refresh_state(self, vm: sqlite3.Row) -> sqlite3.Row:
        backend = str(vm["backend"])
        state = "unknown"
        if backend in {"kvm", "qemu"}:
            state = await self.backend_for(backend).state(int(vm["id"]))  # type: ignore[union-attr]
            if state == "running":
                db_update_vm(vm["id"], status="running")
            elif state in {"shut off", "missing"}:
                db_update_vm(vm["id"], status="stopped")
            ip = await self.backend_for(backend).ip(int(vm["id"]))  # type: ignore[union-attr]
            if ip:
                db_update_vm(vm["id"], ip_address=ip)
        elif backend == "docker":
            state = await docker_state(vm["domain"])
            db_update_vm(vm["id"], status="running" if state == "running" else "stopped")
        return db_get_vm(vm["id"]) or vm

    async def create(self, owner_id: int, username: str, os_type: str, ram: str, cpu: str, disk: str, name: str | None = None, backend_override: str | None = None) -> ActionResult:
        norm_os = normalize_os(os_type)
        if not norm_os:
            return ActionResult(False, "Unsupported operating system.")
        try:
            ram_text, vcpu, disk_text, _ = validate_resources(ram, cpu, disk)
        except ValueError as exc:
            return ActionResult(False, str(exc))
        banned, reason = db_is_banned(owner_id)
        if banned:
            return ActionResult(False, f"Account is blocked from VM creation: {reason}")
        async with self.create_lock:
            existing = len(db_get_vms(owner_id))
            if owner_id != ADMIN_ID and existing >= SERVER_LIMIT:
                return ActionResult(False, f"VM slot limit reached: {existing}/{SERVER_LIMIT}.")
            running = db_running_count()
            if owner_id != ADMIN_ID and running >= TOTAL_RUNNING_LIMIT:
                return ActionResult(False, f"Global running VM limit reached: {TOTAL_RUNNING_LIMIT}.")
            backend = choose_backend(backend_override)
            vm_name = safe_name(name or f"rgnodes-{owner_id}-{secrets.token_hex(3)}")
            # Domain names are deterministic and immutable after creation.
            domain = f"rgnodes-vm-{uuid.uuid4().hex[:12]}"
            db_upsert_user(owner_id, username)
            vm_id = db_insert_vm(
                owner_id=owner_id,
                name=vm_name,
                backend=backend,
                domain=domain,
                os_type=norm_os,
                ram=ram_text,
                vcpu=vcpu,
                disk=disk_text,
                disk_path=None,
                status="creating",
                suspended=0,
            )
            db_audit(str(owner_id), "create-start", str(vm_id), f"backend={backend}; os={norm_os}; ram={ram_text}; cpu={vcpu}; disk={disk_text}")
            try:
                if backend in {"kvm", "qemu"}:
                    ok, msg, disk_path = await self.backend_for(backend).create(vm_id, norm_os, ram_text, vcpu, disk_text, vm_name)  # type: ignore[union-attr]
                    if not ok:
                        db_update_vm(vm_id, status="error", abuse_reason=msg)
                        db_audit("system", "create-failed", str(vm_id), msg)
                        return ActionResult(False, msg, db_get_vm(vm_id))
                    db_update_vm(vm_id, status="stopped", disk_path=disk_path, bootstrap_status="pending", bootstrap_message="Cloud-init bootstrap scheduled.")
                    if GUEST_BOOTSTRAP:
                        started, start_msg = await self.backend_for(backend).start(vm_id)
                        if started:
                            db_update_vm(vm_id, status="running", bootstrap_status="running", bootstrap_message="Guest provisioning started.")
                            deadline = asyncio.get_running_loop().time() + GUEST_BOOTSTRAP_TIMEOUT
                            complete = False
                            while asyncio.get_running_loop().time() < deadline:
                                if await self.backend_for(backend).guest_bootstrap_complete(vm_id):
                                    complete = True
                                    break
                                if await self.backend_for(backend).state(vm_id) != "running":
                                    break
                                await asyncio.sleep(5)
                            db_update_vm(vm_id, bootstrap_status="complete" if complete else "timeout", bootstrap_message="Requested software installed." if complete else "Cloud-init did not report completion before timeout.")
                            if not KVM_AUTOSTART:
                                await self.backend_for(backend).stop(vm_id)
                                db_update_vm(vm_id, status="stopped")
                        else:
                            db_update_vm(vm_id, bootstrap_status="start-failed", bootstrap_message=start_msg)
                elif backend == "docker":
                    ok, msg = await docker_create(vm_id, norm_os, ram_text, vcpu, disk_text, domain)
                    if not ok:
                        db_update_vm(vm_id, status="error", abuse_reason=msg)
                        return ActionResult(False, msg, db_get_vm(vm_id))
                    db_update_vm(vm_id, status="running")
                elif backend == "pterodactyl":
                    return ActionResult(False, "Pterodactyl creation requires the panel-specific Egg/environment configuration; use KVM/QEMU for true VM creation.", db_get_vm(vm_id))
                else:
                    return ActionResult(False, f"Unsupported backend: {backend}.", db_get_vm(vm_id))
                db_audit(str(owner_id), "create", str(vm_id), f"{backend}/{norm_os}")
                vm = db_get_vm(vm_id)
                return ActionResult(True, f"VM #{vm_id} created successfully using {backend.upper()}.", vm)
            except Exception as exc:
                logger.exception("VM creation failed")
                db_update_vm(vm_id, status="error", abuse_reason=str(exc))
                return ActionResult(False, f"VM creation failed safely: {clean(exc, 1200)}", db_get_vm(vm_id))

    async def action(self, vm: sqlite3.Row, action: str, actor: str = "system") -> ActionResult:
        vm_id = int(vm["id"])
        backend = str(vm["backend"])
        async with self.lock(vm_id):
            current = db_get_vm(vm_id)
            if not current:
                return ActionResult(False, "VM no longer exists.")
            if int(current["suspended"]):
                if action == "start":
                    return ActionResult(False, "VM is suspended by an administrator.", current)
            if backend in {"kvm", "qemu"}:
                handler = self.backend_for(backend)
                if action == "start":
                    ok, msg = await handler.start(vm_id)  # type: ignore[union-attr]
                elif action == "stop":
                    ok, msg = await handler.stop(vm_id)  # type: ignore[union-attr]
                elif action == "restart":
                    ok, msg = await handler.restart(vm_id)  # type: ignore[union-attr]
                elif action == "delete":
                    ok, msg = await handler.delete(vm_id)  # type: ignore[union-attr]
                else:
                    return ActionResult(False, f"Unsupported action: {action}.", current)
            elif backend == "docker":
                ok, msg = await docker_action(current["domain"], action)
            else:
                return ActionResult(False, "Unsupported backend.", current)
            if not ok:
                db_audit(actor, f"{action}-failed", str(vm_id), msg)
                return ActionResult(False, msg, db_get_vm(vm_id) or current)
            if action == "delete":
                db_update_vm(vm_id, status="deleted", deleted_at=now_iso())
            elif action in {"stop"}:
                db_update_vm(vm_id, status="stopped")
            elif action in {"start", "restart"}:
                db_update_vm(vm_id, status="running")
            db_audit(actor, action, str(vm_id), msg)
            return ActionResult(True, msg, db_get_vm(vm_id) or current)

    async def suspend(self, vm: sqlite3.Row, actor: str, reason: str) -> ActionResult:
        result = await self.action(vm, "stop", actor)
        if not result.ok:
            return result
        db_update_vm(vm["id"], suspended=1, abuse_reason=reason)
        db_audit(actor, "suspend", str(vm["id"]), reason)
        return ActionResult(True, "VM suspended and stopped.", db_get_vm(vm["id"]))

    async def unsuspend(self, vm: sqlite3.Row, actor: str) -> ActionResult:
        db_update_vm(vm["id"], suspended=0, abuse_reason=None, abuse_score=0)
        db_audit(actor, "unsuspend", str(vm["id"]))
        return ActionResult(True, "VM unsuspended. It remains stopped until started.", db_get_vm(vm["id"]))

    async def stats(self, vm: sqlite3.Row) -> dict[str, str]:
        vm = await self.refresh_state(vm)
        backend = str(vm["backend"])
        if backend in {"kvm", "qemu"}:
            raw = await self.backend_for(backend).stats(int(vm["id"]))  # type: ignore[union-attr]
            return {
                "state": clean(raw.get("state", vm["status"])),
                "ip": clean(raw.get("ip", vm["ip_address"] or "N/A")),
                "cpu_time": clean(raw.get("vcpu.0.state.time", "N/A")),
                "balloon": clean(raw.get("balloon.current", "N/A")),
                "vcpu": clean(raw.get("vcpu.current", vm["vcpu"])),
            }
        return {"state": clean(vm["status"]), "ip": clean(vm["ip_address"] or "N/A"), "cpu_time": "N/A", "balloon": "N/A", "vcpu": clean(vm["vcpu"])}


SERVICE = VMService()


# ============================================================================
# Abuse / anti-hacking enforcement
# ============================================================================

async def abuse_connections(ip: str | None) -> tuple[int, int]:
    if not ip or not command_available("conntrack"):
        return 0, 0
    try:
        rc, out, _ = await run_process("conntrack", "-L", "-f", "ipv4", timeout=12)
        if rc != 0:
            return 0, 0
        total = 0
        dests: set[str] = set()
        for line in out.splitlines():
            if f"src={ip}" not in line:
                continue
            total += 1
            m = re.search(r"dst=([^ ]+)", line)
            if m:
                dests.add(m.group(1))
        return total, len(dests)
    except Exception:
        return 0, 0


def suspicious_processes(text: str | None) -> list[str]:
    if not text:
        return []
    lowered = text.lower()
    return sorted({term for term in ABUSE_TERMS if term in lowered})


async def enforce_abuse(vm: sqlite3.Row) -> None:
    if not ABUSE_ENABLED or vm["backend"] not in {"kvm", "qemu"}:
        return
    try:
        vm = await SERVICE.refresh_state(vm)
    except Exception as exc:
        logger.debug("Abuse state refresh failed for VM %s: %s", vm["id"], clean(exc))
    if vm["status"] != "running" or int(vm["suspended"]):
        return
    reasons: list[str] = []
    score = 0
    ip = vm["ip_address"]
    total_conn, unique_dest = await abuse_connections(ip)
    if total_conn >= ABUSE_CONN_THRESHOLD:
        score += 2
        reasons.append(f"high connection count={total_conn}")
    if unique_dest >= ABUSE_DEST_THRESHOLD:
        score += 2
        reasons.append(f"high destination diversity={unique_dest}")
    with contextlib.suppress(Exception):
        proc_text = await SERVICE.backend_for(vm["backend"]).guest_process_text(int(vm["id"]))  # type: ignore[union-attr]
        terms = suspicious_processes(proc_text)
        if terms:
            score += 3
            reasons.append("suspicious process indicators=" + ",".join(terms))
    if score <= 0:
        return
    new_score = int(vm["abuse_score"]) + score
    reason = "; ".join(reasons)
    db_update_vm(vm["id"], abuse_score=new_score, abuse_reason=reason)
    db_log_abuse(vm["id"], score, reason)
    db_audit("abuse-guard", "signal", str(vm["id"]), reason)
    latest = db_get_vm(vm["id"])
    if not latest:
        return
    suspicious_hit = any("suspicious process indicators=" in item for item in reasons)
    if ABUSE_AUTO_DELETE and suspicious_hit and score >= 3:
        # High-confidence guest-side abuse indicators trigger immediate removal.
        result = await SERVICE.action(latest, "delete", "abuse-guard")
        if result.ok:
            db_set_ban(int(vm["owner_id"]), True, "automatic abuse-policy enforcement: " + reason)
            db_audit("abuse-guard", "auto-delete", str(vm["id"]), reason)
            db_audit("abuse-guard", "auto-ban", str(vm["owner_id"]), reason)
        return
    if ABUSE_AUTO_SUSPEND and new_score >= 2:
        await SERVICE.suspend(latest, "abuse-guard", reason)


async def abuse_loop(stop_event: asyncio.Event) -> None:
    while not stop_event.is_set():
        try:
            for vm in db_get_vms():
                await enforce_abuse(vm)
        except Exception:
            logger.exception("Abuse monitor iteration failed")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=ABUSE_SCAN_INTERVAL)
        except asyncio.TimeoutError:
            pass


# ============================================================================
# Web dashboard / authentication
# ============================================================================

@dataclass(slots=True)
class WebSession:
    username: str
    csrf: str
    expires_at: float


WEB_SESSIONS: dict[str, WebSession] = {}
WEB_LOGIN_LOCK = asyncio.Lock()
WEB_FAIL_LOCK = asyncio.Lock()


def session_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def cleanup_sessions() -> None:
    now = time.time()
    conn = db_connect()
    try:
        conn.execute("DELETE FROM sessions WHERE expires_at<?", (now,))
    finally:
        conn.close()
    WEB_SESSIONS.clear()


def get_client_ip(request: web.Request) -> str:  # type: ignore[union-attr]
    peer = request.transport.get_extra_info("peername") if request.transport else None
    return str(peer[0]) if isinstance(peer, tuple) and peer else "unknown"


def csrf_valid(request: web.Request, session: WebSession) -> bool:  # type: ignore[union-attr]
    token = request.headers.get("X-CSRF-Token") or request.query.get("csrf")
    return bool(token and hmac.compare_digest(token, session.csrf))


def get_session(request: web.Request) -> WebSession | None:  # type: ignore[union-attr]
    token = request.cookies.get("rgnodes_session", "")
    if not token:
        return None
    hashed = session_hash(token)
    session = WEB_SESSIONS.get(hashed)
    if not session or session.expires_at < time.time():
        return None
    session.expires_at = time.time() + SESSION_TTL
    conn = db_connect()
    try:
        conn.execute("UPDATE sessions SET expires_at=?,last_seen=? WHERE token_hash=?", (session.expires_at, time.time(), hashed))
    finally:
        conn.close()
    return session


def html_page(title: str, body: str, script: str = "", authenticated: bool = False) -> str:
    logout = "<form method='post' action='/logout'><input type='hidden' name='csrf' id='logoutcsrf'><button class='danger'>Logout</button></form>" if authenticated else ""
    return f"""<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>{html.escape(title)}</title><style>
:root{{color-scheme:dark}}body{{margin:0;background:#0b1020;color:#e8eef7;font-family:Inter,system-ui,Segoe UI,Arial,sans-serif}}
.wrap{{max-width:1200px;margin:0 auto;padding:28px}}.top{{display:flex;justify-content:space-between;gap:20px;align-items:center;margin-bottom:22px}}
.card{{background:#121a2b;border:1px solid #24304a;border-radius:16px;padding:18px;margin-bottom:18px;box-shadow:0 14px 50px #0005}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px}}h1{{margin:0 0 4px;font-size:28px}}h2{{font-size:18px;margin-top:0}}small,.muted{{color:#9eabc0}}label{{display:block;margin:10px 0 6px;color:#b8c3d5}}input,select,button{{width:100%;box-sizing:border-box;border:1px solid #33415e;background:#0f1727;color:#edf3fb;border-radius:10px;padding:10px;font:inherit}}button{{cursor:pointer;background:#25365a}}button:hover{{background:#2e4775}}button.danger{{background:#71363d}}button.good{{background:#285a45}}.row{{display:flex;gap:8px;margin-top:10px}}.row>*{{flex:1}}pre{{white-space:pre-wrap;word-break:break-word;background:#09101d;padding:12px;border-radius:10px;max-height:360px;overflow:auto}}
.badge{{display:inline-block;border-radius:999px;padding:4px 9px;background:#25314a;font-size:12px}}.running{{background:#1e6548}}.stopped{{background:#5e2930}}.suspended{{background:#684f22}}table{{width:100%;border-collapse:collapse}}th,td{{text-align:left;padding:10px;border-bottom:1px solid #24304a;font-size:14px}}.mono{{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}}
</style></head><body><div class='wrap'><div class='top'><div><h1>RGNODES™ VM Manager</h1><div class='muted'>{html.escape(BUILD)} • dashboard :{WEB_PORT}</div></div>{logout}</div>{body}</div><script>{script}</script></body></html>"""


async def web_require_auth(request: web.Request) -> WebSession | web.Response:  # type: ignore[union-attr]
    if not password_configured():
        return web.Response(status=503, text="Web login is not configured. Set WEB_ADMIN_PASSWORD_HASH or WEB_ADMIN_PASSWORD.")
    session = get_session(request)
    if not session:
        raise web.HTTPFound("/login")
    return session


async def web_login_get(request: web.Request) -> web.Response:  # type: ignore[union-attr]
    body = """<div class='card' style='max-width:420px;margin:80px auto'><h2>Admin login</h2><p class='muted'>Authenticate to manage RGNODES VMs.</p><form method='post' action='/login'>
<label>Username</label><input name='username' autocomplete='username' required><label>Password</label><input type='password' name='password' autocomplete='current-password' required>
<div style='margin-top:14px'><button class='good'>Login</button></div></form></div>"""
    return web.Response(text=html_page("Login", body), content_type="text/html")


async def web_login_post(request: web.Request) -> web.Response:  # type: ignore[union-attr]
    source = get_client_ip(request)
    async with WEB_LOGIN_LOCK:
        conn = db_connect()
        try:
            row = conn.execute("SELECT failures,first_seen,blocked_until FROM login_failures WHERE source=?", (source,)).fetchone()
            now = time.time()
            if row and row[2] > now:
                return web.Response(status=429, text="Too many login failures. Try again later.")
            if row and now - row[1] > LOGIN_WINDOW:
                conn.execute("DELETE FROM login_failures WHERE source=?", (source,))
        finally:
            conn.close()
    data = await request.post()
    username = str(data.get("username", ""))[:200]
    password = str(data.get("password", ""))[:1000]
    if not verify_web_credentials(username, password):
        async with WEB_FAIL_LOCK:
            conn = db_connect()
            try:
                row = conn.execute("SELECT failures,first_seen FROM login_failures WHERE source=?", (source,)).fetchone()
                now = time.time()
                failures = int(row[0]) + 1 if row else 1
                first = float(row[1]) if row else now
                blocked = now + 300 if failures >= LOGIN_MAX_FAILURES else 0
                conn.execute(
                    "INSERT INTO login_failures(source,failures,first_seen,blocked_until) VALUES(?,?,?,?) "
                    "ON CONFLICT(source) DO UPDATE SET failures=excluded.failures,first_seen=excluded.first_seen,blocked_until=excluded.blocked_until",
                    (source, failures, first, blocked),
                )
            finally:
                conn.close()
        return web.Response(status=401, text="Invalid credentials.")
    token = secrets.token_urlsafe(48)
    csrf = secrets.token_urlsafe(24)
    expires = time.time() + SESSION_TTL
    hashed = session_hash(token)
    WEB_SESSIONS[hashed] = WebSession(username, csrf, expires)
    conn = db_connect()
    try:
        conn.execute("INSERT INTO sessions(token_hash,username,expires_at,csrf,created_at,last_seen) VALUES(?,?,?,?,?,?)", (hashed, username, expires, csrf, now_iso(), time.time()))
        conn.execute("DELETE FROM login_failures WHERE source=?", (source,))
    finally:
        conn.close()
    db_audit(username, "web-login", source)
    response = web.HTTPFound("/")
    response.set_cookie("rgnodes_session", token, max_age=SESSION_TTL, httponly=True, secure=COOKIE_SECURE, samesite="Lax", path="/")
    return response


async def web_logout(request: web.Request) -> web.Response:  # type: ignore[union-attr]
    session = get_session(request)
    data = await request.post()
    if session and not hmac.compare_digest(str(data.get("csrf", "")), session.csrf):
        return web.Response(status=403, text="CSRF validation failed.")
    token = request.cookies.get("rgnodes_session", "")
    if token:
        hashed = session_hash(token)
        WEB_SESSIONS.pop(hashed, None)
        conn = db_connect()
        try:
            conn.execute("DELETE FROM sessions WHERE token_hash=?", (hashed,))
        finally:
            conn.close()
    response = web.HTTPFound("/login")
    response.del_cookie("rgnodes_session", path="/")
    return response


async def web_index(request: web.Request) -> web.Response:  # type: ignore[union-attr]
    session = await web_require_auth(request)
    if isinstance(session, web.Response):
        return session
    rows = db_get_vms()
    cards = []
    for vm in rows:
        badge = "suspended" if vm["suspended"] else ("running" if vm["status"] == "running" else "stopped")
        cards.append(
            f"<div class='card'><div class='top'><div><h2>#{vm['id']} • {html.escape(vm['name'])}</h2><span class='badge {badge}'>{html.escape(vm['status'])}</span> <span class='badge'>{html.escape(vm['backend'].upper())}</span></div><div class='muted mono'>{html.escape(vm['domain'])}</div></div>"
            f"<div class='grid'><div><div>Owner <b>{vm['owner_id']}</b></div><div>OS <b>{html.escape(os_label(vm['os_type']))}</b></div><div>Bootstrap <b>{html.escape(vm['bootstrap_status'])}</b></div><div>Bootstrap info <b>{html.escape(vm['bootstrap_message'] or '')}</b></div><div>RAM <b>{html.escape(vm['ram'])}</b></div><div>vCPU <b>{vm['vcpu']}</b></div><div>Disk <b>{html.escape(vm['disk'])}</b></div><div>IP <b>{html.escape(vm['ip_address'] or 'N/A')}</b></div><div>Abuse score <b>{vm['abuse_score']}</b></div></div>"
            f"<div class='row'><button onclick=act({vm['id']},'start')>Start</button><button onclick=act({vm['id']},'stop')>Stop</button><button onclick=act({vm['id']},'restart')>Restart</button><button class='danger' onclick=act({vm['id']},'delete')>Delete</button></div></div>"
            f"<div class='row'><button onclick=info({vm['id']})>Refresh stats</button><button onclick=logs({vm['id']})>Logs</button><button onclick=files({vm['id']})>Files</button></div><pre id='out-{vm['id']}'>Ready.</pre></div>"
        )
    if not cards:
        cards = ["<div class='card'><div class='muted'>No VMs yet.</div></div>"]
    body = "<div class='card'><h2>Create VM</h2><div class='grid'><div><label>OS</label><select id='os'><option>ubuntu-24.04</option><option>ubuntu-22.04</option><option>debian-12</option><option>debian-11</option><option>rocky-9</option><option>alma-9</option><option>windows-11</option></select><label>Name</label><input id='name' placeholder='rgnodes-vm'></div><div><label>RAM</label><input id='ram' value='4G'><label>vCPU</label><input id='cpu' value='2'><label>Disk</label><input id='disk' value='20G'></div><div><label>Backend</label><select id='backend'><option value='auto'>Auto</option><option value='kvm'>KVM</option><option value='qemu'>QEMU</option><option value='docker'>Docker</option></select><button class='good' style='margin-top:28px' onclick='createVm()'>Create VM</button></div></div></div>" + "".join(cards)
    script = f"const CSRF={json.dumps(session.csrf)};async function api(u,o={{}}){{o.headers=Object.assign({{'X-CSRF-Token':CSRF,'Content-Type':'application/json'}},o.headers||{{}});const r=await fetch(u,o);let t=await r.text();try{{t=JSON.parse(t)}}catch{{}};if(!r.ok)throw new Error(typeof t==='string'?t:(t.error||'request failed'));return t}}async function act(id,a){{try{{const x=await api('/api/vm/'+id+'/'+a,{{method:'POST',body:'{{}}'}});document.getElementById('out-'+id).textContent=JSON.stringify(x,null,2);setTimeout(()=>location.reload(),700)}}catch(e){{document.getElementById('out-'+id).textContent=e.message}}}}async function info(id){{try{{const x=await api('/api/vm/'+id+'/stats',{{method:'POST',body:'{{}}'}});document.getElementById('out-'+id).textContent=JSON.stringify(x,null,2)}}catch(e){{document.getElementById('out-'+id).textContent=e.message}}}}async function logs(id){{try{{const x=await api('/api/vm/'+id+'/logs',{{method:'POST',body:'{{}}'}});document.getElementById('out-'+id).textContent=x.logs||JSON.stringify(x,null,2)}}catch(e){{document.getElementById('out-'+id).textContent=e.message}}}}async function files(id){{try{{const x=await api('/api/vm/'+id+'/files',{{method:'POST',body:'{{}}'}});document.getElementById('out-'+id).textContent=JSON.stringify(x,null,2)}}catch(e){{document.getElementById('out-'+id).textContent=e.message}}}}async function createVm(){{const p={{os:document.getElementById('os').value,name:document.getElementById('name').value,ram:document.getElementById('ram').value,cpu:document.getElementById('cpu').value,disk:document.getElementById('disk').value,backend:document.getElementById('backend').value}};try{{alert(JSON.stringify(await api('/api/vm',{{method:'POST',body:JSON.stringify(p)}})));location.reload()}}catch(e){{alert(e.message)}}}}document.getElementById('logoutcsrf')?.setAttribute('value',CSRF);"
    return web.Response(text=html_page("Dashboard", body, script, True), content_type="text/html")


def safe_vm_file_path(vm: sqlite3.Row, requested: str) -> Path:
    base = (KVM_STORAGE / f"rgnodes-vm-{int(vm['id'])}" / "files").resolve()
    base.mkdir(parents=True, exist_ok=True)
    rel = str(requested or "").replace("\\", "/").lstrip("/")
    target = (base / rel).resolve()
    if target != base and base not in target.parents:
        raise ValueError("Unsafe file path")
    return target

async def web_api_vm_files(request: web.Request) -> web.Response:  # type: ignore[union-attr]
    session = await web_require_auth(request)
    if isinstance(session, web.Response):
        return session
    if not csrf_valid(request, session):
        return web.json_response({"error": "CSRF validation failed"}, status=403)
    vm = db_get_vm(int(request.match_info["id"]))
    if not vm:
        return web.json_response({"error": "VM not found"}, status=404)
    try:
        base = safe_vm_file_path(vm, "")
        items = []
        for child in sorted(base.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
            items.append({"name": child.name, "directory": child.is_dir(), "size": child.stat().st_size if child.is_file() else 0})
        return web.json_response({"vm_id": int(vm["id"]), "path": "", "items": items})
    except OSError as exc:
        return web.json_response({"error": clean(exc, 500)}, status=500)

async def web_api_vm_file_put(request: web.Request) -> web.Response:  # type: ignore[union-attr]
    session = await web_require_auth(request)
    if isinstance(session, web.Response):
        return session
    if not csrf_valid(request, session):
        return web.json_response({"error": "CSRF validation failed"}, status=403)
    vm = db_get_vm(int(request.match_info["id"]))
    if not vm:
        return web.json_response({"error": "VM not found"}, status=404)
    data = await request.json()
    name = str(data.get("name", "")).strip()
    content = str(data.get("content", ""))
    if not name or len(name) > 180 or len(content.encode("utf-8")) > 512 * 1024:
        return web.json_response({"error": "Invalid filename or file too large"}, status=400)
    try:
        path = safe_vm_file_path(vm, name)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and not path.is_file():
            return web.json_response({"error": "Target is not a file"}, status=400)
        path.write_text(content, encoding="utf-8")
        db_audit(session.username, "file-write", str(vm["id"]), name)
        return web.json_response({"ok": True, "path": str(path.relative_to((KVM_STORAGE / f"rgnodes-vm-{vm['id']}" / 'files').resolve()))})
    except (OSError, ValueError) as exc:
        return web.json_response({"error": clean(exc, 500)}, status=400)

async def web_api_vm_file_delete(request: web.Request) -> web.Response:  # type: ignore[union-attr]
    session = await web_require_auth(request)
    if isinstance(session, web.Response):
        return session
    if not csrf_valid(request, session):
        return web.json_response({"error": "CSRF validation failed"}, status=403)
    vm = db_get_vm(int(request.match_info["id"]))
    if not vm:
        return web.json_response({"error": "VM not found"}, status=404)
    try:
        path = safe_vm_file_path(vm, request.query.get("path", ""))
        base = safe_vm_file_path(vm, "")
        if path == base:
            return web.json_response({"error": "Cannot delete file root"}, status=400)
        if path.is_dir():
            for child in sorted(path.rglob("*"), reverse=True):
                if child.is_file() or child.is_symlink(): child.unlink(missing_ok=True)
            for child in sorted(path.rglob("*"), reverse=True):
                if child.is_dir(): child.rmdir()
            path.rmdir()
        elif path.is_file():
            path.unlink()
        else:
            return web.json_response({"error": "File not found"}, status=404)
        db_audit(session.username, "file-delete", str(vm["id"]), request.query.get("path", ""))
        return web.json_response({"ok": True})
    except (OSError, ValueError) as exc:
        return web.json_response({"error": clean(exc, 500)}, status=400)

async def web_api_vm_create(request: web.Request) -> web.Response:  # type: ignore[union-attr]
    session = await web_require_auth(request)
    if isinstance(session, web.Response):
        return session
    if not csrf_valid(request, session):
        return web.json_response({"error": "CSRF validation failed"}, status=403)
    data = await request.json()
    result = await SERVICE.create(ADMIN_ID or 0, session.username, str(data.get("os", "")), str(data.get("ram", DEFAULT_RAM)), str(data.get("cpu", DEFAULT_CPU)), str(data.get("disk", DEFAULT_DISK)), str(data.get("name", "")) or None, str(data.get("backend", "auto")))
    return web.json_response({"ok": result.ok, "message": result.message, "vm_id": result.vm["id"] if result.vm else None}, status=200 if result.ok else 400)


async def web_api_vm_action(request: web.Request) -> web.Response:  # type: ignore[union-attr]
    session = await web_require_auth(request)
    if isinstance(session, web.Response):
        return session
    if not csrf_valid(request, session):
        return web.json_response({"error": "CSRF validation failed"}, status=403)
    vm = db_get_vm(int(request.match_info["id"]))
    if not vm:
        return web.json_response({"error": "VM not found"}, status=404)
    action = request.match_info["action"]
    if action == "stats":
        return web.json_response(await SERVICE.stats(vm))
    if action == "logs":
        if vm["backend"] in {"kvm", "qemu"}:
            text = await SERVICE.backend_for(vm["backend"]).logs(int(vm["id"]))  # type: ignore[union-attr]
        else:
            text = "Docker logs are intentionally not exposed on the public dashboard in this hardened build."
        return web.json_response({"logs": text})
    if action not in {"start", "stop", "restart", "delete"}:
        return web.json_response({"error": "Unsupported action"}, status=400)
    result = await SERVICE.action(vm, action, session.username)
    return web.json_response({"ok": result.ok, "message": result.message}, status=200 if result.ok else 400)


async def web_command(request: web.Request) -> web.Response:  # type: ignore[union-attr]
    session = await web_require_auth(request)
    if isinstance(session, web.Response):
        return session
    if not csrf_valid(request, session):
        return web.json_response({"error": "CSRF validation failed"}, status=403)
    data = await request.json()
    raw = str(data.get("command", "")).strip()
    if len(raw) > 300:
        return web.json_response({"error": "Command too long"}, status=400)
    try:
        parts = shlex.split(raw)
    except ValueError:
        return web.json_response({"error": "Invalid command syntax"}, status=400)
    if not parts:
        return web.json_response({"error": "Command is empty"}, status=400)
    cmd = parts[0].lstrip(PREFIX).lower()
    allowed = {"list", "status", "start", "stop", "restart", "delete", "suspend", "unsuspend"}
    if cmd not in allowed:
        return web.json_response({"error": "Only safe VM management commands are allowed."}, status=400)
    if cmd == "list":
        return web.json_response({"vms": [dict(r) for r in db_get_vms()]})
    if len(parts) < 2 or not parts[1].isdigit():
        return web.json_response({"error": "Usage: command VM_ID"}, status=400)
    vm = db_get_vm(int(parts[1]))
    if not vm:
        return web.json_response({"error": "VM not found"}, status=404)
    if cmd == "status":
        return web.json_response(dict(await SERVICE.refresh_state(vm)))
    if cmd == "suspend":
        result = await SERVICE.suspend(vm, session.username, "manual dashboard suspension")
    elif cmd == "unsuspend":
        result = await SERVICE.unsuspend(vm, session.username)
    else:
        result = await SERVICE.action(vm, cmd, session.username)
    return web.json_response({"ok": result.ok, "message": result.message})


async def start_web_server() -> web.AppRunner | None:  # type: ignore[union-attr]
    if aiohttp is None or web is None:
        logger.error("aiohttp is not installed; dashboard disabled")
        return None
    app = web.Application(client_max_size=1024 * 1024)
    app.router.add_get("/login", web_login_get)
    app.router.add_post("/login", web_login_post)
    app.router.add_post("/logout", web_logout)
    app.router.add_get("/", web_index)
    app.router.add_post("/api/vm", web_api_vm_create)
    app.router.add_post("/api/vm/{id:\\d+}/{action}", web_api_vm_action)
    app.router.add_post("/api/command", web_command)
    app.router.add_get("/health", lambda request: web.json_response({"status": "online", "build": BUILD}))
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, WEB_HOST, WEB_PORT, reuse_address=True)
    await site.start()
    logger.info("RGNODES dashboard online at %s:%s", WEB_HOST, WEB_PORT)
    return runner


# ============================================================================
# Discord bot
# ============================================================================

if commands is not None:
    intents = discord.Intents.default()
    intents.message_content = True

    class RGNODESBot(commands.Bot):
        def __init__(self) -> None:
            super().__init__(command_prefix=PREFIX, intents=intents, help_command=None)

    bot = RGNODESBot()
else:  # pragma: no cover
    bot = None


def is_admin(user_id: int) -> bool:
    return ADMIN_ID > 0 and int(user_id) == ADMIN_ID


def discord_embed(title: str, description: str = ""):
    if discord is None:
        return None
    embed = discord.Embed(title=title, description=description, color=discord.Color.blurple(), timestamp=discord.utils.utcnow())
    embed.set_footer(text="⚡ RGNODES™ • VM Management")
    return embed


async def send_vm_summary(target: Any, vm: sqlite3.Row) -> None:
    vm = await SERVICE.refresh_state(vm)
    stats = await SERVICE.stats(vm)
    embed = discord_embed(
        f"🖥️ VM #{vm['id']} • {vm['name']}",
        f"**{vm['status'].upper()}** • Backend `{vm['backend']}` • OS `{os_label(vm['os_type'])}`",
    )
    embed.add_field(name="Resources", value=f"RAM `{vm['ram']}` • vCPU `{vm['vcpu']}` • Disk `{vm['disk']}`", inline=False)
    embed.add_field(name="Network", value=f"IP `{stats.get('ip','N/A')}`", inline=True)
    embed.add_field(name="Abuse Guard", value=f"Score `{vm['abuse_score']}` • `{clean(vm['abuse_reason'] or 'clear', 300)}`", inline=True)
    await target.send(embed=embed)


if bot is not None:
    @bot.event
    async def on_ready() -> None:
        try:
            if DISCORD_GUILD_ID:
                guild = discord.Object(id=DISCORD_GUILD_ID)
                bot.tree.copy_global_to(guild=guild)
                await bot.tree.sync(guild=guild)
            else:
                await bot.tree.sync()
        except Exception:
            logger.exception("Discord command sync failed")
        await bot.change_presence(activity=discord.Game(name=f"{PREFIX}manage • VM Dashboard"))
        logger.info("Discord ready as %s", bot.user)

    @bot.tree.command(name="myvm", description="Open your newest RGNODES VM dashboard.")
    async def myvm_slash(interaction: discord.Interaction) -> None:
        await manage_slash(interaction, None)

    @bot.tree.command(name="myvps", description="Compatibility alias for myvm.")
    async def myvps_slash(interaction: discord.Interaction) -> None:
        await manage_slash(interaction, None)

    @bot.tree.command(name="vps-info", description="Show VM information.")
    async def vps_info_slash(interaction: discord.Interaction, vm_identifier: str = "") -> None:
        await manage_slash(interaction, vm_identifier)

    @bot.tree.command(name="vps-stats", description="Show live VM statistics.")
    async def vps_stats_slash(interaction: discord.Interaction, vm_identifier: str) -> None:
        await interaction.response.defer(ephemeral=True)
        vm = db_find_vm(vm_identifier, None if is_admin(interaction.user.id) else interaction.user.id)
        if not vm:
            await interaction.followup.send(embed=discord_embed("❌ VM Not Found"), ephemeral=True); return
        await interaction.followup.send(embed=discord_embed("📊 VM Stats", json.dumps(await SERVICE.stats(vm), indent=2)), ephemeral=True)

    @bot.tree.command(name="vps-uptime", description="Show VM uptime/status.")
    async def vps_uptime_slash(interaction: discord.Interaction, vm_identifier: str) -> None:
        await interaction.response.defer(ephemeral=True)
        vm = db_find_vm(vm_identifier, None if is_admin(interaction.user.id) else interaction.user.id)
        if not vm:
            await interaction.followup.send("VM not found.", ephemeral=True); return
        fresh = await SERVICE.refresh_state(vm)
        await interaction.followup.send(embed=discord_embed("⏱️ VM Uptime", f"Status: `{fresh['status']}`"), ephemeral=True)

    @bot.tree.command(name="restart-vps", description="Compatibility alias for restart.")
    async def restart_vps_slash(interaction: discord.Interaction, vm_identifier: str) -> None:
        await vm_action_slash(interaction, vm_identifier, "restart")

    @bot.tree.command(name="console", description="Show VM console information.")
    async def console_slash(interaction: discord.Interaction, vm_identifier: str) -> None:
        await interaction.response.defer(ephemeral=True)
        vm = db_find_vm(vm_identifier, None if is_admin(interaction.user.id) else interaction.user.id)
        if not vm:
            await interaction.followup.send("VM not found.", ephemeral=True); return
        if vm['backend'] in {'kvm','qemu'}:
            await interaction.followup.send(embed=discord_embed("🖥️ VM Console", "Use the authenticated dashboard for console and lifecycle operations. VNC/SPICE remains bound to localhost by design."), ephemeral=True)
        else:
            await interaction.followup.send(embed=discord_embed("🖥️ VM Console", "Console access is backend-dependent. Use the dashboard."), ephemeral=True)

    @bot.tree.command(name="logs", description="View recent VM logs.")
    async def logs_slash(interaction: discord.Interaction, vm_identifier: str) -> None:
        await interaction.response.defer(ephemeral=True)
        vm = db_find_vm(vm_identifier, None if is_admin(interaction.user.id) else interaction.user.id)
        if not vm:
            await interaction.followup.send("VM not found.", ephemeral=True); return
        text = await SERVICE.backend_for(vm['backend']).logs(int(vm['id'])) if vm['backend'] in {'kvm','qemu'} else "Docker logs are available only from the local host/operator environment."
        await interaction.followup.send(embed=discord_embed("📜 VM Logs", f"```text\n{clean(text, 3800)}\n```"), ephemeral=True)

    @bot.tree.command(name="about", description="Show RGNODES VM Manager information.")
    async def about_slash(interaction: discord.Interaction) -> None:
        await interaction.response.send_message(embed=discord_embed("ℹ️ RGNODES™", f"Build: `{BUILD}`\nDashboard: `:{WEB_PORT}`\nPrimary backend: `{choose_backend()}`"), ephemeral=True)

    @bot.tree.command(name="serverstats", description="Show host statistics.")
    async def serverstats_slash(interaction: discord.Interaction) -> None:
        load = os.getloadavg()[0] if hasattr(os, "getloadavg") else 0
        await interaction.response.send_message(embed=discord_embed("📊 Server Statistics", f"OS: `{sys.platform}`\nCPU: `{os.cpu_count() or 1}`\nLoad: `{load:.2f}`\nRunning VMs: `{db_running_count()}`"), ephemeral=True)

    @bot.tree.command(name="thresholds", description="Show resource/security thresholds.")
    async def thresholds_slash(interaction: discord.Interaction) -> None:
        await interaction.response.send_message(embed=discord_embed("📋 Thresholds", f"Per-user VMs: `{SERVER_LIMIT}`\nRunning limit: `{TOTAL_RUNNING_LIMIT}`\nAbuse scan: `{ABUSE_SCAN_INTERVAL}s`\nConnection threshold: `{ABUSE_CONN_THRESHOLD}`"), ephemeral=True)

    @bot.tree.command(name="help", description="Show command help.")
    async def help_slash(interaction: discord.Interaction) -> None:
        await interaction.response.send_message(embed=discord_embed("📚 RGNODES™ Commands", f"`{PREFIX}deploy`, `{PREFIX}manage`, `{PREFIX}start`, `{PREFIX}stop`, `{PREFIX}restart`, `{PREFIX}remove`, `{PREFIX}list`, `{PREFIX}console`, `{PREFIX}vm-command`\nAdmin: `admin-manage`, `admin-ban`, `admin-unban`, `admin-create`, `add-slots`, `remove-all`, `admin-kill-all`"), ephemeral=True)

    @bot.tree.command(name="ports", description="Show VM network/port information.")
    async def ports_slash(interaction: discord.Interaction, vm_identifier: str) -> None:
        await interaction.response.send_message(embed=discord_embed("🔌 Ports", "KVM/QEMU networking is managed by the libvirt network configured for this VM. Host port-forwarding is intentionally not exposed from the public dashboard."), ephemeral=True)

    @bot.tree.command(name="port-add", description="Compatibility command for adding a port mapping.")
    async def port_add_slash(interaction: discord.Interaction, vm_identifier: str, port: int) -> None:
        await interaction.response.send_message(embed=discord_embed("🔌 Port Mapping", "Direct public port forwarding is disabled by default in the hardened KVM build. Configure a trusted libvirt/NAT or reverse proxy rule on the host."), ephemeral=True)

    @bot.tree.command(name="port-remove", description="Compatibility command for removing a port mapping.")
    async def port_remove_slash(interaction: discord.Interaction, port_id: int) -> None:
        await interaction.response.send_message(embed=discord_embed("🔌 Port Mapping", "Port mapping is host-network configuration in this build."), ephemeral=True)

    @bot.tree.command(name="share-user", description="Compatibility VPS sharing command.")
    async def share_user_slash(interaction: discord.Interaction, vm_identifier: str, target_user: discord.User) -> None:
        await interaction.response.send_message(embed=discord_embed("👥 Sharing", "Web dashboard accounts are administrator-scoped in this build; per-VM Discord delegation is intentionally not exposed."), ephemeral=True)

    @bot.tree.command(name="unshare-user", description="Compatibility VPS unshare command.")
    async def unshare_user_slash(interaction: discord.Interaction, vm_identifier: str, target_user: discord.User) -> None:
        await interaction.response.send_message(embed=discord_embed("👥 Sharing", "No change was made."), ephemeral=True)

    @bot.tree.command(name="share-ruser", description="Compatibility alias for unshare-user.")
    async def share_ruser_slash(interaction: discord.Interaction, vm_identifier: str, target_user: discord.User) -> None:
        await unshare_user_slash(interaction, vm_identifier, target_user)

    @bot.tree.command(name="manage-shared", description="Compatibility command for shared VM management.")
    async def manage_shared_slash(interaction: discord.Interaction, vm_identifier: str) -> None:
        await interaction.response.send_message(embed=discord_embed("👥 Shared Access", "Shared access is disabled in the hardened build."), ephemeral=True)

    @bot.tree.command(name="snapshot", description="Create a libvirt snapshot for a VM.")
    async def snapshot_slash(interaction: discord.Interaction, vm_identifier: str, name: str) -> None:
        await interaction.response.defer(ephemeral=True)
        vm = db_find_vm(vm_identifier, None if is_admin(interaction.user.id) else interaction.user.id)
        if not vm or vm['backend'] not in {'kvm','qemu'}:
            await interaction.followup.send("KVM/QEMU VM not found.", ephemeral=True); return
        ok, msg = await KVM.snapshot(int(vm['id']), name) if vm['backend']=='kvm' else await QEMU.snapshot(int(vm['id']), name)
        await interaction.followup.send(embed=discord_embed("✅ Snapshot" if ok else "❌ Snapshot", msg), ephemeral=True)

    @bot.tree.command(name="list-snapshots", description="List VM snapshots.")
    async def list_snapshots_slash(interaction: discord.Interaction, vm_identifier: str) -> None:
        await interaction.response.defer(ephemeral=True)
        vm = db_find_vm(vm_identifier, None if is_admin(interaction.user.id) else interaction.user.id)
        if not vm or vm['backend'] not in {'kvm','qemu'}:
            await interaction.followup.send("KVM/QEMU VM not found.", ephemeral=True); return
        snaps = await (KVM.snapshot_list(int(vm['id'])) if vm['backend']=='kvm' else QEMU.snapshot_list(int(vm['id'])))
        await interaction.followup.send(embed=discord_embed("📸 Snapshots", "\n".join(snaps) or "No snapshots."), ephemeral=True)

    @bot.tree.command(name="restore-snapshot", description="Restore a VM snapshot.")
    async def restore_snapshot_slash(interaction: discord.Interaction, vm_identifier: str, name: str) -> None:
        await interaction.response.defer(ephemeral=True)
        vm = db_find_vm(vm_identifier, None if is_admin(interaction.user.id) else interaction.user.id)
        if not vm or vm['backend'] not in {'kvm','qemu'}:
            await interaction.followup.send("KVM/QEMU VM not found.", ephemeral=True); return
        handler = KVM if vm['backend']=='kvm' else QEMU
        ok, msg = await handler.snapshot_restore(int(vm['id']), name)
        await interaction.followup.send(embed=discord_embed("✅ Snapshot Restored" if ok else "❌ Restore Failed", msg), ephemeral=True)

    @bot.tree.command(name="admin-create", description="Admin: create a VM for another Discord user.")
    async def admin_create_slash(interaction: discord.Interaction, target_user: discord.User, os_type: str, ram: str = DEFAULT_RAM, cpu: str = DEFAULT_CPU, disk: str = DEFAULT_DISK, backend: str = "auto") -> None:
        if not is_admin(interaction.user.id):
            await interaction.response.send_message("Administrator access is required.", ephemeral=True); return
        await interaction.response.defer(ephemeral=True)
        result = await SERVICE.create(target_user.id, str(target_user), os_type, ram, cpu, disk, None, backend)
        await interaction.followup.send(embed=discord_embed("✅ VM Created" if result.ok else "❌ Creation Failed", result.message), ephemeral=True)

    @bot.tree.command(name="add-slots", description="Compatibility command for per-user slots.")
    async def add_slots_slash(interaction: discord.Interaction, target_user: discord.User, amount: int = 1) -> None:
        if not is_admin(interaction.user.id):
            await interaction.response.send_message("Administrator access is required.", ephemeral=True); return
        await interaction.response.send_message(embed=discord_embed("🎟️ Slots", "The current DB uses SERVER_LIMIT as the per-user cap. Adjust SERVER_LIMIT in `.env` for this build."), ephemeral=True)

    @bot.tree.command(name="admin-list", description="Admin: list all VMs.")
    async def admin_list_slash(interaction: discord.Interaction) -> None:
        if not is_admin(interaction.user.id):
            await interaction.response.send_message("Administrator access is required.", ephemeral=True); return
        rows=db_get_vms(); text="\n".join(f"#{r['id']} {r['name']} • {r['backend']} • {r['status']}" for r in rows[:50]) or "No VMs."
        await interaction.response.send_message(embed=discord_embed("🗂️ Admin • All VMs", text), ephemeral=True)

    @bot.tree.command(name="admin-delete-user", description="Admin: delete a VM belonging to a user.")
    async def admin_delete_user_slash(interaction: discord.Interaction, target_user: discord.User, vm_identifier: str) -> None:
        if not is_admin(interaction.user.id):
            await interaction.response.send_message("Administrator access is required.", ephemeral=True); return
        await interaction.response.defer(ephemeral=True)
        vm=db_find_vm(vm_identifier,target_user.id)
        if not vm:
            await interaction.followup.send("VM not found.",ephemeral=True); return
        result=await SERVICE.action(vm,"delete",str(interaction.user.id))
        await interaction.followup.send(embed=discord_embed("✅ Deleted" if result.ok else "❌ Failed",result.message),ephemeral=True)

    @bot.tree.command(name="admin-list-users", description="Admin: list users and VM counts.")
    async def admin_list_users_slash(interaction: discord.Interaction) -> None:
        if not is_admin(interaction.user.id):
            await interaction.response.send_message("Administrator access is required.", ephemeral=True); return
        rows=db_get_vms(); owners={}
        for r in rows: owners[int(r['owner_id'])]=owners.get(int(r['owner_id']),0)+1
        text="\n".join(f"<@{uid}> • {count} VM(s)" for uid,count in sorted(owners.items(),key=lambda x:-x[1])) or "No users."
        await interaction.response.send_message(embed=discord_embed("👥 Admin • Users",text),ephemeral=True)

    @bot.tree.command(name="admin-stats", description="Admin: show VM statistics.")
    async def admin_stats_slash(interaction: discord.Interaction) -> None:
        if not is_admin(interaction.user.id):
            await interaction.response.send_message("Administrator access is required.", ephemeral=True); return
        await interaction.response.send_message(embed=discord_embed("📊 Admin • Statistics",f"VMs: `{len(db_get_vms())}`\nRunning: `{db_running_count()}`\nKVM available: `{detect_kvm()}`"),ephemeral=True)

    @bot.tree.command(name="admin-vps-info", description="Admin: inspect one VM.")
    async def admin_vps_info_slash(interaction: discord.Interaction, vm_id: int) -> None:
        if not is_admin(interaction.user.id):
            await interaction.response.send_message("Administrator access is required.", ephemeral=True); return
        vm=db_get_vm(vm_id)
        await interaction.response.send_message(embed=discord_embed("🖥️ Admin VM Info",json.dumps(dict(vm),indent=2) if vm else "VM not found."),ephemeral=True)

    @bot.tree.command(name="admin-logs", description="Admin: inspect VM logs.")
    async def admin_logs_slash(interaction: discord.Interaction, vm_id: int) -> None:
        if not is_admin(interaction.user.id):
            await interaction.response.send_message("Administrator access is required.", ephemeral=True); return
        vm=db_get_vm(vm_id)
        if not vm: await interaction.response.send_message("VM not found.",ephemeral=True); return
        text=await SERVICE.backend_for(vm['backend']).logs(vm_id) if vm['backend'] in {'kvm','qemu'} else "Not available."
        await interaction.response.send_message(embed=discord_embed("📜 Admin Logs",f"```text\n{clean(text,3800)}\n```"),ephemeral=True)

    @bot.tree.command(name="admin-kill-all", description="Admin: stop all running VMs.")
    async def admin_kill_all_slash(interaction: discord.Interaction) -> None:
        if not is_admin(interaction.user.id):
            await interaction.response.send_message("Administrator access is required.",ephemeral=True); return
        await interaction.response.defer(ephemeral=True)
        stopped=0
        for vm in db_get_vms():
            if vm['status']=='running':
                r=await SERVICE.action(vm,'stop',str(interaction.user.id)); stopped += int(r.ok)
        await interaction.followup.send(embed=discord_embed("🛑 Kill All",f"Stopped `{stopped}` VM(s)."),ephemeral=True)

    @bot.tree.command(name="remove-all", description="Admin: delete every managed VM.")
    async def remove_all_slash(interaction: discord.Interaction, confirm: bool = False) -> None:
        if not is_admin(interaction.user.id):
            await interaction.response.send_message("Administrator access is required.",ephemeral=True); return
        if not confirm:
            await interaction.response.send_message("Set `confirm:true` to permanently delete all managed VMs.",ephemeral=True); return
        await interaction.response.defer(ephemeral=True)
        removed=0
        for vm in list(db_get_vms()):
            r=await SERVICE.action(vm,'delete',str(interaction.user.id)); removed += int(r.ok)
        await interaction.followup.send(embed=discord_embed("✅ Remove All",f"Removed `{removed}` VM(s)."),ephemeral=True)

    @bot.tree.command(name="set-status", description="Admin: set Discord bot presence.")
    async def set_status_slash(interaction: discord.Interaction, status_type: str, name: str) -> None:
        if not is_admin(interaction.user.id):
            await interaction.response.send_message("Administrator access is required.",ephemeral=True); return
        kind=status_type.lower()
        activity=discord.Game(name=name) if kind=='playing' else discord.Activity(type=getattr(discord.ActivityType,kind,discord.ActivityType.playing),name=name)
        await bot.change_presence(activity=activity)
        await interaction.response.send_message(embed=discord_embed("✅ Status Updated",f"`{kind}` • `{name}`"),ephemeral=True)

    @bot.tree.command(name="install-system", description="Admin: install required host virtualization/runtime packages.")
    async def install_system_slash(interaction: discord.Interaction, confirm: bool = False) -> None:
        if not is_admin(interaction.user.id):
            await interaction.response.send_message("Administrator access is required.",ephemeral=True); return
        if not confirm:
            await interaction.response.send_message("Set `confirm:true` to run the host dependency installer.",ephemeral=True); return
        await interaction.response.defer(ephemeral=True)
        ok,msg=await install_host_dependencies()
        await interaction.followup.send(embed=discord_embed("✅ Host Bootstrap" if ok else "⚠️ Host Bootstrap",msg),ephemeral=True)

    @bot.tree.command(name="ping", description="Check bot latency.")
    async def ping_slash(interaction: discord.Interaction) -> None:
        await interaction.response.send_message(embed=discord_embed("🏓 Pong", f"Latency: `{round(bot.latency*1000)}ms`"), ephemeral=True)

    @bot.tree.command(name="start", description="Start a VM.")
    async def start_slash(interaction: discord.Interaction, vm_identifier: str) -> None:
        await vm_action_slash(interaction, vm_identifier, "start")

    @bot.tree.command(name="stop", description="Stop a VM.")
    async def stop_slash(interaction: discord.Interaction, vm_identifier: str) -> None:
        await vm_action_slash(interaction, vm_identifier, "stop")

    @bot.tree.command(name="restart", description="Restart a VM.")
    async def restart_slash(interaction: discord.Interaction, vm_identifier: str) -> None:
        await vm_action_slash(interaction, vm_identifier, "restart")

    @bot.tree.command(name="remove", description="Delete a VM.")
    async def remove_slash(interaction: discord.Interaction, vm_identifier: str) -> None:
        await vm_action_slash(interaction, vm_identifier, "delete")

    @bot.tree.command(name="sshx", description="Compatibility alias for secure console access.")
    async def sshx_slash(interaction: discord.Interaction, vm_identifier: str) -> None:
        await console_slash(interaction, vm_identifier)

    @bot.tree.command(name="deploy", description="Create a new RGNODES VM.")
    @app_commands.describe(os_type="Guest OS", ram="RAM e.g. 4G", cpu="vCPU count", disk="Disk e.g. 20G", backend="auto/kvm/qemu/docker", name="VM name")
    async def deploy_slash(interaction: discord.Interaction, os_type: str, ram: str = DEFAULT_RAM, cpu: str = DEFAULT_CPU, disk: str = DEFAULT_DISK, backend: str = "auto", name: str = "") -> None:
        await interaction.response.defer(ephemeral=True)
        result = await SERVICE.create(interaction.user.id, str(interaction.user), os_type, ram, cpu, disk, name or None, backend)
        if result.ok and result.vm:
            await send_vm_summary(interaction.followup, result.vm)
        else:
            await interaction.followup.send(embed=discord_embed("❌ VM Creation Failed", result.message), ephemeral=True)

    @bot.tree.command(name="manage", description="Manage one of your VMs.")
    async def manage_slash(interaction: discord.Interaction, vm_identifier: str = "") -> None:
        await interaction.response.defer(ephemeral=True)
        vm = db_find_vm(vm_identifier, None if is_admin(interaction.user.id) else interaction.user.id)
        if not vm:
            await interaction.followup.send(embed=discord_embed("❌ VM Not Found", "No matching VM was found."), ephemeral=True)
            return
        await send_vm_summary(interaction.followup, vm)

    @bot.tree.command(name="vm-action", description="Start/stop/restart/delete one of your VMs.")
    @app_commands.choices(action=[app_commands.Choice(name=x.title(), value=x) for x in ("start", "stop", "restart", "delete")])
    async def vm_action_slash(interaction: discord.Interaction, vm_identifier: str, action: str) -> None:
        await interaction.response.defer(ephemeral=True)
        vm = db_find_vm(vm_identifier, None if is_admin(interaction.user.id) else interaction.user.id)
        if not vm:
            await interaction.followup.send(embed=discord_embed("❌ VM Not Found"), ephemeral=True)
            return
        result = await SERVICE.action(vm, action, str(interaction.user.id))
        await interaction.followup.send(embed=discord_embed("✅ Done" if result.ok else "❌ Failed", result.message), ephemeral=True)

    @bot.tree.command(name="list", description="List your VMs.")
    async def list_slash(interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)
        rows = db_get_vms(None if is_admin(interaction.user.id) else interaction.user.id)
        embed = discord_embed("📋 RGNODES™ • VMs", "")
        if not rows:
            embed.description = "No VMs found."
        for vm in rows[:25]:
            embed.add_field(name=f"#{vm['id']} • {vm['name']}", value=f"`{vm['status']}` • `{vm['backend']}` • `{os_label(vm['os_type'])}` • `{vm['ram']}` / `{vm['vcpu']}vCPU` / `{vm['disk']}`", inline=False)
        await interaction.followup.send(embed=embed, ephemeral=True)

    @bot.tree.command(name="admin-ban", description="Admin: block VM creation for a user.")
    async def admin_ban_slash(interaction: discord.Interaction, target_user: discord.User, reason: str = "policy violation") -> None:
        if not is_admin(interaction.user.id):
            await interaction.response.send_message("Administrator access is required.", ephemeral=True)
            return
        db_set_ban(target_user.id, True, reason)
        db_audit(str(interaction.user.id), "ban", str(target_user.id), reason)
        await interaction.response.send_message(embed=discord_embed("✅ User Banned", f"<@{target_user.id}> cannot create VMs."), ephemeral=True)

    @bot.tree.command(name="admin-unban", description="Admin: restore VM creation for a user.")
    async def admin_unban_slash(interaction: discord.Interaction, target_user: discord.User) -> None:
        if not is_admin(interaction.user.id):
            await interaction.response.send_message("Administrator access is required.", ephemeral=True)
            return
        db_set_ban(target_user.id, False)
        db_audit(str(interaction.user.id), "unban", str(target_user.id))
        await interaction.response.send_message(embed=discord_embed("✅ User Unbanned", f"<@{target_user.id}> may create VMs again."), ephemeral=True)

    @bot.tree.command(name="admin-manage", description="Admin: control any VM.")
    @app_commands.choices(action=[app_commands.Choice(name=x.title(), value=x) for x in ("start", "stop", "restart", "delete", "suspend", "unsuspend")])
    async def admin_manage_slash(interaction: discord.Interaction, vm_id: int, action: str) -> None:
        if not is_admin(interaction.user.id):
            await interaction.response.send_message("Administrator access is required.", ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True)
        vm = db_get_vm(vm_id)
        if not vm:
            await interaction.followup.send("VM not found.", ephemeral=True)
            return
        if action == "suspend":
            result = await SERVICE.suspend(vm, str(interaction.user.id), "admin suspension")
        elif action == "unsuspend":
            result = await SERVICE.unsuspend(vm, str(interaction.user.id))
        else:
            result = await SERVICE.action(vm, action, str(interaction.user.id))
        await interaction.followup.send(embed=discord_embed("✅ Done" if result.ok else "❌ Failed", result.message), ephemeral=True)

    @bot.command(name="ping")
    async def prefix_ping(ctx: commands.Context) -> None:
        await ctx.send(embed=discord_embed("🏓 Pong", f"Latency: `{round(bot.latency*1000)}ms`"))

    @bot.command(name="about")
    async def prefix_about(ctx: commands.Context) -> None:
        await ctx.send(embed=discord_embed("ℹ️ RGNODES™", f"Build: `{BUILD}` • Dashboard `:{WEB_PORT}` • Backend `{choose_backend()}`"))

    @bot.command(name="uptime", aliases=["vps-uptime"])
    async def prefix_uptime(ctx: commands.Context, vm_identifier: str = "") -> None:
        vm=db_find_vm(vm_identifier,None if is_admin(ctx.author.id) else ctx.author.id)
        if not vm: await ctx.send(embed=discord_embed("❌ VM Not Found")); return
        vm=await SERVICE.refresh_state(vm)
        await ctx.send(embed=discord_embed("⏱️ VM Status",f"`{vm['status']}` • `{vm['backend']}`"))

    @bot.command(name="vpsinfo", aliases=["vps-info"])
    async def prefix_vpsinfo(ctx: commands.Context, vm_identifier: str = "") -> None:
        vm=db_find_vm(vm_identifier,None if is_admin(ctx.author.id) else ctx.author.id)
        await ctx.send(embed=discord_embed("🖥️ VM Info",json.dumps(dict(vm),indent=2) if vm else "VM not found."))

    @bot.command(name="vps-stats")
    async def prefix_vps_stats(ctx: commands.Context, vm_identifier: str = "") -> None:
        vm=db_find_vm(vm_identifier,None if is_admin(ctx.author.id) else ctx.author.id)
        if not vm: await ctx.send(embed=discord_embed("❌ VM Not Found")); return
        await ctx.send(embed=discord_embed("📊 VM Stats",json.dumps(await SERVICE.stats(vm),indent=2)))

    @bot.command(name="restart-vps")
    async def prefix_restart_vps(ctx: commands.Context, vm_identifier: str = "") -> None:
        await prefix_action(ctx,vm_identifier,"restart")

    @bot.command(name="console")
    async def prefix_console(ctx: commands.Context, vm_identifier: str = "") -> None:
        vm=db_find_vm(vm_identifier,None if is_admin(ctx.author.id) else ctx.author.id)
        await ctx.send(embed=discord_embed("🖥️ VM Console","Use the authenticated dashboard for secure console/lifecycle management." if vm else "VM not found."))

    @bot.command(name="logs")
    async def prefix_logs(ctx: commands.Context, vm_identifier: str = "") -> None:
        vm=db_find_vm(vm_identifier,None if is_admin(ctx.author.id) else ctx.author.id)
        if not vm: await ctx.send(embed=discord_embed("❌ VM Not Found")); return
        text=await SERVICE.backend_for(vm['backend']).logs(int(vm['id'])) if vm['backend'] in {'kvm','qemu'} else "Logs unavailable."
        await ctx.send(embed=discord_embed("📜 VM Logs",f"```text\n{clean(text,3800)}\n```"))

    @bot.command(name="help")
    async def prefix_help(ctx: commands.Context) -> None:
        await ctx.send(embed=discord_embed("📚 RGNODES™ Commands",f"`{PREFIX}deploy`, `{PREFIX}manage`, `{PREFIX}list`, `{PREFIX}start`, `{PREFIX}stop`, `{PREFIX}restart`, `{PREFIX}remove`, `{PREFIX}console`, `{PREFIX}logs`, `{PREFIX}ports`, `{PREFIX}vm-command`\nAdmin commands remain available."))

    @bot.command(name="snapshot")
    async def prefix_snapshot(ctx: commands.Context, vm_identifier: str = "", name: str = "snapshot") -> None:
        vm=db_find_vm(vm_identifier,None if is_admin(ctx.author.id) else ctx.author.id)
        if not vm or vm['backend'] not in {'kvm','qemu'}:
            await ctx.send("KVM/QEMU VM not found."); return
        handler=KVM if vm['backend']=='kvm' else QEMU
        ok,msg=await handler.snapshot(int(vm['id']),name)
        await ctx.send(embed=discord_embed("✅ Snapshot" if ok else "❌ Snapshot",msg))

    @bot.command(name="list-snapshots")
    async def prefix_list_snapshots(ctx: commands.Context, vm_identifier: str = "") -> None:
        vm=db_find_vm(vm_identifier,None if is_admin(ctx.author.id) else ctx.author.id)
        if not vm or vm['backend'] not in {'kvm','qemu'}: await ctx.send("KVM/QEMU VM not found."); return
        handler=KVM if vm['backend']=='kvm' else QEMU
        snaps=await handler.snapshot_list(int(vm['id']))
        await ctx.send(embed=discord_embed("📸 Snapshots","\n".join(snaps) or "No snapshots."))

    @bot.command(name="restore-snapshot")
    async def prefix_restore_snapshot(ctx: commands.Context, vm_identifier: str, name: str) -> None:
        vm=db_find_vm(vm_identifier,None if is_admin(ctx.author.id) else ctx.author.id)
        if not vm or vm['backend'] not in {'kvm','qemu'}: await ctx.send("KVM/QEMU VM not found."); return
        handler=KVM if vm['backend']=='kvm' else QEMU
        ok,msg=await handler.snapshot_restore(int(vm['id']),name)
        await ctx.send(embed=discord_embed("✅ Restored" if ok else "❌ Restore Failed",msg))

    @bot.command(name="ports")
    async def prefix_ports(ctx: commands.Context, vm_identifier: str = "") -> None:
        await ctx.send(embed=discord_embed("🔌 Ports","Use the libvirt network or reverse proxy configured on the host. Public arbitrary forwarding is disabled by default."))

    @bot.command(name="serverstats")
    async def prefix_serverstats(ctx: commands.Context) -> None:
        load=os.getloadavg()[0] if hasattr(os,'getloadavg') else 0
        await ctx.send(embed=discord_embed("📊 Server Statistics",f"CPU: `{os.cpu_count() or 1}` • Load: `{load:.2f}` • Running: `{db_running_count()}` • KVM: `{detect_kvm()}`"))

    @bot.command(name="thresholds")
    async def prefix_thresholds(ctx: commands.Context) -> None:
        await ctx.send(embed=discord_embed("📋 Thresholds",f"Per-user VM limit: `{SERVER_LIMIT}` • Running limit: `{TOTAL_RUNNING_LIMIT}` • Abuse interval: `{ABUSE_SCAN_INTERVAL}s`"))

    @bot.command(name="set-status")
    async def prefix_set_status(ctx: commands.Context, status_type: str, *, name: str) -> None:
        if not is_admin(ctx.author.id): await ctx.send("Administrator access is required."); return
        activity=discord.Game(name=name) if status_type.lower()=='playing' else discord.Activity(type=getattr(discord.ActivityType,status_type.lower(),discord.ActivityType.playing),name=name)
        await bot.change_presence(activity=activity)
        await ctx.send(embed=discord_embed("✅ Status Updated",f"`{status_type}` • `{name}`"))

    @bot.command(name="share-user")
    async def prefix_share_user(ctx: commands.Context, target_user: discord.User, vm_identifier: str) -> None:
        await ctx.send(embed=discord_embed("👥 Sharing","Shared Discord access is disabled in the hardened build."))

    @bot.command(name="share-ruser", aliases=["unshare-user"])
    async def prefix_share_ruser(ctx: commands.Context, target_user: discord.User, vm_identifier: str) -> None:
        await ctx.send(embed=discord_embed("👥 Sharing","No change was made."))

    @bot.command(name="manage-shared")
    async def prefix_manage_shared(ctx: commands.Context, vm_identifier: str = "") -> None:
        await ctx.send(embed=discord_embed("👥 Shared Access","Shared access is disabled in the hardened build."))

    @bot.command(name="admin-list")
    async def prefix_admin_list(ctx: commands.Context) -> None:
        if not is_admin(ctx.author.id): await ctx.send("Administrator access is required."); return
        text="\n".join(f"#{v['id']} {v['name']} • {v['backend']} • {v['status']}" for v in db_get_vms()[:50]) or "No VMs."
        await ctx.send(embed=discord_embed("🗂️ Admin • All VMs",text))

    @bot.command(name="admin-stats")
    async def prefix_admin_stats(ctx: commands.Context) -> None:
        if not is_admin(ctx.author.id): await ctx.send("Administrator access is required."); return
        await ctx.send(embed=discord_embed("📊 Admin • Stats",f"VMs: `{len(db_get_vms())}` • Running: `{db_running_count()}` • KVM: `{detect_kvm()}`"))

    @bot.command(name="admin-ban")
    async def prefix_admin_ban(ctx: commands.Context, target_user: discord.User, *, reason: str = "policy violation") -> None:
        if not is_admin(ctx.author.id): await ctx.send("Administrator access is required."); return
        db_set_ban(target_user.id,True,reason); db_audit(str(ctx.author.id),'ban',str(target_user.id),reason)
        await ctx.send(embed=discord_embed("✅ User Banned",f"<@{target_user.id}>: `{reason}`"))

    @bot.command(name="admin-unban")
    async def prefix_admin_unban(ctx: commands.Context, target_user: discord.User) -> None:
        if not is_admin(ctx.author.id): await ctx.send("Administrator access is required."); return
        db_set_ban(target_user.id,False); db_audit(str(ctx.author.id),'unban',str(target_user.id))
        await ctx.send(embed=discord_embed("✅ User Unbanned",f"<@{target_user.id}> may create VMs again."))

    @bot.command(name="deploy")
    async def prefix_deploy(ctx: commands.Context, os_type: str | None = None, ram: str = DEFAULT_RAM, cpu: str = DEFAULT_CPU, disk: str = DEFAULT_DISK, backend: str = "auto", *, name: str = "") -> None:
        if not os_type:
            await ctx.send(embed=discord_embed("🚀 Deploy VM", f"Usage: `{PREFIX}deploy <os> [ram] [cpu] [disk] [backend] [name]`\nExample: `{PREFIX}deploy ubuntu-24.04 4G 2 20G kvm my-vm`"))
            return
        msg = await ctx.send(embed=discord_embed("⏳ Creating VM", "Provisioning safely; this may take a little time."))
        result = await SERVICE.create(ctx.author.id, str(ctx.author), os_type, ram, cpu, disk, name or None, backend)
        if result.ok and result.vm:
            await msg.edit(embed=discord_embed("✅ VM Ready", result.message))
            await send_vm_summary(ctx, result.vm)
        else:
            await msg.edit(embed=discord_embed("❌ VM Creation Failed", result.message))

    @bot.command(name="manage", aliases=["myvps", "myvm"])
    async def prefix_manage(ctx: commands.Context, vm_identifier: str = "") -> None:
        vm = db_find_vm(vm_identifier, None if is_admin(ctx.author.id) else ctx.author.id)
        if not vm:
            await ctx.send(embed=discord_embed("❌ VM Not Found", f"Use `{PREFIX}list` to see your VMs."))
            return
        await send_vm_summary(ctx, vm)

    @bot.command(name="list")
    async def prefix_list(ctx: commands.Context) -> None:
        rows = db_get_vms(None if is_admin(ctx.author.id) else ctx.author.id)
        text = "\n".join(f"#{r['id']} • `{r['status']}` • `{r['backend']}` • {r['name']}" for r in rows[:25]) or "No VMs found."
        await ctx.send(embed=discord_embed("📋 RGNODES™ • VMs", text))

    @bot.command(name="start")
    async def prefix_start(ctx: commands.Context, vm_identifier: str = "") -> None:
        await prefix_action(ctx, vm_identifier, "start")

    @bot.command(name="stop")
    async def prefix_stop(ctx: commands.Context, vm_identifier: str = "") -> None:
        await prefix_action(ctx, vm_identifier, "stop")

    @bot.command(name="restart")
    async def prefix_restart(ctx: commands.Context, vm_identifier: str = "") -> None:
        await prefix_action(ctx, vm_identifier, "restart")

    @bot.command(name="remove")
    async def prefix_remove(ctx: commands.Context, vm_identifier: str = "") -> None:
        await prefix_action(ctx, vm_identifier, "delete")

    @bot.command(name="vm-command")
    async def prefix_vm_command(ctx: commands.Context, *, command_text: str) -> None:
        if not is_admin(ctx.author.id):
            await ctx.send(embed=discord_embed("❌ Permission Denied", "Administrator access is required for the VM command console."))
            return
        parts = shlex.split(command_text)
        if not parts:
            await ctx.send(f"Usage: `{PREFIX}vm-command status <vmid>`")
            return
        action = parts[0].lower()
        if action == "status" and len(parts) >= 2 and parts[1].isdigit():
            vm = db_get_vm(int(parts[1]))
            if not vm:
                await ctx.send("VM not found.")
                return
            data = await SERVICE.stats(vm)
            await ctx.send(f"```json\n{json.dumps(data, indent=2)}\n```")
            return
        await ctx.send(embed=discord_embed("❌ Invalid Command", "Only safe management actions are supported. No arbitrary host shell commands are exposed."))

    async def prefix_action(ctx: commands.Context, identifier: str, action: str) -> None:
        vm = db_find_vm(identifier, None if is_admin(ctx.author.id) else ctx.author.id)
        if not vm:
            await ctx.send(embed=discord_embed("❌ VM Not Found"))
            return
        result = await SERVICE.action(vm, action, str(ctx.author.id))
        await ctx.send(embed=discord_embed("✅ Done" if result.ok else "❌ Failed", result.message))

else:
    prefix_action = None  # pragma: no cover


async def system_cmd(*args: str, timeout: float = 180.0) -> tuple[int, str, str]:
    return await run_process(*args, timeout=timeout)


async def install_host_dependencies() -> tuple[bool, str]:
    """Best-effort Debian/Ubuntu host bootstrap for VM dependencies.
    This never executes arbitrary user-supplied package names or commands.
    """
    if not sys.platform.startswith('linux'):
        return False, 'Automatic host bootstrap is supported only on Linux.'
    if hasattr(os, 'geteuid') and os.geteuid() != 0:
        return False, 'Root privileges are required for host dependency installation.'
    if not command_available('apt-get'):
        return False, 'apt-get is unavailable; install the virtualization stack manually.'
    packages = [
        'software-properties-common','ca-certificates','curl','apt-transport-https','gnupg',
        'tar','unzip','git','mariadb-server','redis-server','nginx','certbot',
        'python3-certbot-nginx','qemu-kvm','qemu-utils','libvirt-daemon-system',
        'libvirt-clients','virtinst','bridge-utils','ovmf','cloud-image-utils','xorriso','genisoimage',
        'qemu-guest-agent','socat'
    ]
    rc, out, err = await system_cmd('apt-get','update','-y',timeout=600)
    if rc != 0: return False, 'apt-get update failed: ' + clean(err or out, 1200)
    rc, out, err = await system_cmd('apt-get','full-upgrade','-y',timeout=1800)
    if rc != 0: return False, 'apt full-upgrade failed: ' + clean(err or out, 1200)
    rc, out, err = await system_cmd('apt-get','install','-y','--no-install-recommends',*packages,timeout=1800)
    if rc != 0: return False, 'Dependency installation failed: ' + clean(err or out, 1800)
    for unit in ('docker','libvirtd','ssh','mariadb','redis-server','nginx'):
        await system_cmd('systemctl','enable','--now',unit,timeout=90)
    if command_available('docker'):
        await system_cmd('docker','compose','version',timeout=30)
    return True, 'Host dependencies installed/verified: Docker/KVM/libvirt/QEMU/SSHx prerequisites/Node tooling prerequisites.'

# ============================================================================
# Bootstrap / shutdown
# ============================================================================

STOP_EVENT = asyncio.Event()
WEB_RUNNER: web.AppRunner | None = None  # type: ignore[union-attr]


def acquire_pid_lock() -> Any:
    lock_path = Path(os.getenv("LOCK_FILE", "/tmp/rgnodes-vm-manager.lock"))
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_path.open("a+")
    try:
        import fcntl
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (BlockingIOError, ImportError):
        handle.close()
        raise RuntimeError("Another RGNODES VM Manager process is already running.")
    handle.seek(0)
    handle.truncate()
    handle.write(str(os.getpid()))
    handle.flush()
    return handle


async def shutdown() -> None:
    STOP_EVENT.set()
    global WEB_RUNNER
    if WEB_RUNNER is not None:
        await WEB_RUNNER.cleanup()
        WEB_RUNNER = None
    if bot is not None and not bot.is_closed():
        await bot.close()


async def main() -> None:
    db_init()
    lock_handle = acquire_pid_lock()
    try:
        global WEB_RUNNER
        if not password_configured():
            logger.warning("WEB_ADMIN_PASSWORD_HASH/WEB_ADMIN_PASSWORD is not set; web dashboard login is disabled.")
        else:
            WEB_RUNNER = await start_web_server()
        abuse_task = asyncio.create_task(abuse_loop(STOP_EVENT), name="rgnodes-abuse-monitor")
        try:
            if bot is not None and DISCORD_TOKEN:
                await bot.start(DISCORD_TOKEN)
            else:
                logger.warning("Discord bot disabled because DISCORD_TOKEN is missing.")
                await STOP_EVENT.wait()
        finally:
            abuse_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await abuse_task
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await shutdown()
        with contextlib.suppress(Exception):
            import fcntl
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
        lock_handle.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
