from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import re
import signal
import shutil
import socket
import ipaddress
import sqlite3
import sys
import json
import time
import uuid
import shlex
import aiohttp
import secrets
try:
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None
import string
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Awaitable, Callable
from urllib.parse import urlsplit, urlunsplit, quote

import discord
from discord import app_commands
from discord.ext import commands, tasks
from dotenv import load_dotenv

# ================================================================
# RGNODES™ VPS Management Bot — hardened/stable build
# UI/command names are intentionally kept compatible with the build
# supplied by the user.
# ================================================================

load_dotenv()


def env_int(name: str, default: int, minimum: int | None = None, maximum: int | None = None) -> int:
    try:
        value = int(os.getenv(name, str(default)).strip())
    except (TypeError, ValueError):
        value = default
    if minimum is not None:
        value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def normalize_bot_token(raw: str | None) -> str:
    """Return a clean Discord bot token without exposing it in logs."""
    token = str(raw or "").strip()
    if not token:
        return ""
    if len(token) >= 2 and token[0] == token[-1] and token[0] in {"'", '"'}:
        token = token[1:-1].strip()
    if token.lower().startswith("bot "):
        token = token[4:].strip()
    token = token.replace("\r", "").replace("\n", "").strip()
    return token


def load_discord_token() -> tuple[str, str]:
    """Return (token, source), supporting common environment variable names."""
    for name in ("TOKEN", "DISCORD_TOKEN", "BOT_TOKEN"):
        token = normalize_bot_token(os.getenv(name))
        if token:
            return token, name
    return "", "none"


TOKEN, TOKEN_SOURCE = load_discord_token()
# Native-Docker guest bootstrap settings.
# Kept near the top because function default arguments are evaluated when the
# function is defined, not when it is called.
GUEST_SYSTEMD_ENABLED = True
GUEST_NESTED_DOCKER = env_bool("GUEST_NESTED_DOCKER", True)
GUEST_SYSTEMD_PRIVILEGED = env_bool("GUEST_SYSTEMD_PRIVILEGED", True)
GUEST_CGROUPNS_HOST = env_bool("GUEST_CGROUPNS_HOST", True)
GUEST_KVM_ENABLED = False
GUEST_INSTALL_WINGS = env_bool("GUEST_INSTALL_WINGS", True)
GUEST_INSTALL_WEB_STACK = env_bool("GUEST_INSTALL_WEB_STACK", True)
GUEST_INSTALL_DATABASE_STACK = env_bool("GUEST_INSTALL_DATABASE_STACK", True)
GUEST_BOOTSTRAP_TIMEOUT = env_int("GUEST_BOOTSTRAP_TIMEOUT", 1200, 120, 1800)
GUEST_DOCKER_PACKAGE = os.getenv("GUEST_DOCKER_PACKAGE", "docker.io").strip() or "docker.io"
GUEST_PERSISTENT_DATA = env_bool("GUEST_PERSISTENT_DATA", True)

# Real VPS backend: QEMU system emulation with software TCG only. KVM is never used.
VPS_BACKEND = "qemu"
QEMU_ACCEL = "tcg"
QEMU_VM_ROOT = Path(os.getenv("QEMU_VM_ROOT", "qemu-vms")).expanduser().resolve()
QEMU_IMAGE_CACHE = Path(os.getenv("QEMU_IMAGE_CACHE", str(QEMU_VM_ROOT / "_images"))).expanduser().resolve()
QEMU_SSH_PORT_START = env_int("QEMU_SSH_PORT_START", 41000, 1024, 65530)
QEMU_SSH_PORT_END = env_int("QEMU_SSH_PORT_END", 45000, QEMU_SSH_PORT_START, 65535)
QEMU_AUTO_INSTALL_HOST_TOOLS = env_bool("QEMU_AUTO_INSTALL_HOST_TOOLS", True)
QEMU_HOST_PREP_TIMEOUT = env_int("QEMU_HOST_PREP_TIMEOUT", 900, 120, 1800)
QEMU_BOOT_TIMEOUT = env_int("QEMU_BOOT_TIMEOUT", 900, 120, 1800)
QEMU_SSH_USER = os.getenv("QEMU_SSH_USER", "rgnodes").strip() or "rgnodes"

QEMU_IMAGE_URLS = {
    "ubuntu-22.04": "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img",
    "ubuntu-24.04": "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img",
    "ubuntu-26.04": "https://cloud-images.ubuntu.com/resolute/current/resolute-server-cloudimg-amd64.img",
    "debian-11": "https://cloud.debian.org/images/cloud/bullseye/latest/debian-11-generic-amd64.qcow2",
    "debian-12": "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2",
    "debian-13": "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-amd64.qcow2",
}

ADMIN_ID = env_int("ADMIN_ID", 0, 0)
DATABASE_FILE = os.getenv("DATABASE_FILE", "vps_bot.db").strip() or "vps_bot.db"
LOG_FILE = os.getenv("LOG_FILE", "vps_bot.log").strip() or "vps_bot.log"
BOT_STATUS_NAME = os.getenv("BOT_STATUS_NAME", "RGNODES™ VPS Management").strip() or "RGNODES™ VPS Management"
PREFIX = (os.getenv("PREFIX") or "-").strip() or "-"
VPS_HOSTNAME_PREFIX = os.getenv("VPS_HOSTNAME_PREFIX", "rgnodes").strip() or "rgnodes"
DEFAULT_RAM = os.getenv("DEFAULT_RAM", "4G").strip() or "4G".strip() or "2g"
DEFAULT_CPU = os.getenv("DEFAULT_CPU", "1").strip() or "1".strip() or "1"
DEFAULT_DISK = os.getenv("DEFAULT_DISK", "10G").strip() or "10G".strip() or "10g"
DEFAULT_LOCATION = os.getenv("DEFAULT_LOCATION", "SG").strip().upper() or "SG"
if DEFAULT_LOCATION not in {"SG", "IN"}:
    DEFAULT_LOCATION = "SG"
SERVER_LIMIT = env_int("SERVER_LIMIT", 1, 1, 100)
TOTAL_RUNNING_LIMIT = env_int("TOTAL_RUNNING_LIMIT", 50, 1, 10_000)
ADMIN_BYPASS_LIMITS = env_bool("ADMIN_BYPASS_LIMITS", True)
STATUS_INTERVAL = env_int("STATUS_INTERVAL", 45, 15, 300)
DOCKER_TIMEOUT = env_int("DOCKER_TIMEOUT", 120, 30, 900)
ACCESS_TIMEOUT = env_int("ACCESS_TIMEOUT", 120, 30, 300)
DEPLOY_TIMEOUT = env_int("DEPLOY_TIMEOUT", 1200, 300, 1800)
IMAGE_PULL_TIMEOUT = env_int("IMAGE_PULL_TIMEOUT", 300, 60, 600)
INTERACTION_LOG_UNKNOWN_AS_DEBUG = env_bool("INTERACTION_LOG_UNKNOWN_AS_DEBUG", True)
ENABLE_HARD_DISK_QUOTA = env_bool("ENABLE_HARD_DISK_QUOTA", False)
QUOTA_FALLBACK = env_bool("QUOTA_FALLBACK", True)
DOCKER_FEATURE_FALLBACK = env_bool("DOCKER_FEATURE_FALLBACK", True)
DOCKER_RETRIES = env_int("DOCKER_RETRIES", 2, 0, 5)
STATUS_CONCURRENCY = env_int("STATUS_CONCURRENCY", 5, 1, 25)
MEMORY_RESERVATION_PERCENT = env_int("MEMORY_RESERVATION_PERCENT", 75, 0, 100)
DISABLE_CONTAINER_SWAP = env_bool("DISABLE_CONTAINER_SWAP", True)
# Never start/reconfigure a host Docker daemon implicitly. This is especially
# important when RGNODES itself runs under Pterodactyl/Wings or another supervisor.
MANAGE_DOCKER_DAEMON = env_bool("MANAGE_DOCKER_DAEMON", False)
DISCORD_API_TIMEOUT = env_int("DISCORD_API_TIMEOUT", 10, 3, 30)
PROGRESS_UPDATE_TIMEOUT = env_int("PROGRESS_UPDATE_TIMEOUT", 5, 2, 20)
SSHX_TOTAL_TIMEOUT = env_int("SSHX_TOTAL_TIMEOUT", 100, 30, 240)
SSHX_START_TIMEOUT = env_int("SSHX_START_TIMEOUT", 45, 15, 120)
SSHX_POLL_SECONDS = env_int("SSHX_POLL_SECONDS", 30, 5, 90)
HOST_TOTAL_RAM = os.getenv("HOST_TOTAL_RAM", "64G").strip() or "64G"
HOST_TOTAL_CPU = env_int("HOST_TOTAL_CPU", 10, 1, 256)
HOST_TOTAL_DISK = os.getenv("HOST_TOTAL_DISK", "10T").strip() or "10T"
MAX_PORTS_PER_VPS = env_int("MAX_PORTS_PER_VPS", 10, 1, 50)
PORT_RANGE_START = env_int("PORT_RANGE_START", 20000, 1024, 65534)
PORT_RANGE_END = env_int("PORT_RANGE_END", 40000, 1025, 65535)
PORT_SUPERVISOR_INTERVAL = env_int("PORT_SUPERVISOR_INTERVAL", 20, 5, 120)
PUBLIC_IP_REFRESH = env_int("PUBLIC_IP_REFRESH", 300, 60, 3600)
REAL_LOCATION_REFRESH = env_int("REAL_LOCATION_REFRESH", 900, 120, 7200)
IPV4_MODE = os.getenv("IPV4_MODE", "shared").strip().lower() or "shared"
if IPV4_MODE not in {"shared"}:
    IPV4_MODE = "shared"
REQUIRE_REAL_PUBLIC_IPV4 = env_bool("REQUIRE_REAL_PUBLIC_IPV4", True)
IPV4_REFRESH = env_int("IPV4_REFRESH", 300, 30, 3600)

# Discord startup/network resilience. A failed HTTPS handshake should not
# terminate the whole service; the health endpoint and worker remain alive
# while Discord login is retried with exponential backoff.
DISCORD_LOGIN_RETRY_BASE = env_int("DISCORD_LOGIN_RETRY_BASE", 5, 1, 60)
DISCORD_LOGIN_RETRY_MAX = env_int("DISCORD_LOGIN_RETRY_MAX", 120, 10, 600)
DISCORD_LOGIN_MAX_ATTEMPTS = env_int("DISCORD_LOGIN_MAX_ATTEMPTS", 0, 0, 1000)

# Hosting-platform health/keep-alive HTTP listener. Most platforms (Render,
# Railway, etc.) provide PORT automatically; locally it falls back to 247.
WEB_HOST = os.getenv("WEB_HOST", "0.0.0.0").strip() or "0.0.0.0"
# Never let the bot health server occupy Pterodactyl Wings/SFTP ports on a VM.
# Hosting platforms can opt into their injected PORT explicitly.
USE_PLATFORM_PORT = env_bool("USE_PLATFORM_PORT", False)
WEB_RESERVED_PORTS = {2022, 8080, 8443}
_requested_web_port = env_int("PORT", 247, 1, 65535) if USE_PLATFORM_PORT else env_int("WEB_PORT", 247, 1, 65535)
WEB_PORT = 247 if _requested_web_port in WEB_RESERVED_PORTS else _requested_web_port
WEB_PATH = os.getenv("WEB_PATH", "/").strip() or "/"

PTERO_URL = os.getenv("PTERO_URL", "").strip().rstrip("/")
PTERO_API_KEY = (os.getenv("PTERO_API_KEY") or os.getenv("PTERODACTYL_APPLICATION_API_KEY") or "").strip()
PTERO_CLIENT_API_KEY = (os.getenv("PTERO_CLIENT_API_KEY") or os.getenv("PTERODACTYL_CLIENT_API_KEY") or "").strip()
PTERO_PANEL_PUBLIC_URL = os.getenv("PTERO_PANEL_PUBLIC_URL", PTERO_URL).strip().rstrip("/")
PTERO_NODE_ID = env_int("PTERO_NODE_ID", 0, 0)
PTERO_NEST_ID = env_int("PTERO_NEST_ID", 0, 0)
PTERO_EGG_ID = env_int("PTERO_EGG_ID", 0, 0)
PTERO_ALLOCATION_ID = env_int("PTERO_ALLOCATION_ID", 0, 0)
PTERO_DEFAULT_USER_ID = env_int("PTERO_DEFAULT_USER_ID", 0, 0)
PTERO_AUTO_CREATE_USERS = env_bool("PTERO_AUTO_CREATE_USERS", True)
PTERO_MEMORY_SWAP = env_int("PTERO_MEMORY_SWAP", 0)
PTERO_IO = env_int("PTERO_IO", 500, 10, 1000)
PTERO_DATABASES = env_int("PTERO_DATABASES", 0, 0, 100)
PTERO_ALLOCATIONS = env_int("PTERO_ALLOCATIONS", 1, 1, 100)
PTERO_BACKUPS = env_int("PTERO_BACKUPS", 5, 0, 100)
PTERO_DOCKER_IMAGE = os.getenv("PTERO_DOCKER_IMAGE", "").strip()
PTERO_STARTUP = os.getenv("PTERO_STARTUP", "").strip()
PTERO_SKIP_SCRIPTS = env_bool("PTERO_SKIP_SCRIPTS", False)
PTERO_ENVIRONMENT_JSON = os.getenv("PTERO_ENVIRONMENT_JSON", "{}").strip() or "{}"
try:
    PTERO_ENVIRONMENT = json.loads(PTERO_ENVIRONMENT_JSON)
    if not isinstance(PTERO_ENVIRONMENT, dict):
        PTERO_ENVIRONMENT = {}
except (TypeError, ValueError, json.JSONDecodeError):
    PTERO_ENVIRONMENT = {}

def ptero_application_configured() -> bool:
    return bool(
        PTERO_URL and PTERO_API_KEY and PTERO_DEFAULT_USER_ID
        and PTERO_NODE_ID and PTERO_NEST_ID and PTERO_EGG_ID
        and PTERO_ALLOCATION_ID
    )


def ptero_client_configured() -> bool:
    return bool(PTERO_URL and PTERO_CLIENT_API_KEY)


def ptero_configured() -> bool:
    return ptero_application_configured() and ptero_client_configured()

def active_backend() -> str:
    return "qemu"

if not WEB_PATH.startswith("/"):
    WEB_PATH = "/" + WEB_PATH

LOCATION_CONFIG = {
    "SG": {"label": "Singapore 🇸🇬", "short": "SG"},
    "IN": {"label": "India 🇮🇳", "short": "IN"},
}

OS_CONFIG = {
    "ubuntu-26.04": {"label": "Ubuntu 26.04 LTS", "image": "ubuntu:26.04"},
    "ubuntu-24.04": {"label": "Ubuntu 24.04 LTS", "image": "ubuntu:24.04"},
    "ubuntu-22.04": {"label": "Ubuntu 22.04 LTS", "image": "ubuntu:22.04"},
    "debian-13": {"label": "Debian 13", "image": "debian:13.6"},
    "debian-12": {"label": "Debian 12", "image": "debian:12.15"},
    "debian-11": {"label": "Debian 11", "image": "debian:11.11"},
}

LOCATION_ALIASES = {
    "sg": "SG",
    "singapore": "SG",
    "in": "IN",
    "india": "IN",
}

OS_ALIASES = {
    "ubuntu": "ubuntu-24.04", "ubuntu26": "ubuntu-26.04", "ubuntu26.04": "ubuntu-26.04", "ubuntu-26.04": "ubuntu-26.04",
    "ubuntu24": "ubuntu-24.04", "ubuntu24.04": "ubuntu-24.04", "ubuntu-24.04": "ubuntu-24.04",
    "ubuntu22": "ubuntu-22.04", "ubuntu22.04": "ubuntu-22.04", "ubuntu-22.04": "ubuntu-22.04",
    "debian": "debian-13", "debian13": "debian-13", "debian-13": "debian-13",
    "debian12": "debian-12", "debian-12": "debian-12",
    "debian11": "debian-11", "debian-11": "debian-11",
}

ACCESS_URL_RE = re.compile(r"https://sshx\.io/s/[A-Za-z0-9_-]+(?:#[A-Za-z0-9_=-]+)?", re.IGNORECASE)
Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    handlers=[logging.FileHandler(LOG_FILE, encoding="utf-8"), logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("rgnodes")

# Prevent multiple copies of the same bot from connecting with the same token.
# Two gateway sessions will both receive the same message and cause duplicate
# replies. This lock is held for the complete process lifetime.
SINGLETON_LOCK_FILE = Path(os.getenv("SINGLETON_LOCK_FILE", "/tmp/rgnodes-vm.lock")).expanduser()
_SINGLETON_HANDLE = None

def _same_script_process(pid: int) -> bool:
    if pid <= 0 or pid == os.getpid():
        return False
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", "replace")
    except (OSError, ValueError):
        return False
    return str(Path(__file__).resolve()) in raw

def acquire_singleton() -> None:
    """Acquire a process-wide lock and refuse a second bot instance.

    Never terminate another process from inside the application. A restart
    supervisor/systemd/pm2 should own process lifecycle; killing a peer here
    can create a short overlap where both gateway sessions receive events.
    """
    global _SINGLETON_HANDLE
    SINGLETON_LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    handle = SINGLETON_LOCK_FILE.open("a+")
    if fcntl is None:
        handle.close()
        raise SystemExit("fcntl is unavailable; refusing to start without duplicate-process protection.")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        raise SystemExit("Another RGNODES bot process is already running. Stop the existing copy before starting a new one.")
    handle.seek(0)
    handle.truncate()
    handle.write(str(os.getpid()))
    handle.flush()
    _SINGLETON_HANDLE = handle
    logger.info("RGNODES singleton lock acquired (pid=%s).", os.getpid())

def release_singleton() -> None:
    global _SINGLETON_HANDLE
    handle = _SINGLETON_HANDLE
    _SINGLETON_HANDLE = None
    if handle is None:
        return
    with contextlib.suppress(Exception):
        if fcntl is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    with contextlib.suppress(Exception):
        handle.close()


# ================================================================
# Lightweight 24/7 HTTP health/landing server
# ================================================================
# This server intentionally uses only Python's asyncio standard library so the
# existing dependency set does not need Flask/FastAPI/aiohttp. It runs in the
# same event loop as discord.py and therefore stays alive for the full process
# lifetime. Hosting platforms can probe the assigned PORT and receive HTTP 200.
WEB_SERVER: asyncio.AbstractServer | None = None
WEB_SERVER_TASK: asyncio.Task[None] | None = None
WEB_STARTED_AT = datetime.now(timezone.utc)


def _html_escape(value: Any) -> str:
    text = str(value)
    return (text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#39;"))


def _health_html() -> bytes:
    discord_online = bool(bot.is_ready()) if "bot" in globals() else False
    bot_name = str(bot.user) if discord_online and getattr(bot, "user", None) else "Starting…"
    state = "Online" if discord_online else "Starting"
    started = WEB_STARTED_AT.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    body = f"""<!doctype html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\">
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
<meta http-equiv=\"refresh\" content=\"30\">
<title>RGNODES™ • Bot Status</title>
<style>
body{{margin:0;min-height:100vh;background:#111318;color:#f5f7fa;font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;display:grid;place-items:center}}
.card{{width:min(680px,calc(100% - 40px));padding:34px;border:1px solid #2a2e38;border-radius:20px;background:#181b22;box-shadow:0 20px 70px rgba(0,0,0,.35)}}
.badge{{display:inline-flex;align-items:center;gap:8px;padding:7px 12px;border-radius:999px;background:#20252e;font-size:14px}}
.dot{{width:9px;height:9px;border-radius:50%;background:#48d597;box-shadow:0 0 14px #48d597}}
h1{{margin:18px 0 10px;font-size:34px}}
p{{color:#aeb6c4;line-height:1.6}}
.row{{display:flex;justify-content:space-between;gap:18px;margin-top:22px;padding-top:18px;border-top:1px solid #2a2e38}}
code{{color:#dfe5ee}}
</style>
</head>
<body>
<main class=\"card\">
<div class=\"badge\"><span class=\"dot\"></span>Bot is <strong>{_html_escape(state)}</strong></div>
<h1>RGNODES™ Bot is online…</h1>
<p>The 24/7 health endpoint is running and ready for hosting-platform health checks. Opening or pinging this port confirms the process is serving HTTP.</p>
<div class=\"row\"><span>Status</span><strong>{_html_escape(state)}</strong></div>
<div class=\"row\"><span>Discord</span><strong>{_html_escape(bot_name)}</strong></div>
<div class=\"row\"><span>Started</span><code>{_html_escape(started)}</code></div>
</main>
</body>
</html>
"""
    return body.encode("utf-8")


async def _http_health_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername")
    try:
        # Read only the request headers, with a hard cap to avoid oversized or
        # slowloris-style requests taking resources from the Discord bot.
        try:
            request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
            return
        if len(request) > 16 * 1024:
            return

        first_line = request.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        parts = first_line.split()
        method = parts[0].upper() if parts else ""
        target = parts[1] if len(parts) >= 2 else "/"
        path = target.split("?", 1)[0].split("#", 1)[0]

        if method not in {"GET", "HEAD"}:
            payload = b"Method Not Allowed\n"
            headers = (
                b"HTTP/1.1 405 Method Not Allowed\r\n"
                b"Content-Type: text/plain; charset=utf-8\r\n"
                + f"Content-Length: {len(payload)}\r\n".encode()
                + b"Connection: close\r\n\r\n"
            )
        elif path in {"/", WEB_PATH, "/health", "/healthz", "/ping"}:
            if path in {"/health", "/healthz"}:
                discord_online = bool(bot.is_ready())
                payload = (
                    ("{\"status\":\"online\",\"discord_ready\":" + ("true" if discord_online else "false") + "}")
                    .encode("utf-8")
                )
                content_type = b"application/json; charset=utf-8"
            else:
                payload = _health_html()
                content_type = b"text/html; charset=utf-8"
            headers = (
                b"HTTP/1.1 200 OK\r\n"
                + b"Content-Type: " + content_type + b"\r\n"
                + f"Content-Length: {len(payload)}\r\n".encode()
                + b"Cache-Control: no-store, no-cache, must-revalidate\r\n"
                + b"Connection: close\r\n\r\n"
            )
        else:
            payload = b"Not Found\n"
            headers = (
                b"HTTP/1.1 404 Not Found\r\n"
                b"Content-Type: text/plain; charset=utf-8\r\n"
                + f"Content-Length: {len(payload)}\r\n".encode()
                + b"Connection: close\r\n\r\n"
            )

        writer.write(headers)
        if method != "HEAD":
            writer.write(payload)
        await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
        pass
    except Exception as exc:
        logger.debug("Health client error from %s: %s", peer, safe_log(exc))
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def start_health_server() -> asyncio.AbstractServer | None:
    global WEB_SERVER, WEB_SERVER_TASK
    if WEB_SERVER is not None:
        return WEB_SERVER
    try:
        last_error = None
        candidates: list[int] = []
        for candidate in [WEB_PORT, *range(WEB_PORT + 1, min(WEB_PORT + 11, 65536))]:
            if candidate in WEB_RESERVED_PORTS or candidate in candidates:
                continue
            candidates.append(candidate)
        for candidate in candidates:
            try:
                WEB_SERVER = await asyncio.start_server(
                    _http_health_client,
                    host=WEB_HOST,
                    port=candidate,
                    limit=16 * 1024,
                    reuse_address=True,
                )
                if candidate != WEB_PORT:
                    logger.warning("Health port %s is busy; using fallback port %s.", WEB_PORT, candidate)
                break
            except OSError as exc:
                last_error = exc
        if WEB_SERVER is None:
            raise last_error or OSError("No health port available")
        WEB_SERVER_TASK = asyncio.create_task(
            WEB_SERVER.serve_forever(),
            name="rgnodes-http-health",
        )
        sockets = WEB_SERVER.sockets or []
        bound = ", ".join(str(sock.getsockname()) for sock in sockets) or f"{WEB_HOST}:{WEB_PORT}"
        logger.info("24/7 HTTP health server online at %s | GET / or /health", bound)
        return WEB_SERVER
    except (OSError, asyncio.CancelledError) as exc:
        WEB_SERVER = None
        WEB_SERVER_TASK = None
        if isinstance(exc, asyncio.CancelledError):
            raise
        logger.error("Could not start HTTP health server on %s:%s: %s", WEB_HOST, WEB_PORT, safe_log(exc))
        return None


async def stop_health_server() -> None:
    global WEB_SERVER, WEB_SERVER_TASK
    server, task = WEB_SERVER, WEB_SERVER_TASK
    WEB_SERVER = None
    WEB_SERVER_TASK = None
    if server is not None:
        server.close()
        with contextlib.suppress(Exception):
            await server.wait_closed()
    if task is not None:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task


def safe_log(value: Any, limit: int = 1800) -> str:
    text = str(value)
    # Preserve the useful SSHx session ID while redacting only the browser-side
    # E2E key fragment. Logging the full fragment would expose the private console.
    text = re.sub(
        r"(https://sshx\.io/s/[A-Za-z0-9_-]+)#([^\s<>\]\[\"']+)",
        r"\1#<e2e-key-redacted>",
        text,
        flags=re.I,
    )
    text = re.sub(r"Bearer\s+\S+", "Bearer <redacted>", text, flags=re.I)
    text = re.sub(r"ssh\s+\S+@\S+", "ssh <redacted>", text, flags=re.I)
    return text[:max(1, int(limit))]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_os(value: str | None) -> str | None:
    return OS_ALIASES.get((value or "").strip().lower())


def os_label(value: str | None) -> str:
    normalized = normalize_os(value) or (value or "Unknown")
    return OS_CONFIG.get(normalized, {"label": normalized})["label"]


def normalize_location(value: str | None) -> str | None:
    raw = (value or "").strip().lower()
    if raw in LOCATION_ALIASES:
        return LOCATION_ALIASES[raw]
    key = raw.upper()
    return key if key in LOCATION_CONFIG else None


def location_label(value: str | None) -> str:
    return LOCATION_CONFIG[(normalize_location(value) or DEFAULT_LOCATION)]["label"]


def clean(value: Any, limit: int = 1024) -> str:
    return str(value if value is not None else "N/A").replace("`", "'")[:limit]


def parse_size_bytes(value: str) -> int:
    text = str(value or "").strip().lower().replace(" ", "")
    match = re.fullmatch(r"(\d+(?:\.\d+)?)(b|kb|k|mb|m|gb|g|tb|t)?", text)
    if not match:
        raise ValueError(f"Invalid resource value: {value}")
    amount = float(match.group(1))
    unit = match.group(2) or "g"
    multiplier = {"b": 1, "k": 1024, "kb": 1024, "m": 1024**2, "mb": 1024**2, "g": 1024**3, "gb": 1024**3, "t": 1024**4, "tb": 1024**4}[unit]
    return int(amount * multiplier)


def format_bytes(value: int) -> str:
    """Human-readable binary byte formatting for Discord dashboard values."""
    try:
        value = max(0, int(value))
    except (TypeError, ValueError):
        return "N/A"
    if value < 1024:
        return f"{value} B"
    if value < 1024**2:
        return f"{value / 1024:.0f}KB"
    if value < 1024**3:
        return f"{value / 1024**2:.1f}MB"
    if value < 1024**4:
        return f"{value / 1024**3:.2f}GB"
    return f"{value / 1024**4:.2f}TB"


def normalize_dashboard_memory(raw: str | None) -> str:
    """Normalize Docker/cgroup memory text to a stable Discord-friendly form."""
    text = str(raw or "").strip()
    if not text:
        return "N/A"
    if "/" not in text:
        return text

    left, right = (part.strip() for part in text.split("/", 1))

    def to_bytes(part: str) -> int | None:
        m = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)\s*([kmgtpe]i?b)?", part, re.I)
        if not m:
            return None
        try:
            amount = float(m.group(1))
            unit = (m.group(2) or "b").lower()
            factors = {
                "b": 1, "kb": 1000, "kib": 1024,
                "mb": 1000**2, "mib": 1024**2,
                "gb": 1000**3, "gib": 1024**3,
                "tb": 1000**4, "tib": 1024**4,
                "pb": 1000**5, "pib": 1024**5,
                "eb": 1000**6, "eib": 1024**6,
            }
            return int(amount * factors[unit])
        except (KeyError, ValueError, OverflowError):
            return None

    used = to_bytes(left)
    limit = to_bytes(right)
    if used is not None and limit is not None:
        return f"{format_bytes(used)} / {format_bytes(limit)}"
    return text


def normalize_network_stats(raw: str | None) -> str:
    """Render Docker NetIO as download/upload without changing the measured values."""
    text = str(raw or "").strip()
    if not text:
        return "N/A"
    if " / " in text:
        left, right = text.split(" / ", 1)
        return f"{left.strip()} ↓ / {right.strip()} ↑"
    return text


def validate_resources(ram: str, cpu: str, disk: str) -> tuple[str, str, str]:
    try:
        ram_bytes = parse_size_bytes(ram)
        disk_bytes = parse_size_bytes(disk)
        cpu_value = float(str(cpu).strip())
    except (TypeError, ValueError):
        raise ValueError("RAM, CPU, or disk format is invalid. Example: `2g`, `2`, `10g`.")
    if not 256 * 1024**2 <= ram_bytes <= 256 * 1024**3:
        raise ValueError("RAM must be between 256MB and 256GB.")
    if not 1 * 1024**3 <= disk_bytes <= 10 * 1024**4:
        raise ValueError("Disk must be between 1GB and 10TB.")
    if not 0 < cpu_value <= 64:
        raise ValueError("CPU must be greater than 0 and no more than 64 cores.")
    ram = str(ram).strip().lower()
    cpu = f"{cpu_value:g}"
    disk = str(disk).strip().lower()
    return ram, cpu, disk


# ================================================================
# SQLite — serialized writes + resilient migration
# ================================================================

DB_WRITE_LOCK = asyncio.Lock()


def db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE_FILE, timeout=30, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def init_db() -> None:
    conn = db_connect()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                container_id TEXT UNIQUE NOT NULL,
                container_name TEXT NOT NULL,
                os_type TEXT NOT NULL,
                location TEXT NOT NULL DEFAULT 'SG',
                hostname TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'stopped',
                ssh_command TEXT,
                ram TEXT NOT NULL DEFAULT '2g',
                cpu TEXT NOT NULL DEFAULT '1',
                disk TEXT NOT NULL DEFAULT '10g',
                suspended INTEGER NOT NULL DEFAULT 0,
                sshx_url TEXT,
                sshx_pid TEXT,
                public_ipv4 TEXT,
                ipv4_verified_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vps_shares (
                vps_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                shared_by INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (vps_id, user_id),
                FOREIGN KEY(vps_id) REFERENCES vps(id) ON DELETE CASCADE
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS bans (
                user_id INTEGER PRIMARY KEY,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_slots (
                user_id INTEGER PRIMARY KEY,
                slots INTEGER NOT NULL DEFAULT 1 CHECK(slots > 0),
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS processed_events (
                event_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_processed_events_created_at ON processed_events(created_at)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vps_ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vps_id INTEGER NOT NULL,
                container_port INTEGER NOT NULL,
                host_port INTEGER NOT NULL UNIQUE,
                protocol TEXT NOT NULL DEFAULT 'tcp',
                target_ip TEXT,
                pid INTEGER,
                status TEXT NOT NULL DEFAULT 'stopped',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(vps_id, container_port, protocol),
                FOREIGN KEY(vps_id) REFERENCES vps(id) ON DELETE CASCADE
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS vps_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vps_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                image_ref TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(vps_id, name),
                FOREIGN KEY(vps_id) REFERENCES vps(id) ON DELETE CASCADE
            )
        """)
        def cols(table: str) -> set[str]:
            return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        vps_cols = cols("vps")
        for name, ddl in {
            "location": "ALTER TABLE vps ADD COLUMN location TEXT NOT NULL DEFAULT 'SG'",
            "sshx_url": "ALTER TABLE vps ADD COLUMN sshx_url TEXT",
            "sshx_pid": "ALTER TABLE vps ADD COLUMN sshx_pid TEXT",
            "public_ipv4": "ALTER TABLE vps ADD COLUMN public_ipv4 TEXT",
            "ipv4_verified_at": "ALTER TABLE vps ADD COLUMN ipv4_verified_at TEXT",
            "backend": "ALTER TABLE vps ADD COLUMN backend TEXT NOT NULL DEFAULT 'docker'",
            "ptero_server_id": "ALTER TABLE vps ADD COLUMN ptero_server_id INTEGER",
            "ptero_identifier": "ALTER TABLE vps ADD COLUMN ptero_identifier TEXT",
            "ptero_user_id": "ALTER TABLE vps ADD COLUMN ptero_user_id INTEGER",
        }.items():
            if name not in vps_cols:
                conn.execute(ddl)
        # Refresh the schema view after ALTER TABLE operations.
        vps_cols = cols("vps")
        required_vps = {
            "user_id", "container_id", "container_name", "os_type", "location",
            "hostname", "status", "ram", "cpu", "disk", "sshx_url", "sshx_pid",
            "public_ipv4", "ipv4_verified_at", "created_at", "updated_at",
            "backend", "ptero_server_id", "ptero_identifier", "ptero_user_id",
        }
        missing_vps = sorted(required_vps - vps_cols)
        if missing_vps:
            raise RuntimeError(f"SQLite VPS schema is incomplete; missing columns: {', '.join(missing_vps)}")

        share_cols = cols("vps_shares")
        if "shared_by" not in share_cols:
            conn.execute("ALTER TABLE vps_shares ADD COLUMN shared_by INTEGER")
        if "created_at" not in share_cols:
            conn.execute("ALTER TABLE vps_shares ADD COLUMN created_at TEXT")

        if "updated_at" not in cols("users"):
            conn.execute("ALTER TABLE users ADD COLUMN updated_at TEXT")
        if "created_at" not in cols("bans"):
            conn.execute("ALTER TABLE bans ADD COLUMN created_at TEXT")
        now = utc_now()
        conn.execute("UPDATE users SET updated_at=COALESCE(updated_at,created_at,?)", (now,))
        conn.execute("UPDATE vps SET location=COALESCE(location,'SG'),updated_at=COALESCE(updated_at,created_at,?)", (now,))
        conn.execute("UPDATE bans SET created_at=COALESCE(created_at,?)", (now,))
        conn.execute("UPDATE user_slots SET updated_at=COALESCE(updated_at,?)", (now,))
    finally:
        conn.close()


init_db()


def claim_processed_event(event_id: str, kind: str, *, ttl_seconds: int = 900) -> bool:
    """Atomically claim a Discord event across all bot processes using SQLite.

    This is a second layer of duplicate protection in addition to the OS
    singleton lock. If two bot processes briefly overlap during restart, only
    the first process that inserts the event ID is allowed to handle it.
    """
    event_id = str(event_id or "").strip()
    if not event_id:
        return True
    now_dt = datetime.now(timezone.utc)
    cutoff = (now_dt - timedelta(seconds=max(60, int(ttl_seconds)))).isoformat()
    now = now_dt.isoformat()
    conn = db_connect()
    try:
        conn.execute("DELETE FROM processed_events WHERE created_at < ?", (cutoff,))
        cur = conn.execute(
            "INSERT OR IGNORE INTO processed_events(event_id,kind,created_at) VALUES(?,?,?)",
            (event_id, kind[:32], now),
        )
        return cur.rowcount == 1
    except sqlite3.Error as exc:
        # Fail closed: allowing the event through when the cross-process guard
        # is unavailable can create the exact duplicate side effect this table
        # is designed to prevent.
        logger.error("Event de-duplication check failed; blocking event: %s", safe_log(exc))
        return False
    finally:
        conn.close()


def db_upsert_user(user_id: int, username: str) -> None:
    now = utc_now()
    conn = db_connect()
    try:
        conn.execute("""
            INSERT INTO users(user_id,username,created_at,updated_at) VALUES(?,?,?,?)
            ON CONFLICT(user_id) DO UPDATE SET username=excluded.username,updated_at=excluded.updated_at
        """, (user_id, username[:200], now, now))
    finally:
        conn.close()


def db_is_banned(user_id: int) -> bool:
    conn = db_connect()
    try:
        return conn.execute("SELECT 1 FROM bans WHERE user_id=?", (user_id,)).fetchone() is not None
    finally:
        conn.close()


def db_set_ban(user_id: int, banned: bool) -> None:
    conn = db_connect()
    try:
        if banned:
            conn.execute("INSERT OR IGNORE INTO bans(user_id,created_at) VALUES(?,?)", (user_id, utc_now()))
        else:
            conn.execute("DELETE FROM bans WHERE user_id=?", (user_id,))
    finally:
        conn.close()


def db_insert_vps(**data: Any) -> int:
    """Insert a VPS row using generated placeholders to prevent column/value drift.

    Returns the inserted SQLite row id.  The previous implementation used a
    hand-written VALUES list that was easy to break during schema evolution.
    """
    now = utc_now()
    fields = {
        "user_id": data["user_id"],
        "container_id": data["container_id"],
        "container_name": data["container_name"],
        "os_type": data["os_type"],
        "location": data.get("location", DEFAULT_LOCATION),
        "hostname": data["hostname"],
        "status": data.get("status", "running"),
        "ram": data["ram"],
        "cpu": data["cpu"],
        "disk": data["disk"],
        "sshx_url": data.get("sshx_url"),
        "sshx_pid": data.get("sshx_pid"),
        "public_ipv4": data.get("public_ipv4"),
        "ipv4_verified_at": data.get("ipv4_verified_at"),
        "created_at": data.get("created_at", now),
        "updated_at": data.get("updated_at", now),
        "backend": data.get("backend", "docker"),
        "ptero_server_id": data.get("ptero_server_id"),
        "ptero_identifier": data.get("ptero_identifier"),
        "ptero_user_id": data.get("ptero_user_id"),
    }
    columns = list(fields.keys())
    placeholders = ",".join("?" for _ in columns)
    sql = f"INSERT INTO vps ({','.join(columns)}) VALUES ({placeholders})"
    conn = db_connect()
    try:
        cur = conn.execute(sql, tuple(fields[col] for col in columns))
        return int(cur.lastrowid)
    finally:
        conn.close()


def db_get_vps(vps_id: int) -> sqlite3.Row | None:
    conn = db_connect()
    try:
        return conn.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()
    finally:
        conn.close()


def db_get_user_vps(user_id: int) -> list[sqlite3.Row]:
    conn = db_connect()
    try:
        return conn.execute("SELECT * FROM vps WHERE user_id=? ORDER BY id DESC", (user_id,)).fetchall()
    finally:
        conn.close()


def db_get_all_vps() -> list[sqlite3.Row]:
    conn = db_connect()
    try:
        return conn.execute("SELECT * FROM vps ORDER BY id DESC").fetchall()
    finally:
        conn.close()


def db_vps_count(user_id: int) -> int:
    conn = db_connect()
    try:
        return int(conn.execute("SELECT COUNT(*) FROM vps WHERE user_id=?", (user_id,)).fetchone()[0])
    finally:
        conn.close()


def db_running_count() -> int:
    conn = db_connect()
    try:
        return int(conn.execute("SELECT COUNT(*) FROM vps WHERE status='running' AND suspended=0").fetchone()[0])
    finally:
        conn.close()


def db_allocated_resources() -> tuple[int, float, int]:
    """Sum requested resources of all managed VPS records for capacity checks."""
    conn = db_connect()
    try:
        rows = conn.execute("SELECT ram,cpu,disk FROM vps").fetchall()
    finally:
        conn.close()
    ram = cpu = disk = 0.0
    for row in rows:
        try:
            ram += parse_size_bytes(row["ram"])
            disk += parse_size_bytes(row["disk"])
            cpu += float(row["cpu"])
        except (TypeError, ValueError):
            logger.warning("Ignoring malformed resource allocation while checking host capacity")
    return int(ram), cpu, int(disk)


def resource_capacity_error(ram: str, cpu: str, disk: str) -> str | None:
    try:
        request_ram = parse_size_bytes(ram)
        request_cpu = float(cpu)
        request_disk = parse_size_bytes(disk)
        total_ram = parse_size_bytes(HOST_TOTAL_RAM)
        total_disk = parse_size_bytes(HOST_TOTAL_DISK)
    except (TypeError, ValueError):
        return "Host resource capacity configuration is invalid."
    used_ram, used_cpu, used_disk = db_allocated_resources()
    if used_ram + request_ram > total_ram:
        return f"RAM capacity exceeded: requested `{ram}`, allocated `{format_bytes(used_ram)}`, host capacity `{format_bytes(total_ram)}`."
    if used_cpu + request_cpu > HOST_TOTAL_CPU:
        return f"CPU capacity exceeded: requested `{cpu}` core(s), allocated `{used_cpu:g}`, host capacity `{HOST_TOTAL_CPU}`."
    if used_disk + request_disk > total_disk:
        return f"Disk allocation exceeded: requested `{disk}`, allocated `{format_bytes(used_disk)}`, allocation capacity `{format_bytes(total_disk)}`."
    return None


def db_effective_slots(user_id: int) -> int:
    conn = db_connect()
    try:
        row = conn.execute("SELECT slots FROM user_slots WHERE user_id=?", (int(user_id),)).fetchone()
        return max(1, int(row[0])) if row else max(1, SERVER_LIMIT)
    finally:
        conn.close()


def db_add_slots(user_id: int, amount: int) -> int:
    if amount <= 0:
        raise ValueError("Slot amount must be positive.")
    now = utc_now()
    conn = db_connect()
    try:
        row = conn.execute("SELECT slots FROM user_slots WHERE user_id=?", (int(user_id),)).fetchone()
        current = int(row[0]) if row else max(1, SERVER_LIMIT)
        new_total = current + int(amount)
        conn.execute("INSERT INTO user_slots(user_id,slots,updated_at) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET slots=excluded.slots,updated_at=excluded.updated_at", (int(user_id), new_total, now))
        return new_total
    finally:
        conn.close()


def db_list_ports(vps_id: int) -> list[sqlite3.Row]:
    conn = db_connect()
    try:
        return conn.execute("SELECT * FROM vps_ports WHERE vps_id=? ORDER BY host_port", (int(vps_id),)).fetchall()
    finally:
        conn.close()


def db_get_port(port_id: int) -> sqlite3.Row | None:
    conn = db_connect()
    try:
        return conn.execute("SELECT * FROM vps_ports WHERE id=?", (int(port_id),)).fetchone()
    finally:
        conn.close()


def db_find_port(vps_id: int, container_port: int, protocol: str = "tcp") -> sqlite3.Row | None:
    conn = db_connect()
    try:
        return conn.execute("SELECT * FROM vps_ports WHERE vps_id=? AND container_port=? AND protocol=?", (int(vps_id), int(container_port), protocol.lower())).fetchone()
    finally:
        conn.close()


def db_insert_port(vps_id: int, container_port: int, host_port: int, protocol: str = "tcp") -> int:
    now = utc_now()
    conn = db_connect()
    try:
        cur = conn.execute("INSERT INTO vps_ports(vps_id,container_port,host_port,protocol,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", (int(vps_id), int(container_port), int(host_port), protocol.lower(), "stopped", now, now))
        return int(cur.lastrowid)
    finally:
        conn.close()


def db_update_port(port_id: int, **fields: Any) -> None:
    allowed = {"target_ip", "pid", "status"}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return
    assignments = ", ".join(f"{k}=?" for k in updates)
    values = list(updates.values()) + [utc_now(), int(port_id)]
    conn = db_connect()
    try:
        conn.execute(f"UPDATE vps_ports SET {assignments},updated_at=? WHERE id=?", values)
    finally:
        conn.close()


def db_delete_port(port_id: int) -> None:
    conn = db_connect()
    try:
        conn.execute("DELETE FROM vps_ports WHERE id=?", (int(port_id),))
    finally:
        conn.close()


def db_delete_all_vps() -> None:
    conn = db_connect()
    try:
        conn.execute("DELETE FROM vps")
        conn.execute("DELETE FROM sqlite_sequence WHERE name='vps'")
        conn.execute("DELETE FROM sqlite_sequence WHERE name='vps_ports'")
    finally:
        conn.close()


def db_find_vps(user_id: int, identifier: str | None, admin: bool = False) -> sqlite3.Row | None:
    rows = db_get_all_vps() if admin else db_get_user_vps(user_id)
    needle = (identifier or "").strip().lower()
    if not needle:
        return rows[0] if rows else None
    exact = [r for r in rows if needle in {str(r["id"]).lower(), str(r["container_id"]).lower(), str(r["container_name"]).lower()}]
    if exact:
        return exact[0]
    partial = [r for r in rows if needle in str(r["container_id"]).lower() or needle in str(r["container_name"]).lower()]
    return partial[0] if len(partial) == 1 else None


def db_share_vps(vps_id: int, user_id: int, shared_by: int) -> tuple[bool, str]:
    if int(user_id) == int(shared_by):
        return False, "You cannot share a VPS with yourself."
    conn = db_connect()
    try:
        if conn.execute("SELECT 1 FROM vps WHERE id=?", (vps_id,)).fetchone() is None:
            return False, "VPS not found."
        cur = conn.execute(
            "INSERT OR IGNORE INTO vps_shares(vps_id,user_id,shared_by,created_at) VALUES(?,?,?,?)",
            (vps_id, user_id, shared_by, utc_now()),
        )
        if cur.rowcount == 0:
            return False, "That user already has access to this VPS."
        return True, "VPS access granted."
    finally:
        conn.close()


def db_unshare_vps(vps_id: int, user_id: int) -> tuple[bool, str]:
    conn = db_connect()
    try:
        cur = conn.execute("DELETE FROM vps_shares WHERE vps_id=? AND user_id=?", (vps_id, user_id))
        return (cur.rowcount > 0, "VPS access removed." if cur.rowcount else "That user does not have shared access.")
    finally:
        conn.close()


def db_find_accessible_vps(user_id: int, identifier: str | None) -> sqlite3.Row | None:
    owner = db_find_vps(user_id, identifier, admin=False)
    if owner:
        return owner
    needle = (identifier or "").strip().lower()
    conn = db_connect()
    try:
        rows = conn.execute(
            "SELECT v.* FROM vps v INNER JOIN vps_shares s ON s.vps_id=v.id WHERE s.user_id=? ORDER BY v.id DESC",
            (user_id,),
        ).fetchall()
    finally:
        conn.close()
    if not needle:
        return rows[0] if rows else None
    exact = [r for r in rows if needle in {str(r["id"]).lower(), str(r["container_id"]).lower(), str(r["container_name"]).lower()}]
    if exact:
        return exact[0]
    partial = [r for r in rows if needle in str(r["container_id"]).lower() or needle in str(r["container_name"]).lower()]
    return partial[0] if len(partial) == 1 else None


def db_is_owner_or_admin(user_id: int, vps: sqlite3.Row) -> bool:
    return int(user_id) == int(vps["user_id"]) or (ADMIN_ID > 0 and int(user_id) == int(ADMIN_ID))


def db_update_vps(container_id: str, **fields: Any) -> None:
    allowed = {"status", "suspended", "ssh_command", "sshx_url", "sshx_pid", "os_type", "location", "hostname", "public_ipv4", "ipv4_verified_at", "backend", "ptero_server_id", "ptero_identifier", "ptero_user_id"}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return
    assignments = ", ".join(f"{k}=?" for k in updates)
    values = list(updates.values()) + [utc_now(), container_id]
    conn = db_connect()
    try:
        conn.execute(f"UPDATE vps SET {assignments},updated_at=? WHERE container_id=?", values)
    finally:
        conn.close()


def db_set_vps_ipv4(container_id: str, ipv4: str | None) -> None:
    if ipv4 is not None and not valid_public_ipv4(ipv4):
        raise ValueError("Refusing to store a non-public IPv4 address.")
    db_update_vps(container_id, public_ipv4=ipv4, ipv4_verified_at=utc_now() if ipv4 else None)



def db_list_shared(vps_id: int) -> list[sqlite3.Row]:
    conn = db_connect()
    try:
        return conn.execute(
            """SELECT s.vps_id, s.user_id, s.shared_by, s.created_at,
                      COALESCE(u.username, CAST(s.user_id AS TEXT)) AS username
               FROM vps_shares s LEFT JOIN users u ON u.user_id=s.user_id
               WHERE s.vps_id=? ORDER BY s.created_at""",
            (int(vps_id),),
        ).fetchall()
    finally:
        conn.close()


def db_find_vps_by_ptero_identifier(identifier: str) -> sqlite3.Row | None:
    conn = db_connect()
    try:
        return conn.execute(
            "SELECT * FROM vps WHERE ptero_identifier=? OR container_id=? LIMIT 1",
            (identifier, identifier),
        ).fetchone()
    finally:
        conn.close()


def db_insert_snapshot(vps_id: int, name: str, image_ref: str) -> int:
    conn = db_connect()
    try:
        cur = conn.execute(
            "INSERT INTO vps_snapshots(vps_id,name,image_ref,created_at) VALUES(?,?,?,?)",
            (int(vps_id), name, image_ref, utc_now()),
        )
        return int(cur.lastrowid)
    finally:
        conn.close()


def db_list_snapshots(vps_id: int) -> list[sqlite3.Row]:
    conn = db_connect()
    try:
        return conn.execute(
            "SELECT * FROM vps_snapshots WHERE vps_id=? ORDER BY id DESC",
            (int(vps_id),),
        ).fetchall()
    finally:
        conn.close()


def db_get_snapshot(vps_id: int, name: str) -> sqlite3.Row | None:
    conn = db_connect()
    try:
        return conn.execute(
            "SELECT * FROM vps_snapshots WHERE vps_id=? AND lower(name)=lower(?)",
            (int(vps_id), name),
        ).fetchone()
    finally:
        conn.close()


def db_delete_all_snapshots(vps_id: int) -> None:
    conn = db_connect()
    try:
        conn.execute("DELETE FROM vps_snapshots WHERE vps_id=?", (int(vps_id),))
    finally:
        conn.close()


def db_delete_snapshot(vps_id: int, name: str) -> None:
    conn = db_connect()
    try:
        conn.execute("DELETE FROM vps_snapshots WHERE vps_id=? AND lower(name)=lower(?)", (int(vps_id), name))
    finally:
        conn.close()


def db_delete_vps(container_id: str) -> None:
    conn = db_connect()
    try:
        conn.execute("DELETE FROM vps WHERE container_id=?", (container_id,))
    finally:
        conn.close()


# ================================================================
# Process/Docker execution
# ================================================================

async def run_process(*args: str, timeout: float = 60, stdin: bytes | None = None) -> tuple[int, bytes, bytes]:
    try:
        process = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
    except FileNotFoundError as exc:
        return 127, b"", str(exc).encode()
    except OSError as exc:
        return 126, b"", str(exc).encode()

    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(stdin), timeout=timeout)
        return process.returncode if process.returncode is not None else -1, stdout, stderr
    except asyncio.TimeoutError:
        with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
            os.killpg(process.pid, signal.SIGKILL)
        with contextlib.suppress(Exception):
            await asyncio.wait_for(process.wait(), timeout=5)
        return -1, b"", b"process timeout"
    except asyncio.CancelledError:
        # A cancelled Docker operation must not leave a live child process behind.
        with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
            os.killpg(process.pid, signal.SIGKILL)
        with contextlib.suppress(Exception):
            await asyncio.wait_for(process.wait(), timeout=5)
        raise


async def docker_cli(*args: str, timeout: float = DOCKER_TIMEOUT, retries: int = 0) -> tuple[int, bytes, bytes]:
    last: tuple[int, bytes, bytes] = (126, b"", b"docker command failed")
    for attempt in range(max(0, retries) + 1):
        last = await run_process("docker", *args, timeout=timeout)
        if last[0] == 0:
            return last
        text = last[2].decode("utf-8", "replace").lower()
        transient = any(x in text for x in ("connection reset", "temporarily unavailable", "i/o timeout", "context deadline exceeded", "connection refused", "tls handshake timeout", "unexpected eof", "eof"))
        if not transient or attempt >= retries:
            break
        await asyncio.sleep(1.5 * (attempt + 1))
    return last


async def spawn_detached(*args: str) -> tuple[int | None, str]:
    try:
        proc = await asyncio.create_subprocess_exec(*args, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL, start_new_session=True)
        await asyncio.sleep(0.15)
        if proc.returncode is not None:
            return None, f"process exited with code {proc.returncode}"
        return proc.pid, ""
    except FileNotFoundError:
        return None, f"{args[0]} is not installed."
    except OSError as exc:
        return None, str(exc)


# ================================================================
# QEMU real VM backend — TCG only, no KVM required
# ================================================================

def qemu_vm_dir(vm_id: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(vm_id)).strip("-._") or "vm"
    return QEMU_VM_ROOT / safe


def qemu_meta_path(vm_id: str) -> Path:
    return qemu_vm_dir(vm_id) / "vm.json"


def qemu_load_meta(vm_id: str) -> dict[str, Any] | None:
    try:
        data = json.loads(qemu_meta_path(vm_id).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None


def qemu_save_meta(vm_id: str, data: dict[str, Any]) -> None:
    directory = qemu_vm_dir(vm_id)
    directory.mkdir(parents=True, exist_ok=True)
    temp = directory / "vm.json.tmp"
    temp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    temp.replace(qemu_meta_path(vm_id))


def qemu_process_alive(pid: int | str | None) -> bool:
    try:
        number = int(pid or 0)
        if number <= 1:
            return False
        os.kill(number, 0)
        cmdline = Path(f"/proc/{number}/cmdline")
        if cmdline.exists():
            text = cmdline.read_bytes().replace(b"\x00", b" ").decode("utf-8", "replace")
            if "qemu-system" not in text.lower():
                return False
        return True
    except (OSError, ValueError):
        return False


def qemu_binary() -> str | None:
    return shutil.which("qemu-system-x86_64")


def qemu_seed_builder() -> str | None:
    return shutil.which("cloud-localds") or shutil.which("genisoimage") or shutil.which("xorriso")


def qemu_os_from_image(image: str) -> str | None:
    value = str(image or "").lower()
    mapping = {
        "ubuntu-22.04": ("ubuntu:22.04", "jammy"),
        "ubuntu-24.04": ("ubuntu:24.04", "noble"),
        "ubuntu-26.04": ("ubuntu:26.04", "resolute"),
        "debian-11": ("debian:11", "bullseye"),
        "debian-12": ("debian:12", "bookworm"),
        "debian-13": ("debian:13", "trixie"),
    }
    for os_name, tokens in mapping.items():
        if any(token in value for token in tokens):
            return os_name
    return None


async def qemu_host_prepare(progress: Callable[[str], Awaitable[None]] | None = None) -> tuple[bool, str]:
    QEMU_VM_ROOT.mkdir(parents=True, exist_ok=True)
    QEMU_IMAGE_CACHE.mkdir(parents=True, exist_ok=True)

    def missing_tools() -> list[str]:
        missing: list[str] = []
        if not qemu_binary():
            missing.append("qemu-system-x86_64")
        if not shutil.which("qemu-img"):
            missing.append("qemu-img")
        if not qemu_seed_builder():
            missing.append("cloud-localds/genisoimage/xorriso")
        if not shutil.which("ssh"):
            missing.append("ssh client")
        if not shutil.which("ssh-keygen"):
            missing.append("ssh-keygen")
        return missing

    missing = missing_tools()
    if not missing:
        return True, "QEMU TCG host tools are ready; KVM is disabled and never used."

    if progress is not None:
        with contextlib.suppress(Exception):
            await progress("Installing missing QEMU host tools")

    if not QEMU_AUTO_INSTALL_HOST_TOOLS:
        return False, "Missing QEMU host tools: " + ", ".join(missing) + "."

    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return False, (
            "Missing QEMU host tools: " + ", ".join(missing) +
            ". Automatic installation requires root; install QEMU system emulator, "
            "qemu-img, a NoCloud ISO builder (cloud-localds/genisoimage/xorriso), "
            "and OpenSSH client on the host."
        )

    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"

    async def install_with(manager: str, packages: list[str]) -> bool:
        try:
            if manager == "apt-get":
                rc, _, _ = await run_process(
                    "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "update", "-y", timeout=300
                )
                if rc != 0:
                    return False
                rc, _, _ = await run_process(
                    "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y",
                    "-o", "Dpkg::Options::=--force-confdef",
                    "-o", "Dpkg::Options::=--force-confold",
                    "--no-install-recommends", *packages, timeout=900
                )
                return rc == 0
            if manager in {"dnf", "yum"}:
                rc, _, _ = await run_process(manager, "-y", "install", *packages, timeout=900)
                return rc == 0
            if manager == "apk":
                rc, _, _ = await run_process(manager, "add", "--no-cache", *packages, timeout=900)
                return rc == 0
            if manager == "pacman":
                rc, _, _ = await run_process(manager, "-Sy", "--noconfirm", *packages, timeout=900)
                return rc == 0
        except Exception as exc:
            logger.warning("QEMU host package installation failed via %s: %s", manager, safe_log(exc))
        return False

    if progress is not None:
        with contextlib.suppress(Exception):
            await progress("Detecting host package manager")

    if shutil.which("apt-get"):
        await install_with("apt-get", [
            "qemu-system-x86", "qemu-utils", "cloud-image-utils", "genisoimage", "xorriso", "openssh-client",
        ])
    elif shutil.which("dnf"):
        await install_with("dnf", ["qemu-system-x86-core", "qemu-img", "xorriso", "openssh-clients"])
    elif shutil.which("yum"):
        await install_with("yum", ["qemu-system-x86-core", "qemu-img", "xorriso", "openssh-clients"])
    elif shutil.which("apk"):
        await install_with("apk", ["qemu-system-x86_64", "qemu-img", "xorriso", "openssh-client"])
    elif shutil.which("pacman"):
        await install_with("pacman", ["qemu-desktop", "qemu-img", "xorriso", "openssh"])

    missing = missing_tools()
    if missing:
        return False, "Missing QEMU host tools after installation attempt: " + ", ".join(missing) + "."
    return True, "QEMU TCG host tools are ready; KVM is disabled and never used."


async def qemu_download_base(os_type: str) -> tuple[bool, str, Path | None]:
    url = QEMU_IMAGE_URLS.get(os_type)
    if not url:
        return False, f"No official QEMU image is configured for {os_type}.", None
    target = QEMU_IMAGE_CACHE / re.sub(r"[^A-Za-z0-9_.-]+", "-", url.rsplit("/", 1)[-1])
    if target.exists() and target.stat().st_size > 1024 * 1024:
        rc, _, _ = await run_process("qemu-img", "info", str(target), timeout=30)
        if rc == 0:
            return True, "", target
    partial = target.with_suffix(target.suffix + ".part")
    with contextlib.suppress(OSError):
        partial.unlink()
    rc, _, err = await run_process(
        "curl", "-fL", "--retry", "3", "--retry-delay", "2",
        "--connect-timeout", "20", "--max-time", "900", "-o", str(partial),
        url, timeout=930,
    )
    if rc != 0:
        with contextlib.suppress(OSError):
            partial.unlink()
        return False, safe_log(err.decode("utf-8", "replace").strip() or "QEMU image download failed."), None
    rc, _, err = await run_process("qemu-img", "info", str(partial), timeout=30)
    if rc != 0:
        with contextlib.suppress(OSError):
            partial.unlink()
        return False, safe_log(err.decode("utf-8", "replace").strip() or "Downloaded QEMU image is invalid."), None
    partial.replace(target)
    return True, "", target


def qemu_free_port() -> int | None:
    reserved: set[int] = set()
    with contextlib.suppress(OSError):
        for child in QEMU_VM_ROOT.iterdir():
            if not child.is_dir() or child.name == "_images":
                continue
            meta = qemu_load_meta(child.name)
            if meta and qemu_process_alive(meta.get("pid")):
                with contextlib.suppress(TypeError, ValueError):
                    reserved.add(int(meta.get("ssh_port", 0)))
    for port in range(QEMU_SSH_PORT_START, QEMU_SSH_PORT_END + 1):
        if port in reserved:
            continue
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("127.0.0.1", port))
            return port
        except OSError:
            continue
    return None


def qemu_cloud_config(hostname: str, pubkey: str) -> str:
    return f"""#cloud-config
users:
  - default
  - name: {QEMU_SSH_USER}
    gecos: RGNODES
    groups: [sudo]
    sudo: ["ALL=(ALL) NOPASSWD:ALL"]
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - {pubkey.strip()}
ssh_pwauth: false
write_files:
  - path: /etc/ssh/sshd_config.d/99-rgnodes.conf
    permissions: '0644'
    content: |
      PasswordAuthentication no
      PubkeyAuthentication yes
      PermitRootLogin prohibit-password
      UseDNS no
  - path: /usr/local/sbin/rgnodes-firstboot.sh
    permissions: '0755'
    content: |
      #!/bin/bash
      set +e
      mkdir -p /etc/rgnodes /var/lib/rgnodes
      export DEBIAN_FRONTEND=noninteractive
      if [ -f /etc/debian_version ]; then
        . /etc/os-release
        if [ "${{VERSION_CODENAME:-}}" = "bullseye" ]; then
          sed -i -E 's#https?://[^ ]*debian.org/debian#http://archive.debian.org/debian#g; s#https?://security.debian.org/debian-security#http://archive.debian.org/debian-security#g' /etc/apt/sources.list 2>/dev/null || true
          printf '%s\\n' 'Acquire::Check-Valid-Until "false";' >/etc/apt/apt.conf.d/99rgnodes-bullseye
        fi
      fi
      dpkg --configure -a -D777 >/var/log/rgnodes-dpkg.log 2>&1 || true
      apt-get update -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold >/var/log/rgnodes-apt-update.log 2>&1 || true
      apt-get install -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold curl ca-certificates sudo openssh-server bash coreutils procps >/var/log/rgnodes-base.log 2>&1 || true
      mkdir -p /run/sshd /var/run/sshd
      sshd -t >/var/log/rgnodes-sshd-test.log 2>&1 || true
      systemctl enable ssh.service >/dev/null 2>&1 || systemctl enable sshd.service >/dev/null 2>&1 || true
      systemctl restart ssh.service >/dev/null 2>&1 || systemctl restart sshd.service >/dev/null 2>&1 || true
      printf '%s\\n' 'ready=1' >/etc/rgnodes/.system-ready
      printf '%s\\n' 'accelerator=tcg' >/etc/rgnodes/virtualization
      touch /var/lib/rgnodes/cloud-init-complete
runcmd:
  - [bash, /usr/local/sbin/rgnodes-firstboot.sh]
final_message: 'RGNODES QEMU TCG VPS is ready.'
"""


async def qemu_build_seed(vm_id: str, hostname: str, pubkey: str) -> tuple[bool, str, Path | None]:
    directory = qemu_vm_dir(vm_id)
    directory.mkdir(parents=True, exist_ok=True)
    user_data = directory / "user-data"
    meta_data = directory / "meta-data"
    seed = directory / "seed.iso"
    user_data.write_text(qemu_cloud_config(hostname, pubkey), encoding="utf-8")
    meta_data.write_text(f"instance-id: rgnodes-{vm_id}\nlocal-hostname: {hostname}\n", encoding="utf-8")
    builder = qemu_seed_builder()
    if not builder:
        return False, "No cloud-init seed builder is installed.", None
    if Path(builder).name == "cloud-localds":
        rc, _, err = await run_process(builder, str(seed), str(user_data), str(meta_data), timeout=60)
    elif Path(builder).name == "genisoimage":
        rc, _, err = await run_process(builder, "-quiet", "-output", str(seed), "-volid", "CIDATA", "-joliet", "-rock", str(user_data), str(meta_data), timeout=60)
    else:
        rc, _, err = await run_process(builder, "-as", "mkisofs", "-quiet", "-o", str(seed), "-V", "CIDATA", "-J", "-R", str(user_data), str(meta_data), timeout=60)
    if rc != 0 or not seed.exists() or seed.stat().st_size < 4096:
        return False, safe_log(err.decode("utf-8", "replace").strip() or "Cloud-init seed creation failed."), None
    return True, "", seed


def qemu_command(meta: dict[str, Any], port_forwards: list[tuple[int, int]] | None = None, *, legacy_tcg: bool = False, machine: str | None = None) -> list[str]:
    net = f"user,id=net0,hostfwd=tcp:127.0.0.1:{int(meta['ssh_port'])}-:22"
    for host_port, guest_port in port_forwards or []:
        net += f",hostfwd=tcp:0.0.0.0:{int(host_port)}-:{int(guest_port)}"
    accel_args = ["-accel", "tcg"] if legacy_tcg else ["-accel", "tcg,thread=multi"]
    return [
        qemu_binary() or "qemu-system-x86_64",
        "-name", str(meta.get("name") or "rgnodes-vm"),
        "-machine", machine or str(meta.get("machine") or "q35"),
        *accel_args,
        "-cpu", "max",
        "-m", str(meta.get("ram") or "1G"),
        "-smp", str(meta.get("cpu") or "1"),
        "-boot", "order=c,menu=off",
        "-drive", f"file={meta['disk_path']},if=virtio,format=qcow2,cache=writeback,aio=threads",
        "-drive", f"file={meta['seed_path']},media=cdrom,readonly=on",
        "-netdev", net,
        "-device", "virtio-net-pci,netdev=net0",
        "-display", "none",
        "-serial", f"file:{meta['log_path']}",
        "-monitor", "none",
        "-no-reboot",
        "-daemonize",
        "-pidfile", str(meta["pid_path"]),
    ]


async def qemu_launch(vm_id: str, port_forwards: list[tuple[int, int]] | None = None) -> tuple[bool, str]:
    meta = qemu_load_meta(vm_id)
    if not meta:
        return False, "QEMU VM metadata is missing."
    if qemu_process_alive(meta.get("pid")):
        return True, ""
    with contextlib.suppress(OSError):
        Path(str(meta["pid_path"])).unlink()

    last_error = "QEMU failed to start."
    variants = [
        (False, str(meta.get("machine") or "q35")),
        (True, str(meta.get("machine") or "q35")),
        (True, "pc"),
    ]
    for legacy_tcg, machine in variants:
        rc, out, err = await run_process(
            *qemu_command(meta, port_forwards, legacy_tcg=legacy_tcg, machine=machine), timeout=60
        )
        combined = (err + out).decode("utf-8", "replace").strip()
        if rc != 0:
            last_error = safe_log(combined or "QEMU failed to start.")
            text = last_error.lower()
            if "address already in use" in text or "could not set up host forwarding" in text or "bind() failed" in text:
                return False, last_error
            continue
        await asyncio.sleep(1)
        try:
            pid = int(Path(str(meta["pid_path"])).read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            last_error = "QEMU started without producing a valid PID file."
            continue
        meta["pid"] = pid
        meta["machine"] = machine
        meta["tcg_legacy"] = legacy_tcg
        qemu_save_meta(vm_id, meta)
        if qemu_process_alive(pid):
            return True, ""
        last_error = "QEMU exited immediately; inspect the VM serial log."
    return False, last_error


async def qemu_create_vm(*, os_type: str, hostname: str, ram: str, cpu: str, disk: str, name: str, persistent_key: str | None = None) -> tuple[str | None, str]:
    normalized = normalize_os(os_type) or qemu_os_from_image(os_type)
    if not normalized:
        return None, f"Unsupported QEMU operating system: {os_type}"
    ok, detail = await qemu_host_prepare()
    if not ok:
        return None, detail
    base_ok, base_detail, base = await qemu_download_base(normalized)
    if not base_ok or base is None:
        return None, base_detail
    # qemu-img resolves a relative backing-file path relative to the new
    # overlay's directory. Always pass the canonical absolute path so an
    # overlay under <vm>/ does not accidentally become <vm>/<cache>/... .
    base = base.expanduser().resolve()
    if not base.is_file():
        return None, f"Base QEMU image is missing after download: {base}"

    vm_id = "qemu-" + uuid.uuid4().hex[:24]
    directory = qemu_vm_dir(vm_id)
    directory.mkdir(parents=True, exist_ok=True)
    try:
        ssh_port = qemu_free_port()
        if not ssh_port:
            raise RuntimeError("No free local SSH forwarding port is available.")

        priv = directory / "id_ed25519"
        pub = directory / "id_ed25519.pub"
        rc, _, err = await run_process(
            "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(priv), timeout=30
        )
        if rc != 0 or not pub.exists():
            raise RuntimeError(safe_log(err.decode("utf-8", "replace").strip() or "SSH key generation failed."))
        os.chmod(priv, 0o600)

        seed_ok, seed_detail, seed = await qemu_build_seed(
            vm_id, hostname, pub.read_text(encoding="utf-8").strip()
        )
        if not seed_ok or seed is None:
            raise RuntimeError(seed_detail or "Cloud-init seed creation failed.")

        disk_path = directory / "disk.qcow2"
        rc_info, out_info, _ = await run_process(
            "qemu-img", "info", "--output=json", str(base), timeout=30
        )
        backing_format = "qcow2"
        if rc_info == 0:
            with contextlib.suppress(ValueError, TypeError, json.JSONDecodeError):
                image_info = json.loads(out_info.decode("utf-8", "replace"))
                candidate = str(image_info.get("format") or "").strip().lower()
                if re.fullmatch(r"[a-z0-9_-]+", candidate):
                    backing_format = candidate
        rc, _, err = await run_process(
            "qemu-img", "create", "-f", "qcow2", "-F", backing_format, "-b", str(base),
            str(disk_path.resolve()), str(disk), timeout=120
        )
        if rc != 0:
            raise RuntimeError(safe_log(err.decode("utf-8", "replace").strip() or "VM disk creation failed."))

        # Validate the newly-created overlay before booting it.
        rc, _, err = await run_process("qemu-img", "check", "-f", "qcow2", str(disk_path.resolve()), timeout=120)
        if rc != 0:
            raise RuntimeError(safe_log(err.decode("utf-8", "replace").strip() or "VM disk validation failed."))

        meta = {
            "name": name, "hostname": hostname, "os_type": normalized,
            "ram": ram, "cpu": cpu, "disk": disk, "ssh_port": ssh_port,
            "ssh_user": QEMU_SSH_USER, "ssh_private_key": str(priv),
            "ssh_public_key": str(pub.resolve()), "disk_path": str(disk_path.resolve()),
            "seed_path": str(seed.resolve()), "log_path": str((directory / "serial.log").resolve()),
            "pid_path": str((directory / "qemu.pid").resolve()), "base_path": str(base),
            "accelerator": "tcg", "kvm": False,
            "persistent_key": str(persistent_key or name),
            "created_at": utc_now(), "pid": None, "machine": "q35",
        }
        qemu_save_meta(vm_id, meta)
        started, start_detail = await qemu_launch(vm_id)
        if not started:
            raise RuntimeError(start_detail or "QEMU VM failed to start.")
        return vm_id, ""
    except Exception as exc:
        with contextlib.suppress(Exception):
            await qemu_stop_vm(vm_id)
        with contextlib.suppress(OSError):
            shutil.rmtree(directory)
        return None, safe_log(exc)


async def qemu_ssh(vm_id: str, command: str, timeout: float = ACCESS_TIMEOUT) -> tuple[int, bytes, bytes]:
    meta = qemu_load_meta(vm_id)
    if not meta:
        return 1, b"", b"QEMU VM metadata is missing."
    port = int(meta.get("ssh_port", 0))
    priv = Path(str(meta.get("ssh_private_key", "")))
    user = str(meta.get("ssh_user") or QEMU_SSH_USER)
    if not port or not priv.exists():
        return 1, b"", b"QEMU VM SSH configuration is missing."
    return await run_process(
        "ssh", "-i", str(priv), "-p", str(port), "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10", "-o", "ConnectionAttempts=2",
        "-o", "IdentitiesOnly=yes", "-o", "PreferredAuthentications=publickey",
        "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2",
        f"{user}@127.0.0.1", "bash", "-lc", command, timeout=timeout,
    )


async def qemu_state(vm_id: str) -> str | None:
    meta = qemu_load_meta(vm_id)
    if not meta:
        return None
    return "running" if qemu_process_alive(meta.get("pid")) else "stopped"


async def qemu_stop_vm(vm_id: str) -> bool:
    meta = qemu_load_meta(vm_id)
    if not meta:
        return False
    pid = meta.get("pid")
    if not qemu_process_alive(pid):
        meta["pid"] = None
        qemu_save_meta(vm_id, meta)
        return True
    with contextlib.suppress(OSError, ValueError):
        os.kill(int(pid), signal.SIGTERM)
    for _ in range(30):
        if not qemu_process_alive(pid):
            meta["pid"] = None
            qemu_save_meta(vm_id, meta)
            return True
        await asyncio.sleep(0.5)
    with contextlib.suppress(OSError, ValueError):
        os.kill(int(pid), signal.SIGKILL)
    meta["pid"] = None
    qemu_save_meta(vm_id, meta)
    return True


async def qemu_remove_vm(vm_id: str) -> bool:
    await qemu_stop_vm(vm_id)
    try:
        shutil.rmtree(qemu_vm_dir(vm_id))
        return True
    except OSError:
        return False


def qemu_running_forwards(vps_id: int | None) -> list[tuple[int, int]]:
    if vps_id is None:
        return []
    forwards: list[tuple[int, int]] = []
    try:
        rows = db_list_ports(int(vps_id))
    except Exception:
        return forwards
    for row in rows:
        try:
            if str(row["protocol"]).lower() != "tcp":
                continue
            if str(row["status"]).lower() != "running":
                continue
            host_port = int(row["host_port"])
            guest_port = int(row["container_port"])
            if 1 <= host_port <= 65535 and 1 <= guest_port <= 65535:
                forwards.append((host_port, guest_port))
        except (TypeError, ValueError, KeyError):
            continue
    # Stable de-duplication protects QEMU from duplicate hostfwd definitions.
    return list(dict.fromkeys(forwards))


async def qemu_restart_vm(vm_id: str, vps_id: int | None = None) -> tuple[bool, str]:
    await qemu_stop_vm(vm_id)
    return await qemu_launch(vm_id, qemu_running_forwards(vps_id))


async def _wait_qemu_ready(container: str) -> tuple[bool, str]:
    deadline = asyncio.get_running_loop().time() + QEMU_BOOT_TIMEOUT
    last = "Waiting for the real VM to boot and cloud-init to finish."
    while asyncio.get_running_loop().time() < deadline:
        if await qemu_state(container) != "running":
            meta = qemu_load_meta(container) or {}
            log_path = Path(str(meta.get("log_path", "")))
            text = ""
            if log_path.exists():
                with contextlib.suppress(OSError):
                    text = "\n".join(log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-80:])
            return False, "QEMU VM stopped during boot." + (("\nSerial log:\n" + safe_log(text, 3000)) if text else "")
        ok, detail = await guest_system_ready(container)
        if ok:
            return True, detail
        last = detail
        await asyncio.sleep(3)
    return False, f"QEMU VPS readiness timed out after {QEMU_BOOT_TIMEOUT}s. Last check: {last}"


async def docker_exists(container: str) -> bool:
    if qemu_load_meta(container):
        return True
    rc, _, _ = await docker_cli("inspect", container, timeout=20, retries=1)
    return rc == 0


async def docker_state(container: str) -> str | None:
    if qemu_load_meta(container):
        return await qemu_state(container)
    rc, out, _ = await docker_cli("inspect", "-f", "{{.State.Status}}", container, timeout=20, retries=1)
    if rc != 0:
        return None
    return out.decode("utf-8", "replace").strip().lower() or None


async def _wait_for_docker_ready(timeout: float = 30.0) -> tuple[bool, str]:
    deadline = asyncio.get_running_loop().time() + max(5.0, timeout)
    last_detail = "Docker daemon is not ready."
    while asyncio.get_running_loop().time() < deadline:
        ok, detail = await _probe_docker_info()
        if ok:
            return True, detail
        last_detail = detail
        await asyncio.sleep(1.0)
    return False, last_detail


async def _start_docker_daemon() -> tuple[bool, str]:
    """Start an existing Docker daemon without assuming systemd is PID 1."""
    if not command_available("docker"):
        return False, "Docker CLI is not installed."

    ok, detail = await _probe_docker_info()
    if ok:
        return True, "Docker daemon is already reachable."

    attempts: list[str] = []

    # systemd hosts
    if command_available("systemctl"):
        rc, out, err = await system_command("systemctl", "start", "docker.service", timeout=60)
        attempts.append(f"systemctl start docker.service: {('ok' if rc == 0 else safe_log(err.strip() or out.strip() or 'failed'))}")
        ok, detail = await _wait_for_docker_ready(15)
        if ok:
            if command_available("systemctl"):
                await system_command("systemctl", "enable", "docker.service", timeout=30)
            return True, "Docker daemon started with systemd."

    # SysV/service-managed hosts
    if command_available("service"):
        rc, out, err = await system_command("service", "docker", "start", timeout=60)
        attempts.append(f"service docker start: {('ok' if rc == 0 else safe_log(err.strip() or out.strip() or 'failed'))}")
        ok, detail = await _wait_for_docker_ready(15)
        if ok:
            return True, "Docker daemon started with service management."

    # Alpine/OpenRC hosts
    if command_available("rc-service"):
        rc, out, err = await system_command("rc-service", "docker", "start", timeout=60)
        attempts.append(f"rc-service docker start: {('ok' if rc == 0 else safe_log(err.strip() or out.strip() or 'failed'))}")
        ok, detail = await _wait_for_docker_ready(15)
        if ok:
            return True, "Docker daemon started with OpenRC."

    # Last resort for a real Linux host where dockerd exists but no init system
    # is available (common in minimal rescue images). Only attempt this as root.
    dockerd = shutil.which("dockerd")
    if dockerd and hasattr(os, "geteuid") and os.geteuid() == 0:
        socket_path = "/var/run/docker.sock"
        Path(socket_path).parent.mkdir(parents=True, exist_ok=True)
        # Avoid starting a second daemon if another dockerd is already alive.
        existing = False
        try:
            rc, out, _ = await system_command("pgrep", "-x", "dockerd", timeout=10)
            existing = rc == 0 and bool(out.strip())
        except Exception:
            existing = False
        if not existing:
            pid, error = await spawn_detached(
                dockerd,
                "--host=unix:///var/run/docker.sock",
                "--host=fd://",
            )
            # Some dockerd builds reject fd:// when no socket activation exists;
            # if that happens, retry with the explicit Unix socket only.
            if not pid:
                pid, error = await spawn_detached(dockerd, "--host=unix:///var/run/docker.sock")
            attempts.append(f"dockerd direct start: {('started' if pid else error or 'failed')}")
        else:
            attempts.append("dockerd process already exists")
        ok, detail = await _wait_for_docker_ready(20)
        if ok:
            return True, "Docker daemon started directly."

    return False, (
        "Docker CLI is installed, but the Docker daemon is not reachable. "
        + safe_log(detail)
        + (" Attempts: " + " | ".join(attempts) if attempts else "")
        + " This host must provide a running Docker daemon/socket."
    )


async def docker_info() -> tuple[bool, str]:
    """Return readiness for the active VM backend."""
    if active_backend() == "qemu":
        return await qemu_host_prepare()
    if not command_available("docker"):
        return False, (
            "Docker CLI is not installed. Run `/install-system confirm:true` "
            "as an administrator on a host where Docker is supported."
        )

    ok, detail = await _probe_docker_info()
    if ok:
        return True, detail

    if MANAGE_DOCKER_DAEMON:
        started, start_detail = await _start_docker_daemon()
        if started:
            return True, start_detail
        return False, start_detail or detail

    return False, (
        "Docker CLI is installed, but the Docker daemon is not reachable. "
        "RGNODES will not start/reconfigure the host daemon automatically. "
        + safe_log(detail)
    )


async def docker_running_count() -> tuple[bool, int]:
    if active_backend() == "qemu":
        count = 0
        try:
            for child in QEMU_VM_ROOT.iterdir():
                if child.is_dir() and child.name != "_images":
                    meta_path = child / "vm.json"
                    if not meta_path.exists():
                        continue
                    try:
                        data = json.loads(meta_path.read_text(encoding="utf-8"))
                    except (OSError, ValueError, TypeError, json.JSONDecodeError):
                        continue
                    if qemu_process_alive(data.get("pid")):
                        count += 1
            return True, count
        except OSError as exc:
            return False, db_running_count()
    # Do not depend only on labels: older Docker clients may not advertise --label.
    # The RGNODES namespace is the canonical container-name prefix as well.
    rc, out, _ = await docker_cli("ps", "--format", "{{.ID}}\t{{.Names}}", timeout=20, retries=1)
    if rc != 0:
        return False, db_running_count()
    count = 0
    for line in out.decode("utf-8", "replace").splitlines():
        parts = line.strip().split("\t", 1)
        if len(parts) == 2 and re.fullmatch(r"rgnodes-\d+", parts[1].strip(), flags=re.I):
            count += 1
    return True, count


async def docker_pull(image: str) -> tuple[bool, str]:
    if active_backend() == "qemu":
        os_name = qemu_os_from_image(image)
        if not os_name:
            return False, f"Unsupported QEMU image mapping: {image}"
        ok, detail, _ = await qemu_download_base(os_name)
        return ok, detail
    rc, _, err = await docker_cli("pull", image, timeout=IMAGE_PULL_TIMEOUT, retries=2)
    if rc == 0:
        return True, ""
    return False, safe_log(err.decode("utf-8", "replace").strip() or "Docker image pull failed.")


def quota_error(text: str) -> bool:
    lowered = text.lower()
    return any(term in lowered for term in ("storage-opt", "disk quota", "quota", "btrfs", "overlay2", "storage driver"))


DOCKER_RUN_FEATURES: set[str] | None = None
DOCKER_FEATURE_LOCK = asyncio.Lock()


async def docker_run_features() -> set[str]:
    global DOCKER_RUN_FEATURES
    if DOCKER_RUN_FEATURES is not None:
        return DOCKER_RUN_FEATURES
    async with DOCKER_FEATURE_LOCK:
        if DOCKER_RUN_FEATURES is not None:
            return DOCKER_RUN_FEATURES
        features: set[str] = set()
        rc, out, _ = await docker_cli("run", "--help", timeout=20, retries=0)
        if rc == 0:
            text = out.decode("utf-8", "replace")
            for flag in (
                "--init", "--pids-limit", "--storage-opt", "--cpus",
                "--memory", "--memory-reservation", "--memory-swap",
                "--memory-swappiness", "--restart", "--hostname", "--name",
                "--label", "--log-driver", "--log-opt", "--privileged",
                "--tmpfs", "--mount", "--device", "--cgroupns",
                "--security-opt", "--stop-signal",
            ):
                if flag in text:
                    features.add(flag)
        DOCKER_RUN_FEATURES = features
        logger.info("Docker run capabilities detected: %s", ", ".join(sorted(features)) or "basic-only")
        return features


def feature_error(text: str) -> bool:
    lowered = text.lower()
    return any(term in lowered for term in (
        "unknown flag", "unknown option", "invalid option", "not supported",
        "not supported by this daemon", "no such option", "unrecognized option",
    ))


GUEST_BOOTSTRAP_SCRIPT = r"""#!/bin/bash
set -Eeuo pipefail
BOOTSTRAP_LOG=/var/lib/rgnodes/bootstrap.log
mkdir -p /var/lib/rgnodes
exec 3>>"$BOOTSTRAP_LOG"
log_bootstrap_error() { rc=$?; printf '[RGNODES guest] bootstrap command failed rc=%s line=%s\n' "$rc" "${BASH_LINENO[0]:-0}" >&3; }
trap log_bootstrap_error ERR
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
# Prevent apt helper calls from trying to control services before PID 1 is
# systemd. This variable must never be inherited by the final systemd process.
export SYSTEMD_OFFLINE=1

MARKER=/etc/rgnodes/.system-ready
BOOTSTRAP_MARKER=/etc/rgnodes/.bootstrap-installed
# Persistent VPS data lives in named Docker volumes. docker rm (without -v)
# does not delete these volumes, allowing reinstall/recreate to reattach them.
PERSISTENCE_POLICY=/var/lib/rgnodes/persistence-policy
mkdir -p /var/lib/rgnodes /etc/rgnodes /etc/ssh /etc/systemd/system
printf 'named-volumes=enabled\ncontainer-delete=preserve-volumes\n' >"$PERSISTENCE_POLICY"

log() { printf '[RGNODES guest] %s\\n' "$*"; }

# Packages are installed with service auto-start disabled. Services are started
# later by systemd after PID 1 has actually become systemd.
install_policy() {
    cat >/usr/sbin/policy-rc.d <<'EOF'
#!/bin/sh
exit 101
EOF
    chmod 0755 /usr/sbin/policy-rc.d
}
remove_policy() { rm -f /usr/sbin/policy-rc.d; }

prepare_apt_sources() {
    local id codename backup_dir f
    id="$(. /etc/os-release && printf '%s' "${ID:-}")"
    codename="$(. /etc/os-release && printf '%s' "${VERSION_CODENAME:-}")"

    # A single non-interactive APT/Dpkg policy applies to every supported OS.
    # This is critical when /etc contains persistent files from an earlier
    # installation: dpkg must never wait for stdin on a conffile question.
    cat >/etc/apt/apt.conf.d/99rgnodes-noninteractive <<'EOF'
Dpkg::Options {
  "--force-confdef";
  "--force-confold";
};
Dpkg::Use-Pty "0";
APT::Get::Assume-Yes "true";
Acquire::Retries "3";
EOF
    export APT_LISTCHANGES_FRONTEND=none
    export UCF_FORCE_CONFOLD=1
    export UCF_FORCE_CONFFNEW=0

    # Override apt-get inside this bootstrap so every package operation receives
    # the same conffile policy, including operations in later helper functions.
    apt-get() {
        command apt-get \
            -o Dpkg::Options::=--force-confdef \
            -o Dpkg::Options::=--force-confold \
            -o Dpkg::Use-Pty=0 \
            "$@"
    }

    # Debian 11 is archived. Disable stale third-party sources and use the
    # coherent Bullseye archive snapshot instead of mixing repositories.
    if [ "$id" = "debian" ] && [ "$codename" = "bullseye" ]; then
        backup_dir=/etc/apt/rgnodes-disabled-sources
        mkdir -p "$backup_dir"
        if [ -f /etc/apt/sources.list ]; then
            cp -an /etc/apt/sources.list "$backup_dir/sources.list.base" || true
        fi
        for f in /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
            [ -f "$f" ] || continue
            mv -f "$f" "$backup_dir/$(basename "$f").disabled" || true
        done
        # Bullseye base repositories are archived. Do not use Bullseye security
        # metadata here: it became inconsistent after Bullseye LTS ended in 2026
        # and can advertise package files that are no longer published. The base
        # Debian 11.11 image already contains a coherent root filesystem; this
        # source is used only for packages that are still present in the archive.
        cat >/etc/apt/sources.list <<'EOF'
deb http://archive.debian.org/debian bullseye main contrib non-free
deb http://archive.debian.org/debian bullseye-updates main contrib non-free
EOF
        cat >/etc/apt/apt.conf.d/99rgnodes-bullseye-archive <<'EOF'
Acquire::Check-Valid-Until "false";
Acquire::AllowInsecureRepositories "true";
Acquire::Retries "5";
APT::Get::Update::Error-Mode "any";
EOF
        log 'Debian 11 detected: using coherent archived Bullseye base/update repositories only.'
    fi

    # Never let stale package lists from a previous image win over the current
    # OS repositories. This keeps Ubuntu/Debian upgrades coherent as well.
    rm -rf /var/lib/apt/lists/*
    apt-get update -y || return 1
}

apt_install_base() {
    apt_retry() {
        local tries=0
        while :; do
            tries=$((tries + 1))
            if "$@"; then return 0; fi
            if [ "$tries" -ge 4 ]; then return 1; fi
            log "APT operation failed; retry $tries/3"
            sleep $((tries * 2))
        done
    }

    prepare_apt_sources || {
        echo 'Guest APT repository setup failed.' >&2
        return 1
    }

    local id codename
    id="$(. /etc/os-release && printf '%s' "${ID:-}")"
    codename="$(. /etc/os-release && printf '%s' "${VERSION_CODENAME:-}")"

    # Finish interrupted unpack/configure operations, but never let dpkg ask for
    # a conffile answer from stdin. This matters with persistent /etc/ssh data.
    dpkg --force-confdef --force-confold --configure -a || true
    dpkg --audit >&2 || true

    # Debian 11 can enter bootstrap with an old gnupg package paired with a newer
    # gpgv package. Because Bullseye's post-LTS security metadata is inconsistent,
    # trying to repair that pair through the security repository can make the
    # dependency graph strictly worse. The VPS does not need the gnupg frontend to
    # boot systemd, and all repository helpers below can use ASCII-armored keys.
    if [ "$id" = "debian" ] && [ "$codename" = "bullseye" ]; then
        # The failing Bullseye state seen in the field is a mixed gnupg/gpgv pair.
        # Keep gpgv because APT needs it, but remove only the optional GnuPG
        # front-end packages. No systemd boot dependency requires them, and all
        # third-party repository helpers below use signed ASCII/binary key files
        # directly instead of invoking the gpg frontend.
        for pkg in gnupg gnupg2 gpg gpg-agent gpgconf gpgsm dirmngr gnupg-utils gnupg-l10n gpg-wks-client gpg-wks-server; do
            dpkg --remove --force-depends --force-remove-reinstreq "$pkg" >/dev/null 2>&1 || true
        done
        log 'Debian 11: removed potentially inconsistent GnuPG frontend packages; retaining gpgv for APT.'
    fi

    local essential="systemd systemd-sysv libsystemd0 dbus dbus-user-session init-system-helpers ca-certificates curl wget gpgv lsb-release bash coreutils procps psmisc iproute2 iputils-ping util-linux sudo openssh-client openssh-server tar gzip unzip xz-utils zip rsync acl openssl locales logrotate"
    # Avoid a broad full-upgrade during guest creation. It is unnecessary for a
    # fresh OS image and can introduce cross-suite dependency conflicts.
    if ! apt_retry apt-get install -y --no-install-recommends --allow-downgrades --allow-change-held-packages $essential; then
        dpkg --force-confdef --force-confold --configure -a || true
        apt_retry apt-get -f install -y --allow-downgrades --allow-change-held-packages || true
        apt_retry apt-get install -y --no-install-recommends --allow-downgrades --allow-change-held-packages \
            systemd systemd-sysv libsystemd0 dbus dbus-user-session init-system-helpers \
            ca-certificates curl wget gpgv openssh-client openssh-server || {
            echo 'Essential guest package installation failed: systemd/SSH could not be installed.' >&2
            apt-cache policy systemd systemd-sysv libsystemd0 gnupg gpgv >&2 || true
            return 1
        }
    fi

    command -v systemctl >/dev/null 2>&1 || {
        echo 'systemctl is still unavailable after APT repair.' >&2
        return 1
    }
    [ -x /lib/systemd/systemd ] || [ -x /usr/lib/systemd/systemd ] || {
        echo 'systemd binary is missing after APT repair.' >&2
        return 1
    }

    apt_retry apt-get install -y --no-install-recommends --allow-downgrades \
        iptables nftables net-tools netcat-openbsd socat jq git \
        build-essential pkg-config make gcc g++ python3 python3-pip python3-venv \
        systemd-container dbus-x11 systemd-timesyncd systemd-resolved \
        lsof htop tmux screen bash-completion || \
        log 'Optional base utilities were not all installed.'
}


install_web_and_database_stack() {
    [ "__WEB_STACK__" = "1" ] || return 0
    set +e
    local id codename
    id="$(. /etc/os-release && printf '%s' "${ID:-}")"
    codename="$(. /etc/os-release && printf '%s' "${VERSION_CODENAME:-}")"

    if [ "$id" = "ubuntu" ]; then
        case "$codename" in
            jammy|noble) LC_ALL=C.UTF-8 add-apt-repository -y ppa:ondrej/php >/dev/null 2>&1 || true ;;
            *) log "Using distro PHP packages on Ubuntu $codename" ;;
        esac
    elif [ "$id" = "debian" ]; then
        install -m 0755 -d /etc/apt/keyrings
        if curl -fsSL https://packages.sury.org/php/apt.gpg -o /etc/apt/keyrings/sury-php.gpg; then
            chmod 0644 /etc/apt/keyrings/sury-php.gpg
            printf 'deb [signed-by=/etc/apt/keyrings/sury-php.gpg] https://packages.sury.org/php/ %s main\n' "$codename" >/etc/apt/sources.list.d/php-sury.list
        fi
    fi

    if [ "$id" = "debian" ] && [ "$codename" = "bookworm" ]; then
        if curl -fsSL https://packages.redis.io/gpg -o /etc/apt/keyrings/redis-archive-keyring.asc; then
            chmod 0644 /etc/apt/keyrings/redis-archive-keyring.asc
            printf 'deb [signed-by=/etc/apt/keyrings/redis-archive-keyring.asc] https://packages.redis.io/deb %s main\n' "$codename" >/etc/apt/sources.list.d/redis.list
        fi
        if curl -fsSL https://r.mariadb.com/downloads/mariadb_repo_setup -o /tmp/mariadb_repo_setup; then
            chmod 0755 /tmp/mariadb_repo_setup
            /tmp/mariadb_repo_setup --skip-maxscale --skip-tools || true
            rm -f /tmp/mariadb_repo_setup
        fi
    elif [ "$id" = "debian" ] && [ "$codename" = "bullseye" ]; then
        # Stay entirely on archived Bullseye package metadata here. Debian 11's
        # distro MariaDB/Redis are preferable to introducing another repository
        # into a release whose security metadata is no longer maintained.
        rm -f /etc/apt/sources.list.d/php-sury.list /etc/apt/sources.list.d/redis.list 2>/dev/null || true
    fi

    apt-get update -y || {
        rm -f /etc/apt/sources.list.d/php-sury.list /etc/apt/sources.list.d/redis.list
        apt-get update -y || true
    }
    apt-get install -y --no-install-recommends nginx certbot python3-certbot-nginx \
        mariadb-server mariadb-client redis-server || log 'Web/database base packages were not fully installed.'

    if ! apt-get install -y --no-install-recommends \
        php8.3 php8.3-common php8.3-cli php8.3-gd php8.3-mysql \
        php8.3-mbstring php8.3-bcmath php8.3-xml php8.3-tokenizer \
        php8.3-fpm php8.3-curl php8.3-zip; then
        if ! apt-get install -y --no-install-recommends \
            php8.2 php8.2-common php8.2-cli php8.2-gd php8.2-mysql \
            php8.2-mbstring php8.2-bcmath php8.2-xml php8.2-tokenizer \
            php8.2-fpm php8.2-curl php8.2-zip; then
            apt-get install -y --no-install-recommends php php-common php-cli php-gd \
                php-mysql php-mbstring php-bcmath php-xml php-fpm php-curl php-zip \
                || log 'Compatible PHP package set could not be installed.'
        fi
    fi
    set -e
    return 0
}


install_docker_debian_ubuntu() {
    local id codename arch repo_url compose_arch
    id="$(. /etc/os-release && printf '%s' "${ID:-}")"
    codename="$(. /etc/os-release && printf '%s' "${VERSION_CODENAME:-}")"
    ubuntu_codename="$(. /etc/os-release && printf '%s' "${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}")"
    arch="$(dpkg --print-architecture)"
    case "$id" in
        ubuntu) repo_url='https://download.docker.com/linux/ubuntu' ;;
        debian) repo_url='https://download.docker.com/linux/debian' ;;
        *) repo_url='' ;;
    esac

    # Remove only conflicting package names. Never remove Docker data.
    apt-get remove -y docker.io docker-compose docker-compose-v2 docker-doc docker-buildx \
        podman-docker containerd runc >/dev/null 2>&1 || true

    if [ -n "$repo_url" ] && [ -n "$codename" ]; then
        install -m 0755 -d /etc/apt/keyrings
        repo_suite="$codename"
        [ "$id" = "ubuntu" ] && repo_suite="$ubuntu_codename"
        if curl -fsSL "https://download.docker.com/linux/$id/gpg" \
            -o /etc/apt/keyrings/docker.asc; then
            chmod a+r /etc/apt/keyrings/docker.asc
            cat >/etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: $repo_url
Suites: $repo_suite
Components: stable
Architectures: $arch
Signed-By: /etc/apt/keyrings/docker.asc
EOF
            if apt-get update -y && apt-get install -y --no-install-recommends \
                docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then
                return 0
            fi
        fi
        rm -f /etc/apt/sources.list.d/docker.sources
    fi

    apt-get update -y
    apt-get install -y --no-install-recommends docker.io containerd runc

    if ! docker compose version >/dev/null 2>&1; then
        apt-get install -y --no-install-recommends docker-compose-v2 docker-compose-plugin || true
    fi
    if ! docker compose version >/dev/null 2>&1; then
        apt-get install -y --no-install-recommends docker-compose-plugin || true
    fi
    if ! docker compose version >/dev/null 2>&1; then
        install -m 0755 -d /usr/local/lib/docker/cli-plugins
        compose_arch="$(uname -m)"
        case "$compose_arch" in
            x86_64|amd64) compose_arch='x86_64' ;;
            aarch64|arm64) compose_arch='aarch64' ;;
            *) compose_arch='' ;;
        esac
        if [ -n "$compose_arch" ]; then
            curl -fsSL \
                "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-${compose_arch}" \
                -o /usr/local/lib/docker/cli-plugins/docker-compose || true
            chmod 0755 /usr/local/lib/docker/cli-plugins/docker-compose 2>/dev/null || true
        fi
    fi
    docker compose version >/dev/null 2>&1
}

install_node_pm2_yarn() {
    local arch node_arch version tarball tmpdir
    arch="$(dpkg --print-architecture)"
    install -m 0755 -d /etc/apt/keyrings
    case "$arch" in
        amd64) node_arch='x64' ;;
        arm64) node_arch='arm64' ;;
        armhf) node_arch='armv7l' ;;
        ppc64el) node_arch='ppc64le' ;;
        s390x) node_arch='s390x' ;;
        *) node_arch='' ;;
    esac

    if [ -n "$node_arch" ] && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
        -o /etc/apt/keyrings/nodesource.asc; then
        chmod 0644 /etc/apt/keyrings/nodesource.asc
        cat >/etc/apt/sources.list.d/nodesource.sources <<EOF
Types: deb
URIs: https://deb.nodesource.com/node_20.x
Suites: nodistro
Components: main
Architectures: $arch
Signed-By: /etc/apt/keyrings/nodesource.asc
EOF
        apt-get update -y || true
    fi

    if ! apt-get install -y --no-install-recommends nodejs; then
        true
    fi

    if ! command -v node >/dev/null 2>&1 || ! node -e 'process.exit(process.versions.node.startsWith("20.") ? 0 : 1)'; then
        [ -n "$node_arch" ] || { echo "Unsupported Node.js architecture: $arch" >&2; return 1; }
        version="$(curl -fsSL https://nodejs.org/dist/index.tab | awk -v want='^v20\\.' '$1 ~ want && $0 !~ /-rc|-nightly|-test/ {print $1; exit}')"
        [ -n "$version" ] || { echo 'Could not resolve a stable Node.js 20 release.' >&2; return 1; }
        tarball="node-${version}-linux-${node_arch}.tar.xz"
        tmpdir="/tmp/rgnodes-node20"
        rm -rf "$tmpdir"
        mkdir -p "$tmpdir"
        curl -fsSL "https://nodejs.org/dist/${version}/${tarball}" -o "$tmpdir/$tarball"
        tar -xJf "$tmpdir/$tarball" -C "$tmpdir"
        rm -rf /opt/nodejs-20
        mv "$tmpdir/node-${version}-linux-${node_arch}" /opt/nodejs-20
        ln -sf /opt/nodejs-20/bin/node /usr/local/bin/node
        ln -sf /opt/nodejs-20/bin/npm /usr/local/bin/npm
        ln -sf /opt/nodejs-20/bin/npx /usr/local/bin/npx
        ln -sf /opt/nodejs-20/bin/corepack /usr/local/bin/corepack 2>/dev/null || true
        rm -rf "$tmpdir"
    fi

    node -e 'process.exit(process.versions.node.startsWith("20.") ? 0 : 1)'
    npm --version >/dev/null 2>&1
    npm install -g --no-audit --no-fund yarn@1.22.22 pm2
    command -v yarn >/dev/null 2>&1
    command -v pm2 >/dev/null 2>&1
}



install_composer() {
    local installer="/tmp/composer-setup.php" expected actual
    expected="$(curl -fsSL https://composer.github.io/installer.sig)"
    curl -fsSL https://getcomposer.org/installer -o "$installer"
    actual="$(php -r "echo hash_file('sha384', '$installer');")"
    [ -n "$expected" ] && [ "$actual" = "$expected" ] || {
        rm -f "$installer"
        echo 'Composer installer checksum verification failed.' >&2
        return 1
    }
    php "$installer" --install-dir=/usr/local/bin --filename=composer
    rm -f "$installer"
    chmod 0755 /usr/local/bin/composer
    composer --version --no-ansi | grep -Eq 'Composer version 2\.'
}

install_kvm_stack() {
    [ "__KVM_ENABLED__" = "1" ] || return 0
    log 'Installing QEMU/KVM/libvirt virtualization stack'
    set +e
    local arch qemu_pkg
    arch="$(dpkg --print-architecture 2>/dev/null || true)"
    qemu_pkg=""
    case "$arch" in
        amd64|i386) qemu_pkg='qemu-system-x86 qemu-kvm ovmf' ;;
        arm64|armhf) qemu_pkg='qemu-system-arm' ;;
        armel) qemu_pkg='qemu-system-arm' ;;
        ppc64el) qemu_pkg='qemu-system-ppc' ;;
        s390x) qemu_pkg='qemu-system-s390x' ;;
        riscv64) qemu_pkg='qemu-system-misc' ;;
        *) qemu_pkg='qemu-system-misc' ;;
    esac

    apt-get install -y --no-install-recommends \
        qemu-utils qemu-system-common qemu-system-data libvirt-daemon-system \
        libvirt-clients cloud-image-utils swtpm swtpm-tools cpu-checker \
        bridge-utils "$qemu_pkg" >/tmp/rgnodes-qemu-install.log 2>&1 || true

    command -v modprobe >/dev/null 2>&1 && modprobe kvm >/dev/null 2>&1 || true
    if [ "$arch" = "amd64" ] || [ "$arch" = "i386" ]; then
        command -v modprobe >/dev/null 2>&1 && \
            (modprobe kvm_intel >/dev/null 2>&1 || modprobe kvm_amd >/dev/null 2>&1 || true)
    fi

    mkdir -p /var/lib/rgnodes
    printf 'qemu_arch=%s\n' "$arch" >/var/lib/rgnodes/qemu-status
    if command -v qemu-img >/dev/null 2>&1; then
        tmp_qcow="/var/lib/rgnodes/.qemu-selftest.qcow2"
        if qemu-img create -f qcow2 "$tmp_qcow" 1M >/dev/null 2>&1; then
            printf 'qemu-img=selftest-ok\n' >>/var/lib/rgnodes/qemu-status
            rm -f "$tmp_qcow"
        else
            printf 'qemu-img=selftest-failed\n' >>/var/lib/rgnodes/qemu-status
        fi
    else
        printf 'qemu-img=missing\n' >>/var/lib/rgnodes/qemu-status
    fi
    if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
        printf 'kvm-device=available\n' >>/var/lib/rgnodes/qemu-status
        if command -v kvm-ok >/dev/null 2>&1 && kvm-ok >/tmp/rgnodes-kvm-ok.log 2>&1; then
            printf 'kvm-acceleration=available\n' >>/var/lib/rgnodes/qemu-status
        else
            printf 'kvm-acceleration=unverified\n' >>/var/lib/rgnodes/qemu-status
        fi
    else
        printf 'kvm-device=unavailable\n' >>/var/lib/rgnodes/qemu-status
        printf 'kvm-acceleration=unavailable\n' >>/var/lib/rgnodes/qemu-status
    fi

    # Enable libvirt only when the container really has /dev/kvm. Package
    # installation itself must not make the VPS fail on providers without KVM.
    if [ -e /dev/kvm ]; then
        systemctl enable libvirtd.service >/dev/null 2>&1 || true
        systemctl enable virtlogd.socket >/dev/null 2>&1 || true
        systemctl enable virtlockd.socket >/dev/null 2>&1 || true
        systemctl enable virtqemud.socket >/dev/null 2>&1 || true
    fi

    if [ -f /tmp/rgnodes-qemu-install.log ]; then
        tail -n 12 /tmp/rgnodes-qemu-install.log >&2 || true
    fi
    set -e
    return 0
}


install_wings() {
    [ "__INSTALL_WINGS__" = "1" ] || return 0
    local arch suffix url
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64) suffix='amd64' ;;
        aarch64|arm64) suffix='arm64' ;;
        *) log "Wings binary skipped: unsupported architecture $arch"; return 0 ;;
    esac
    mkdir -p /etc/pterodactyl /var/lib/pterodactyl /var/log/pterodactyl
    url="https://github.com/pterodactyl/wings/releases/latest/download/wings_linux_${suffix}"
    if curl -fsSL --retry 3 --retry-delay 2 "$url" -o /usr/local/bin/wings; then
        chmod 0755 /usr/local/bin/wings
        cat >/etc/systemd/system/wings.service <<'EOF'
[Unit]
Description=Pterodactyl Wings Daemon
Documentation=https://pterodactyl.io/wings/
After=docker.service network-online.target
Wants=network-online.target
Requires=docker.service
PartOf=docker.service

[Service]
User=root
WorkingDirectory=/etc/pterodactyl
LimitNOFILE=4096
PIDFile=/var/run/wings/daemon.pid
ExecStart=/usr/local/bin/wings
Restart=on-failure
StartLimitInterval=180
StartLimitBurst=30
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload >/dev/null 2>&1 || true
        # Do not start Wings until a real Panel-generated config.yml exists.
        systemctl disable wings.service >/dev/null 2>&1 || true
    else
        log 'Wings download failed; keeping the guest otherwise healthy'
    fi
}

repair_ssh() {
    mkdir -p /etc/ssh /var/run/sshd
    touch /etc/ssh/sshd_config
    chmod 0644 /etc/ssh/sshd_config
    grep -Eq '^[[:space:]]*Port[[:space:]]+' /etc/ssh/sshd_config \
        || printf '\nPort 22\n' >>/etc/ssh/sshd_config
    grep -Eq '^[[:space:]]*PermitRootLogin[[:space:]]+' /etc/ssh/sshd_config \
        || printf 'PermitRootLogin yes\n' >>/etc/ssh/sshd_config
    grep -Eq '^[[:space:]]*PasswordAuthentication[[:space:]]+' /etc/ssh/sshd_config \
        || printf 'PasswordAuthentication yes\n' >>/etc/ssh/sshd_config
    ssh-keygen -A >/dev/null 2>&1 || true
    sshd -t
}

install_firstboot_unit() {
    cat >/usr/local/sbin/rgnodes-firstboot-verify <<'EOF'
#!/bin/bash
set -Eeuo pipefail
mkdir -p /etc/rgnodes /var/lib/rgnodes
READY=/etc/rgnodes/.system-ready
rm -f "$READY"
systemctl daemon-reload

wait_active() {
    local unit="$1" tries="${2:-30}" i
    for ((i=1; i<=tries; i++)); do
        if systemctl is-active --quiet "$unit"; then return 0; fi
        systemctl start "$unit" >/dev/null 2>&1 || true
        sleep 1
    done
    systemctl status "$unit" --no-pager -l || true
    return 1
}

systemctl enable docker.service >/dev/null 2>&1 || true
systemctl enable ssh.service >/dev/null 2>&1 || systemctl enable sshd.service >/dev/null 2>&1 || true
wait_active docker.service 60
if systemctl cat ssh.service >/dev/null 2>&1; then
    wait_active ssh.service 30
elif systemctl cat sshd.service >/dev/null 2>&1; then
    wait_active sshd.service 30
else
    echo 'OpenSSH service unit not found.' >&2
    exit 25
fi

for unit in nginx.service redis-server.service mariadb.service; do
    if systemctl cat "$unit" >/dev/null 2>&1; then
        systemctl enable "$unit" >/dev/null 2>&1 || true
        wait_active "$unit" 45 || true
    fi
done

command -v systemctl >/dev/null
command -v docker >/dev/null
docker info >/dev/null 2>&1
docker compose version >/dev/null 2>&1
command -v node >/dev/null
command -v npm >/dev/null
command -v yarn >/dev/null
command -v pm2 >/dev/null
pm2 -v >/dev/null
sshd -t
command -v composer >/dev/null
composer --version --no-ansi | grep -Eq 'Composer version 2\.'
command -v php >/dev/null
php -r 'exit(version_compare(PHP_VERSION, "8.2", ">=") ? 0 : 1);'
for ext in curl dom fileinfo gd mbstring openssl pdo pdo_mysql tokenizer xml zip bcmath; do
    php -m | grep -iq "^$ext$" || { echo "missing PHP extension: $ext" >&2; exit 26; }
done
if systemctl list-unit-files 'php*-fpm.service' 2>/dev/null | grep -q 'php.*-fpm.service'; then
    php_unit="$(systemctl list-unit-files 'php*-fpm.service' --no-legend 2>/dev/null | awk 'NR==1{print $1}')"
    [ -n "$php_unit" ] && wait_active "$php_unit" 45 || true
fi

if command -v wings >/dev/null 2>&1; then
    wings --version >/dev/null 2>&1 || true
fi

# KVM is an optional acceleration capability. QEMU userspace is mandatory, but
# absence of /dev/kvm must not brick a VPS on hosts that do not expose nesting.
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    printf 'kvm=device-present\n' >/var/lib/rgnodes/kvm-status
    if command -v kvm-ok >/dev/null 2>&1 && kvm-ok >/dev/null 2>&1; then
        printf 'acceleration=kvm\n' >>/var/lib/rgnodes/kvm-status
    else
        printf 'acceleration=unverified\n' >>/var/lib/rgnodes/kvm-status
    fi
else
    printf 'kvm=device-unavailable\n' >/var/lib/rgnodes/kvm-status
    printf 'acceleration=tcg\n' >>/var/lib/rgnodes/kvm-status
fi
qemu_ok=0
for qemu_bin in qemu-system-x86_64 qemu-system-aarch64 qemu-system-ppc64 qemu-system-ppc qemu-system-s390x qemu-system-riscv64; do
    if command -v "$qemu_bin" >/dev/null 2>&1 && "$qemu_bin" --version >/dev/null 2>&1; then
        qemu_ok=1
        break
    fi
done
[ "$qemu_ok" -eq 1 ] || {
    echo 'No working QEMU system emulator was installed.' >&2
    exit 27
}

printf 'ready=1\n' >"$READY"
EOF
    chmod 0755 /usr/local/sbin/rgnodes-firstboot-verify

    cat >/etc/systemd/system/rgnodes-firstboot.service <<'EOF'
[Unit]
Description=RGNODES Guest First Boot Verification
Wants=docker.service ssh.service network-online.target
After=docker.service ssh.service network-online.target
ConditionPathExists=!/etc/rgnodes/.system-ready

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/rgnodes-firstboot-verify
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    ln -sf ../rgnodes-firstboot.service \
        /etc/systemd/system/multi-user.target.wants/rgnodes-firstboot.service
}

if command -v apt-get >/dev/null 2>&1; then
    if [ ! -f "$BOOTSTRAP_MARKER" ]; then
        install_policy
        trap remove_policy EXIT
        log 'Installing base Linux/systemd/SSH dependencies'
        apt_install_base
        if ! install_docker_debian_ubuntu; then log 'Docker installation failed; systemd will still boot for recovery.'; fi
        if ! install_node_pm2_yarn; then log 'Node.js/PM2/Yarn installation failed; continuing to systemd.'; fi
        install_web_and_database_stack || log 'Web/database stack provisioning failed; continuing to systemd.'
        if ! install_composer; then log 'Composer installation failed; continuing to systemd.'; fi
        install_kvm_stack || log 'KVM/QEMU package installation was incomplete; continuing to systemd.'
        if ! repair_ssh; then log 'SSH repair failed; continuing to systemd.'; fi
        install_wings || log 'Wings installation failed; continuing to systemd.'
        install_firstboot_unit
        touch "$BOOTSTRAP_MARKER"
        remove_policy
        trap - EXIT
    else
        repair_ssh || log 'SSH repair failed on subsequent boot; preserving systemd startup.'
        install_firstboot_unit
    fi
elif command -v apk >/dev/null 2>&1; then
    # The selectable bot OSes are Debian/Ubuntu. This branch remains safe for
    # an externally supplied Alpine image without pretending systemd is native.
    apk add --no-cache bash curl wget ca-certificates coreutils procps iproute2 \
        iputils iptables nftables util-linux net-tools tar gzip unzip xz socat \
        sudo jq git openssh openssh-client openrc
    if [ "__NESTED_DOCKER__" = "1" ]; then
        apk add --no-cache docker docker-cli-compose || true
    fi
    repair_ssh
else
    echo 'Unsupported guest package manager; cannot bootstrap Linux services.' >&2
    exit 40
fi

# Keep the final runtime process as systemd. The first-boot unit will run on the
# actual systemd boot and only then publish .system-ready. SYSTEMD_OFFLINE must
# not leak into PID 1, otherwise later `systemctl` calls may operate offline.
unset SYSTEMD_OFFLINE 2>/dev/null || true
printf 'bootstrap=complete\n' >/var/lib/rgnodes/bootstrap-state 2>/dev/null || true
if [ -x /sbin/init ]; then
    exec /sbin/init
fi
if [ -x /lib/systemd/systemd ]; then
    exec /lib/systemd/systemd
fi
if [ -x /usr/lib/systemd/systemd ]; then
    exec /usr/lib/systemd/systemd
fi

echo 'systemd binary was not installed correctly.' >&2
printf 'bootstrap_failed=systemd-missing\n' > /var/lib/rgnodes/bootstrap-failure 2>/dev/null || true
# Keep the guest alive for diagnosis/recovery instead of silently exiting.
exec tail -f /dev/null
"""

async def docker_run(*, image: str, hostname: str, ram: str, cpu: str, disk: str, container_name: str, location: str, persistent_key: str | None = None) -> tuple[str | None, str]:
    if active_backend() == "qemu":
        return await qemu_create_vm(
            os_type=qemu_os_from_image(image) or image, hostname=hostname, ram=ram, cpu=cpu,
            disk=disk, name=container_name, persistent_key=persistent_key,
        )
    rc, out, err = await docker_cli(
        "run", "--detach", "--name", container_name, "--hostname", hostname,
        "--memory", ram, "--cpus", cpu, image, "tail", "-f", "/dev/null",
        timeout=DOCKER_TIMEOUT, retries=0,
    )
    if rc == 0:
        return out.decode("utf-8", "replace").strip().splitlines()[0], ""
    return None, safe_log(err.decode("utf-8", "replace").strip() or "Docker container creation failed.")


async def docker_start(container: str) -> tuple[bool, str]:
    if qemu_load_meta(container):
        return await qemu_launch(container)
    rc, _, err = await docker_cli("start", container, timeout=60, retries=1)
    return rc == 0, safe_log(err.decode("utf-8", "replace").strip())


async def ensure_docker_running(container: str) -> tuple[bool, str]:
    """Treat docker run --detach as already started and only start when needed."""
    state = await docker_state(container)
    if state == "running":
        return True, ""
    ok, error = await docker_start(container)
    if not ok:
        # A concurrent supervisor may have started it between inspect and start.
        if await docker_state(container) == "running":
            return True, ""
        return False, error or "Container could not be started."
    return True, ""


async def guest_system_ready(container: str) -> tuple[bool, str]:
    """Verify a real QEMU guest booted with systemd; KVM is never used."""
    if qemu_load_meta(container):
        rc, out, err = await qemu_ssh(container, "pid1=$(cat /proc/1/comm 2>/dev/null || true); [ \"$pid1\" = systemd ] || { echo \"PID 1 is $pid1, not systemd\" >&2; exit 1; }; command -v systemctl >/dev/null 2>&1 || exit 2; command -v sshd >/dev/null 2>&1 || exit 3; sshd -t >/dev/null 2>&1 || exit 4; test -f /etc/rgnodes/.system-ready", timeout=30)
        if rc == 0:
            return True, "Real QEMU VPS is ready (systemd + SSH, accelerator=TCG, KVM disabled)."
        return False, err.decode("utf-8", "replace").strip() or out.decode("utf-8", "replace").strip() or "QEMU guest is still booting."
    if not GUEST_SYSTEMD_ENABLED:
        return True, "systemd guest mode is disabled."
    nested = "1" if GUEST_NESTED_DOCKER else "0"
    kvm = "1" if GUEST_KVM_ENABLED else "0"
    wings = "1" if GUEST_INSTALL_WINGS else "0"
    script = f"""
set -u
fail() {{ echo "$*" >&2; exit 1; }}
pid1="$(cat /proc/1/comm 2>/dev/null || true)"
[ "$pid1" = "systemd" ] || fail "PID 1 is '$pid1', not systemd"
command -v systemctl >/dev/null 2>&1 || fail "systemctl is missing"
command -v curl >/dev/null 2>&1 || fail "curl is missing"
command -v sshd >/dev/null 2>&1 || fail "sshd is missing"
sshd -t >/dev/null 2>&1 || fail "sshd configuration validation failed"
command -v node >/dev/null 2>&1 || fail "node is missing"
command -v npm >/dev/null 2>&1 || fail "npm is missing"
command -v yarn >/dev/null 2>&1 || fail "yarn is missing"
command -v pm2 >/dev/null 2>&1 || fail "pm2 is missing"
node -e 'process.exit(process.versions.node.startsWith("20.") ? 0 : 1)' || fail "Node.js 20 is not active"
if [ "{nested}" = "1" ]; then
    command -v docker >/dev/null 2>&1 || fail "Docker CLI is missing"
    command -v containerd >/dev/null 2>&1 || fail "containerd is missing"
    docker info >/dev/null 2>&1 || fail "Docker daemon is not reachable"
    docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is unavailable"
    systemctl is-active --quiet docker.service || fail "docker.service is not active"
fi
command -v qemu-img >/dev/null 2>&1 || fail "qemu-img is missing"
qemu-img --version >/dev/null 2>&1 || fail "qemu-img is broken"
qemu_bin=""
for candidate in qemu-system-x86_64 qemu-system-aarch64 qemu-system-ppc64 qemu-system-s390x qemu-system-riscv64; do
    if command -v "$candidate" >/dev/null 2>&1; then qemu_bin="$candidate"; break; fi
done
[ -n "$qemu_bin" ] || fail "No QEMU system emulator is installed"
"$qemu_bin" --version >/dev/null 2>&1 || fail "QEMU system emulator is broken"
if [ "{kvm}" = "1" ]; then
    if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
        if command -v kvm-ok >/dev/null 2>&1 && kvm-ok >/dev/null 2>&1; then
            printf 'kvm=available\n' >/var/lib/rgnodes/kvm-status
            printf 'acceleration=kvm\n' >>/var/lib/rgnodes/kvm-status
        else
            printf 'kvm=present-but-unverified\n' >/var/lib/rgnodes/kvm-status
        fi
    else
        printf 'kvm=unavailable\n' >/var/lib/rgnodes/kvm-status
    fi
fi
if [ "{wings}" = "1" ]; then
    command -v wings >/dev/null 2>&1 || fail "Wings binary is missing"
fi
[ -f /etc/rgnodes/.system-ready ] || fail "first-boot verification has not completed"
"""
    rc, _, err = await docker_exec_shell(container, script, timeout=25)
    if rc == 0:
        return True, "systemd, Docker, Compose, SSH, Node.js, npm, Yarn, PM2, QEMU and guest Pterodactyl prerequisites are ready."
    detail = err.decode("utf-8", "replace").strip()
    return False, detail or f"guest readiness check exited with code {rc}"


async def _repair_guest_services(container: str) -> str:
    """Perform bounded in-guest service repair while systemd is PID 1."""
    script = r'''set +e
unset SYSTEMD_OFFLINE
mkdir -p /run/sshd /var/run/sshd
sshd -t >/dev/null 2>&1 || true
systemctl daemon-reload >/dev/null 2>&1 || true
systemctl reset-failed docker.service ssh.service sshd.service >/dev/null 2>&1 || true
systemctl start docker.service >/dev/null 2>&1 || true
systemctl start ssh.service >/dev/null 2>&1 || systemctl start sshd.service >/dev/null 2>&1 || true
if command -v docker >/dev/null 2>&1 && ! docker info >/dev/null 2>&1 && command -v dockerd >/dev/null 2>&1; then
  if ! pgrep -x dockerd >/dev/null 2>&1; then
    nohup dockerd --host=unix:///var/run/docker.sock >/var/log/rgnodes-dockerd-fallback.log 2>&1 </dev/null &
  fi
fi
sleep 2
if docker info >/dev/null 2>&1; then echo docker=ready; else echo docker=not-ready; fi
if systemctl is-active --quiet ssh.service || systemctl is-active --quiet sshd.service; then echo ssh=ready; else echo ssh=not-ready; fi
if docker info >/dev/null 2>&1 && { systemctl is-active --quiet ssh.service || systemctl is-active --quiet sshd.service; }; then
  if [ -x /usr/local/sbin/rgnodes-firstboot-verify ]; then
    timeout 75 /usr/local/sbin/rgnodes-firstboot-verify >/var/log/rgnodes-firstboot-retry.log 2>&1 || true
  fi
fi
'''
    rc, out, err = await docker_exec_shell(container, script, timeout=25)
    text = (out + err).decode("utf-8", "replace").strip()
    return text[-1200:] if text else f"guest service repair exit={rc}"


async def wait_for_guest_ready(
    container: str,
    timeout: float = GUEST_BOOTSTRAP_TIMEOUT,
    progress: OperationCallback | None = None,
    *,
    os_type: str = "unknown",
    location: str = "SG",
    ram: str = DEFAULT_RAM,
    cpu: str = DEFAULT_CPU,
    disk: str = DEFAULT_DISK,
    name: str = "vps",
) -> tuple[bool, str]:
    """Wait for provisioning with bounded retries; never leave Discord stuck at 60%."""
    if qemu_load_meta(container):
        return await _wait_qemu_ready(container)
    budget = min(max(45.0, float(timeout)), 300.0)
    deadline = asyncio.get_running_loop().time() + budget
    last = "guest bootstrap is still running"
    attempt = 0
    while asyncio.get_running_loop().time() < deadline:
        state = await docker_state(container)
        if state != "running":
            rc_i, out_i, _ = await docker_cli(
                "inspect", "--format", "{{.State.Status}}|{{.State.ExitCode}}|{{.State.OOMKilled}}",
                container, timeout=15, retries=0,
            )
            state_diag = out_i.decode("utf-8", "replace").strip() if rc_i == 0 else state
            rc_l, out_l, err_l = await docker_cli(
                "logs", "--tail", "120", container, timeout=20, retries=0,
            )
            logs = (out_l or err_l).decode("utf-8", "replace").strip() if rc_l == 0 else ""
            detail = "Guest stopped during bootstrap. The container exited before system services became ready."
            if state_diag:
                detail += f" Diagnostic: {state_diag}"
            if logs:
                detail += "\nLast guest logs:\n" + safe_log(logs, 3000)
            return False, detail
        ok, detail = await guest_system_ready(container)
        if ok:
            return True, detail
        last = detail
        attempt += 1
        if progress and attempt % 3 == 0:
            stage_title = {
                3: "Starting Linux services",
                6: "Checking Docker service",
                9: "Checking SSH service",
                12: "Checking Node.js and PM2",
                15: "Checking QEMU and KVM",
            }.get(min(15, attempt), "Finalizing Linux services")
            await update_progress(
                progress, 6, stage_title, os_type=os_type, location=location,
                ram=ram, cpu=cpu, disk=disk, name=name
            )
        if attempt in {2, 6, 12}:
            repair = await _repair_guest_services(container)
            logger.warning("Guest service repair for %s: %s", clean(container, 32), safe_log(repair))
        await asyncio.sleep(2)
    diag_script = (
        "set +e; "
        "echo '--- systemd ---'; systemctl is-system-running 2>&1; "
        "echo '--- docker ---'; systemctl status docker.service --no-pager -l 2>&1 | tail -n 35; "
        "echo '--- ssh ---'; systemctl status ssh.service --no-pager -l 2>&1 | tail -n 20; "
        "echo '--- recent journal ---'; journalctl -u docker.service -u rgnodes-firstboot.service -n 45 --no-pager 2>&1 | tail -n 70"
    )
    rc, out, err = await docker_exec_shell(container, diag_script, timeout=30)
    diag = (out + err).decode("utf-8", "replace").strip()
    if rc != 0 and not diag:
        diag = f"diagnostic command failed with exit={rc}"
    return False, f"Guest readiness timed out after {int(budget)}s. Last check: {last}.\n{safe_log(diag, 3500)}"


async def docker_stop(container: str) -> bool:
    if qemu_load_meta(container):
        return await qemu_stop_vm(container)
    rc, _, _ = await docker_cli("stop", "--time", "20", container, timeout=40, retries=1)
    if rc == 0:
        return True
    rc, _, _ = await docker_cli("kill", container, timeout=25, retries=1)
    return rc == 0


async def docker_restart(container: str) -> tuple[bool, str]:
    if qemu_load_meta(container):
        return await qemu_restart_vm(container)
    rc, _, err = await docker_cli("restart", "--time", "20", container, timeout=60, retries=1)
    return rc == 0, safe_log(err.decode("utf-8", "replace").strip())


async def docker_remove(container: str) -> bool:
    if qemu_load_meta(container):
        return await qemu_remove_vm(container)
    rc, _, _ = await docker_cli("rm", "--force", container, timeout=60, retries=1)
    if rc == 0:
        return True
    return not await docker_exists(container)


async def docker_exec(
    container: str,
    *command: str,
    timeout: float = 120,
    retries: int = 1,
) -> tuple[int, bytes, bytes]:
    if qemu_load_meta(container):
        text = " ".join(shlex.quote(str(part)) for part in command)
        return await qemu_ssh(container, text, timeout=timeout)
    return await docker_cli("exec", container, *command, timeout=timeout, retries=max(0, int(retries)))


async def docker_exec_shell(container: str, script: str, timeout: float = ACCESS_TIMEOUT) -> tuple[int, bytes, bytes]:
    if qemu_load_meta(container):
        return await qemu_ssh(container, script, timeout=timeout)
    # Shell scripts may have side effects. Never let the generic transient-error
    # retry mechanism execute the same script a second time.
    return await docker_exec(container, "sh", "-c", script, timeout=timeout, retries=0)


async def docker_stats(container: str) -> dict[str, str]:
    """Live resource data for either Docker legacy records or real QEMU VMs."""
    if qemu_load_meta(container):
        script = (
            "free -b 2>/dev/null | awk '/Mem:/ {print $3, $2}'; "
            "awk 'NR>2 {rx+=$2; tx+=$10} END {printf \"%d %d\\n\", rx+0, tx+0}' "
            "/proc/net/dev 2>/dev/null || true"
        )
        rc, out, _ = await qemu_ssh(container, script, timeout=15)
        parts = out.decode("utf-8", "replace").splitlines()
        used = total = 0
        rx = tx = 0
        if parts:
            try:
                a = parts[0].split()
                if len(a) >= 2:
                    used, total = int(a[0]), int(a[1])
            except ValueError:
                pass
        if len(parts) > 1:
            try:
                a = parts[1].split()
                if len(a) >= 2:
                    rx, tx = int(a[0]), int(a[1])
            except ValueError:
                pass
        return {
            "cpu": "N/A (TCG)",
            "memory": f"{format_bytes(used)} / {format_bytes(total)}" if total else "N/A",
            "network": f"{format_bytes(rx)} / {format_bytes(tx)}",
        }
    memory_text = "N/A"
    cgroup_script = r'''set -u
if [ -r /sys/fs/cgroup/memory.current ]; then
  current=$(cat /sys/fs/cgroup/memory.current 2>/dev/null || echo 0)
  inactive=$(awk '$1=="inactive_file"{print $2; found=1} END{if(!found) print 0}' /sys/fs/cgroup/memory.stat 2>/dev/null)
  max=$(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo max)
  case "$current" in ''|*[!0-9]*) current=0;; esac
  case "$inactive" in ''|*[!0-9]*) inactive=0;; esac
  usage=$(( current > inactive ? current-inactive : 0 ))
  printf 'v2\t%s\t%s\n' "$usage" "$max"
  exit 0
fi
if [ -r /sys/fs/cgroup/memory/memory.usage_in_bytes ]; then
  current=$(cat /sys/fs/cgroup/memory/memory.usage_in_bytes 2>/dev/null || echo 0)
  inactive=$(awk '$1=="total_inactive_file"{print $2; found=1} END{if(!found) print 0}' /sys/fs/cgroup/memory/memory.stat 2>/dev/null)
  limit=$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null || echo 0)
  case "$current" in ''|*[!0-9]*) current=0;; esac
  case "$inactive" in ''|*[!0-9]*) inactive=0;; esac
  case "$limit" in ''|*[!0-9]*) limit=0;; esac
  usage=$(( current > inactive ? current-inactive : 0 ))
  printf 'v1\t%s\t%s\n' "$usage" "$limit"
  exit 0
fi
exit 1
'''
    rc_mem, out_mem, _ = await docker_exec_shell(container, cgroup_script, timeout=10)
    if rc_mem == 0:
        parts = out_mem.decode("utf-8", "replace").strip().split("\t")
        if len(parts) == 3:
            try:
                used = int(parts[1])
                raw_limit = parts[2].strip()
                if raw_limit.isdigit():
                    limit = int(raw_limit)
                    if 0 < limit < (1 << 50):
                        memory_text = f"{format_bytes(max(0, used))} / {format_bytes(limit)}"
            except (ValueError, TypeError):
                pass

    rc, out, err = await docker_cli(
        "stats", "--no-stream", "--format", "{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}",
        container, timeout=30, retries=1,
    )
    if rc == 0:
        parts = out.decode("utf-8", "replace").strip().split("\t")
        if len(parts) == 3:
            cpu = parts[0].strip() or "0.00%"
            mem = memory_text if memory_text != "N/A" else normalize_dashboard_memory(parts[1].strip())
            network = normalize_network_stats(parts[2].strip() or "0 B / 0 B")
            return {"cpu": cpu, "memory": mem or "0 B", "network": network}
    # Fallback: old/minimal Docker clients can return a plain row. Keep CPU visible instead of N/A when possible.
    plain = out.decode("utf-8", "replace").strip()
    if plain:
        match = re.search(r"(\d+(?:\.\d+)?%)", plain)
        if match:
            return {"cpu": match.group(1), "memory": memory_text, "network": "N/A"}
    logger.debug("docker stats failed for %s: %s", clean(container, 32), safe_log(err.decode("utf-8", "replace")))
    return {"cpu": "N/A", "memory": memory_text, "network": "N/A"}


async def docker_uptime(container: str) -> str:
    if qemu_load_meta(container):
        rc, out, _ = await qemu_ssh(container, "awk '{print int($1)}' /proc/uptime", timeout=10)
        if rc == 0:
            try:
                seconds = max(0, int(out.decode("utf-8", "replace").strip()))
                days, rem = divmod(seconds, 86400)
                hours, rem = divmod(rem, 3600)
                minutes, _ = divmod(rem, 60)
                return f"{days}d {hours}h {minutes}m"
            except ValueError:
                pass
        return "N/A"
    rc, out, _ = await docker_cli("inspect", "-f", "{{.State.StartedAt}}", container, timeout=20, retries=1)
    if rc != 0:
        return "N/A"
    raw = out.decode("utf-8", "replace").strip()
    try:
        started = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        seconds = max(0, int((datetime.now(timezone.utc) - started).total_seconds()))
        days, rem = divmod(seconds, 86400)
        hours, rem = divmod(rem, 3600)
        minutes, _ = divmod(rem, 60)
        return f"{days}d {hours}h {minutes}m"
    except (ValueError, TypeError):
        return "N/A"


async def docker_disk_usage(container: str) -> dict[str, str]:
    if qemu_load_meta(container):
        rc, out, _ = await qemu_ssh(container, "df -B1 / 2>/dev/null | awk 'NR==2 {print $2, $3, $5}'", timeout=15)
        parts = out.decode("utf-8", "replace").strip().split()
        if rc == 0 and len(parts) >= 3:
            try:
                return {"used": format_bytes(int(parts[1])), "total": format_bytes(int(parts[0])), "percent": parts[2]}
            except ValueError:
                pass
        return {"used": "N/A", "total": "N/A", "percent": "N/A"}
    """Return container disk usage while always using the VPS allocation as the dashboard limit.

    Hard disk quotas are optional in RGNODES, so Docker may not expose a real per-container
    quota. In that case we still report the measured writable usage (when available) and
    let the dashboard use the configured VPS disk allocation as the visible limit.
    """
    rc, out, _ = await docker_cli(
        "inspect", "--size", "-f", "{{.SizeRw}}", container,
        timeout=25, retries=1,
    )
    if rc == 0:
        raw = out.decode("utf-8", "replace").strip()
        # Docker normally returns an integer byte count. Treat an empty/<no value> response
        # as unavailable rather than raising and breaking the dashboard.
        if raw.isdigit():
            return {"used": format_bytes(max(0, int(raw))), "total": "configured", "percent": "allocation"}

    # Reliable in-container fallback. Prefer / because it represents the container's root
    # filesystem rather than the host filesystem path.
    script = "df -B1 / 2>/dev/null | awk 'NR==2 {print $2, $3, $4, $5}'"
    rc, out, _ = await docker_exec_shell(container, script, timeout=20)
    parts = out.decode("utf-8", "replace").strip().split()
    if rc == 0 and len(parts) >= 4:
        try:
            total = int(parts[0])
            used = int(parts[1])
            return {
                "used": format_bytes(max(0, used)),
                "total": format_bytes(max(0, total)),
                "percent": parts[3],
            }
        except (TypeError, ValueError):
            pass

    # Do not surface an avoidable N/A for a running VPS: when Docker cannot expose the
    # writable-layer metric, zero is a safe baseline until the next successful refresh.
    return {"used": "0 B", "total": "configured", "percent": "allocation"}


async def docker_logs(container: str, lines: int = 50) -> str:
    safe_lines = max(1, min(int(lines), 200))
    if qemu_load_meta(container):
        meta = qemu_load_meta(container) or {}
        log_path = Path(str(meta.get("log_path", "")))
        if not log_path.exists():
            return "No QEMU serial log is available yet."
        try:
            return "\n".join(log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-safe_lines:])[-3800:] or "No recent QEMU serial logs."
        except OSError as exc:
            return f"Unable to read QEMU serial log: {safe_log(exc)}"
    rc, out, err = await docker_cli("logs", "--tail", str(safe_lines), container, timeout=30, retries=1)
    if rc != 0:
        return "Unable to fetch container logs."
    text = out.decode("utf-8", "replace") or err.decode("utf-8", "replace")
    return text.replace("\x00", "")[-3800:] or "No recent logs."


# ================================================================
# SSHx — verified current installer flow, no fragile line continuations
# ================================================================

SSHX_INSTALL_SCRIPT = r"""
set +e
export NO_COLOR=1

D='/tmp/sshx-RGNODES™'
LOG="$D/sshx-RGNODES™.log"
PID="$D/sshx-RGNODES™.pid"
URL="$D/sshx-RGNODES™.url"
STATE_DIR='/var/lib/rgnodes/sshx'

mkdir -p "$D" "$STATE_DIR" 2>/dev/null || true
chmod 700 "$D" "$STATE_DIR" 2>/dev/null || true

clean_ansi() {
    sed -E 's/\x1B\[[0-9;?]*[ -\/]*[@-~]//g'
}

extract_url() {
    [ -s "$1" ] || return 1
    clean_ansi < "$1" \
      | tr -d '\r' \
      | grep -Eao 'https://sshx\.io/s/[^[:space:]]+' \
      | tail -n1
}

valid_pid() {
    case "${1:-}" in
        ''|*[!0-9]*) return 1 ;;
    esac
    kill -0 "$1" 2>/dev/null || return 1
    [ -r "/proc/$1/cmdline" ] || return 1
    tr '\000' ' ' < "/proc/$1/cmdline" 2>/dev/null \
        | grep -qi 'sshx' || return 1
    return 0
}

save_state() {
    [ -s "$PID" ] && cp -f "$PID" "$STATE_DIR/sshx.pid" 2>/dev/null || true
    [ -s "$LOG" ] && cp -f "$LOG" "$STATE_DIR/sshx.log" 2>/dev/null || true
    [ -s "$URL" ] && cp -f "$URL" "$STATE_DIR/sshx.url" 2>/dev/null || true
    chmod 600 "$STATE_DIR/sshx.pid" "$STATE_DIR/sshx.url" 2>/dev/null || true
}

OLD_PID=""
if [ -s "$PID" ]; then
    OLD_PID="$(cat "$PID" 2>/dev/null || true)"
fi

# Never destroy the URL of a healthy existing session.  A second Console
# request must reuse the same SSHx process whenever possible.
if valid_pid "$OLD_PID"; then
    if [ ! -s "$URL" ]; then
        extract_url "$LOG" > "$URL" 2>/dev/null || true
    fi
    save_state
    printf '%s\n' "[SSHX] Existing session reused • PID $OLD_PID"
    if [ -s "$URL" ]; then
        cat "$URL"
    fi
    exit 0
fi

# ---------------------------------------------------------------
# 1) Exact official SSHx installer command.
# ---------------------------------------------------------------
if ! command -v curl >/dev/null 2>&1; then
    if [ "$(id -u 2>/dev/null)" = "0" ] && command -v apt-get >/dev/null 2>&1; then
        apt-get update -y >/dev/null 2>&1 || true
        apt-get install -y curl ca-certificates bash coreutils procps \
            >/dev/null 2>&1 || true
    elif command -v sudo >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update -y >/dev/null 2>&1 || true
        sudo apt-get install -y curl ca-certificates bash coreutils procps \
            >/dev/null 2>&1 || true
    fi
fi

if ! command -v curl >/dev/null 2>&1; then
    printf '%s\n' '[SSHX] ERROR: curl is unavailable.'
    exit 20
fi

cd "$D" 2>/dev/null || exit 21

# Run the exact official installer requested by RGNODES when a local binary
# is missing.  Keep a log so installer failures remain diagnosable.
if [ ! -x "$D/sshx" ]; then
    printf '%s\n' '[RGNODES™ ;D] Downloading sshx...'
    rm -f "$D/sshx" 2>/dev/null || true
    curl -sSf https://sshx.io/get | sh >"$D/install.log" 2>&1
    INSTALL_RC=$?

    # The official installer may have installed into PATH; copy it locally so
    # every SSHx session uses one deterministic binary inside this VPS.
    if [ ! -x "$D/sshx" ] && command -v sshx >/dev/null 2>&1; then
        cp -f "$(command -v sshx)" "$D/sshx" 2>/dev/null || true
    fi

    # The official installer also documents `download` as the non-running
    # installation mode; use it as the deterministic local fallback.
    if [ ! -x "$D/sshx" ]; then
        (cd "$D" && curl -fsSL https://sshx.io/get | NO_COLOR=1 sh -s download) \
            >"$D/download.log" 2>&1
        DOWNLOAD_RC=$?
        chmod +x "$D/sshx" 2>/dev/null || true
    else
        DOWNLOAD_RC=0
    fi

    chmod +x "$D/sshx" 2>/dev/null || true
    if [ ! -x "$D/sshx" ]; then
        printf '%s\n' "[SSHX] ERROR: sshx binary unavailable (installer=$INSTALL_RC download=$DOWNLOAD_RC)"
        tail -n 50 "$D/install.log" 2>/dev/null || true
        tail -n 50 "$D/download.log" 2>/dev/null || true
        exit 22
    fi
fi

SSHX_BIN="$D/sshx"

# A stale PID from a dead process must not survive into the new session.
rm -f "$LOG" "$URL" 2>/dev/null || true
: > "$LOG"

printf '%s\n' '[RGNODES™ ;D] Starting sshx in background...'
# Exact requested SSHx launch parameters.
nohup "$SSHX_BIN" --quiet --name 'RGNODES™ ;D' --shell "${SHELL:-/bin/bash}" \
    >"$LOG" 2>&1 </dev/null &
SSHX_PID=$!
printf '%s\n' "$SSHX_PID" > "$PID"

# Wait only for the SSHx startup output, exactly as requested.  It is bounded
# to 70 seconds and terminates immediately once a URL is present or the process
# dies; it never keeps the Discord event handler waiting indefinitely.
for i in $(seq 1 70); do
    extract_url "$LOG" > "$URL" 2>/dev/null || true
    [ -s "$URL" ] && break
    if ! valid_pid "$SSHX_PID"; then
        break
    fi
    sleep 1
done

save_state

printf '%s\n' ''
printf '%s\n' '================ SSHX BY RGNODES™ ;D ================'
printf '%s\n' "PID: $SSHX_PID"
printf '%s' 'URL: '
cat "$URL" 2>/dev/null || true
printf '%s\n' ''
printf '%s\n' "LOG: $LOG"
printf '%s\n' '========================================================'

if [ -s "$URL" ] && valid_pid "$SSHX_PID"; then
    printf '%s\n' "[SSHX] ONLINE • encrypted URL READY • PID $SSHX_PID"
    exit 0
fi

if valid_pid "$SSHX_PID"; then
    printf '%s\n' '[SSHX] ONLINE • URL not emitted yet.'
    tail -n 40 "$LOG" 2>/dev/null || true
    exit 24
fi

printf '%s\n' '[SSHX] PROCESS EXITED'
tail -n 80 "$LOG" 2>/dev/null || true
exit 23
"""



def normalize_sshx_url(raw: str | None) -> str | None:
    """Validate an SSHx share URL and preserve its browser key fragment exactly."""
    text = str(raw or "").replace("\r", " ").replace("\n", " ")
    # SSHx emits https://sshx.io/s/<session>[#<browser-key>].  Never
    # percent-decode, quote, or otherwise rewrite the fragment.
    match = re.search(
        r"https://sshx\.io/s/[A-Za-z0-9_-]+#[^\s<>\[\]\"']+",
        text,
        flags=re.I,
    )
    if not match:
        return None
    url = match.group(0).rstrip(".,;:)]}'\"")
    try:
        parsed = urlsplit(url)
    except ValueError:
        return None
    if parsed.scheme.lower() != "https" or parsed.netloc.lower() != "sshx.io":
        return None
    if not re.fullmatch(r"/s/[A-Za-z0-9_-]+", parsed.path):
        return None
    # Do not accept the known-broken form without its E2E fragment.
    if not parsed.fragment or len(parsed.fragment) < 8:
        return None
    if any(ord(ch) < 0x21 or ch in ' <>\"\'[]' for ch in parsed.fragment):
        return None
    return urlunsplit(("https", "sshx.io", parsed.path, parsed.query, parsed.fragment))



async def sshx_process_alive(container: str, pid: str | None) -> bool:
    if not pid or not str(pid).isdigit():
        return False
    script = (
        'PID="' + str(pid) + '"; '
        'if [ -r "/proc/$PID/cmdline" ]; then '
        'CMD="$(tr "\\000" " " < "/proc/$PID/cmdline" 2>/dev/null || true)"; '
        'case "$CMD" in *sshx*) exit 0;; esac; '
        'fi; '
        'if command -v ps >/dev/null 2>&1; then '
        'ps -p "$PID" -o args= 2>/dev/null | grep -qi "sshx" && exit 0; '
        'fi; exit 1'
    )
    rc, _, _ = await docker_exec_shell(container, script, timeout=10)
    return rc == 0


async def _read_sshx_state(container: str) -> tuple[str | None, str | None]:
    rc, out, _ = await docker_exec_shell(
        container,
        "printf '%s\\n' 'URL:'; cat /var/lib/rgnodes/sshx/sshx.url 2>/dev/null || true; printf '%s\\n' 'PID:'; cat /var/lib/rgnodes/sshx/sshx.pid 2>/dev/null || true",
        timeout=10,
    )
    if rc != 0:
        return None, None
    lines = out.decode("utf-8", "replace").splitlines()
    url = None
    pid = None
    try:
        if "URL:" in lines:
            i = lines.index("URL:") + 1
            if i < len(lines):
                url = normalize_sshx_url(lines[i])
        if "PID:" in lines:
            i = lines.index("PID:") + 1
            if i < len(lines):
                candidate = lines[i].strip()
                if candidate.isdigit():
                    pid = candidate
    except (ValueError, IndexError):
        pass
    return url, pid


async def install_and_start_sshx(container: str) -> dict[str, str] | None:
    """Create or reuse one SSHx session for a running Docker VPS.

    The container-side launcher follows the user's exact SSHx commands.  A
    per-VPS asyncio lock prevents two Discord button presses from racing into
    two SSHx processes, while durable PID/URL state allows later requests to
    reuse the same encrypted session.
    """
    if await docker_state(container) != "running":
        logger.warning("SSHx skipped: container %s is not running.", clean(container, 32))
        return None

    lock = VPS_SSHX_LOCKS.setdefault(str(container), asyncio.Lock())
    async with lock:
        if await docker_state(container) != "running":
            return None

        saved_url, saved_pid = await _read_sshx_state(container)
        if saved_pid and await sshx_process_alive(container, saved_pid):
            if saved_url:
                logger.info("Reusing SSHx session for %s (PID %s).", clean(container, 32), saved_pid)
                return {"url": saved_url, "pid": saved_pid}

        timeout = max(85.0, min(float(SSHX_TOTAL_TIMEOUT), 130.0))
        try:
            rc, out, err = await docker_exec(
                container,
                "bash",
                "-lc",
                SSHX_INSTALL_SCRIPT,
                timeout=timeout,
                retries=0,
            )
        except asyncio.TimeoutError:
            logger.warning("SSHx launcher timeout for %s; recovering durable state.", clean(container, 32))
            saved_url, saved_pid = await _read_sshx_state(container)
            if saved_pid and await sshx_process_alive(container, saved_pid):
                return {"url": saved_url or "", "pid": saved_pid}
            return None
        except Exception as exc:
            logger.warning("SSHx launcher error for %s: %s", clean(container, 32), safe_log(exc))
            return None

        stdout = out.decode("utf-8", "replace")
        stderr = err.decode("utf-8", "replace")
        url = normalize_sshx_url(stdout + "\n" + stderr)
        state_url, state_pid = await _read_sshx_state(container)
        final_url = state_url or url
        final_pid = state_pid

        if final_pid and await sshx_process_alive(container, final_pid):
            if final_url:
                logger.info("SSHx ready for %s (PID %s).", clean(container, 32), final_pid)
            else:
                logger.info("SSHx running for %s (PID %s), but encrypted URL is not ready.", clean(container, 32), final_pid)
            return {"url": final_url or "", "pid": final_pid}

        detail = safe_log((stderr or stdout).strip() or f"exit={rc}", 2400)
        logger.warning("SSHx launch failed for %s: %s", clean(container, 32), detail)
        return None


async def stop_sshx(container: str) -> None:
    script = r"""
set +e
PID_FILE=/var/lib/rgnodes/sshx/sshx.pid
if [ -s "$PID_FILE" ]; then
  PID="$(cat "$PID_FILE" 2>/dev/null)"
  case "$PID" in
    ''|*[!0-9]*) ;;
    *)
      if [ -r "/proc/$PID/cmdline" ]; then
        CMD="$(tr '\000' ' ' < "/proc/$PID/cmdline" 2>/dev/null || true)"
        case "$CMD" in *sshx*) kill "$PID" 2>/dev/null || true; sleep 1; kill -9 "$PID" 2>/dev/null || true;; esac
      fi
      ;;
  esac
fi
rm -f /var/lib/rgnodes/sshx/sshx.pid /var/lib/rgnodes/sshx/sshx.url
"""
    await docker_exec_shell(container, script, timeout=15)


# ================================================================
# Discord UI helpers — text/layout retained
# ================================================================

EMBED_COLOR = discord.Color.from_rgb(43, 45, 49)
FOOTER = "⚡ RGNODES™ • VPS Management"
RGNODES_BUILD = "2026.09.11-real-qemu-tcg-final-audit"


def make_embed(title: str, description: str | None = None) -> discord.Embed:
    embed = discord.Embed(title=title, description=description, color=EMBED_COLOR, timestamp=discord.utils.utcnow())
    embed.set_footer(text=FOOTER)
    return embed


def slot_status_text(user_id: int) -> str:
    """Return the real persisted slot allocation and current usage."""
    try:
        used = max(0, int(db_vps_count(int(user_id))))
        limit = max(1, int(db_effective_slots(int(user_id))))
    except Exception:
        used, limit = 0, max(1, int(SERVER_LIMIT))
    remaining = max(0, limit - used)
    if remaining == 0:
        return f"`{used}/{limit}` used • **SLOTS FULL**"
    return f"`{used}/{limit}` used • `{remaining}` available"


def status_text(status: str, suspended: bool = False) -> str:
    if suspended:
        return "⛔ SUSPENDED"
    return {"running": "🟢 RUNNING", "stopped": "🔴 STOPPED", "created": "🟡 CREATED", "starting": "🟡 STARTING", "restarting": "🟡 RESTARTING"}.get(status, "⚪ " + clean(status).upper())


def is_unknown_interaction(exc: BaseException) -> bool:
    return isinstance(exc, discord.NotFound) and getattr(exc, "code", None) == 10062


async def safe_defer(interaction: discord.Interaction, ephemeral: bool = False, *, claim: bool = True) -> bool:
    """Defer the original interaction response, optionally claiming it for de-duplication."""
    if claim and not await claim_interaction_once(interaction):
        return False
    if interaction.response.is_done():
        return True
    try:
        await interaction.response.defer(ephemeral=ephemeral, thinking=True)
        return True
    except discord.InteractionResponded:
        return True
    except discord.NotFound as exc:
        if is_unknown_interaction(exc):
            logger.debug("Ignoring expired interaction during defer (10062).")
            return False
        logger.warning("Interaction defer failed: %s", safe_log(exc))
        return False
    except discord.HTTPException as exc:
        logger.warning("Interaction defer failed: %s", safe_log(exc))
        return False


async def safe_edit_original(
    interaction: discord.Interaction,
    *,
    embed: discord.Embed,
    view: discord.ui.View | None = None,
) -> bool:
    try:
        await asyncio.wait_for(
            interaction.edit_original_response(embed=embed, view=view),
            timeout=DISCORD_API_TIMEOUT,
        )
        return True
    except discord.NotFound as exc:
        if is_unknown_interaction(exc):
            if not INTERACTION_LOG_UNKNOWN_AS_DEBUG:
                return False
            logger.debug("Ignoring expired interaction while editing original response (10062).")
            return False
        logger.warning("Interaction edit failed: %s", safe_log(exc))
        return False
    except (asyncio.TimeoutError, discord.HTTPException, TypeError) as exc:
        logger.warning("Interaction edit failed: %s", safe_log(exc))
        return False


async def safe_followup(
    interaction: discord.Interaction,
    *,
    embed: discord.Embed,
    view: discord.ui.View | None = None,
    ephemeral: bool = True,
) -> bool:
    """Finish an interaction without ever creating a second response message."""
    if interaction.response.is_done():
        return await safe_edit_original(interaction, embed=embed, view=view)
    if not await claim_interaction_once(interaction):
        return False
    try:
        await asyncio.wait_for(
            interaction.response.send_message(embed=embed, view=view, ephemeral=ephemeral),
            timeout=DISCORD_API_TIMEOUT,
        )
        return True
    except discord.NotFound as exc:
        if is_unknown_interaction(exc):
            logger.debug("Ignoring expired interaction while responding (10062).")
            return False
        logger.warning("Interaction response failed: %s", safe_log(exc))
        return False
    except (asyncio.TimeoutError, discord.HTTPException) as exc:
        logger.warning("Interaction response failed: %s", safe_log(exc))
        return False


async def safe_respond(interaction: discord.Interaction, *, embed: discord.Embed, ephemeral: bool = True, view: discord.ui.View | None = None) -> bool:
    """Send/edit the single response owned by this interaction."""
    if not interaction.response.is_done():
        if not await claim_interaction_once(interaction):
            return False
        try:
            kwargs: dict[str, Any] = {"embed": embed, "ephemeral": ephemeral}
            if view is not None:
                kwargs["view"] = view
            await asyncio.wait_for(
                interaction.response.send_message(**kwargs),
                timeout=DISCORD_API_TIMEOUT,
            )
            return True
        except discord.NotFound as exc:
            if is_unknown_interaction(exc):
                logger.debug("Ignoring expired interaction response (10062).")
                return False
            logger.warning("Response failed: %s", safe_log(exc))
            return False
        except (asyncio.TimeoutError, discord.HTTPException) as exc:
            logger.warning("Response failed: %s", safe_log(exc))
            return False
    return await safe_edit_original(interaction, embed=embed, view=view)


async def safe_component_edit(
    interaction: discord.Interaction,
    *,
    embed: discord.Embed,
    view: discord.ui.View | None = None,
) -> bool:
    """Edit the source component message exactly once for this interaction."""
    if not interaction.response.is_done():
        if not await claim_interaction_once(interaction):
            return False
        try:
            await asyncio.wait_for(
                interaction.response.edit_message(embed=embed, view=view),
                timeout=DISCORD_API_TIMEOUT,
            )
            return True
        except discord.NotFound as exc:
            if is_unknown_interaction(exc):
                logger.debug("Ignoring expired component interaction (10062).")
                return False
            logger.warning("Component edit failed: %s", safe_log(exc))
            return False
        except (asyncio.TimeoutError, discord.HTTPException) as exc:
            logger.warning("Component edit failed: %s", safe_log(exc))
            return False
    return await safe_edit_original(interaction, embed=embed, view=view)


async def safe_dm(user: discord.User | discord.Member, embed: discord.Embed, view: discord.ui.View | None = None) -> bool:
    try:
        kwargs: dict[str, Any] = {"embed": embed}
        if view is not None:
            kwargs["view"] = view
        await asyncio.wait_for(user.send(**kwargs), timeout=DISCORD_API_TIMEOUT)
        return True
    except discord.Forbidden:
        return False
    except (asyncio.TimeoutError, discord.HTTPException) as exc:
        logger.warning("DM failed: %s", safe_log(exc))
        return False


def sshx_view(url: str) -> discord.ui.View:
    view = discord.ui.View(timeout=900)
    view.add_item(discord.ui.Button(label="Click to Open", emoji="🌐", style=discord.ButtonStyle.link, url=url))
    return view


def console_embed(vps_name: str, url: str, ipv4: str | None = None, location: str | None = None) -> discord.Embed:
    embed = make_embed("✨ RGNODES™ • 🌐 SSHx Access", "Your private web SSH console is ready.")
    embed.add_field(name="🖥️ VPS", value=f"`{clean(vps_name)}`", inline=False)
    if valid_public_ipv4(ipv4):
        embed.add_field(name="🌐 Verified IPv4", value=f"`{ipv4}`", inline=True)
    if location:
        embed.add_field(name="🌍 Node", value=clean(location, 80), inline=True)
    embed.add_field(name="🔗 Link", value="Click **Open Console** below.", inline=False)
    embed.add_field(name="⚠️ Security", value="This link grants direct root access. Do not share it. Generate a new link if it is exposed.", inline=False)
    return embed


def ipv4_dm_embed(vps: sqlite3.Row, network: dict[str, str]) -> discord.Embed:
    ip = network.get("ip")
    embed = make_embed("🔐 RGNODES™ • Private Network Details", "Your verified public IPv4 is provided privately in this DM.")
    embed.add_field(name="🖥️ VPS", value=f"`{clean(vps['container_name'])}` • ID `{vps['id']}`", inline=False)
    embed.add_field(name="🌐 Verified Public IPv4", value=f"`{clean(ip, 64)}`", inline=True)
    embed.add_field(name="🌍 Detected Location", value=clean(actual_location_label(network), 80), inline=True)
    embed.add_field(name="🔒 Privacy", value="This IPv4 is intentionally hidden from public/channel embeds.", inline=False)
    return embed


def vps_ready_dm_embed(vps: sqlite3.Row, network: dict[str, str], console_url: str | None) -> discord.Embed:
    embed = make_embed(
        "✅ RGNODES™ • VPS Ready",
        "Your VPS has been created successfully and is online.",
    )
    embed.add_field(name="🖥️ VPS", value=f"`{clean(vps['container_name'])}` • ID `{vps['id']}`", inline=False)
    embed.add_field(name="💿 OS", value=os_label(vps['os_type']), inline=True)
    embed.add_field(name="🌍 Location", value=location_label(vps['location']), inline=True)
    embed.add_field(name="⚙️ Resources", value=f"RAM `{clean(vps['ram'])}` • CPU `{clean(vps['cpu'])}` • Disk `{clean(vps['disk'])}`", inline=False)
    if console_url:
        embed.add_field(name="🌐 Console", value="Your private SSHx console is ready. Use **Open Console** below.", inline=False)
    else:
        embed.add_field(name="🌐 Console", value="SSHx is temporarily unavailable. Use the Console action from your VPS dashboard to retry.", inline=False)
    ip = network.get("ip")
    if valid_public_ipv4(ip):
        embed.add_field(name="🌐 Verified IPv4", value=f"`{clean(ip, 64)}`", inline=False)
    embed.add_field(name="🔒 Security", value="Keep console links and private network details secret.", inline=False)
    return embed


async def send_vps_ready_dm(user: discord.User | discord.Member, vps: sqlite3.Row, network: dict[str, str]) -> bool:
    console_url = normalize_sshx_url(vps["sshx_url"]) if vps["sshx_url"] else None
    view = sshx_view(console_url) if console_url else None
    return await safe_dm(user, vps_ready_dm_embed(vps, network, console_url), view)


async def send_private_ipv4(user: discord.User | discord.Member, vps: sqlite3.Row) -> bool:
    network = await detect_public_network(force=True)
    ip = network.get("ip")
    if not valid_public_ipv4(ip):
        return False
    db_set_vps_ipv4(vps["container_id"], ip)
    return await safe_dm(user, ipv4_dm_embed(vps, network))


async def host_uptime() -> str:
    try:
        raw = Path("/proc/uptime").read_text(encoding="utf-8", errors="replace").split()[0]
        seconds = max(0, int(float(raw)))
        days, rem = divmod(seconds, 86400)
        hours, rem = divmod(rem, 3600)
        minutes, secs = divmod(rem, 60)
        return f"{days}d {hours}h {minutes}m {secs}s"
    except (OSError, ValueError, IndexError):
        return "N/A"


async def backend_state(vps: sqlite3.Row) -> str | None:
    backend = str(vps["backend"] or "qemu").lower()
    if backend == "pterodactyl":
        return await ptero_status(vps)
    if backend == "qemu":
        return await qemu_state(str(vps["container_id"]))
    return await docker_state(str(vps["container_id"]))


async def backend_stats(vps: sqlite3.Row) -> dict[str, str]:
    backend = str(vps["backend"] or "qemu").lower()
    if backend == "pterodactyl":
        return await ptero_utilization(vps)
    if backend == "qemu":
        return await docker_stats(str(vps["container_id"]))
    return await docker_stats(str(vps["container_id"]))


def format_duration_ms(ms: int | float | str | None) -> str:
    try:
        seconds = max(0, int(float(ms or 0) / 1000))
    except (TypeError, ValueError):
        return "N/A"
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


async def backend_uptime(vps: sqlite3.Row) -> str:
    if str(vps["backend"] or "docker").lower() == "pterodactyl":
        if not ptero_client_configured():
            return "N/A"
        identifier = vps["ptero_identifier"] or vps["container_id"]
        status, body = await ptero_request(
            "GET", f"client/servers/{quote(str(identifier), safe='')}/resources",
            api_key=PTERO_CLIENT_API_KEY,
        )
        if status == 200 and isinstance(body, dict):
            attrs = _ptero_attr(body) or {}
            resources = attrs.get("resources") or {}
            return format_duration_ms(resources.get("uptime"))
        return "N/A"
    return await docker_uptime(vps["container_id"])


async def backend_disk(vps: sqlite3.Row) -> dict[str, str]:
    if str(vps["backend"] or "docker").lower() == "pterodactyl":
        stats = await ptero_utilization(vps)
        return {"used": str(stats.get("disk", "N/A")), "total": clean(vps["disk"]), "percent": "panel limit"}
    return await docker_disk_usage(vps)


async def backend_panel_or_console(vps: sqlite3.Row) -> str | None:
    if str(vps["backend"] or "docker").lower() == "pterodactyl":
        return await ptero_panel_link(vps)
    return normalize_sshx_url(vps["sshx_url"])


async def refresh_vps_record_state(vps: sqlite3.Row) -> sqlite3.Row:
    """Best-effort live state refresh; never let a backend probe break the dashboard."""
    backend = str(vps["backend"] or "docker").lower()
    try:
        state = await asyncio.wait_for(backend_state(vps), timeout=20)
    except Exception as exc:
        logger.warning("VPS #%s state probe failed: %s", vps["id"], safe_log(exc))
        state = None
    try:
        if state == "running":
            db_update_vps(
                vps["container_id"],
                status="running",
                sshx_pid=None if backend == "pterodactyl" else vps["sshx_pid"],
            )
        elif state in {"stopped", "off"}:
            db_update_vps(
                vps["container_id"],
                status="stopped",
                sshx_url=None if backend in {"docker", "qemu"} else vps["sshx_url"],
                sshx_pid=None,
            )
    except Exception as exc:
        logger.warning("VPS #%s state persistence failed: %s", vps["id"], safe_log(exc))
    return db_get_vps(vps["id"]) or vps


def dashboard_embed(vps: sqlite3.Row, stats: dict[str, str], uptime: str, disk: dict[str, str], network: dict[str, str] | None = None, ports: list[sqlite3.Row] | None = None) -> discord.Embed:
    """Render one stable dashboard layout used by both prefix and slash commands."""
    _ = network  # Kept for API compatibility; detected node is intentionally not displayed.
    ports = ports if ports is not None else db_list_ports(vps["id"])
    port_summary = "None configured" if not ports else " • ".join(
        f"`{p['host_port']}→{p['container_port']}/{str(p['protocol']).upper()}`" for p in ports[:10]
    )
    live = status_text(vps["status"], bool(vps["suspended"]))
    backend = str(vps["backend"] or "docker").lower()
    embed = make_embed(
        f"🖥️ VPS #{vps['id']} • VMID `{vps['id']}`",
        f"**{live}** • `{clean(vps['container_name'])}`",
    )

    embed.add_field(
        name="📦 Resources",
        value=(
            f"╭ **RAM:** {clean(vps['ram'])}\n"
            f"├ **CPU Limit:** {clean(vps['cpu'])} Core(s)\n"
            f"├ **Storage:** {clean(vps['disk'])}\n"
            f"├ **OS:** {os_label(vps['os_type'])}\n"
            f"╰ **Node:** {location_label(vps['location'])}"
        ),
        inline=True,
    )

    runtime_label = "QEMU TCG: **✅ Ready**" if backend == "qemu" else ("Docker: **:whale:** Ready" if backend == "docker" else "Pterodactyl: Ready")
    embed.add_field(
        name="⚙️ Configuration",
        value=(
            f"╭ **Slots:** {slot_status_text(vps['user_id'])}\n"
            f"├ **Uptime:** {clean(uptime)}\n"
            f"├ **Hostname:** `{clean(vps['hostname'])}`\n"
            f"├ **IPv4:** 🔒 Sent privately in DM\n"
            f"╰ **{runtime_label}**"
        ),
        inline=True,
    )

    cpu_value = clean(stats.get("cpu"))
    memory_value = normalize_dashboard_memory(stats.get("memory"))
    disk_used = clean(disk.get("used"))
    # The configured disk is an allocation even when hard quota enforcement is off.
    if disk_used in {"", "N/A", "None", "null"}:
        disk_used = "0 B (baseline)" if str(vps["status"]).lower() == "running" else "N/A"
    network_value = normalize_network_stats(stats.get("network"))
    embed.add_field(
        name="📈 Live Stats",
        value=(
            f"💻 **CPU:** {cpu_value} used / {clean(vps['cpu'])} limit\n"
            f"🧠 **Memory:** {memory_value}\n"
            f"💾 **Disk:** {disk_used} / {clean(vps['disk'])}\n"
            f"🌐 **Network:** {network_value}"
        ),
        inline=False,
    )

    if backend == "pterodactyl":
        embed.add_field(
            name="🦖 Pterodactyl",
            value=f"Server ID: `{clean(vps['ptero_server_id'])}` • Identifier: `{clean(vps['ptero_identifier'])}`",
            inline=False,
        )
        embed.add_field(name="🌐 Allocations", value="Managed by Pterodactyl Panel/Wings.", inline=False)
    else:
        embed.add_field(
            name=f"🌐 Port Forwarding • {len(ports)}/{MAX_PORTS_PER_VPS}",
            value=port_summary,
            inline=False,
        )

    embed.add_field(
        name="🎮 Action",
        value="Use the buttons below to control your VPS.",
        inline=False,
    )
    return embed



def progress_embed(stage: int, title: str, os_type: str, location: str, ram: str, cpu: str, disk: str, name: str) -> discord.Embed:
    total = 10
    filled = max(0, min(stage, total))
    bar = "▰" * filled + "▱" * (total - filled)
    embed = make_embed("✨ RGNODES™ VPS Deployment", f"**{title}**\n`{bar}` **{filled * 10}%**")
    embed.add_field(name="🖥️ OS", value=os_label(os_type), inline=True)
    embed.add_field(name="🌍 Location", value=location_label(location), inline=True)
    embed.add_field(name="📦 VPS", value=f"`{clean(name)}`", inline=True)
    embed.add_field(name="⚙️ Resources", value=f"`{ram}` RAM • `{cpu}` CPU • `{disk}` Disk", inline=False)
    return embed



# ================================================================
# Pterodactyl Application/Client API integration
# ================================================================
PTERO_API_LOCK = asyncio.Lock()

def _ptero_headers(api_key: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "Application/vnd.pterodactyl.v1+json",
        "User-Agent": "RGNODES-VPS-Manager/2.0",
    }


def _ptero_request_sync(method: str, url: str, api_key: str, payload: dict[str, Any] | None = None) -> tuple[int, dict[str, Any] | str]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method.upper(), headers=_ptero_headers(api_key))
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            raw = resp.read().decode("utf-8", "replace")
            if not raw:
                return resp.status, {}
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, raw
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read().decode("utf-8", "replace")
            try:
                body: dict[str, Any] | str = json.loads(raw)
            except json.JSONDecodeError:
                body = raw
        except Exception:
            body = str(exc)
        return int(exc.code), body
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return 599, str(exc)


async def ptero_request(method: str, path: str, *, payload: dict[str, Any] | None = None, api_key: str | None = None) -> tuple[int, dict[str, Any] | str]:
    key = api_key or PTERO_API_KEY
    if not PTERO_URL or not key:
        return 503, "Pterodactyl is not configured."
    url = f"{PTERO_URL}/api/{path.lstrip('/')}"
    async with PTERO_API_LOCK:
        return await asyncio.to_thread(_ptero_request_sync, method, url, key, payload)


def ptero_error_message(status: int, body: dict[str, Any] | str) -> str:
    if isinstance(body, dict):
        errors = body.get("errors")
        if isinstance(errors, list):
            msgs: list[str] = []
            for item in errors[:4]:
                if isinstance(item, dict):
                    detail = item.get("detail") or item.get("code") or item.get("title")
                    if detail:
                        msgs.append(str(detail))
            if msgs:
                return "; ".join(msgs)
        if body.get("message"):
            return str(body["message"])
    if status == 599:
        return "Pterodactyl panel is unreachable or timed out."
    return safe_log(str(body or f"HTTP {status}"), 1200)


def _ptero_attr(body: dict[str, Any] | str) -> dict[str, Any] | None:
    if not isinstance(body, dict):
        return None
    attrs = body.get("attributes")
    return attrs if isinstance(attrs, dict) else None


def _ptero_limit_mb(value: str) -> int:
    return max(256, int(parse_size_bytes(value) / 1024**2))


async def ptero_get_server(server_id: int | str) -> dict[str, Any] | None:
    status, body = await ptero_request("GET", f"application/servers/{quote(str(server_id), safe='')}?include=allocations,node,user")
    if status != 200:
        logger.warning("Pterodactyl server lookup failed (%s): %s", status, ptero_error_message(status, body))
        return None
    return _ptero_attr(body)


async def ptero_create_server(*, name: str, ram: str, cpu: str, disk: str) -> tuple[bool, str, dict[str, Any] | None]:
    if not ptero_application_configured():
        return False, (
            "Pterodactyl Application API is not fully configured. Set "
            "PTERO_URL, PTERO_API_KEY, PTERO_DEFAULT_USER_ID, PTERO_NODE_ID, "
            "PTERO_NEST_ID, PTERO_EGG_ID and PTERO_ALLOCATION_ID."
        ), None
    owner_id = PTERO_DEFAULT_USER_ID

    environment = dict(PTERO_ENVIRONMENT)
    payload: dict[str, Any] = {
        "name": name,
        "user": owner_id,
        "node": PTERO_NODE_ID,
        "nest": PTERO_NEST_ID,
        "egg": PTERO_EGG_ID,
        "docker_image": PTERO_DOCKER_IMAGE or "ghcr.io/pterodactyl/yolks:debian",
        "startup": PTERO_STARTUP or "bash",
        "environment": environment,
        "limits": {
            "memory": _ptero_limit_mb(ram),
            "swap": PTERO_MEMORY_SWAP,
            "disk": int(parse_size_bytes(disk) / 1024**2),
            "io": PTERO_IO,
            "cpu": max(1, int(float(cpu) * 100)),
        },
        "feature_limits": {
            "databases": PTERO_DATABASES,
            "allocations": PTERO_ALLOCATIONS,
            "backups": PTERO_BACKUPS,
        },
        "allocation": {"default": PTERO_ALLOCATION_ID},
        "deploy": {
            "locations": [],
            "port_range": [],
            "dedicated_ip": False,
        },
    }
    payload = {k: v for k, v in payload.items() if v is not None}
    status, body = await ptero_request("POST", "application/servers", payload=payload)
    if status not in {200, 201}:
        return False, ptero_error_message(status, body), None
    attrs = _ptero_attr(body)
    if not attrs:
        return False, "Pterodactyl created the server but returned no server attributes.", None
    return True, "Pterodactyl server created successfully.", attrs


async def ptero_power(vps: sqlite3.Row, action: str) -> tuple[bool, str]:
    identifier = vps["ptero_identifier"] or vps["container_id"]
    if not ptero_client_configured():
        return False, "PTERO_CLIENT_API_KEY is not configured; Pterodactyl power and live-resource commands require a Client API key."
    signal_name = {"start": "start", "stop": "stop", "restart": "restart", "kill": "kill"}.get(action)
    if not signal_name:
        return False, "Unsupported Pterodactyl power action."
    status, body = await ptero_request("POST", f"client/servers/{quote(str(identifier), safe='')}/power", payload={"signal": signal_name}, api_key=PTERO_CLIENT_API_KEY)
    if status not in {200, 204}:
        return False, ptero_error_message(status, body)
    return True, f"Pterodactyl power action `{signal_name}` completed."


async def ptero_utilization(vps: sqlite3.Row) -> dict[str, str]:
    identifier = vps["ptero_identifier"] or vps["container_id"]
    if PTERO_CLIENT_API_KEY:
        status, body = await ptero_request(
            "GET", f"client/servers/{quote(str(identifier), safe='')}/resources",
            api_key=PTERO_CLIENT_API_KEY,
        )
        if status == 200 and isinstance(body, dict):
            attrs = _ptero_attr(body) or {}
            current = attrs.get("current_state", "offline")
            res = attrs.get("resources") or {}
            memory = int(res.get("memory_bytes") or 0)
            cpu_ns = float(res.get("cpu_absolute") or 0.0)
            disk = int(res.get("disk_bytes") or 0)
            return {
                "cpu": f"{cpu_ns:.2f}%",
                "memory": format_bytes(memory),
                "network": f"{format_bytes(int(res.get('network_rx_bytes') or 0))} ↓ / {format_bytes(int(res.get('network_tx_bytes') or 0))} ↑",
                "state": str(current),
                "disk": format_bytes(disk),
            }
    app = await ptero_get_server(vps["ptero_server_id"])
    if app:
        suspended = bool(app.get("suspended", False))
        installed = bool(app.get("installed", True))
        return {
            "cpu": "N/A", "memory": "N/A", "network": "N/A", "disk": "N/A",
            "state": "suspended" if suspended else ("installing" if not installed else "unknown"),
        }
    return {"cpu": "N/A", "memory": "N/A", "network": "N/A", "disk": "N/A", "state": "unknown"}


async def ptero_status(vps: sqlite3.Row) -> str:
    data = await ptero_utilization(vps)
    state = str(data.get("state", "unknown")).lower()
    if state in {"running", "on"}:
        return "running"
    if state in {"starting", "restarting", "installing"}:
        return state
    if state in {"stopped", "offline", "off"}:
        return "stopped"
    return "unknown"


async def ptero_panel_link(vps: sqlite3.Row) -> str:
    identifier = str(vps["ptero_identifier"] or vps["container_id"])
    return f"{PTERO_PANEL_PUBLIC_URL}/server/{identifier}" if PTERO_PANEL_PUBLIC_URL else ""


# ================================================================
# Lifecycle / deployment
# ================================================================

OperationCallback = Callable[[discord.Embed], Awaitable[None]]
CREATE_LOCK = asyncio.Lock()
CAPACITY_LOCK = asyncio.Lock()
VPS_LOCKS: dict[str, asyncio.Lock] = {}
VPS_SSHX_LOCKS: dict[str, asyncio.Lock] = {}


def vps_lock(vps_id: int) -> asyncio.Lock:
    key = str(vps_id)
    return VPS_LOCKS.setdefault(key, asyncio.Lock())


async def next_container_name() -> str:
    used: set[int] = set()
    for row in db_get_all_vps():
        m = re.fullmatch(r"rgnodes-(\d+)", str(row["container_name"]), flags=re.I)
        if m:
            used.add(int(m.group(1)))
    with contextlib.suppress(OSError):
        QEMU_VM_ROOT.mkdir(parents=True, exist_ok=True)
        for child in QEMU_VM_ROOT.iterdir():
            if not child.is_dir() or child.name == "_images":
                continue
            meta = qemu_load_meta(child.name)
            if not meta:
                continue
            m = re.fullmatch(r"rgnodes-(\d+)", str(meta.get("name", "")), flags=re.I)
            if m:
                used.add(int(m.group(1)))
    n = 1
    while n in used:
        n += 1
    return f"rgnodes-{n}"


async def update_progress(callback: OperationCallback | None, stage: int, title: str, *, os_type: str, location: str, ram: str, cpu: str, disk: str, name: str) -> None:
    if not callback:
        return
    try:
        await asyncio.wait_for(
            callback(progress_embed(stage, title, os_type, location, ram, cpu, disk, name)),
            timeout=PROGRESS_UPDATE_TIMEOUT,
        )
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        # UI/network failure must never turn a healthy VPS deployment into a rollback.
        logger.debug("Progress update skipped at stage %s: %s", stage, safe_log(exc))


async def create_vps(
    user: discord.User | discord.Member,
    *,
    os_type: str,
    location: str,
    ram: str,
    cpu: str,
    disk: str,
    progress: OperationCallback | None = None,
    backend_override: str | None = None,
) -> tuple[bool, str, sqlite3.Row | None]:
    normalized_os = normalize_os(os_type)
    normalized_location = normalize_location(location)
    if not normalized_os:
        return False, "Unsupported operating system.", None
    if not normalized_location:
        return False, "Unsupported location. Choose Singapore (SG) or India (IN).", None
    try:
        ram, cpu, disk = validate_resources(ram, cpu, disk)
    except ValueError as exc:
        return False, str(exc), None
    backend = "qemu"
    if db_is_banned(user.id):
        return False, "You are not allowed to create VPS instances.", None
    capacity_error = resource_capacity_error(ram, cpu, disk)
    if capacity_error:
        return False, capacity_error, None

    async with CREATE_LOCK:
        is_admin_user = ADMIN_BYPASS_LIMITS and ADMIN_ID > 0 and int(user.id) == int(ADMIN_ID)
        slot_limit = db_effective_slots(user.id)
        slot_used = db_vps_count(user.id)
        if not is_admin_user and slot_used >= slot_limit:
            return False, f"SLOTS FULL — you are using `{slot_used}/{slot_limit}` VPS slots.", None

        async with CAPACITY_LOCK:
            live_ok, live_running = await docker_running_count()
            if not live_ok:
                live_running = db_running_count()
            if not is_admin_user and live_running >= TOTAL_RUNNING_LIMIT:
                return False, f"Global running VPS limit reached ({TOTAL_RUNNING_LIMIT}).", None

        name = await next_container_name()
        hostname = f"{VPS_HOSTNAME_PREFIX}-{user.id}"[:63]
        resource_id: str | None = None

        async def qemu_progress(stage: int, title: str) -> None:
            await update_progress(
                progress, stage, title, os_type=normalized_os, location=normalized_location,
                ram=ram, cpu=cpu, disk=disk, name=name,
            )

        try:
            await qemu_progress(1, "Checking QEMU host tools")

            async def host_progress(title: str) -> None:
                await qemu_progress(2, title)

            host_ok, host_detail = await asyncio.wait_for(
                qemu_host_prepare(host_progress), timeout=max(60, QEMU_HOST_PREP_TIMEOUT)
            )
            if not host_ok:
                return False, f"QEMU host is not ready: {host_detail}", None

            await qemu_progress(2, "Preparing QEMU TCG")
            await qemu_progress(3, "Preparing official VM image")
            base_ok, base_detail, _ = await qemu_download_base(normalized_os)
            if not base_ok:
                return False, f"Could not prepare `{os_label(normalized_os)}` VM image: {base_detail}", None

            await qemu_progress(4, "Creating real QEMU VPS")
            resource_id, create_error = await qemu_create_vm(
                os_type=normalized_os, hostname=hostname, ram=ram, cpu=cpu, disk=disk,
                name=name, persistent_key=name,
            )
            if not resource_id:
                return False, f"Real QEMU VM creation failed: {create_error}", None

            await qemu_progress(5, "Booting real Linux VM")
            if await qemu_state(resource_id) != "running":
                raise RuntimeError("QEMU VM was created but did not remain running.")

            await qemu_progress(6, "Waiting for systemd and SSH")
            guest_ready, guest_error = await _wait_qemu_ready(resource_id)
            if not guest_ready:
                meta = qemu_load_meta(resource_id) or {}
                diag = ""
                log_path = Path(str(meta.get("log_path", "")))
                if log_path.exists():
                    with contextlib.suppress(OSError):
                        diag = "\n".join(log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-100:])
                raise RuntimeError((guest_error or "QEMU guest readiness failed.") + (f"\nSerial log:\n{safe_log(diag, 4000)}" if diag else ""))

            await qemu_progress(7, "Saving VPS record")
            db_upsert_user(user.id, str(user))
            db_insert_vps(
                user_id=user.id, container_id=resource_id, container_name=name,
                os_type=normalized_os, location=normalized_location, hostname=hostname,
                ram=ram, cpu=cpu, disk=disk, sshx_url=None, sshx_pid=None,
                public_ipv4=None, ipv4_verified_at=None, backend="qemu",
                ptero_server_id=None, ptero_identifier=None, ptero_user_id=None,
            )
            row = db_find_vps(user.id, resource_id)
            if not row:
                raise RuntimeError("VPS was created but could not be saved to SQLite.")

            console = None
            await qemu_progress(8, "Preparing optional console access")
            try:
                console = await asyncio.wait_for(
                    install_and_start_sshx(resource_id), timeout=max(20, SSHX_TOTAL_TIMEOUT + 5)
                )
            except Exception as exc:
                logger.warning("Optional SSHx setup failed for %s; VPS remains healthy: %s", clean(resource_id, 32), safe_log(exc))

            if console and console.get("pid"):
                db_update_vps(
                    resource_id,
                    sshx_url=normalize_sshx_url(console.get("url")) if console.get("url") else None,
                    sshx_pid=console.get("pid"),
                )

            with contextlib.suppress(Exception):
                await supervise_vps_ports(db_get_vps(row["id"]) or row)

            final_row = db_get_vps(row["id"]) or row
            await qemu_progress(10, "VPS Ready")
            return True, "Real QEMU VPS created successfully (TCG, no KVM).", final_row

        except asyncio.CancelledError:
            logger.warning("QEMU VPS creation cancelled for user %s", user.id)
            if resource_id:
                with contextlib.suppress(Exception):
                    await stop_sshx(resource_id)
                with contextlib.suppress(Exception):
                    await qemu_remove_vm(resource_id)
            raise
        except Exception as exc:
            logger.error("QEMU VPS creation failed: %s", safe_log(exc))
            if resource_id:
                with contextlib.suppress(Exception):
                    await stop_sshx(resource_id)
                with contextlib.suppress(Exception):
                    await qemu_remove_vm(resource_id)
            return False, f"VPS creation failed safely: {safe_log(exc)}", None


async def ptero_delete_server(server_id: int, force: bool = False) -> tuple[bool, str]:
    suffix = "?force=true" if force else ""
    status, body = await ptero_request("DELETE", f"application/servers/{int(server_id)}{suffix}")
    if status not in {200, 204}:
        return False, ptero_error_message(status, body)
    return True, "Pterodactyl server deleted."


async def ptero_suspend_server(server_id: int, suspended: bool) -> tuple[bool, str]:
    action = "suspend" if suspended else "unsuspend"
    status, body = await ptero_request("POST", f"application/servers/{int(server_id)}/{action}")
    if status not in {200, 204}:
        return False, ptero_error_message(status, body)
    return True, f"Pterodactyl server {action}ed."


async def docker_reinstall_vps(vps: sqlite3.Row, os_type: str) -> tuple[bool, str]:
    """Reinstall a real QEMU VPS while preserving its database identity."""
    normalized = normalize_os(os_type)
    if not normalized:
        return False, "Unsupported operating system."
    old_vm = str(vps["container_id"])
    new_name = f"{str(vps['container_name'])[:42]}-reinstall-{int(time.time()) % 100000}"[:63]
    new_vm: str | None = None
    try:
        await stop_sshx(old_vm)
        for p_row in db_list_ports(vps["id"]):
            await stop_port_forward(p_row)
        if await qemu_state(old_vm) == "running":
            await qemu_stop_vm(old_vm)

        new_vm, error = await qemu_create_vm(
            os_type=normalized, hostname=str(vps["hostname"]), ram=str(vps["ram"]),
            cpu=str(vps["cpu"]), disk=str(vps["disk"]), name=new_name,
            persistent_key=str(vps["container_name"]),
        )
        if not new_vm:
            with contextlib.suppress(Exception):
                await qemu_launch(old_vm)
            return False, f"Reinstall failed while creating the replacement VM: {error or 'QEMU failed.'}"

        ready, detail = await _wait_qemu_ready(new_vm)
        if not ready:
            with contextlib.suppress(Exception):
                await qemu_remove_vm(new_vm)
            with contextlib.suppress(Exception):
                await qemu_launch(old_vm)
            return False, f"Replacement VM failed readiness: {detail}"

        console = await install_and_start_sshx(new_vm)
        new_url = normalize_sshx_url(console.get("url")) if console and console.get("url") else None
        new_pid = console.get("pid") if console else None

        if await qemu_state(old_vm) in {"running", "stopped"}:
            with contextlib.suppress(Exception):
                await qemu_remove_vm(old_vm)

        # Snapshots are internal to the old qcow2 overlay and cannot safely
        # reference the replacement disk. Preserve the VPS, not stale snapshots.
        with contextlib.suppress(Exception):
            db_delete_all_snapshots(vps["id"])
        db_update_vps(
            old_vm,
            container_id=new_vm,
            container_name=new_name,
            os_type=normalized,
            status="running",
            suspended=0,
            sshx_url=new_url,
            sshx_pid=new_pid,
            backend="qemu",
        )
        latest = db_get_vps(vps["id"])
        if latest:
            await supervise_vps_ports(latest)
        return True, f"VPS reinstalled successfully with **{os_label(normalized)}**."
    except Exception as exc:
        logger.exception("QEMU reinstall failed for VPS #%s", vps["id"])
        if new_vm:
            with contextlib.suppress(Exception):
                await qemu_remove_vm(new_vm)
        with contextlib.suppress(Exception):
            await qemu_launch(old_vm)
        return False, f"Reinstall failed safely: {safe_log(exc)}"


async def lifecycle_action(vps: sqlite3.Row, action: str) -> tuple[bool, str]:
    async with vps_lock(vps["id"]):
        backend = str(vps["backend"] or "docker").lower()

        if backend == "pterodactyl":
            server_id = int(vps["ptero_server_id"] or 0)
            if not server_id:
                return False, "Pterodactyl server ID is missing from this VPS record."

            if action in {"start", "stop", "restart"}:
                if action == "start" and vps["suspended"]:
                    return False, "This VPS is suspended by an administrator."
                if action == "start" and not vps["suspended"]:
                    current_state = await ptero_status(vps)
                    if current_state != "running":
                        running_count = sum(
                            1 for row in db_get_all_vps()
                            if str(row["backend"] or "docker").lower() == "pterodactyl"
                            and str(row["status"]).lower() == "running"
                            and not row["suspended"]
                        )
                        if running_count >= TOTAL_RUNNING_LIMIT and not (ADMIN_BYPASS_LIMITS and int(vps["user_id"]) == int(ADMIN_ID)):
                            return False, f"Global running VPS limit reached ({TOTAL_RUNNING_LIMIT})."
                ok, message = await ptero_power(vps, action)
                if ok:
                    await asyncio.sleep(1)
                    status_now = await ptero_status(vps)
                    db_update_vps(vps["container_id"], status=status_now, sshx_url=await ptero_panel_link(vps))
                    return True, message
                return False, message

            if action == "suspend":
                ok, message = await ptero_suspend_server(server_id, True)
                if ok:
                    db_update_vps(vps["container_id"], status="stopped", suspended=1)
                return ok, message

            if action == "unsuspend":
                ok, message = await ptero_suspend_server(server_id, False)
                if ok:
                    db_update_vps(vps["container_id"], suspended=0)
                return ok, message

            if action == "delete":
                for p_row in db_list_ports(vps["id"]):
                    await stop_port_forward(p_row)
                ok, message = await ptero_delete_server(server_id, force=False)
                if not ok and "not found" in message.lower():
                    ok, message = await ptero_delete_server(server_id, force=True)
                if ok:
                    db_delete_vps(vps["container_id"])
                return ok, message

            if action == "reinstall":
                status, body = await ptero_request("POST", f"application/servers/{server_id}/reinstall")
                if status not in {200, 204}:
                    return False, ptero_error_message(status, body)
                return True, "Pterodactyl reinstall requested."

            if action == "rebuild":
                status, body = await ptero_request("POST", f"application/servers/{server_id}/rebuild")
                if status not in {200, 204}:
                    return False, ptero_error_message(status, body)
                return True, "Pterodactyl rebuild requested."

            return False, "Unsupported Pterodactyl VPS action."

        container = str(vps["container_id"])
        if backend != "qemu":
            return False, "Unsupported local VPS backend."
        exists = qemu_load_meta(container) is not None

        if action == "start":
            if vps["suspended"]:
                return False, "This VPS is suspended by an administrator."
            if not exists:
                return False, "The QEMU VM metadata no longer exists. Ask an administrator to recreate this VPS."
            async with CAPACITY_LOCK:
                _, current = await docker_running_count()
                already_running = (await qemu_state(container)) == "running"
                if not already_running and current >= TOTAL_RUNNING_LIMIT:
                    return False, f"Global running VPS limit reached ({TOTAL_RUNNING_LIMIT})."
                ok, error = await qemu_launch(container, qemu_running_forwards(int(vps["id"])))
            if not ok:
                return False, error or "Failed to start the VPS."
            if not already_running:
                ready, detail = await _wait_qemu_ready(container)
                if not ready:
                    return False, f"VPS started but readiness failed: {detail}"
            console = await install_and_start_sshx(container)
            existing = db_get_vps(vps["id"]) or vps
            db_update_vps(
                container, status="running",
                sshx_url=normalize_sshx_url(console.get("url")) if console and console.get("url") else existing["sshx_url"],
                sshx_pid=console.get("pid") if console and console.get("pid") else existing["sshx_pid"],
            )
            latest = db_get_vps(vps["id"]) or vps
            await supervise_vps_ports(latest)
            return True, "VPS started successfully." + (" Console refreshed." if console else " Press Console to retry SSHx.")

        if action == "stop":
            if exists:
                await stop_sshx(container)
                for p_row in db_list_ports(vps["id"]):
                    await stop_port_forward(p_row)
                if not await qemu_stop_vm(container) and await qemu_state(container) == "running":
                    return False, "Failed to stop the VPS."
            db_update_vps(container, status="stopped", sshx_url=None, sshx_pid=None)
            return True, "VPS stopped successfully."

        if action == "restart":
            if not exists:
                return False, "The QEMU VM metadata no longer exists."
            async with CAPACITY_LOCK:
                await stop_sshx(container)
                ok, error = await qemu_restart_vm(container, int(vps["id"]))
            if not ok:
                return False, error or "Failed to restart the VPS."
            ready, detail = await _wait_qemu_ready(container)
            if not ready:
                return False, f"VPS restarted but readiness failed: {detail}"
            console = await install_and_start_sshx(container)
            existing = db_get_vps(vps["id"]) or vps
            db_update_vps(
                container, status="running",
                sshx_url=normalize_sshx_url(console.get("url")) if console and console.get("url") else existing["sshx_url"],
                sshx_pid=console.get("pid") if console and console.get("pid") else existing["sshx_pid"],
            )
            latest = db_get_vps(vps["id"]) or vps
            await supervise_vps_ports(latest)
            return True, "VPS restarted successfully."

        if action == "reinstall":
            return False, "Select an operating system from the Reinstall menu first."

        if action == "delete":
            for p_row in db_list_ports(vps["id"]):
                await stop_port_forward(p_row)
            if exists:
                await stop_sshx(container)
                if not await qemu_remove_vm(container):
                    return False, "QEMU cleanup failed; the VPS record was kept."
            db_delete_vps(container)
            return True, "VPS deleted successfully."

        if action == "suspend":
            if exists:
                await stop_sshx(container)
                for p_row in db_list_ports(vps["id"]):
                    await stop_port_forward(p_row)
                await qemu_stop_vm(container)
            db_update_vps(container, status="stopped", suspended=1, sshx_url=None, sshx_pid=None)
            return True, "VPS stopped and suspended."

        if action == "unsuspend":
            db_update_vps(container, suspended=0)
            return True, "VPS unsuspended."

        return False, "Unsupported VPS action."


async def create_console_access(vps: sqlite3.Row, user: discord.User | discord.Member) -> tuple[bool, str]:
    backend = str(vps["backend"] or "docker").lower()
    if backend == "pterodactyl":
        status = await ptero_status(vps)
        if status != "running":
            return False, "Start the Pterodactyl server before opening Console."
        url = await ptero_panel_link(vps)
        if not url:
            return False, "Pterodactyl panel URL is not configured."
        db_update_vps(vps["container_id"], status="running", sshx_url=url, sshx_pid=None)
        sent = await safe_dm(user, make_embed("✨ RGNODES™ • 🦖 Pterodactyl Panel", "Open your VPS panel from the button below."), sshx_view(url))
        return True, "Pterodactyl panel access link sent by DM." if sent else "Pterodactyl panel is ready, but your DM is closed."

    backend = str(vps["backend"] or "qemu").lower()
    state = await qemu_state(str(vps["container_id"])) if backend == "qemu" else await docker_state(str(vps["container_id"]))
    if state != "running":
        db_update_vps(vps["container_id"], status="stopped", sshx_url=None, sshx_pid=None)
        return False, "Start the VPS before opening Console."
    try:
        console = await asyncio.wait_for(
            install_and_start_sshx(vps["container_id"]),
            timeout=max(20, SSHX_TOTAL_TIMEOUT + 5),
        )
    except asyncio.TimeoutError:
        console = None
        logger.warning("SSHx Console request timed out for VPS %s", vps["id"])
    if not console:
        existing_url = normalize_sshx_url(vps["sshx_url"]) if vps["sshx_url"] else None
        existing_pid = str(vps["sshx_pid"] or "")
        if existing_url and existing_pid and await sshx_process_alive(vps["container_id"], existing_pid):
            return True, "Private SSHx link is still active and was kept unchanged."
        db_update_vps(vps["container_id"], sshx_url=None, sshx_pid=None)
        return False, "SSHx could not start a console session. The VPS is still online. Press Console again after checking SSHx network/launch logs."

    console_pid = str(console.get("pid") or "")
    console_url = normalize_sshx_url(console.get("url")) if console.get("url") else None

    # The launcher is intentionally non-blocking. When SSHx has started but
    # its encrypted browser URL has not been emitted yet, read the persisted
    # state once more after a very short delay. This does not turn deployment
    # into a long polling loop.
    if console_pid and not console_url:
        await asyncio.sleep(0.35)
        late_url, late_pid = await _read_sshx_state(vps["container_id"])
        if late_url and late_pid:
            console_url, console_pid = late_url, late_pid

    if not console_url:
        if console_pid and await sshx_process_alive(vps["container_id"], console_pid):
            db_update_vps(vps["container_id"], sshx_url=None, sshx_pid=console_pid)
            return False, "SSHx is running and initializing its encrypted console link. Press Console again in a moment."
        db_update_vps(vps["container_id"], sshx_url=None, sshx_pid=None)
        return False, "SSHx started incorrectly and stopped. Check the VPS SSHx log and press Console again."

    db_update_vps(vps["container_id"], sshx_url=console_url, sshx_pid=console_pid or None)
    network = await detect_public_network(force=True)
    ip_ok = valid_public_ipv4(network.get("ip"))
    if ip_ok:
        db_set_vps_ipv4(vps["container_id"], network["ip"])
    dm_sent = await safe_dm(user, console_embed(vps["container_name"], console_url, network.get("ip") if ip_ok else None, actual_location_label(network)), sshx_view(console_url))
    if ip_ok:
        await safe_dm(user, ipv4_dm_embed(vps, network))
    return (True, "Private SSHx link generated and sent to your DM." if dm_sent else "Console is ready, but your DM is closed. Enable DMs and press Console again.")


# ================================================================
# Public network identity + real host location
# ================================================================

NETWORK_CACHE: dict[str, str] = {"ip": "N/A", "country": "N/A", "region": "N/A", "city": "N/A"}
NETWORK_CACHE_AT = 0.0
NETWORK_LOCK = asyncio.Lock()


def valid_public_ipv4(value: str | None) -> bool:
    try:
        ip = ipaddress.ip_address(str(value or "").strip())
        return isinstance(ip, ipaddress.IPv4Address) and ip.is_global
    except ValueError:
        return False


def local_ipv4_addresses() -> set[str]:
    addresses: set[str] = set()
    try:
        for item in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addresses.add(item[4][0])
    except OSError:
        pass
    # iproute2 is already a bootstrap dependency; use it when available so
    # cloud secondary IPv4 addresses are detected reliably.
    return addresses


def _fetch_real_public_ipv4_sync() -> str | None:
    """Return an externally observed, globally routable IPv4 only after quorum.

    This is the host's real Internet egress/public IPv4. We intentionally do
    not invent or derive a public address from private container addresses.
    A value must be independently observed by at least two providers.
    """
    headers = {"User-Agent": "RGNODES-VPS/IPv4-verify"}
    endpoints = (
        "https://api.ipify.org",
        "https://icanhazip.com",
        "https://ifconfig.me/ip",
        "https://checkip.amazonaws.com",
    )
    observations: list[str] = []
    for url in endpoints:
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=7) as resp:
                value = resp.read().decode("utf-8", "replace").strip()
            # Reject anything containing extra text, not only invalid ipaddress objects.
            if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value) and valid_public_ipv4(value):
                observations.append(value)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            continue
    counts: dict[str, int] = {}
    for value in observations:
        counts[value] = counts.get(value, 0) + 1
    if not counts:
        return None
    winner, votes = max(counts.items(), key=lambda item: item[1])
    # Two independent confirmations are required for a verified address.
    return winner if votes >= 2 else None


async def real_public_ipv4(force: bool = False) -> str | None:
    global NETWORK_CACHE_AT, NETWORK_CACHE
    now = asyncio.get_running_loop().time()
    cached = str(NETWORK_CACHE.get("ip") or "")
    if not force and NETWORK_CACHE_AT and now - NETWORK_CACHE_AT < IPV4_REFRESH and valid_public_ipv4(cached):
        return cached
    ip = await asyncio.to_thread(_fetch_real_public_ipv4_sync)
    if ip:
        NETWORK_CACHE["ip"] = ip
        NETWORK_CACHE_AT = asyncio.get_running_loop().time()
    return ip


async def detect_public_network(force: bool = False) -> dict[str, str]:
    global NETWORK_CACHE_AT, NETWORK_CACHE
    now = asyncio.get_running_loop().time()
    if not force and NETWORK_CACHE_AT and now - NETWORK_CACHE_AT < PUBLIC_IP_REFRESH:
        return dict(NETWORK_CACHE)
    async with NETWORK_LOCK:
        now = asyncio.get_running_loop().time()
        if not force and NETWORK_CACHE_AT and now - NETWORK_CACHE_AT < PUBLIC_IP_REFRESH:
            return dict(NETWORK_CACHE)

        verified_ip = await real_public_ipv4(force=force)
        if not valid_public_ipv4(verified_ip):
            # Keep previously verified information only while it is still valid.
            return dict(NETWORK_CACHE)

        def fetch_geo() -> dict[str, str]:
            headers = {"User-Agent": "RGNODES-VPS/1.0"}
            for url in ("https://ipapi.co/json/", "https://ipinfo.io/json"):
                try:
                    req = urllib.request.Request(url, headers=headers)
                    with urllib.request.urlopen(req, timeout=7) as resp:
                        data = json.loads(resp.read().decode("utf-8", "replace"))
                    # The IP shown to users always comes from quorum verification;
                    # geo providers supply location metadata only.
                    return {
                        "ip": verified_ip,
                        "country": str(data.get("country_name") or data.get("country") or "N/A"),
                        "region": str(data.get("region") or data.get("regionName") or "N/A"),
                        "city": str(data.get("city") or "N/A"),
                    }
                except (urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
                    continue
            return {"ip": verified_ip, "country": "N/A", "region": "N/A", "city": "N/A"}

        NETWORK_CACHE = fetch_geo()
        NETWORK_CACHE["ip"] = verified_ip
        NETWORK_CACHE_AT = asyncio.get_running_loop().time()
        return dict(NETWORK_CACHE)


def actual_location_label(network: dict[str, str]) -> str:
    country = network.get("country", "N/A")
    if country in {"Singapore", "SG"}:
        return "Singapore 🇸🇬"
    if country in {"India", "IN"}:
        return "India 🇮🇳"
    return clean(country, 64)


# ================================================================
# Port forwarding (10 TCP mappings per VPS, supervised 24/7)
# ================================================================

PORT_LOCK = asyncio.Lock()


def port_in_use(host: str, port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return sock.connect_ex((host, port)) == 0
    except OSError:
        return True
    finally:
        sock.close()


def port_bindable(port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


async def docker_container_ip(container: str) -> str | None:
    rc, out, _ = await docker_cli("inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", container, timeout=20, retries=1)
    if rc != 0:
        return None
    ip = out.decode("utf-8", "replace").strip().splitlines()[0] if out else ""
    return ip if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", ip) else None


async def process_matches(pid: int, needle: str) -> bool:
    if pid <= 0:
        return False
    try:
        proc_cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", "replace")
        return needle.lower() in proc_cmdline.lower()
    except (OSError, UnicodeError):
        return False


async def process_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


async def kill_host_pid(pid: int | None, expected_command: str | None = None) -> None:
    if not pid or int(pid) <= 0:
        return
    pid = int(pid)
    if expected_command and not await process_matches(pid, expected_command):
        return
    if not await process_alive(pid):
        return
    with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
        os.kill(pid, signal.SIGTERM)
    for _ in range(10):
        if not await process_alive(pid):
            return
        await asyncio.sleep(0.1)
    if await process_alive(pid):
        with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
            os.kill(pid, signal.SIGKILL)


async def allocate_host_port() -> int | None:
    conn = db_connect()
    try:
        reserved = {int(r[0]) for r in conn.execute("SELECT host_port FROM vps_ports")}
    finally:
        conn.close()
    start = max(1024, PORT_RANGE_START)
    end = min(65535, PORT_RANGE_END)
    for port in range(start, end + 1):
        if port in reserved:
            continue
        if port_bindable(port):
            return port
    return None


async def verify_host_listener(port: int) -> bool:
    """Confirm a local TCP listener exists on the selected host port."""
    try:
        rc, out, _ = await system_command("ss", "-H", "-ltn", timeout=8) if command_available("ss") else (127, "", "")
        if rc == 0:
            for line in out.splitlines():
                if re.search(rf":{int(port)}\b", line):
                    return True
        # Fallback: probe localhost. This does not guarantee Internet reachability
        # but confirms the forwarding process is accepting local TCP connections.
        return await asyncio.to_thread(port_in_use, "127.0.0.1", int(port))
    except Exception:
        return False


async def start_port_forward(port_row: sqlite3.Row, vps: sqlite3.Row) -> tuple[bool, str]:
    if str(port_row["protocol"]).lower() != "tcp":
        return False, "Only TCP forwarding is enabled."
    if str(vps["backend"] or "docker").lower() == "qemu":
        if await qemu_state(vps["container_id"]) != "running":
            db_update_port(port_row["id"], status="stopped", pid=None, target_ip=None)
            return False, "VPS is not running. Start it first."
        host_port = int(port_row["host_port"])
        if str(port_row["status"]).lower() == "running":
            desired = [
                (int(row["host_port"]), int(row["container_port"]))
                for row in db_list_ports(vps["id"])
                if str(row["protocol"]).lower() == "tcp" and str(row["status"]).lower() == "running"
            ]
            if (host_port, int(port_row["container_port"])) in desired and await qemu_state(vps["container_id"]) == "running":
                return True, f"QEMU forwarding is already online on public port `{host_port}`."
        if not port_bindable(host_port) and str(port_row["status"]).lower() != "running":
            db_update_port(port_row["id"], status="error", pid=None, target_ip=None)
            return False, f"Public port `{host_port}` is already in use."
        desired = [
            (int(row["host_port"]), int(row["container_port"]))
            for row in db_list_ports(vps["id"])
            if str(row["protocol"]).lower() == "tcp" and (int(row["id"]) == int(port_row["id"]) or str(row["status"]).lower() == "running")
        ]
        await qemu_stop_vm(vps["container_id"])
        ok, detail = await qemu_launch(vps["container_id"], desired)
        if not ok:
            db_update_port(port_row["id"], status="error", pid=None, target_ip=None)
            return False, detail or "QEMU network reconfiguration failed."
        db_update_port(port_row["id"], status="running", pid=None, target_ip="127.0.0.1")
        return True, f"QEMU forwarding is online on public port `{host_port}`."
    if await docker_state(vps["container_id"]) != "running":
        db_update_port(port_row["id"], status="stopped", pid=None, target_ip=None)
        return False, "VPS is not running. Start it first."
    if not command_available("socat"):
        return False, "Port forwarding requires `socat`. Run `/install-system confirm` as administrator."

    public_ipv4 = str(vps["public_ipv4"] or "").strip()
    if not valid_public_ipv4(public_ipv4):
        public_ipv4 = await real_public_ipv4(force=True) or ""
        if valid_public_ipv4(public_ipv4):
            db_set_vps_ipv4(vps["container_id"], public_ipv4)
    if not valid_public_ipv4(public_ipv4):
        return False, "Verified real public IPv4 is unavailable; forwarding was not started."

    target_ip = await docker_container_ip(vps["container_id"])
    if not target_ip:
        return False, "Could not determine the VPS container IPv4."
    try:
        target_obj = ipaddress.ip_address(target_ip)
        if not isinstance(target_obj, ipaddress.IPv4Address) or not target_obj.is_private:
            return False, "Container IPv4 validation failed."
    except ValueError:
        return False, "Container IPv4 validation failed."

    host_port = int(port_row["host_port"])
    container_port = int(port_row["container_port"])
    old_pid = int(port_row["pid"]) if str(port_row["pid"] or "").isdigit() else None

    async with PORT_LOCK:
        if old_pid and await process_alive(old_pid) and await process_matches(old_pid, "socat"):
            if str(port_row["target_ip"] or "") == target_ip and await verify_host_listener(host_port):
                db_update_port(port_row["id"], status="running")
                return True, f"Port forwarding is already online on public port `{host_port}`."
            await kill_host_pid(old_pid, "socat")

        if not port_bindable(host_port):
            # It may be the same listener just not represented by our PID; refuse
            # to steal an unrelated service's port.
            db_update_port(port_row["id"], status="error", pid=None, target_ip=target_ip)
            return False, f"Public port `{host_port}` is already in use."

        pid, error = await spawn_detached(
            "socat",
            "-ly",
            f"TCP4-LISTEN:{host_port},bind=0.0.0.0,reuseaddr,fork",
            f"TCP4:{target_ip}:{container_port}",
        )
        if not pid:
            db_update_port(port_row["id"], status="error", pid=None, target_ip=target_ip)
            return False, error or "Could not start the forwarding process."

        await asyncio.sleep(0.25)
        if not await process_alive(pid) or not await process_matches(pid, "socat") or not await verify_host_listener(host_port):
            await kill_host_pid(pid, "socat")
            db_update_port(port_row["id"], status="error", pid=None, target_ip=target_ip)
            return False, f"Forwarding process started but could not be verified on port `{host_port}`."

        db_update_port(port_row["id"], status="running", pid=pid, target_ip=target_ip)
        return True, f"Port forwarding is online: public port `{host_port}` → VPS port `{container_port}/TCP`."


async def stop_port_forward(port_row: sqlite3.Row) -> None:
    await kill_host_pid(int(port_row["pid"]) if port_row["pid"] else None, "socat")
    db_update_port(port_row["id"], status="stopped", pid=None)


async def supervise_vps_ports(vps: sqlite3.Row) -> None:
    try:
        ports = db_list_ports(vps["id"])
        if not ports:
            return
        running = (await docker_state(vps["container_id"])) == "running"
        for p_row in ports:
            try:
                if running:
                    await start_port_forward(p_row, vps)
                else:
                    await stop_port_forward(p_row)
            except Exception as exc:
                logger.warning("Port supervisor failed for VPS #%s port #%s: %s", vps["id"], p_row["id"], safe_log(exc))
    except Exception as exc:
        logger.warning("Port supervisor unavailable for VPS #%s: %s", vps["id"], safe_log(exc))



# ================================================================
# Docker snapshots
# ================================================================
SNAPSHOT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


async def docker_snapshot_create(vps: sqlite3.Row, name: str) -> tuple[bool, str]:
    if str(vps["backend"] or "qemu").lower() != "qemu":
        return False, "Snapshots are available for real QEMU VPS instances."
    name = name.strip()
    if not SNAPSHOT_NAME_RE.fullmatch(name):
        return False, "Snapshot name must be 1–64 characters and use only letters, numbers, `.`, `_`, or `-`."
    if db_get_snapshot(vps["id"], name):
        return False, "A snapshot with that name already exists."
    vm_id = str(vps["container_id"])
    if await qemu_state(vm_id) != "running":
        return False, "Start the VPS before creating a snapshot."
    meta = qemu_load_meta(vm_id) or {}
    disk = Path(str(meta.get("disk_path", "")))
    if not disk.exists():
        return False, "The QEMU disk image is missing."
    snap_dir = disk.parent / "snapshots"
    snap_dir.mkdir(parents=True, exist_ok=True)
    snap_path = snap_dir / f"{name}.qcow2"
    was_running = await qemu_state(vm_id) == "running"
    if was_running:
        await qemu_stop_vm(vm_id)
    try:
        rc, _, err = await run_process("qemu-img", "snapshot", "-c", name, str(disk), timeout=180)
        if rc != 0:
            return False, safe_log(err.decode("utf-8", "replace").strip() or "QEMU snapshot failed.")
        db_insert_snapshot(vps["id"], name, str(disk))
        return True, f"Snapshot `{name}` created successfully."
    finally:
        if was_running:
            with contextlib.suppress(Exception):
                await qemu_launch(vm_id)


async def docker_snapshot_restore(vps: sqlite3.Row, name: str) -> tuple[bool, str]:
    if str(vps["backend"] or "qemu").lower() != "qemu":
        return False, "Snapshot restore is currently available for real QEMU VPS instances."
    snap = db_get_snapshot(vps["id"], name.strip())
    if not snap:
        return False, "Snapshot not found."
    vm_id = str(vps["container_id"])
    meta = qemu_load_meta(vm_id) or {}
    disk = Path(str(meta.get("disk_path", "")))
    if not disk.exists():
        return False, "The QEMU disk image is missing."
    await qemu_stop_vm(vm_id)
    rc, _, err = await run_process("qemu-img", "snapshot", "-a", str(name).strip(), str(disk), timeout=180)
    if rc != 0:
        return False, safe_log(err.decode("utf-8", "replace").strip() or "QEMU snapshot restore failed.")
    ok, detail = await qemu_launch(vm_id)
    if not ok:
        return False, detail or "QEMU could not restart after snapshot restore."
    ready, detail = await _wait_qemu_ready(vm_id)
    if not ready:
        return False, detail
    return True, f"Snapshot `{name}` restored successfully."


async def snapshot_delete_image(vps: sqlite3.Row, name: str) -> tuple[bool, str]:
    if str(vps["backend"] or "qemu").lower() != "qemu":
        return False, "Snapshot deletion is currently available for real QEMU VPS instances."
    snap = db_get_snapshot(vps["id"], name.strip())
    if not snap:
        return False, "Snapshot not found."
    vm_id = str(vps["container_id"])
    meta = qemu_load_meta(vm_id) or {}
    disk = Path(str(meta.get("disk_path", "")))
    if disk.exists():
        rc, _, err = await run_process("qemu-img", "snapshot", "-d", str(name).strip(), str(disk), timeout=120)
        if rc != 0:
            return False, safe_log(err.decode("utf-8", "replace").strip() or "QEMU snapshot deletion failed.")
    db_delete_snapshot(vps["id"], name.strip())
    return True, f"Snapshot `{name}` deleted successfully."

# ================================================================
# Host/system bootstrap
# ================================================================

SYSTEM_PACKAGE_LOCK = asyncio.Lock()
SYSTEM_PACKAGES = (
    "ca-certificates",
    "curl",
    "bash",
    "coreutils",
    "procps",
    "iproute2",
    "iputils-ping",
    "tar",
    "gzip",
    "unzip",
    "socat",
    "systemd",
    "systemd-sysv",
    "dbus",
)
DOCKER_PACKAGE = "docker.io"


def host_os_info() -> dict[str, str]:
    data: dict[str, str] = {}
    try:
        for raw in Path("/etc/os-release").read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" not in raw or raw.startswith("#"):
                continue
            key, value = raw.split("=", 1)
            data[key] = value.strip().strip('"')
    except (OSError, UnicodeError):
        pass
    try:
        pid1 = Path("/proc/1/comm").read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        pid1 = "unknown"
    return {
        "id": data.get("ID", "unknown"),
        "name": data.get("PRETTY_NAME", data.get("NAME", "Unknown Linux")),
        "version": data.get("VERSION_ID", "unknown"),
        "pid1": pid1 or "unknown",
        "systemd": str(pid1 == "systemd" or Path("/run/systemd/system").exists()).lower(),
        "root": str(os.geteuid() == 0).lower() if hasattr(os, "geteuid") else "unknown",
    }


async def system_command(*args: str, timeout: float = 180) -> tuple[int, str, str]:
    rc, out, err = await run_process(*args, timeout=timeout)
    return rc, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


def command_available(name: str) -> bool:
    return shutil.which(name) is not None


async def _probe_docker_info() -> tuple[bool, str]:
    """Probe the Docker CLI/daemon without attempting installation or repair."""
    if not command_available("docker"):
        return False, "Docker CLI is not installed or is not available in PATH."
    rc, out, err = await docker_cli("info", timeout=30, retries=2)
    if rc == 0:
        return True, out.decode("utf-8", "replace")
    detail = safe_log(err.decode("utf-8", "replace").strip() or out.decode("utf-8", "replace").strip() or "Docker daemon is unavailable.")
    return False, detail


async def docker_daemon_ready() -> tuple[bool, str]:
    return await _probe_docker_info()


async def install_system_dependencies() -> tuple[bool, str]:
    async with SYSTEM_PACKAGE_LOCK:
        info = host_os_info()
        if info["root"] != "true":
            return False, "Administrator/root privileges are required. Run the bot as root or grant it the required host permissions."

        package_manager = shutil.which("apt-get")
        if not package_manager:
            if shutil.which("apk"):
                return False, "This host uses Alpine/apk. Automatic bootstrap is intentionally limited to Debian/Ubuntu apt hosts."
            return False, "No supported package manager was found. Supported automatic bootstrap: Debian/Ubuntu with apt-get."

        os_id = info["id"].lower()
        if os_id not in {"debian", "ubuntu", "linuxmint", "pop", "raspbian"}:
            return False, f"Unsupported host OS for automatic bootstrap: `{info['name']}`."

        messages: list[str] = [f"Host: {info['name']}", f"PID 1: `{info['pid1']}`"]
        env = os.environ.copy()
        env["DEBIAN_FRONTEND"] = "noninteractive"

        async def apt(*args: str, timeout: float = 300) -> tuple[int, str, str]:
            return await system_command(
                "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", *args,
                timeout=timeout,
            )

        # Do not assume systemd exists just because systemctl exists. This is
        # important in Docker/containers/WSL-like environments.
        rc, _, err = await apt("update", "-y", timeout=300)
        if rc != 0:
            return False, "apt-get update failed:\n" + safe_log(err.strip() or "unknown apt error")

        # command/package names differ (ca-certificates has no binary check).
        # Install the full small base set; apt safely skips packages already installed.
        rc, out, err = await apt("install", "-y", "--no-install-recommends", *SYSTEM_PACKAGES, timeout=360)
        if rc != 0:
            return False, "Base dependency installation failed:\n" + safe_log(err.strip() or out.strip() or "unknown apt error")
        messages.append("Base Linux dependencies: installed/verified.")

        # Install Docker only when the CLI is actually missing. Existing Docker
        # installations are never replaced by this command.
        if not command_available("docker"):
            rc, out, err = await apt("install", "-y", "--no-install-recommends", DOCKER_PACKAGE, timeout=360)
            if rc != 0:
                return False, "Docker installation failed:\n" + safe_log(err.strip() or out.strip() or "unknown apt error")
            messages.append("Docker CLI: installed from the distro package.")
        else:
            messages.append("Docker CLI: already present.")

        # Refresh PATH-dependent checks after package installation.
        docker_bin = shutil.which("docker")
        if not docker_bin:
            return False, "\n".join(messages + ["Docker CLI is still unavailable after installation."])

        if info["systemd"] == "true" and command_available("systemctl"):
            rc_unit, _, _ = await system_command("systemctl", "list-unit-files", "docker.service", timeout=30)
            if rc_unit == 0:
                rc_start, out_start, err_start = await system_command(
                    "systemctl", "enable", "--now", "docker.service", timeout=90
                )
                if rc_start == 0:
                    messages.append("Docker service: enabled and started via systemd.")
                else:
                    messages.append("Docker service: systemd detected, but start failed: " + safe_log(err_start.strip() or out_start.strip() or "unknown error"))
            else:
                messages.append("systemd: running, but docker.service was not found; Docker daemon may be socket-managed or externally managed.")
        else:
            messages.append(
                "systemd: not active as PID 1. The command did not attempt `systemctl` "
                "because systemd cannot manage services from this environment."
            )

        ready, docker_detail = await _probe_docker_info()
        if ready:
            messages.append("Docker daemon: ✅ reachable.")
        else:
            messages.append("Docker daemon: ⚠️ not reachable.")
            messages.append("Reason: " + safe_log(docker_detail))

        messages.append("Install-system completed without modifying VPS containers.")
        return ready, "\n".join(messages)


# ================================================================
# Bot + UI
# ================================================================

intents = discord.Intents.default()
intents.message_content = True


class RGNODESBot(commands.Bot):
    def __init__(self) -> None:
        super().__init__(command_prefix=PREFIX, intents=intents, help_command=None)
        self.synced = False
        self.loops_started = False


bot = RGNODESBot()
CLAIMED_INTERACTION_IDS: set[str] = set()
INTERACTION_GUARD_LOCK = asyncio.Lock()

async def claim_interaction_once(interaction: discord.Interaction) -> bool:
    """Atomically allow exactly one response pipeline per Discord interaction."""
    interaction_id = getattr(interaction, "id", None)
    if interaction_id is None:
        return True
    key = str(interaction_id)
    async with INTERACTION_GUARD_LOCK:
        if key in CLAIMED_INTERACTION_IDS:
            return False
        if not claim_processed_event(f"interaction:{key}", "interaction"):
            return False
        CLAIMED_INTERACTION_IDS.add(key)
        if len(CLAIMED_INTERACTION_IDS) > 20000:
            CLAIMED_INTERACTION_IDS.clear()
            CLAIMED_INTERACTION_IDS.add(key)
        return True


class ReinstallView(discord.ui.View):
    def __init__(self, vps_id: int, owner_id: int):
        super().__init__(timeout=300)
        self.vps_id = int(vps_id)
        self.owner_id = int(owner_id)
        self.os_select = discord.ui.Select(
            placeholder="Select OS for clean reinstall",
            min_values=1, max_values=1, row=0,
            options=[
                discord.SelectOption(label=c["label"], value=k, emoji="🟠" if k.startswith("ubuntu") else "🔵")
                for k, c in OS_CONFIG.items()
            ],
        )
        self.confirm_button = discord.ui.Button(label="Confirm Reinstall", emoji="♻️", style=discord.ButtonStyle.danger, row=1)
        self.cancel_button = discord.ui.Button(label="Cancel", emoji="✖️", style=discord.ButtonStyle.secondary, row=1)
        self.os_select.callback = self.select_os
        self.confirm_button.callback = self.confirm
        self.cancel_button.callback = self.cancel
        self.add_item(self.os_select); self.add_item(self.confirm_button); self.add_item(self.cancel_button)

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        vps = db_get_vps(self.vps_id)
        allowed = bool(vps and (interaction.user.id in {self.owner_id, ADMIN_ID} or db_find_accessible_vps(interaction.user.id, str(self.vps_id))))
        if allowed:
            return True
        await safe_respond(interaction, embed=make_embed("❌ Access Denied", "You do not have access to this VPS."))
        return False

    async def select_os(self, interaction: discord.Interaction) -> None:
        value = self.os_select.values[0]
        await safe_component_edit(
            interaction,
            embed=make_embed("♻️ Reinstall VPS", f"Selected OS: **{os_label(value)}**\n\nThis performs a clean reinstall and replaces the current container. Existing VPS data inside the container will be lost.\n\nPress **Confirm Reinstall** to continue."),
            view=self,
        )

    async def confirm(self, interaction: discord.Interaction) -> None:
        if not await claim_interaction_once(interaction):
            return
        selected = self.os_select.values[0] if self.os_select.values else ""
        if not selected:
            await safe_respond(interaction, embed=make_embed("⚠️ Select OS", "Choose an operating system before confirming reinstall."))
            return
        if not await safe_defer(interaction, ephemeral=True, claim=False):
            return
        try:
            vps = db_get_vps(self.vps_id)
            if not vps:
                await safe_edit_original(interaction, embed=make_embed("❌ VPS Not Found", "This VPS no longer exists."), view=None)
                return
            backend = str(vps["backend"] or "qemu").lower()
            if backend in {"docker", "qemu"}:
                async with vps_lock(self.vps_id):
                    ok, message = await docker_reinstall_vps(vps, selected)
            elif backend == "pterodactyl":
                # lifecycle_action() owns its own VPS lock; do not nest it here.
                ok, message = await lifecycle_action(vps, "reinstall")
                if ok:
                    message = f"Pterodactyl reinstall requested. The panel controls the server image; OS selector **{os_label(selected)}** was informational only."
            else:
                ok, message = False, "Unsupported VPS backend."
            if ok:
                latest = db_get_vps(self.vps_id) or vps
                stats, uptime, disk, network, ports = await _dashboard_live_data(latest)
                await safe_edit_original(interaction, embed=dashboard_embed(latest, stats, uptime, disk, network, ports), view=ManageView(latest["id"], latest["user_id"]))
            else:
                await safe_edit_original(interaction, embed=make_embed("❌ Reinstall Failed", message), view=ManageView(vps["id"], vps["user_id"]))
        finally:
            self.stop()

    async def cancel(self, interaction: discord.Interaction) -> None:
        await safe_component_edit(
            interaction,
            embed=make_embed("♻️ Reinstall Cancelled", "No changes were made to this VPS."),
            view=None,
        )
        self.stop()


class ManageView(discord.ui.View):
    def __init__(self, vps_id: int, owner_id: int):
        super().__init__(timeout=900)
        self.vps_id = int(vps_id)
        self.owner_id = int(owner_id)

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        vps = db_get_vps(self.vps_id)
        allowed = bool(vps and (
            int(interaction.user.id) in {int(self.owner_id), int(ADMIN_ID)}
            or db_find_accessible_vps(int(interaction.user.id), str(self.vps_id))
        ))
        if allowed:
            return True
        await safe_respond(
            interaction,
            embed=make_embed("❌ Access Denied", "You do not have access to this VPS."),
        )
        return False

    async def run_action(self, interaction: discord.Interaction, action: str) -> None:
        if not await claim_interaction_once(interaction):
            return
        if not await safe_defer(interaction, ephemeral=True, claim=False):
            return
        vps = db_get_vps(self.vps_id)
        if not vps:
            await safe_followup(interaction, embed=make_embed("❌ VPS Not Found", "This VPS no longer exists."))
            self.stop()
            return
        try:
            if action in {"stats", "refresh"}:
                await show_dashboard(interaction, vps)
                return
            if action == "console":
                ok, message = await create_console_access(vps, interaction.user)
                latest = db_get_vps(self.vps_id) or vps
                if ok and latest["sshx_url"]:
                    # Keep console result as a single edited response; no duplicate follow-up.
                    await safe_edit_original(
                        interaction,
                        embed=make_embed("✅ Console Ready", message),
                        view=sshx_view(latest["sshx_url"]),
                    )
                else:
                    await safe_edit_original(
                        interaction,
                        embed=make_embed("✅ Console Ready" if ok else "❌ Console Failed", message),
                        view=ManageView(vps["id"], vps["user_id"]) if ok else ManageView(vps["id"], vps["user_id"]),
                    )
                return
            ok, message = await lifecycle_action(vps, action)
            if ok and action in {"start", "restart"}:
                await send_private_ipv4(interaction.user, db_get_vps(vps["id"]) or vps)
            if action == "delete" and ok:
                self.stop()
                await safe_edit_original(interaction, embed=make_embed("🗑️ VPS Removed", f"`{clean(vps['container_name'])}` and its forwarding rules were removed successfully."), view=None)
                return
            latest = await refresh_vps_record_state(db_get_vps(self.vps_id) or vps)
            if str(latest["backend"] or "qemu").lower() in {"docker", "qemu"}:
                await asyncio.gather(supervise_vps_ports(latest), detect_public_network(), return_exceptions=True)
                ports = db_list_ports(latest["id"])
            else:
                ports = []
            stats, uptime, disk = await _safe_vps_live_data(latest)
            dash = dashboard_embed(latest, stats, uptime, disk, NETWORK_CACHE, ports)
            prefix = "✅" if ok else "❌"
            dash.description = f"{prefix} {message}\n\n`{clean(latest['container_name'])}`\n\n**Status:** {status_text(latest['status'], bool(latest['suspended']))}"
            await safe_edit_original(interaction, embed=dash, view=ManageView(latest["id"], latest["user_id"]))
        except Exception as exc:
            logger.error("Manage action failed for VPS #%s: %s", self.vps_id, safe_log(exc))
            await safe_edit_original(
                interaction,
                embed=make_embed("❌ Action Failed", "The action could not be completed safely."),
                view=ManageView(vps["id"], vps["user_id"]),
            )

    @discord.ui.button(label="Start", emoji="▶️", style=discord.ButtonStyle.secondary, row=0)
    async def start(self, interaction: discord.Interaction, button: discord.ui.Button): await self.run_action(interaction, "start")
    @discord.ui.button(label="Stop", emoji="⏹️", style=discord.ButtonStyle.secondary, row=0)
    async def stop_vps(self, interaction: discord.Interaction, button: discord.ui.Button): await self.run_action(interaction, "stop")
    @discord.ui.button(label="Console", emoji="🖥️", style=discord.ButtonStyle.secondary, row=0)
    async def console(self, interaction: discord.Interaction, button: discord.ui.Button): await self.run_action(interaction, "console")
    @discord.ui.button(label="Stats", emoji="📊", style=discord.ButtonStyle.secondary, row=0)
    async def stats(self, interaction: discord.Interaction, button: discord.ui.Button): await self.run_action(interaction, "stats")
    @discord.ui.button(label="Restart", emoji="🔄", style=discord.ButtonStyle.secondary, row=1)
    async def restart(self, interaction: discord.Interaction, button: discord.ui.Button): await self.run_action(interaction, "restart")
    @discord.ui.button(label="Reinstall", emoji="♻️", style=discord.ButtonStyle.danger, row=1)
    async def reinstall(self, interaction: discord.Interaction, button: discord.ui.Button):
        vps = db_get_vps(self.vps_id)
        if not vps:
            await safe_respond(interaction, embed=make_embed("❌ VPS Not Found", "This VPS no longer exists."))
            return
        await safe_respond(
            interaction,
            embed=make_embed("♻️ Reinstall VPS", "Select the operating system for the clean reinstall, then confirm.\n\n⚠️ Existing data inside the current VPS container will be lost."),
            view=ReinstallView(self.vps_id, self.owner_id),
            ephemeral=True,
        )
    @discord.ui.button(label="Refresh", emoji="🔃", style=discord.ButtonStyle.secondary, row=1)
    async def refresh(self, interaction: discord.Interaction, button: discord.ui.Button): await self.run_action(interaction, "stats")
    @discord.ui.button(label="Delete", emoji="🗑️", style=discord.ButtonStyle.secondary, row=1)
    async def delete_vps(self, interaction: discord.Interaction, button: discord.ui.Button): await self.run_action(interaction, "delete")


class DeployView(discord.ui.View):
    def __init__(self, user_id: int):
        super().__init__(timeout=180)
        self.user_id = int(user_id)
        self.selected_os = "ubuntu-24.04"
        self.selected_location = DEFAULT_LOCATION
        self.os_select = discord.ui.Select(placeholder="1️⃣ Select operating system", options=[discord.SelectOption(label=c["label"], value=k, emoji="🟠" if k.startswith("ubuntu") else "🔵") for k, c in OS_CONFIG.items()], row=0)
        self.location_select = discord.ui.Select(
            placeholder="2️⃣ Select location",
            options=[
                discord.SelectOption(
                    label=cfg["label"],
                    value=code,
                    emoji=("🇸🇬" if code == "SG" else "🇮🇳"),
                )
                for code, cfg in LOCATION_CONFIG.items()
            ],
            row=1,
        )
        self.deploy_button = discord.ui.Button(label="Deploy VPS", emoji="🚀", style=discord.ButtonStyle.secondary, row=2)
        self.os_select.callback = self.select_os
        self.location_select.callback = self.select_location
        self.deploy_button.callback = self.deploy
        self.add_item(self.os_select); self.add_item(self.location_select); self.add_item(self.deploy_button)

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id in {self.user_id, ADMIN_ID}:
            return True
        await safe_respond(interaction, embed=make_embed("❌ Access Denied", "This deployment menu belongs to another user."))
        return False

    async def select_os(self, interaction: discord.Interaction) -> None:
        self.selected_os = normalize_os(self.os_select.values[0]) or self.selected_os
        await safe_component_edit(
            interaction,
            embed=make_embed("🚀 Configure RGNODES™ VPS", f"OS: **{os_label(self.selected_os)}**\nLocation: **{location_label(self.selected_location)}**\n\nSelect both options, then press **Deploy VPS**."),
            view=self,
        )

    async def select_location(self, interaction: discord.Interaction) -> None:
        self.selected_location = normalize_location(self.location_select.values[0]) or DEFAULT_LOCATION
        await safe_component_edit(
            interaction,
            embed=make_embed("🚀 Configure RGNODES™ VPS", f"OS: **{os_label(self.selected_os)}**\nLocation: **{location_label(self.selected_location)}**\n\nSelect both options, then press **Deploy VPS**."),
            view=self,
        )

    async def deploy(self, interaction: discord.Interaction) -> None:
        # Claim and defer exactly once before any early response.
        if not await safe_defer(interaction, ephemeral=True):
            return
        # Re-check slots at click time so two open deploy menus cannot oversubscribe.
        is_admin = ADMIN_BYPASS_LIMITS and ADMIN_ID > 0 and interaction.user.id == ADMIN_ID
        used = db_vps_count(interaction.user.id)
        limit = db_effective_slots(interaction.user.id)
        if not is_admin and used >= limit:
            await safe_edit_original(
                interaction,
                embed=make_embed(
                    "🎟️ Slots Full",
                    f"You are using **{used}/{limit}** VPS slots.\n\n**SLOTS FULL** — additional slots will be available soon. Ask an administrator to add slots.",
                ),
                view=self,
            )
            return
        self.deploy_button.disabled = True
        try:
            await deploy_flow(interaction, user=interaction.user, os_type=self.selected_os, location=self.selected_location, ram=DEFAULT_RAM, cpu=DEFAULT_CPU, disk=DEFAULT_DISK)
        finally:
            self.stop()


async def _dashboard_live_data(vps: sqlite3.Row) -> tuple[dict[str, str], str, dict[str, str], dict[str, str], list[sqlite3.Row]]:
    """Collect dashboard data independently so one broken probe cannot blank the UI."""
    backend = str(vps["backend"] or "docker").lower()
    network = NETWORK_CACHE
    ports: list[sqlite3.Row] = []
    if backend in {"docker", "qemu"}:
        await asyncio.gather(
            supervise_vps_ports(vps),
            detect_public_network(),
            return_exceptions=True,
        )
        try:
            ports = db_list_ports(vps["id"])
        except Exception as exc:
            logger.warning("VPS #%s port listing failed: %s", vps["id"], safe_log(exc))
            ports = []

    stats, uptime, disk = await _safe_vps_live_data(vps)
    return stats, uptime, disk, network, ports


async def _safe_vps_live_data(vps: sqlite3.Row) -> tuple[dict[str, str], str, dict[str, str]]:
    """Collect live metrics independently; failed probes become N/A."""
    try:
        stats, uptime, disk = await asyncio.gather(
            backend_stats(vps), backend_uptime(vps), backend_disk(vps),
            return_exceptions=True,
        )
    except Exception as exc:
        logger.warning("VPS #%s live-data gather failed: %s", vps["id"], safe_log(exc))
        stats, uptime, disk = RuntimeError("stats unavailable"), "N/A", RuntimeError("disk unavailable")
    if isinstance(stats, BaseException) or not isinstance(stats, dict):
        stats = {"cpu": "N/A", "memory": "N/A", "network": "N/A"}
    else:
        stats = {str(k): clean(v) for k, v in stats.items()}
    stats.setdefault("cpu", "N/A")
    stats.setdefault("memory", "N/A")
    stats.setdefault("network", "N/A")
    if isinstance(uptime, BaseException) or uptime is None:
        uptime = "N/A"
    if isinstance(disk, BaseException) or not isinstance(disk, dict):
        disk = {"used": "N/A", "total": clean(vps["disk"]), "percent": "N/A"}
    else:
        disk = {str(k): clean(v) for k, v in disk.items()}
    disk.setdefault("used", "N/A")
    disk.setdefault("total", clean(vps["disk"]))
    disk.setdefault("percent", "N/A")
    return stats, str(uptime), disk


async def show_dashboard(interaction: discord.Interaction, vps: sqlite3.Row) -> None:
    """Render exactly one dashboard response for slash/component interactions."""
    vps = await refresh_vps_record_state(vps)
    stats, uptime, disk, network, ports = await _dashboard_live_data(vps)
    embed = dashboard_embed(vps, stats, uptime, disk, network, ports)
    view = ManageView(vps["id"], vps["user_id"])
    # A deferred interaction already owns its original response. Editing it is
    # the only safe path; creating a follow-up here is what previously produced
    # duplicate dashboard messages after button presses.
    if interaction.response.is_done():
        await safe_edit_original(interaction, embed=embed, view=view)
    else:
        await safe_followup(interaction, embed=embed, view=view)


async def deploy_flow(interaction: discord.Interaction, *, user: discord.User | discord.Member, os_type: str, location: str, ram: str, cpu: str, disk: str, backend_override: str | None = None) -> None:
    async def progress(embed: discord.Embed) -> None:
        await safe_edit_original(interaction, embed=embed)

    try:
        ok, message, vps = await asyncio.wait_for(
            create_vps(
                user,
                os_type=os_type,
                location=location,
                ram=ram,
                cpu=cpu,
                disk=disk,
                progress=progress,
                backend_override=backend_override,
            ),
            timeout=DEPLOY_TIMEOUT,
        )
    except asyncio.TimeoutError:
        logger.error("Deployment timed out for user %s after %ss", user.id, DEPLOY_TIMEOUT)
        await safe_edit_original(
            interaction,
            embed=make_embed(
                "❌ VPS Creation Timed Out",
                "QEMU took too long to complete the real VM deployment. Any partial VM was cleaned up when possible. Please retry.",
            ),
        )
        return
    except Exception:
        logger.exception("Unhandled deployment exception for user %s", user.id)
        await safe_edit_original(
            interaction,
            embed=make_embed("❌ VPS Creation Failed", "Deployment failed safely due to an unexpected backend error. Check the bot log for details."),
        )
        return
    if not ok or not vps:
        await safe_edit_original(interaction, embed=make_embed("❌ VPS Creation Failed", message))
        return
    network = await detect_public_network(force=True)
    ip_ok = valid_public_ipv4(network.get("ip"))
    if ip_ok:
        with contextlib.suppress(Exception):
            db_set_vps_ipv4(vps["container_id"], network["ip"])

    console_url = normalize_sshx_url(vps["sshx_url"]) if vps["sshx_url"] else None
    dm_sent = await send_vps_ready_dm(user, vps, network)

    final = make_embed("✅ VPS Ready", f"Your **{os_label(vps['os_type'])}** VPS is online.")
    final.add_field(name="🖥️ VPS", value=f"`{clean(vps['container_name'])}` • ID `{vps['id']}`", inline=False)
    final.add_field(name="🌍 Location", value=location_label(vps["location"]), inline=True)
    if console_url:
        console_state = "✅ SSHx link sent by DM" if dm_sent else "⚠️ SSHx ready, but DM is closed"
    else:
        console_state = "⚠️ SSHx temporarily unavailable — use Console/sshx to retry"
    final.add_field(name="🌐 Console", value=console_state, inline=True)
    await safe_edit_original(interaction, embed=final, view=ManageView(vps["id"], vps["user_id"]))


def actor_vps(interaction: discord.Interaction, identifier: str | None) -> sqlite3.Row | None:
    if interaction.user.id == ADMIN_ID:
        return db_find_vps(interaction.user.id, identifier, admin=True)
    return db_find_accessible_vps(interaction.user.id, identifier)


# ================================================================
# Slash commands (same public UI)
# ================================================================


def os_choices():
    return [app_commands.Choice(name=c["label"], value=k) for k, c in OS_CONFIG.items()]


def location_choices():
    return [app_commands.Choice(name=c["label"], value=k) for k, c in LOCATION_CONFIG.items()]


@bot.tree.command(name="deploy", description="Deploy a new RGNODES VPS.")
@app_commands.describe(os_type="Operating system", location="VPS location", ram="RAM, e.g. 2g", cpu="CPU cores, e.g. 1", disk="Disk allocation, e.g. 10g")
@app_commands.choices(os_type=os_choices(), location=location_choices())
async def deploy_slash(interaction: discord.Interaction, os_type: str, location: str = DEFAULT_LOCATION, ram: str = DEFAULT_RAM, cpu: str = DEFAULT_CPU, disk: str = DEFAULT_DISK) -> None:
    if await safe_defer(interaction, ephemeral=True):
        await deploy_flow(interaction, user=interaction.user, os_type=os_type, location=location, ram=ram, cpu=cpu, disk=disk)


@bot.tree.command(name="myvm", description="Open your newest RGNODES™ VPS dashboard.")
async def myvm_slash(interaction: discord.Interaction) -> None:
    """Open the caller's newest VPS, matching /manage with no identifier."""
    if not await safe_defer(interaction, ephemeral=True):
        return
    vps = db_find_vps(interaction.user.id, None, admin=True) if interaction.user.id == ADMIN_ID and ADMIN_ID > 0 else db_find_accessible_vps(interaction.user.id, None)
    if not vps:
        await safe_followup(
            interaction,
            embed=make_embed("❌ No VPS Found", f"You do not have any VPS instances yet. Use `{PREFIX}deploy` first."),
        )
        return
    await show_dashboard(interaction, vps)


@bot.tree.command(name="manage", description="Open your VPS management dashboard.")
@app_commands.describe(vps_identifier="VPS ID/name; blank uses your newest VPS")
async def manage_slash(interaction: discord.Interaction, vps_identifier: str | None = None):
    if not await safe_defer(interaction, ephemeral=True): return
    vps = actor_vps(interaction, vps_identifier)
    if not vps: await safe_followup(interaction, embed=make_embed("❌ VPS Not Found", "No matching VPS was found.")); return
    await show_dashboard(interaction, vps)


async def slash_lifecycle(interaction: discord.Interaction, identifier: str, action: str):
    if not await safe_defer(interaction, ephemeral=True): return
    vps = actor_vps(interaction, identifier)
    if not vps: await safe_followup(interaction, embed=make_embed("❌ VPS Not Found", "No matching VPS was found.")); return
    ok, message = await lifecycle_action(vps, action)
    if ok and action in {"start", "restart"}:
        await send_private_ipv4(interaction.user, db_get_vps(vps["id"]) or vps)
    await safe_followup(interaction, embed=make_embed("✅ Action Complete" if ok else "❌ Action Failed", message))


@bot.tree.command(name="start", description="Start a VPS.")
async def start_slash(interaction: discord.Interaction, vps_identifier: str): await slash_lifecycle(interaction, vps_identifier, "start")
@bot.tree.command(name="stop", description="Stop a VPS.")
async def stop_slash(interaction: discord.Interaction, vps_identifier: str): await slash_lifecycle(interaction, vps_identifier, "stop")
@bot.tree.command(name="restart", description="Restart a VPS.")
async def restart_slash(interaction: discord.Interaction, vps_identifier: str): await slash_lifecycle(interaction, vps_identifier, "restart")


@bot.tree.command(name="console", description="Generate a private SSHx console link and send it by DM.")
async def console_slash(interaction: discord.Interaction, vps_identifier: str):
    if not await safe_defer(interaction, ephemeral=True): return
    vps = actor_vps(interaction, vps_identifier)
    if not vps: await safe_followup(interaction, embed=make_embed("❌ VPS Not Found", "No matching VPS was found.")); return
    ok, message = await create_console_access(vps, interaction.user)
    await safe_followup(interaction, embed=make_embed("✅ Console Ready" if ok else "❌ Console Failed", message))


@bot.tree.command(name="vps-info", description="Show full live VPS information.")
async def vps_info_slash(interaction: discord.Interaction, vps_identifier: str | None = None):
    if not await safe_defer(interaction, ephemeral=True): return
    vps = actor_vps(interaction, vps_identifier)
    if not vps: await safe_followup(interaction, embed=make_embed("❌ VPS Not Found", "No matching VPS was found.")); return
    await show_dashboard(interaction, vps)


@bot.tree.command(name="remove", description="Delete a RGNODES VPS.")
async def remove_slash(interaction: discord.Interaction, vps_identifier: str): await slash_lifecycle(interaction, vps_identifier, "delete")


@bot.tree.command(name="list", description="List your VPS instances.")
async def list_slash(interaction: discord.Interaction):
    if not await safe_defer(interaction, ephemeral=True): return
    rows = db_get_all_vps() if interaction.user.id == ADMIN_ID and ADMIN_ID > 0 else db_get_user_vps(interaction.user.id)
    embed = make_embed("📋 Your RGNODES™ VPS")
    if not rows: embed.description = "You do not have any VPS instances."
    for row in rows[:25]:
        embed.add_field(name=f"{status_text(row['status'], bool(row['suspended']))} {clean(row['container_name'])}", value=f"ID: `{row['id']}` • {os_label(row['os_type'])}\n{clean(row['ram'])} RAM • {clean(row['cpu'])} CPU • {clean(row['disk'])} Disk • {location_label(row['location'])}", inline=False)
    await safe_followup(interaction, embed=embed)


@bot.tree.command(name="ping", description="Check RGNODES™ bot latency.")
async def ping_slash(interaction: discord.Interaction):
    await safe_respond(interaction, embed=make_embed("🏓 Pong!", f"Discord latency: `{round(bot.latency * 1000)}ms`"))



@bot.tree.command(name="myvps", description="Open your newest RGNODES™ VPS dashboard.")
async def myvps_slash_alias(interaction: discord.Interaction):
    await myvm_slash(interaction)


@bot.tree.command(name="vps-stats", description="Show live VPS statistics.")
async def vps_stats_slash(interaction: discord.Interaction, vps_identifier: str):
    if not await safe_defer(interaction, ephemeral=True):
        return
    vps = actor_vps(interaction, vps_identifier)
    if not vps:
        await safe_followup(interaction, embed=make_embed("❌ VPS Not Found", "No matching VPS was found."))
        return
    vps = await refresh_vps_record_state(vps)
    stats, uptime, disk = await _safe_vps_live_data(vps)
    await safe_followup(interaction, embed=make_embed(
        f"📈 VPS Stats • {clean(vps['container_name'])}",
        f"CPU: `{clean(stats.get('cpu'))}`\nMemory: `{clean(stats.get('memory'))}`\n"
        f"Disk: `{clean(disk.get('used'))} / {clean(vps['disk'])}`\n"
        f"Network: `{clean(stats.get('network'))}`\nUptime: `{clean(uptime)}`"
    ))


@bot.tree.command(name="vps-uptime", description="Show VPS uptime.")
async def vps_uptime_slash(interaction: discord.Interaction, vps_identifier: str):
    if not await safe_defer(interaction, ephemeral=True):
        return
    vps = actor_vps(interaction, vps_identifier)
    if not vps:
        await safe_followup(interaction, embed=make_embed("❌ VPS Not Found", "No matching VPS was found."))
        return
    await safe_followup(interaction, embed=make_embed("⏱️ VPS Uptime", f"`{clean(await backend_uptime(vps))}`"))


@bot.tree.command(name="restart-vps", description="Restart a VPS safely.")
async def restart_vps_slash(interaction: discord.Interaction, vps_identifier: str):
    await slash_lifecycle(interaction, vps_identifier, "restart")


@bot.tree.command(name="snapshot", description="Create a real VPS snapshot.")
async def snapshot_slash(interaction: discord.Interaction, vps_identifier: str, name: str | None = None):
    if not await safe_defer(interaction, ephemeral=True):
        return
    vps = actor_vps(interaction, vps_identifier)
    if not vps:
        await safe_followup(interaction, embed=make_embed("❌ VPS Not Found", "No matching VPS was found."))
        return
    snap_name = (name or "").strip() or f"snapshot-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    ok, message = await docker_snapshot_create(vps, snap_name)
    await safe_followup(interaction, embed=make_embed("📸 Snapshot Created" if ok else "❌ Snapshot Failed", message))


@bot.tree.command(name="list-snapshots", description="List snapshots for a VPS.")
async def list_snapshots_slash(interaction: discord.Interaction, vps_identifier: str):
    if not await safe_defer(interaction, ephemeral=True):
        return
    vps = actor_vps(interaction, vps_identifier)
    if not vps:
        await safe_followup(interaction, embed=make_embed("❌ VPS Not Found", "No matching VPS was found."))
        return
    if str(vps["backend"] or "qemu").lower() not in {"docker", "qemu"}:
        await safe_followup(interaction, embed=make_embed("🦖 Pterodactyl Backups", "This VPS uses Pterodactyl. Use the Panel's backup system instead of local Docker snapshots."))
        return
    rows = db_list_snapshots(vps["id"])
    body = "\n".join(f"`{clean(r['name'])}` • {str(r['created_at'])[:19]} UTC" for r in rows[:20]) or "No snapshots."
    await safe_followup(interaction, embed=make_embed(f"📋 Snapshots • {clean(vps['container_name'])}", body))


@bot.tree.command(name="restore-snapshot", description="Restore a VPS snapshot.")
async def restore_snapshot_slash(interaction: discord.Interaction, vps_identifier: str, name: str):
    if not await safe_defer(interaction, ephemeral=True):
        return
    vps = actor_vps(interaction, vps_identifier)
    if not vps:
        await safe_followup(interaction, embed=make_embed("❌ VPS Not Found", "No matching VPS was found."))
        return
    if not db_is_owner_or_admin(interaction.user.id, vps):
        await safe_followup(interaction, embed=make_embed("❌ Permission Denied", "Only the VPS owner or administrator can restore snapshots."))
        return
    ok, message = await docker_snapshot_restore(vps, name)
    await safe_followup(interaction, embed=make_embed("✅ Snapshot Restored" if ok else "❌ Restore Failed", message))


@bot.tree.command(name="manage-shared", description="Manage a user's shared VPS access.")
async def manage_shared_slash(interaction: discord.Interaction, owner_user: discord.User, vps_identifier: str):
    if not await safe_defer(interaction, ephemeral=True):
        return
    vps = db_find_vps(owner_user.id, vps_identifier)
    if not vps or not db_is_owner_or_admin(interaction.user.id, vps):
        await safe_followup(interaction, embed=make_embed("❌ Permission Denied", "Only the VPS owner or administrator can manage shared access."))
        return
    shared = db_list_shared(vps["id"])
    body = "\n".join(f"<@{r['user_id']}> • granted by <@{r['shared_by']}>" for r in shared) or "No users currently have shared access."
    await safe_followup(interaction, embed=make_embed(f"👥 Shared Access • {clean(vps['container_name'])}", body), view=ManageView(vps["id"], vps["user_id"]))


@bot.tree.command(name="share-ruser", description="Revoke a user's shared VPS access.")
async def share_ruser_slash(interaction: discord.Interaction, vps_identifier: str, target_user: discord.User):
    if not await safe_defer(interaction, ephemeral=True):
        return
    vps = actor_vps(interaction, vps_identifier)
    if not vps or not db_is_owner_or_admin(interaction.user.id, vps):
        await safe_followup(interaction, embed=make_embed("❌ Permission Denied", "Only the VPS owner or administrator can revoke shared access."))
        return
    ok, message = db_unshare_vps(vps["id"], target_user.id)
    await safe_followup(interaction, embed=make_embed("✅ Access Removed" if ok else "⚠️ Nothing Changed", f"{message}\nVPS: `{clean(vps['container_name'])}` • User: <@{target_user.id}>"))


@bot.tree.command(name="serverstats", description="Show host and VPS server statistics.")
async def serverstats_slash(interaction: discord.Interaction):
    await safe_defer(interaction, ephemeral=True)
    info = host_os_info()
    try:
        load = os.getloadavg()[0]
        load_text = f"{load:.2f}"
    except (AttributeError, OSError):
        load_text = "N/A"
    try:
        meminfo = Path("/proc/meminfo").read_text(encoding="utf-8", errors="replace")
        total_m = re.search(r"^MemTotal:\s+(\d+)", meminfo, re.M)
        avail_m = re.search(r"^MemAvailable:\s+(\d+)", meminfo, re.M)
        ram_text = f"{format_bytes((int(total_m.group(1))-int(avail_m.group(1)))*1024)} / {format_bytes(int(total_m.group(1))*1024)}" if total_m and avail_m else "N/A"
    except Exception:
        ram_text = "N/A"
    du = shutil.disk_usage("/")
    ok, active = await docker_running_count()
    if not ok:
        active = db_running_count()
    await safe_followup(interaction, embed=make_embed("📊 RGNODES™ • Server Statistics",
        f"OS: `{clean(info['name'], 100)}`\nPID 1: `{clean(info['pid1'])}`\n"
        f"Host uptime: `{await host_uptime()}`\nRAM: `{ram_text}`\n"
        f"Disk: `{format_bytes(du.used)} / {format_bytes(du.total)}`\n"
        f"CPU cores: `{os.cpu_count() or 1}` • Load: `{load_text}`\nActive VPS: `{active}`"))


@bot.tree.command(name="thresholds", description="Show RGNODES™ resource thresholds.")
async def thresholds_slash(interaction: discord.Interaction):
    await safe_respond(interaction, embed=make_embed("📋 RGNODES™ • Thresholds",
        f"Per-user slots: `{db_effective_slots(interaction.user.id)}`\nGlobal running VPS: `{TOTAL_RUNNING_LIMIT}`\n"
        f"Max ports/VPS: `{MAX_PORTS_PER_VPS}`\nPort range: `{PORT_RANGE_START}-{PORT_RANGE_END}`\n"
        "RAM per VPS: `256MB-256GB`\nDisk per VPS: `1GB-10TB`\nCPU per VPS: `>0-64 cores`"))


@bot.tree.command(name="set-status", description="Admin: set the bot presence.")
@app_commands.choices(status_type=[
    app_commands.Choice(name="Playing", value="playing"),
    app_commands.Choice(name="Watching", value="watching"),
    app_commands.Choice(name="Listening", value="listening"),
    app_commands.Choice(name="Competing", value="competing"),
])
async def set_status_slash(interaction: discord.Interaction, status_type: str, name: str):
    if not admin_ok(interaction):
        await safe_respond(interaction, embed=make_embed("❌ Permission Denied", "Administrator access is required."))
        return
    if status_type == "watching":
        activity = discord.Activity(type=discord.ActivityType.watching, name=name)
    elif status_type == "listening":
        activity = discord.Activity(type=discord.ActivityType.listening, name=name)
    elif status_type == "competing":
        activity = discord.Activity(type=discord.ActivityType.competing, name=name)
    else:
        activity = discord.Game(name=name)
    await bot.change_presence(activity=activity)
    await safe_respond(interaction, embed=make_embed("✅ Status Updated", f"Type: `{status_type}`\nName: `{clean(name, 200)}`"))


@bot.tree.command(name="about", description="Show RGNODES™ information.")
async def about_slash(interaction: discord.Interaction):
    embed = make_embed("☁️ RGNODES™ VPS Management", "Fast real QEMU VPS management with private SSHx access.")
    embed.add_field(name="🛠️ Stack", value="Python 3 • discord.py • Docker • SQLite WAL", inline=False)
    embed.add_field(name="🔐 Security", value="Console links are generated on demand and sent by DM only.", inline=False)
    await safe_respond(interaction, embed=embed)


@bot.tree.command(name="logs", description="View recent logs for your VPS.")
async def logs_slash(interaction: discord.Interaction, vps_identifier: str, lines: int = 50):
    if not await safe_defer(interaction, ephemeral=True): return
    vps = actor_vps(interaction, vps_identifier)
    if not vps: await safe_followup(interaction, embed=make_embed("❌ VPS Not Found", "No matching VPS was found.")); return
    logs = await docker_logs(vps["container_id"], lines)
    embed = make_embed(f"📜 Logs • {clean(vps['container_name'])}")
    # Prevent user/container output from closing the Discord code block.
    logs = str(logs).replace("```", "'''")
    embed.add_field(name="Recent output", value=f"```text\n{logs[:3900]}\n```", inline=False)
    await safe_followup(interaction, embed=embed)


@bot.tree.command(name="ports", description="Show your VPS port forwarding rules.")
async def ports_slash(interaction: discord.Interaction, vps_identifier: str):
    if not await safe_defer(interaction, ephemeral=True):
        return
    vps = actor_vps(interaction, vps_identifier)
    if not vps:
        await safe_followup(interaction, embed=make_embed("❌ VPS Not Found", "No matching VPS was found."))
        return
    await supervise_vps_ports(vps)
    ports = db_list_ports(vps["id"])
    network = await detect_public_network(force=True)
    if valid_public_ipv4(network.get("ip")):
        db_set_vps_ipv4(vps["container_id"], network["ip"])
        await safe_dm(interaction.user, ipv4_dm_embed(vps, network))
    embed = make_embed(f"🌐 Ports • {clean(vps['container_name'])}", f"IPv4: 🔒 Sent by DM\nUsed: `{len(ports)}/{MAX_PORTS_PER_VPS}`")
    if not ports:
        embed.description += "\n\nNo forwarding rules configured. Use `/port-add`."
    for p_row in ports:
        embed.add_field(name=f"#{p_row['id']} • {str(p_row['protocol']).upper()}", value=f"Public port `{p_row['host_port']}` → VPS port `:{p_row['container_port']}` • **{clean(p_row['status']).upper()}**", inline=False)
    await safe_followup(interaction, embed=embed)


@bot.tree.command(name="port-add", description="Add a TCP port forward (maximum 10 per VPS).")
@app_commands.describe(vps_identifier="VPS ID/name", container_port="Port inside the VPS", host_port="Public host port; leave 0 for automatic allocation")
async def port_add_slash(interaction: discord.Interaction, vps_identifier: str, container_port: int, host_port: int = 0):
    if not await safe_defer(interaction, ephemeral=True):
        return
    if not 1 <= container_port <= 65535:
        await safe_followup(interaction, embed=make_embed("❌ Invalid Port", "Container port must be between 1 and 65535."))
        return
    vps = actor_vps(interaction, vps_identifier)
    if not vps:
        await safe_followup(interaction, embed=make_embed("❌ VPS Not Found", "No matching VPS was found."))
        return
    async with PORT_LOCK:
        ports = db_list_ports(vps["id"])
        if len(ports) >= MAX_PORTS_PER_VPS:
            await safe_followup(interaction, embed=make_embed("⚠️ Port Limit Reached", f"A VPS can use at most `{MAX_PORTS_PER_VPS}` forwarding rules."))
            return
        if db_find_port(vps["id"], container_port, "tcp"):
            await safe_followup(interaction, embed=make_embed("⚠️ Already Exists", "That container port is already forwarded."))
            return
        if host_port == 0:
            host_port = await allocate_host_port() or 0
        if not 1024 <= host_port <= 65535 or not port_bindable(host_port):
            await safe_followup(interaction, embed=make_embed("❌ Host Port Unavailable", "Choose a free host port from 1024–65535, or use `0` for automatic allocation."))
            return
        try:
            port_id = db_insert_port(vps["id"], container_port, host_port, "tcp")
        except sqlite3.IntegrityError:
            await safe_followup(interaction, embed=make_embed("❌ Port Conflict", "That public port is already reserved by another VPS."))
            return
    row = db_get_port(port_id)
    ok, message = await start_port_forward(row, vps) if row else (False, "Forwarding record disappeared unexpectedly.")
    if not ok:
        if row:
            await stop_port_forward(row)
        db_delete_port(port_id)
    else:
        await send_private_ipv4(interaction.user, db_get_vps(vps["id"]) or vps)
    await safe_followup(interaction, embed=make_embed("✅ Port Forward Added" if ok else "❌ Port Forward Failed", message))


@bot.tree.command(name="port-remove", description="Remove a TCP port forward.")
async def port_remove_slash(interaction: discord.Interaction, vps_identifier: str, port_id: int):
    if not await safe_defer(interaction, ephemeral=True):
        return
    vps = actor_vps(interaction, vps_identifier)
    row = db_get_port(port_id)
    if not vps or not row or int(row["vps_id"]) != int(vps["id"]):
        await safe_followup(interaction, embed=make_embed("❌ Port Not Found", "That forwarding rule does not belong to the selected VPS."))
        return
    await stop_port_forward(row)
    db_delete_port(port_id)
    await safe_followup(interaction, embed=make_embed("🗑️ Port Forward Removed", f"Forwarding rule `#{port_id}` has been removed."))


@bot.tree.command(name="help", description="Open the RGNODES command navigator.")
async def help_slash(interaction: discord.Interaction):
    admin = interaction.user.id == ADMIN_ID
    await safe_respond(interaction, embed=build_help_embed(admin, "home"), ephemeral=True, view=HelpView(interaction.user.id, admin))


# ================================================================
# Admin commands — compatibility surface kept
# ================================================================


def admin_ok(source: discord.Interaction | commands.Context) -> bool:
    """Check the configured admin for slash interactions and prefix contexts."""
    user = getattr(source, "user", None)
    if user is None:
        user = getattr(source, "author", None)
    return bool(user and ADMIN_ID > 0 and int(user.id) == int(ADMIN_ID))


@bot.tree.command(name="admin-create", description="Admin: create a VPS for another user.")
@app_commands.choices(os_type=os_choices(), location=location_choices())
async def admin_create(interaction: discord.Interaction, target_user: discord.User, os_type: str, location: str = DEFAULT_LOCATION, ram: str = DEFAULT_RAM, cpu: str = DEFAULT_CPU, disk: str = DEFAULT_DISK):
    if not admin_ok(interaction): await safe_respond(interaction, embed=make_embed("❌ Permission Denied", "Administrator access is required.")); return
    if await safe_defer(interaction, ephemeral=True): await deploy_flow(interaction, user=target_user, os_type=os_type, location=location, ram=ram, cpu=cpu, disk=disk)


@bot.tree.command(name="add-slots", description="Admin: add VPS slots to a user.")
@app_commands.describe(target_user="Discord user", slots="How many additional VPS slots to add")
async def add_slots_slash(interaction: discord.Interaction, target_user: discord.User, slots: int):
    if not admin_ok(interaction):
        await safe_respond(interaction, embed=make_embed("❌ Permission Denied", "Administrator access is required."))
        return
    if slots <= 0 or slots > 1000:
        await safe_respond(interaction, embed=make_embed("❌ Invalid Slot Amount", "Choose a positive slot amount up to 1000."))
        return
    db_upsert_user(target_user.id, str(target_user))
    total = db_add_slots(target_user.id, slots)
    await safe_respond(interaction, embed=make_embed("🎟️ Slots Added", f"<@{target_user.id}> now has **{total} VPS slots**.\n\nAdditional slots added: `{slots}`"))


@bot.tree.command(name="remove-all", description="Admin: delete every RGNODES VPS and reset VPS IDs.")
@app_commands.describe(confirm="Must be true to perform this destructive action")
async def remove_all_slash(interaction: discord.Interaction, confirm: bool = False):
    if not admin_ok(interaction):
        await safe_respond(interaction, embed=make_embed("❌ Permission Denied", "Administrator access is required."))
        return
    if not confirm:
        await safe_respond(interaction, embed=make_embed("⚠️ Confirm Remove All", "This permanently removes all managed VPS containers, forwarding rules and VPS records. It also resets the VPS ID sequence. Run `/remove-all confirm:true` to continue."))
        return
    if not await safe_defer(interaction, ephemeral=True):
        return
    rows = db_get_all_vps()
    removed = 0
    failed = 0
    for vps in rows:
        try:
            ok, _ = await lifecycle_action(vps, "delete")
            removed += 1 if ok else 0
            failed += 0 if ok else 1
        except Exception as exc:
            failed += 1
            logger.exception("remove-all failed for VPS #%s: %s", vps["id"], exc)
    # Clean orphaned managed Docker containers and reset relational records/sequence.
    rc, out, _ = await docker_cli("ps", "-aq", "--format", "{{.ID}}\t{{.Names}}", timeout=60, retries=1)
    orphans = []
    if rc == 0:
        for line in out.decode("utf-8", "replace").splitlines():
            parts = line.strip().split("\t", 1)
            if len(parts) == 2 and re.fullmatch(r"rgnodes-\d+", parts[1].strip(), flags=re.I):
                orphans.append(parts[0])
    for cid in orphans:
        with contextlib.suppress(Exception):
            await docker_remove(cid)
    # Explicit destructive cleanup also removes orphaned QEMU metadata/VM disks
    # that are no longer referenced by the database. Normal startup never does
    # this automatically, so unexpected files are not silently deleted.
    referenced_qemu = {str(row["container_id"]) for row in rows if str(row["backend"] or "").lower() == "qemu"}
    with contextlib.suppress(OSError):
        QEMU_VM_ROOT.mkdir(parents=True, exist_ok=True)
        for child in QEMU_VM_ROOT.iterdir():
            if not child.is_dir() or child.name == "_images" or child.name in referenced_qemu:
                continue
            if child.name.startswith("qemu-"):
                with contextlib.suppress(Exception):
                    await qemu_remove_vm(child.name)
    db_delete_all_vps()
    await safe_followup(interaction, embed=make_embed("✅ Remove All Complete", f"Managed VPS removed: `{removed}`\nFailures: `{failed}`\nVPS ID sequence reset to `1`.\nAll forwarding records were cleared."))


@bot.tree.command(name="admin-list", description="Admin: list all VPS instances.")
async def admin_list(interaction: discord.Interaction):
    if not admin_ok(interaction): await safe_respond(interaction, embed=make_embed("❌ Permission Denied", "Administrator access is required.")); return
    if not await safe_defer(interaction, ephemeral=True): return
    rows = db_get_all_vps(); embed = make_embed("🗂️ Admin • All VPS")
    if not rows: embed.description = "No VPS instances found."
    for row in rows[:25]: embed.add_field(name=f"#{row['id']} • {clean(row['container_name'])}", value=f"Owner: <@{row['user_id']}>\n{status_text(row['status'], bool(row['suspended']))} • {location_label(row['location'])}", inline=False)
    await safe_followup(interaction, embed=embed)


@bot.tree.command(name="admin-delete-user", description="Admin: delete one VPS belonging to a user.")
async def admin_delete_user(interaction: discord.Interaction, target_user: discord.User, vps_identifier: str):
    if not admin_ok(interaction): await safe_respond(interaction, embed=make_embed("❌ Permission Denied", "Administrator access is required.")); return
    if not await safe_defer(interaction, ephemeral=True): return
    vps = db_find_vps(target_user.id, vps_identifier)
    if not vps: await safe_followup(interaction, embed=make_embed("❌ VPS Not Found", "No matching VPS was found.")); return
    ok, message = await lifecycle_action(vps, "delete")
    await safe_followup(interaction, embed=make_embed("✅ VPS Deleted" if ok else "❌ Delete Failed", message))


@bot.tree.command(name="admin-ban", description="Admin: block a user from creating VPS instances.")
async def admin_ban(interaction: discord.Interaction, target_user: discord.User):
    if not admin_ok(interaction): await safe_respond(interaction, embed=make_embed("❌ Permission Denied", "Administrator access is required.")); return
    db_set_ban(target_user.id, True); await safe_respond(interaction, embed=make_embed("✅ User Restricted", f"<@{target_user.id}> can no longer create VPS instances."))


@bot.tree.command(name="admin-unban", description="Admin: allow a user to create VPS instances again.")
async def admin_unban(interaction: discord.Interaction, target_user: discord.User):
    if not admin_ok(interaction): await safe_respond(interaction, embed=make_embed("❌ Permission Denied", "Administrator access is required.")); return
    db_set_ban(target_user.id, False); await safe_respond(interaction, embed=make_embed("✅ User Restored", f"<@{target_user.id}> may create VPS instances again."))


@bot.tree.command(name="sshx", description="Generate a fresh private SSHx browser console link.")
async def sshx_slash(interaction: discord.Interaction, vps_identifier: str): await console_slash(interaction, vps_identifier)


@bot.tree.command(name="share-user", description="Share your VPS with another Discord user.")
async def share_user_slash(interaction: discord.Interaction, vps_identifier: str, target_user: discord.User):
    if not await safe_defer(interaction, ephemeral=True):
        return
    vps = actor_vps(interaction, vps_identifier)
    if not vps or not db_is_owner_or_admin(interaction.user.id, vps):
        await safe_followup(interaction, embed=make_embed("❌ Permission Denied", "Only the VPS owner or administrator can share this VPS."))
        return
    ok, message = db_share_vps(vps["id"], target_user.id, interaction.user.id)
    await safe_followup(interaction, embed=make_embed("✅ VPS Shared" if ok else "⚠️ Share Failed", f"{message}\nVPS: `{vps['container_name']}` • User: <@{target_user.id}>"))


@bot.tree.command(name="unshare-user", description="Remove a user's access to your VPS.")
async def unshare_user_slash(interaction: discord.Interaction, vps_identifier: str, target_user: discord.User):
    if not await safe_defer(interaction, ephemeral=True):
        return
    vps = actor_vps(interaction, vps_identifier)
    if not vps or not db_is_owner_or_admin(interaction.user.id, vps):
        await safe_followup(interaction, embed=make_embed("❌ Permission Denied", "Only the VPS owner or administrator can remove shared access."))
        return
    ok, message = db_unshare_vps(vps["id"], target_user.id)
    await safe_followup(interaction, embed=make_embed("✅ Access Removed" if ok else "⚠️ Nothing Changed", f"{message}\nVPS: `{vps['container_name']}` • User: <@{target_user.id}>"))




@bot.tree.command(name="admin-manage", description="Admin: control a user's VPS.")
@app_commands.choices(action=[app_commands.Choice(name=x.title(), value=x) for x in ("start", "stop", "restart", "delete", "suspend", "unsuspend")])
async def admin_manage(interaction: discord.Interaction, target_user: discord.User, vps_identifier: str, action: str):
    if not admin_ok(interaction): await safe_respond(interaction, embed=make_embed("❌ Permission Denied", "Administrator access is required.")); return
    if not await safe_defer(interaction, ephemeral=True): return
    vps = db_find_vps(target_user.id, vps_identifier)
    if not vps: await safe_followup(interaction, embed=make_embed("❌ VPS Not Found", "No matching VPS was found.")); return
    if action in {"start", "stop", "restart", "delete"}:
        ok, message = await lifecycle_action(vps, action)
    elif action == "suspend":
        ok, message = await lifecycle_action(vps, "stop")
        if ok: db_update_vps(vps["container_id"], suspended=1); message = "VPS stopped and suspended."
    else:
        db_update_vps(vps["container_id"], suspended=0); ok, message = True, "VPS unsuspended."
    await safe_followup(interaction, embed=make_embed("✅ Admin Action Complete" if ok else "❌ Admin Action Failed", message))


@bot.tree.command(name="admin-list-users", description="Admin: list users and VPS counts.")
async def admin_list_users(interaction: discord.Interaction):
    if not admin_ok(interaction): await safe_respond(interaction, embed=make_embed("❌ Permission Denied", "Administrator access is required.")); return
    if not await safe_defer(interaction, ephemeral=True): return
    conn = db_connect()
    try:
        rows = conn.execute("SELECT u.user_id,u.username,COUNT(v.id) AS total_vps,SUM(CASE WHEN v.status='running' AND v.suspended=0 THEN 1 ELSE 0 END) AS running_vps FROM users u LEFT JOIN vps v ON u.user_id=v.user_id GROUP BY u.user_id,u.username ORDER BY total_vps DESC").fetchall()
    finally: conn.close()
    embed = make_embed("👥 Admin • Users")
    if not rows: embed.description = "No users have been recorded yet."
    for row in rows[:25]: embed.add_field(name=clean(row["username"]), value=f"Total: `{row['total_vps']}` • Running: `{row['running_vps'] or 0}`", inline=False)
    await safe_followup(interaction, embed=embed)


@bot.tree.command(name="admin-stats", description="Admin: show RGNODES statistics.")
async def admin_stats(interaction: discord.Interaction):
    if not admin_ok(interaction): await safe_respond(interaction, embed=make_embed("❌ Permission Denied", "Administrator access is required.")); return
    if not await safe_defer(interaction, ephemeral=True): return
    conn = db_connect()
    try:
        users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]; total = conn.execute("SELECT COUNT(*) FROM vps").fetchone()[0]; running = conn.execute("SELECT COUNT(*) FROM vps WHERE status='running' AND suspended=0").fetchone()[0]; banned = conn.execute("SELECT COUNT(*) FROM bans").fetchone()[0]
    finally: conn.close()
    embed = make_embed("📊 Admin • Statistics")
    docker_ok, docker_running = await docker_running_count()
    if not docker_ok:
        docker_running = db_running_count()
    ptero_running = sum(1 for row in db_get_all_vps() if str(row["backend"] or "docker").lower() == "pterodactyl" and str(row["status"]).lower() in {"running", "starting", "restarting"} and not row["suspended"])
    live_running = docker_running + ptero_running
    for n, v in (("Users", users), ("Banned", banned), ("Total VPS", total), ("DB Running", running), ("Live Active", live_running), ("Running limit", TOTAL_RUNNING_LIMIT)): embed.add_field(name=n, value=str(v), inline=True)
    await safe_followup(interaction, embed=embed)


@bot.tree.command(name="admin-vps-info", description="Admin: view a user's VPS dashboard.")
async def admin_vps_info(interaction: discord.Interaction, target_user: discord.User, vps_identifier: str):
    if not admin_ok(interaction): await safe_respond(interaction, embed=make_embed("❌ Permission Denied", "Administrator access is required.")); return
    if not await safe_defer(interaction, ephemeral=True): return
    vps = db_find_vps(target_user.id, vps_identifier)
    if not vps: await safe_followup(interaction, embed=make_embed("❌ VPS Not Found", "No matching VPS was found.")); return
    vps = await refresh_vps_record_state(vps)
    stats, uptime, disk = await _safe_vps_live_data(vps)
    ports = db_list_ports(vps["id"]) if str(vps["backend"] or "qemu").lower() in {"docker", "qemu"} else []
    await safe_followup(interaction, embed=dashboard_embed(vps, stats, uptime, disk, NETWORK_CACHE, ports))


@bot.tree.command(name="admin-logs", description="Admin: view a user's VPS logs.")
async def admin_logs(interaction: discord.Interaction, target_user: discord.User, vps_identifier: str, lines: int = 50):
    if not admin_ok(interaction): await safe_respond(interaction, embed=make_embed("❌ Permission Denied", "Administrator access is required.")); return
    if not await safe_defer(interaction, ephemeral=True): return
    vps = db_find_vps(target_user.id, vps_identifier)
    if not vps: await safe_followup(interaction, embed=make_embed("❌ VPS Not Found", "No matching VPS was found.")); return
    logs = (await docker_logs(vps["container_id"], lines)).replace("```", "'''")
    embed = make_embed(f"📜 Admin Logs • {clean(vps['container_name'])}"); embed.add_field(name="Recent output", value=f"```text\n{logs[:3900]}\n```", inline=False)
    await safe_followup(interaction, embed=embed)


@bot.tree.command(name="admin-kill-all", description="Admin: stop all running VPS instances.")
async def admin_kill_all(interaction: discord.Interaction):
    if not admin_ok(interaction): await safe_respond(interaction, embed=make_embed("❌ Permission Denied", "Administrator access is required.")); return
    if not await safe_defer(interaction, ephemeral=True): return
    results = await asyncio.gather(*(lifecycle_action(vps, "stop") for vps in db_get_all_vps() if vps["status"] == "running"), return_exceptions=True)
    stopped = sum(1 for x in results if isinstance(x, tuple) and x[0])
    await safe_followup(interaction, embed=make_embed("🛑 Admin • Kill All", f"Stopped `{stopped}` VPS instance(s)."))
















# ================================================================
# System bootstrap commands
# ================================================================

def confirm_value(value: str | bool | None) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"confirm", "true", "yes", "y", "1"}


@bot.tree.command(
    name="install-system",
    description="Admin: install/repair QEMU VPS host dependencies.",
)
@app_commands.describe(confirm="Set true to actually run the system bootstrap.")
async def install_system_slash(interaction: discord.Interaction, confirm: bool = False):
    if not admin_ok(interaction):
        await safe_respond(interaction, embed=make_embed(
            "❌ Permission Denied",
            "Administrator access is required.",
        ))
        return

    if not confirm:
        info = host_os_info()
        await safe_respond(interaction, embed=make_embed(
            "🛠️ RGNODES™ • Install System",
            (
                "This command can install/repair the QEMU TCG host dependencies needed "
                "for real VPS creation. KVM is not required.\n\n"
                f"**Detected OS:** `{clean(info['name'])}`\n"
                f"**PID 1:** `{clean(info['pid1'])}`\n"
                f"**Root:** `{clean(info['root'])}`\n\n"
                "**Nothing has been changed.**\n"
                "Run `/install-system confirm:true` to proceed."
            ),
        ))
        return

    if not await safe_defer(interaction, ephemeral=True):
        return
    try:
        if active_backend() == "qemu":
            ok, result = await asyncio.wait_for(qemu_host_prepare(), timeout=900)
        else:
            ok, result = await asyncio.wait_for(install_system_dependencies(), timeout=900)
        title = "✅ Install System Complete" if ok else "⚠️ Install System Finished With Issues"
        await safe_followup(interaction, embed=make_embed(title, f"```text\n{safe_log(result, 3800)}\n```"))
    except asyncio.TimeoutError:
        await safe_followup(interaction, embed=make_embed(
            "❌ Install System Timeout",
            "The host bootstrap exceeded the 15-minute safety timeout. Check the host package manager and Docker daemon manually.",
        ))
    except Exception as exc:
        logger.exception("install-system failed")
        await safe_followup(interaction, embed=make_embed(
            "❌ Install System Failed",
            f"```text\n{safe_log(exc, 3800)}\n```",
        ))


# ================================================================
# Prefix compatibility layer
# ================================================================

def ctx_vps(ctx: commands.Context, identifier: str | None = None) -> sqlite3.Row | None:
    """Single VPS resolver for every prefix command. Admins can see all VPSs;
    normal users can see owned or shared VPSs. Empty identifier means newest.
    """
    needle = (identifier or "").strip()
    if ctx.author.id == ADMIN_ID and ADMIN_ID > 0:
        return db_find_vps(ctx.author.id, needle, admin=True)
    return db_find_accessible_vps(ctx.author.id, needle)


@bot.check
async def _global_prefix_event_guard(ctx: commands.Context) -> bool:
    """Prevent the same Discord message from being processed twice.

    This protects against brief multi-process overlap and duplicate gateway
    delivery during a restart without sending a second response.
    """
    message = getattr(ctx, "message", None)
    event_id = getattr(message, "id", None)
    allowed = claim_processed_event(f"msg:{event_id}", "prefix")
    if not allowed:
        setattr(ctx, "_rgnodes_duplicate_event", True)
    return allowed


@bot.command(name="share-user")
async def prefix_share_user(ctx: commands.Context, target_user: discord.User, vps_identifier: str):
    vps = ctx_vps(ctx, vps_identifier)
    if not vps or not db_is_owner_or_admin(ctx.author.id, vps):
        await safe_ctx_send(ctx, make_embed("❌ Permission Denied", "Only the VPS owner or administrator can share this VPS."))
        return
    ok, message = db_share_vps(vps["id"], target_user.id, ctx.author.id)
    await safe_ctx_send(ctx, make_embed("✅ VPS Shared" if ok else "⚠️ Share Failed", f"{message}\nVPS: `{clean(vps['container_name'])}` • User: <@{target_user.id}>"))


@bot.command(name="share-ruser", aliases=["unshare-user"])
async def prefix_share_ruser(ctx: commands.Context, target_user: discord.User, vps_identifier: str):
    vps = ctx_vps(ctx, vps_identifier)
    if not vps or not db_is_owner_or_admin(ctx.author.id, vps):
        await safe_ctx_send(ctx, make_embed("❌ Permission Denied", "Only the VPS owner or administrator can revoke access."))
        return
    ok, message = db_unshare_vps(vps["id"], target_user.id)
    await safe_ctx_send(ctx, make_embed("✅ Access Removed" if ok else "⚠️ Nothing Changed", f"{message}\nVPS: `{clean(vps['container_name'])}` • User: <@{target_user.id}>"))




@bot.command(name="myvps", aliases=["myvm"])
async def prefix_myvps(ctx: commands.Context) -> None:
    await prefix_manage(ctx, "")


@bot.command(name="uptime")
async def prefix_uptime(ctx: commands.Context):
    await safe_ctx_send(ctx, make_embed("⏱️ RGNODES™ • Host Uptime", f"Host uptime: `{await host_uptime()}`"))


@bot.command(name="vpsinfo", aliases=["vps-info"])
async def prefix_vpsinfo(ctx: commands.Context, identifier: str = ""):
    vps = ctx_vps(ctx, identifier)
    if not vps:
        await safe_ctx_send(ctx, make_embed("❌ VPS Not Found", "No VPS matches that identifier."))
        return
    await safe_ctx_send(ctx, make_embed(
        f"📊 VPS Info • {clean(vps['container_name'])}",
        f"ID: `{vps['id']}`\nStatus: **{status_text(vps['status'], bool(vps['suspended']))}**\n"
        f"OS: `{os_label(vps['os_type'])}`\nLocation: `{location_label(vps['location'])}`\n"
        f"RAM: `{vps['ram']}` • CPU: `{vps['cpu']}` • Disk: `{vps['disk']}`\n"
        f"Backend: `{str(vps['backend'] or 'docker').lower()}`"
    ))


@bot.command(name="vps-stats")
async def prefix_vps_stats(ctx: commands.Context, identifier: str = ""):
    vps = ctx_vps(ctx, identifier)
    if not vps:
        await safe_ctx_send(ctx, make_embed("❌ VPS Not Found", "No VPS matches that identifier."))
        return
    vps = await refresh_vps_record_state(vps)
    stats, uptime, disk = await _safe_vps_live_data(vps)
    await safe_ctx_send(ctx, make_embed(
        f"📈 VPS Stats • {clean(vps['container_name'])}",
        f"CPU: `{clean(stats.get('cpu'))}`\nMemory: `{clean(stats.get('memory'))}`\n"
        f"Disk: `{clean(disk.get('used'))} / {clean(vps['disk'])}`\nNetwork: `{clean(stats.get('network'))}`\nUptime: `{clean(uptime)}`"
    ))


@bot.command(name="vps-uptime")
async def prefix_vps_uptime(ctx: commands.Context, identifier: str = ""):
    vps = ctx_vps(ctx, identifier)
    if not vps:
        await safe_ctx_send(ctx, make_embed("❌ VPS Not Found", "No VPS matches that identifier."))
        return
    try:
        uptime = await asyncio.wait_for(backend_uptime(vps), timeout=25)
    except Exception as exc:
        logger.warning("Prefix VPS uptime failed for #%s: %s", vps["id"], safe_log(exc))
        uptime = "N/A"
    await safe_ctx_send(ctx, make_embed("⏱️ VPS Uptime", f"`{clean(uptime)}`"))




@bot.command(name="restart-vps")
async def prefix_restart_vps(ctx: commands.Context, identifier: str = ""):
    await prefix_action(ctx, identifier, "restart")


@bot.command(name="snapshot")
async def prefix_snapshot(ctx: commands.Context, identifier: str, name: str = ""):
    vps = ctx_vps(ctx, identifier)
    if not vps:
        await safe_ctx_send(ctx, make_embed("❌ VPS Not Found", "No VPS matches that identifier."))
        return
    name = name.strip() or f"snapshot-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    ok, message = await docker_snapshot_create(vps, name)
    await safe_ctx_send(ctx, make_embed("📸 Snapshot Created" if ok else "❌ Snapshot Failed", message))


@bot.command(name="list-snapshots")
async def prefix_list_snapshots(ctx: commands.Context, identifier: str = ""):
    vps = ctx_vps(ctx, identifier)
    if not vps:
        await safe_ctx_send(ctx, make_embed("❌ VPS Not Found", "No VPS matches that identifier."))
        return
    rows = db_list_snapshots(vps["id"])
    body = "\n".join(f"`{r['name']}` • {str(r['created_at'])[:19]}" for r in rows[:20]) or "No snapshots."
    await safe_ctx_send(ctx, make_embed(f"📋 Snapshots • {clean(vps['container_name'])}", body))


@bot.command(name="restore-snapshot")
async def prefix_restore_snapshot(ctx: commands.Context, identifier: str, name: str):
    vps = ctx_vps(ctx, identifier)
    if not vps:
        await safe_ctx_send(ctx, make_embed("❌ VPS Not Found", "No VPS matches that identifier."))
        return
    if not db_is_owner_or_admin(ctx.author.id, vps):
        await safe_ctx_send(ctx, make_embed("❌ Permission Denied", "Only the VPS owner or administrator can restore snapshots."))
        return
    ok, message = await docker_snapshot_restore(vps, name)
    await safe_ctx_send(ctx, make_embed("✅ Snapshot Restored" if ok else "❌ Restore Failed", message))


@bot.command(name="manage-shared")
async def prefix_manage_shared(ctx: commands.Context, target_user: discord.User, vps_identifier: str):
    vps = db_find_vps(target_user.id, vps_identifier)
    if not vps or not db_is_owner_or_admin(ctx.author.id, vps):
        await safe_ctx_send(ctx, make_embed("❌ Permission Denied", "Only the VPS owner or administrator can manage shared access."))
        return
    shared = db_list_shared(vps["id"])
    body = "\n".join(f"<@{r['user_id']}> • granted by <@{r['shared_by']}>" for r in shared) or "No users currently have shared access."
    await safe_ctx_send(ctx, make_embed(f"👥 Shared Access • {clean(vps['container_name'])}", body), ManageView(vps["id"], vps["user_id"]))


@bot.command(name="serverstats")
async def prefix_serverstats(ctx: commands.Context):
    info = host_os_info()
    try:
        load = os.getloadavg()[0]
        load_text = f"{load:.2f}"
    except (AttributeError, OSError):
        load_text = "N/A"
    try:
        meminfo = Path("/proc/meminfo").read_text(encoding="utf-8", errors="replace")
        total_kb = int(re.search(r"^MemTotal:\\s+(\\d+)", meminfo, re.M).group(1))
        avail_kb = int(re.search(r"^MemAvailable:\\s+(\\d+)", meminfo, re.M).group(1))
        ram_text = f"{format_bytes((total_kb-avail_kb)*1024)} / {format_bytes(total_kb*1024)}"
    except Exception:
        ram_text = "N/A"
    disk = shutil.disk_usage("/")
    ok, active = await docker_running_count()
    if not ok:
        active = db_running_count()
    await safe_ctx_send(ctx, make_embed("📊 RGNODES™ • Server Statistics",
        f"OS: `{clean(info['name'], 100)}`\nPID 1: `{clean(info['pid1'])}`\n"
        f"Host uptime: `{await host_uptime()}`\nRAM: `{ram_text}`\n"
        f"Disk: `{format_bytes(disk.used)} / {format_bytes(disk.total)}`\n"
        f"CPU cores: `{os.cpu_count() or 1}` • Load: `{load_text}`\nActive VPS: `{active}`"))


@bot.command(name="thresholds")
async def prefix_thresholds(ctx: commands.Context):
    await safe_ctx_send(ctx, make_embed("📋 RGNODES™ • Thresholds",
        f"Per-user slots: `{db_effective_slots(ctx.author.id)}`\n"
        f"Global running VPS: `{TOTAL_RUNNING_LIMIT}`\n"
        f"Max ports/VPS: `{MAX_PORTS_PER_VPS}`\n"
        f"Port range: `{PORT_RANGE_START}-{PORT_RANGE_END}`\n"
        f"RAM per VPS: `256MB-256GB`\nDisk per VPS: `1GB-10TB`\nCPU per VPS: `0-64 cores`"))


@bot.command(name="set-status")
async def prefix_set_status(ctx: commands.Context, status_type: str, *, name: str):
    if not admin_ok(ctx):
        await safe_ctx_send(ctx, make_embed("❌ Permission Denied", "Administrator access is required."))
        return
    kind = status_type.strip().lower()
    activity: discord.BaseActivity
    if kind == "watching":
        activity = discord.Activity(type=discord.ActivityType.watching, name=name)
    elif kind == "listening":
        activity = discord.Activity(type=discord.ActivityType.listening, name=name)
    elif kind == "competing":
        activity = discord.Activity(type=discord.ActivityType.competing, name=name)
    else:
        kind = "playing"
        activity = discord.Game(name=name)
    await bot.change_presence(activity=activity)
    await safe_ctx_send(ctx, make_embed("✅ Status Updated", f"Type: `{kind}`\nName: `{clean(name, 200)}`"))


@bot.group(name="ports", invoke_without_command=True)
async def prefix_ports(ctx: commands.Context, identifier: str = ""):
    if ctx.invoked_subcommand:
        return
    vps = ctx_vps(ctx, identifier)
    if not vps:
        await safe_ctx_send(ctx, make_embed("❌ VPS Not Found", f"Use `{PREFIX}ports list <vps#>` or open `{PREFIX}manage`."))
        return
    if str(vps["backend"] or "qemu").lower() not in {"docker", "qemu"}:
        panel = await ptero_panel_link(vps)
        await safe_ctx_send(ctx, make_embed("🦖 Pterodactyl Ports", f"Port allocations are managed by Pterodactyl.\nPanel: {panel or 'not configured'}"))
        return
    rows = db_list_ports(vps["id"])
    body = "\n".join(f"#{r['id']} • `{r['host_port']}→{r['container_port']}/TCP` • `{r['status']}`" for r in rows) or "No forwarding rules."
    await safe_ctx_send(ctx, make_embed(f"🌐 Ports • {clean(vps['container_name'])}", body))


@prefix_ports.command(name="add")
async def prefix_ports_add(ctx: commands.Context, identifier: str, container_port: int, host_port: int = 0):
    vps = ctx_vps(ctx, identifier)
    if not vps:
        await safe_ctx_send(ctx, make_embed("❌ VPS Not Found", "No VPS matches that identifier."))
        return
    if str(vps["backend"] or "qemu").lower() not in {"docker", "qemu"}:
        await safe_ctx_send(ctx, make_embed("🦖 Pterodactyl Allocations", "This VPS uses Pterodactyl. Manage ports/allocations from the panel."))
        return
    if not 1 <= container_port <= 65535:
        await safe_ctx_send(ctx, make_embed("❌ Invalid Port", "Container port must be between 1 and 65535."))
        return
    async with PORT_LOCK:
        if len(db_list_ports(vps["id"])) >= MAX_PORTS_PER_VPS:
            await safe_ctx_send(ctx, make_embed("⚠️ Port Limit Reached", f"Maximum `{MAX_PORTS_PER_VPS}` forwarding rules per VPS."))
            return
        if db_find_port(vps["id"], container_port, "tcp"):
            await safe_ctx_send(ctx, make_embed("⚠️ Already Exists", "That container port is already forwarded."))
            return
        if host_port == 0:
            host_port = await allocate_host_port() or 0
        if not 1024 <= host_port <= 65535 or not port_bindable(host_port):
            await safe_ctx_send(ctx, make_embed("❌ Host Port Unavailable", "Use a free port 1024–65535 or 0 for auto-allocation."))
            return
        try:
            port_id = db_insert_port(vps["id"], container_port, host_port, "tcp")
        except sqlite3.IntegrityError:
            await safe_ctx_send(ctx, make_embed("❌ Port Conflict", "That public port is already reserved."))
            return
    row = db_get_port(port_id)
    ok, message = await start_port_forward(row, vps) if row else (False, "Forwarding record disappeared.")
    if not ok:
        if row:
            await stop_port_forward(row)
        db_delete_port(port_id)
    await safe_ctx_send(ctx, make_embed("✅ Port Added" if ok else "❌ Port Failed", message))


@prefix_ports.command(name="list")
async def prefix_ports_list(ctx: commands.Context, identifier: str = ""):
    vps = ctx_vps(ctx, identifier)
    if not vps:
        await safe_ctx_send(ctx, make_embed("❌ VPS Not Found", "No VPS matches that identifier."))
        return
    if str(vps["backend"] or "qemu").lower() not in {"docker", "qemu"}:
        panel = await ptero_panel_link(vps)
        await safe_ctx_send(ctx, make_embed("🦖 Pterodactyl Ports", f"Port allocations are managed by Pterodactyl.\nPanel: {panel or 'not configured'}"))
        return
    rows = db_list_ports(vps["id"])
    body = "\n".join(f"#{r['id']} • `{r['host_port']}→{r['container_port']}/TCP` • `{r['status']}`" for r in rows) or "No forwarding rules."
    await safe_ctx_send(ctx, make_embed(f"🌐 Ports • {clean(vps['container_name'])}", body))


@prefix_ports.command(name="remove")
async def prefix_ports_remove(ctx: commands.Context, port_id: int):
    row = db_get_port(port_id)
    if not row:
        await safe_ctx_send(ctx, make_embed("❌ Port Not Found", "No such forwarding rule exists."))
        return
    vps = db_get_vps(int(row["vps_id"]))
    if not vps or not db_is_owner_or_admin(ctx.author.id, vps):
        await safe_ctx_send(ctx, make_embed("❌ Permission Denied", "You do not own that forwarding rule."))
        return
    await stop_port_forward(row)
    db_delete_port(port_id)
    await safe_ctx_send(ctx, make_embed("🗑️ Port Removed", f"Forwarding rule `#{port_id}` removed."))


@bot.command(name="deploy")
async def prefix_deploy(
    ctx: commands.Context,
    os_type: str | None = None,
    ram: str = DEFAULT_RAM,
    cpu: str = DEFAULT_CPU,
    disk: str = DEFAULT_DISK,
    location: str = DEFAULT_LOCATION,
):
    if not os_type:
        is_admin = ADMIN_BYPASS_LIMITS and ADMIN_ID > 0 and ctx.author.id == ADMIN_ID
        used = db_vps_count(ctx.author.id)
        limit = db_effective_slots(ctx.author.id)
        if not is_admin and used >= limit:
            await safe_ctx_send(ctx, make_embed(
                "🎟️ VPS Slots Full",
                f"You are using **{used}/{limit}** VPS slots.\n\n**SLOTS FULL** — more slots are coming soon. Ask an administrator to add slots.\n\nCurrent allocation: `{used}/{limit}`.",
            ))
            return
        await safe_ctx_send(
            ctx,
            make_embed(
                "🚀 Deploy RGNODES™ VPS",
                f"Current slots: **{slot_status_text(ctx.author.id)}**\n\nSelect the operating system first, then choose a location: Singapore 🇸🇬 or India 🇮🇳.",
            ),
            DeployView(ctx.author.id),
        )
        return

    normalized_location = normalize_location(location) or DEFAULT_LOCATION
    message = await ctx.send(
        embed=progress_embed(
            1,
            "Starting deployment",
            normalize_os(os_type) or os_type,
            normalized_location,
            ram,
            cpu,
            disk,
            "rgnodes-pending",
        )
    )

    async def edit(embed: discord.Embed):
        with contextlib.suppress(discord.HTTPException):
            await message.edit(embed=embed)

    try:
        ok, reason, vps = await asyncio.wait_for(
            create_vps(
                ctx.author,
                os_type=os_type,
                location=normalized_location,
                ram=ram,
                cpu=cpu,
                disk=disk,
                progress=edit,
            ),
            timeout=DEPLOY_TIMEOUT,
        )
    except asyncio.TimeoutError:
        ok, reason, vps = False, "Deployment timed out safely. Check the bot log before retrying.", None
    except Exception:
        logger.exception("Prefix deployment failed for user %s", ctx.author.id)
        ok, reason, vps = False, "Deployment failed safely. Check the bot log for details.", None
    if not ok or not vps:
        with contextlib.suppress(discord.HTTPException):
            await message.edit(embed=make_embed("❌ VPS Creation Failed", reason))
        return
    network = await detect_public_network(force=True)
    console_url = normalize_sshx_url(vps["sshx_url"]) if vps["sshx_url"] else None
    dm_sent = await send_vps_ready_dm(ctx.author, vps, network)
    final = make_embed("✅ VPS Ready", f"`{clean(vps['container_name'])}` is online.")
    final.add_field(name="🌐 Console", value="✅ Ready details sent by DM" if dm_sent else ("⚠️ SSHx pending — use Console to retry" if not console_url else "⚠️ DM unavailable"), inline=False)
    await message.edit(embed=final, view=ManageView(vps["id"], vps["user_id"]))


@bot.command(name="manage")
async def prefix_manage(ctx: commands.Context, identifier: str = ""):
    vps = ctx_vps(ctx, identifier)
    if not vps:
        await safe_ctx_send(ctx, make_embed("❌ VPS Not Found", f"No matching VPS was found. Create one with `{PREFIX}deploy`."))
        return
    try:
        vps = await refresh_vps_record_state(vps)
        stats, uptime, disk, network, ports = await _dashboard_live_data(vps)
        await safe_ctx_send(
            ctx,
            dashboard_embed(vps, stats, uptime, disk, network, ports),
            ManageView(vps["id"], vps["user_id"]),
        )
    except Exception as exc:
        logger.exception("Prefix manage failed for VPS %s: %s", identifier or "latest", exc)
        await safe_ctx_send(ctx, make_embed("❌ Dashboard Error", "The VPS record exists, but its live dashboard could not be loaded. Try the command again."))


@bot.command(name="console")
async def prefix_console(ctx: commands.Context, identifier: str = ""):
    vps = ctx_vps(ctx, identifier)
    if not vps:
        await safe_ctx_send(ctx, make_embed("❌ VPS Not Found", "No matching VPS was found."))
        return
    ok, message = await create_console_access(vps, ctx.author)
    latest = db_get_vps(vps["id"]) or vps
    view = sshx_view(latest["sshx_url"]) if latest["sshx_url"] else None
    await safe_ctx_send(ctx, make_embed("✅ Console Ready" if ok else "❌ Console Failed", message), view=view)


@bot.command(name="list")
async def prefix_list(ctx: commands.Context):
    rows = db_get_all_vps() if (ctx.author.id == ADMIN_ID and ADMIN_ID > 0) else db_get_user_vps(ctx.author.id); embed = make_embed("📋 Your RGNODES™ VPS")
    if not rows:
        embed.description = "You do not have any VPS instances."
    else:
        embed.add_field(name="🎟️ VPS Slots", value=slot_status_text(ctx.author.id), inline=False)
    for row in rows[:25]:
        embed.add_field(
            name=f"{status_text(row['status'], bool(row['suspended']))} {clean(row['container_name'])}",
            value=f"ID: `{row['id']}` • {os_label(row['os_type'])} • {location_label(row['location'])}",
            inline=False,
        )
    await safe_ctx_send(ctx, embed)


@bot.command(name="remove")
async def prefix_remove(ctx: commands.Context, identifier: str = ""): await prefix_action(ctx, identifier, "delete")


@bot.command(name="start")
async def prefix_start(ctx: commands.Context, identifier: str = ""): await prefix_action(ctx, identifier, "start")
@bot.command(name="stop")
async def prefix_stop(ctx: commands.Context, identifier: str = ""): await prefix_action(ctx, identifier, "stop")
@bot.command(name="restart")
async def prefix_restart(ctx: commands.Context, identifier: str = ""): await prefix_action(ctx, identifier, "restart")


async def prefix_action(ctx: commands.Context, identifier: str, action: str):
    vps = ctx_vps(ctx, identifier)
    if not vps:
        await safe_ctx_send(ctx, make_embed("❌ VPS Not Found", "No matching VPS was found."))
        return
    try:
        ok, message = await lifecycle_action(vps, action)
    except Exception:
        logger.exception("Prefix lifecycle action %s failed for VPS #%s", action, vps["id"])
        ok, message = False, "The VPS action failed safely. Check the bot log for details."
    await safe_ctx_send(ctx, make_embed("✅ Action Complete" if ok else "❌ Action Failed", message))


class HelpSelect(discord.ui.Select):
    def __init__(self, owner_id: int, admin: bool):
        options = [
            discord.SelectOption(label="User Commands", value="user", emoji="👤", description="Commands for all VPS users"),
            discord.SelectOption(label="VPS Management", value="vps", emoji="🖥️", description="Start, stop, stats and VPS access"),
            discord.SelectOption(label="Port Forwarding", value="ports", emoji="🔌", description="Network and port management"),
            discord.SelectOption(label="System Status", value="system", emoji="⚙️", description="Host monitoring and limits"),
            discord.SelectOption(label="Bot Info", value="bot", emoji="🤖", description="Bot information and status"),
        ]
        if admin:
            options.append(discord.SelectOption(label="Admin Commands", value="admin", emoji="🛡️", description="Administrator commands"))
        super().__init__(
            placeholder="Select Category",
            min_values=1,
            max_values=1,
            options=options,
        )
        self.owner_id = owner_id
        self.admin = admin

    async def callback(self, interaction: discord.Interaction) -> None:
        if interaction.user.id != self.owner_id:
            await safe_respond(interaction, embed=make_embed("❌ Access Denied", "This help menu belongs to another user."))
            return
        try:
            await safe_component_edit(interaction, embed=build_help_embed(self.admin, self.values[0]), view=self.view)
        except discord.NotFound:
            return
        except discord.HTTPException as exc:
            logger.warning("Help menu interaction failed: %s", safe_log(exc))
            with contextlib.suppress(Exception):
                await safe_respond(interaction, embed=make_embed("❌ Help Error", f"The menu expired. Run `{PREFIX}help` again."))
        except Exception as exc:
            logger.exception("Help menu callback failed: %s", exc)
            with contextlib.suppress(Exception):
                await safe_respond(interaction, embed=make_embed("❌ Help Error", "The help menu could not be updated."))


class HelpView(discord.ui.View):
    def __init__(self, owner_id: int, admin: bool):
        super().__init__(timeout=600)
        self.add_item(HelpSelect(owner_id, admin))

    async def on_timeout(self) -> None:
        for item in self.children:
            item.disabled = True


def build_help_embed(admin: bool, category: str = "user") -> discord.Embed:
    embed = make_embed("📚 RGNODES™ Help", "Use the dropdown below to switch categories.")
    category = category if category in {"user", "vps", "ports", "system", "bot", "admin"} else "user"

    if category == "user":
        embed.title = "📚 RGNODES™ • 👤 User Commands"
        embed.add_field(name="Basic commands for all users", value="Use the dropdown below to switch categories.", inline=False)
        embed.add_field(name="Available Commands", value=(
            f"**`{PREFIX}ping`** ╰ Check bot latency\n"
            f"**`{PREFIX}uptime`** ╰ Show host uptime\n"
            f"**`{PREFIX}myvps`** ╰ View your VPS dashboard\n"
            f"**`{PREFIX}manage [vps#]`** ╰ Manage your VPS instances\n"
            f"**`{PREFIX}share-user @user <vps#>`** ╰ Share VPS access\n"
            f"**`{PREFIX}share-ruser @user <vps#>`** ╰ Revoke shared access\n"
            f"**`{PREFIX}manage-shared @owner <vps#>`** ╰ Manage shared VPS"
        ), inline=False)
        return embed

    if category == "vps":
        embed.title = "📚 RGNODES™ • 🖥️ VPS Management"
        embed.add_field(name="Commands for VPS control", value="Use the dropdown below to switch categories.", inline=False)
        embed.add_field(name="Available Commands", value=(
            f"**`{PREFIX}myvps`** ╰ List your VPS\n"
            f"**`{PREFIX}vpsinfo <vps#>`** ╰ VPS information\n"
            f"**`{PREFIX}vps-stats <vps#>`** ╰ Live statistics\n"
            f"**`{PREFIX}vps-uptime <vps#>`** ╰ VPS uptime\n"
            f"**`{PREFIX}restart-vps <vps#>`** ╰ Restart VPS\n"
            f"**`{PREFIX}snapshot <vps#> [name]`** ╰ Create snapshot\n"
            f"**`{PREFIX}list-snapshots <vps#>`** ╰ List snapshots\n"
            f"**`{PREFIX}restore-snapshot <vps#> <name>`** ╰ Restore snapshot"
        ), inline=False)
        embed.add_field(name="Also available", value=f"`{PREFIX}start` • `{PREFIX}stop` • `{PREFIX}restart` • `{PREFIX}console` • `{PREFIX}logs` • `{PREFIX}remove`", inline=False)
        return embed

    if category == "ports":
        embed.title = "📚 RGNODES™ • 🔌 Port Forwarding"
        embed.add_field(name="Network and port management", value="Use the dropdown below to switch categories.", inline=False)
        embed.add_field(name="Available Commands", value=(
            f"**`{PREFIX}ports add <vps#> <port>`** ╰ Add port forward\n"
            f"**`{PREFIX}ports list <vps#>`** ╰ List your ports\n"
            f"**`{PREFIX}ports remove <id>`** ╰ Remove port forward\n"
            f"**`/ports <vps#>`** ╰ View forwarding rules\n"
            f"**`/port-add <vps#> <port>`** ╰ Add forwarding rule\n"
            f"**`/port-remove <vps#> <id>`** ╰ Remove forwarding rule"
        ), inline=False)
        return embed

    if category == "system":
        embed.title = "📚 RGNODES™ • ⚙️ System Status"
        embed.add_field(name="System monitoring commands", value="Use the dropdown below to switch categories.", inline=False)
        embed.add_field(name="Available Commands", value=(
            f"**`{PREFIX}serverstats`** ╰ Server statistics\n"
            f"**`{PREFIX}thresholds`** ╰ View thresholds\n"
            f"**`{PREFIX}set-status <type> <name>`** ╰ Set bot status (admin)"
        ), inline=False)
        return embed

    if category == "bot":
        embed.title = "📚 RGNODES™ • 🤖 Bot Info"
        embed.add_field(name="Bot information and status", value="Use the dropdown below to switch categories.", inline=False)
        embed.add_field(name="Available Commands", value=(
            f"**`{PREFIX}ping`** ╰ Check latency\n"
            f"**`{PREFIX}uptime`** ╰ Host uptime\n"
            f"**`{PREFIX}help`** ╰ This help menu\n"
            f"**`/about`** ╰ RGNODES™ information"
        ), inline=False)
        return embed

    embed.title = "📚 RGNODES™ • 🛡️ Admin Commands"
    embed.add_field(name="Administration", value=(
        "`/admin-create` • `/admin-manage` • `/admin-list` • `/admin-list-users` • `/admin-stats`\n"
        "`/admin-vps-info` • `/admin-logs` • `/admin-delete-user` • `/admin-ban` • `/admin-unban`\n"
        "`/add-slots` • `/remove-all confirm:true` • `/admin-kill-all` • `/install-system confirm:true`"
    ), inline=False)
    return embed


@bot.command(name="ping")
async def prefix_ping(ctx: commands.Context):
    latency = round(bot.latency * 1000) if bot.is_ready() else 0
    await safe_ctx_send(ctx, make_embed("🏓 Pong!", f"Discord latency: `{latency}ms`"))


@bot.command(name="about")
async def prefix_about(ctx: commands.Context):
    embed = make_embed("☁️ RGNODES™ VPS Management", "Production Discord VPS management with real QEMU TCG/Pterodactyl backends.")
    embed.add_field(name="🛠️ Stack", value="Python • discord.py • QEMU TCG • SQLite WAL", inline=False)
    embed.add_field(name="⚙️ Prefix", value=f"`{PREFIX}`", inline=True)
    embed.add_field(name="🖥️ Backend", value=f"`{active_backend()}`", inline=True)
    await safe_ctx_send(ctx, embed)


@bot.command(name="logs")
async def prefix_logs(ctx: commands.Context, identifier: str, lines: int = 50):
    vps = ctx_vps(ctx, identifier)
    if not vps:
        await safe_ctx_send(ctx, make_embed("❌ VPS Not Found", "No VPS matches that identifier."))
        return
    if str(vps["backend"] or "qemu").lower() not in {"docker", "qemu"}:
        await safe_ctx_send(ctx, make_embed("🦖 Pterodactyl Logs", "Use the Pterodactyl Panel for server logs or the QEMU serial log for local VPS diagnostics."))
        return
    logs = (await docker_logs(vps["container_id"], lines)).replace("```", "'''")
    await safe_ctx_send(ctx, make_embed(
        f"📜 Logs • {clean(vps['container_name'])}",
        f"```text\n{logs[:3900]}\n```",
    ))


@bot.command(name="help")
async def prefix_help(ctx: commands.Context):
    admin = ctx.author.id == ADMIN_ID
    await safe_ctx_send(ctx, build_help_embed(admin, "user"), HelpView(ctx.author.id, admin))


async def safe_ctx_send(ctx: commands.Context, embed: discord.Embed, view: discord.ui.View | None = None) -> None:
    """Best-effort prefix response that never creates a second command exception."""
    try:
        kwargs: dict[str, Any] = {"embed": embed}
        if view is not None:
            kwargs["view"] = view
        await ctx.send(**kwargs)
    except discord.HTTPException as exc:
        logger.warning("Prefix response HTTP failure: %s", safe_log(exc))
    except Exception as exc:
        logger.exception("Prefix response failed: %s", exc)


# ================================================================
# Background sync / startup recovery
# ================================================================

STATUS_SEMAPHORE = asyncio.Semaphore(STATUS_CONCURRENCY)


async def recover_qemu_vms() -> None:
    """Recover database-marked running QEMU VMs after a bot/host restart.

    Intentional stopped/deleted VMs are never started because recovery only
    considers records whose durable database status was running before restart.
    """
    if active_backend() != "qemu":
        return
    rows = db_get_all_vps()
    by_vm = {str(row["container_id"]): row for row in rows if str(row["backend"] or "").lower() == "qemu"}
    if not QEMU_VM_ROOT.exists():
        return
    recovered = 0
    for child in QEMU_VM_ROOT.iterdir():
        if not child.is_dir():
            continue
        vm_id = child.name
        meta = qemu_load_meta(vm_id)
        row = by_vm.get(vm_id)
        if not meta or not row:
            continue
        if str(row["status"] or "stopped").lower() not in {"running", "starting", "restarting"}:
            continue
        try:
            if qemu_process_alive(meta.get("pid")):
                continue
            ok, detail = await qemu_launch(vm_id, qemu_running_forwards(int(row["id"])))
            if ok:
                ready, ready_detail = await _wait_qemu_ready(vm_id)
                if ready:
                    db_update_vps(vm_id, status="running")
                    recovered += 1
                    logger.info("Recovered QEMU VPS #%s (%s) after restart.", row["id"], vm_id)
                else:
                    db_update_vps(vm_id, status="stopped", sshx_url=None, sshx_pid=None)
                    logger.warning("QEMU VPS #%s restarted but failed readiness: %s", row["id"], safe_log(ready_detail))
            else:
                db_update_vps(vm_id, status="stopped", sshx_url=None, sshx_pid=None)
                logger.warning("QEMU VPS #%s could not be recovered: %s", row["id"], safe_log(detail))
        except Exception as exc:
            logger.warning("QEMU recovery failed for VPS #%s: %s", row["id"], safe_log(exc))
    if recovered:
        logger.info("Recovered %d QEMU VPS instance(s) after startup.", recovered)


async def sync_one(row: sqlite3.Row) -> None:
    async with STATUS_SEMAPHORE:
        try:
            backend = str(row["backend"] or "docker").lower()
            if backend == "pterodactyl":
                state = await ptero_status(row)
                if state in {"running", "starting", "restarting", "stopped"}:
                    db_update_vps(row["container_id"], status=state, sshx_url=await ptero_panel_link(row), sshx_pid=None)
                return

            state = await docker_state(row["container_id"])
            if state == "running":
                if row["status"] != "running":
                    db_update_vps(row["container_id"], status="running")
                await supervise_vps_ports(row)
            elif state in {"exited", "created", "dead", "paused", "restarting", "removing"}:
                if row["status"] != "stopped" or row["sshx_url"] or row["sshx_pid"]:
                    db_update_vps(row["container_id"], status="stopped", sshx_url=None, sshx_pid=None)
                for p_row in db_list_ports(row["id"]):
                    await stop_port_forward(p_row)
            elif state is None:
                logger.debug("Backend state unavailable for VPS #%s; retaining current database status.", row["id"])
        except Exception as exc:
            logger.warning("Status sync failed for #%s: %s", row["id"], safe_log(exc))


@tasks.loop(seconds=STATUS_INTERVAL)
async def sync_statuses() -> None:
    rows = db_get_all_vps()
    if rows:
        await asyncio.gather(*(sync_one(row) for row in rows), return_exceptions=True)


@sync_statuses.before_loop
async def before_sync_statuses(): await bot.wait_until_ready()


@tasks.loop(seconds=60)
async def update_presence():
    try:
        if not bot.is_ready():
            return
        docker_ok, docker_active = await docker_running_count()
        if not docker_ok:
            docker_active = db_running_count()
        ptero_active = sum(1 for row in db_get_all_vps() if str(row["backend"] or "docker").lower() == "pterodactyl" and str(row["status"]).lower() in {"running", "starting", "restarting"} and not row["suspended"])
        active = docker_active + ptero_active
        await bot.change_presence(activity=discord.Game(name=f"{BOT_STATUS_NAME} • {active} Active ⚡"))
    except (discord.HTTPException, discord.GatewayNotFound, discord.ClientException, asyncio.CancelledError):
        if isinstance(sys.exc_info()[1], asyncio.CancelledError):
            raise
    except Exception as exc:
        logger.debug("Presence update skipped: %s", safe_log(exc))


@update_presence.before_loop
async def before_update_presence(): await bot.wait_until_ready()


@tasks.loop(seconds=PORT_SUPERVISOR_INTERVAL)
async def supervise_all_ports_loop():
    try:
        await asyncio.gather(*(supervise_vps_ports(vps) for vps in db_get_all_vps()), return_exceptions=True)
    except Exception as exc:
        logger.warning("Port supervisor loop error: %s", safe_log(exc))


@supervise_all_ports_loop.before_loop
async def before_supervise_all_ports_loop(): await bot.wait_until_ready()


@tasks.loop(seconds=REAL_LOCATION_REFRESH)
async def refresh_network_identity():
    try:
        await detect_public_network(force=True)
    except Exception as exc:
        logger.debug("Network identity refresh skipped: %s", safe_log(exc))


@refresh_network_identity.before_loop
async def before_refresh_network_identity(): await bot.wait_until_ready()


@bot.event
async def on_ready():
    logger.info("RGNODES™ online as %s", bot.user)
    if not bot.loops_started:
        if not sync_statuses.is_running():
            sync_statuses.start()
        if not update_presence.is_running():
            update_presence.start()
        if not supervise_all_ports_loop.is_running():
            supervise_all_ports_loop.start()
        if not refresh_network_identity.is_running():
            refresh_network_identity.start()
        bot.loops_started = True
        with contextlib.suppress(Exception):
            await asyncio.wait_for(recover_qemu_vms(), timeout=min(900, max(120, QEMU_HOST_PREP_TIMEOUT)))
        await detect_public_network()

    if not bot.synced:
        for attempt in range(3):
            try:
                synced = await bot.tree.sync()
                bot.synced = True
                logger.info("Synced %d slash commands", len(synced))
                break
            except discord.HTTPException as exc:
                logger.warning("Slash command sync attempt %d failed: %s", attempt + 1, safe_log(exc))
                if attempt < 2:
                    await asyncio.sleep(3 * (attempt + 1))


@bot.event
async def on_command_error(ctx: commands.Context, error: commands.CommandError):
    if getattr(ctx, "_rgnodes_duplicate_event", False):
        return
    # CommandInvokeError is the wrapper discord.py uses for exceptions raised
    # inside a command. Always log the original exception so the real cause is
    # visible instead of producing an unhelpful generic Discord message.
    original = getattr(error, "original", error)
    if isinstance(error, commands.CommandNotFound):
        return
    if isinstance(error, commands.CommandOnCooldown):
        await safe_ctx_send(ctx, make_embed("⏳ Please Wait", f"Try again in `{error.retry_after:.1f}s`."))
        return
    if isinstance(error, commands.MissingRequiredArgument):
        await safe_ctx_send(ctx, make_embed("❌ Missing Argument", f"Use `{PREFIX}help` to view the correct command syntax."))
        return
    if isinstance(error, (commands.BadArgument, commands.UserNotFound, commands.MemberNotFound, commands.ChannelNotFound, commands.RoleNotFound)):
        await safe_ctx_send(ctx, make_embed("❌ Invalid Argument", f"Use `{PREFIX}help` to view the correct command syntax."))
        return
    command_name = getattr(ctx.command, "qualified_name", "unknown")
    if isinstance(original, BaseException):
        logger.error(
            "Prefix command '%s' failed: %s",
            command_name,
            safe_log(original),
            exc_info=(type(original), original, original.__traceback__),
        )
    else:
        logger.error("Prefix command '%s' failed: %s", command_name, safe_log(original))
    await safe_ctx_send(ctx, make_embed("❌ Command Error", "That command hit an internal error. The failure was logged for repair."))


@bot.tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    logger.error("Slash command error: %s", safe_log(error))
    await safe_respond(
        interaction,
        embed=make_embed("❌ Command Error", "The command could not be completed safely."),
    )


async def main() -> None:
    acquire_singleton()
    # Start the health listener before Discord so hosting platforms can still
    # observe the service while Discord connectivity is temporarily unavailable.
    await start_health_server()

    if not TOKEN:
        await stop_health_server()
        raise SystemExit(
            "Discord bot token is missing. Set TOKEN=YOUR_BOT_TOKEN in .env "
            "(or DISCORD_TOKEN/BOT_TOKEN) and restart the bot."
        )

    if ADMIN_ID <= 0:
        logger.warning("ADMIN_ID is not configured; admin commands will be unavailable.")

    logger.info(
        "RGNODES starting | build=%s | token_source=%s | prefix=%r | backend=%s | quota=%s fallback=%s location=%s | locations=SG,IN",
        RGNODES_BUILD, TOKEN_SOURCE, PREFIX, active_backend(), ENABLE_HARD_DISK_QUOTA, QUOTA_FALLBACK, DEFAULT_LOCATION,
    )

    attempt = 0
    try:
        while True:
            attempt += 1
            try:
                # discord.py's reconnect=True handles normal gateway disconnects.
                # This outer retry additionally covers failures before the
                # gateway session exists, such as aiohttp TCP/TLS resets while
                # requesting GET /users/@me.
                await bot.start(TOKEN, reconnect=True)
                logger.warning("Discord client stopped cleanly; restarting login loop.")
                attempt = 0

            except discord.LoginFailure:
                # Invalid/revoked credentials will not be fixed by retrying.
                logger.error("Discord rejected the bot token (HTTP 401 / invalid credentials).")
                logger.error(
                    "Check that %s contains the current token for the correct Discord bot.",
                    TOKEN_SOURCE,
                )
                logger.error("The value should be the raw bot token, without a leading 'Bot '.")
                raise SystemExit(1) from None

            except (aiohttp.ClientConnectorError, aiohttp.ClientConnectionError,
                    aiohttp.ClientOSError, aiohttp.ServerDisconnectedError,
                    asyncio.TimeoutError, ConnectionError, ConnectionResetError,
                    BrokenPipeError, OSError) as exc:
                # These are transport-level failures. They are often caused by
                # transient host egress/DNS/TLS problems and are safe to retry.
                delay = min(
                    DISCORD_LOGIN_RETRY_MAX,
                    DISCORD_LOGIN_RETRY_BASE * (2 ** min(max(attempt - 1, 0), 6)),
                )
                logger.warning(
                    "Discord network connection failed during startup/session: %s | retry=%ss | attempt=%s",
                    safe_log(exc), delay, attempt,
                )
                if DISCORD_LOGIN_MAX_ATTEMPTS and attempt >= DISCORD_LOGIN_MAX_ATTEMPTS:
                    logger.error("Discord retry limit reached (%s attempts).", DISCORD_LOGIN_MAX_ATTEMPTS)
                    raise SystemExit(1) from None
                with contextlib.suppress(Exception):
                    await bot.close()
                await asyncio.sleep(delay)

            except discord.HTTPException as exc:
                status = getattr(exc, "status", None)
                # Retry transient HTTP failures, but do not loop forever on
                # authentication/permission failures.
                if status in {401, 403}:
                    logger.error(
                        "Discord HTTP authentication/permission failure: status=%s code=%s message=%s",
                        status, getattr(exc, "code", "unknown"), safe_log(str(exc)),
                    )
                    raise SystemExit(1) from None
                delay = min(
                    DISCORD_LOGIN_RETRY_MAX,
                    DISCORD_LOGIN_RETRY_BASE * (2 ** min(max(attempt - 1, 0), 6)),
                )
                logger.warning(
                    "Discord HTTP startup/session failure: status=%s code=%s message=%s | retry=%ss",
                    status, getattr(exc, "code", "unknown"), safe_log(str(exc)), delay,
                )
                if DISCORD_LOGIN_MAX_ATTEMPTS and attempt >= DISCORD_LOGIN_MAX_ATTEMPTS:
                    logger.error("Discord retry limit reached (%s attempts).", DISCORD_LOGIN_MAX_ATTEMPTS)
                    raise SystemExit(1) from None
                with contextlib.suppress(Exception):
                    await bot.close()
                await asyncio.sleep(delay)

            except discord.GatewayNotFound as exc:
                delay = min(
                    DISCORD_LOGIN_RETRY_MAX,
                    DISCORD_LOGIN_RETRY_BASE * (2 ** min(max(attempt - 1, 0), 6)),
                )
                logger.warning("Discord gateway unavailable: %s | retry=%ss", safe_log(exc), delay)
                if DISCORD_LOGIN_MAX_ATTEMPTS and attempt >= DISCORD_LOGIN_MAX_ATTEMPTS:
                    logger.error("Discord retry limit reached (%s attempts).", DISCORD_LOGIN_MAX_ATTEMPTS)
                    raise SystemExit(1) from None
                with contextlib.suppress(Exception):
                    await bot.close()
                await asyncio.sleep(delay)

            except discord.ClientException as exc:
                # Client lifecycle/configuration errors are generally not fixed
                # by retrying, except when they are explicitly transport-like.
                text = str(exc).lower()
                if any(token in text for token in (
                    "connection", "connect", "reset", "timeout", "gateway", "disconnected"
                )):
                    delay = min(
                        DISCORD_LOGIN_RETRY_MAX,
                        DISCORD_LOGIN_RETRY_BASE * (2 ** min(max(attempt - 1, 0), 6)),
                    )
                    logger.warning("Discord client connectivity error: %s | retry=%ss", safe_log(exc), delay)
                    if DISCORD_LOGIN_MAX_ATTEMPTS and attempt >= DISCORD_LOGIN_MAX_ATTEMPTS:
                        raise SystemExit(1) from None
                    with contextlib.suppress(Exception):
                        await bot.close()
                    await asyncio.sleep(delay)
                    continue
                logger.error("Discord client startup failed: %s", safe_log(exc))
                raise SystemExit(1) from None

            except asyncio.CancelledError:
                raise

            except Exception as exc:
                # Last-resort protection: unexpected startup exceptions are
                # logged and retried unless explicitly limited by env config.
                delay = min(
                    DISCORD_LOGIN_RETRY_MAX,
                    DISCORD_LOGIN_RETRY_BASE * (2 ** min(max(attempt - 1, 0), 6)),
                )
                logger.exception(
                    "Unexpected Discord startup/session exception: %s | retry=%ss",
                    safe_log(exc), delay,
                )
                if DISCORD_LOGIN_MAX_ATTEMPTS and attempt >= DISCORD_LOGIN_MAX_ATTEMPTS:
                    raise
                with contextlib.suppress(Exception):
                    await bot.close()
                await asyncio.sleep(delay)

    finally:
        for loop in (sync_statuses, update_presence, supervise_all_ports_loop, refresh_network_identity):
            if loop.is_running():
                loop.cancel()
        with contextlib.suppress(Exception):
            await bot.close()
        with contextlib.suppress(Exception):
            await stop_health_server()
        release_singleton()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("RGNODES stopped by user.")
