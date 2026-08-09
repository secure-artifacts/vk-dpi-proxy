#!/usr/bin/env python3
"""
Local DPI bypass proxy using TLS Record Fragmentation.
Targets SNI-blocked sites (vk.com / vk.ru etc.) without a VPN.
stdlib only — Windows / macOS / Linux.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import os
import random
import re
import select
import socket
import sys
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tkinter import messagebox, scrolledtext
from typing import Callable, Optional
from urllib.parse import urlsplit

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 8888
PAC_PORT = 8889


def _app_dir() -> Path:
    if getattr(sys, "frozen", False):
        # PyInstaller onefile extracts data to _MEIPASS; exe sits beside user files
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            return Path(meipass)
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


APP_DIR = _app_dir()
PAC_FILE = APP_DIR / "proxy.pac"
PAC_URL = f"http://{LISTEN_HOST}:{PAC_PORT}/proxy.pac"
# "split" = 2 records (fast, recommended for images / chat)
# "multi" = ~40B chunks (stronger DPI bypass, heavier)
# "fine"  = 1-byte records (very slow; last resort)
FRAGMENT_MODE = "split"
FINE_SIZE = 2
SPLIT_FIRST = 1
MULTI_SIZE = 40

SO_TIMEOUT = 60
CONNECT_TIMEOUT = 2.5  # try next IP quickly
PIPE_IDLE = 600        # longpoll / websocket may sit idle for minutes
PIPE_BUF = 65536
HELLO_MAX = 64 * 1024

# Destination IPs / prefixes that blackhole TCP from this network.
BLOCKED_IP_PREFIXES = (
    "95.142.204.",  # subset of sun1-* / st1-* storage edges
    "195.3.244.",   # some sun10-* edges
)
# Filled at runtime when connect times out — covers one-off bad edges
# like 195.3.244.42 without over-blocking whole ranges.
_runtime_blocked_ips: set[str] = set()
# CDN object hosts (avatars/static). Do NOT blanket-force-rewrite these:
# many sun1-*/st1-* resolve to working 87.240.* — rewriting those blanks avatars.
_CDN_STORAGE_HOST = re.compile(
    r"^(sun\d+-\d+|st\d+-\d+)\.(userapi\.com|vk\.ru|vk\.com)$",
    re.I,
)
# Long-lived IM / queue sockets + image CDN: heavy multi fragment stalls loads.
_MESSAGING_HOST = re.compile(
    r"^(im|queuev?\d*|queue|pubsub|notify|sapi)[\.-]",
    re.I,
)
_USERAPI_HOST = re.compile(r"(^|\.)userapi\.com$", re.I)

# When a VK CDN IP is firewalled, dial a working peer that still presents
# a valid cert for the original SNI. Pools are family-specific:
# userapi.com avatars must NOT fall back to vk.com edges (wrong cert / empty).
FALLBACK_SEEDS = {
    "userapi": (
        # Gateway edges: accept other sun*-SNI and 301 → ps/pp.userapi.com
        "uk.userapi.com",
        "ppu.userapi.com",
        "ps.userapi.com",
        "sun1-1.userapi.com",
        "sun1-2.userapi.com",
        "sun1-3.userapi.com",
        "sun1-10.userapi.com",
        "sun1-50.userapi.com",
        "sun1-60.userapi.com",
        "sun1-76.userapi.com",
        "sun1-100.userapi.com",
        "sun1-120.userapi.com",
        "sun6-1.userapi.com",
        "pp.userapi.com",
        "sun9-16.userapi.com",
        "sun9-22.userapi.com",
        "sun9-50.userapi.com",
        "sun9-60.userapi.com",
        "sun9-76.userapi.com",
        "sun2-10.userapi.com",
        "sun2-20.userapi.com",
        "sun8-1.userapi.com",
    ),
    "vk": (
        "st1-1.vk.ru",
        "st1-2.vk.ru",
        "st1-10.vk.ru",
        "st1-50.vk.ru",
        "st1-100.vk.ru",
        "st.vk.ru",
        "vk.com",
        "vk.ru",
        "login.vk.ru",
        "api.vk.com",
    ),
    "mycdn": ("mycdn.me",),
    "okcdn": ("okcdn.ru",),
}
# Seeds whose IPs accept foreign sun*-SNI and 301 → ps/pp.
# Do NOT include ps/pp themselves here — wrong SNI on those IPs breaks TLS.
_USERAPI_GATEWAY_SEEDS = (
    "uk.userapi.com",
    "ppu.userapi.com",
    "sun1-1.userapi.com",
    "sun1-50.userapi.com",
    "sun6-1.userapi.com",
)
# IPs from these often 403 when SNI is another sun*-host → blank/blurry avatars.
_USERAPI_DEPRIORITIZE_SEEDS = (
    "pp.userapi.com",
    "sun9-16.userapi.com",
    "sun9-22.userapi.com",
    "sun9-50.userapi.com",
    "sun9-60.userapi.com",
    "sun9-76.userapi.com",
    "sun2-10.userapi.com",
    "sun2-20.userapi.com",
    "sun8-1.userapi.com",
)
_fallback_pools: dict[str, list[str]] = {}
_fallback_pool_ts: dict[str, float] = {}
_FALLBACK_TTL = 300.0
_fallback_lock = threading.Lock()
_fallback_building: dict[str, threading.Event] = {}
# sun1 / st1 / … → IPs learned from working seeds of that shard only
_shard_edges: dict[str, list[str]] = {}
_userapi_gateway_ips: list[str] = []
_userapi_deprioritize_ips: set[str] = set()
_SHARD_RE = re.compile(r"^(sun\d+|st\d+)-", re.I)
TARGET_SUFFIXES = (
    "vk.com",
    "vk.ru",
    "vk.me",
    "userapi.com",
    "vk-cdn.net",
    "vk-cdn.me",
    "vkuservideo.net",
    "vkuservideo.com",
    "vkuseraudio.net",
    "vkuserlive.net",
    "vk-portal.net",
    "mvk.com",
    "vkontakte.ru",
    "vkontakte.com",
    "vkcc.com",
    "vk.link",
    "mycdn.me",
    "okcdn.ru",
    "vkuser.net",
)

CONNECT_RE = re.compile(
    rb"^CONNECT\s+(\S+)\s+HTTP/\d\.\d",
    re.IGNORECASE,
)
HTTP_RE = re.compile(
    rb"^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+(\S+)\s+HTTP/\d\.\d",
    re.IGNORECASE,
)
HOST_RE = re.compile(rb"(?im)^Host:\s*([^\r\n]+)")


def decode_host_bytes(raw: bytes) -> str:
    """Host from CONNECT/Host header — browsers send ASCII / punycode."""
    text = raw.decode("latin-1", errors="replace").strip().strip('"')
    if not text:
        raise ValueError("empty host")
    # Optional IDNA for rare non-ASCII labels (idna codec has no errors=)
    try:
        text.encode("ascii")
        return text
    except UnicodeEncodeError:
        try:
            return text.encode("utf-8").decode("idna")
        except Exception:
            return text


def parse_connect_target(target: bytes) -> tuple[str, int]:
    """Parse CONNECT host:port or [ipv6]:port."""
    s = decode_host_bytes(target)
    if s.startswith("["):
        end = s.find("]")
        if end < 0:
            raise ValueError(f"bad IPv6 CONNECT target: {s!r}")
        host = s[1:end]
        rest = s[end + 1 :]
        if rest.startswith(":"):
            return host, int(rest[1:])
        return host, 443
    host, sep, port_s = s.rpartition(":")
    if not sep or not host or not port_s.isdigit():
        raise ValueError(f"bad CONNECT target: {s!r}")
    return host, int(port_s)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def now() -> str:
    return datetime.now().strftime("%H:%M:%S")


def is_target_host(host: str) -> bool:
    h = host.lower().rstrip(".").split(":")[0]
    if h.startswith("["):
        h = h.strip("[]")
    try:
        ipaddress.ip_address(h)
        return False
    except ValueError:
        pass
    return any(h == s or h.endswith("." + s) for s in TARGET_SUFFIXES)


def recv_until(sock: socket.socket, marker: bytes, limit: int = 65536) -> bytes:
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > limit:
            break
    return data


def recv_tls_records(sock: socket.socket, max_bytes: int = HELLO_MAX) -> bytes:
    """Read at least one complete TLS record (usually the ClientHello)."""
    buf = b""
    sock.settimeout(SO_TIMEOUT)
    while len(buf) < 5:
        chunk = sock.recv(4096)
        if not chunk:
            return buf
        buf += chunk

    if buf[0] != 0x16:
        # Not handshake — return whatever we have (caller may forward as-is)
        return buf

    need = 5 + int.from_bytes(buf[3:5], "big")
    while len(buf) < need and len(buf) < max_bytes:
        chunk = sock.recv(min(4096, need - len(buf)))
        if not chunk:
            break
        buf += chunk
    return buf


def fragment_client_hello(data: bytes, mode: str = FRAGMENT_MODE) -> list[bytes]:
    """Split first TLS Handshake record so SNI is not in one contiguous DPI window."""
    if len(data) < 6 or data[0] != 0x16:
        return [data]

    content_type = data[0:1]
    version = data[1:3]
    record_len = int.from_bytes(data[3:5], "big")
    first_end = 5 + record_len
    if first_end > len(data):
        return [data]  # incomplete — do not invent lengths

    handshake = data[5:first_end]
    rest = data[first_end:]
    if not handshake:
        return [data]

    out: list[bytes] = []
    if mode == "fine":
        size = max(1, FINE_SIZE)
        for i in range(0, len(handshake), size):
            piece = handshake[i : i + size]
            out.append(content_type + version + len(piece).to_bytes(2, "big") + piece)
    elif mode == "multi":
        size = max(8, MULTI_SIZE)
        for i in range(0, len(handshake), size):
            piece = handshake[i : i + size]
            out.append(content_type + version + len(piece).to_bytes(2, "big") + piece)
    else:
        # Two-record split (SpoofDPI-style): tiny head + remainder
        n = min(max(1, SPLIT_FIRST), len(handshake) - 1) if len(handshake) > 1 else 1
        head, tail = handshake[:n], handshake[n:]
        out.append(content_type + version + len(head).to_bytes(2, "big") + head)
        if tail:
            out.append(content_type + version + len(tail).to_bytes(2, "big") + tail)

    if rest:
        out.append(rest)
    return out


def send_parts(remote: socket.socket, parts: list[bytes]) -> None:
    """Send TLS fragments; lightly TCP-split the first record only."""
    for i, part in enumerate(parts):
        if i == 0 and len(part) > 8:
            remote.sendall(part[:5])
            time.sleep(0.008)
            remote.sendall(part[5:])
        else:
            remote.sendall(part)
        if i == 0 and len(parts) > 1:
            time.sleep(0.008)


def _shard_key(host: str) -> Optional[str]:
    m = _SHARD_RE.match(host.lower().rstrip("."))
    return m.group(1).lower() if m else None


def _cdn_family_for(host: str) -> str:
    h = host.lower().rstrip(".")
    if h == "userapi.com" or h.endswith(".userapi.com"):
        return "userapi"
    if h == "mycdn.me" or h.endswith(".mycdn.me"):
        return "mycdn"
    if h == "okcdn.ru" or h.endswith(".okcdn.ru"):
        return "okcdn"
    return "vk"


def _probe_ip(ip: str) -> Optional[str]:
    if is_blocked_ip(ip):
        return None
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.settimeout(0.9)
        probe.connect((ip, 443))
        return ip
    except OSError:
        return None
    finally:
        try:
            probe.close()
        except OSError:
            pass


def _build_fallback_pool(kind: str) -> list[str]:
    """Resolve + probe seed hosts; remember per-shard / gateway edges."""
    seeds = FALLBACK_SEEDS.get(kind, ())
    seed_ips: list[tuple[str, str]] = []
    candidates: list[str] = []
    seen: set[str] = set()
    for name in seeds:
        try:
            infos = socket.getaddrinfo(name, 443, socket.AF_INET, socket.SOCK_STREAM)
        except socket.gaierror:
            continue
        for *_, sockaddr in infos:
            ip = sockaddr[0]
            if ip in seen or is_blocked_ip(ip):
                continue
            seen.add(ip)
            candidates.append(ip)
            seed_ips.append((name, ip))

    found: list[str] = []
    if candidates:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(16, len(candidates))
        ) as pool:
            for ip in pool.map(_probe_ip, candidates):
                if ip:
                    found.append(ip)

    ok = set(found)
    shard_acc: dict[str, list[str]] = {}
    gateway: list[str] = []
    deprioritize: set[str] = set()
    for name, ip in seed_ips:
        if ip not in ok:
            continue
        sk = _shard_key(name)
        if sk:
            bucket = shard_acc.setdefault(sk, [])
            if ip not in bucket:
                bucket.append(ip)
        if kind == "userapi":
            if name in _USERAPI_GATEWAY_SEEDS and ip not in gateway:
                gateway.append(ip)
            if name in _USERAPI_DEPRIORITIZE_SEEDS:
                deprioritize.add(ip)

    with _fallback_lock:
        for sk, iplist in shard_acc.items():
            _shard_edges[sk] = iplist
        if kind == "userapi":
            # Gateway wins over deprioritize if an IP appears in both
            _userapi_gateway_ips[:] = gateway
            _userapi_deprioritize_ips.clear()
            _userapi_deprioritize_ips.update(deprioritize - set(gateway))
    return found


def refresh_fallback_pool(kind: str) -> list[str]:
    """
    Resolve seed hostnames for a CDN family; keep only quick-connectable IPs.
    Single-flight: concurrent avatar CONNECTs wait on one build instead of
    each probing all seeds (that race made direct Messages blank).
    """
    now_ts = time.time()
    with _fallback_lock:
        cached = _fallback_pools.get(kind)
        if cached and now_ts - _fallback_pool_ts.get(kind, 0) < _FALLBACK_TTL:
            return list(cached)
        waiter = _fallback_building.get(kind)
        if waiter is not None:
            builder = False
        else:
            waiter = threading.Event()
            _fallback_building[kind] = waiter
            builder = True

    if not builder:
        waiter.wait(timeout=12.0)
        with _fallback_lock:
            return list(_fallback_pools.get(kind, []))

    try:
        found = _build_fallback_pool(kind)
        with _fallback_lock:
            _fallback_pools[kind] = found
            _fallback_pool_ts[kind] = time.time()
        return list(found)
    finally:
        with _fallback_lock:
            _fallback_building.pop(kind, None)
        waiter.set()


def fallback_ips_for(host: str) -> list[str]:
    """
    Pick rewrite candidates.
    For sun*-*.userapi.com: ONLY gateway IPs (uk/sun1-1 style) that 301→ps/pp.
    Never dial pp/ps/sun9 with foreign SNI (403 / blur).
    """
    kind = _cdn_family_for(host)
    ips = refresh_fallback_pool(kind)
    if kind in ("mycdn", "okcdn") and not ips:
        ips = refresh_fallback_pool("vk")

    h = host.lower().rstrip(".")
    sk = _shard_key(h)

    with _fallback_lock:
        gateway = list(_userapi_gateway_ips)
        shard = list(_shard_edges.get(sk, [])) if sk else []

    if kind == "userapi" and sk and sk.startswith("sun"):
        ordered: list[str] = []
        for ip in gateway + shard:
            if ip in ips and ip not in ordered:
                ordered.append(ip)
        # If gateway empty, fall back to any non-deprioritized pool IP
        if not ordered:
            with _fallback_lock:
                bad = set(_userapi_deprioritize_ips)
            ordered = [ip for ip in ips if ip not in bad]
            random.shuffle(ordered)
        return ordered

    if sk:
        prefer = [ip for ip in shard if ip in ips]
        rest = [ip for ip in ips if ip not in prefer]
        random.shuffle(rest)
        return prefer + rest
    out = list(ips)
    random.shuffle(out)
    return out


def is_blocked_ip(ip: str) -> bool:
    ip = str(ip)
    if ip in _runtime_blocked_ips:
        return True
    return any(ip.startswith(p) for p in BLOCKED_IP_PREFIXES)


def mark_ip_blocked(ip: str, log: Optional[Callable[[str], None]] = None) -> None:
    ip = str(ip)
    if ip in _runtime_blocked_ips or any(ip.startswith(p) for p in BLOCKED_IP_PREFIXES):
        return
    _runtime_blocked_ips.add(ip)
    if log:
        log(f"[{now()}] [BLOCK-LEARN] marked {ip} as blocked for this session")


def _should_learn_native_block(ip: str, host: str) -> bool:
    """
    Only learn-block CDN storage edges. Never poison working VK edges —
    one false timeout there rewrites good hosts and blurs every image.
    """
    if any(ip.startswith(p) for p in BLOCKED_IP_PREFIXES):
        return False
    # Never learn-block known-good VK / userapi ranges
    if ip.startswith(("87.240.", "93.186.", "185.32.", "95.213.")):
        return False
    if _CDN_STORAGE_HOST.match(host):
        return ip.startswith("95.142.") or ip.startswith("195.3.")
    return False


def _dial(ip: str, port: int, family: int = socket.AF_INET) -> socket.socket:
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(CONNECT_TIMEOUT)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.connect((ip, port))
    s.settimeout(SO_TIMEOUT)
    return s


def connect_remote(
    host: str, port: int, log: Optional[Callable[[str], None]] = None
) -> tuple[socket.socket, bool]:
    """
    Connect to host:port.
    Returns (socket, rewritten). rewritten=True means we dialed a same-family
    fallback IP because the native CDN address is blocked.
    """
    last_err: Optional[Exception] = None
    tried: list[str] = []

    infos: list = []
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            got = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
        except socket.gaierror as exc:
            last_err = exc
            continue
        for item in got:
            if item not in infos:
                infos.append(item)

    seen = set()
    ordered = []
    for family, socktype, proto, _, sockaddr in infos:
        key = (family, sockaddr[0], sockaddr[1])
        if key in seen:
            continue
        seen.add(key)
        ordered.append((family, socktype, proto, sockaddr))

    native_ips = [str(sa[0]) for *_, sa in ordered]
    # Only rewrite when EVERY native IP is known-blocked. Many sun1-*/st1-*
    # still land on working 87.240.* — those must stay native.
    if (
        port == 443
        and is_target_host(host)
        and bool(native_ips)
        and all(is_blocked_ip(ip) for ip in native_ips)
    ):
        if log:
            log(
                f"[{now()}] [REWRITE-SKIP-NATIVE] {host} "
                f"native={','.join(native_ips[:4])}"
            )
        return _connect_fallback(host, port, tried + native_ips, last_err, log)

    for family, socktype, proto, sockaddr in ordered:
        ip = str(sockaddr[0])
        tried.append(ip)
        if is_blocked_ip(ip):
            last_err = TimeoutError(f"known-blocked prefix {ip}")
            continue
        s = socket.socket(family, socktype, proto)
        try:
            s.settimeout(CONNECT_TIMEOUT)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect(sockaddr)
            s.settimeout(SO_TIMEOUT)
            return s, False
        except OSError as exc:
            last_err = exc
            timed_out = (
                isinstance(exc, (TimeoutError, socket.timeout))
                or "timed out" in str(exc).lower()
            )
            if timed_out and _should_learn_native_block(ip, host):
                mark_ip_blocked(ip, log)
            try:
                s.close()
            except OSError:
                pass

    if port == 443 and is_target_host(host):
        return _connect_fallback(host, port, tried, last_err, log)

    raise OSError(
        f"connect failed for {host}:{port} via {', '.join(tried[:10])}: {last_err}"
    )


def _connect_fallback(
    host: str,
    port: int,
    tried: list[str],
    last_err: Optional[Exception],
    log: Optional[Callable[[str], None]],
) -> tuple[socket.socket, bool]:
    candidates = fallback_ips_for(host)
    if not candidates:
        raise OSError(
            f"connect failed for {host}:{port} via {', '.join(tried[:10])}: "
            f"no CDN fallback IPs ({last_err})"
        )
    for ip in candidates:
        tag = f"{ip}(fallback)"
        if ip in tried or tag in tried or is_blocked_ip(ip):
            continue
        tried.append(tag)
        try:
            sock = _dial(ip, port)
            if log:
                log(f"[{now()}] [REWRITE] {host} -> {ip} (CDN IP blocked)")
            return sock, True
        except OSError as exc:
            last_err = exc

    raise OSError(
        f"connect failed for {host}:{port} via {', '.join(tried[:10])}: {last_err}"
    )


def pipe_bidirectional(a: socket.socket, b: socket.socket) -> None:
    """Relay bytes both ways. Idle is normal for VK longpoll / WebSocket."""
    # Blocking sockets: a 60s SO_TIMEOUT during idle longpoll kills Messages.
    for s in (a, b):
        try:
            s.settimeout(None)
        except OSError:
            pass
    sockets = [a, b]
    try:
        while True:
            readable, _, errored = select.select(sockets, [], sockets, PIPE_IDLE)
            if errored:
                return
            if not readable:
                continue
            for s in readable:
                other = b if s is a else a
                try:
                    data = s.recv(PIPE_BUF)
                except OSError:
                    return
                if not data:
                    return
                try:
                    other.sendall(data)
                except OSError:
                    return
    except Exception:
        return


def parse_http_host(req: bytes) -> tuple[str, int]:
    m = HOST_RE.search(req)
    if not m:
        raise ValueError("no Host header")
    s = decode_host_bytes(m.group(1))
    if s.startswith("["):
        end = s.find("]")
        if end < 0:
            raise ValueError(f"bad IPv6 Host: {s!r}")
        host = s[1:end]
        rest = s[end + 1 :]
        if rest.startswith(":") and rest[1:].isdigit():
            return host, int(rest[1:])
        return host, 80
    if s.count(":") == 1:
        host, port_s = s.split(":")
        if port_s.isdigit():
            return host, int(port_s)
    return s, 80


# ---------------------------------------------------------------------------
# PAC HTTP server + Windows system proxy helpers
# ---------------------------------------------------------------------------

class _PacHandler(BaseHTTPRequestHandler):
    pac_bytes: bytes = b""

    def do_GET(self) -> None:  # noqa: N802
        if self.path.split("?", 1)[0] in ("/proxy.pac", "/"):
            body = self.pac_bytes
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ns-proxy-autoconfig")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        return


class PacServer:
    def __init__(self, host: str, port: int, pac_path: Path, log: Callable[[str], None]):
        self.host = host
        self.port = port
        self.pac_path = pac_path
        self.log = log
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.running:
            return
        data = self.pac_path.read_bytes() if self.pac_path.is_file() else (
            b'function FindProxyForURL(url, host){return "DIRECT";}\n'
        )
        handler = type("PacHandlerBound", (_PacHandler,), {"pac_bytes": data})
        httpd = ThreadingHTTPServer((self.host, self.port), handler)
        self._httpd = httpd
        self._thread = threading.Thread(target=httpd.serve_forever, name="pac-http", daemon=True)
        self._thread.start()
        self.log(f"[{now()}] PAC http://{self.host}:{self.port}/proxy.pac")

    def stop(self) -> None:
        httpd = self._httpd
        self._httpd = None
        if httpd is not None:
            try:
                httpd.shutdown()
            except Exception:
                pass
            try:
                httpd.server_close()
            except Exception:
                pass
        t = self._thread
        if t is not None:
            t.join(timeout=2)
        self._thread = None


def _win_inet_refresh() -> None:
    if sys.platform != "win32":
        return
    try:
        import ctypes

        ctypes.windll.Wininet.InternetSetOptionW(0, 39, 0, 0)  # SETTINGS_CHANGED
        ctypes.windll.Wininet.InternetSetOptionW(0, 37, 0, 0)  # REFRESH
    except Exception:
        pass


def windows_set_pac(url: str) -> None:
    if sys.platform != "win32":
        raise RuntimeError("仅支持 Windows")
    import winreg

    key = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        0,
        winreg.KEY_SET_VALUE,
    )
    try:
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, url)
    finally:
        winreg.CloseKey(key)
    _win_inet_refresh()


def windows_clear_proxy() -> None:
    if sys.platform != "win32":
        raise RuntimeError("仅支持 Windows")
    import winreg

    key = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        0,
        winreg.KEY_SET_VALUE,
    )
    try:
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, "")
        winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, "")
    finally:
        winreg.CloseKey(key)
    _win_inet_refresh()


# ---------------------------------------------------------------------------
# Proxy server
# ---------------------------------------------------------------------------

class FragmentProxy:
    def __init__(self, host: str, port: int, log: Callable[[str], None]):
        self.host = host
        self.port = port
        self.log = log
        self.mode = FRAGMENT_MODE
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._active = 0
        self._lock = threading.Lock()
        self._live: set[socket.socket] = set()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and not self._stop.is_set()

    def _track(self, sock: socket.socket) -> None:
        with self._lock:
            self._live.add(sock)

    def _untrack(self, sock: socket.socket) -> None:
        with self._lock:
            self._live.discard(sock)

    @staticmethod
    def _force_close(sock: Optional[socket.socket]) -> None:
        if sock is None:
            return
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass

    def start(self) -> None:
        if self.running:
            return
        # leftover accept thread from a previous stop
        if self._thread is not None and self._thread.is_alive():
            self._stop.set()
            self._thread.join(timeout=2)

        self._stop.clear()
        _runtime_blocked_ips.clear()

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(256)
        srv.settimeout(0.5)
        self._sock = srv
        self._thread = threading.Thread(
            target=self._accept_loop, args=(srv,), name="proxy-accept", daemon=True
        )
        self._thread.start()
        self.log(f"[{now()}] Proxy listening on {self.host}:{self.port}  mode={self.mode}")

        def _prewarm() -> None:
            try:
                u = refresh_fallback_pool("userapi")
                v = refresh_fallback_pool("vk")
                self.log(
                    f"[{now()}] CDN fallback ready: userapi={len(u)} ips, vk={len(v)} ips"
                )
            except Exception as exc:
                self.log(f"[{now()}] CDN fallback warmup failed: {exc}")

        self.log(f"[{now()}] Warming CDN fallback pools…")
        threading.Thread(target=_prewarm, name="cdn-warmup", daemon=True).start()

    def stop(self) -> None:
        """Stop accepting and cut all live tunnels (so browser notices immediately)."""
        self._stop.set()
        listen = self._sock
        self._sock = None
        self._force_close(listen)

        with self._lock:
            live = list(self._live)
            self._live.clear()
        for s in live:
            self._force_close(s)

        t = self._thread
        if t is not None and t.is_alive():
            t.join(timeout=1.5)
        self._thread = None
        self.log(f"[{now()}] Proxy stopped (listener + {len(live)} connection(s) closed)")

    def _accept_loop(self, listen: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                client, addr = listen.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if self._stop.is_set():
                self._force_close(client)
                break
            try:
                client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            self._track(client)
            threading.Thread(
                target=self._handle_client,
                args=(client, addr),
                name=f"conn-{addr[0]}:{addr[1]}",
                daemon=True,
            ).start()
        self._force_close(listen)

    def _handle_client(self, client: socket.socket, addr) -> None:
        remote: Optional[socket.socket] = None
        with self._lock:
            self._active += 1
            active = self._active
        try:
            if self._stop.is_set():
                return
            client.settimeout(SO_TIMEOUT)
            req = recv_until(client, b"\r\n\r\n")
            if not req or self._stop.is_set():
                return

            m = CONNECT_RE.match(req)
            if m:
                host, port = parse_connect_target(m.group(1))
                remote = self._handle_connect(client, host, port, active)
                return

            hm = HTTP_RE.match(req)
            if hm:
                remote = self._handle_http(client, req, active)
                return

            client.sendall(
                b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"
            )
            self.log(f"[{now()}] Bad request from {addr[0]}")
        except Exception as exc:
            if not self._stop.is_set():
                self.log(f"[{now()}] Error {addr[0]}: {exc}")
        finally:
            self._force_close(remote)
            self._untrack(client)
            self._force_close(client)
            with self._lock:
                self._active -= 1

    def _handle_connect(
        self, client: socket.socket, host: str, port: int, active: int
    ) -> Optional[socket.socket]:
        bypass = is_target_host(host)
        mode = "FRAGMENT" if bypass else "PASS"
        self.log(f"[{now()}] [{mode}] CONNECT {host}:{port}  (active={active})")

        remote, _rewritten = connect_remote(host, port, self.log)
        self._track(remote)
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        if bypass:
            # Light split for chat + userapi images; multi is too heavy and
            # leaves VK stuck on blurry placeholders (full image never arrives).
            mode_override = None
            if (
                _MESSAGING_HOST.match(host)
                or _USERAPI_HOST.search(host)
                or _rewritten
            ):
                mode_override = "split"
            self._fragment_then_pipe(client, remote, host, mode_override=mode_override)
        else:
            pipe_bidirectional(client, remote)
        return remote

    def _handle_http(
        self, client: socket.socket, req: bytes, active: int
    ) -> Optional[socket.socket]:
        """
        Forward plain HTTP. For VK hosts, 302 → HTTPS avoids broken http auth loops
        when the browser still probes http://login.vk.ru.
        """
        try:
            host, port = parse_http_host(req)
        except ValueError:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            return None

        path_m = HTTP_RE.match(req)
        path = path_m.group(2).decode("latin-1", errors="ignore") if path_m else "/"
        if path.startswith("http://") or path.startswith("https://"):
            parts = urlsplit(path)
            path = parts.path or "/"
            if parts.query:
                path += "?" + parts.query

        # Local health check for the browser extension popup
        path_only = path.split("?", 1)[0]
        if path_only in ("/health", "/health/") or (
            host in ("127.0.0.1", "localhost") and path_only in ("/", "/health", "/health/")
        ):
            body = b"OK"
            client.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Access-Control-Allow-Origin: *\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + body
            )
            return None

        if is_target_host(host) and port == 80:
            loc = f"https://{host}{path}".encode("ascii", errors="ignore")
            client.sendall(
                b"HTTP/1.1 302 Found\r\n"
                b"Location: " + loc + b"\r\n"
                b"Connection: close\r\n"
                b"Content-Length: 0\r\n\r\n"
            )
            self.log(f"[{now()}] [HTTP→HTTPS] {host}{path}")
            return None

        self.log(f"[{now()}] [HTTP-PASS] {host}:{port}  (active={active})")
        remote, _rewritten = connect_remote(host, port, self.log)
        self._track(remote)
        remote.sendall(req)
        pipe_bidirectional(client, remote)
        return remote

    def _fragment_then_pipe(
        self,
        client: socket.socket,
        remote: socket.socket,
        host: str,
        mode_override: Optional[str] = None,
    ) -> None:
        try:
            first = recv_tls_records(client)
        except OSError as exc:
            self.log(f"[{now()}] No ClientHello for {host}: {exc}")
            return
        if not first:
            return

        mode = mode_override or self.mode
        if first[0:1] == b"\x16":
            parts = fragment_client_hello(first, mode)
            self.log(
                f"[{now()}] Fragmented → {host} "
                f"({len(first)} B → {len(parts)} rec, mode={mode})"
            )
            if self._stop.is_set():
                return
            send_parts(remote, parts)
        else:
            remote.sendall(first)

        pipe_bidirectional(client, remote)


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("VK DPI Bypass Proxy")
        self.geometry("760x620")
        self.minsize(580, 480)

        self.proxy = FragmentProxy(LISTEN_HOST, LISTEN_PORT, self._ui_log)
        self.pac = PacServer(LISTEN_HOST, PAC_PORT, PAC_FILE, self._ui_log)
        self._build()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build(self) -> None:
        top = tk.Frame(self, padx=10, pady=10)
        top.pack(fill=tk.X)

        ui_font = (
            ("Microsoft YaHei UI", 11, "bold")
            if "Microsoft YaHei UI" in tkfont.families()
            else (
                ("Segoe UI", 11, "bold")
                if "Segoe UI" in tkfont.families()
                else ("Helvetica", 11, "bold")
            )
        )
        tk.Label(
            top, text=f"本地代理  {LISTEN_HOST}:{LISTEN_PORT}", font=ui_font
        ).pack(side=tk.LEFT)

        self.btn_start = tk.Button(top, text="启动", width=10, command=self._start)
        self.btn_start.pack(side=tk.RIGHT, padx=(6, 0))
        self.btn_stop = tk.Button(
            top, text="停止", width=10, command=self._stop, state=tk.DISABLED
        )
        self.btn_stop.pack(side=tk.RIGHT)
        tk.Button(top, text="使用说明", width=10, command=self._show_usage).pack(
            side=tk.RIGHT, padx=(0, 8)
        )

        guide = tk.LabelFrame(self, text=" 使用说明（新手看这里） ", padx=10, pady=8)
        guide.pack(fill=tk.X, padx=10, pady=(0, 6))
        tk.Label(
            guide,
            justify=tk.LEFT,
            anchor="w",
            text=(
                "① 点右上角「启动」，状态变成绿色「运行中」\n"
                "② 浏览器打开插件 VK DPI Proxy Helper，点「开启」（角标显示 ON）\n"
                "③ 打开 https://vk.com 或 https://vk.ru\n"
                "④ 不用时：插件点「关闭」→ 软件点「停止」\n"
                "\n"
                "记住：软件 + 插件 两个都要开。只开一个会转圈或打不开。\n"
                "不要开系统全局代理。分段模式选「中等 multi」即可。\n"
                "聊天图若仍模糊：高清文件只在被封节点上时无法拉清，可点图看是否能加载。"
            ),
        ).pack(fill=tk.X)

        mode_row = tk.Frame(self, padx=10)
        mode_row.pack(fill=tk.X)
        tk.Label(mode_row, text="分段模式:").pack(side=tk.LEFT)
        self.mode_var = tk.StringVar(value=FRAGMENT_MODE)
        for label, val in (
            ("稳妥 split（推荐·图片）", "split"),
            ("中等 multi", "multi"),
            ("激进 fine（很慢）", "fine"),
        ):
            tk.Radiobutton(
                mode_row,
                text=label,
                variable=self.mode_var,
                value=val,
                command=self._on_mode,
            ).pack(side=tk.LEFT, padx=(8, 0))

        self.status = tk.Label(self, text="状态: 已停止", anchor="w", padx=10, fg="#a33")
        self.status.pack(fill=tk.X)

        self.log_box = scrolledtext.ScrolledText(
            self, height=16, state=tk.DISABLED, wrap=tk.WORD
        )
        self.log_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=(4, 8))

        win_row = tk.Frame(self)
        win_row.pack(pady=(0, 4))
        tk.Button(
            win_row, text="仅代理 VK（系统 PAC）", width=20, command=self._enable_vk_only
        ).pack(side=tk.LEFT, padx=4)
        tk.Button(
            win_row, text="恢复直连（修 YouTube）", width=20, command=self._disable_sys_proxy
        ).pack(side=tk.LEFT, padx=4)

        btns = tk.Frame(self)
        btns.pack(pady=(0, 10))
        tk.Button(btns, text="使用说明", width=12, command=self._show_usage).pack(
            side=tk.LEFT, padx=4
        )
        tk.Button(btns, text="浏览器高级配置", command=self._show_help).pack(
            side=tk.LEFT, padx=4
        )
        tk.Button(btns, text="修复重定向问题", command=self._show_redirect_help).pack(
            side=tk.LEFT, padx=4
        )
        tk.Button(btns, text="如何判断是否还要代理", command=self._show_need_proxy).pack(
            side=tk.LEFT, padx=4
        )

        self._ui_log(f"[{now()}] Ready. 点「使用说明」可再次查看步骤。")
        self._ui_log(
            f"[{now()}] 推荐：本软件「启动」+ 浏览器插件「开启」（比系统 PAC 更安全）。"
        )
    def _on_mode(self) -> None:
        self.proxy.mode = self.mode_var.get()
        self._ui_log(f"[{now()}] Fragment mode → {self.proxy.mode}")

    def _ui_log(self, msg: str) -> None:
        def append() -> None:
            self.log_box.configure(state=tk.NORMAL)
            self.log_box.insert(tk.END, msg + "\n")
            self.log_box.see(tk.END)
            self.log_box.configure(state=tk.DISABLED)

        try:
            self.after(0, append)
        except RuntimeError:
            pass

    def _start(self) -> None:
        self.proxy.mode = self.mode_var.get()
        try:
            self.proxy.start()
            self.pac.start()
        except OSError as exc:
            self.proxy.stop()
            self.pac.stop()
            messagebox.showerror(
                "启动失败", f"无法监听端口\n{exc}"
            )
            return
        self.btn_start.configure(state=tk.DISABLED)
        self.btn_stop.configure(state=tk.NORMAL)
        self.status.configure(text="状态: 运行中 — 拦截/转发已启用", fg="#080")

    def _stop(self) -> None:
        self.btn_stop.configure(state=tk.DISABLED)
        self.status.configure(text="状态: 正在停止…", fg="#a60")
        self._ui_log(f"[{now()}] Stopping — closing listener and live tunnels…")

        def work() -> None:
            try:
                self.proxy.stop()
                self.pac.stop()
            finally:
                self.after(0, self._after_stopped)

        threading.Thread(target=work, name="proxy-stop", daemon=True).start()

    def _after_stopped(self) -> None:
        self.btn_start.configure(state=tk.NORMAL)
        self.btn_stop.configure(state=tk.DISABLED)
        self.status.configure(text="状态: 已停止", fg="#a33")

    def _enable_vk_only(self) -> None:
        if sys.platform != "win32":
            messagebox.showinfo("提示", f"请在浏览器 PAC 填：\n{PAC_URL}")
            return
        if not self.proxy.running:
            self._start()
            if not self.proxy.running:
                return
        try:
            windows_set_pac(PAC_URL)
        except Exception as exc:
            messagebox.showerror("设置失败", str(exc))
            return
        self._ui_log(f"[{now()}] Windows PAC → {PAC_URL}（仅 VK）")
        messagebox.showinfo(
            "已开启仅代理 VK",
            "已设置系统 PAC（只把 VK 送进本代理）。\n"
            "请完全退出浏览器再打开，然后访问 https://vk.com\n\n"
            "看 YouTube / 其它网站前，点「恢复直连」。",
        )

    def _disable_sys_proxy(self) -> None:
        if sys.platform != "win32":
            messagebox.showinfo("提示", "请在浏览器里关闭代理即可。")
            return
        try:
            windows_clear_proxy()
        except Exception as exc:
            messagebox.showerror("关闭失败", str(exc))
            return
        self._ui_log(f"[{now()}] Windows proxy cleared — direct connection")
        messagebox.showinfo(
            "已恢复直连",
            "系统代理已关闭。\n请完全退出浏览器再打开，YouTube 应恢复正常。",
        )

    def _on_close(self) -> None:
        if sys.platform == "win32":
            try:
                windows_clear_proxy()
                self._ui_log(f"[{now()}] Auto-cleared Windows proxy on exit")
            except Exception:
                pass
        if self.proxy.running or (
            self.proxy._thread is not None and self.proxy._thread.is_alive()
        ):
            self.proxy.stop()
        self.pac.stop()
        self.destroy()

    def _show_usage(self) -> None:
        messagebox.showinfo(
            "使用说明",
            "三步就会用：\n\n"
            "① 本软件点「启动」→ 状态显示「运行中」\n"
            "② 浏览器插件点「开启」→ 角标显示 ON\n"
            "③ 打开 https://vk.com 或 https://vk.ru\n\n"
            "不用时：\n"
            "· 插件点「关闭」\n"
            "· 软件点「停止」\n\n"
            "注意：\n"
            "· 软件和插件必须同时开，缺一不可\n"
            "· 只开插件不开软件 = 一直转圈\n"
            "· 不要开系统「全部网站」代理（会搞坏 YouTube）\n"
            "· 分段模式选「中等 multi」即可",
        )

    def _show_need_proxy(self) -> None:
        messagebox.showinfo(
            "VK 是修好了，还是代理在起作用？",
            "快速判断：\n\n"
            "1. 点「恢复直连」，完全重开浏览器\n"
            "2. 再打开 https://vk.com\n\n"
            "· 仍能打开 → 多半已不需要代理\n"
            "· 打不开 → 点「仅代理 VK」再用\n\n"
            "代理在工作时日志应有 [FRAGMENT] vk.com",
        )

    def _show_redirect_help(self) -> None:
        messagebox.showinfo(
            "重定向过多（可不清 Cookie）",
            "不必清空 Cookie，主账号可以保留。\n\n"
            "优先这样做：\n"
            "1. 启动 → 点「仅代理 VK」\n"
            "2. 重开浏览器，打开 https://vk.com（不要进 login.vk.ru）\n"
            "3. 看完后点「恢复直连」，避免影响 YouTube",
        )

    def _show_help(self) -> None:
        messagebox.showinfo(
            "浏览器代理配置",
            "推荐：装浏览器插件（只影响 VK）\n"
            "1. 本软件点「启动」\n"
            "2. Chrome 打开 chrome://extensions\n"
            "   Edge 打开 edge://extensions\n"
            "3. 打开「开发者模式」→ 加载已解压的扩展程序\n"
            "4. 选择插件文件夹：\n"
            f"   {APP_DIR.parent / 'vk-dpi-extension'}\n"
            "5. 点插件图标 → 开启，再打开 https://vk.com\n\n"
            "备选：点「仅代理 VK」（系统 PAC）\n"
            "不要用「全部手动代理 8888」，会弄坏 YouTube。",
        )


def main() -> None:
    app = App()
    # Auto-start so extension ON is never left pointing at a dead 8888
    app.after(200, app._start)
    app.mainloop()


if __name__ == "__main__":
    main()
