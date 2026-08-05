#!/usr/bin/env python3
"""
Local DPI bypass proxy using TLS Record Fragmentation.
Targets SNI-blocked sites (vk.com / vk.ru etc.) without a VPN.
stdlib only — Windows / macOS / Linux.
"""

from __future__ import annotations

import ipaddress
import os
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
# "split" = 2 records (compatible, recommended)
# "fine"  = 1–2 byte records (aggressive)
FRAGMENT_MODE = "split"
FINE_SIZE = 2
SPLIT_FIRST = 1  # first TLS record payload size (bytes of handshake body)

SO_TIMEOUT = 45
PIPE_BUF = 65536
HELLO_MAX = 64 * 1024

TARGET_SUFFIXES = (
    "vk.com",
    "vk.ru",
    "vk.me",
    "userapi.com",
    "vk-cdn.net",
    "vk-cdn.me",
    "vkuservideo.net",
    "vkuseraudio.net",
    "vkuserlive.net",
    "vk-portal.net",
    "mvk.com",
    "vkontakte.ru",
    "vkontakte.com",
    "vkcc.com",
    "vk.link",
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


def connect_remote(host: str, port: int) -> socket.socket:
    """Prefer IPv4 — some ISPs treat AAAA paths differently."""
    last_err: Optional[Exception] = None
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror:
        infos = []
    if not infos:
        infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)

    for family, socktype, proto, _, sockaddr in infos:
        s = socket.socket(family, socktype, proto)
        try:
            s.settimeout(SO_TIMEOUT)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect(sockaddr)
            return s
        except OSError as exc:
            last_err = exc
            try:
                s.close()
            except OSError:
                pass
    raise OSError(f"connect failed for {host}:{port}: {last_err}")


def pipe_bidirectional(a: socket.socket, b: socket.socket) -> None:
    sockets = [a, b]
    try:
        while True:
            readable, _, errored = select.select(sockets, [], sockets, SO_TIMEOUT)
            if errored or not readable:
                break
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
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(128)
        srv.settimeout(0.5)
        self._sock = srv
        self._thread = threading.Thread(
            target=self._accept_loop, args=(srv,), name="proxy-accept", daemon=True
        )
        self._thread.start()
        self.log(f"[{now()}] Proxy listening on {self.host}:{self.port}  mode={self.mode}")

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

        remote = connect_remote(host, port)
        self._track(remote)
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        if bypass:
            self._fragment_then_pipe(client, remote, host)
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
        remote = connect_remote(host, port)
        self._track(remote)
        remote.sendall(req)
        pipe_bidirectional(client, remote)
        return remote

    def _fragment_then_pipe(
        self, client: socket.socket, remote: socket.socket, host: str
    ) -> None:
        try:
            first = recv_tls_records(client)
        except OSError as exc:
            self.log(f"[{now()}] No ClientHello for {host}: {exc}")
            return
        if not first:
            return

        if first[0:1] == b"\x16":
            parts = fragment_client_hello(first, self.mode)
            self.log(
                f"[{now()}] Fragmented → {host} "
                f"({len(first)} B → {len(parts)} rec, mode={self.mode})"
            )
            for i, part in enumerate(parts):
                if self._stop.is_set():
                    return
                remote.sendall(part)
                if i == 0:
                    time.sleep(0.005)
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
        self.geometry("740x560")
        self.minsize(560, 420)

        self.proxy = FragmentProxy(LISTEN_HOST, LISTEN_PORT, self._ui_log)
        self.pac = PacServer(LISTEN_HOST, PAC_PORT, PAC_FILE, self._ui_log)
        self._build()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build(self) -> None:
        top = tk.Frame(self, padx=10, pady=10)
        top.pack(fill=tk.X)

        ui_font = (
            ("Segoe UI", 11, "bold")
            if "Segoe UI" in tkfont.families()
            else ("Helvetica", 11, "bold")
        )
        tk.Label(
            top, text=f"Local proxy  {LISTEN_HOST}:{LISTEN_PORT}", font=ui_font
        ).pack(side=tk.LEFT)

        self.btn_start = tk.Button(top, text="启动", width=10, command=self._start)
        self.btn_start.pack(side=tk.RIGHT, padx=(6, 0))
        self.btn_stop = tk.Button(
            top, text="停止", width=10, command=self._stop, state=tk.DISABLED
        )
        self.btn_stop.pack(side=tk.RIGHT)

        mode_row = tk.Frame(self, padx=10)
        mode_row.pack(fill=tk.X)
        tk.Label(mode_row, text="分段模式:").pack(side=tk.LEFT)
        self.mode_var = tk.StringVar(value=FRAGMENT_MODE)
        for label, val in (("稳妥 split", "split"), ("激进 fine", "fine")):
            tk.Radiobutton(
                mode_row,
                text=label,
                variable=self.mode_var,
                value=val,
                command=self._on_mode,
            ).pack(side=tk.LEFT, padx=(8, 0))

        info = tk.Label(
            self,
            justify=tk.LEFT,
            anchor="w",
            padx=10,
            text=(
                "不要用「全部手动代理」——会把 YouTube 等网站也塞进来。\n"
                "正确用法：启动后点「仅代理 VK」，看完 VK 再点「恢复直连」。"
            ),
        )
        info.pack(fill=tk.X)

        self.status = tk.Label(self, text="状态: 已停止", anchor="w", padx=10, fg="#a33")
        self.status.pack(fill=tk.X)

        self.log_box = scrolledtext.ScrolledText(
            self, height=18, state=tk.DISABLED, wrap=tk.WORD
        )
        self.log_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=(4, 8))

        win_row = tk.Frame(self)
        win_row.pack(pady=(0, 4))
        tk.Button(
            win_row, text="仅代理 VK（推荐）", width=18, command=self._enable_vk_only
        ).pack(side=tk.LEFT, padx=4)
        tk.Button(
            win_row, text="恢复直连（修 YouTube）", width=20, command=self._disable_sys_proxy
        ).pack(side=tk.LEFT, padx=4)

        btns = tk.Frame(self)
        btns.pack(pady=(0, 10))
        tk.Button(btns, text="浏览器配置说明", command=self._show_help).pack(
            side=tk.LEFT, padx=4
        )
        tk.Button(btns, text="修复重定向问题", command=self._show_redirect_help).pack(
            side=tk.LEFT, padx=4
        )
        tk.Button(btns, text="如何判断是否还要代理", command=self._show_need_proxy).pack(
            side=tk.LEFT, padx=4
        )

        self._ui_log(
            f"[{now()}] Ready. 启动后监听 {LISTEN_HOST}:{LISTEN_PORT}"
        )
        if sys.platform == "win32":
            self._ui_log(
                f"[{now()}] Tip: 点「仅代理 VK」→ 浏览器访问 vk.com；"
                "YouTube 异常时点「恢复直连」。"
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
    app.mainloop()


if __name__ == "__main__":
    main()
