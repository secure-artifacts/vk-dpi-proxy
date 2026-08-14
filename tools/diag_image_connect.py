#!/usr/bin/env python3
"""
Optional live diagnostic (no tokens logged).
Usage:
  python tools/diag_image_connect.py sun9-76.userapi.com
Compares: direct TCP, resolve IPs, blocked-prefix match, fragment policy.
"""

from __future__ import annotations

import socket
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import dpi_proxy as P  # noqa: E402


def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else "pp.userapi.com"
    print(f"host={host}")
    print(f"class={P.host_traffic_class(host)}")
    print(f"image_cdn={P.is_image_cdn_host(host)}")
    print(f"fragment_policy={P.resolve_fragment_mode(host, P.FRAGMENT_MODE)}")
    print(f"IMAGE_CDN_FRAGMENT_MODE={P.IMAGE_CDN_FRAGMENT_MODE}")
    try:
        infos = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        print(f"dns_error={exc}")
        return 1
    ips = []
    for *_, sa in infos:
        ip = sa[0]
        if ip not in ips:
            ips.append(ip)
    print(f"native_ips={','.join(ips[:8])}")
    for ip in ips[:6]:
        blocked = P.is_blocked_ip(ip)
        t0 = time.perf_counter()
        ok = False
        err = ""
        try:
            s = socket.create_connection((ip, 443), timeout=3)
            s.close()
            ok = True
        except OSError as exc:
            err = P.classify_close_error(exc)
        ms = int((time.perf_counter() - t0) * 1000)
        print(f"  ip={ip} blocked={int(blocked)} tcp_ok={int(ok)} ms={ms} err={err or '-'}")
    print("note=No URLs/tokens fetched. Use browser Network for Content-Type checks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
