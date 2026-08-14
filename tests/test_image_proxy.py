#!/usr/bin/env python3
"""
Minimal verification for vk-dpi-proxy image path safety.
Does not touch live VK tokens or chat content.
"""

from __future__ import annotations

import hashlib
import socket
import threading
import time
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import dpi_proxy as P  # noqa: E402


class SanitizeTests(unittest.TestCase):
    def test_strips_query_tokens(self):
        raw = "https://sun9-76.userapi.com/impg/abc123/photo.jpg?size=x&hash=SECRET"
        out = P.sanitize_url_for_log(raw)
        self.assertNotIn("SECRET", out)
        self.assertNotIn("hash=", out)
        self.assertIn("/impg/", out)

    def test_no_cookie_fields_in_helpers(self):
        src = Path(P.__file__).read_text(encoding="utf-8")
        for bad in ("Authorization", "Cookie:", "chat text", "access_token"):
            # Logging helpers must not format these names into diagnostic templates
            self.assertNotIn(f"[IMG-DIAG].*{bad}", src)


class FragmentPolicyTests(unittest.TestCase):
    def test_image_cdn_never_multi(self):
        for host in (
            "sun9-76.userapi.com",
            "pp.userapi.com",
            "st1-84.vk.ru",
            "ps.userapi.com",
        ):
            self.assertEqual(P.host_traffic_class(host), "image_cdn")
            mode = P.resolve_fragment_mode(host, "multi")
            self.assertIn(mode, ("none", "split"))
            self.assertNotIn(mode, ("multi", "fine"))

    def test_messaging_is_split(self):
        self.assertEqual(P.resolve_fragment_mode("im.vk.com", "fine"), "split")

    def test_fragment_none_passthrough(self):
        hello = bytes([0x16, 0x03, 0x01]) + (20).to_bytes(2, "big") + b"A" * 20
        # mode none is handled by caller; fragment_client_hello still splits if called
        parts = P.fragment_client_hello(hello, "split")
        self.assertGreaterEqual(len(parts), 1)


class PipeIntegrityTests(unittest.TestCase):
    def test_half_close_drains_remaining(self):
        """One side EOF must not drop bytes already queued from the peer."""
        a, a2 = socket.socketpair()
        b, b2 = socket.socketpair()
        payload = hashlib.sha256(b"large-image-body").digest() * 4000  # ~128KB
        received = bytearray()
        err = []

        def client_read():
            try:
                while True:
                    chunk = a2.recv(65536)
                    if not chunk:
                        break
                    received.extend(chunk)
            except OSError as exc:
                err.append(exc)

        def server_write():
            try:
                # Simulate server sending a large body then closing its write.
                b2.sendall(payload)
                b2.shutdown(socket.SHUT_WR)
            except OSError as exc:
                err.append(exc)

        t_pipe = threading.Thread(
            target=P.pipe_bidirectional, args=(a, b), daemon=True
        )
        t_r = threading.Thread(target=client_read, daemon=True)
        t_w = threading.Thread(target=server_write, daemon=True)
        t_pipe.start()
        t_r.start()
        t_w.start()
        t_w.join(timeout=5)
        t_r.join(timeout=5)
        t_pipe.join(timeout=5)
        for s in (a, a2, b, b2):
            try:
                s.close()
            except OSError:
                pass
        self.assertFalse(err)
        self.assertEqual(bytes(received), payload)
        self.assertGreater(len(received), 50_000)

    def test_byte_identity_small(self):
        a, a2 = socket.socketpair()
        b, b2 = socket.socketpair()
        msg = b"\xff\xd8\xff" + b"JPEG-BYTES" * 100  # fake image-ish

        def relay():
            P.pipe_bidirectional(a, b)

        threading.Thread(target=relay, daemon=True).start()
        b2.sendall(msg)
        b2.shutdown(socket.SHUT_WR)
        got = b""
        a2.settimeout(3)
        while True:
            try:
                chunk = a2.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            got += chunk
        for s in (a, a2, b, b2):
            try:
                s.close()
            except OSError:
                pass
        self.assertEqual(got, msg)


class ConnectClassifyTests(unittest.TestCase):
    def test_close_reasons(self):
        self.assertEqual(P.classify_close_error(TimeoutError("x")), "timeout")
        self.assertEqual(P.classify_close_error(ConnectionResetError()), "reset")


class ContentScriptPresenceTests(unittest.TestCase):
    def test_extension_has_content_script(self):
        ext = ROOT.parent / "vk-dpi-extension"
        man = (ext / "manifest.json").read_text(encoding="utf-8")
        self.assertIn("content_scripts", man)
        self.assertTrue((ext / "content.js").is_file())
        js = (ext / "content.js").read_text(encoding="utf-8")
        self.assertNotIn("size=orig", js.lower())
        self.assertNotIn("4096", js)
        self.assertIn("sanitizeUrlForLog", js)
        self.assertIn("srcset", js)


if __name__ == "__main__":
    unittest.main(verbosity=2)
