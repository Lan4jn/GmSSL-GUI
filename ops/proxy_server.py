#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Loopback Static & API Reverse Proxy Server for GmSSL-GUI.

Serves static frontend assets from web/dist and forwards /api/ requests to
platform-service on 127.0.0.1:8080.
Binds strictly to 127.0.0.1.
Enforces strict root boundary checks (no directory traversal, no directory listings).
"""

import argparse
import http.client
from http.server import HTTPServer, BaseHTTPRequestHandler
import mimetypes
import os
from pathlib import Path
import sys
import urllib.parse

class LoopbackProxyHandler(BaseHTTPRequestHandler):
    server_version = "GmSSL-Proxy/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        # Structured single-line log without sensitive payloads
        sys.stderr.write(f"[{self.log_date_time_string()}] {self.command} {self.path.split('?')[0]} -> {format % args}\n")

    @property
    def dist_root(self) -> Path:
        return self.server.dist_root

    @property
    def api_host(self) -> str:
        return self.server.api_host

    @property
    def api_port(self) -> int:
        return self.server.api_port

    def do_HEAD(self):
        self._handle_request(send_body=False)

    def do_GET(self):
        self._handle_request(send_body=True)

    def do_POST(self):
        self._handle_request(send_body=True)

    def do_PUT(self):
        self._handle_request(send_body=True)

    def do_DELETE(self):
        self._handle_request(send_body=True)

    def do_PATCH(self):
        self._handle_request(send_body=True)

    def do_OPTIONS(self):
        self._handle_request(send_body=True)

    def _handle_request(self, send_body: bool):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path

        if path.startswith("/api/"):
            self._proxy_api(parsed, send_body)
        else:
            self._serve_static(path, send_body)

    def _proxy_api(self, parsed: urllib.parse.SplitResult, send_body: bool):
        # Read body if present
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else None

        # Prepare upstream connection
        conn = http.client.HTTPConnection(self.api_host, self.api_port, timeout=30)
        upstream_path = parsed.path
        if parsed.query:
            upstream_path += "?" + parsed.query

        # Forward headers
        headers = {}
        for k, v in self.headers.items():
            k_lower = k.lower()
            if k_lower not in ("host", "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade"):
                headers[k] = v

        # Set upstream Host and forwarding metadata
        headers["Host"] = f"{self.api_host}:{self.api_port}"
        client_host = self.headers.get("Host", f"127.0.0.1:{self.server.server_port}")
        headers["X-Forwarded-Host"] = client_host
        headers["X-Forwarded-Proto"] = self.headers.get("X-Forwarded-Proto", "https")
        headers["X-Forwarded-For"] = self.headers.get("X-Forwarded-For", self.client_address[0])

        try:
            conn.request(self.command, upstream_path, body=body, headers=headers)
            res = conn.getresponse()
            res_body = res.read()
        except Exception as e:
            self.send_error(502, f"Upstream connection failed: {e}")
            return
        finally:
            conn.close()

        # Send response status
        self.send_response(res.status, res.reason)

        # Forward response headers (handling multiple Set-Cookie)
        for k, v in res.getheaders():
            k_lower = k.lower()
            if k_lower in ("transfer-encoding", "connection", "server", "content-length"):
                continue
            self.send_header(k, v)
        if send_body:
            self.send_header("Content-Length", str(len(res_body)))
        self.send_header("Connection", "close")
        self.end_headers()

        if send_body and res_body:
            self.wfile.write(res_body)

    def _serve_static(self, path: str, send_body: bool):
        if self.command not in ("GET", "HEAD"):
            self.send_error(405, "Method Not Allowed")
            return

        # Canonicalize target path within dist_root
        clean_path = os.path.normpath(urllib.parse.unquote(path)).lstrip("/")
        target = (self.dist_root / clean_path).resolve()

        # Strict containment check
        try:
            target.relative_to(self.dist_root)
        except ValueError:
            self.send_error(403, "Forbidden: Path traversal blocked")
            return

        # Directory handling
        if target.is_dir():
            target = target / "index.html"

        # SPA fallback: If file does not exist, fall back to root index.html
        if not target.is_file():
            # Check if this might be an asset that genuinely 404s
            if clean_path.startswith("assets/") or "." in Path(clean_path).name:
                self.send_error(404, "File not found")
                return
            target = self.dist_root / "index.html"

        if not target.is_file():
            self.send_error(404, "index.html not found")
            return

        # Serve the file
        mime_type, _ = mimetypes.guess_type(str(target))
        if not mime_type:
            mime_type = "application/octet-stream"
        if mime_type.startswith("text/") or mime_type in ("application/javascript", "application/json"):
            mime_type += "; charset=utf-8"

        file_size = target.stat().st_size
        self.send_response(200)
        self.send_header("Content-Type", mime_type)
        self.send_header("Content-Length", str(file_size))

        if target.name == "index.html":
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        elif "assets" in str(target):
            self.send_header("Cache-Control", "public, max-age=31536000, immutable")
        else:
            self.send_header("Cache-Control", "public, max-age=3600")

        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()

        if send_body:
            with open(target, "rb") as f:
                while chunk := f.read(65536):
                    self.wfile.write(chunk)


def run():
    parser = argparse.ArgumentParser(description="GmSSL-GUI Static and API Proxy Server")
    parser.add_argument("--host", default="127.0.0.1", help="Loopback host to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5180, help="Port to listen (default: 5180)")
    parser.add_argument("--dist", default="web/dist", help="Path to static web dist directory")
    parser.add_argument("--api-host", default="127.0.0.1", help="Upstream API host (default: 127.0.0.1)")
    parser.add_argument("--api-port", type=int, default=8080, help="Upstream API port (default: 8080)")
    args = parser.parse_args()

    dist_path = Path(args.dist).resolve()
    if not dist_path.is_dir() or not (dist_path / "index.html").is_file():
        sys.stderr.write(f"Error: Static directory {dist_path} does not exist or lacks index.html\n")
        sys.exit(1)

    server = HTTPServer((args.host, args.port), LoopbackProxyHandler)
    server.dist_root = dist_path
    server.api_host = args.api_host
    server.api_port = args.api_port
    sys.stderr.write(f"Proxy server running on http://{args.host}:{args.port} (serving {dist_path}, forwarding /api to {args.api_host}:{args.api_port})\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    run()
