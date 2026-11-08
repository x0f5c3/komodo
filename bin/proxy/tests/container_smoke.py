"""Run against the locally built komodo-proxy:0.0.0 image on a Unix Docker host."""

import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import uuid


def docker(*args):
    result = subprocess.run(
        ["docker", *args], text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if result.returncode:
        raise RuntimeError(f"docker {args}: {result.stdout}")
    return result.stdout.strip()


class Origin(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"container-origin-ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


with tempfile.TemporaryDirectory(prefix="komodo-proxy-smoke-") as root:
    root = Path(root)
    certs = root / "certs"
    config = root / "config"
    certs.mkdir()
    config.mkdir()
    for version in ("v1", "v2"):
        directory = certs / version
        directory.mkdir()
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "ed25519", "-nodes",
             "-keyout", str(directory / "tls.key"),
             "-out", str(directory / "tls.crt"), "-days", "1",
             "-subj", "/CN=app.example.com",
             "-addext", "subjectAltName=DNS:app.example.com"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        (directory / "tls.key").chmod(0o444)
        (directory / "tls.crt").chmod(0o444)
    (certs / "current").symlink_to("v1")
    origin = http.server.ThreadingHTTPServer(("0.0.0.0", 0), Origin)
    thread = threading.Thread(target=origin.serve_forever, daemon=True)
    thread.start()
    routes = {
        "https_port": 443,
        "routes": [{
            "domain": "app.example.com",
            "upstream": f"http://host.docker.internal:{origin.server_port}",
            "certificate_directory": "/certificates/test",
        }],
    }
    (config / "routes.json").write_text(json.dumps(routes))
    name = "komodo-proxy-smoke-" + uuid.uuid4().hex[:12]
    started = False
    try:
        docker(
            "run", "--detach", "--name", name, "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--add-host", "host.docker.internal:host-gateway",
            "--health-cmd=proxy --health", "--health-interval=1s",
            "--health-timeout=3s", "--health-retries=3",
            "--publish", "127.0.0.1::8080", "--publish", "127.0.0.1::8443",
            "--volume", f"{config}:/etc/komodo-proxy:ro",
            "--volume", f"{certs}:/certificates/test:ro",
            "komodo-proxy:0.0.0",
        )
        started = True
        docker("exec", name, "proxy", "--check")
        for _ in range(30):
            if docker("inspect", "--format", "{{.State.Health.Status}}", name) == "healthy":
                break
            time.sleep(1)
        else:
            raise AssertionError("Container did not become healthy")
        bindings = json.loads(docker("inspect", name))[0]["NetworkSettings"]["Ports"]
        tls_port = int(bindings["8443/tcp"][0]["HostPort"])
        http_port = int(bindings["8080/tcp"][0]["HostPort"])
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        def request():
            with socket.create_connection(("127.0.0.1", tls_port), timeout=5) as raw:
                with context.wrap_socket(raw, server_hostname="app.example.com") as conn:
                    cert = conn.getpeercert(binary_form=True)
                    conn.sendall(b"GET /smoke HTTP/1.1\r\nHost: app.example.com\r\nConnection: close\r\n\r\n")
                    response = b""
                    while chunk := conn.recv(65536):
                        response += chunk
                    assert b"200 OK" in response and b"container-origin-ok" in response, response
                    return cert

        first = request()
        with socket.create_connection(("127.0.0.1", http_port), timeout=5) as conn:
            conn.sendall(b"GET /smoke?q=1 HTTP/1.1\r\nHost: app.example.com\r\nConnection: close\r\n\r\n")
            response = conn.recv(65536)
            assert b"308" in response and b"https://app.example.com/smoke?q=1" in response, response
        (certs / "next").symlink_to("v2")
        os.replace(certs / "next", certs / "current")
        for _ in range(30):
            if request() != first:
                break
            time.sleep(0.2)
        else:
            raise AssertionError("Container certificate did not rotate")
        (config / "next.json").write_text("{invalid")
        os.replace(config / "next.json", config / "routes.json")
        time.sleep(2)
        request()
        logs = docker("logs", name)
        assert "retaining last good configuration" in logs
        print("PASS: image startup, hardened flags, health, config check, HTTPS origin, redirect, certificate rotation, invalid-reload retention")
    finally:
        if started:
            print(docker("logs", name))
            subprocess.run(["docker", "rm", "-f", name], check=True, stdout=subprocess.DEVNULL)
        origin.shutdown()
        origin.server_close()
        thread.join()
