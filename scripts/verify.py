#!/usr/bin/env python3
"""One-shot verification entrypoint for the Compose ``verify`` service.

Steps:
  1. Run the full unit test suite.
  2. Smoke-test a running server (BUNDLE_BASE_URL, http://web:8080 under
     Compose; otherwise a server is started locally):
       - GET  /health
       - POST a valid bundle            -> 200 + correct digests
       - POST a bad-checksum bundle     -> 400 bad_checksum, no partial list
       - POST a duplicate-path bundle   -> 400 duplicate_path, no partial list

Exits 0 only when every step succeeds.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.tarbuilder import archive, build_header, file_block  # noqa: E402


def run_unit_tests() -> bool:
    print("== [1/4] unit tests ==", flush=True)
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-v", "-s", "tests"],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )
    return proc.returncode == 0


def wait_for_health(base_url: str, attempts: int = 30) -> bool:
    for i in range(attempts):
        try:
            with urllib.request.urlopen(f"{base_url}/health", timeout=2) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(1)
        print(f"   waiting for {base_url}/health ... ({i + 1})", flush=True)
    return False


def post_tar(base_url: str, blob: bytes):
    req = urllib.request.Request(
        f"{base_url}/api/bundles/attest",
        data=blob,
        method="POST",
        headers={"Content-Type": "application/x-tar"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def smoke(base_url: str) -> bool:
    ok = True

    print(f"== [2/4] health check against {base_url} ==", flush=True)
    with urllib.request.urlopen(f"{base_url}/health", timeout=3) as resp:
        body = json.loads(resp.read())
    if resp.status == 200 and body.get("status") == "ok":
        print("   PASS health 200", flush=True)
    else:
        print(f"   FAIL health: {resp.status} {body}", flush=True)
        ok = False

    print("== [3/4] valid bundle ==", flush=True)
    files = [("a.txt", b"hello"), ("nested/b.bin", bytes(range(256)))]
    blob = archive(*(file_block(n, c) for n, c in files))
    status, body = post_tar(base_url, blob)
    expected_paths = sorted((n for n, _ in files), key=lambda p: p.encode("utf-8"))
    h = hashlib.sha256()
    for n, c in sorted(files, key=lambda f: f[0].encode("utf-8")):
        pb = n.encode("utf-8")
        h.update(len(pb).to_bytes(4, "big"))
        h.update(pb)
        h.update(len(c).to_bytes(8, "big"))
        h.update(hashlib.sha256(c).digest())
    if (
        status == 200
        and [f["path"] for f in body.get("files", [])] == expected_paths
        and body.get("bundleSha256") == h.hexdigest()
    ):
        print(f"   PASS valid bundle 200 bundleSha256={body['bundleSha256'][:16]}...", flush=True)
    else:
        print(f"   FAIL valid bundle: {status} {body}", flush=True)
        ok = False

    print("== [4/4] bad checksum + duplicate path ==", flush=True)
    bad_sum = archive(build_header(b"a", 1, bad_checksum=True) + b"a")
    status, body = post_tar(base_url, bad_sum)
    if status == 400 and body.get("error", {}).get("category") == "bad_checksum" and "files" not in body:
        print("   PASS bad checksum -> 400 bad_checksum (no partial listing)", flush=True)
    else:
        print(f"   FAIL bad checksum: {status} {body}", flush=True)
        ok = False

    conflict = archive(file_block("a", b"1"), file_block("a", b"2"))
    status, body = post_tar(base_url, conflict)
    if status == 400 and body.get("error", {}).get("category") == "duplicate_path" and "files" not in body:
        print("   PASS duplicate path -> 400 duplicate_path (no partial listing)", flush=True)
    else:
        print(f"   FAIL duplicate path: {status} {body}", flush=True)
        ok = False

    return ok


def start_local_server() -> tuple[subprocess.Popen | None, str]:
    base_url = os.environ.get("BUNDLE_BASE_URL")
    if base_url:
        return None, base_url.rstrip("/")
    port = 8090
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    env = dict(os.environ, BUNDLE_HOST="127.0.0.1", BUNDLE_PORT=str(port))
    proc = subprocess.Popen(
        [sys.executable, "-m", "app.server"],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return proc, f"http://127.0.0.1:{port}"


def main() -> int:
    proc, base_url = start_local_server()
    try:
        if not wait_for_health(base_url):
            print(f"FATAL: service at {base_url} never became healthy", flush=True)
            return 1
        results = [run_unit_tests(), smoke(base_url)]
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    if all(results):
        print("\nALL CHECKS PASSED", flush=True)
        return 0
    print("\nVERIFICATION FAILED", flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())
