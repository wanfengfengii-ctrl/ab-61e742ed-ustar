"""HTTP service: POST /api/bundles/attest and GET /health.

Only the Python standard library is used.
"""

from __future__ import annotations

import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .tarparser import TarError, bundle_digest, parse_tar

MAX_BUNDLE_BYTES = 8 * 1024 * 1024
TAR_MEDIA_TYPE = "application/x-tar"

# Categories that mean the request itself was too big.
_SIZE_CATEGORIES = frozenset({"content_too_large", "too_many_files", "bundle_too_large"})


class _Reject(Exception):
    def __init__(self, status: HTTPStatus, category: str, message: str):
        super().__init__(message)
        self.status = status
        self.category = category
        self.message = message


def _read_body(handler: BaseHTTPRequestHandler, length_header: str | None) -> bytes:
    if handler.headers.get("Transfer-Encoding", "").lower():
        raise _Reject(
            HTTPStatus.LENGTH_REQUIRED,
            "length_required",
            "a Content-Length-delimited body is required; chunked encoding is not accepted",
        )
    enc = handler.headers.get("Content-Encoding", "")
    if enc:
        raise _Reject(
            HTTPStatus.BAD_REQUEST,
            "compressed_or_encoded",
            f"content encoding {enc!r} is not accepted; the bundle must be uncompressed",
        )
    if length_header is not None:
        try:
            length = int(length_header)
            if length < 0:
                raise ValueError
        except ValueError:
            raise _Reject(
                HTTPStatus.LENGTH_REQUIRED,
                "invalid_length",
                "Content-Length is not a non-negative integer",
            )
        if length > MAX_BUNDLE_BYTES:
            raise _Reject(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "bundle_too_large",
                f"bundle exceeds {MAX_BUNDLE_BYTES} bytes",
            )
        data = b""
        while len(data) < length:
            chunk = handler.rfile.read(min(65536, length - len(data)))
            if not chunk:
                raise _Reject(
                    HTTPStatus.BAD_REQUEST,
                    "truncated",
                    "request body ended before Content-Length bytes",
                )
            data += chunk
        return data

    # Chunked or unknown length: read until close, enforcing the cap.
    data = b""
    while True:
        chunk = handler.rfile.read(65536)
        if not chunk:
            break
        data += chunk
        if len(data) > MAX_BUNDLE_BYTES:
            raise _Reject(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "bundle_too_large",
                f"bundle exceeds {MAX_BUNDLE_BYTES} bytes",
            )
    return data


def attest(data: bytes) -> dict:
    if len(data) > MAX_BUNDLE_BYTES:
        raise _Reject(
            HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            "bundle_too_large",
            f"bundle exceeds {MAX_BUNDLE_BYTES} bytes",
        )
    try:
        entries = parse_tar(data)
    except TarError as exc:
        status = (
            HTTPStatus.REQUEST_ENTITY_TOO_LARGE
            if exc.category in _SIZE_CATEGORIES
            else HTTPStatus.BAD_REQUEST
        )
        raise _Reject(status, exc.category, exc.to_detail()) from None

    ordered = sorted(entries, key=lambda e: e.path.encode("utf-8"))
    return {
        "files": [
            {"path": e.path, "size": e.size, "sha256": e.digest.hex()}
            for e in ordered
        ],
        "bundleSha256": bundle_digest(entries).hex(),
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "BundleAttest/1.0"

    def _send_json(self, status: HTTPStatus, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status: HTTPStatus, category: str, message: str) -> None:
        # On failure no partial listing is ever returned.
        self._send_json(status, {"error": {"category": category, "message": message}})

    def do_GET(self) -> None:
        if self.path.split("?", 1)[0] == "/health":
            self._send_json(HTTPStatus.OK, {"status": "ok"})
            return
        self._send_error(HTTPStatus.NOT_FOUND, "not_found", f"unknown path: {self.path}")

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        if path != "/api/bundles/attest":
            self._send_error(HTTPStatus.NOT_FOUND, "not_found", f"unknown path: {self.path}")
            return

        ctype = self.headers.get("Content-Type", "")
        media = ctype.split(";", 1)[0].strip().lower()
        if media != TAR_MEDIA_TYPE:
            self._send_error(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
                f"Content-Type must be {TAR_MEDIA_TYPE}, got {ctype!r}",
            )
            return

        try:
            data = _read_body(self, self.headers.get("Content-Length"))
            result = attest(data)
        except _Reject as exc:
            self._send_error(exc.status, exc.category, exc.message)
            return
        self._send_json(HTTPStatus.OK, result)

    def do_PUT(self) -> None:
        self._method_not_allowed()

    def do_DELETE(self) -> None:
        self._method_not_allowed()

    def do_PATCH(self) -> None:
        self._method_not_allowed()

    def _method_not_allowed(self) -> None:
        self._send_error(
            HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed", "method not allowed"
        )


def main() -> None:
    host = os.environ.get("BUNDLE_HOST", "0.0.0.0")
    port = int(os.environ.get("BUNDLE_PORT", "8080"))
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"bundle attestation service listening on {host}:{port}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
