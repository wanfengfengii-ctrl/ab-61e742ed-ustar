import hashlib
import io
import json
import os
import sys
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.tarparser import bundle_digest, parse_tar
from app import server as srv
from tests.tarbuilder import archive, build_header, file_block

BLOCK = 512


def expected_bundle(files):
    h = hashlib.sha256()
    for path, content in sorted(files, key=lambda f: f[0].encode("utf-8")):
        p = path.encode("utf-8")
        h.update(len(p).to_bytes(4, "big"))
        h.update(p)
        h.update(len(content).to_bytes(8, "big"))
        h.update(hashlib.sha256(content).digest())
    return h.hexdigest()


class ParserTests(unittest.TestCase):
    def test_minimal_valid(self):
        blob = archive(file_block("a.txt", b"hello"))
        entries = parse_tar(blob)
        self.assertEqual([(e.path, e.size) for e in entries], [("a.txt", 5)])
        self.assertEqual(entries[0].digest, hashlib.sha256(b"hello").digest())
        self.assertEqual(bundle_digest(entries).hex(), expected_bundle([("a.txt", b"hello")]))

    def test_valid_with_record_padding(self):
        # Padding out to the 10240-byte blocking factor is canonical.
        blob = archive(file_block("a", b"x")) + b"\x00" * (10240 - 3 * BLOCK)
        parse_tar(blob)

    def test_multiple_sorted_by_utf8_bytes(self):
        files = [("z/b", b"2"), ("a", b"0"), ("z/a", b"1"), ("é", b"3")]
        blob = archive(*(file_block(n, c) for n, c in files))
        entries = parse_tar(blob)
        # Parse preserves archive order; the attest response and bundle digest
        # impose the canonical UTF-8 byte ordering.
        result = srv.attest(blob)
        self.assertEqual(
            [f["path"] for f in result["files"]],
            sorted((p for p, _ in files), key=lambda p: p.encode("utf-8")),
        )
        self.assertEqual(bundle_digest(entries).hex(), expected_bundle(files))

    def test_empty_file(self):
        entries = parse_tar(archive(file_block("empty", b"")))
        self.assertEqual(entries[0].size, 0)
        self.assertEqual(entries[0].digest.hex(), hashlib.sha256(b"").hexdigest())

    def test_ustar_prefix_field(self):
        # Same logical path expressed via prefix + name must parse identically.
        name = "b" * 90
        prefix = "a" * 100
        logical = f"{prefix}/{name}"
        blob = archive(file_block(name.encode(), b"abc", prefix=prefix.encode()))
        entries = parse_tar(blob)
        self.assertEqual(entries[0].path, logical)

    def test_empty_archive_rejected(self):
        from app.tarparser import TarError

        with self.assertRaises(TarError) as ctx:
            parse_tar(archive())
        self.assertEqual(ctx.exception.category, "empty_archive")

    def test_bad_checksum(self):
        h = build_header(b"a", 1, bad_checksum=True)
        with self.assertRaisesRegex(Exception, "bad_checksum"):
            parse_tar(archive(h + b"a"))

    def test_full_width_name_without_nul(self):
        h = build_header(b"n" * 100, 1)
        entries = parse_tar(archive(h + b"x" + b"\x00" * 511))
        self.assertEqual(entries[0].path, "n" * 100)

    def test_space_terminated_octal_accepted(self):
        # POSIX also allows space fill instead of NUL in numeric fields.
        h = bytearray(build_header(b"a", 1))
        h[124:136] = b"000000000001"  # size = 1, space-terminated
        h[148:156] = b"        "
        h[148:156] = format(sum(h), "06o").encode() + b"\x00 "
        entries = parse_tar(archive(bytes(h) + b"x" + b"\x00" * 511))
        self.assertEqual(entries[0].size, 1)

    def test_nonstandard_checksum_encoding_rejected(self):
        # Same numeric checksum, but a non-canonical field encoding:
        # space + 6 digits + space (POSIX requires "...\0 " or " ...\0").
        good_header = build_header(b"a", 1)
        good = format(sum(good_header[:148]) + sum(b"        ") + sum(good_header[156:]), "06o")
        h = bytearray(good_header)
        h[148:156] = b" " + good.encode() + b" "
        blob = archive(bytes(h) + b"x")
        with self.assertRaisesRegex(Exception, "bad_checksum"):
            parse_tar(blob)

    def test_zero_block_then_data_rejected(self):
        blob = file_block("a", b"x") + b"\x00" * BLOCK + build_header(b"b", 0)
        with self.assertRaisesRegex(Exception, "invalid_terminator"):
            parse_tar(blob)

    def test_non_ustar_magic(self):
        h = build_header(b"a", 1, magic=b"ustar  ")  # GNU magic
        with self.assertRaisesRegex(Exception, "non_ustar"):
            parse_tar(archive(h + b"a"))

    def test_link_types_rejected(self):
        for tf, cat in [(b"1", "unsupported_type"), (b"2", "unsupported_type"),
                        (b"5", "unsupported_type"), (b"L", "unsupported_type"),
                        (b"x", "unsupported_type")]:
            with self.subTest(typeflag=tf):
                h = build_header(b"x", 0, typeflag=tf, linkname=b"target" if tf == b"2" else b"")
                with self.assertRaisesRegex(Exception, cat):
                    parse_tar(archive(h))

    def test_symlink_payload_rejected_even_as_typeflag_zero(self):
        h = build_header(b"a", 6, linkname=b"target")
        with self.assertRaisesRegex(Exception, "invalid_header"):
            parse_tar(archive(h + b"target"))

    def test_duplicate_path(self):
        blob = archive(file_block("a", b"1"), file_block("a", b"2"))
        with self.assertRaisesRegex(Exception, "duplicate_path"):
            parse_tar(blob)

    def test_duplicate_via_prefix_split(self):
        b1 = file_block(b"a/b", b"x")
        b2 = file_block(b"b", b"y", prefix=b"a")
        with self.assertRaisesRegex(Exception, "duplicate_path"):
            parse_tar(archive(b1, b2))

    def test_path_violations(self):
        bad = [
            ("/abs", "invalid_path"),
            ("a/../b", "invalid_path"),
            ("a/./b", "invalid_path"),
            ("a//b", "invalid_path"),
            ("a/b/", "invalid_path"),
            ("a\\b", "invalid_path"),
            ("a\tb", "invalid_path"),
        ]
        for name, cat in bad:
            with self.subTest(path=name):
                blob = archive(file_block(name.encode("utf-8", "surrogateescape"), b"x"))
                with self.assertRaisesRegex(Exception, cat):
                    parse_tar(blob)

    def test_nfc_required(self):
        import unicodedata

        nfd = unicodedata.normalize("NFD", "café").encode("utf-8")
        blob = archive(file_block(nfd, b"x"))
        with self.assertRaisesRegex(Exception, "invalid_path"):
            parse_tar(blob)

    def test_embedded_nul_rejected(self):
        # A NUL inside the name field leaves non-zero "fill", so the header
        # cannot be given a single unambiguous interpretation.
        h = build_header(b"a\x00b", 1)
        with self.assertRaisesRegex(Exception, "invalid_header|invalid_path"):
            parse_tar(archive(h + b"x"))

    def test_non_utf8_path(self):
        h = build_header(b"caf\xff", 1)
        with self.assertRaisesRegex(Exception, "invalid_path"):
            parse_tar(archive(h + b"x"))

    def test_truncated_header(self):
        blob = archive(file_block("a", b"x"))[:300]
        with self.assertRaisesRegex(Exception, "truncated"):
            parse_tar(blob)

    def test_truncated_data(self):
        h = build_header(b"a", 100)
        with self.assertRaisesRegex(Exception, "truncated"):
            parse_tar(archive(h + b"short", terminator=None))

    def test_nonzero_padding(self):
        h = build_header(b"a", 1)
        blob = h + b"x" + b"\x00" * 510 + b"Z" + b"\x00" * BLOCK * 2
        with self.assertRaisesRegex(Exception, "invalid_padding"):
            parse_tar(blob)

    def test_nonzero_trailing(self):
        blob = archive(file_block("a", b"x")) + b"\x00" * 100 + b"Z"
        with self.assertRaisesRegex(Exception, "trailing_data"):
            parse_tar(blob)

    def test_missing_terminator(self):
        blob = file_block("a", b"x")
        with self.assertRaisesRegex(Exception, "truncated"):
            parse_tar(blob)

    def test_only_one_zero_block(self):
        blob = file_block("a", b"x") + b"\x00" * BLOCK
        with self.assertRaisesRegex(Exception, "truncated|trailing"):
            parse_tar(blob)

    def test_base256_size_rejected(self):
        h = bytearray(build_header(b"a", 0))
        h[124:136] = b"\x80" + b"\x00" * 11
        h[148:156] = b"        "
        h[148:156] = format(sum(h), "06o").encode() + b"\x00 "
        with self.assertRaisesRegex(Exception, "invalid_header"):
            parse_tar(archive(bytes(h)))

    def test_too_many_files(self):
        blocks = [file_block(f"f{i:03d}", b"x") for i in range(101)]
        with self.assertRaisesRegex(Exception, "too_many_files"):
            parse_tar(archive(*blocks))

    def test_content_over_limit(self):
        big = b"x" * (6 * 1024 * 1024 + 1)
        with self.assertRaisesRegex(Exception, "content_too_large"):
            parse_tar(archive(file_block("big", big)))

    def test_total_content_over_limit(self):
        a = b"x" * (3 * 1024 * 1024 + 1)
        b = b"y" * (3 * 1024 * 1024 + 1)
        with self.assertRaisesRegex(Exception, "content_too_large"):
            parse_tar(archive(file_block("a", a), file_block("b", b)))

    def test_error_carries_entry_index(self):
        from app.tarparser import TarError

        blob = archive(file_block("ok", b"1"), file_block("ok2", b"2", bad_checksum=False))
        # corrupt the second header checksum
        data = bytearray(blob)
        off = 2 * BLOCK  # header of entry 2 (file 1: 512 header + 512 data)
        data[off + 148] = ord("7")
        try:
            parse_tar(bytes(data))
            self.fail("expected TarError")
        except TarError as e:
            self.assertEqual(e.index, 2)
            self.assertEqual(e.category, "bad_checksum")


class InteropTests(unittest.TestCase):
    def test_stdlib_ustar_archive_accepted(self):
        import tarfile

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, format=tarfile.USTAR_FORMAT, mode="w") as tf:
            for name, content in [("hello.txt", b"hi"),
                                  ("nested/deep/file.bin", bytes(range(256)))]:
                info = tf.tarinfo(name)
                info.size = len(content)
                tf.addfile(info, io.BytesIO(content))
        blob = buf.getvalue()
        result = srv.attest(blob)
        self.assertEqual(
            [(f["path"], f["size"]) for f in result["files"]],
            [("hello.txt", 2), ("nested/deep/file.bin", 256)],
        )

    def test_pax_archive_rejected(self):
        import tarfile

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, format=tarfile.PAX_FORMAT, mode="w") as tf:
            # A 200-char name forces a pax extended header in PAX_FORMAT.
            name = ("very/" * 50).rstrip("/") + ".txt"
            info = tf.tarinfo(name)
            info.size = 1
            tf.addfile(info, io.BytesIO(b"x"))
        with self.assertRaisesRegex(Exception, "unsupported_type"):
            parse_tar(buf.getvalue())

    def test_gnu_longname_rejected(self):
        import tarfile

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, format=tarfile.GNU_FORMAT, mode="w") as tf:
            name = ("g/" * 60).rstrip("/") + ".txt"
            info = tf.tarinfo(name)
            info.size = 1
            tf.addfile(info, io.BytesIO(b"x"))
        with self.assertRaisesRegex(Exception, "non_ustar|unsupported_type"):
            parse_tar(buf.getvalue())


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = srv.ThreadingHTTPServer(("127.0.0.1", 0), srv.Handler)
        cls.port = cls.httpd.server_address[1]
        import threading

        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)

    def _request(self, path, data=None, headers=None, method="POST"):
        url = f"http://127.0.0.1:{self.port}{path}"
        req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_health(self):
        status, body = self._request("/health", method="GET")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"status": "ok"})

    def test_attest_ok(self):
        blob = archive(file_block("a.txt", b"hello"), file_block("b/c.bin", b"\x00\x01"))
        status, body = self._request(
            "/api/bundles/attest", blob, {"Content-Type": "application/x-tar"}
        )
        self.assertEqual(status, 200)
        self.assertEqual([f["path"] for f in body["files"]], ["a.txt", "b/c.bin"])
        self.assertEqual(body["files"][0]["size"], 5)
        self.assertEqual(
            body["files"][0]["sha256"], hashlib.sha256(b"hello").hexdigest()
        )
        self.assertEqual(body["bundleSha256"],
                         expected_bundle([("a.txt", b"hello"), ("b/c.bin", b"\x00\x01")]))

    def test_bad_checksum_no_partial_listing(self):
        h = build_header(b"a", 1, bad_checksum=True)
        blob = archive(h + b"a")
        status, body = self._request(
            "/api/bundles/attest", blob, {"Content-Type": "application/x-tar"}
        )
        self.assertEqual(status, 400)
        self.assertNotIn("files", body)
        self.assertEqual(body["error"]["category"], "bad_checksum")
        self.assertIn("entry 1", body["error"]["message"])

    def test_path_conflict(self):
        blob = archive(file_block("a", b"1"), file_block("a", b"2"))
        status, body = self._request(
            "/api/bundles/attest", blob, {"Content-Type": "application/x-tar"}
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["category"], "duplicate_path")
        self.assertNotIn("files", body)

    def test_wrong_media_type(self):
        status, body = self._request(
            "/api/bundles/attest", b"x", {"Content-Type": "application/octet-stream"}
        )
        self.assertEqual(status, 415)
        self.assertEqual(body["error"]["category"], "unsupported_media_type")

    def test_bundle_too_large(self):
        with self.assertRaises(srv._Reject) as ctx:
            srv.attest(b"x" * (8 * 1024 * 1024 + 1))
        self.assertEqual(ctx.exception.status, 413)
        self.assertEqual(ctx.exception.category, "bundle_too_large")

    def test_chunked_rejected(self):
        # urllib sends chunked when no Content-Length is given via a file-like
        # object; emulate by talking raw on a socket.
        import socket

        payload = archive(file_block("a", b"x"))
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            sock.sendall(
                b"POST /api/bundles/attest HTTP/1.1\r\nHost: x\r\n"
                b"Content-Type: application/x-tar\r\nTransfer-Encoding: chunked\r\n\r\n"
                + format(len(payload), "x").encode() + b"\r\n" + payload + b"\r\n0\r\n\r\n"
            )
            response = b""
            while b"\r\n\r\n" not in response:
                response += sock.recv(4096)
        self.assertIn(b" 411 ", response.split(b"\r\n", 1)[0])

    def test_unknown_route(self):
        status, _ = self._request("/nope", method="GET")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)
