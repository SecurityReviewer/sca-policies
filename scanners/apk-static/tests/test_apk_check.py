"""Unit tests for apk_check.py (stdlib unittest, no external APK needed: a minimal APK is built in memory).

Run: python -m unittest discover -s wodles/apk-static/tests
"""
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import apk_check  # noqa: E402


def build_axml(elements):
    """elements: list of (tag, {attrname: bool|int|str}); returns a binary AndroidManifest.xml."""
    strings = []

    def sid(s):
        if s not in strings:
            strings.append(s)
        return strings.index(s)

    body = b""
    for tag, attrs in elements:
        name_i = sid(tag)
        attr_blob = b""
        for k, v in attrs.items():
            k_i = sid(k)
            if isinstance(v, bool):
                dtype, data, raw = 0x12, (0xFFFFFFFF if v else 0), -1
            elif isinstance(v, int):
                dtype, data, raw = 0x10, v, -1
            else:
                dtype, data, raw = 0x03, sid(v), sid(v)
            attr_blob += struct.pack("<iiiHBBI", -1, k_i, raw, 8, 0, dtype, data)
        size = 36 + len(attr_blob)
        body += struct.pack("<HHIIiiiHHHHHH", 0x0102, 16, size, 1, -1, -1, name_i, 20, 20, len(attrs), 0, 0, 0)
        body += attr_blob

    pool_strings = b""
    offsets = []
    for s in strings:
        offsets.append(len(pool_strings))
        pool_strings += struct.pack("<H", len(s)) + s.encode("utf-16le") + b"\x00\x00"
    while len(pool_strings) % 4:
        pool_strings += b"\x00"
    header_size = 28
    strings_start = header_size + 4 * len(strings)
    pool = struct.pack("<HHIIIIII", 0x0001, header_size, strings_start + len(pool_strings), len(strings), 0, 0, strings_start, 0)
    pool += b"".join(struct.pack("<I", o) for o in offsets) + pool_strings
    total = 8 + len(pool) + len(body)
    return struct.pack("<HHI", 0x0003, 8, total) + pool + body


def make_apk(path, manifest_elements, dex=b"", signed_v2=False):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("AndroidManifest.xml", build_axml(manifest_elements))
        z.writestr("classes.dex", dex)
    if signed_v2:
        with open(path, "ab") as f:
            f.write(b"APK Sig Block 42")


class ApkCheckTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def apk(self, elements, **kw):
        p = str(Path(self.tmp.name) / "t.apk")
        make_apk(p, elements, **kw)
        return p

    def test_debuggable_and_backup(self):
        bad = self.apk([("manifest", {}), ("application", {"debuggable": True})])
        self.assertFalse(apk_check.run("debuggable", bad)[0])
        self.assertFalse(apk_check.run("allow_backup", bad)[0])  # unset -> default true
        good = self.apk([("manifest", {}), ("application", {"debuggable": False, "allowBackup": False})])
        self.assertTrue(apk_check.run("debuggable", good)[0])
        self.assertTrue(apk_check.run("allow_backup", good)[0])

    def test_exported_components(self):
        p = self.apk([("manifest", {}), ("application", {}),
                      ("activity", {"name": "com.x.Open", "exported": True}),
                      ("service", {"name": "com.x.Safe", "exported": True, "permission": "com.x.PERM"}),
                      ("receiver", {"name": "com.x.Implicit"}), ("intent-filter", {})])
        ok, detail = apk_check.run("exported_components", p)
        self.assertFalse(ok)
        self.assertIn("activity:Open", detail)
        self.assertIn("receiver:Implicit", detail)  # intent-filter without exported => legacy exported
        self.assertNotIn("Safe", detail)

    def test_sdk_and_permissions(self):
        p = self.apk([("manifest", {}), ("uses-sdk", {"minSdkVersion": 21, "targetSdkVersion": 34}),
                      ("uses-permission", {"name": "android.permission.READ_SMS"}),
                      ("uses-permission", {"name": "android.permission.INTERNET"})])
        self.assertFalse(apk_check.run("min_sdk", p)[0])
        self.assertTrue(apk_check.run("target_sdk", p)[0])
        ok, detail = apk_check.run("dangerous_permissions", p)
        self.assertFalse(ok)
        self.assertIn("READ_SMS", detail)
        self.assertNotIn("INTERNET", detail)

    def test_string_scans(self):
        dex = b"\x00http://api.example.com/v1\x00AKIAABCDEFGHIJKLMNOP\x00addJavascriptInterface\x00\"DES/CBC\""
        p = self.apk([("manifest", {}), ("application", {})], dex=dex)
        self.assertFalse(apk_check.run("http_urls", p)[0])
        self.assertFalse(apk_check.run("hardcoded_secrets", p)[0])
        self.assertFalse(apk_check.run("js_interface", p)[0])
        self.assertFalse(apk_check.run("weak_crypto", p)[0])
        clean = self.apk([("manifest", {}), ("application", {})], dex=b"http://schemas.android.com/apk/res/android")
        self.assertTrue(apk_check.run("http_urls", clean)[0])

    def test_signature_scheme(self):
        self.assertFalse(apk_check.run("signature_scheme", self.apk([("manifest", {})]))[0])
        self.assertTrue(apk_check.run("signature_scheme", self.apk([("manifest", {})], signed_v2=True))[0])

    def test_unknown_check_and_bad_file_do_not_crash_main(self):
        sys.argv = ["apk_check.py", "nope", self.apk([("manifest", {})])]
        self.assertEqual(apk_check.main(), 0)
        sys.argv = ["apk_check.py", "debuggable", str(Path(self.tmp.name) / "missing.apk")]
        self.assertEqual(apk_check.main(), 0)


if __name__ == "__main__":
    unittest.main()
