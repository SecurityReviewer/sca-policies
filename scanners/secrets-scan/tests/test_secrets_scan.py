"""Unit tests for secrets_scan.py: python -m unittest discover -s wodles/secrets-scan/tests"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import secrets_scan as ss  # noqa: E402

PATTERNS = ss.load_patterns()
FAKE_AWS = "AKIA" + "QWERTYUIOPASDFGH"          # split so the test file itself is not a finding
FAKE_STRIPE = "sk_live_" + "a1B2c3D4e5F6g7H8i9J0k1L2"
SECRET_PW = "Sup3rS3cretValue"


class Tree(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "root"
        self.scan_dir = Path(self.tmp.name) / "scan"
        (self.scan_dir / "app").mkdir(parents=True)
        (self.scan_dir / "node_modules").mkdir()
        (self.scan_dir / "app" / "id_rsa").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n")
        (self.scan_dir / "app" / ".env").write_text(
            "DB_PASSWORD=" + SECRET_PW + "\nAPI_KEY=changeme\nPASSWORD=${FROM_ENV}\nAWS=" + FAKE_AWS + "\n")
        (self.scan_dir / "app" / "pay.py").write_text(
            'KEY = "' + FAKE_STRIPE + '"\nurl = "postgres://admin:hunter2pass@db.local/x"\n')
        (self.scan_dir / "node_modules" / "skip.env").write_text("PASSWORD=" + SECRET_PW + "\n")
        (self.scan_dir / "app" / "logo.png").write_bytes(b"\x89PNG\0" + FAKE_AWS.encode())
        self.cfg = dict(ss.DEFAULT_CONFIG, paths=[str(self.scan_dir)], exclude_regex=[], engine="custom")

    def tearDown(self):
        self.tmp.cleanup()

    def findings(self):
        return ss.custom_scan(self.cfg, PATTERNS, self.root, self.cfg["paths"])[0]


class CustomScanner(Tree):
    def test_detects_each_category(self):
        cats = {f["category"] for f in self.findings()}
        self.assertEqual(cats, {"private_keys", "cloud_credentials", "service_tokens", "hardcoded_credentials"})

    def test_skips_placeholders_binary_and_excluded_dirs(self):
        files = {os.path.basename(f["file"]) for f in self.findings()}
        self.assertNotIn("logo.png", files)
        self.assertNotIn("skip.env", files)
        creds = [f for f in self.findings() if f["detector"] == "hardcoded credential-like literal"]
        self.assertEqual([f["line"] for f in creds], [1])          # only DB_PASSWORD; changeme and ${FROM_ENV} are placeholders

    def test_no_raw_secret_in_results(self):
        ss.do_scan(self.cfg, self.root)
        blob = (self.root / "var" / "secrets-scan" / "results.json").read_text()
        for secret in (SECRET_PW, FAKE_AWS, FAKE_STRIPE, "hunter2pass"):
            self.assertNotIn(secret, blob)

    def test_findings_log_one_line_per_finding_without_secrets(self):
        res = ss.do_scan(self.cfg, self.root)
        log = self.root / "var" / "secrets-scan" / "findings.jsonl"
        lines = log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), len(res["findings"]))
        first = json.loads(lines[0])
        self.assertEqual(first["module"], "secrets-scan")
        self.assertEqual(first["scan_id"], res["finished"])
        for key in ("category", "detector", "path", "line", "fingerprint"):
            self.assertIn(key, first)
        blob = log.read_text(encoding="utf-8")
        for secret in (SECRET_PW, FAKE_AWS, FAKE_STRIPE, "hunter2pass"):
            self.assertNotIn(secret, blob)
        ss.do_scan(self.cfg, self.root)                      # a second scan appends
        self.assertEqual(len(log.read_text(encoding="utf-8").splitlines()), 2 * len(res["findings"]))

    def test_findings_log_rotates_when_large(self):
        ss.do_scan(self.cfg, self.root)
        log = self.root / "var" / "secrets-scan" / "findings.jsonl"
        log.write_text("x" * (ss.FINDINGS_LOG_MAX_BYTES + 1), encoding="utf-8")
        res = ss.do_scan(self.cfg, self.root)
        self.assertEqual(len(log.read_text(encoding="utf-8").splitlines()), len(res["findings"]))

    def test_fingerprint_is_stable_and_salted(self):
        a, b = self.findings(), self.findings()
        self.assertEqual([f["fingerprint"] for f in a], [f["fingerprint"] for f in b])
        other = Path(self.tmp.name) / "other"
        c = ss.custom_scan(self.cfg, PATTERNS, other, self.cfg["paths"])[0]
        self.assertNotEqual(a[0]["fingerprint"], c[0]["fingerprint"])

    def test_max_findings_truncates(self):
        self.cfg["max_findings"] = 2
        findings, errors, _ = ss.custom_scan(self.cfg, PATTERNS, self.root, self.cfg["paths"])
        self.assertEqual(len(findings), 2)
        self.assertTrue(any("max_findings" in e for e in errors))


class Checks(Tree):
    def run_scan(self):
        return ss.do_scan(self.cfg, self.root)

    def test_check_fail_then_pass_after_cleanup(self):
        self.run_scan()
        ok, msg = ss.do_check("private_keys", self.cfg, self.root)
        self.assertFalse(ok)
        self.assertIn("id_rsa", msg)
        (self.scan_dir / "app" / "id_rsa").unlink()
        self.run_scan()
        self.assertTrue(ss.do_check("private_keys", self.cfg, self.root)[0])

    def test_no_results_fails(self):
        ok, msg = ss.do_check("scan_health", self.cfg, self.root)
        self.assertFalse(ok)
        self.assertIn("no scan results", msg)

    def test_scan_health_stale_and_errors(self):
        self.run_scan()
        self.assertTrue(ss.do_check("scan_health", self.cfg, self.root)[0])
        self.assertFalse(ss.do_check("scan_health", dict(self.cfg, stale_hours=-1), self.root)[0])
        f = self.root / "var" / "secrets-scan" / "results.json"
        res = json.loads(f.read_text())
        res["errors"] = ["timeout after 1s: partial results"]
        f.write_text(json.dumps(res))
        ok, msg = ss.do_check("scan_health", self.cfg, self.root)
        self.assertFalse(ok)
        self.assertIn("timeout", msg)


class EngineSelection(unittest.TestCase):
    def cfg(self, **kw):
        return dict(ss.DEFAULT_CONFIG, **kw)

    def test_supported_platform_without_binary_is_unhealthy_not_custom(self):
        with mock.patch.object(ss, "platform_supported", return_value=True), mock.patch.object(ss, "find_trufflehog", return_value=None):
            self.assertEqual(ss.choose_engine(self.cfg(), "/x")[0], "none")

    def test_unsupported_platform_uses_custom(self):
        with mock.patch.object(ss, "platform_supported", return_value=False), mock.patch.object(ss, "find_trufflehog", return_value="/bin/th"):
            engine, _, _, reason = ss.choose_engine(self.cfg(), "/x")
        self.assertEqual(engine, "custom")
        self.assertIn("does not support", reason)

    def test_supported_platform_with_binary_uses_trufflehog(self):
        with mock.patch.object(ss, "platform_supported", return_value=True), mock.patch.object(ss, "find_trufflehog", return_value="/bin/th"), \
                mock.patch.object(ss, "trufflehog_version", return_value="3.97.5"):
            self.assertEqual(ss.choose_engine(self.cfg(), "/x")[0], "trufflehog")

    def test_platform_matrix(self):
        for system, machine, expected in (("Linux", "x86_64", True), ("Linux", "aarch64", True), ("Darwin", "arm64", True),
                                          ("Linux", "i686", False), ("Linux", "armv7l", False), ("Linux", "s390x", False), ("FreeBSD", "amd64", False)):
            with mock.patch("platform.system", return_value=system), mock.patch("platform.machine", return_value=machine):
                self.assertEqual(ss.platform_supported(), expected, (system, machine))


class TruffleHogParsing(unittest.TestCase):
    LINE = json.dumps({"DetectorName": "Postgres", "Verified": False, "Raw": "postgres://u:p@h/db",
                       "SourceMetadata": {"Data": {"Filesystem": {"file": "/srv/app/settings.py", "line": 7}}}})

    def test_parse_filesystem(self):
        f = ss.parse_trufflehog_line(self.LINE, PATTERNS, "/tmp/r")
        self.assertEqual((f["category"], f["file"], f["line"], f["verified"]), ("hardcoded_credentials", "/srv/app/settings.py", 7, False))
        self.assertNotIn("Raw", f)
        self.assertNotIn("postgres://", json.dumps(f))

    def test_parse_git(self):
        line = json.dumps({"DetectorName": "PrivateKey", "Verified": True, "Raw": "k",
                           "SourceMetadata": {"Data": {"Git": {"file": "id", "line": 1, "commit": "0123456789abcdef", "repository": "file:///r"}}}})
        f = ss.parse_trufflehog_line(line, PATTERNS, "/tmp/r", "git", "/r")
        self.assertEqual((f["category"], f["commit"], f["repo"], f["verified"]), ("private_keys", "0123456789ab", "/r", True))

    def test_ignores_log_lines(self):
        self.assertIsNone(ss.parse_trufflehog_line('{"level":"info-0","msg":"x"}', PATTERNS, "/tmp/r"))
        self.assertIsNone(ss.parse_trufflehog_line("not json", PATTERNS, "/tmp/r"))

    def test_categories(self):
        for det, cat in (("AWS", "cloud_credentials"), ("GCP", "cloud_credentials"), ("PrivateKey", "private_keys"), ("URI", "hardcoded_credentials"),
                         ("Github", "service_tokens"), ("Stripe", "service_tokens")):
            self.assertEqual(ss.categorize(det, PATTERNS), cat, det)


if __name__ == "__main__":
    unittest.main()
