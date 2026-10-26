#!/usr/bin/env python3
"""secrets_scan.py — secrets detection for Cyber Reviewer agents (Linux / macOS), reported as SCA checks.

Engine selection (per host):
  * TruffleHog (https://github.com/trufflesecurity/trufflehog) when the platform is supported (Linux/macOS, x86_64/arm64).
    Verification (which sends candidate secrets to third-party APIs) is OFF unless "verify" is set in the configuration.
  * The built-in CUSTOM scanner (patterns.json) ONLY when TruffleHog does not support the platform (other architectures);
    a supported host without the TruffleHog binary is reported as unhealthy, it is not silently scanned by the custom engine.
  Windows agents use secrets_scan.ps1 (same results file, same checks).

Actions:
  scan            run a scan and write <root>/var/secrets-scan/results.json (raw secret values are NEVER stored)
  check <name>    print PASS:/FAIL: for one SCA check: private_keys | cloud_credentials | service_tokens |
                  hardcoded_credentials | scan_health
  report          print the findings of the last scan
  status          print engine selection and the state of the last scan

Configuration (optional): secrets_scan.conf.json next to this script, see README.md.
"""
import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
CHECKS = ("private_keys", "cloud_credentials", "service_tokens", "hardcoded_credentials", "scan_health")
SUPPORTED = {("Linux", "x86_64"), ("Linux", "amd64"), ("Linux", "aarch64"), ("Linux", "arm64"),
             ("Darwin", "x86_64"), ("Darwin", "amd64"), ("Darwin", "arm64")}

DEFAULT_CONFIG = {
    "engine": "auto",               # auto | trufflehog | custom
    "paths": ["/root", "/home", "/opt", "/srv", "/var/www", "/etc", "/usr/local/etc"],
    "exclude_regex": [
        r"^/etc/ssh/ssh_host_", r"^/etc/ssl/private/ssl-cert-snakeoil\.key$", r"^/etc/(ssl|pki|ca-certificates)/certs/",
        r"/node_modules/", r"/\.git/", r"/\.cache/", r"/site-packages/", r"/dist-packages/", r"^/var/ossec/",
    ],
    "trufflehog_path": "",
    "git_history": True,            # also scan the history of git repositories found under "paths"
    "max_repos": 20,
    "verify": False,                # TruffleHog live verification calls third-party APIs with the candidate secrets: keep off
    "timeout_s": 3600,
    "max_findings": 2000,
    "max_file_kb": 1024,            # custom engine
    "stale_hours": 72,
}


# ----------------------------------------------------------------------------------------------- configuration
def get_root():
    env = os.environ.get("SECRETS_SCAN_ROOT")
    if env:
        return Path(env)
    return HERE.parents[1] if HERE.parent.name == "wodles" else HERE


def load_config(path=None):
    cfg = dict(DEFAULT_CONFIG)
    p = Path(path or os.environ.get("SECRETS_SCAN_CONFIG") or HERE / "secrets_scan.conf.json")
    if p.exists():
        cfg.update(json.loads(p.read_text(encoding="utf-8")))
    return cfg


def load_patterns():
    return json.loads((HERE / "patterns.json").read_text(encoding="utf-8"))


def state_dir(root):
    d = Path(root) / "var" / "secrets-scan"
    d.mkdir(parents=True, exist_ok=True)
    return d


def salt(root):
    f = state_dir(root) / ".salt"
    if not f.exists():
        f.write_bytes(os.urandom(16))
        try:
            f.chmod(0o600)
        except OSError:
            pass
    return f.read_bytes()


def fingerprint(root, *parts):
    """Salted, truncated hash used only to tell findings apart; the secret itself is never stored."""
    h = hashlib.sha256(salt(root))
    for p in parts:
        h.update(str(p).encode("utf-8", "replace") + b"\0")
    return h.hexdigest()[:12]


# ----------------------------------------------------------------------------------------------- engine selection
def platform_supported():
    return (platform.system(), platform.machine().lower()) in SUPPORTED


def find_trufflehog(cfg, root):
    cands = []
    if cfg.get("trufflehog_path"):
        cands.append(cfg["trufflehog_path"])
    cands += [str(Path(root) / "wodles" / "secrets-scan" / "bin" / "trufflehog"), shutil.which("trufflehog") or "",
              "/usr/local/bin/trufflehog", "/usr/bin/trufflehog", "/opt/homebrew/bin/trufflehog"]
    for c in cands:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


def trufflehog_version(binary):
    try:
        out = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=30)
        return (out.stdout + out.stderr).strip().split()[-1]
    except Exception:
        return None


def choose_engine(cfg, root):
    """-> (engine, binary, version, reason). engine: trufflehog | custom | none."""
    want = cfg.get("engine", "auto")
    if want == "custom":
        return "custom", None, None, "engine forced to custom by configuration"
    binary = find_trufflehog(cfg, root)
    if want == "trufflehog" or platform_supported():
        if not binary:
            return "none", None, None, "TruffleHog is supported on this platform but the binary was not found"
        ver = trufflehog_version(binary)
        if not ver:
            return "none", binary, None, "TruffleHog binary found but it does not run"
        return "trufflehog", binary, ver, "TruffleHog supported on this platform"
    return "custom", None, None, f"TruffleHog does not support {platform.system()}/{platform.machine()}: using the custom scanner"


# ----------------------------------------------------------------------------------------------- helpers
def categorize(detector, patterns):
    for rx, cat in patterns["detector_categories"]:
        if re.search(rx, detector or ""):
            return cat
    return patterns["default_category"]


def excluded(path, regexes):
    return any(r.search(path) for r in regexes)


def compile_excludes(cfg):
    return [re.compile(r) for r in cfg.get("exclude_regex", [])]


def is_placeholder(value, patterns):
    p = patterns["placeholders"]
    v = value.strip().strip("\"'").lower()
    return (not v or v in p["literals"] or any(v.startswith(x) for x in p["prefixes"]) or re.match(p["regex"], v) is not None)


def existing(paths):
    return [p for p in paths if os.path.exists(p)]


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ----------------------------------------------------------------------------------------------- TruffleHog engine
def parse_trufflehog_line(line, patterns, root, source="filesystem", repo=None):
    """One JSON line of TruffleHog -> finding dict (without the raw secret), or None."""
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        d = json.loads(line)
    except ValueError:
        return None
    if "DetectorName" not in d:
        return None
    data = (d.get("SourceMetadata") or {}).get("Data") or {}
    meta = data.get("Filesystem") or data.get("Git") or {}
    detector = d.get("DetectorName", "")
    raw = d.get("Raw") or d.get("RawV2") or ""
    f = {"engine": "trufflehog", "source": source, "detector": detector, "category": categorize(detector, patterns),
         "file": meta.get("file", ""), "line": meta.get("line", 0), "verified": bool(d.get("Verified")),
         "fingerprint": fingerprint(root, detector, raw)}
    if source == "git":
        f["repo"] = repo or meta.get("repository", "")
        f["commit"] = (meta.get("commit") or "")[:12]
    return f


def run_trufflehog(binary, cfg, patterns, root, paths):
    findings, errors = [], []
    excl = compile_excludes(cfg)
    deadline = time.monotonic() + cfg["timeout_s"]
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as xf:
        xf.write("\n".join(cfg.get("exclude_regex", [])) + "\n")
        xf_path = xf.name
    common = ["--json", "--no-update", "--log-level=-1", "--exclude-paths", xf_path]
    if not cfg.get("verify"):
        common.append("--no-verification")

    def run(args, source, repo=None):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            errors.append("timeout: scan time budget exhausted before running " + " ".join(args[:2]))
            return
        errf = tempfile.TemporaryFile()
        proc = subprocess.Popen([binary] + args, stdout=subprocess.PIPE, stderr=errf, text=True, errors="replace")
        timer_expired = False
        try:
            for line in proc.stdout:
                f = parse_trufflehog_line(line, patterns, root, source, repo)
                if f and len(findings) < cfg["max_findings"] and not (f["file"] and source == "filesystem" and excluded(f["file"], excl)):
                    findings.append(f)
                if time.monotonic() > deadline:
                    timer_expired = True
                    proc.kill()
                    break
        finally:
            proc.wait()
        if timer_expired:
            errors.append(f"timeout after {cfg['timeout_s']}s: partial results")
        elif proc.returncode not in (0, None):
            errf.seek(0)
            tail = errf.read().decode("utf-8", "replace").strip().splitlines()[-2:]
            errors.append(f"trufflehog {args[0]} exited with {proc.returncode}: " + " | ".join(tail)[:300])
        errf.close()

    try:
        targets = existing(paths)
        if targets:
            run(["filesystem"] + common + targets, "filesystem")
        if cfg.get("git_history"):
            for repo in discover_repos(targets, cfg.get("max_repos", 20)):
                run(["git", "file://" + repo] + common, "git", repo)
    finally:
        os.unlink(xf_path)
    return findings, errors


def discover_repos(paths, max_repos, max_depth=4):
    repos = []
    for base in paths:
        base_depth = base.rstrip(os.sep).count(os.sep)
        for dirpath, dirnames, _ in os.walk(base):
            if dirpath.count(os.sep) - base_depth >= max_depth:
                dirnames[:] = []
            if ".git" in dirnames:
                repos.append(dirpath)
                dirnames[:] = [d for d in dirnames if d != ".git"]
                if len(repos) >= max_repos:
                    return repos
            dirnames[:] = [d for d in dirnames if d not in ("node_modules", "proc", "sys", "dev")]
    return repos


# ----------------------------------------------------------------------------------------------- custom engine
def custom_scan(cfg, patterns, root, paths):
    """Regex scanner for platforms TruffleHog does not support. Returns (findings, errors, files_scanned)."""
    findings, errors, seen, scanned = [], [], set(), 0
    excl = compile_excludes(cfg)
    skip_dirs = set(patterns["exclude_dir_names"])
    skip_ext = set(patterns["exclude_extensions"])
    pats = [dict(p, rx=re.compile(p["regex"])) for p in patterns["patterns"]]
    max_bytes = cfg["max_file_kb"] * 1024
    deadline = time.monotonic() + cfg["timeout_s"]
    for base in existing(paths):
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            dirnames[:] = [d for d in dirnames if d not in skip_dirs and not excluded(os.path.join(dirpath, d) + "/", excl)]
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                ext = os.path.splitext(fn)[1].lower()
                if ext in skip_ext or os.path.islink(full) or excluded(full, excl):
                    continue
                if time.monotonic() > deadline:
                    errors.append(f"timeout after {cfg['timeout_s']}s: partial results")
                    return findings, errors, scanned
                try:
                    if os.path.getsize(full) > max_bytes:
                        continue
                    with open(full, "rb") as fh:
                        blob = fh.read()
                except OSError:
                    continue
                if b"\0" in blob[:4096]:
                    continue
                scanned += 1
                text = blob.decode("utf-8", "replace")
                for lineno, line in enumerate(text.splitlines(), 1):
                    if len(line) > 5000:
                        continue
                    for p in pats:
                        exts, prefixes = p.get("file_extensions"), p.get("file_name_prefixes")
                        if exts and ext not in exts and not any(fn.startswith(x) for x in (prefixes or [])):
                            continue
                        m = p["rx"].search(line)
                        if not m:
                            continue
                        value = m.group(p["value_group"]) if p.get("value_group") else m.group(0)
                        if p.get("value_group") and is_placeholder(value, patterns):
                            continue
                        key = (full, lineno, p["id"])
                        if key in seen:
                            continue
                        seen.add(key)
                        if len(findings) >= cfg["max_findings"]:
                            errors.append("max_findings reached: results truncated")
                            return findings, errors, scanned
                        findings.append({"engine": "custom", "source": "filesystem", "detector": p["label"], "category": p["category"],
                                         "file": full, "line": lineno, "verified": False,
                                         "fingerprint": fingerprint(root, p["id"], full, lineno if not p.get("value_group") else value)})
    return findings, errors, scanned


# ----------------------------------------------------------------------------------------------- actions
def do_scan(cfg, root):
    patterns = load_patterns()
    started = time.monotonic()
    engine, binary, version, reason = choose_engine(cfg, root)
    res = {"schema": 1, "host": socket.gethostname(), "platform": f"{platform.system()}/{platform.machine()}", "engine": engine,
           "engine_version": version, "engine_reason": reason, "verify": bool(cfg.get("verify")) and engine == "trufflehog",
           "started": now_iso(), "paths": existing(cfg["paths"]), "errors": [], "findings": [], "truncated": False, "files_scanned": None}
    if engine == "trufflehog":
        res["findings"], res["errors"] = run_trufflehog(binary, cfg, patterns, root, cfg["paths"])
    elif engine == "custom":
        res["findings"], res["errors"], res["files_scanned"] = custom_scan(cfg, patterns, root, cfg["paths"])
    else:
        res["errors"].append(reason)
    res["truncated"] = len(res["findings"]) >= cfg["max_findings"]
    res["finished"] = now_iso()
    res["duration_s"] = round(time.monotonic() - started, 1)
    out = state_dir(root) / "results.json"
    tmp = out.with_suffix(".tmp")
    tmp.write_text(json.dumps(res, indent=1), encoding="utf-8")
    os.replace(tmp, out)
    write_findings_log(res, root)
    return res


FINDINGS_LOG = "findings.jsonl"
FINDINGS_LOG_MAX_BYTES = 2 * 1024 * 1024


def write_findings_log(res, root):
    """Append one JSON line per finding to findings.jsonl, for the agent's logcollector (`log_format json`): each line becomes
    an event in the indexer (integration secrets-scan), so file/line/detector can be searched in the dashboard. No secret values."""
    f = state_dir(root) / FINDINGS_LOG
    mode = "w" if f.exists() and f.stat().st_size > FINDINGS_LOG_MAX_BYTES else "a"   # cheap rotation: everything old was read long ago
    with open(f, mode, encoding="utf-8", newline="\n") as fh:
        for x in res["findings"]:
            line = {"module": "secrets-scan", "scan_id": res["finished"], "host": res["host"], "engine": x["engine"], "category": x["category"],
                    "detector": x["detector"], "path": x["file"], "line": x["line"], "verified": x["verified"], "fingerprint": x["fingerprint"]}
            if x.get("repo"):
                line["repo"], line["commit"] = x["repo"], x.get("commit", "")
            fh.write(json.dumps(line, ensure_ascii=False) + "\n")


def load_results(root):
    f = state_dir(root) / "results.json"
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except ValueError:
        return None


def age_hours(res):
    fin = datetime.strptime(res["finished"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - fin).total_seconds() / 3600


def do_check(name, cfg, root):
    """Return (ok, message) for an SCA check."""
    res = load_results(root)
    if res is None:
        return False, "no scan results yet (run: secrets_scan.py scan)"
    if name == "scan_health":
        problems = list(res.get("errors", []))
        if res["engine"] == "none" and res["engine_reason"] not in problems:
            problems.append(res["engine_reason"])
        if res.get("truncated"):
            problems.append("results truncated at max_findings")
        h = age_hours(res)
        if h > cfg["stale_hours"]:
            problems.append(f"last scan finished {h:.0f}h ago (limit {cfg['stale_hours']}h)")
        if problems:
            return False, "; ".join(problems)[:400]
        return True, f"engine={res['engine']} {res.get('engine_version') or ''}".strip() + f", finished {h:.1f}h ago, {len(res['paths'])} path(s)"
    hits = [f for f in res["findings"] if f["category"] == name]
    if not hits:
        return True, f"no {name.replace('_', ' ')} found (engine={res['engine']}, finished {res['finished']})"
    files = sorted({(f.get("repo") or "") + ("@" + f["commit"] + ":" if f.get("commit") else "") + f["file"] for f in hits})
    verified = sum(1 for f in hits if f["verified"])
    return False, (f"{len(hits)} finding(s) in {len(files)} file(s)" + (f", {verified} VERIFIED live" if verified else "") +
                   "; e.g. " + ", ".join(files[:3]) + " (details: secrets_scan.py report)")


def do_report(res):
    if not res:
        return "no scan results"
    lines = [f"engine={res['engine']} {res.get('engine_version') or ''} ({res['engine_reason']}); finished {res['finished']}; "
             f"{len(res['findings'])} finding(s); errors={res['errors'] or 'none'}"]
    for f in sorted(res["findings"], key=lambda x: (x["category"], x["file"], x["line"])):
        loc = f"{f['file']}:{f['line']}" + (f" (repo {f['repo']} commit {f['commit']})" if f.get("repo") else "")
        lines.append(f"{f['category']:<22} {f['detector']:<34} {'VERIFIED ' if f['verified'] else ''}{loc}  [{f['fingerprint']}]")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("action", choices=["scan", "check", "report", "status"])
    ap.add_argument("name", nargs="?", choices=CHECKS)
    ap.add_argument("--config")
    ap.add_argument("--root")
    a = ap.parse_args(argv)
    if a.root:
        os.environ["SECRETS_SCAN_ROOT"] = a.root
    root, cfg = get_root(), load_config(a.config)
    if a.action == "scan":
        res = do_scan(cfg, root)
        print(f"secrets_scan: engine={res['engine']} findings={len(res['findings'])} errors={len(res['errors'])} duration={res['duration_s']}s")
        return 0
    if a.action == "check":
        if not a.name:
            ap.error("check needs a name")
        ok, msg = do_check(a.name, cfg, root)
        print(("PASS: " if ok else "FAIL: ") + msg)
        return 0
    if a.action == "report":
        print(do_report(load_results(root)))
        return 0
    engine, binary, version, reason = choose_engine(cfg, root)
    print(json.dumps({"engine": engine, "binary": binary, "version": version, "reason": reason, "platform_supported": platform_supported(),
                      "results": bool(load_results(root))}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
