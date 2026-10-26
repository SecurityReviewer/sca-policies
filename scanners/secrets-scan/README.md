# Secrets detection (TruffleHog + custom scanner), reported as SCA

Finds secrets left in files and git history on the monitored hosts and reports them in *Configuration Assessment* as
normal SCA checks (Passed / Failed per category, per agent, with the usual compliance mapping).

| Category (SCA check) | What it covers |
|---|---|
| `private_keys` | PEM / OpenSSH / PGP private keys |
| `cloud_credentials` | AWS, Google Cloud, Azure and other cloud provider credentials |
| `service_tokens` | API tokens of third-party services (GitHub, GitLab, Slack, Stripe, npm, ...) |
| `hardcoded_credentials` | connection strings with passwords, `password=` literals in configuration files, scripts and `.env` |
| `scan_health` | the scan is scheduled, has an engine, finished without errors within the time budget and is recent |

## Engines: TruffleHog first, custom scanner only where TruffleHog does not run

| Host | Engine |
|---|---|
| Linux / macOS, x86_64 or arm64 | **TruffleHog** (`filesystem` + `git` history of the repositories found under the scanned paths) |
| Windows 10 / Server 2016 or later, 64-bit | **TruffleHog** (`secrets_scan.ps1`) |
| Anything else (Windows 7/8, Server 2008 R2 / 2012 R2, 32-bit Windows, other CPU architectures) | **custom scanner** (`patterns.json`, regex + placeholder filter; no git history) |

A host where TruffleHog *is* supported but the binary is missing is **not** silently downgraded to the custom scanner:
`scan_health` fails with "binary was not found", so the gap is visible. `"engine": "custom"` forces the custom scanner.

**TruffleHog is not bundled** (AGPL-3.0, separate program invoked as a command). Install the release binary
(https://github.com/trufflesecurity/trufflehog/releases, verify the published checksums) as
`<install>/wodles/secrets-scan/bin/trufflehog` (Windows: `bin\trufflehog.exe`), or anywhere on `PATH`, or set `trufflehog_path`.

Scope of each engine: TruffleHog recognises secrets by known formats (~800 detectors), private keys and URIs with credentials.
It deliberately does **not** flag generic `password = ...` literals; that gap is covered only by the custom scanner's
`credential-literal` pattern, i.e. on hosts where the custom engine runs. Use `"engine": "custom"` in addition if that is needed
(a second scan with the custom engine is not run automatically).

## What is stored and what leaves the host

* **Verification is off.** TruffleHog verification sends candidate secrets to the provider's API to check they are live; it is
  disabled (`--no-verification`) unless `"verify": true` is set. With it on, a `VERIFIED live` finding is reported.
* `results.json` (`<install>/var/secrets-scan/`) contains **no secret values**: file, line, detector, category, verified flag and a
  salted 12-hex fingerprint (salt in `.salt`, host-specific) to recognise the same finding across scans.
* The SCA result carries only the check outcome and a short message (count, first three file names). Full detail is on the host:
  `python3 secrets_scan.py report` / `powershell -File secrets_scan.ps1 report`.

## Files

| File | Role |
|---|---|
| `secrets_scan.py` | Linux/macOS scanner. Actions: `scan`, `check <name>`, `report`, `status` |
| `secrets_scan.ps1` | Windows scanner (Windows PowerShell 2.0 and later, not PowerShell 7). Same actions |
| `patterns.json` | custom-engine patterns, placeholder filter, exclusions, and the TruffleHog-detector → category map (shared by both scanners) |
| `secrets_scan.conf.json` | optional configuration next to the script (or `SECRETS_SCAN_CONFIG`) |
| `tests/test_secrets_scan.py` | `python -m unittest discover -s wodles/secrets-scan/tests` |
| `ruleset/sca/applications/secrets_scan_unix.yml` | policy `secrets_scan_unix`, checks 62001-62005 |
| `ruleset/sca/applications/secrets_scan_windows.yml` | policy `secrets_scan_windows`, checks 62101-62105 |

Configuration keys (all optional): `engine` (`auto`/`trufflehog`/`custom`), `paths`, `exclude_regex`, `trufflehog_path`, `git_history`,
`max_repos` (20), `verify` (false), `timeout_s` (3600), `max_findings` (2000), `max_file_kb` (1024, custom engine), `stale_hours` (72).
Default paths: Linux `/root /home /opt /srv /var/www /etc /usr/local/etc`; Windows `C:\Users C:\inetpub C:\xampp C:\wamp C:\ProgramData C:\Apps C:\Data`.

## Deployment

1. Linux: `src/init/inst-functions.sh` installs the scanner under `<install>/wodles/secrets-scan/`. Windows: the MSI installs
   `secrets_scan.ps1`, `patterns.json` and `secrets_scan_windows.yml` there. Add the TruffleHog binary (see above).
2. **Opt-in.** The policy is deliberately not placed in `ruleset/sca/` (the SCA module loads every policy found there): without a
   scheduled scan it would report Failed on every host. Enable it per host in `ossec.conf` (Linux: copy `secrets_scan_unix.yml`
   into `wodles/secrets-scan/` first):

```xml
<sca>
  <policies><policy>wodles/secrets-scan/secrets_scan_unix.yml</policy></policies>   <!-- Windows: secrets_scan_windows.yml -->
</sca>
```

   To switch it off again, remove the `<policy>` line **and** the file if you had copied it into `ruleset/sca/`.

3. Schedule the scan (a full scan can take minutes; the SCA checks only read the last result). Linux:

```xml
<wodle name="command">
  <disabled>no</disabled>
  <tag>secrets-scan</tag>
  <command>python3 /var/ossec/wodles/secrets-scan/secrets_scan.py scan</command>
  <interval>1d</interval>
  <run_on_start>yes</run_on_start>
  <timeout>3700</timeout>
</wodle>
```

Windows: `<command>powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files (x86)\ossec-agent\wodles\secrets-scan\secrets_scan.ps1" scan</command>`.
Keep `interval` (scan) shorter than the SCA `interval` (check), and `stale_hours` above the scan interval.

**First run:** the SCA scan on agent start and the first secrets scan (`run_on_start`) run at the same time, and a full scan takes
minutes, so the first SCA cycle reports all five checks as Failed ("no scan results yet"). Real results appear at the next SCA
cycle (`<interval>` of the `<sca>` block, 12 h by default) or after restarting the agent once `results.json` exists.

## Where each finding is (file, line): one event per finding

After every scan the scanner appends one JSON line per finding to `<install>/var/secrets-scan/findings.jsonl` (no secret values:
category, detector, file, line, fingerprint, scan time; plus repo and commit for git history). The agent's logcollector sends the
file and the Cyber Reviewer engine turns each line into an event (integration `secrets-scan`, index `wazuh-events-v5-security`).
Two things are needed:

1. **Once per indexer**: `python api/tools/env/wazuh-indexer/create-secrets-decoder.py` creates the custom integration with its
   decoders and promotes them draft → test → custom (rerun it after wiping the indexer volume; `--test` runs a logtest without
   promoting). It also gives the custom space policy a root decoder of its own, restricted to these events, so no other event is
   decoded twice.
2. **On every agent** that runs the scan, next to the `<wodle name="command">` block:

```xml
<localfile>
  <log_format>json</log_format>
  <location>C:\Program Files (x86)\ossec-agent\var\secrets-scan\findings.jsonl</location>   <!-- Linux: /var/ossec/var/secrets-scan/findings.jsonl -->
</localfile>
```

Every scan appends all its findings again (the file is truncated when it grows past 2 MB), so the events show the state at each scan
time; `event.start` holds the scan time. Events are searchable with `tags:secrets-scan` and carry `file.path`,
`log.origin.file.line`, `rule.category`, `rule.name`, `event.hash` (fingerprint) and, for git history, `file.directory` (repository)
and `event.reason` (commit).

## Dashboard

Configuration Assessment has two extra tabs (next to Dashboard / Inventory / Findings), added by
`api/tools/env/wazuh-dashboard/secrets-tab.js` at dashboard image build time:

* **Secrets** opens the Inventory filtered on both policies (`policy.id:(secrets_scan_unix or secrets_scan_windows)`): the five
  checks per host, Passed/Failed.
* **Secret files** opens Discover on `tags:secrets-scan` (last 7 days) with the columns agent, `file.path`, line, category, detector:
  the file of every finding.

## Remediation reminder

A finding means the secret must be considered compromised: rotate/revoke it first, then remove it from the file **and from git
history**. Deleting the file alone does not make the check pass for repositories: the secret stays in the history.
