# apk-static — Android APK static analysis (permanent Cyber Reviewer feature)

No agent runs on the Android device. The APK is **extracted** (`adb pull`, a build artifact, or a store download)
and placed on a **Linux agent host** (Python 3 required); the agent's SCA module runs static checks on it and the
results appear as a normal SCA policy in *Configuration Assessment*, per agent, with pass/fail, rationale,
remediation and compliance tags (NIS2 21.2.e, ISO 27001 A.8.26/A.8.28, GDPR Art. 32) plus an OWASP MASVS reference.
The static analysis works on manifest + bytecode strings: a *Failed* check is a finding to review, a *Passed* check is
not a proof of security.

## Components
| Path | Purpose |
|---|---|
| `wodles/apk-static/apk_check.py` | stdlib-only scanner (binary AXML parser + dex/resource string scan); one check per call, prints `PASS:`/`FAIL:` |
| `wodles/apk-static/make_policy.py` | generates the SCA policy (default product policy or one per application) |
| `ruleset/sca/applications/android_apk_static.yml` | product policy, 15 checks (ids 60001-60015), APK at `/var/ossec/var/apk-static/app.apk` |
| `src/init/inst-functions.sh` | installs the scanner to `<install>/wodles/apk-static/` and creates `<install>/var/apk-static/` |
| `wodles/apk-static/tests/` | unit tests: `python -m unittest discover -s wodles/apk-static/tests` |

## Checks
debuggable, allowBackup, cleartext traffic, testOnly, exported components / content providers without permission,
targetSdk >= 34, minSdk >= 26, high-risk permissions, signature scheme v2+, hardcoded http:// URLs, hardcoded secrets,
WebView addJavascriptInterface, dynamic code loading / Runtime.exec, weak crypto strings.

## Enabling it on an agent
1. Put the APK at `/var/ossec/var/apk-static/app.apk` (or generate a policy for another path/name, see below).
2. Copy `android_apk_static.yml` to `<agent>/ruleset/sca/` and add to the agent `ossec.conf`:
   ```xml
   <sca>
     <policies><policy>ruleset/sca/android_apk_static.yml</policy></policies>
   </sca>
   ```
3. Restart the agent; the results show up in Configuration Assessment for that agent (agent group = customer, see
   `api/tools/env/tenants/README.md` for per-customer isolation).

Several apps on one host: `python wodles/apk-static/make_policy.py --apk /var/ossec/var/apk-static/myapp.apk --id android_apk_myapp --name MyApp`
generates `android_apk_myapp.yml` in the current directory.

## Limits
Linux agents only (needs `python3`). Heuristics, no decompilation, no dynamic analysis, no native-library analysis.
Keep the APK current: the SCA scan reflects the file on disk, not what is installed on devices.
