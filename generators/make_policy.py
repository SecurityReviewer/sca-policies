#!/usr/bin/env python3
"""
Generates an SCA policy for the Android APK static analysis (wodle `apk-static`).

Default (product policy):   python make_policy.py
  -> ruleset/sca/applications/android_apk_static.yml, APK expected at /var/ossec/var/apk-static/app.apk
Per application:            python make_policy.py --apk /var/ossec/var/apk-static/myapp.apk --id android_apk_myapp --name "MyApp"
  -> ./android_apk_myapp.yml (copy it to <agent>/ruleset/sca/ and reference it in <sca><policies>)
"""
from pathlib import Path

import argparse

_ap = argparse.ArgumentParser(description="Generate the Android APK static analysis SCA policy")
_ap.add_argument("--apk", default="/var/ossec/var/apk-static/app.apk", help="path of the APK on the agent host")
_ap.add_argument("--id", default="android_apk_static", help="policy id (also the file name)")
_ap.add_argument("--name", default="", help="application name shown in the policy title")
_args = _ap.parse_args()

SCRIPT = "/var/ossec/wodles/apk-static/apk_check.py"
APK = _args.apk
POLICY_ID = _args.id
SUFFIX = f" - {_args.name}" if _args.name else ""

# (id, check, title, description, rationale, remediation, masvs)
CHECKS = [
    (60001, "debuggable", "Ensure the application is not debuggable",
     "android:debuggable must not be true in a release build.",
     "A debuggable app lets anyone attach a debugger, read memory and bypass client-side controls.",
     "Remove android:debuggable or set it to false for release builds.", "MASVS-RESILIENCE-2"),
    (60002, "allow_backup", "Ensure application data backup is disabled",
     "android:allowBackup should be false (default is true when unset).",
     "Backups expose app data (tokens, databases) through adb backup / cloud backup.",
     "Set android:allowBackup=\"false\" or restrict with fullBackupContent/dataExtractionRules.", "MASVS-STORAGE-1"),
    (60003, "cleartext_traffic", "Ensure cleartext (HTTP) traffic is not permitted",
     "android:usesCleartextTraffic must not be true.",
     "Cleartext traffic can be intercepted or modified by a network attacker.",
     "Set usesCleartextTraffic=\"false\" and use a network security config that enforces TLS.", "MASVS-NETWORK-1"),
    (60004, "test_only", "Ensure the application is not flagged testOnly",
     "android:testOnly must not be set in release builds.",
     "testOnly builds are intended for development and may bypass release protections.",
     "Rebuild without android:testOnly.", "MASVS-CODE-1"),
    (60005, "exported_components", "Ensure no activity, service or receiver is exported without a permission",
     "Components with an intent-filter (or exported=true) and no android:permission can be invoked by any app.",
     "Unprotected exported components allow intent injection, data exfiltration and privilege abuse by other apps.",
     "Set android:exported=\"false\" or protect the component with a signature-level permission.", "MASVS-PLATFORM-1"),
    (60006, "exported_providers", "Ensure no content provider is exported without a permission",
     "Exported content providers without read/write permission expose their data to every app.",
     "Unprotected providers allow reading and modifying app data and SQL injection through URIs.",
     "Set android:exported=\"false\" or define readPermission/writePermission (signature level).", "MASVS-PLATFORM-1"),
    (60007, "target_sdk", "Ensure targetSdkVersion is current (>= 34)",
     "targetSdkVersion should target a recent Android release.",
     "Apps targeting old API levels run with legacy, weaker security behaviours.",
     "Raise targetSdkVersion to 34 or higher and retest.", "MASVS-CODE-3"),
    (60008, "min_sdk", "Ensure minSdkVersion is not obsolete (>= 26)",
     "minSdkVersion below 26 keeps support for Android versions without current platform protections.",
     "Old Android versions lack fixes and hardening the app cannot compensate for.",
     "Raise minSdkVersion to 26 or higher where business allows.", "MASVS-CODE-3"),
    (60009, "dangerous_permissions", "Ensure no high-risk permissions are requested unnecessarily",
     "Permissions such as SMS, contacts, call log, storage, overlay or install-packages give broad access to user data.",
     "Excess permissions increase impact if the app is abused or compromised and raise privacy (GDPR) exposure.",
     "Remove permissions that are not strictly required; document the justification for those kept.", "MASVS-PRIVACY-1"),
    (60010, "signature_scheme", "Ensure the APK is signed with signature scheme v2 or later",
     "APKs signed only with the v1 (JAR) scheme are vulnerable to tampering (e.g. Janus, CVE-2017-13156).",
     "A weak signature scheme allows modified code to keep a valid signature.",
     "Sign with apksigner using v2/v3/v4 schemes.", "MASVS-RESILIENCE-1"),
    (60011, "http_urls", "Ensure no cleartext http:// URLs are hardcoded",
     "Hardcoded http:// endpoints in code or resources.",
     "Cleartext endpoints leak data and credentials and are trivially intercepted.",
     "Replace with https:// endpoints and remove unused URLs.", "MASVS-NETWORK-1"),
    (60012, "hardcoded_secrets", "Ensure no secrets are hardcoded in code or resources",
     "Heuristic scan for access keys, private keys and credential-like literals.",
     "Secrets embedded in an APK are trivially extracted by decompiling it.",
     "Move secrets to a backend or the Android Keystore; rotate any exposed credential.", "MASVS-STORAGE-2"),
    (60013, "js_interface", "Ensure WebView JavaScript interfaces are not used",
     "WebView.addJavascriptInterface exposes native methods to web content.",
     "Injected or malicious web content can call native code.",
     "Avoid addJavascriptInterface; if required, restrict to trusted origins and annotate with @JavascriptInterface.", "MASVS-PLATFORM-2"),
    (60014, "dynamic_code", "Ensure no dynamic code loading or command execution is used",
     "DexClassLoader / Runtime.exec references.",
     "Loading code at runtime or executing commands can bypass review and enable code injection.",
     "Remove dynamic loading and process execution, or verify the integrity of any loaded code.", "MASVS-CODE-4"),
    (60015, "weak_crypto", "Ensure weak cryptographic algorithms are not referenced",
     "DES, 3DES, ECB mode, MD5 or SHA-1 strings in code.",
     "Weak algorithms do not provide adequate confidentiality or integrity.",
     "Use AES-GCM, SHA-256 or stronger, and keys from the Android Keystore.", "MASVS-CRYPTO-1"),
]

HEAD = f'''# Security Configuration Assessment
# Static security analysis of an Android APK (Cyber Reviewer)
#
# No agent runs on the device: the APK is extracted (adb pull, build artifact or store download) and
# stored on an agent host at {APK}. This policy runs {SCRIPT}
# (stdlib-only static checks, see apk_check.py) and reports each check as Passed/Failed.
# Findings are heuristics on manifest/bytecode strings, referenced to OWASP MASVS.

policy:
  id: "{POLICY_ID}"
  file: "{POLICY_ID}.yml"
  name: "Android APK static security analysis (OWASP MASVS){SUFFIX}"
  description: "Static checks on an Android APK: manifest hardening, exported components, permissions, signing, hardcoded secrets and risky APIs."
  references:
    - https://mas.owasp.org/MASVS/
    - https://developer.android.com/topic/security/best-practices

requirements:
  name: "Check that the APK to analyse is present"
  description: "The APK is expected at {APK}."
  condition: all
  rules:
    - 'f:{APK}'

checks:
'''


def q(text):
    """escape for a YAML double-quoted scalar"""
    return text.replace("\\", "\\\\").replace('"', '\\"')


def block(cid, check, title, desc, rat, rem, masvs):
    title, desc, rat, rem = q(title), q(desc), q(rat), q(rem)
    return f'''  - id: {cid}
    name: "{title}"
    description: "{desc}"
    rationale: "{rat}"
    remediation: "{rem}"
    compliance:
      gdpr: ["IV_32.1.b"]
      iso_27001: ["A.8.28", "A.8.26"]
      nis2: ["21.2.e"]
    references:
      - https://mas.owasp.org/MASVS/
      - "OWASP {masvs}"
    condition: all
    rules:
      - 'c:python3 {SCRIPT} {check} {APK} -> r:^PASS'
'''


if _args.id == "android_apk_static" and not _args.name:
    out = Path(__file__).resolve().parents[2] / "ruleset" / "sca" / "applications" / "android_apk_static.yml"
else:
    out = Path.cwd() / f"{POLICY_ID}.yml"
out.write_text(HEAD + "\n".join(block(*c) for c in CHECKS), encoding="utf-8", newline="\n")
print("written", out)
