#!/usr/bin/env python3
"""
Static security checks for an Android APK, used by the SCA policy `android_apk_static.yml`.

Stdlib only (zipfile/struct/re): parses the binary AndroidManifest.xml (AXML) and scans classes*.dex /
resources for well known risky patterns. Prints ONE line per invocation, `PASS: ...` or `FAIL: ...`,
which the SCA rule matches with `-> r:^PASS`. Exit code is always 0 (an unreadable APK prints `ERROR:`).

Usage: apk_check.py <check> <path-to.apk>
Checks: debuggable allow_backup cleartext_traffic test_only exported_components exported_providers
        target_sdk min_sdk dangerous_permissions signature_scheme http_urls hardcoded_secrets
        js_interface dynamic_code weak_crypto
These are heuristics on bytecode/strings (no decompilation): a FAIL is a finding to review, a PASS is not a proof.
"""
import re
import struct
import sys
import zipfile

ANDROID_NS = "http://schemas.android.com/apk/res/android"


# ---------------------------------------------------------------- AXML parser
def parse_axml(data: bytes):
    """Returns a list of (tag, {attr: value}) for every start element, in document order."""
    def u16(o): return struct.unpack_from("<H", data, o)[0]
    def u32(o): return struct.unpack_from("<I", data, o)[0]

    assert u16(0) == 0x0003, "not a binary XML"
    off = u16(2)  # header size of the file chunk
    strings, elements = [], []
    while off < len(data):
        ctype, hsize, csize = u16(off), u16(off + 2), u32(off + 4)
        if ctype == 0x0001:  # string pool
            count, _styles, flags, s_start = u32(off + 8), u32(off + 12), u32(off + 16), u32(off + 20)
            utf8 = bool(flags & (1 << 8))
            offsets = [u32(off + hsize + 4 * i) for i in range(count)]
            base = off + s_start
            for so in offsets:
                p = base + so
                if utf8:
                    l = data[p]; p += 1 if not (l & 0x80) else 2
                    l2 = data[p]; p += 1
                    if l2 & 0x80:
                        l2 = ((l2 & 0x7F) << 8) | data[p]; p += 1
                    strings.append(data[p:p + l2].decode("utf-8", "replace"))
                else:
                    l = u16(p); p += 2
                    if l & 0x8000:
                        l = ((l & 0x7FFF) << 16) | u16(p); p += 2
                    strings.append(data[p:p + 2 * l].decode("utf-16le", "replace"))
        elif ctype == 0x0102:  # start element
            ns_i, name_i = struct.unpack_from("<ii", data, off + 16)  # after line/comment header
            attr_start, attr_size, attr_count = struct.unpack_from("<HHH", data, off + 24)
            a_off = off + 16 + attr_start
            attrs = {}
            for i in range(attr_count):
                ao = a_off + i * attr_size
                a_ns, a_name, a_raw = struct.unpack_from("<iii", data, ao)
                _sz, _res, dtype, ddata = struct.unpack_from("<HBBI", data, ao + 12)
                name = strings[a_name] if a_name >= 0 else ""
                if dtype == 0x12:            # boolean
                    val = ddata != 0
                elif dtype == 0x03:          # string
                    val = strings[ddata]
                elif dtype in (0x10, 0x11):  # int / hex
                    val = ddata
                elif a_raw >= 0:
                    val = strings[a_raw]
                else:
                    val = ddata
                attrs[name] = val
            elements.append((strings[name_i], attrs))
        off += csize if csize else hsize
    return elements


def load_manifest(apk):
    with zipfile.ZipFile(apk) as z:
        return parse_axml(z.read("AndroidManifest.xml"))


def dex_and_res_bytes(apk, limit=80_000_000):
    out = []
    with zipfile.ZipFile(apk) as z:
        for n in z.namelist():
            if n.endswith(".dex") or n.endswith(".arsc") or n.startswith("res/raw") or n.startswith("assets/"):
                if z.getinfo(n).file_size <= limit:
                    out.append(z.read(n))
    return b"\n".join(out)


def app_attr(els, name):
    for tag, a in els:
        if tag == "application":
            return a.get(name)
    return None


# ---------------------------------------------------------------- checks
COMPONENTS = ("activity", "activity-alias", "service", "receiver", "provider")
DANGEROUS = {
    "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "READ_CONTACTS", "WRITE_CONTACTS", "READ_CALL_LOG", "RECORD_AUDIO",
    "ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION", "CAMERA", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
    "MANAGE_EXTERNAL_STORAGE", "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES", "BIND_ACCESSIBILITY_SERVICE",
    "READ_PHONE_STATE", "CALL_PHONE", "GET_ACCOUNTS", "QUERY_ALL_PACKAGES",
}
LOCAL_URL = re.compile(rb"http://(?!schemas\.android\.com|www\.w3\.org|xml\.org|xmlpull\.org|ns\.adobe\.com|"
                       rb"localhost|127\.0\.0\.1|10\.0\.2\.2|www\.apache\.org|apache\.org|java\.sun\.com|"
                       rb"javax\.xml|www\.opengis|purl\.org|www\.google\.com/schemas)[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}")
SECRETS = [
    (re.compile(rb"AKIA[0-9A-Z]{16}"), "AWS access key id"),
    (re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "private key"),
    (re.compile(rb"AIza[0-9A-Za-z_\-]{35}"), "Google API key"),
    (re.compile(rb"(?i)(?:password|passwd|secret|api[_-]?key|token)\s*[=:]\s*[\"'][^\"'\s]{6,}[\"']"), "hardcoded credential-like literal"),
]


def exported(attrs, has_filter):
    e = attrs.get("exported")
    return bool(e) if e is not None else has_filter  # legacy default: exported when an intent-filter exists


def run(check, apk):
    els = load_manifest(apk)
    if check == "debuggable":
        v = app_attr(els, "debuggable")
        return (not v), f"android:debuggable={'true' if v else 'not set/false'}"
    if check == "allow_backup":
        v = app_attr(els, "allowBackup")
        return (v is False), f"android:allowBackup={'true (default when unset)' if v is None else str(v).lower()}"
    if check == "cleartext_traffic":
        v = app_attr(els, "usesCleartextTraffic")
        return (v is not True), f"android:usesCleartextTraffic={'true' if v else 'not true'}"
    if check == "test_only":
        v = app_attr(els, "testOnly")
        return (not v), f"android:testOnly={'true' if v else 'not set/false'}"
    if check in ("exported_components", "exported_providers"):
        bad, i = [], 0
        cur = None
        for tag, a in els:
            if tag in COMPONENTS:
                cur = {"tag": tag, "name": a.get("name", "?"), "a": a, "filter": False}
                bad.append(cur)
            elif tag == "intent-filter" and cur is not None:
                cur["filter"] = True
            elif tag in ("application", "manifest"):
                cur = None
        hits = []
        for c in bad:
            if check == "exported_providers" and c["tag"] != "provider":
                continue
            if check == "exported_components" and c["tag"] == "provider":
                continue
            # the launcher activity must be exported; ignore activities that only have MAIN/LAUNCHER (approximation: only when no permission)
            if exported(c["a"], c["filter"]) and not c["a"].get("permission") and not c["a"].get("readPermission"):
                hits.append(f"{c['tag']}:{c['name'].split('.')[-1]}")
        return (not hits), ("no unprotected exported " + ("providers" if check == "exported_providers" else "components")
                            if not hits else f"{len(hits)} exported without permission: " + ", ".join(hits[:8]))
    if check in ("target_sdk", "min_sdk"):
        key = "targetSdkVersion" if check == "target_sdk" else "minSdkVersion"
        val = next((a.get(key) for t, a in els if t == "uses-sdk"), None)
        need = 34 if check == "target_sdk" else 26
        return (isinstance(val, int) and val >= need), f"{key}={val} (required >= {need})"
    if check == "dangerous_permissions":
        perms = [a.get("name", "") for t, a in els if t == "uses-permission"]
        bad = sorted({p.split(".")[-1] for p in perms if p.split(".")[-1] in DANGEROUS})
        return (not bad), (f"{len(bad)} high-risk permissions: " + ", ".join(bad)) if bad else f"{len(perms)} permissions, none high-risk"
    if check == "signature_scheme":
        with zipfile.ZipFile(apk) as z:
            v1 = any(n.startswith("META-INF/") and n.endswith((".RSA", ".DSA", ".EC")) for n in z.namelist())
        with open(apk, "rb") as fh:
            v2 = b"APK Sig Block 42" in fh.read()
        return v2, f"v1(JAR)={'yes' if v1 else 'no'}, v2+(APK Signing Block)={'yes' if v2 else 'no'}"
    blob = dex_and_res_bytes(apk)
    if check == "http_urls":
        urls = sorted({m.group(0).decode("latin1")[:60] for m in LOCAL_URL.finditer(blob)})
        return (not urls), ("no cleartext http:// URLs" if not urls else f"{len(urls)} http:// URLs: " + ", ".join(urls[:4]))
    if check == "hardcoded_secrets":
        found = sorted({label for rx, label in SECRETS if rx.search(blob)})
        return (not found), ("no secret patterns" if not found else "possible: " + ", ".join(found))
    if check == "js_interface":
        hit = b"addJavascriptInterface" in blob
        return (not hit), ("WebView.addJavascriptInterface referenced" if hit else "no addJavascriptInterface")
    if check == "dynamic_code":
        hit = [n for n in (b"dalvik/system/DexClassLoader", b"dalvik/system/PathClassLoader", b"Ljava/lang/Runtime;->exec") if n in blob]
        bad = [h.decode() for h in hit if b"Runtime" in h or b"DexClassLoader" in h]
        return (not bad), ("no dynamic code loading / exec" if not bad else "uses " + ", ".join(bad))
    if check == "weak_crypto":
        pats = [(rb"\"DES/", "DES"), (rb"\"DESede", "3DES"), (rb"/ECB/", "ECB mode"), (rb"MessageDigest.*MD5|\"MD5\"", "MD5"), (rb"\"SHA-?1\"", "SHA-1")]
        found = sorted({label for rx, label in pats if re.search(rx, blob)})
        return (not found), ("no weak crypto strings" if not found else "weak algorithms referenced: " + ", ".join(found))
    raise ValueError(f"unknown check {check}")


def main():
    if len(sys.argv) != 3:
        print("ERROR: usage: apk_check.py <check> <apk>")
        return 0
    try:
        ok, detail = run(sys.argv[1], sys.argv[2])
        print(("PASS: " if ok else "FAIL: ") + detail)
    except Exception as e:  # never break the SCA scan
        print(f"ERROR: {type(e).__name__}: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
