"""Generates ms_office_2013.yml / ms_office_2016.yml.  Usage: python make_ms_office_policy.py <out.yml> <15.0|16.0>"""
import json
import sys

VER = sys.argv[2] if len(sys.argv) > 2 else "16.0"
YEAR = {"16.0": "2016", "15.0": "2013"}[VER]

BS = chr(92)
P = BS.join(["HKLM", "SOFTWARE", "Policies", "Microsoft", "Office", VER]) + BS
REF = "https://learn.microsoft.com/en-us/deployoffice/security/"
checks = []


def add(name, desc, rat, rem, key, val, rx, nis="21.2.e"):
    alts = [a.strip("^$") for a in rx.split("|")]
    pat = "|".join("^" + a for a in alts)
    ps = ("c:powershell -NoProfile -Command \"$o = reg query ''%s%s'' /v %s /reg:64 2>&1; "
          "if ($o -match ''REG_DWORD\\s+0x([0-9a-fA-F]+)'') {[Convert]::ToInt32($matches[1],16)} else {''MISSING''}\" -> r:%s") % (P.rstrip(BS) + BS, key, val, pat)
    checks.append(dict(name=name, desc=desc, rat=rat, rem=rem, rule=ps, nis=nis))


for app in ("Word", "Excel", "PowerPoint"):
    s = app + BS + "Security"
    add("Ensure %s macros are disabled or limited to digitally signed ones" % app,
        "VBAWarnings must be 3 (disable all except digitally signed macros) or 4 (disable all without notification) via policy.",
        "Malicious macros are the most common delivery vector of ransomware and infostealers through Office documents.",
        "Set 'VBA Macro Notification Settings' to 'Disable all except digitally signed macros' or 'Disable all without notification' (Microsoft %s %s > Application Settings > Security > Trust Center)." % (app, YEAR),
        s, "VBAWarnings", "^3$|^4$")
    add("Ensure %s blocks macros from running in files from the Internet" % app,
        "blockcontentexecutionfrominternet must be 1 so macros in files carrying the Mark of the Web are blocked.",
        "Documents downloaded from the Internet or received by e-mail carry the Mark of the Web; blocking macros there removes the main phishing path.",
        "Enable 'Block macros from running in Office files from the Internet' for %s." % app,
        s, "blockcontentexecutionfrominternet", "^1$")
    add("Ensure %s does not trust access to the VBA object model" % app,
        "AccessVBOM must be 0.",
        "Trusted programmatic access to the VBA project lets a macro create or modify other macros, enabling self-replicating malicious code.",
        "Disable 'Trust access to the VBA project object model' for %s." % app,
        s, "AccessVBOM", "^0$")
    for v, txt in (("DisableInternetFilesInPV", "files from the Internet"),
                   ("DisableAttachmentsInPV", "Outlook attachments"),
                   ("DisableUnsafeLocationsInPV", "files in unsafe locations")):
        add("Ensure Protected View is not disabled for %s in %s" % (txt, app),
            "%s must be 0 so the document opens in Protected View." % v,
            "Protected View opens untrusted documents in a sandbox where active content does not run.",
            "Do not enable the 'Turn off Protected View for %s' setting in %s." % (txt, app),
            s + BS + "ProtectedView", v, "^0$")

ec = "Excel" + BS + "Security" + BS + "External Content"
add("Ensure Excel does not launch DDE servers", "DisableDDEServerLaunch must be 1.",
    "DDE lets a document start other applications and has been used to run commands without macros.",
    "Enable 'Don't allow Dynamic Data Exchange (DDE) server launch in Excel'.", ec, "DisableDDEServerLaunch", "^1$")
add("Ensure Excel does not look up DDE servers", "DisableDDEServerLookup must be 1.",
    "Same DDE abuse path as above.",
    "Enable 'Don't allow Dynamic Data Exchange (DDE) server lookup in Excel'.", ec, "DisableDDEServerLookup", "^1$")
add("Ensure Word does not allow DDE", "AllowDDE must be 0 (no DDE) or 1 (only where Office needs it), never 2.",
    "DDE fields in Word documents can run arbitrary commands.",
    "Set 'Dynamic Data Exchange' for Word to 'Don't allow DDE'.", "Word" + BS + "Security", "AllowDDE", "^0$|^1$")
add("Ensure all ActiveX controls are disabled in Office", "DisableAllActiveX must be 1.",
    "ActiveX controls in documents run native code and have a long history of exploitable flaws.",
    "Enable 'Disable All ActiveX' in the Office Trust Center.", "Common" + BS + "Security", "DisableAllActiveX", "^1$")
add("Ensure Outlook blocks external content in HTML mail", "BlockExtContent must be 1.",
    "External images and content are used for tracking and to confirm that a mailbox is live.",
    "Block external content in HTML e-mail in the Outlook Trust Center.", "Outlook" + BS + "Options" + BS + "Mail", "BlockExtContent", "^1$")
add("Ensure Outlook keeps level 1 (dangerous) attachments blocked", "ShowLevel1Attach must be 0.",
    "Level 1 attachments (executables, scripts) must stay blocked.",
    "Do not enable 'Display Level 1 attachments'.", "Outlook" + BS + "Security", "ShowLevel1Attach", "^0$")
add("Ensure Outlook prompts when a program tries to send mail", "PromptOOMSend must be 0 (prompt the user) so programs cannot send mail silently.",
    "Object Model access to send mail is used by malware to spread through the mailbox.",
    "Set the programmatic access security setting to 'Prompt user'.", "Outlook" + BS + "Security", "PromptOOMSend", "^0$")
add("Ensure automatic Office updates are enabled", "EnableAutomaticUpdates must be 1.",
    "Unpatched Office installations are exploited through known vulnerabilities.",
    "Enable 'Enable Automatic Updates' in the Office Update policy.", "Common" + BS + "OfficeUpdate", "EnableAutomaticUpdates", "^1$")

hk = "HKLM" + BS
lines = [
    "# Security Configuration Assessment",
    "# Microsoft Office " + YEAR + " hardening (Cyber Reviewer)",
    "#",
    "# Registry checks of the machine-wide Office policy keys (" + P + "). A missing key means the",
    "# setting is not enforced by policy and the check fails. This is an original policy based on the Microsoft Office",
    "# security baseline guidance; it is not a CIS Benchmark.",
    "",
    "policy:",
    '  id: "ms_office_%s"' % YEAR,
    '  file: "ms_office_%s.yml"' % YEAR,
    '  name: "Microsoft Office %s hardening (macros, Protected View, DDE, ActiveX, updates)"' % YEAR,
    '  description: "Machine-wide policy checks for Word, Excel, PowerPoint and Outlook %s."' % YEAR,
    "  references:",
    "    - " + REF,
    "",
    "requirements:",
    '  name: "Check that Microsoft Office %s is installed"' % YEAR,
    '  description: "Office %s (MSI or Click-to-Run, 32 or 64 bit). File rules cover installs that a 32-bit agent cannot see in the 64-bit registry view."' % VER,
    "  condition: any",
    "  rules:",
    "    - 'c:powershell -NoProfile -Command \"if ((reg query ''HKLM%sSOFTWARE%sMicrosoft%sOffice%s%s%sCommon%sInstallRoot'' /reg:64 2>&1) -match ''InstallRoot'') {''INSTALLED''} elseif ((reg query ''HKLM%sSOFTWARE%sMicrosoft%sOffice%s%s%sCommon%sInstallRoot'' /reg:32 2>&1) -match ''InstallRoot'') {''INSTALLED''} else {''NO''}\" -> r:^INSTALLED'" % ((BS, BS, BS, BS, VER, BS, BS) * 2),
    "",
    "checks:",
]
i = 61000 if VER == "16.0" else 61100
for c in checks:
    lines += ["  - id: %d" % i,
              "    name: %s" % json.dumps(c["name"]),
              "    description: %s" % json.dumps(c["desc"]),
              "    rationale: %s" % json.dumps(c["rat"]),
              "    remediation: %s" % json.dumps(c["rem"]),
              "    compliance:",
              '      gdpr: ["IV_32.1.b"]',
              '      iso_27001: ["A.8.7", "A.8.9"]',
              '      nis2: ["%s"]' % c["nis"],
              "    references:",
              "      - " + REF,
              "    condition: all",
              "    rules:",
              "      - '%s'" % c["rule"].replace(BS + BS, BS + BS),
              ""]
    i += 1
open(sys.argv[1], "w", encoding="utf-8", newline="\n").write("\n".join(lines))
print(len(checks))
