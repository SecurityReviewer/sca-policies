# secrets_scan.ps1 - secrets detection for Cyber Reviewer Windows agents, reported as SCA checks.
# PowerShell 2.0 compatible (Windows Server 2008 R2 / Windows 7 and later).
#
# Engine selection (per host), same policy as secrets_scan.py:
#   * TruffleHog when the platform is supported: 64-bit Windows 10 / Server 2016 (build >= 10240) or later.
#     Verification (sends candidate secrets to third-party APIs) is OFF unless "verify" is set in the configuration.
#   * The built-in CUSTOM scanner (patterns.json) ONLY when TruffleHog does not support the platform
#     (Windows 7/8/2008 R2/2012 R2, 32-bit Windows). A supported host without the binary is reported as unhealthy.
#
# Usage:  powershell -NoProfile -ExecutionPolicy Bypass -File secrets_scan.ps1 <scan|check|report|status> [check-name]
#   check names: private_keys | cloud_credentials | service_tokens | hardcoded_credentials | scan_health
# Raw secret values are never stored: results.json (in <install>\var\secrets-scan) has only file, line, detector and a salted fingerprint.
param(
    [Parameter(Position = 0)][string]$Action = "status",
    [Parameter(Position = 1)][string]$Name = ""
)
$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Checks = @("private_keys", "cloud_credentials", "service_tokens", "hardcoded_credentials", "scan_health")
[void][System.Reflection.Assembly]::LoadWithPartialName("System.Web.Extensions")
$Json = New-Object System.Web.Script.Serialization.JavaScriptSerializer
$Json.MaxJsonLength = 67108864

function Get-Root {
    if ($env:SECRETS_SCAN_ROOT) { return $env:SECRETS_SCAN_ROOT }
    $parent = Split-Path -Parent $Here
    if ((Split-Path -Leaf $parent) -eq "wodles") { return (Split-Path -Parent $parent) }
    return $Here
}
$Root = Get-Root

# JavaScriptSerializer returns Dictionary<string,object>/ArrayList; Windows PowerShell 2.0 only supports $obj.key on Hashtable.
function ConvertTo-PlainData($o) {
    if ($o -is [System.Collections.IDictionary]) {
        $h = @{}
        foreach ($k in $o.Keys) { $h[[string]$k] = ConvertTo-PlainData $o[$k] }
        return $h
    }
    if ($o -is [System.Collections.IEnumerable] -and $o -isnot [string]) {
        $a = New-Object System.Collections.ArrayList
        foreach ($i in $o) { [void]$a.Add((ConvertTo-PlainData $i)) }
        return ,$a.ToArray()
    }
    return $o
}

function Read-Json($path) { return ConvertTo-PlainData ($Json.DeserializeObject([System.IO.File]::ReadAllText($path))) }

function Get-Config {
    $cfg = @{
        engine = "auto"
        paths = @("C:\Users", "C:\inetpub", "C:\xampp", "C:\wamp", "C:\ProgramData", "C:\Apps", "C:\Data")
        exclude_regex = @('\\node_modules\\', '\\\.git\\', '\\AppData\\Local\\(Temp|Microsoft|Packages|Google\\Chrome|Mozilla)\\', '\\AppData\\Roaming\\(Microsoft|Code|Mozilla)\\',
                          '\\ProgramData\\(Microsoft|Package Cache|Packages)\\', '\\ossec-agent\\', '\\site-packages\\', '\\\.nuget\\', '\\\.vscode\\extensions\\')
        trufflehog_path = ""
        git_history = $true
        max_repos = 20
        verify = $false
        timeout_s = 3600
        max_findings = 2000
        max_file_kb = 1024
        stale_hours = 72
    }
    $f = Join-Path $Here "secrets_scan.conf.json"
    if ($env:SECRETS_SCAN_CONFIG) { $f = $env:SECRETS_SCAN_CONFIG }
    if (Test-Path $f) {
        $user = Read-Json $f
        foreach ($k in @($user.Keys)) { $cfg[$k] = $user[$k] }
    }
    return $cfg
}
$Cfg = Get-Config
$Patterns = Read-Json (Join-Path $Here "patterns.json")

function Get-StateDir {
    $d = Join-Path (Join-Path $Root "var") "secrets-scan"
    if (-not (Test-Path $d)) { [void](New-Item -ItemType Directory -Path $d -Force) }
    return $d
}

function Get-Salt {
    $f = Join-Path (Get-StateDir) ".salt"
    if (-not (Test-Path $f)) {
        $b = New-Object byte[] 16
        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        $rng.GetBytes($b)
        [System.IO.File]::WriteAllBytes($f, $b)
    }
    return [System.IO.File]::ReadAllBytes($f)
}
$Salt = Get-Salt

function Get-Fingerprint([string[]]$parts) {
    $enc = [System.Text.Encoding]::UTF8
    $buf = New-Object System.Collections.ArrayList
    $buf.AddRange($Salt)
    foreach ($p in $parts) { $buf.AddRange($enc.GetBytes([string]$p)); [void]$buf.Add([byte]0) }
    $sha = New-Object System.Security.Cryptography.SHA256Managed
    $hash = $sha.ComputeHash([byte[]]$buf.ToArray())
    return (([BitConverter]::ToString($hash)).Replace("-", "").ToLower()).Substring(0, 12)
}

function Get-Category([string]$detector) {
    foreach ($pair in $Patterns.detector_categories) {
        if ([regex]::IsMatch($detector, $pair[0])) { return $pair[1] }
    }
    return $Patterns.default_category
}

function Test-Excluded([string]$path, $regexes) {
    foreach ($r in $regexes) { if ($r.IsMatch($path)) { return $true } }
    return $false
}

function Test-Placeholder([string]$value) {
    $p = $Patterns.placeholders
    $v = $value.Trim().Trim('"', "'").ToLower()
    if ($v.Length -eq 0) { return $true }
    if ($p.literals -contains $v) { return $true }
    foreach ($x in $p.prefixes) { if ($v.StartsWith($x)) { return $true } }
    return [regex]::IsMatch($v, $p.regex)
}

function Test-PlatformSupported {
    $build = [Environment]::OSVersion.Version.Build
    $arch = $env:PROCESSOR_ARCHITEW6432
    if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
    return (($arch -eq "AMD64" -or $arch -eq "ARM64") -and $build -ge 10240)
}

function Find-TruffleHog {
    $cands = @()
    if ($Cfg.trufflehog_path) { $cands += $Cfg.trufflehog_path }
    $cands += (Join-Path $Here "bin\trufflehog.exe")
    $cmd = Get-Command trufflehog.exe -ErrorAction SilentlyContinue
    if ($cmd) { $cands += $cmd.Path }
    $cands += "C:\Program Files\trufflehog\trufflehog.exe"
    foreach ($c in $cands) { if ($c -and (Test-Path $c -PathType Leaf)) { return $c } }
    return $null
}

function Get-TruffleHogVersion($bin) {
    try { $o = (& $bin --version 2>&1 | Out-String).Trim(); return ($o -split "\s+")[-1] } catch { return $null }
}

function Select-Engine {
    $want = $Cfg.engine
    if ($want -eq "custom") { return @{ engine = "custom"; binary = $null; version = $null; reason = "engine forced to custom by configuration" } }
    $supported = Test-PlatformSupported
    $bin = Find-TruffleHog
    if ($want -eq "trufflehog" -or $supported) {
        if (-not $bin) { return @{ engine = "none"; binary = $null; version = $null; reason = "TruffleHog is supported on this platform but the binary was not found" } }
        $ver = Get-TruffleHogVersion $bin
        if (-not $ver) { return @{ engine = "none"; binary = $bin; version = $null; reason = "TruffleHog binary found but it does not run" } }
        return @{ engine = "trufflehog"; binary = $bin; version = $ver; reason = "TruffleHog supported on this platform" }
    }
    return @{ engine = "custom"; binary = $null; version = $null; reason = ("TruffleHog does not support this Windows version/architecture (build " + [Environment]::OSVersion.Version.Build + "): using the custom scanner") }
}

function Get-ExcludeRegexes {
    $l = New-Object System.Collections.ArrayList
    foreach ($r in $Cfg.exclude_regex) { [void]$l.Add((New-Object System.Text.RegularExpressions.Regex($r, "IgnoreCase"))) }
    return ,$l.ToArray()
}

function Find-Repos($paths, $max) {
    $repos = New-Object System.Collections.ArrayList
    $skip = @("node_modules", "Windows", "Program Files", "Program Files (x86)")
    foreach ($base in $paths) {
        $stack = New-Object System.Collections.Stack
        $stack.Push(@($base, 0))
        while ($stack.Count -gt 0) {
            $item = $stack.Pop(); $dir = $item[0]; $depth = $item[1]
            if ([System.IO.Directory]::Exists((Join-Path $dir ".git"))) {
                [void]$repos.Add($dir)
                if ($repos.Count -ge $max) { return ,$repos.ToArray() }
                continue
            }
            if ($depth -ge 4) { continue }
            try { $subs = [System.IO.Directory]::GetDirectories($dir) } catch { continue }
            foreach ($s in $subs) { if ($skip -notcontains [System.IO.Path]::GetFileName($s)) { $stack.Push(@($s, ($depth + 1))) } }
        }
    }
    return ,$repos.ToArray()
}

function Invoke-TruffleHogRun($bin, $arguments, $source, $repo, $deadline, $findings, $errors, $excl) {
    $remaining = ($deadline - (Get-Date)).TotalSeconds
    if ($remaining -le 0) { [void]$errors.Add("timeout: scan time budget exhausted before running trufflehog $($arguments[0])"); return }
    $q = ($arguments | ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }) -join " "
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $bin; $psi.Arguments = $q
    $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.CreateNoWindow = $true
    $proc = [System.Diagnostics.Process]::Start($psi)
    $expired = $false
    while ($null -ne ($line = $proc.StandardOutput.ReadLine())) {
        $line = $line.Trim()
        if (-not $line.StartsWith("{")) { continue }
        try { $d = $Json.DeserializeObject($line) } catch { continue }
        if (-not $d.ContainsKey("DetectorName")) { continue }
        $meta = $null
        $data = $d["SourceMetadata"]["Data"]
        if ($data.ContainsKey("Filesystem")) { $meta = $data["Filesystem"] } elseif ($data.ContainsKey("Git")) { $meta = $data["Git"] }
        $file = ""; $ln = 0
        if ($meta) { if ($meta.ContainsKey("file")) { $file = [string]$meta["file"] }; if ($meta.ContainsKey("line")) { $ln = [int]$meta["line"] } }
        if ($source -eq "filesystem" -and $file -and (Test-Excluded $file $excl)) { continue }
        $raw = ""
        if ($d.ContainsKey("Raw")) { $raw = [string]$d["Raw"] }
        $det = [string]$d["DetectorName"]
        $f = @{ engine = "trufflehog"; source = $source; detector = $det; category = (Get-Category $det); file = $file; line = $ln;
                verified = [bool]$d["Verified"]; fingerprint = (Get-Fingerprint @($det, $raw)) }
        if ($source -eq "git") { $f["repo"] = $repo; $f["commit"] = ([string]$meta["commit"]).Substring(0, [Math]::Min(12, ([string]$meta["commit"]).Length)) }
        if ($findings.Count -lt $Cfg.max_findings) { [void]$findings.Add($f) }
        if ((Get-Date) -gt $deadline) { $expired = $true; try { $proc.Kill() } catch {}; break }
    }
    $proc.WaitForExit()
    if ($expired) { [void]$errors.Add("timeout after $($Cfg.timeout_s)s: partial results") }
    elseif ($proc.ExitCode -ne 0) { [void]$errors.Add("trufflehog $($arguments[0]) exited with $($proc.ExitCode)") }
}

function Invoke-TruffleHogScan($bin, $paths) {
    $findings = New-Object System.Collections.ArrayList
    $errors = New-Object System.Collections.ArrayList
    $excl = Get-ExcludeRegexes
    $deadline = (Get-Date).AddSeconds([double]$Cfg.timeout_s)
    $xf = [System.IO.Path]::GetTempFileName()
    try {
        [System.IO.File]::WriteAllText($xf, (($Cfg.exclude_regex -join "`n") + "`n"))
        $common = @("--json", "--no-update", "--log-level=-1", "--exclude-paths", $xf)
        if (-not $Cfg.verify) { $common += "--no-verification" }
        $targets = @($paths | Where-Object { Test-Path $_ })
        if ($targets.Count -gt 0) { Invoke-TruffleHogRun $bin (@("filesystem") + $common + $targets) "filesystem" $null $deadline $findings $errors $excl }
        if ($Cfg.git_history -and $targets.Count -gt 0) {
            foreach ($repo in (Find-Repos $targets $Cfg.max_repos)) {
                Invoke-TruffleHogRun $bin (@("git", ("file://" + ($repo -replace "\\", "/"))) + $common) "git" $repo $deadline $findings $errors $excl
            }
        }
    } finally { Remove-Item $xf -ErrorAction SilentlyContinue }
    return @{ findings = $findings; errors = $errors; files_scanned = $null }
}

function Invoke-CustomScan($paths) {
    $findings = New-Object System.Collections.ArrayList
    $errors = New-Object System.Collections.ArrayList
    $seen = @{}
    $scanned = 0
    $excl = Get-ExcludeRegexes
    $skipDirs = @{}; foreach ($d in $Patterns.exclude_dir_names) { $skipDirs[$d.ToLower()] = $true }
    $skipExt = @{}; foreach ($e in $Patterns.exclude_extensions) { $skipExt[$e.ToLower()] = $true }
    $pats = @()
    foreach ($p in $Patterns.patterns) { $pats += ,@{ def = $p; rx = (New-Object System.Text.RegularExpressions.Regex($p.regex)) } }
    $maxBytes = [int64]$Cfg.max_file_kb * 1024
    $deadline = (Get-Date).AddSeconds([double]$Cfg.timeout_s)
    foreach ($base in $paths) {
        if (-not (Test-Path $base)) { continue }
        $stack = New-Object System.Collections.Stack
        $stack.Push($base)
        while ($stack.Count -gt 0) {
            $dir = $stack.Pop()
            try { $subs = [System.IO.Directory]::GetDirectories($dir) } catch { $subs = @() }
            foreach ($s in $subs) {
                if ($skipDirs.ContainsKey([System.IO.Path]::GetFileName($s).ToLower())) { continue }
                if (Test-Excluded ($s + "\") $excl) { continue }
                $stack.Push($s)
            }
            try { $files = [System.IO.Directory]::GetFiles($dir) } catch { continue }
            foreach ($full in $files) {
                $fn = [System.IO.Path]::GetFileName($full)
                $ext = [System.IO.Path]::GetExtension($full).ToLower()
                if ($skipExt.ContainsKey($ext) -or (Test-Excluded $full $excl)) { continue }
                if ((Get-Date) -gt $deadline) { [void]$errors.Add("timeout after $($Cfg.timeout_s)s: partial results"); return @{ findings = $findings; errors = $errors; files_scanned = $scanned } }
                try {
                    $fi = New-Object System.IO.FileInfo($full)
                    if ($fi.Length -gt $maxBytes -or $fi.Length -eq 0) { continue }
                    $text = [System.IO.File]::ReadAllText($full)
                } catch { continue }
                if ($text.IndexOf([char]0) -ge 0 -and $text.IndexOf([char]0) -lt 4096) { continue }
                $scanned++
                $lineNo = 0
                foreach ($line in ($text -split "`n")) {
                    $lineNo++
                    if ($line.Length -gt 5000) { continue }
                    foreach ($pt in $pats) {
                        $p = $pt.def
                        if ($p.ContainsKey("file_extensions")) {
                            $okName = $false
                            if ($p.file_extensions -contains $ext) { $okName = $true }
                            if ($p.ContainsKey("file_name_prefixes")) { foreach ($x in $p.file_name_prefixes) { if ($fn.StartsWith($x)) { $okName = $true } } }
                            if (-not $okName) { continue }
                        }
                        $m = $pt.rx.Match($line)
                        if (-not $m.Success) { continue }
                        $value = $m.Value
                        if ($p.ContainsKey("value_group")) {
                            $value = $m.Groups[[int]$p.value_group].Value
                            if (Test-Placeholder $value) { continue }
                        }
                        $key = "$full|$lineNo|$($p.id)"
                        if ($seen.ContainsKey($key)) { continue }
                        $seen[$key] = $true
                        if ($findings.Count -ge $Cfg.max_findings) { [void]$errors.Add("max_findings reached: results truncated"); return @{ findings = $findings; errors = $errors; files_scanned = $scanned } }
                        $fpv = "$lineNo"; if ($p.ContainsKey("value_group")) { $fpv = $value }
                        [void]$findings.Add(@{ engine = "custom"; source = "filesystem"; detector = $p.label; category = $p.category; file = $full; line = $lineNo;
                                               verified = $false; fingerprint = (Get-Fingerprint @($p.id, $full, $fpv)) })
                    }
                }
            }
        }
    }
    return @{ findings = $findings; errors = $errors; files_scanned = $scanned }
}

function Get-NowIso { return [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") }

# One JSON line per finding in findings.jsonl for the agent's logcollector (log_format json): each line becomes an event in the
# indexer (integration secrets-scan), so file/line/detector can be searched in the dashboard. No secret values.
function Write-FindingsLog($res) {
    $f = Join-Path (Get-StateDir) "findings.jsonl"
    $append = $true
    if ((Test-Path $f) -and ((Get-Item $f).Length -gt 2097152)) { $append = $false }   # cheap rotation: everything old was read long ago
    $sb = New-Object System.Text.StringBuilder
    foreach ($x in $res.findings) {
        $line = @{ module = "secrets-scan"; scan_id = $res.finished; host = $res.host; engine = $x.engine; category = $x.category
                   detector = $x.detector; path = $x.file; line = $x.line; verified = $x.verified; fingerprint = $x.fingerprint }
        if ($x.ContainsKey("repo")) { $line["repo"] = $x.repo; $line["commit"] = $x.commit }
        [void]$sb.Append($Json.Serialize($line)).Append("`n")
    }
    $enc = New-Object System.Text.UTF8Encoding($false)
    if ($append) { [System.IO.File]::AppendAllText($f, $sb.ToString(), $enc) } else { [System.IO.File]::WriteAllText($f, $sb.ToString(), $enc) }
}

function Invoke-Scan {
    $started = Get-Date
    $eng = Select-Engine
    $existing = New-Object System.Collections.ArrayList
    foreach ($p in $Cfg.paths) { if (Test-Path $p) { [void]$existing.Add([string]$p) } }
    $res = @{ schema = 1; host = $env:COMPUTERNAME; platform = ("Windows/" + [Environment]::OSVersion.Version.ToString()); engine = $eng.engine;
              engine_version = $eng.version; engine_reason = $eng.reason; verify = ([bool]$Cfg.verify -and $eng.engine -eq "trufflehog");
              started = (Get-NowIso); paths = $existing.ToArray(); errors = @(); findings = @(); truncated = $false; files_scanned = $null }
    $out = $null
    if ($eng.engine -eq "trufflehog") { $out = Invoke-TruffleHogScan $eng.binary $Cfg.paths }
    elseif ($eng.engine -eq "custom") { $out = Invoke-CustomScan $Cfg.paths }
    else { $res.errors = @($eng.reason) }
    if ($out) { $res.findings = @($out.findings); $res.errors = @($out.errors); $res.files_scanned = $out.files_scanned }
    $res.truncated = ($res.findings.Count -ge $Cfg.max_findings)
    $res.finished = (Get-NowIso)
    $res.duration_s = [Math]::Round(((Get-Date) - $started).TotalSeconds, 1)
    $file = Join-Path (Get-StateDir) "results.json"
    $tmp = $file + ".tmp"
    [System.IO.File]::WriteAllText($tmp, $Json.Serialize($res))
    if (Test-Path $file) { Remove-Item $file -Force }
    Move-Item $tmp $file
    Write-FindingsLog $res
    Write-Output ("secrets_scan: engine=" + $res.engine + " findings=" + $res.findings.Count + " errors=" + $res.errors.Count + " duration=" + $res.duration_s + "s")
}

function Get-Results {
    $f = Join-Path (Get-StateDir) "results.json"
    if (-not (Test-Path $f)) { return $null }
    try { return Read-Json $f } catch { return $null }
}

function Invoke-Check([string]$check) {
    $res = Get-Results
    if (-not $res) { Write-Output "FAIL: no scan results yet (run: secrets_scan.ps1 scan)"; return }
    $fin = [DateTime]::ParseExact($res.finished, "yyyy-MM-ddTHH:mm:ssZ", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal)
    $age = ([DateTime]::UtcNow - $fin).TotalHours
    if ($check -eq "scan_health") {
        $problems = @()
        if ($res.engine -eq "none") { $problems += $res.engine_reason }
        $problems += @($res.errors)
        if ($res.truncated) { $problems += "results truncated at max_findings" }
        if ($age -gt $Cfg.stale_hours) { $problems += ("last scan finished {0:N0}h ago (limit {1}h)" -f $age, $Cfg.stale_hours) }
        if ($problems.Count -gt 0) { $m = ($problems -join "; "); Write-Output ("FAIL: " + $m.Substring(0, [Math]::Min(400, $m.Length))); return }
        $eng = ("" + $res.engine + " " + $res.engine_version).Trim()
        Write-Output ("PASS: engine={0}, finished {1:N1}h ago, {2} path(s)" -f $eng, $age, @($res.paths).Count)
        return
    }
    $hits = @($res.findings | Where-Object { $_.category -eq $check })
    if ($hits.Count -eq 0) { Write-Output ("PASS: no " + $check.Replace("_", " ") + " found (engine=" + $res.engine + ", finished " + $res.finished + ")"); return }
    $files = @($hits | ForEach-Object { $_.file } | Sort-Object -Unique)
    $verified = @($hits | Where-Object { $_.verified }).Count
    $msg = "$($hits.Count) finding(s) in $($files.Count) file(s)"
    if ($verified -gt 0) { $msg += ", $verified VERIFIED live" }
    $msg += "; e.g. " + (($files | Select-Object -First 3) -join ", ") + " (details: secrets_scan.ps1 report)"
    Write-Output ("FAIL: " + $msg)
}

function Invoke-Report {
    $res = Get-Results
    if (-not $res) { Write-Output "no scan results"; return }
    Write-Output ("engine=" + $res.engine + " " + $res.engine_version + " (" + $res.engine_reason + "); finished " + $res.finished + "; " + @($res.findings).Count + " finding(s); errors=" + $(if (@($res.errors).Count) { @($res.errors) -join " | " } else { "none" }))
    foreach ($f in ($res.findings | Sort-Object { $_.category }, { $_.file }, { [int]$_.line })) {
        $v = ""; if ($f.verified) { $v = "VERIFIED " }
        Write-Output ("{0,-22} {1,-34} {2}{3}:{4}  [{5}]" -f $f.category, $f.detector, $v, $f.file, $f.line, $f.fingerprint)
    }
}

switch ($Action) {
    "scan" { Invoke-Scan }
    "check" {
        if ($Checks -notcontains $Name) { Write-Output ("FAIL: unknown check '" + $Name + "'"); exit 0 }
        Invoke-Check $Name
    }
    "report" { Invoke-Report }
    "status" {
        $e = Select-Engine
        $r = Get-Results
        Write-Output ($Json.Serialize(@{ engine = $e.engine; binary = $e.binary; version = $e.version; reason = $e.reason; platform_supported = (Test-PlatformSupported); results = [bool]$r }))
    }
    default { Write-Output "usage: secrets_scan.ps1 <scan|check|report|status> [check-name]"; exit 2 }
}
exit 0
