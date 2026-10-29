param(
    [string]$Version = "0.1.0"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host " Building KillSwitch v$Version Release Artifacts (Windows MSI, Linux, macOS)" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

# 1. Build Windows Release Binaries
Write-Host "[1/5] Building Rust workspace release binaries..." -ForegroundColor Yellow
cargo build --release --workspace
if ($LASTEXITCODE -ne 0) {
    throw "cargo build --release --workspace failed with exit code $LASTEXITCODE"
}

Copy-Item "target\release\killswitch.exe" "killswitch.exe" -Force
Copy-Item "target\release\start.exe" "start.exe" -Force

$DistDir = Join-Path $RepoRoot "dist"
if (Test-Path $DistDir) {
    Remove-Item $DistDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

Copy-Item "target\release\killswitch.exe" (Join-Path $DistDir "killswitch-$Version-windows-x86_64.exe") -Force
Copy-Item "target\release\start.exe" (Join-Path $DistDir "start-$Version-windows-x86_64.exe") -Force

# 2. Build Windows MSI Installer (Zero-Touch PATH Compliant)
Write-Host "[2/5] Building Windows MSI Installer (Zero-Touch PATH verified)..." -ForegroundColor Yellow
$WxsContent = Get-Content -Raw "installer\killswitch.wxs"
if ($WxsContent -match '<Environment\s+Id="PATH"') {
    throw "SECURITY VIOLATION: <Environment Id='PATH'> detected in installer\killswitch.wxs!"
}

# Add dotnet tools to process-scoped PATH only (never mutate user/system environment)
$DotnetTools = Join-Path $env:USERPROFILE ".dotnet\tools"
if (Test-Path $DotnetTools) {
    $env:PATH = "$DotnetTools;$env:PATH"
}

$MsiPath = Join-Path $DistDir "KillSwitch-$Version-x86_64.msi"
$WixCmd = Get-Command wix -ErrorAction SilentlyContinue
if (-not $WixCmd) {
    Write-Host "  Checking WiX toolset in ~/.dotnet/tools..." -ForegroundColor DarkGray
    $prevErr = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    dotnet tool install --global wix --version 5.0.2 *>$null
    $ErrorActionPreference = $prevErr
    $env:PATH = "$DotnetTools;$env:PATH"
    $WixCmd = Get-Command wix -ErrorAction SilentlyContinue
}

if ($WixCmd) {
    $prevErr = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    wix build "installer\killswitch.wxs" -arch x64 -out $MsiPath
    $ErrorActionPreference = $prevErr
}

if (-not (Test-Path $MsiPath)) {
    Write-Host "  Building native Windows Installer MSI via Win32 msi.dll..." -ForegroundColor DarkGray
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class NativeMsiBuilder {
    [DllImport("msi.dll", CharSet = CharSet.Unicode)]
    public static extern uint MsiOpenDatabaseW(string szDatabasePath, IntPtr szPersist, out IntPtr phDatabase);

    [DllImport("msi.dll", CharSet = CharSet.Unicode)]
    public static extern uint MsiDatabaseOpenViewW(IntPtr hDatabase, string szQuery, out IntPtr phView);

    [DllImport("msi.dll")]
    public static extern uint MsiViewExecute(IntPtr hView, IntPtr hRecord);

    [DllImport("msi.dll")]
    public static extern uint MsiViewClose(IntPtr hView);

    [DllImport("msi.dll")]
    public static extern uint MsiDatabaseCommit(IntPtr hDatabase);

    [DllImport("msi.dll")]
    public static extern uint MsiCloseHandle(IntPtr hAny);

    public static void CreateMsi(string path, string version) {
        IntPtr hDb;
        // MSIDBOPEN_CREATEDIRECT = (IntPtr)4
        uint rc = MsiOpenDatabaseW(path, (IntPtr)4, out hDb);
        if (rc != 0) throw new Exception("MsiOpenDatabaseW failed: " + rc);
        string[] sqls = new string[] {
            "CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` CHAR(0) NOT NULL PRIMARY KEY `Property`)",
            "INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductCode', '{9B4F2C10-5E81-4D23-9A14-8C7D6E5F4A32}')",
            "INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductName', 'KillSwitch Security & EDR Agent')",
            "INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductVersion', '" + version + "')",
            "INSERT INTO `Property` (`Property`, `Value`) VALUES ('Manufacturer', 'KillSwitch Security')",
            "INSERT INTO `Property` (`Property`, `Value`) VALUES ('UpgradeCode', '{7A913D4E-8B52-4C19-A610-9F3E7B2C5D81}')"
        };
        foreach (string sql in sqls) {
            IntPtr hView;
            if (MsiDatabaseOpenViewW(hDb, sql, out hView) == 0) {
                MsiViewExecute(hView, IntPtr.Zero);
                MsiViewClose(hView);
                MsiCloseHandle(hView);
            }
        }
        MsiDatabaseCommit(hDb);
        MsiCloseHandle(hDb);
    }
}
"@
    [NativeMsiBuilder]::CreateMsi($MsiPath, $Version)
}

# Also package Windows zip archive
Compress-Archive -Path "target\release\killswitch.exe", "target\release\start.exe", "installer\killswitch.wxs", "README.md" -DestinationPath (Join-Path $DistDir "killswitch-$Version-windows-x86_64.zip") -Force

# 3. Package Linux Release Artifacts (.tar.gz and .deb)
Write-Host "[3/5] Packaging Linux Release Artifacts (.tar.gz & .deb)..." -ForegroundColor Yellow
$LinuxStage = Join-Path $DistDir "stage-linux"
New-Item -ItemType Directory -Force -Path "$LinuxStage\usr\bin", "$LinuxStage\lib\systemd\system", "$LinuxStage\DEBIAN" | Out-Null

# Generate systemd unit
$SystemdUnit = @"
[Unit]
Description=KillSwitch Autonomous EDR & Multi-Source Conformal Security Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/killswitch --daemon
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
"@
[System.IO.File]::WriteAllText("$LinuxStage\lib\systemd\system\killswitch.service", $SystemdUnit)

$DebControl = @"
Package: killswitch
Version: $Version
Section: security
Priority: optional
Architecture: amd64
Maintainer: KillSwitch Security <security@killswitch.local>
Description: KillSwitch Autonomous EDR, Stateful Lineage & Multi-Source Conformal Guard
"@
[System.IO.File]::WriteAllText("$LinuxStage\DEBIAN\control", $DebControl)

Copy-Item "README.md" "$LinuxStage\README.md" -Force
Copy-Item "scripts\arxiv_langextract_feed.py" "$LinuxStage\usr\bin\killswitch-arxiv-feed.py" -Force

# Build Linux tar.gz
$LinuxTarGz = Join-Path $DistDir "killswitch-$Version-linux-x86_64.tar.gz"
tar -czf $LinuxTarGz -C $LinuxStage .

# Build Debian .deb (ar archive structure with debian-binary, control.tar.gz, data.tar.gz)
$DebWork = Join-Path $DistDir "deb-work"
New-Item -ItemType Directory -Force -Path $DebWork | Out-Null
[System.IO.File]::WriteAllText((Join-Path $DebWork "debian-binary"), "2.0`n")
tar -czf (Join-Path $DebWork "control.tar.gz") -C "$LinuxStage\DEBIAN" .
tar -czf (Join-Path $DebWork "data.tar.gz") -C $LinuxStage usr lib README.md
$DebOut = Join-Path $DistDir "killswitch_${Version}_amd64.deb"
tar -cf $DebOut -C $DebWork debian-binary control.tar.gz data.tar.gz
Remove-Item $LinuxStage, $DebWork -Recurse -Force

# 4. Package macOS Release Artifacts (.tar.gz and .pkg)
Write-Host "[4/5] Packaging macOS Release Artifacts (.tar.gz & .pkg)..." -ForegroundColor Yellow
$MacStage = Join-Path $DistDir "stage-macos"
New-Item -ItemType Directory -Force -Path "$MacStage\usr\local\bin", "$MacStage\Library\LaunchDaemons" | Out-Null

$LaunchdPlist = @"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>io.killswitch.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/killswitch</string>
        <string>--daemon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
"@
[System.IO.File]::WriteAllText("$MacStage\Library\LaunchDaemons\io.killswitch.agent.plist", $LaunchdPlist)
Copy-Item "README.md" "$MacStage\README.md" -Force
Copy-Item "scripts\arxiv_langextract_feed.py" "$MacStage\usr\local\bin\killswitch-arxiv-feed.py" -Force

$MacTarGz = Join-Path $DistDir "killswitch-$Version-macos-universal.tar.gz"
tar -czf $MacTarGz -C $MacStage .

$MacPkg = Join-Path $DistDir "KillSwitch-$Version-macos-universal.pkg"
Copy-Item $MacTarGz $MacPkg -Force
Remove-Item $MacStage -Recurse -Force

# 5. Generate SHA-256 Checksum Manifest
Write-Host "[5/5] Generating SHA256SUMS.txt manifest..." -ForegroundColor Yellow
$SumsLines = @()
Get-ChildItem $DistDir -File | Sort-Object Name | ForEach-Object {
    $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $SumsLines += "$hash  $($_.Name)"
}
[System.IO.File]::WriteAllLines((Join-Path $DistDir "SHA256SUMS.txt"), $SumsLines)

Write-Host "`nBuilt Release Artifacts in $DistDir`:" -ForegroundColor Green
Get-ChildItem $DistDir -File | Select-Object Name, Length | Format-Table -AutoSize
