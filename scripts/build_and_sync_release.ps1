[CmdletBinding()]
param(
    [string]$PubspecPath = "flutter_app/pubspec.yaml",
    [string]$FlutterProjectDir = "flutter_app",
    [string]$PublishDir = "flutter",
    [string]$PublishedFileName = "app-arm64-v8a-release.apk",
    [string]$ApkUrl = "https://app.vvc.asia/flutter/app-arm64-v8a-release.apk",
    [string]$UpdateMessage = "",
    [string]$DbServer = "",
    [string]$DbName = "",
    [string]$DbUser = "",
    [string]$DbPass = "",
    [switch]$ForceUpdate,
    [switch]$NoForceUpdate,
    [switch]$SkipBuild,
    [switch]$SkipPublish,
    [switch]$SkipSync,
    [string]$PhpExe = ""
)

$ErrorActionPreference = "Stop"

function Resolve-RepoPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PathValue,
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot
    )

    if ([System.IO.Path]::IsPathRooted($PathValue)) {
        return $PathValue
    }

    return Join-Path $RepoRoot $PathValue
}

function Get-PubspecVersionInfo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        throw "pubspec.yaml not found: $Path"
    }

    $match = Select-String -Path $Path -Pattern '^\s*version:\s*([^\s#]+)\s*$' | Select-Object -First 1
    if (-not $match) {
        throw "Unable to find version line in $Path"
    }

    $rawVersion = $match.Matches[0].Groups[1].Value.Trim()
    $parts = $rawVersion.Split('+', 2)
    $versionName = $parts[0].Trim()
    $buildNumber = if ($parts.Count -gt 1) { $parts[1].Trim() } else { "1" }

    if (-not $versionName) {
        throw "Version name is empty in $Path"
    }
    if (-not ($buildNumber -match '^\d+$')) {
        throw "Build number is invalid in ${Path}: $buildNumber"
    }

    return @{
        Raw = $rawVersion
        Version = $versionName
        Build = $buildNumber
    }
}

function Resolve-PhpExecutable {
    param(
        [string]$Candidate
    )

    if ($Candidate) {
        if (-not (Test-Path $Candidate)) {
            throw "PHP executable not found: $Candidate"
        }
        return $Candidate
    }

    $xamppPhp = "C:\\xampp\\php\\php.exe"
    if (Test-Path $xamppPhp) {
        return $xamppPhp
    }

    $phpCommand = Get-Command php -ErrorAction SilentlyContinue
    if ($phpCommand) {
        return $phpCommand.Source
    }

    throw "PHP executable not found. Pass -PhpExe with a valid php.exe path."
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$pubspecFullPath = Resolve-RepoPath -PathValue $PubspecPath -RepoRoot $repoRoot
$flutterProjectFullPath = Resolve-RepoPath -PathValue $FlutterProjectDir -RepoRoot $repoRoot
$publishDirFullPath = Resolve-RepoPath -PathValue $PublishDir -RepoRoot $repoRoot
$syncScriptPath = Join-Path $repoRoot "scripts\\sync_release_settings.php"

$versionInfo = Get-PubspecVersionInfo -Path $pubspecFullPath
Write-Host "Release version: $($versionInfo.Version)+$($versionInfo.Build)"

if (-not $SkipBuild) {
    if (-not (Test-Path $flutterProjectFullPath)) {
        throw "Flutter project directory not found: $flutterProjectFullPath"
    }

    Push-Location $flutterProjectFullPath
    try {
        & flutter build apk --release --target-platform android-arm64 --split-per-abi
        if ($LASTEXITCODE -ne 0) {
            throw "Flutter build failed with exit code $LASTEXITCODE"
        }
    } finally {
        Pop-Location
    }
}

$builtApkPath = Join-Path $flutterProjectFullPath "build\\app\\outputs\\flutter-apk\\app-arm64-v8a-release.apk"
$builtSha1Path = "$builtApkPath.sha1"
if (-not (Test-Path $builtApkPath)) {
    throw "Built APK not found: $builtApkPath"
}

$publishedApkPath = $builtApkPath
if (-not $SkipPublish) {
    New-Item -ItemType Directory -Path $publishDirFullPath -Force | Out-Null
    $publishedApkPath = Join-Path $publishDirFullPath $PublishedFileName
    Copy-Item -Path $builtApkPath -Destination $publishedApkPath -Force

    if (Test-Path $builtSha1Path) {
        Copy-Item -Path $builtSha1Path -Destination "$publishedApkPath.sha1" -Force
    }
}

if (-not $SkipSync) {
    if (-not (Test-Path $syncScriptPath)) {
        throw "Sync script not found: $syncScriptPath"
    }

    $phpExecutable = Resolve-PhpExecutable -Candidate $PhpExe
    $syncArgs = @(
        $syncScriptPath,
        "--pubspec=$pubspecFullPath",
        "--apk-url=$ApkUrl",
        "--apk-path=$publishedApkPath"
    )

    if ($UpdateMessage) {
        $syncArgs += "--update-message=$UpdateMessage"
    }

    if ($DbServer) {
        $syncArgs += "--db-server=$DbServer"
    }
    if ($DbName) {
        $syncArgs += "--db-name=$DbName"
    }
    if ($DbUser) {
        $syncArgs += "--db-user=$DbUser"
    }
    if ($DbPass) {
        $syncArgs += "--db-pass=$DbPass"
    }

    if ($ForceUpdate -and $NoForceUpdate) {
        throw "Use either -ForceUpdate or -NoForceUpdate, not both."
    }

    if ($ForceUpdate) {
        $syncArgs += "--force-update"
    } elseif ($NoForceUpdate) {
        $syncArgs += "--no-force-update"
    }

    & $phpExecutable @syncArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Release settings sync failed with exit code $LASTEXITCODE"
    }
}

Write-Host ""
Write-Host "Build + sync completed."
Write-Host "pubspec: $($versionInfo.Raw)"
Write-Host "published APK: $publishedApkPath"
Write-Host "APK URL: $ApkUrl"
