# One-line installer for kubelogin-daemon (Windows)
#
# Install:  irm https://raw.githubusercontent.com/ZihaoZhou/kubelogin-daemon/daemon-mode/install.ps1 | iex
# Upgrade:  irm https://raw.githubusercontent.com/ZihaoZhou/kubelogin-daemon/daemon-mode/install.ps1 | iex
#           (same command — detects existing install and runs setup upgrade)
#
# For Linux/macOS, use install.sh instead:
#   curl -fsSL https://raw.githubusercontent.com/ZihaoZhou/kubelogin-daemon/daemon-mode/install.sh | sh

$ErrorActionPreference = "Stop"

# Detect architecture
$arch = if ([Environment]::Is64BitOperatingSystem) {
    if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
} else {
    Write-Error "32-bit Windows is not supported."
    exit 1
}

# Determine latest release
Write-Host "Fetching latest release..."
$release = Invoke-RestMethod -Uri "https://api.github.com/repos/ZihaoZhou/kubelogin-daemon/releases/latest"
$version = $release.tag_name
if (-not $version) {
    Write-Error "Failed to determine latest release"
    exit 1
}
Write-Host "Latest version: $version"

# Set up paths
$baseUrl = "https://github.com/ZihaoZhou/kubelogin-daemon/releases/download/$version"
$binaryName = "kubelogin-daemon_windows_${arch}.exe"
$installDir = Join-Path $env:LOCALAPPDATA "kubelogin-daemon"
if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
}

# Download to temp
$tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("kld-install-" + [System.Guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

try {
    Write-Host "Downloading kubelogin-daemon $version for windows/$arch..."
    $binaryPath = Join-Path $tmpDir $binaryName
    $checksumsPath = Join-Path $tmpDir "checksums.txt"

    Invoke-WebRequest -Uri "$baseUrl/$binaryName" -OutFile $binaryPath -UseBasicParsing
    Invoke-WebRequest -Uri "$baseUrl/checksums.txt" -OutFile $checksumsPath -UseBasicParsing

    # Verify checksum
    $checksumLine = Get-Content $checksumsPath | Where-Object { $_ -match $binaryName } | Select-Object -First 1
    if (-not $checksumLine) {
        Write-Error "No checksum entry found for $binaryName in checksums.txt"
        exit 1
    }
    $expected = ($checksumLine -split '\s+')[0]
    $actual = (Get-FileHash -Path $binaryPath -Algorithm SHA256).Hash.ToLower()

    if ($actual -ne $expected) {
        Write-Error "CHECKSUM MISMATCH!`n  Expected: $expected`n  Got:      $actual"
        exit 1
    }
    Write-Host "Checksum verified."

    # Check for existing installation
    $existingPath = $null
    $existing = Get-Command kubelogin-daemon -ErrorAction SilentlyContinue
    if ($existing) {
        $existingPath = $existing.Source
    } elseif (Test-Path (Join-Path $installDir "kubelogin-daemon.exe")) {
        $existingPath = Join-Path $installDir "kubelogin-daemon.exe"
    }

    $destPath = Join-Path $installDir "kubelogin-daemon.exe"

    if ($existingPath) {
        $oldVersion = & $existingPath --version 2>&1 | Select-Object -First 1
        Write-Host "Existing installation found: $oldVersion at $existingPath"

        # Stop any running daemon and stresstest before overwriting binary
        Get-Process -Name "kld-stresstest" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Get-Process -Name "kubelogin-daemon" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2

        Copy-Item -Path $binaryPath -Destination $destPath -Force

        # Run setup upgrade. Native exe stderr must not become a PowerShell error.
        Write-Host "Running setup upgrade..."
        $upgradeOutput = cmd /c "`"$destPath`" setup upgrade --yes 2>&1"
        $upgradeOutput | ForEach-Object { Write-Host $_ }
    } else {
        Copy-Item -Path $binaryPath -Destination $destPath -Force
    }

    # Verify
    try {
        $installedVersion = & $destPath --version 2>&1 | Select-Object -First 1
        Write-Host "Installed: $installedVersion"
    } catch {
        Write-Host "Installed kubelogin-daemon to $destPath"
    }

    # Check PATH
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -notlike "*$installDir*") {
        Write-Host ""
        Write-Host "Adding $installDir to your PATH..."
        [Environment]::SetEnvironmentVariable("Path", "$installDir;$userPath", "User")
        $env:Path = "$installDir;$env:Path"
        Write-Host "PATH updated. Restart your terminal for it to take effect."
    }

    Write-Host ""
    if (-not $existingPath) {
        Write-Host "Next steps:"
        Write-Host ""
        Write-Host "  Fresh setup:"
        Write-Host "    kubelogin-daemon setup install ``"
        Write-Host "      --oidc-issuer-url=https://YOUR_ISSUER ``"
        Write-Host "      --oidc-client-id=YOUR_CLIENT_ID"
        Write-Host ""
        Write-Host "  Migrate from kubelogin:"
        Write-Host "    kubelogin-daemon setup migrate"
    } else {
        Write-Host "Upgrade complete."
    }
} finally {
    Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
}
