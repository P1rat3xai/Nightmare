# InstallScript.ps1
# ------------------
# Sets up IIS, Print Services, and shared printers for PrinterC2 lab.
# Run as Administrator. Configure SSL separately for production use.

function Invoke-CheckIfElevated {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object System.Security.Principal.WindowsPrincipal($id)
    if ($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Install-Prerequisites
    } else {
        Write-Output "[!] Not running in administrative context. Please run as Administrator."
        exit 1
    }
}

function Install-Prerequisites {
    # Install required Windows Features.
    Write-Host "[+] Installing IIS..."
    Install-WindowsFeature -ComputerName $env:COMPUTERNAME -name Web-Server -IncludeManagementTools

    Write-Host "[+] Installing Windows Print Services, Print Server, and Internet Printing..."
    Install-WindowsFeature -ComputerName $env:COMPUTERNAME -Name Print-Services,Print-Server,Print-Internet

    # Create printer port and printer. Prompts for user input.
    Write-Host "[+] Creating and adding shared printers."
    $C2output = Read-Host "Where do you want to store PDF C2 output (eg. c:\\temp\\c2.pdf)?"
    $PrinterName = Read-Host "Name your printer:"
    $Server = Read-Host "What is your server's IP or DNS name?"
    try {
        Add-PrinterPort $C2output
        New-Item $C2output -Force | Out-Null
        Add-Printer -Name $PrinterName -DriverName "Generic / Text Only" -KeepPrintedJobs -Shared -ShareName $PrinterName -PortName $C2output
        Start-Sleep 5
        # Change this to HTTPS once you set up SSL. Remove printers with Remove-Printer -name <printer_name>.
        Add-Printer -Name "http://$Server/$PrinterName" -PortName "http://$Server/printers/$PrinterName/.printer" -DriverName "Microsoft Print To PDF"
    } catch {
        Write-Host "[!] Error creating printer: $_"
    }

    # Enable anonymous authentication to printers (use firewall rules to allow access from specific IPs).
    Write-Host "[+] Enabling anonymous authentication for Internet Printing."
    Set-WebConfigurationProperty -Filter system.webServer/security/authentication/anonymousAuthentication -PSPath MACHINE/WEBROOT/APPHOST -Location 'Default Web Site/Printers' -Name Enabled -Value $true

    Write-Host "[+] Done."
}

# Entry point
Invoke-CheckIfElevated