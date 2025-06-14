
## Abusing Microsoft Printer for C2:

Attackers can exploit Microsoft Windows' Internet Printing Protocol (IPP) to establish a covert command and control (C2) channel. By leveraging shared printers, commands are encoded in document names within the print queue, which infected clients can retrieve and execute. This technique bypasses traditional security controls, requires no administrative privileges for printer addition, and allows data exfiltration via printed documents.

## PrinterC2 set up:

Files
    Install/InstallScript.ps1 - PowerShell script that installs the prerequisites. You should set up SSL yourself
    Server/IPPrintC2.ps1 - PowerShell script for IPPrintC2 that you run on the server hosting Print Services
    Payloads/payloads.txt - basic list of payloads to get started

## Orginal source & creator: 
[IPPrintC2](https://github.com/Diverto/IPPrintC2)
