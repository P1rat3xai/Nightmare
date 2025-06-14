# PrinterC2: Abusing Microsoft Printer for C2

> **Simulate covert command and control (C2) using Windows Internet Printing Protocol (IPP) and shared printers.**

---

## Overview
Attackers can exploit Windows' IPP to establish a covert C2 channel. By encoding commands in document names within the print queue, infected clients can retrieve and execute them. This technique bypasses traditional security controls, requires no admin privileges for printer addition, and allows data exfiltration via printed documents.

---

## Setup Instructions

**Files:**
- `Install/InstallScript.ps1`: Installs prerequisites (set up SSL separately)
- `Server/IPPrintC2.ps1`: Run on the server hosting Print Services
- `Payloads/payloads.txt`: Example payloads to get started

### Quick Start
1. Run `Install/InstallScript.ps1` on the target system to install dependencies.
2. Start the C2 server with `Server/IPPrintC2.ps1`.
3. Add your payloads to `Payloads/payloads.txt`.

---

## Attribution
- Original source & creator: [IPPrintC2](https://github.com/Diverto/IPPrintC2)

---
