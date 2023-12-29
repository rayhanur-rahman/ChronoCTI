# Case Summary

We assess, with moderate confidence, the Trickbot DLL that we executed was originally delivered via a malicious Office document. The threat actors were observed leveraging Trickbot and Cobalt Strike for C2 communication. They began their discovery by running net and nltest commands as well as PowerView domain discovery modules. Minutes later, Lazagne (“retrieve lots of passwords”) was executed using the “all” switch. A registry value was set to enable storing logon credentials in plaintext in memory (WDigest), likely to facilitate future activity as the host was not restarted for this change to take effect.

Before the threat actors departed the network, they successfully accessed the LSASS process and retrieved credentials from memory. No lateral movement or execution on mission was observed.

# analysis

# MITRE ATT&CK

We assess with moderate confidence that this DLL was dropped by a malicious Office document.

Trickbot (click.php.dll) was manually executed on a single endpoint.

Source: https://tria.ge/210412-wmdnkzp5la

Trickbot, from its injected wermgr process, spawned a command process to then run a PowerShell Cobalt Strike Beacon.

Reviewing the above PowerShell code, we can extract the shellcode to discover the IP and User-agent string, the beacon will communicate with.

Getting the IP and port using scdbg.

The threat actor also executed a second Cobalt Strike Beacon (wsuC3C.tmp) using the injected wermgr.exe process.

rundll32.exe C:\Users\redacted\AppData\Local\Temp\wsuC3C.tmp,ControlUnitSpeed

# Persistence

A scheduled task was created to keep the Trickbot malware persistent on the system.

C:\Windows\system32\rundll32.exe" "C:\Users\redacted\AppData\Roaming\DownloadMngNet5353711913\xxclickdr.dwn",#1

Trickbot injected into wermgr.exe processes and used this for communication to command and control infrastructure.

# Credential Access

Lazagne was used with the “all” switch, which runs all modules.

Below we can see registry hives being saved to disk.

LSASS was accessed by rundll32, but we did not see anything written to disk.

Trickbot was used to enable the storage of clear text credentials (WDigest) by setting UseLogonCredential to 1.


The following net commands were used by the threat actor from the injected Trickbot process.
- net config workstation
- net view /all
- net view /all /domain
- net group “Domain Computers” /domain

The following nltest commands were used by the threat actor from the injected Trickbot process.
- nltest / domain_trusts
- nltest / domain_trusts / all_trusts

PowerView modules were also used by the threat actor executed from the Cobalt Strike beacons.
- Get- DomainSearcher
- Get- NetComputer
- Get- NetDomain

The local network was scanned for port 445/SMB.

ipconfig was used to show all IP info.

ipconfig /all

# Trickbot

# MITRE ATT&CK DATASET
User Execution – T1204

Command and Scripting Interpreter – T1059

PowerShell – T1059.001

Windows Command Shell – T1059.003

Domain Trust Discovery – T1482

Network Service Scanning – T1046

Remote System Discovery – T1018

System Network Configuration Discovery – T1016

System Information Discovery – T1082

Process Injection – T1055

Credentials from Web Browsers – T1555.003

OS Credential Dumping – T1003

LSASS Memory – T1003.001

Exfiltration Over C2 Channel – T1041

Non-Standard Port – T1571