# Case Summary

This intrusion once again highlights common tools in-use today for Initial Access and Post-Exploitation. Our intrusion starts when a malicious Word document is executed that drops and executes an HTA file. This HTA file is used to download IcedID in the form of a JPG file. This file is actually a Windows DLL file, which is executed via regsvr32 (1st stage IcedID).

IcedID downloads some 2nd stage payloads and loads the DLL into memory with rundll32 (miubeptk2.dll – IcedID – used for persistence) and regsvr32 (ekix4.dll – Cobalt Strike beacon – privilege escalation via fodhelper) to pillage the domain. Service Execution (T1569.002) via Cobalt Strike Beacon was used throughout the intrusion for privilege escalation.

WMIC was utilized to launch ProcDump in an attempt to dump lsass.exe. WMIC was also used to perform discovery of endpoint security software. A flurry of other programs were used to perform discovery within the environment including nltest.exe, adfind.exe via adf.bat, and net.exe. Command and Control was achieved via IcedID and Cobalt Strike.

There were numerous attempts at lateral movement via Cobalt Strike beacons, with limited success. Ultimately, the threat actors were unsuccessful when AV snagged their attempts to move to certain servers.

Particular to this case, we saw an eleven day gap in activity. While command and control never left, activity–other than beaconing, ceased. On day eleven, a new Cobalt Strike infrastructure was introduced to the environment with the threat actor displaying new techniques that were successful in moving laterally, where the initial activity failed.

This may indicate a hand off to a new group, or the original actor may have returned, either way, we did not see a final action on objectives.

# Analysis

Initial access for this intrusion was via a malicious attachment “order 06.21.doc”. The attachment was a Microsoft Word document that drops a malicious HTA file “textboxNameNamespace.hta”.

Analysis of the encoded HTA file revealed that a file named textboxNameNamespace.jpg was downloaded from http://povertyboring2020b[.]com. This file’s extension is misleading as the file is a Windows DLL.

The HTA file is written to:

C:\users\public

The HTA file when executed downloads a file named “textboxNameNamespace.jpg”, which is actually an IcedID DLL file responsible for the first stage.

Through the same HTA file, the IcedID first stage DLL file is executed via regsvr32.exe.

IcedID executes via rundll32, dropping DLL files related to both the IcedID second stage and Cobalt Strike beacons.

After the initial compromise, the threat actors went silent for eleven days. After that period of time, a new Cobalt Strike beacon was run through IcedID and sent forth to a second phase of their activities.

# Persistence

IcedID establishes persistence on the compromised host using a scheduled task named ‘{0AC9D96E-050C-56DB-87FA-955301D93AB5}’ that executes its second stage. This scheduled task was observed to be executing hourly under the initially compromised user.

# Privilege Escalation

Ekix4.dll, a Cobalt Strike payload was executed via fodhelper UAC bypass.

Additional Cobalt Strike payloads were executed with the same fodhelper UAC bypass technique.

Cobalt Strike payloads were used to escalate privileges to SYSTEM via a service created to run a payload using rundll32.exe as the LocalSystem user. This activity was observed on workstations, a file server, and a backup server.

GetSystem was also used by the threat actors.

# Credential Access

The threat actors were seen using overpass the hash to elevate privileges in the Active Directory environment via Mimikatz style pass the hash logon events, followed by subsequent suspect Kerberos ticket requests matching network alert signatures.

ATTACK [PTsecurity] Overpass the hash. Encryption downgrade activity to ARCFOUR-HMAC-MD5",10002228

Using these credentials, the threat actors attempted to use a Cobalt Strike beacon injected into the LSASS process to execute WMIC, which executed ProcDump on a remote system to dump credentials.

cmd.exe /C wmic /node:"servername.domainname" process call create "C:\PerfLogs\procdump.exe -accepteula -ma lsass C:\PerfLogs\lsass.dmp"

This activity appears to have failed due to Windows Defender activity.

IcedID initially performed some discovery of the local system and the domain.
- WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get * /Format:List
- ipconfig /all systeminfo
- net config workstation
- net view /all /domain nltest /domain_trusts /all_trusts
- nltest /domain_trusts
- net view /all
- net group "Domain Admins" /domain

Later, Cobalt Strike beacons were used to perform discovery of the system and domain.
- cmd.exe /C systeminfo 
- cmd.exe /C nltest /dclist:DOMAIN.local 
- cmd.exe /C nltest /domain_trusts /all_trusts IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:55869/'); Find-LocalAdminAccess

A discovery batch script that runs ADFind.exe was dropped to the system.

ADFind.exe was executed by the discovery batch script.
- cmd.exe /C C:\Windows\Temp\adf\adf.bat
- adfind.exe -f "(objectcategory=person)"
- adfind.exe -f "(objectcategory=organizationalUnit)"
- adfind.exe -f "objectcategory=computer"
- adfind.exe -sc trustdmp
- adfind.exe -subnets -f (objectCategory=subnet)
- adfind.exe -f "(objectcategory=group)"
- adfind.exe -gcb -sc trustdmp

PowerView was used to discover local administrator access in the network. The Cobalt Strike beacon itself was used as a proxy to connect and retrieve the PowerView file.

Cobalt Strike was injected into the winlogon.exe process and used to perform further discovery.
- cmd.exe /C net group "domain Admins" /domain 
- cmd.exe /C net group "Enterprise Admins" /domain 
- cmd.exe /C ping WORKSTATION 
- cmd.exe /C net view \\WORKSTATION /all 
- cmd.exe /C net view \\DOMAINCONTROLLER /all 
- cmd.exe /C dir /s

The following shows the decoded PowerShell commands used by Cobalt Strike to perform discovery.

# Lateral Movement

Lateral Movement chain #1 – The attacker was able to successfully move from workstation #1 to workstation #2 via service execution. The attacker tried to replicate this movement technique towards two servers but were stopped when their Cobalt Strike PowerShell payloads were nabbed by AV.

Lateral Movement chain #2 – Another attempt was made to move from workstation #1 to one of the servers, but this attempt was also thwarted by AV. Just like the previous attempt, a remote service was created, however, this time a DLL payload was used rather than a PowerShell payload.

Lateral Movement chain #3 – Privileges were escalated to SYSTEM on Workstation #1 via the Cobalt Strike ‘GetSystem’ command which makes use of named pipes. A Cobalt Strike DLL was copied to a server and executed using WMI. This activity was observed on three servers, including the Domain Controller.

The logs demonstrate multiple connections from IcedID to their C2 servers, including aws.amazon[.]com for connectivity checks.


The Cobalt Strike beacons also make use of multiple C2 servers on the public internet.

Cobalt Strike Configs:

# MITRE ATT&CK DATASET
Spearphishing Attachment – T1566.001

Malicious File – T1204.002

Signed Binary Proxy Execution – T1218

Windows Management Instrumentation – T1047

Command and Scripting Interpreter – T1059

PowerShell – T1059.001

Windows Command Shell – T1059.003

Service Execution – T1569.002

Windows Service – T1543.003

Bypass User Account Control – T1548.002

OS Credential Dumping – T1003

System Information Discovery – T1082

Security Software Discovery – T1518.001

Domain Trust Discovery – T1482

Network Share Discovery – T1135

SMB/Windows Admin Shares – T1021.002

Lateral Tool Transfer – T1570

Application Layer Protocol – T1071
