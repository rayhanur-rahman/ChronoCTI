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

This activity appears to have failed due to Windows Defender activity.

IcedID initially performed some discovery of the local system and the domain.


Later, Cobalt Strike beacons were used to perform discovery of the system and domain.

A discovery batch script that runs ADFind.exe was dropped to the system.

ADFind.exe was executed by the discovery batch script.

PowerView was used to discover local administrator access in the network. The Cobalt Strike beacon itself was used as a proxy to connect and retrieve the PowerView file.

Cobalt Strike was injected into the winlogon.exe process and used to perform further discovery.

The following shows the decoded PowerShell commands used by Cobalt Strike to perform discovery.

# Lateral Movement

Lateral Movement chain #1 – The attacker was able to successfully move from workstation #1 to workstation #2 via service execution. The attacker tried to replicate this movement technique towards two servers but were stopped when their Cobalt Strike PowerShell payloads were nabbed by AV.

Lateral Movement chain #2 – Another attempt was made to move from workstation #1 to one of the servers, but this attempt was also thwarted by AV. Just like the previous attempt, a remote service was created, however, this time a DLL payload was used rather than a PowerShell payload.

Lateral Movement chain #3 – Privileges were escalated to SYSTEM on Workstation #1 via the Cobalt Strike ‘GetSystem’ command which makes use of named pipes. A Cobalt Strike DLL was copied to a server and executed using WMI. This activity was observed on three servers, including the Domain Controller.

The logs demonstrate multiple connections from IcedID to their C2 servers, including aws.amazon[.]com for connectivity checks.


The Cobalt Strike beacons also make use of multiple C2 servers on the public internet.

Cobalt Strike Configs:
