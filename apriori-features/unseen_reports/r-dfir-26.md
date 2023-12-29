# Case Summary

In this intrusion, we observed a number of interesting techniques being leveraged by the threat actors. The threat actors were able to go from initial access to the deployment of Conti ransomware in a matter of hours. The Conti operators chose to wait a couple days before ransoming the environment. Even though most of the techniques aren’t new or advanced, they have proven to be effective. We have observed the same techniques in other intrusions and understanding these techniques will allow defenders to disrupt such intrusion activity and deny it in their own networks.

The Trickbot payload came from a phishing campaign associated with BazarCall, delivering weaponized XLSB files. Upon execution, certutil.exe was copied to %programdata% and renamed with random alphanumeric characters. Certutil was used to download and load the Trickbot DLL into memory. Trickbot was automatically tasked to inject into the wermgr.exe process and use its well-known “pwgrab” module to steal browser credentials. As part of further automated tasking, Trickbot performed an initial reconnaissance of the environment using native Windows tools such as nltest.exe and net.exe.

First hands-on activity was observed two hours after initial compromise, when Trickbot downloaded and executed Cobalt Strike Beacons. To guarantee execution on the beachhead host, multiple payloads were used. One of the Cobalt Strike Beacons was the same payload and command and control infrastructure as used in a prior case. The initial access method for that case was IcedID, which shows that the threat actors utilize various initial access methods to get into environments and accomplish their goals.

Once access through Cobalt Strike was established, the threat actors immediately proceeded with domain enumeration via Nltest, AdFind, BloodHound, and PowerSploit. Presence was then expanded on the beachhead by using a PowerShell loader to execute additional Beacons.

We observed the threat actors having technical issues. One example being with a Beacon unsuccessfully injecting into a process. It is unclear if this was an untrained actor, or there was a configuration issue.

Fifteen minutes after domain enumeration, we observed successful lateral movement to two endpoints on the network. Ten minutes after lateral movement, a PowerShell Cobalt Strike loader executed as a service on a server. Even though the execution was not successful, the threat actors kept trying, a total of eight times, until it finally worked. Windows Defender real-time monitoring was then disabled, the LSASS.exe process was dumped using SysInternals ProcDump, and privilege was escalated to “SYSTEM” using named pipe impersonation.

Almost four hours after initial execution, the threat actors pivoted to a domain controller using domain admin credentials and executed a Cobalt Strike Beacon. Once they had domain controller access, ntdsutil was used to take a snapshot of “ntds.dit”, saved under “C:\Perflogs\1”, for offline password hash extraction. This is a technique that we don’t see very often, but effective nevertheless.

The threat actors then reran many of the same discovery techniques that were previously executed on the beachhead, including AdFind and BloodHound. This was the last observed hands-on-keyboard activity for awhile.

Two days later, the Cobalt Strike Beacon on the domain controller was once again actively engaged by the threat actors. Psexec, with two separate batch files, were used to execute Conti ransomware on all domain-joined Windows hosts. This final deployment was executed around 6:45 UTC on a Monday morning.

From the point the threat actors returned, to ransom deployment, it was less than 30 minutes. This would give defenders little time to act if they had not identified and contained the activity from the first day of the Trickbot infection.

# analysis

# Initial Access

The initial access was achieved as a result of the user opening what appeared to be a benign workbook, a lure, requiring little user interaction.

The workbook contained hidden and password protected worksheets, these were malicious. Module functions also indicated code designed to obfuscate and hide true values and functions.

This document and the following DLL were noted as being associated to a BazarCall campaign by @ffforward.




# Execution

From the xlsb document, the following execution chain occurs. Including copying the Windows CertUtil program and using that to collect further Trickbot payloads.

We observed a second stage execution using regsvr32 to load a DLL from the user’s AppData\Local\Temp folder.

Almost immediately an outbound IPv4 address lookup was requested via HTTP. This is usually undertaken to identify the compromised environment, and to facilitate C2. The user agent refers to Curl – and used again for another stage of the intrusion.

On the beachhead, multiple executables were saved in a temp directory and then pushed into memory by TrickBot process “wermgr.exe”. The executables were identified as Cobalt Strike and communicated over port 443 to C2 88.80.147[.]101.

A PowerShell download cradle was then used to execute Cobalt Strike Beacon in memory:

# Privilege Escalation

Named pipe impersonation was used to escalate to SYSTEM privileges – a common Cobalt Strike capability:

We observed several attempts by the threat actor trying to escalate to SYSTEM – ultimately succeeding, as evident in several new services running under the Local SYSTEM context:

Service creation events System Event ID 7045, coupled with unusual commands and service names are a strong indication of privilege escalation activity. RedCanary provided useful background on GetSystem capabilities of offensive security tools and methods of detection.

# Defense Evasion

Trickbot made extensive use of process injection to hide in benign operating system processes. It first injected into wermgr.exe and then later into svchost.exe.

Another defense evasion technique employed by Cobalt Strike, was to disable Windows Defender. WMIC was used to remotely execute ‘def.bat’. The contents of ‘def.bat’:

Set-MpPreference -DisableRealtimeMonitoring $true

# Credential Access

Trickbot made use of esentutl to gather MSEdge history, webcache, and saved passwords using TrickBot’s “pwgrab” module.

LSASS was dumped remotely using ProcDump. The execution took place from the beachhead using WMIC.

“Ntdsutil” was used to take a snapshot of ntds.dit and save it under “C:\Perflogs\1”. This technique is useful for offline password hash extraction. This activity occurred twice. The same batch file, ‘12.bat’, was first executed in the context of SYSTEM; and secondly, in the context of a domain admin user. The contents of ‘12.bat’:

ntdsutil "ac in ntds" "ifm" "cr fu C:\Perflogs\1" q q

# Discovery

Net and Nltest commands were used to gather network and domain reconnaissance. During the intrusion, this activity was seen multiple times, on multiple hosts.

Other discovery commands included:
- systeminfo
- nltest /dclist:<hidden>.local
- nltest /domain_trusts /all_trusts
- net localgroup Administrators
- whoami.exe" /groups

AdFind.exe and adf.bat were uploaded to the beachhead. adf.bat was used to execute:
- adfind.exe -f "(objectcategory=person)"
- adfind.exe -f "(objectcategory=organizationalUnit)"
- adfind.exe -f "objectcategory=computer"
- adfind.exe -gcb -sc trustdmp
- adfind.exe -f "(objectcategory=group)"
- adfind.exe -subnets -f (objectCategory=subnet)
- adfind.exe -sc trustdmp

AdFind results were written to the following locations:
- C:\Windows\Temp\adf\ad_group.txt
- C:\Windows\Temp\adf\trustdmp.txt
- C:\Windows\Temp\adf\subnets.txt
- C:\Windows\Temp\adf\ad_ous.txt
- C:\Windows\Temp\adf\ad_computers.txt
- C:\Windows\Temp\adf\ad_users.txt

On the beachhead, Cobalt Strike executed BloodHound in memory. The results were saved in:

"C:\Windows\Temp\Dogi"

BloodHound was later executed on the domain controller as well. Once again the results were stored in:

"C:\Windows\Temp\Dogi"

PowerSploit was loaded into memory on the DC and the following functions were used:
- Get-NetSubnet
- Get-NetComputer –ping

An encoded PowerShell command was executed on the domain controller to enumerate all AD joined hosts and save the results to:

"C:\Users\AllWindows.csv"

The decoded PowerShell command:

# Lateral Movement

From the beachhead, WMIC was used to remotely execute ‘165.bat’ on two other hosts.

Multiple failed attempts were observed prior to the successful execution of a PowerShell Cobalt Strike loader via a service with “SYSTEM” privileges.

Decoded Cobalt Strike shellcode, using Cyber Chef recipe: https://github.com/mattnotmax/cyberchef-recipes#recipe-28—de-obfuscation-of-cobalt-strike-beacon-using-conditional-jumps-to-obtain-shellcode

# Command and Control

Multiple C2 channels were established, some were persistent whilst others appeared to be single purpose – used for payload retrieval or fallback C2. Persistent C2 activity was Cobalt Strike. The beachhead had multiple C2 channels, two of which were unique. We assess that the threat actors were ensuring a loss of a single source C2 wouldn’t result in losing all C2 to the compromised environment.

We observed a payload being retrieved from a unique IPv4 address. An indication that the threat actors were keeping C2 channels independent from payload delivery/retrieval.

Using the Curl 7.74.0 user agent:

Analysis of this binary, shows C2 activity to the following:

The binary has an unusual PDB string that indicates obfuscation:

The two persistent C2 channels were analyzed to determine the Cobalt Strike configuration. Each C2 channel was configured as follows:


# Exfiltration

As part of the discovery stage, we observed data being exfiltrated. The data ranged from host discovery, running processes, and user accounts:

Entire AD forest data – including usernames , DC configuration, and machine enumeration:

# Impact

When, the threat actors returned two days later, the final payloads were staged by the threat actors on a domain controller in the following location:

C:\share$

Two batch scripts were executed on the domain controller to automate ransomware deployment via PSExec. The first was “_COPY.bat”, to stage the CONTI ransomware payload on all domain-joined computers. The second was “_EXE.bat”, to execute the staged CONTI payloads.

The batch scripts ran as expected a set of copy commands and then executed the Conti payload using psexec.

Files were then encrypted with the following extension [KCRAO]:

A readme.txt file was created in each folder:

The content of readme.txt:


# MITRE ATT&CK DATASET
Phishing: Spearphishing Attachment – T1566.001

Signed Binary Proxy Execution: Regsvr32 – T1218.010

Impair Defenses: Disable or Modify Tools – T1562.001

Domain Trust Discovery – T1482

OS Credential Dumping: LSASS Memory – T1003.001

System Owner/User Discovery – T1033

Command and Scripting Interpreter: PowerShell – T1059.001

Data Staged: Local Data Staging – T1074.001

System Information Discovery – T1082

Account Discovery: Local Account – T1087.001

Account Discovery: Domain Account – T1087.002

OS Credential Dumping: NTDS – T1003.003

Windows Management Instrumentation – T1047

Browser Bookmark Discovery – T1217

Data Encrypted for Impact – T1486

Remote Services: SMB/Windows Admin Shares – T1021.002

MITRE Software

AdFind – S0552

BloodHound – S0521

Cobalt Strike – S0154

Systeminfo – S0096

Net – S0039

Nltest – S0359

Esentutl – S0404

PsExec – S0029

Cmd – S0106

References

TrickBot Malware Alert (AA21-076A), US CERT – https://us-cert.cisa.gov/ncas/alerts/aa21-076a

Advisory: Trickbot, NCSC – https://www.ncsc.gov.uk/news/trickbot-advisory

Trickbot Still Alive and Well, The DFIR Report – https://thedfirreport.com/2021/01/11/trickbot-still-alive-and-well/

Hunting for GetSystem in offensive security tools, RedCanary – https://redcanary.com/blog/getsystem-offsec/

TrickBot Banking Trojan, ThreatPost – https://threatpost.com/trickbot-banking-trojan-module/167521/

Internal case #4641

Share this: Twitter

LinkedIn

Reddit

Facebook

WhatsApp

