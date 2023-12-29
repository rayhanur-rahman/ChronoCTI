# Case Summary

This investigation began as many do, with a malicious document delivered via email. The email and accompanying Excel file purported to be a DocuSign request, which entices the user to enable macros. This lead to Bazar being dropped on the system, which created a run key for persistence.

On the first day, after the initial activity, nothing else was seen. On the second day, we observed DNS requests to .bazar domain names (the hallmark of the Bazar malware family). The malware also executed some basic nltest domain discovery, and a short ping to a Cobalt Strike server, but no additional activity was observed.

On the third day, more communication was observed between the Bazar and Cobalt Strike infrastructure, but again, no downloads or follow-on activity was observed.

On the fourth day, Bazar pulled down a Cobalt Strike Beacon in the form of a DLL, which was executed via rundll32 and injected into various system processes. One of those processes injected into, was dllhost, which then ran various PowerSploit commands for discovery activity and dumped credentials from lsass. Shortly thereafter, the threat actors began moving laterally using multiple techniques, such as:
- Pass the Hash
- SMB executable transfer and exec
- RDP
- Remote service execution

The threat actors then continued pivoting and collecting more information about the environment. About an hour after beginning their lateral movement, they had compromised a domain controller. On that domain controller, they executed AdFind, and then dropped a custom PowerShell script named Get-DataInfo.ps1. This script looks for all active machines and queries installed software, i.e., backup software, security software, etc. We first saw this script about a year ago when threat actors deployed Ryuk ransomware across a domain. Other public data has also linked this TTP to Ryuk threat actors.

However, in this case, about 15 minutes after running the script, the threat actor dropped their access and left the environment. We do not know what caused them to leave, but we have some ideas. Based on the TTP’s of this intrusion, we assess, with medium to high confidence, that Ryuk would have been the likely ransomware deployed. Total time in the environment was around 4 days.

We recently started offering intel feeds based on different command and control infrastructure such as Cobalt Strike, Qbot, Trickbot, PoshC2, PS Empire, etc. and this feed would have alerted on the Cobalt Strike C2 in this case. If you’re interested in pricing or interested in a trial please use Contact Us to get in touch.

# analysis

# MITRE ATT&CK

Initial access to the environment was via a malicious email that entices a user to download an Excel document with macros using a DocuSign social engineering theme.

The Excel document required the user to enable content to execute. The embedded macro in the file was using an Excel 4.0 macro, which at time of execution had a detection rate of 1/63 in Virustotal.

Upon execution of the macro the file reached out to:

https://juiceandfilm[.]com/salman/qqum.php

As seen in the contents of the macro below:

From there a file was written:

C:\Users\USER\Downloads\ResizeFormToFit.exe

From here the executable then proceeds to create a new file and execute it via cmd.

Four days post initial access, a Cobalt Strike Beacon was executed via rundll32 and cmd.

# Persistence

Immediately following the execution of M1E1626.exe, a persistence mechanism was created for the file using a run key. This file was found to be a BazarBackdoor sample.

# Privilege Escalation

The use of the Cobalt Strike’s piped privilege escalation (Get-System) was used several times during the intrusion.

cmd.exe /c echo a3fed5b3a32 > \\.\pipe\3406c2

After loading the Cobalt Strike DLL, there was an almost instant injection by the process into the Werfault process.

We also see the Cobalt Strike Beacon running in the dllhost.exe process, loading PowerShell to perform PowerSploit commands in the discovery section.

Additionally via the use of YARA inspection we found Cobalt Strike running or injected into processes across the environment.


# Credential Access

Lsass was dumped using Cobalt Strike on multiple occasions. We were not able to recover any proof other than parent/child processes.

A day after initial access, Bazar initiated some discovery activity using Nltest:

cmd.exe /c nltest /domain_trusts /all_trusts

On the forth day, a Cobalt Strike Beacon was executed and then the following discovery commands were executed.
- C:\Windows\system32\cmd.exe /C net group "enterprise admins" /domain
- C:\Windows\system32\cmd.exe /C net group "domain admins" /domain

On the initial beachhead host, we also saw the Cobalt Strike Beacon initiate the following PowerShell discovery using Powersploit:
- IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:35806/'); Find-LocalAdminAccess
- IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:35585/'); Get-NetComputer -ping -operatingsystem *server*
- IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:23163/'); Get-NetSubnet

After beginning lateral movement, the threat actors used the following Window’s utilities for system profiling:
- C:\Windows\system32\cmd.exe /C systeminfo
- C:\Windows\system32\cmd.exe /C ping HOST

Once the threat actors had access to a domain controller, they ran the following PowerShell discovery:

After running that, the threat actors used nltest again to confirm domain trusts:

C:\Windows\system32\cmd.exe /C nltest /domain_trusts /all_trusts

The local time was also queried on the domain controller:

C:\Windows\system32\cmd.exe /C time

AdFind was executed using adf.bat:
- C:\Windows\system32\cmd.exe /C C:\Windows\Temp\adf\adf.bat
- adfind.exe -f "(objectcategory=person)"
- adfind.exe -f "objectcategory=computer"
- adfind.exe -f "(objectcategory=organizationalUnit)"
- adfind.exe -sc trustdmp
- adfind.exe -subnets -f (objectCategory=subnet)
- adfind.exe -f "(objectcategory=group)"
- adfind.exe -gcb -sc trustdmp

Finally, the following collection of files were dropped on the domain controller: 
- C:\Users\USER\Desktop\info\7z.exe
- C:\Users\USER\Desktop\info\comps.txt
- C:\Users\USER\Desktop\info\Get-DataInfo.ps1
- C:\Users\USER\Desktop\info
- etscan.exe

C:\Users\USER\Desktop\info\start.bat start.bat was executed with the following: C:\Windows\system32\cmd.exe /c ""C:\Users\USER\Desktop\info\start.bat"" This script contents show it to be a wrapper for the PowerShell script Get-DataInfo.ps1 The contents of Get-DataInfo.ps1 show a detailed information collector to provide the threat actor with very specific details of the environment. This includes things like disk size, connectivity, antivirus software, and backup software. The Ryuk group has used this script for at least a year as we’ve seen them use it multiple times.

This script and files are available @ https://thedfirreport.com/services/

# Lateral Movement

The threat actors deployed several types of lateral movements over the course of the intrusion.

The first observed method was the use of a remote service using PowerShell which injected into winlogon.

The threat actors also leveraged SMB to send Cobalt Strike Beacon executables to $ADMIN shares and again execute them on the remote systems via a service. SMB Beacon as its called in Cobalt Strike.

Pass the Hash was also used by the attackers while pivoting through the environment.

RDP was also leveraged by the attacker via their Cobalt Strike Beacons.

# Bazar:

Communication over DNS to .bazar domains.

# Cobalt Strike:

# MITRE ATT&CK DATASET
Spearphishing Link – T1566.002

User Execution – T1204

Command-Line Interface – T1059

Domain Trust Discovery – T1482

Pass the Hash – T1550.002

Remote Desktop Protocol – T1021.001

SMB/Windows Admin Shares – T1021.002

Domain Account – T1087.002

Domain Groups – T1069.002

System Information Discovery – T1082

System Time Discovery – T1124

Security Software Discovery – T1518.001

Software Discovery – T1518

Rundll32 – T1218.011

DNS – T1071.004

Commonly Used Port – T1043

Service Execution – T1569.002

PowerShell – T1059.001

Registry Run Keys / Startup Folder – T1547.001

Internal case #1013

Share this: Twitter

LinkedIn

Reddit

Facebook

WhatsApp

