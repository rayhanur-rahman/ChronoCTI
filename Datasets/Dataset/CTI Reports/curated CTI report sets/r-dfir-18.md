# Case Summary

We did not observe the initial access for this case but assess with medium to high confidence that a malicious email campaign was used to deliver an Excel (xls) document. Following the opening of the xls document, the initial Qbot DLL loader was downloaded and saved to disk. Interestingly, the name of the DLL contained a .html extension to disguise the portable executable nature of the payload. Once executed, the Qbot process creates a scheduled task to elevate itself to system.

Qbot injected into many processes but one favorite in this intrusion, was Microsoft Remote Assistance (msra.exe). Within minutes of landing on the beachhead, a series of discovery commands were executed using Microsoft utilities. Around the same time, LSASS was access by Qbot to collect credentials from memory.

Thirty minutes after initial access, Qbot was observed collecting data from the beachhead host including browser data and emails from Outlook. At around 50 minutes into the infection, the beachhead host copied a Qbot dll to an adjacent workstation, which was then executed by remotely creating a service. Minutes later, the beachhead host did the same thing to another adjacent workstation and then another, and before we knew it, all workstations in the environment were compromised.

Qbot followed it’s normal process on each machine. Servers were not accessed in this intrusion. After this activity, normal beaconing occurred but no further actions on objectives were seen.

# analysis
We assess with medium to high confidence that the QBot infection was delivered to the system via a malspam campaign through a hidden 4.0 Macro’s in Excel.

We believe this is the xls file that lead to the Qbot infection, due to the overlap in time period, download url, and file name.

# Execution

The QBot dll was executed on the system and shortly after, injected into the msra.exe process.

# Privilege Escalation

A scheduled task was created by Qbot to escalate to SYSTEM privileges. This scheduled task was created by the msra.exe process, to be run only once, a few minutes after its creation.

"schtasks.exe" /Create /RU "NT AUTHORITY\SYSTEM" /tn juqpxmakfk /tr "regsvr32.exe -s \"C:\Users\REDACTED\ocrafh.html\"" /SC ONCE /Z /ST 14:20 /ET 14:32

# Defense Evasion

QBot was observed injecting into msra.exe process on multiple systems.

Multiple folders were added to the Windows Defender Exclusions list in order to prevent the Qbot dll placed inside of it from being detected. The newly dropped dll was then executed and process injected into msra.exe.

Qbot used reg.exe to add Defender folder exceptions for folders within AppData and ProgramData.
- C:\Windows\system32\reg.exe ADD \"HKLM\SOFTWARE\Microsoft\Microsoft Antimalware\Exclusions\Paths\" /f /t REG_DWORD /v \"C:\ProgramData\Microsoft\Oweboiqnb\" /d \"0\" 
- C:\Windows\system32\reg.exe ADD \"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\" /f /t REG_DWORD /v \"C:\ProgramData\Microsoft\Oweboiqnb\" /d \"0\"

dll files dropped by Qbot, were deleted after injection into msra.exe.

# Credential Access

LSASS was accessed by Qbot, with the intention of accessing credentials. This can be observed through the Sysmon process access event, indicating the GrantedAccess value of 0x1410 .

Additional evidence of LSASS access was visible in API calls from Qbot injected processes to LSASS.

# Discovery

The following discovery commands where observed coming from the Qbot processes. These commands where executed on the beachhead system along with other workstations compromised through lateral movement.
- whoami /all 
- arp -a 
- cmd /c set 
- arp -a 
- net view /all 
- ipconfig /all 
- net view /all 
- nslookup -querytype=ALL - timeout = 10 _ldap._tcp.dc._msdcs.REDACTED 
- route print 
- net share 
- net1 localgroup 
- net localgroup 
- netstat -nao

# Lateral Movement

Qbot moved laterally to all workstations in the environment by copying a dll to the machine and then remotely creating a service to execute the Qbot dll. The services created had the DeleteFlag set causing the service to be removed upon reboot.

The following occurred on each workstation:

The lateral movement activity from the beachhead host was rapid and connections were seen across all workstations in the network. A view from the memory of the beachhead host shows the injected msra process connecting to hosts across the network.

The service creations were also observed via event id 7045 across all hosts.

# Collection

Qbot is widely known to steal emails with the intention of collecting information and performing email thread hijacking.

Email data will be collected and stored in 1 of 2 locations.
- C:\Users\Username\EmailStorage_ComputerHostname-Username_TimeStamp
- C:\Windows\system32\config\systemprofile\EmailStorage_ComputerHostname-Username_TimeStamp

Once exfiltrated from the system this folder is then deleted as seen below
- cmd.exe /c rmdir /S /Q "C:\Users\REDACTED\EmailStorage_REDACTED-REDACTED_REDACTED" 
- cmd.exe /c rmdir /S /Q "C:\Windows\system32\config\systemprofile\EmailStorage_REDACTED-REDACTED_REDACTED"

Collection of browser data from Internet Explorer and Microsoft Edge was also observed with Qbot using the built-in utility esentutl.exe.

esentutl.exe /r V01 /l"C:\Users\REDACTED\AppData\Local\Microsoft\Windows\WebCache" /s"C:\Users\REDACTED\AppData\Local\Microsoft\Windows\WebCache" /d"C:\Users\REDACTED\AppData\Local\Microsoft\Windows\WebCache"

# Command and Control

Qbot uses a tiered infrastructure, often using other compromised systems as first tier proxy points for establishing a constantly changing list of C2 endpoints. You can review a in-depth analysis of the modules of this malware in this Checkpoint report.

With this type of setup the list of C2 from October 2021, has in large rotated out of use. To keep up to date on current Qbot C2 endpoints you can check out our Threat Feed & All Intel service as we track these changing lists daily.

Qbot does use SSL in it’s C2 communication but does not rely soley on port 443 for communication, in the case investigated here the following ports were found in the extracted C2 configuration.


Qbot uses SSL and while the domains do not resolve, they follow a pattern and are detectable with several Suricata ETPRO signatures.


# Impact

The final actions of the threat actor were not observed, however, the data exfiltrated from the network could be used to conduct further attacks or sold to 3rd parties.



# MITRE ATT&CK DATASET
Rundll32 – T1218.011

Scheduled Task – T1053.005

Disable or Modify Tools – T1562.001

Process Injection – T1055

LSASS Memory – T1003.001

Network Share Discovery – T1135

Local Groups – T1069.001

Local Account – T1087.001

System Network Connections Discovery – T1049

System Network Configuration Discovery – T1016

Internet Connection Discovery – T1016.001

Email Collection – T1114

Credentials from Web Browsers – T1555.003

Commonly Used Port – T1043

Application Layer Protocol – T1071

Web Protocols – T1071.001

Exfiltration Over C2 Channel – T1041

Internal case #7685