# Case Summary

This case started with an IcedID infection from a malware campaign as reported by Myrtus. As with most commodity malware we see, IcedID executes the initial discovery commands and then exfiltrates the results via the C2 channel. If threat actors find the organization to be of interest, they will launch the next phase. In some cases, there might be different threat actor groups working on different phases of the attack. In this instance, the threat actors instructed IcedID to download and execute the next stage malware two hours after the initial compromise. The payload was a Cobalt Strike Beacon in the form of a DLL.

Upon initial execution, Cobalt Strike ran some discovery commands before injecting into the LSASS process to steal cached credentials. The threat actors did not waste any time, and within four minutes, they gained administrative credentials then began searching for the domain controllers. Once the domain controllers were identified, they used Cobalt Strike’s “jump psexec_psh” capability, which creates a Windows service that executes a Beacon executable to move laterally. Having gained access to the domain controllers, the attackers downloaded and executed AdFind to collect further information about the domain.

The attacker’s preferred scripting various parts of the intrusion via batch scripts. They had a script for persistence, defense evasion and execution tasks. A complete list of those scripts came from hxxps://styservice[.]com as we shared with the community in this tweet thread. The first batch script we saw was to schedule a task which would execute a command to load a Cobalt Strike Beacon into memory using regsvr32. This persistence mechanism was only seen on the domain controllers and one other critical server.

The lateral movement and execution of batch scripts continued with the operators expanding their network footprint. It is worth mentioning that it appears they chose which hosts to pivot to by assessing the importance implied by their hostnames. After landing on an “important” host, the first task was to execute various batch scripts to disable antivirus programs. On one host, common backup utilities were also disabled.

Three hours into the intrusion and the attackers had deployed Beacons across various hosts on the network. Despite that, they deployed another Beacon using a PowerShell loader method, this time on the beachhead. They used this Beacon to run PowerView’s Invoke-ShareFinder module in an effort to discover potentially interesting directories and files. BloodHound was also executed as part their reconnaissance activities. At the same time, the operators performed an exhaustive port scan on the servers they had earlier identified to be “important”. Minutes away from meeting their final objective, the operators manually searched for files and directories of interest for the second time.

Around 23 hours after the initial intrusion, the threat actors moved towards their final objective of deploying XingLocker ransomware. The deployment took place via wmic and batch scripts. We did not observe any overt exfiltration of data; however, it is possible that the threat actors used Cobalt Strike to transmit sensitive data.

# analysis

The IcedID infection came as a result of a phishing campaign as reported by Myrtus on Twitter.

Initial IcedID was executed on the beachhead using regsvr32.exe



Automated analysis of this IcedID sample extracts the following configuration for the staging server:


IcedID core analysis show additional C2 infrastructure as per this sample:

gsterangsic .buzz oscanonamik .club riderskop .top iserunifish .club

# Execution

Upon the execution of the IcedID sample, we observed a download and execution of a malicious DLL ikaqkk.dll :



Below is a screenshot of packet where we can spot the GZIPLOADER downloading the first stage from the C2:



A detailed GZIPLOADER analysis from Binary Defense is available here.

The DLL was then executed using rundll32.exe one second later:

rundll32.exe "C:\Users\REDACTED\AppData\Local\REDACTED\ikaqkk.dll", update / i : "TimberMule\license.dat"

Cobalt strike Beacon DLLHost.exe was downloaded and loaded via process hollowing a few hours after the initial IcedID execution:



The threat actors connected to the machine to run the first discovery commands using Cobalt Strike Beacon. The threat actors then downloaded an additional Cobalt Strike Beacon kaslose.dll via curl and executed it via regsvr32 :



The Threat actors also executed HTA and PowerShell loader to load Cobalt Strike Beacon in memory on beachhead:



# Persistence

# IcedID Persistence

Upon IcedID execution, a scheduled task named {3D0CCC72-D85D-7A63-8C0A-66CF5BAFD686} was created. The task was scheduled to execute every hour:



The new scheduled task was registered under EID 106 as seen below. (EIDs: 106,200,201 “Microsoft-Windows-TaskScheduler\Operational.evtx”)

Correlating this with Process Execution logs from MDE, shows that the task was executing the IcedID downloaded DLL:



# Cobalt Strike Persistence

While analyzing this intrusion, we observed further persistence via scheduled tasks associated with post-exploitation activities.

This scheduled task with name HpSupport executed a Cobalt Strike Beacon kaslose64.dll both on the Domain Controller and the File Server:

On the File Server, the same Scheduled task was created with a slightly different name:



The star.bat script contained the following lines in both cases:

! echo OFF regsvr32 C:\users\ public \music\kaslose64.dll

# Defense Evasion

# Process Injection: Process Hollowing

IcedID reached out to 37.120.222[.]100:8080 to download and load Cobalt Strike Beacon via process hollowing technique:



The threat actors executed a 1698 line batch script kasper.bat on a file server, which kills multiple processes using taskill, stops/disables several services using net stop and sc config and disables a number of security tools using WMI.



Here is an extract from the kasper.bat script:

Disabling Windows Defender using multiple techniques

The threat actors executed three other scripts named fed1.bat , fed2.bat and fed3.bat using PowerShell and manipulating several registry keys to disable Windows Defender.

Content of fed1.bat script:

Content of fed2.bat script:

Content of fed3.bat script:


It appears that the information from these 3 scripts were lifted from the first revision of Revisions · quick-disable-windows-defender.bat · GitHub. Fed1 is half of that batch file and Fed2 is the other half. Fed3 is a complete copy. This tells us that the threat actor was not aware of what was in these scripts or else they wouldn’t have ran fed1/fed2 and fed3 considering they do the same thing.

# Credential Access

The threat actors injected into a high privileged process and then access cached credentials from LSASS:



Related named pipe activity based on Cobalt Strike patterns for using Mimikatz Pass-The-Hash function to run local and remote commands. The named pipe was used to pass the results back to the Beacon process.

Windows EID: 4673 – A privileged service was called:



# Discovery

# IcedID initial Environment Discovery

Several discovery commands executed from IcedID after the initial execution:
- ipconfig / all 
- cmd .exe /c chcp >&2
-  WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get * /Format:List 
-  systeminfo 
-  net config workstation 
-  nltest /domain_trusts 
-  nltest /domain_trusts /all_trusts 
-  net view / all /domain 
-  net view / all 
-  net group "Domain Admins" /domain

# Cobalt Strike Beacon Discovery

Cobalt Strike’s appino Beacon, ran discovery commands upon initial execution:



cmd.exe /C ping -n 1 <redacted> cmd.exe /C ping -n 1 <redacted> cmd.exe /C nltest /domain_trusts&nltest /dclist:&c:\windows\sysnative
ltest /domain_trusts&c:\windows\sysnative

ltest /dclist: cmd.exe /C netstat -a -n -p tcp | find "ESTAB" cmd.exe /C net group "domain Admins" /DOMAIN cmd.exe /C net group "Domain Computers" /DOMAIN cmd.exe /C ipconfig /all

# Active Directory Domain Discovery

Discovering domain controllers prior to pivoting:



After discovering and pivoting to the Domain Controller, threat actors used both AdFind and BloodHound to explore the Active Directory Domain.

Executing Adfind on the Domain Controller:



Evidence of BloodHound execution on the Domain Controller:



The threat actors also executed PowerView Invoke-ShareFinder module on the beachhead host:


Decoded command:

IEX (New- Object Net.Webclient).DownloadString( 'http://127.0.0.1:10966/' ); Invoke-ShareFinder -CheckShareAccess

The threat actors also executed PowerView Invoke-FindLocalAdminAccess module on one of the compromised servers:

powershell -nop -exec bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAGMAbABpAGUA bg B0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AbABvAGMAYQBsAGgAbwBzAHQAOgAzADcAOQAyADMALwAnACkAOwAgAEkA bg B2AG8AawBlAC0ARgBpAG4AZABMAG8AYwBhAGwAQQBkAG0AaQBuAEEAYwBjAGUAcwBzACAALQB0AGgAcgBlAGEAZABzACAANQAwAA==

Decoded command:

IEX (New- Object Net.Webclient).DownloadString( 'http://localhost:37923/' ); Invoke-FindLocalAdminAccess -threads 50

We also saw exhaustive port scanners of certain servers before additional discovery.

File and Directory Discovery

The following discovery commands were run on all hosts including the Domain Controllers:



# Lateral Movement

The first Lateral Movement to the Domain Controller was performed using remote services creation (Executing spoolsv.exe via remote services):



The spoolsv.exe binary is a Cobalt Strike artifact used for Lateral Movement and C2 which decodes to the configuration below:

Additional Lateral Movement technique was observed, where the threat actors used Cobalt Strike’s jump psexec_psh :

Using Cyberchef (recipe), we decoded the obfuscated powershell loader, which is using the default named pipe \.\pipe\status_f5 :

Threat actors also pivoted to a domain controller by using the same Cobalt Strike artifacts, spoolsv.exe via remote service creation:



Right after initial Lateral Movement, a second Cobalt Strike Beacon kaslose64.dll was executed on a critical server.



# Command and Control

Rita stands for Real Intelligence Threat Analytics (RITA), developed by Active Countermeasures. Rita is a framework for identifying command and control communication, also known as beaconing. As the name implies, beaconing refers to delivering regular messages from an infected host to an attacker-controlled host. Beacon is the malware agent installed on the victim’s device and is responsible for communicating with the C2 server. Rita is consuming zeek/bro logs and detecting suspected beaconing activity using network traffic calculations.

It then assigns a value ranging from 0.1 to 1.0, with the greater the score indicating that the network activity is suspicious. Rita is utilized as a hunting tool rather than a real-time detection tool, though simple scripting allows Rita to be used for live traffic analysis. However, analysts should add additional context and filter the results accordingly. Rita can only identify suspicious communication and should not be automated as a preventative control. For more info on how RITA works check out the mathamatics here.

Using with this case network traffic RITA was able to identify all active Beacons from the impacted hosts in the network as seen in the screenshot below:

# IcedID:


The following Cobalt Strike server was added to our Threat Feed on 07/26/2021.



This Cobalt Strike server was added to our Threat Feed on 07/27/2021.


# Exfiltration
No exfiltration TTPs were observed while analyzing this intrusion, however, as stated in the case summary, it is possible that the threat actors used Cobalt Strike (encrypted channel) to transmit sensitive data such as Word documents.

# Impact
The ransomware was executed on multiple servers using a batch script start.bat:

Here is the first ransomware execution which was observed on the Domain Controller:
enter image description here

Below is another example of the ransomware execution on one of the external servers:
enter image description here

Once the encryption process was complete a file called RecoveryManual.html was left across the filesystem with the instructions on how to contact the threat actors for the ransom negotiations.

# MITRE ATT&CK DATASET
OS Credential Dumping – T1003
SMB/Windows Admin Shares – T1021.002
System Owner/User Discovery – T1033
Network Service Scanning – T1046
Windows Management Instrumentation – T1047
Scheduled Task/Job – T1053
Process Injection – T1055
PowerShell – T1059.001
Domain Groups – T1069.002
File and Directory Discovery – T1083
Access Token Manipulation – T1134
Network Share Discovery – T1135
Domain Trust Discovery – T1482
Data Encrypted for Impact – T1486
Security Software Discovery – T1518.001
Disable or Modify Tools – T1562.001