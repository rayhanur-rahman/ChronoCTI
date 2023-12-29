# Case summary

The ISO image delivered a hidden directory containing a IcedID payload and a batch file. After being successfully mounted (double clicked), the end user only sees a malicious LNK file named documents inside the virtual hard drive. Clicking on the LNK file executes the batch file, which copies the IcedID payload to the user’s AppData\Local\Temp folder and loads it using rundll32. A scheduled task was created at that time to maintain persistence on this host as well.

Upon the execution of the IcedID payload, discovery commands using Windows utilities such as net, nltest, and ipconfig were executed to discover domain trusts, domain admins, workstation configuration, etc. Around 16 hours after the initial execution, the first Cobalt Strike beacon DLL was executed from the IcedID malware. This led to another round of discovery using net followed by AdFind.

The threat actor installed Atera and Splashtop remote access software via an MSI file. After that, the threat actors tried a GetSystem privilege escalation technique, which was blocked by antivirus. The threat actor then proceeded to exploit CVE-2020-1472 (ZeroLogon). This was followed by a batch script used to perform DNS lookups on hosts across the environment. After this, the threat actors began their first lateral movement to a server in the environment by copying their Cobalt Strike DLL over to the host and executing it via a remote service. They then repeated the install of the remote access software package.

Some two hours later, another Cobalt Strike beacon was executed. With this beacon, the threat actors succeeded in elevating to SYSTEM on the beachhead host and proceeded to dump LSASS memory. Another round of activity took place using system tools, batch files, and Adget. Several more beacons were also loaded on the host using DLLs and PowerShell.

At this point, the threat actors had the clear text credentials for one of the domain administrator accounts and began moving laterally to other systems. They issued remote commands using WMIC to conduct discovery, as well as distribute and execute Cobalt Strike beacons. These actions, however, failed to get a beacon to launch on the domain controller being targeted. After an hour or so of failures, the threat actors proceeded to RDP into the domain controller. Once there, they then loaded textbin[.]net, a pastebin style site, to download Cobalt Strike PowerShell code to the host in a file named pon.txt.

Trying to execute this locally failed as well, and the threat actor moved on to downloading a variety of beacon executables (e.g. lsass.exe, lsasss.exe, etc.). These beacons, however, continued to crash and fail to run. Around an hour after starting the RDP session, the threat actors executed a PowerShell command to disable Windows Defender Antivirus on the host and reviewed Group Policy Objects for the domain. The Cobalt Strike beacons then began to execute successfully on the domain controller. Now, with Cobalt Strike beacons on the domain controller, the threat actors continued with discovery actions using Invoke-ShareFinder and other PowerShell and system utilities.

A few hours after, the threat actors installed the RSAT tools onto the beachhead host. However, they appear to have been unfamiliar with the tools and called up the help menu before using Get-ADComputer to collect the details on hosts in the environment. Back on the domain controller, ProcDump was used to dump LSASS memory. The PowerShell command Get-EventLog was then used to collect logon events on all domain administrators in the network.

The threat actors went quiet for around seven hours. When they returned, several more Cobalt Strike beacons were launched and several different Mimikatz implementations were executed on the domain controller, including a Mimikatz executable and a PowerShell implementation. For the next several hours, repeats of previous discovery actions and additional beacons executed using remote WMIC commands, were observed. During this time, Windows event logs point to the threat actors completing DCSync activities on one of the domain controllers. A new batch file, localdisk.bat, was also executed using remote WMI commands, to collect disk data on hosts around the environment. These discovery actions were completed several times again in other various batch files.

On the start of the fourth day, the threat actors continued to repeat their previous discovery and beacon spreading activity. Near the end of the day, the threat actors moved to install AnyDesk on several servers including a backup management host, likely as a further means of persistence or later command and control. Next, the threat actor executed PowerShell to pop up an alert message on several hosts, letting the user know that the machine was infected with Cobalt Strike.

After completing this activity, they used Rclone to exfiltrate copies of the backup files to the Mega.io cloud storage service. The threat actors then staged a ransomware binary on the backup server but did not immediately execute it.

Around two hours after dropping the file, it was executed using a command line argument, which included a list of hosts to target. This appeared to fail. The threat actors then proceeded to execute the payload manually in several ways, across various hosts. Finally, they connected to a domain controller and dropped three scripts; one to copy the ransomware executable to all hosts, one to reset every users password in the organization, and a final one to execute the staged ransomware payload using PsExec.

Once executed, the ransomware left the ransom note README_TO_DECRYPT.html, which informs the victim that Quantum ransomware is responsible for the intrusion. The time to ransomware was just over 78 hours from the initial IcedID infection. All domain joined systems were encrypted with Quantum ransomware.

# Analysis



This intrusion began by the execution of a malicious LNK embedded in an ISO file (masquerading as a folder). The ISO file was delivered as a ZIP archive via a malicious spam mail campaign.

# Malicious ISO file

First, the user clicked on the ISO file, which created a new virtual hard drive disk. Such activity can be tracked with Event 12 from Microsoft-Windows-VHDMP/Operational.

This ISO file contains a LNK named documents and a hidden directory named max containing a cobalt strike DLL beacon and a batch file.

As we can see below using LECmd by Eric Zimmerman, the file documents.lnk points to max\eyewear.bat.

As a consequence, when the victim clicked on the LNK file, it triggered the execution of the batch file eyewear.bat

The batch file eyewear.bat then executed two commands:

It first moved a DLL file named eyewear.dat, initially located in a hidden folder named max, to the user’s AppData\Local\Temp\ folder :

Then, DLL was executed using rundll32.exe :

Want to block ISOs from automatically mounting when double clicked? Check out Huntress’s recent writeup.

On the second day of the intrusion, the threat actors used the IcedID malware to drop a Cobalt Strike beacon and execut it using regsvr32.exe.

After beginning to move laterally, the threat actors used many other execution techniques such as PowerShell and executables run from their interactive RDP session in addition to DLLs.

A number of application crashes were observed across several compromised hosts. This activity was a result of the threat actors attempting to execute various dropped tools or beacons on the endpoint, triggering a Windows Error Reporting (WER) fault process.

Application crashes are recorded in the Windows Application event log under Event ID 1000 and 1001.

The NSA Cyber Windows Event Monitoring Guidance, has the following statement:

Application crashes may warrant investigation to determine if the crash is malicious or benign.

In this case, the threat actors attempted to rectify the issue by deploying new beacons, renaming executable files by either appending a double extension or adding extra characters to the filename (i.e. lsass.exe to lsasss.exe).

Some of these crashes may have been in response to being detected by Microsoft Defender. These signatures were found in the logs on various hosts.

There was evidence that that the Cobalt Strike aggressor script AnnoyKit was leveraged to launch Internet Explorer via a COM object.

Decoded from Base64:

The decoded PowerShell function is readable in the PowerShell logs:

The PowerShell script used is publicly available, and can be found here, along with the CNA script.

We were unable to ascertain the purpose of running this script or how it furthered the threat actor’s goals.

IcedID created a DLL named Utucka.dll just after the initial execution.

A scheduled task was then created using this same DLL.

First execution was observed on Day 1 at 8:00 PM and was repeated every hour.

# Named pipe impersonation

The named pipe impersonation technique was used multiple times on different hosts in order to get system privileges. This is a common technique used by threat actors, and implemented by the GetSystemCobalt Strike command. As seen in the screenshot below, GetSystem creates a service and connects to a pipe.

The beacon creates the named pipe (seen in Sysmon EventID 17) and impersonates the NT AUTHORITY\SYSTEM account used to connect to the pipe.

The MITRE Cyber Analytics Repository (CAR) details the Get System elevation, CAR-2021-02-002: Get System Elevation

# Winlogon Token Impersonation/Theft

Multiple access to WinLogon with granted access 0x40 (PROCESS_DUP_HANDLE) were performed. Such access can be tracked with Sysmon event ID 10 (ProcessAccess). As explained in this blog written by Jonathan JOHNSON, opening a handle to WinLogon in order to duplicate the token and call ImpersonateLoggedOnUser is a known Cobalt Strike technique.

# ZeroLogon

On the second day of the intrusion, a spike in NetLogon traffic was observed from the beachhead host to a domain controller. This traffic then triggered several network signatures for CVE-2020-1472 otherwise known as ZeroLogon.

The event logs corroborated a successful exploitation with a password update Event 4742 for one of the Domain Controller passwords.

# Mark-of-the-Web Bypass

The threat actors delivered the initial malware as a zip file, with the contents of a ISO file, which contained their payload to gain access to the target environment. These packages are designed to evade controls such as Mark-of-the-Web restrictions.

# Windows Defender tampering

On one host, the threat actors ran the following command to try and clear the way for their activity, likely due to the difficulty the threat actors were having with beacons crashing.

This command was downloaded from a remote site to a file named pon!.txt and then executed locally.

# Process injection

Multiple suspicious calls to the function CreateRemoteThread (Sysmon Event ID 8) were observed. This is a known behavior of Cobalt Strike and its function shinject, which can be used to inject a new beacon or a specific program to another process on the victim’s computer.

As a result, we observed abnormal winlogon.exe process behavior; winlogon.exe performed DNS requests (Sysmon event ID 22) to a Cobalt Strike C2 domain guteyutu[.]com.

The injection is also visible from memory dumps. Several hosts showed rundll32 processes exhibiting common process injection behavior, where the MZ file header is seen in the starting memory address in rundll32 processes with PAGE_EXECUTE_READWRITE permissions.

Many of these beacons could also be detected in memory scanning with the Malpedia Cobalt Strike rule. A sample of a scanning run is displayed below:

Multiple tools and scripts were used to access and collect credentials from compromised hosts. There were several variants of Mimikatz in binary and PowerShell form:

Commands used to collect credentials and export to text files stored in the C:\ProgramData folder included the following:

# DCSync

Credentials were also dumped via DCSync using two compromised high privilege accounts. The activity was observed in Windows Security Event ID 4662, with known indicators including non-computer based account, an access mask of 0x100, and object IDs.



DCSync was observed across 12 events, with separate events for each object ID. It is likely the operator used the Cobalt Strike DCSync command, having observed them already enter this directly in the host OS command shell.

For additional details, SpecterOps has an article covering the DCSync technique.

# Code injection in LSASS

Multiple injections into the LSASS process were observed on multiple hosts.

Threat actors used the function CreateRemoteThread in order to inject malicious code in LSASS process to access credentials.

Process dump of the LSASS process was undertaken using the Sysinternals ProcDump utility:

This process was invoked by RunDLL32.exe which was an injected Cobalt Strike beacon reaching out to the command and control server at 111.90.143[.]191.

# Classic ransomware discovery stages

A number of familiar discovery techniques were utilized using various OS commands to discover information relating to the user, host, and network configuration. Standard time discovery, domain trust discovery, workstation configuration discovery, and use of the net command to discover standard accounts and groups were observed.

From the IcedID malware running via Rundll32, the following LOLBAS commands were observed:

From Nigu.exe (Cobalt Strike beacon), the following LOLBAS commands were observed:

Discovery commands observed from other Cobalt Strike beacons using LOLBAS included:

systeminfo netstat -anop tcp cmd.exe /C echo %%temp%% cmd.exe /C hostname cmd.exe /C nslookup hostname

# RSAT installation to enumerate domain computers properties

Following the first discovery stage, the threat actor installed RSAT (Remote Server Administration Tools) on the beachhead host, which contains the ActiveDirectory PowerShell Module.

One interesting fact to notice, the threat actors had to consult the help menu of Get-ADComputer and Export-CSV using Get-Help.

Domain computers’ properties were then enumerated using the Get-ADComputer. PowerShell cmdlet and names were exported in a CSV file named ADComputers.csv.

In addition, threat actors searched for Active Directory related DLLs in other directories:


# Hands on keyboard!

We observed mistakes made by the threat actors during hands-on keyboard activities, these included typos and incorrect use of commands. An example of an incorrect named command was nslook up (should have been nslookup) that also incorrectly passed the username, instead of the host name.

Another example, the misspelling of administrators:

net group administartors /domain

Further examples included typos of commands:

Other operator errors observed included the use of Cobalt Strike commands being passed as a parameter instead of a beacon task.

The use of DCSync is documented in a previous TheDFIRReport titled ‘Cobalt Strike, a Defender’s Guide

During AD enumeration, the operator made use of the PowerShell Get-help cmdlet to troubleshoot the following:

Two file sharing web sites were used to access files, these were dropmefiles[.]com and file[.]io. Both of these services were accessed on day two from one Domain Controller on the network, with file downloads relating to tooling/scripts. On day three, a second Domain Controller was observed accessing the dropmefiles[.]com domain.

Reviewing the WebCacheV01.dat on the domain controllers, reveals more details on the sites loaded, including the files that where downloaded from those sites:

The threat actors downloaded the lsass.exe beacon from their attacker hosted infrastructure at 199.127.60[.]117.

In addition, the threat actors also used Internet Explorer on the domain controller to search Bing.

This is quite unusual to search directly on the victim’s browser. The current search results point to how to change the hidden view attribute in file explorer in reference to the ProgramData folder.

# Share discovery with Invoke-ShareFinder

Other tools observed in use, included Invoke-ShareFinder, this is a common tool that we frequently encountered in cases for enumerating network shares and identifying data and potential targets. We have a detailed report covering Invoke-ShareFinder. In this case, there is a clear indication that the operator launched the Invoke-ShareFinder command via Cobalt Strike, as observed in Event ID 800:

# Windows Security Logs discovery

Once the threat actors had achieved privilege escalation by compromising administrator accounts, an unusual, but interesting discovery technique was observed as seen below.

Executing this query would return all events in the Security log that references the specified account and with a source network address. Events returned would include process creation, logins, etc.

Its likely that this discovery technique forms an extension of T1033 – System Owner/User Discovery, where the threat actor was leveraging this data source to understand the account pattern of life, any indicators from compromise, and to potentially blend in adversary activities.

# Base64 for the win

Other discovery activities observed included a domain host discovery script via PowerShell. This was double base64 encoded.

Decoding this revealed another PowerShell Base64 encoded string:

The -e is short for -EncodedCommand. The base64 encoding starts with JAB that is a common pattern for UTF-16 starting with $. Refer to the Base64 cheatsheet by Forian Roth here.

There are many different variations of EncodedCommand, with shorthand and aliases available. Unit42 (PaloAlto) provides a good article on trends and observations of PowerShell encoded commands:

Decoding this again using CyberChef shows the resulting PowerShell script:

# More tools dropped by threat actors

Other binaries and scripts were dropped onto one endpoint:

The ns.bat file contained thousands of nslookup commands with a corresponding hostname from the network, with output appended to a ns.txt file.

# ADGet

An Active Directory collection tool named ADGet was dropped into a user’s temp folder and executed with an output filename argument. No file meta data is provided. Its a simple to use tool, the application is invoked from the command line and passes an output file name to save enumerated AD objects.

ADGet is an uncommon tool, however, its function is very similar to ADfind–the key difference is that LDAP queries are not passed, they are instead coded into the binary itself.

The AD objects will be enumerated generating a zip output file containing the following TSV (tab separated files) files if using a default configuration:

These files can be viewed with any editor or reader that supports CSV or TSV.

# AdFind

While Adget was seen used, prior to that tool being run the threat actors also deployed the tried and true AdFind, which was renamed to find.exe and called using find.bat.

Another batch file named AD.bat was dropped into the ProgramData folder on one host and used adfind to enumerate AD objects.

The AD.bat file had the following commands:

Interestingly, the first line in the batch file denotes the WMI output configuration in HTML form (from XSL file c:\windows\system32\wbem\en-US\htable.xsl). The HTML was never used. Its likely the code was reused from other open source pentest enumerations scripts available, such as:

# WMIC

The use of WMIC was leveraged by a batch file named dS.bat that queried a number of target hosts to determine the host disk drive configuration. This can be useful to determine drives, including mounted network shares.

The dS.bat file was executed by the injected Rundll32.exe process.

During hands-on discovery by the threat actors, the Group Policy was viewed by the Microsoft Management Console application to view Domain Group Policy Objects.

This can provide useful information concerning any restrictions or configuration settings for hosts on the network.

# WMI

Threat actors used wmic.exe in order to execute PowerShell Cobalt Strike beacons on multiple workstations and servers. The payloads were stored on textbin[.]net.

As we can see above, WmiPrvSe.exe (WMI Provider Host) executed the PowerShell Cobalt Strike beacon on the remote computers.

Remote Desktop Protocol

The beacon C:\ProgramData\lsass.exe was used to proxy RDP connections and connect to another computer.

Proxying RDP traffic via a process such as a Cobalt Strike beacon reduces the exposure of the threat actor’s own infrastructure, and blends RDP activity to those of internal hosts on the network.

The use of RDP was extensively used throughout the intrusion, using a variety of processes (beacon injected or standalone).

The common processes observed were two injected processes, and the Nigu.exe/lsass.exe.

These processes are unusual for establishing RDP connections. During these RDP sessions, the threat actors often opened Internet Explorer to download their beacons or commands they wanted to run on lateral hosts. An example would be pon.txt. This file was opened during their RDP session and contained the PowerShell commands used to launch a new beacon:

pon.txt contents:

# Remote Service

Remote services were also created in order to propagate Cobalt Strike beacons in the network.

# AnyDesk

AnyDesk was used to move laterally between a workstation and a backup server as shown below with Sysmon event 3 (Network connection):

# Collection

To achieve collection of various directories on multiple hosts, the threat actors used the dir command through the administrative share c$ and redirected the output to a file text named listing.txt.

In addition, multiple text files were also created to store the output of various discovery commands and scripts.

# IcedID

The malware configuration:



Initially the IcedID malware made a connection to 64.227.12[.]180:80 for it’s first call back. This aligns with the domain present in the malware configuration details.

After the first call over an unencrypted port, command and control traffic moved over to TLS on port 443. Connections were made to various IP’s over the length of the intrusion, but two made up the majority of the traffic.



IcedID C2 beaconing over the intrusion:

# Cobalt Strike

There were a number of beacons deployed across the environment, over 70 pipes were created. The beacons used recognizable default Cobalt Strike configurations and attempted to masquerade dropped files as legitimate Microsoft Windows executables. For example, on one host, we could observe over 20 pipes being created, in a pattern of postex_xxxx or MSSE-xxxx-server.

When beacons were deployed within the environment, there was a significant increase in outbound network connections to C2 servers. For example, a beacon injected into a single Rundll32.exe process generated over 10K connections in a three hour window, consistently across two days.

The threat actors deployed various beacons over the course of the intrusion using different methods including executables, DLLs, and PowerShell beacons.

Over the length of the intrusion four different Cobalt Strike servers were observed in use. Some lasted the majority of the intrusion while others only lasted a few days.

Cobalt Strike SSL characteristics:



Analysis of the Nigu.exe binary indicated use of compression and PE loading characteristics, typically observed for Cobalt Strike payload beacon. Using CAPA, the results listed the following capabilities:

Embedded within the binary were strings such as: “inflate 1.2.11 Copyright 1995-2017 Mark Adler”. Once the file was unpacked and the Cobalt Strike beacon binary carved, the Cobalt Strike configuration could be determined as follows:

Configurations for other Cobalt Strike servers observed:


# Remote Access Software

As shown above, three different Remote Access Software were used by the threat actor:

It is unclear why the threat actor used three different tools in order to establish an interactive and persistent command and control channel.

The AnyDesk service password was set manually using the command line as shown below:

The software packages were bundled within a single Microsoft Software Installer (MSI) package, named hp.msi. This was installed from the ProgramData folder, resulting in the installation of the remote management tools. The activity can be correlated against the Application log for MSI installer events (Event ID 1033).

During the intrusion, the threat actors were observed accessing collected data such as ShareFinder.txt using Notepad and then copying the contents to the clipboard.

Whilst the process activity indicated Active Directory accounts being used, correlating this activity to Clipboard activity indicated matching sessions, process IDs, and the true source of the user.

In this case, ShareFinder.txt was created in the ProgramData folder by the ShareFinder.ps1 script. Approximately 2 seconds later, the threat actors accessed this file and copied the contents.

While the threat actors made attempts to proxy RDP traffic and minimize external RDP access, the threat actors’ workstation was revealed in several Windows logs. Sysmon Event ID 24 linked the threat actors host name HYPERV and the IPv4 address of 199.101.184[.]230. This host name was also in the Security events:

For example, Event 4779 relating to a user disconnecting from a terminal session, reveals the client name of the source workstation. The client address was the internal workstation where the RDP traffic was being proxied through.

# Exfiltrated Documents Opened Remotely

During the second day of the intrusion, documents from the organization were opened remotely from 212.102.59[.]162 and 165.231.182[.]14. This occurred before Rclone was used, which leads us to believe the documents were exfiltrated over one of the encrypted C2 channels.

# Rclone

On the backup server, rclone.exe was used in order to exfiltrate data to a MEGA cloud storage.



From the rclone.exe configuration file, we can retrieve the user’s mail address and password.

# Mega user account Alert

Interestingly, the operator issued a command that displayed an alert informing the end user of a compromise, specifically with Cobalt Strike. Its unclear why the operator chose to do this, as this was around three hours prior to the ransomware being executed or a ransom note being dropped.

The alert message that was visible:

The activity can be observed in the PowerShell WinEvent logs:

# Ransomware

The threat actors dropped the first of their ransomware binaries on the fourth day of the intrusion. Around 40 minutes after creating the alert messages for Cobalt Strike to show up, they dropped locker_64.exe on the backup server. They created a file (2.txt) and populated it with a list of hosts they had uncovered during their discovery activity. The locker_64.exe file was then renamed to 64.exe and executed using the text file in the command arguments:

The threat actors attempted to execute the malware across all hosts in the target list, but only execution on the backup server was observed.

The threat actor then tried again on a different server using a DLL this time:

Again, only execution on the server was observed. They then executed a new Cobalt Strike PowerShell beacon on a 3rd server and executed the ramsomware using that.

They then opened an RDP connection back to the primary domain controller and proceeded to try to execute the binary with a target list again. After only affecting the single host, the threat actors dropped several batch scripts on the server:

The script pass.bat proceeded to reset all the user accounts in the domain to a single password set by the threat actors.

There were thousands of Windows Security Event ID 4724 events generated within a two minute period.

This password reset would enable the next scripts to function as intended while also hampering any recovery activity.

The 1.bat file then proceeded to copy the ransomware binary across to hosts in the environment.

Finally 2.bat used the reset password to enable psexec to execute the ransomware on all the remote hosts.

When the payload was executed, there were some telltale registry events observed indicating .Quantum file extension Shell Open Command artifacts.

The HTML message was dropped in various directories across the endpoints:

The HTML file displayed the all but familiar message:

The following Locker files were then deleted: