# Case Summary

The intrusion began with the delivery of an ISO file containing a LNK file and a BumbleBee payload in the form of a hidden DLL file. A user on a workstation mounted the ISO file and executed the LNK file, running the Bumblebee payload.

Around 15 minutes after the execution of BumbleBee, multiple processes were spawned with the goal of injecting Meterpreter into each of them. After the threat actors gained access with Meterpreter, they began conducting reconnaissance on the workstation and network, including querying domain controllers, mapping domain joined computers, enumerating Active Directory trusts, and listing Domain Admin accounts. All of this first wave of discovery relied on built in Windows utilities like nltest, arp, net, ping, nbtstat, and nslookup.

BumbleBee executed under a user with local administrator privileges on all workstations in the environment. At around six hours after initial execution, we observed a new process created that was then used to host a Cobalt Strike beacon, from the same command and control server observed in a prior BumbleBee case. This beacon reprised discovery activity, but also cut a common command short net user /dom instead of /domain , whether from keyboard laziness or a trick to trip-up detections. The threat actor then used their access to execute procdump via a remote service creation with the intention of dumping credentials from LSASS from an adjacent workstation on the network.

Next, the threat actors moved laterally via RDP to a server. A new local user, sql_admin, was created and added to the local administrator’s group and AnyDesk remote access software was installed. Through the AnyDesk session, the threat actor was observed connecting to a file share and accessing multiple documents related to cyber insurance and spreadsheets with passwords.

A second round of enumeration was observed on the beachhead using AdFind, which was executed via the Cobalt Strike beacon on the system. Following this second round of enumeration, the threat actor moved latterly to a server hosting backups, via RDP and interacted with the backup console. From the backup system, the threat actors also opened internet explorer and attempted to load the environment’s mail server, likely checking for Outlook Web Access.

A third round of enumeration, this time taking place from the first lateral server host, was observed via a script named ‘1.bat’ that would ping all computers in the environment. Following this third round of enumeration the threat actors were evicted from the environment and no further impact was observed.

We assess with medium confidence this intrusion was related to pre-ransomware activity due to the tool set and techniques the actor displayed.

# Analysis

The BumbleBee malware has been following the trend of using the effective combination of utilizing an .iso image containing a .lnk and .dll file. We have observed the same behavior with other major malware distributors in previous reports:

Using the event log, “Microsoft-Windows-VHDMP-Operational.evtx”, we can quickly find when the user mounted the .iso.

Upon clicking the LNK file the BumbleBee payload was executed.

# Execution

Following the user mounting the .iso file, they clicked on a .lnk file documents.lnk . As noted in previous reports, the .dll is hidden from the user unless they display hidden items in explorer like so:

The .lnk contains instructions to execute a specific exported function with the BumbleBee DLL file.

When the .lnk was doubled clicked by the user, the BumbleBee malware tamirlan.dll was executed:

The output of LECmd.exe, when used on documents.lnk , provided additional context to where and when this .lnk file was created:

>> Tracker database block Machine ID: user-pc MAC Address: 9a:5b:d6:3e:47:ec MAC Vendor: (Unknown vendor) Creation: <REDACTED DATE>

Approximately 5 seconds after execution, the rundll32.exe process contacted the IP 154.56.0.221 . More information on this traffic is covered in the Command and Control section below.

An interesting tactic of note, was the use of WMI and COM function calls to start the process, used to inject into. The BumbleBee loader uses WMI to start new process by calling COM functions to create a new process. Below you can see the COM instance creation followed by defining the WMI namespace and WMI object being created – “Win32_Process”.

Analysis of the loader found that a function of the malware chooses 1 of 3 target processes before injecting the supplied code:

This resulted in new processes not being a child of BumbleBee, but rather WmiPrvSE.exe.

In this intrusion, an instance of C:\Program Files\Windows Photo Viewer\ImagingDevices.exe was created and accessed by the BumbleBee rundll32.exe process. Shortly after this interaction, the process started communicating to a Meterpreter C2 3.85.198.66 . This process spawned cmd.exe and several typical discovery commands that are covered in more detail below.

The second process, was spawned the WMI technique was an instance of C:\Program Files\Windows Mail\wabmig.exe . This process was used to host both a session to another Meterpreter C2 50.16.62.87 and a Cobalt Strike C2 server 45.153.243.142, which was then used to conduct the majority of additional activity including credential dumping and discovery exercises highlighted below. The pivot to using Cobalt Strike began around 6 hours after the execution of the BumbleBee loader.

# Persistence

A new local administrator user was created on a server to facilitate persistence on the machine. The user account was observed to be accessed via an AnyDesk session on the same machine.

In addition, AnyDesk was installed as a service:

# Defense Evasion

The BumbleBee loader itself uses several defense evasion and anti-analysis techniques. As detailed in the Execution section, the use of WMI to spawn new processes is a known technique to evade any parent/child process heuristics or detections.

# Anti-Analysis

Once the malware is unpacked, it becomes quite apparent to what the malware author(s) were looking for–

Known malware analysis process names running:

Known sandbox usernames (Sorry if your name is Peter Wilson, no malware for you 😟):

Specific Virtualization Software files on disk and registry keys (Virtual Box, Qemu, Parallels), example:

# Process Injection

Create Remote Thread – The malware used the win32 function CreateRemoteThread in order to execute code in rundll32.exe.

Named Pipes – Two named pipes were created in order to establish inter-process communications (IPC) between rundll32.exe and wabmig.exe.


# Credential Access

# ProcDump

A remote service was created on one of the workstations in order to dump lsass.

# Discovery

The first discovery stage includes TTPs that we have seen in multiple cases, such as trusts discovery, domain admin group discovery, network discovery and process enumeration.

# AdFind

AdFind.exe was renamed to af.exe and was used by threat actors in order to enumerate AD users, computers, OU, trusts, subnets and groups.

# Lateral Movement

The threat actor was observed moving via RDP throughout the network with a Domain Admin account.

As mentioned in Credential Access, the threat actor used remote services to execute commands on remote hosts.

SMB was used to transfer the various tools laterally, as needed in the environment, like procdump.exe and AnyDesk executables.

# Collection

The threat actor accessed multiple documents and folders from a remote file server. The SMB share was accessed through a compromised server via an AnyDesk session.

The lsass dump file ran remotely, was copied to the beachhead through the admin share C$.

After being copied, the file was zipped using 7za.exe (7-zip), in preparation for exfiltration.

# Command and Control

# BumbleBee


# Meterpreter

# Cobalt Strike

This C2 server was observed in a previous BumbleBee case.

# AnyDesk

AnyDesk was installed to facilitate interactive desktop command and control access to a server in the environment.

Reviewing the ad_svc.trace logs from Anydesk located in %programdata%\AnyDesk reveal the logins originating from 108.177.235.25. This was again the same IP observered in the prior Bumblebee case.

The Client-ID observed in the logs was 892647610


# Exfiltration

No exfiltration methods were observed beyond the established command and control channels, which can be assessed as likely used to take data like the lsass dump out of the network.

# Impact

The threat actors were evicted from the network before any further impact.

