# Case Summary

In this short intrusion, the threat actor gained initial access on a system through a maldoc campaign which made use of the Hancitor downloader. The first-stage DLL, which was dropped by a malicious Word document, attempted to download multiple malware payloads on the beachhead system, including Ficker Stealer. In addition, a Cobalt Strike beacon payload was downloaded, and deployed to perform post-exploitation activities. Once inside the target environment, port scans and a large amount of ICMP traffic was observed–to identify additional active systems. After about 20 minutes, the threat actor copied a batch script file and DLL file to another system using the SMB protocol. A remote service was installed to start the batch file, which executed the Cobalt Strike shellcode-embedded DLL. On the second compromised system, various discovery-related commands were executed before going silent. The threat actors were evicted before completing their mission.

# analysis

# Initial Access

The Hancitor malware was embedded in a macro-based Word document. This single-paged document contained a picture with instructions, attempting to lure the victim into enabling macros.



When the macro was enabled, the infection chain started, and the first-stage Hancitor DLL was dropped to disk.

Reviewing the macro we can see that in sub yyy (towards the bottom) content within the document is being copied and used to create a file object by sub xxx which then is executed by the shell call to rundll32.

Looking at the strings of the word document, we can see that there’s an embedded OLE object, which appears to be a PE file.

# Execution

The malicious Hancitor DLL in the OLE object, named “rem.r”, was executed via rundll32.exe by passing the entry point “ESLMJYVFM”.

The botnet ID and C2 were extracted using Hatching Triage:

Later on in the intrusion, the threat actor used the following command to execute a Cobalt Strike Beacon on another machine:

rundll32.exe c:\programdata\95.dll,TstSec 11985756

# Defense Evasion

On the beachhead system, the malicious Hancitor DLL injected into the svchost.exe process. The code was injected into multiple instances of svchost.exe.



Memory analysis also shows suspicious memory protections (page_execute_readwrite) and regions of the particular process.





Finally, when looking at the process tree, we can identify the unusual parent-child process relationship of rundll32.exe starting svchost.exe.

The svchost.exe process, in turn, injected a Cobalt Strike beacon into multiple rundll32.exe instances. One of the injected rundll32.exe instance was also observed connecting to the Cobalt Strike C2 server.

In addition, the malicious 95.dll, which was observed during the lateral movement phase, is also designed to evade automated sandbox analysis. This DLL is crafted in such a way that it wouldn’t show malicious behavior if an exported function is not called by passing a specific parameter. The DLL contains the Cobalt Strike shellcode and will only execute if the “11985756” parameter is passed to the TstSec function.



After extracting the Cobalt Strike shellcode from 95.dll and emulating it via scdbg, we found that it’s connecting to 162.244.83[.]95 over port 8080.

Since 95.dll was executed by rundll32.exe, and from the host logs, it is evident that rundll32.exe connected to 162.244.83[.]95 over port 8080.

Packet analysis to the IP address mentioned above, shows that it’s downloading the Cobalt Strike beacon by initiating a HTTP GET request to /hVVH URI.

Once downloaded, the stager allocates a new memory region inside the current rundll32.exe process and loads it into the memory and starts the C2 activity.

# Discovery

On the beachhead system, the threat actor started exploring their options to move laterally within the target network. The logged-on user account was utilized to interact with IPC$ shares.

For one specific system, for which the threat actor showed interest, the contents of the C$ share was listed–we assess, to verify if the account had access permissions to the share before copying the malware to it:

The threat actor also pinged one of the Active Directory domain controllers from the beachhead machine.

A high amount of ICMP traffic, targeting various Class-A subnets ranges, was observed and used to identify other active systems within the environment.



On the second system, to which the adversary laterally moved (see section below), the following discovery commands were executed:
- nltest /domain_trusts
- net view /domain
- net time

# Lateral Movement

The injected svchost process dropped two files: a batch-file named: “95.bat” and a DLL-file named: “95.dll”. Both files were copied to the ProgramData folder of another system within the environment.

The content of the batch file can be seen below–it executes the transferred DLL and then deletes itself:







To execute the batch file, the threat actor installed, and started, a remote service on the other system.

# Credential Access

An attempt to open lsass.exe process was observed on the system where lateral movement occurred but there were no signs of successful read attempts.

# Command and Control

In the network traffic, we can identify a data stream pattern that is distinctive to Hancitor malware.

First, the malware performed a lookup of the external IP-address of the infected system (1). This was followed by Hancitor C2 traffic, sent via HTTP POST requests, which included unique attributes of the infected system, such as hostname and username information (2).

Hancitor then attempted to download additional malware. This included the info-stealer known as “Ficker Stealer” (4), for which the DNS traffic corresponds to a recent article posted by Brad. However, in our case, the post infection HTTP traffic of Ficker Stealer was not observed.

Hancitor also attempted to download Cobalt Strike stagers (.bin files) (3), and Cobalt Strike traffic was sent both encrypted and unencrypted (5).

# MITRE ATT&CK DATASET
User Execution – T1204

Web Protocols – T1071.001

Dynamic-link Library Injection – T1055.001

Remote System Discovery – T1018

Network Service Scanning – T1046

Windows Service – T1543.003

Domain Trust Discovery – T1482

System Time Discovery – T1124

Network Share Discovery – T1135

File Deletion – T1070.004

Internal case 4301

Share this: Twitter

LinkedIn

Reddit

Facebook

WhatsApp

