# Case summary

In this case, we did not see the exact initial access vector but based on other reports at the time we assess with medium to high confidence a malicious email campaign delivering macro enabled Word documents was the delivery vector. Shortly after the initial BazarLoader execution, we observed the first discovery commands using the standard built in Microsoft utilities (net view, net group, nltest). We saw the BazarLoader process download and execute the first Cobalt Strike beacon twenty minutes later using rundll32.

As the operators tried to enumerate the network, they miss-typed a lot of their commands. During interactive discovery tasks via the Cobalt Strike beacon, the threat actors attempted an unusual command that had us scratching our heads for awhile, “av_query”. This left us confused, we were not aware of the reason and/or the purpose of this command.

On August 5th, a threat actor that goes with the name “m1Geelka”, leaked multiple documents that contained instructions, tools and, “training” materials to be used by affiliates of Conti ransomware. We demonstrated some of the documents on one of our recent tweet threads, more info about the Conti leak here. In these materials, we found a file called “AVquery.cna” that refers to a Cobalt Strike aggressor script for identifying AV on the target systems. It is likely that the threat actors in this intrusion meant to use this aggressor script via their Cobalt Strike console, but instead typed or pasted “av_query” into their windows command prompt session. Additionally, threat actors were seen following the instructions of the leaked documents step by step. More specifically, we observed the threat actors copy/pasting the exact commands such as creating local admin users that contained the same passwords we saw in the leaked instructions.

Continuing with the discovery phase, the threat actors executed AdFind via a batch script before further enumerating using native Windows tools and port scanning via the Cobalt Strike beacon. They then successfully escalated privileges by dumping credentials from the LSASS process. After having enough situational awareness over the domain and an administrator’s account in their possession, operators used a reverse proxy and established a RDP connection on the beachhead host. Moments later, we observed them move laterally for the first time to the Domain Controller using RDP. Once on the Domain Controller, they again downloaded and executed AdFind through the same batch script. They also ran two separate Cobalt Strike beacons. As if their presence was not enough with Cobalt Strike and administrator credentials, they proceeded with creating two local administrator accounts.

Next, they installed AnyDesk, a remote access application for RDP connectivity and remote system control. After having four different types of persistence, they felt it was enough and continued enumerating the network, only this time, they searched for valuable documents across all domain-joined hosts. To accomplish that, they used PowerSploit and, more specifically, the “Invoke-ShareFinder” module. While waiting for their script to finish, the threat actors created a full backup of active directory in “IFM” media mode and dumped the password hashes along with the corresponding users. This method is both stealthier and safer for extracting the hashes from active directory, as explained by Black Hills Information Security.

The next step for the threat actors was to download and run “Advanced IP Scanner” and scanned for ranges looking for other active subnets on the LAN. After four hours of downtime, the operators returned to the network and did something unexpected; they used seatbelt to enumerate the domain controller further. They then pivoted over to another domain controller, repeated all the above discovery steps, and ran the same tools as on the first domain controller.

Eventually, this intrusion ended on the third day from the initial BazarLoader execution. After almost a day of inactivity, the operators logged into the network and used RDP to remote into file servers that contained valuable data. They then created a directory called Shares$ and used Rclone to exfiltrate the data to the Mega Fileshare service. Typically, these types of cases end up with Conti ransomware, however, the threat actors were evicted from the network before a final suspected ransomware deployment commenced.

# Analysis

We assess with medium to high confidence that the initial access was a result of malicious, macro-enabled, Word document that was sent as an attachment to the targets of a phishing campaign.

Brad reported on similar BazarLoader activity initiated from malicious TA551 Word Doc email campaign that resulted in Cobalt Strike beacons.

# Execution

The initial execution for this intrusion took place with the use of BazarLoader malware via rundll32.

Immediately after the execution, the malware contacted two of its C2 IPs:
- 35.165.197.209:443 
- 3.101.57.185:443

We then observed the threat actor using the BazarLoader injected process, svchost.exe, to download Cobalt Strike and save it under:

C:\Users\ < user > \Appdata\Local\Temp

before executing it using rundll32.exe.

Throughout the intrusion, the threat actors utilized Cobalt Strike beacons and PowerShell to execute their payloads prior to interactively remoting into hosts using RDP and AnyDesk.

# Persistence

The threat actors created two local user accounts on the first Domain Controller. They also added one of the two to the local administrators group. The passwords that they used were the same as the passwords of the recent Conti leaked documents.

Screenshot from leaked Conti data (“Закреп\ AnyDesk.txt”) (our tweet thread on Conti leak manuals):

Commands from the intrusion:
- net user sqlbackup qc69t4b 
- net user localadmin qc69t4b 
- net localgroup administrators localadmin /add

AnyDesk was also installed on the main domain controller.

The threat actors maintained an open communication channel through AnyDesk for a period of 11 hours.

The threat actor was seen logging in from 185.220.100.242 (Tor Exit Node) using AnyDesk. Client ID 776934005. (ad_svc.trace)

# Privilege Escalation

The threat actors accessed credentials for an administrator account from the LSASS process using the Cobalt Strike beacon. On the image below, we can see that the CS beacon process is injected into LSASS.

# Defense Evasion

Throughout the intrusion, we observed multiple instances of process injection from both the initial BazarLoader malware and Cobalt Strike beacons.

After BazarLoader was loaded in memory, almost immediately it injected into svchost.exe process. Additionally, the Cobalt Strike beacon was injected into mstsc.exe, searchindexer.exe and rundll32.exe and run various tasks from these processes.

# Credential Access

The LSASS process was accessed by an unusual process “searchindexer.exe” on beachhead right before the lateral movement was observed. Searchindexer.exe is a legitimate Windows process responsible for the indexing of files or Windows searches.

This technique is known to be used by Cobaltstrike which inject malicious code into a newly spawned searchindexer process to evade detection. This is associated with MITRE ATT&CK (r) Tactic(s): Defense Evasion and Technique(s): T1036.004.

The Sysmon logs captured in our case below can be used to detect this type of activity.

The threat actors created a full backup of the active directory in “IFM” media mode and dumped the password hashes along with the corresponding users.

ntdsutil "ac in ntds" "ifm" "create full c:\windows\temp\crashpad\x" q q

They also employed the NtdsAudit tool immediately after using NTDSutil to dump the password hashes of all domain users. NtdsAudit requires the “ntds.dit” database file and SYSTEM registry file for extracting the password hashes and usernames. After providing these as arguments, they exported the password hashes in a file that they named “pwdump.txt” and the user details in a csv file called “users.csv”. After obtaining the password hashes, the threat actors can crack the passwords hashes using a program such as hashcat.

ntdsAudit.exe ntds.dit -s SYSTEM -p pwddump.txt -u users.csv

Discovery

A few minutes after the initial execution, BazarLoader ran some discovery tasks using the built in Microsoft net and nltest utilities and transferred the results over the C2 channel.

- net view / all 
- net view / all /domain 
- nltest /domain_trusts /all_trusts 
- net localgroup "administrator" (comment: command mistyped) 
- net group "domain admins" /dom

Later on, hands-on operators carried out some additional network and domain reconnaissance from the Cobalt Strike beacon. Again, built in utilities were favored, with the exception of what we assess was a fat finger or miss-paste by the threat actor entering a command they meant to execute in their Cobalt Strike console into the windows command terminal.

- ipconfig /all 
- nltest /dclist 
- net group "Domain Admins" / dom 
- tasklist 
- av_query ( comment: Not a valid command ) 
- net localgroup Administrateurs ( comment: French translation of the named group administrators ) 
- net localgroup Administrators 
- SYSTEMINFO

The threat actors executed AdFind multiple times on both the beachhead and the domain controllers through a well-known script called adf.bat.

Later on, during the first day of the intrusion, and before we saw the threat actors pivot laterally to the domain controller, they ensured the information that they had collected was accurate by running the below enumeration commands:

- net use 
- ipconfig /all 
- netstat -ano 
- net group "domain admins" / domain 
- net view " Domain Controller name" 
- net view " Second Domain Controller name" 
- ping " Domain Controller IP" 
- ping " Domain Controller name" 
- ping " Second Domain Controller name" 
- ping " Domain Controller IPv6" 
- echo %%username%% 
- arp -a 
- time date

Threat actor dropped and ran a script named ping.bat. Here’s an example:
- ping -n 1 hostname >> C:\programdata\log.txt 
- ping -n 1 hostname2 >> C:\programdata\log.txt 
- ping -n 1 hostname3 >> C:\programdata\log.txt

The threat actors utilized Advanced IP Scanner to the scan for open ports.

One of the first things that the attackers did once on the first domain controller, was to execute Invoke-ShareFinder from PowerSploit via PowerShell ISE. They did the same thing later, on the second domain controller.
- "Command" : "Get-NetCurrentUser" 
- "Command" : "Get-NetDomain" 
- "Command" : "Invoke-ShareFinder -CheckShareAccess -Verbose | Out-File -Encoding ascii C:\ProgramData\shares.txt"

Other Microsoft AD management PowerShell administration modules were also invoked by the threat actors for discovery tasks.

Get-ADDomainController Get-ADDomainController -Filter * | ft Get-ADComputer -Filter * -Properties * | Get-Member Get-ADDomain

From the Domain Controller the threat actor also ran a Seatbelt binary, which was also seen in the Conti leak documents. This utility contains a number of “safety checks” on a host, telling the user about things like installed AV, network drives, local users, and much more.

We also noticed the threat actors searching for any existing antivirus software on the domain controller. They ran “dir” on the “c:\Program Files\” folder and saved the findings in the AV.txt file using a script named av.bat The script looked similar to the below:

# Lateral Movement

Many hours after the initial compromise, we observed the threat actors using RDP to connect to the first domain controller. They used reverse proxy via the Cobalt Strike C2 to initiate the RDP connection and for that reason, the operator’s real hostname was captured in event ID 4624:

# Collection

Prior to exfiltrating the data, operators staged them under a directory called “Shares” on each file server. They then inspected the documents they collected prior to exfiltrating them over to Mega storage servers using the Rclone application.

# Command and Control

BazarLoader initial communication with the C2 is over HTTPS. Data is sent to the C2 via the cookie parameter(screenshot taken from https://tria.ge/210716-v4jh8hf6ea/behavioral2).

Twenty minutes after the initial execution, BazarLoader downloaded and executed Cobalt Strike beacon with the help of rundll32.exe.

The AnyDesk software installed by the threat actors maintained a constant connection to the Anydesk infrastructure for the duration of the intrusion.

# AnyDesk:

Some network oddities appeared several times during the course of the intrusion. One of those oddities was several connections across the intrusion to an XMPP chat server at chatterboxtown.us at 70.35.205.161. These connections originated from one of the Cobalt Strike processes over port 5222. The goal of this traffic was not discovered in the course of the investigation.

Another, was a brief SSH connection to a server on the internet using Putty.

The connection took place for a period of twenty minutes. The reason for this connection is unknown. According to public records, the IP is associated with an old Cobalt Strike C2 server.



# Exfiltration

As the threat actors were perusing files, we received a notification that one of our files had been remotely opened from 46.38.235.14.

The threat actors later exfiltrated sensitive documents from domain joined file servers using the Rclone application. The destination of the exfiltrated data was Mega.io.

The above command was copied and pasted by the threat actors to exfiltrate the data. Prior to the correct command, the threat actors accidentally pasted a command from a previous intrusion. That command contained a different victim organization in the arguments showing through out the intrusion continued sloppiness of the threat actor.

Breaking down the Rclone command line arguments:

A great reference for detecting Rclone data exfiltration is the article from nccgroup: Detecting Rclone – An Effective Tool for Exfiltration – and from Red Canary – Transferring Leverage in a Ransomware Attack.

Impact

Multiple sensitive files were exfiltrated but before the threat actors could take any further action inside the network, they were evicted from the network. BazarLoader infections currently tend to materialize into Conti ransomware, and many of the TTP’s of the infection mimic the instructions from the leaked Conti manual.

Information posted from @AltShiftPrtScn based on an IR engagement where the threat actors already had domain admin on the network two months prior meeting their final objectives.

# MITRE ATT&CK DATASET
Phishing – T1566

Spearphishing Attachment – T1566.001

Domain Accounts – T1078.002

Command and Scripting Interpreter – T1059

User Execution – T1204

PowerShell – T1059.001

Windows Command Shell – T1059.003

Malicious File – T1204.002

Create Account – T1136

Valid Accounts – T1078

Local Account – T1087.001

Process Injection – T1055

Process Hollowing – T1055.012

Signed Binary Proxy Execution – T1218

Rundll32 – T1218.011

OS Credential Dumping – T1003

LSASS Memory – T1003.001

Cached Domain Credentials – T1003.005

Domain Trust Discovery – T1482

Account Discovery – T1087

File and Directory Discovery – T1083

Process Discovery – T1057

Network Share Discovery – T1135

Remote System Discovery – T1018

Software Discovery – T1518

System Owner/User Discovery – T1033

System Time Discovery – T1124

Lateral Tool Transfer – T1570

Remote Services – T1021

Remote Desktop Protocol – T1021.001

SMB/Windows Admin Shares – T1021.002

Windows Remote Management – T1021.006

Data from Local System – T1005

Data from Network Shared Drive – T1039

Data Staged – T1074

Local Data Staging – T1074.001

Remote Data Staging – T1074.002

Internal case #5426