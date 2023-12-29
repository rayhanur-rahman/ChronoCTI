# Case Summary

In this intrusion the entry was a Windows host with RDP exposed to the internet. The threat actors logged in with a valid account (Domain Administrator). The login was from a Tor exit node and over the course of an 8 hour intrusion we saw them hand off 2 times, for a total of 3 different Tor exits being used to maintain RDP access to the environment.

The account used to access the first beachhead host had enough privileges to immediately begin lateral movement to a domain controller just minutes after entry. Network scanning begun on the domain controller followed closely by Empire. While the Empire C2 remained active during the whole intrusion, we saw little activity from it, more like a fallback channel should their RDP access fall off.

As they started to move laterally to other systems, it was very obvious they were following a checklist playbook. Each time they pivoted, they would check quser, and then dump lsass using Task Manager.

During the intrusion we saw the PYSA threat actors attempt to access credentials via the following techniques::
- Dump lsass with Taskmanager
- Dump lsass with Procdump
- Dump lsass with comsvcs.dll
- Dump credentials with Invoke-Mimikatz
- Extract the shadow copy of the ntds.dit from the domain controller
- Extract and decode backup system credentials from a SQL database
- Access LSA Secrets

Most lateral movement in the environment was via RDP with various legitimate user accounts, as well as PsExec to execute scripts throughout the environment for credential dumping and collection activity.

The threat actor disabled security tools throughout the intrusion by using Local Security Policy Editor and MpPreference to disable Defender. PowerShell Remoting was also used to run the arp command on a few systems.

Besides using RDP and Empire the group also used the Offensive Security Tool (OST) Koadic, which bills itself as a post exploitation toolkit that can stay resident in memory using JScript or VBS via Windows Script Host to perform its execution. Koadic was only utilized on a few key servers and one of those servers included a persistence mechanism using the default Koadic HTA scheduled task module.

After around 7 hours post initial access, the threat actors began their final actions by RDPing into systems, dropping a PowerShell script and the ransomware executable. The PowerShell script killed various active processes and made sure RDP was open at the firewall and created what appears to be a potentially unique identifier for systems. After that, the ransom would be run to encrypt the system.

After the encryption was done we were able to confirm exfiltration occurring by receiving a callback from a canary document. The threat actors asked for 5 BTC or around $88,000 USD which tells us these attackers most likely base their ransom demand on the information exfiltrated.

# analysis

# MITRE ATT&CK

# Initial Access

Initial access for this actor was via exposed RDP services. Originally, the actor connected from 198.96.155.3, and then performed a kind of hand off over the course of the campaign, first to 23.129.64.190 and then finally 185.220.100.240. All 3 of these IP’s belong to the Tor network and function as exit nodes.

# Execution

The threat actors started off by using RDP but also relied on 2 different OSTs during this intrusion.

A few minutes after gaining access, they moved laterally to a domain controller and then executed a PowerShell launcher for Empire.

Later during the intrusion, the threat actors employed another OST named Koadic. To execute Koadic, they employed a MSHTA launcher with javascript.



From those two executions, various child processes were created to load stage 2 into memory.

# Persistence

Persistence was setup using Koadic to schedule a task to execute a HTA file located in the C:\ProgramData directory at logon as system. This will initiate C2 back to the Koadic server.



# Defense Evasion

The threat actors disabled Windows Defender using Local Group Policy Editor.

Later, they also ran a PowerShell script that would again disable Windows Defender, this time using MpPreference. The script also targeted Malwarebytes, agents, Citrix, Exchange, Veeam, SQL and many other processes. Event ID 5001 was created due to Defender AV Real-Time being disabled.

A Defender exclusion was also added to exclude everything with .exe as the extension.

Add-MpPreference -ExclusionExtension ".exe" Event ID 5007 Windows Defender Antivirus Configuration has changed. If this is an unexpected event you should review the settings as this may be the result of malware. Old value: New value: HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions\.exe = 0x0

# Credential Access

The threat actors displayed multiple techniques for gathering credentials during this intrusion.

Credentials were dumped manually via Task Manager as they RDPed into each system.

While established on a domain controller the threat actors also created and accessed a shadow copy of the ntds.dit and most likely exfiltrated it via their Koadic C2 channel.

The threat actors also executed a PowerShell script across the environment using PsExec that took advantage of comsvcs.dll to dump the lsass process and then copy the dump back to their pivot position on a domain controller.

The threat actors tried using the Sysinternals ProcDump method but the executable was not present on the endpoint.



The threat actors were focused on the backup server for quite awhile as they dumped credentials from the 3rd party backup software repository. The first script pulls the hashes out of the database and the second decodes the password to plain text. Both scripts were run via PowerShell ISE.

The threat actors also ran Invoke-Mimikatz from BC-Security on one of the domain controllers.

We also saw the threat actors save LSA Secrets to disk using the hashdump_sam module in Koadic which runs impacket.

Inveigh was run on a domain controller.

# Discovery

The threat actors leveraged many built-in Windows tools for discovery including the following:

quser.exe whoami.exe /user net.exe group /domain net.exe group "Domain Users" /domain nltest.exe /dclist: arp -a

The arp command was run using PowerShell Remoting.

They also reviewed a few admin tools while exploring the network including:



The threat actors also brought some tools of their own to aid in discovery tasks including Advanced Port Scanner and ADRecon.

Here’s the description of ADRecon.

Other local discovery was performed using PowerShell such as ps to list the running process on systems.

# Lateral Movement

The first lateral movement occurred just 3 minutes after the initial access by the threat actor. RDP was initiated from the beachhead host to a domain controller using the valid account they had used to gain access to the first host.

RDP continued to be the first method of choice while accessing various systems around the environment. After a few hours in, the threat actors decided to automate some credential collection and used PsExec to execute a PowerShell script that called comsvcs.dll for lsass dumping.



# Command and Control

The threat actors used 3 different C2 channels, RDP, PowerShell Empire, and Koadic.

IP’s used to maintain access over RDP


# Empire

# Koadic

# C2 Check-in

# Command execution

# Exfiltration

While no plain text exfiltration was seen during this intrusion, canary documents were opened by the threat actors hours after the ransom, confirming that the hours spent on network before ransoming was used to gather files.

The source IP’s from these canary documents were also Tor exit nodes just like the RDP connections.

Since no plaintext exfil was observed we assess that the exfiltration was performed via one of the command and control channels either RDP, Empire, or Koadic.

# Impact

Around the 7.5 hour mark the threat actors began ransom deployment. Two files were dropped via RDP on each system, a PowerShell script and a PYSA ransomware executable.



The purpose of the PowerShell script was to disable security tools that might not have been disabled through-out the intrusion.

Additionally, the script would kill many server and database processes allowing encryption of the files that might otherwise be locked by running processes.

Finally, the ransomware exe was executed and the systems ransomed.


