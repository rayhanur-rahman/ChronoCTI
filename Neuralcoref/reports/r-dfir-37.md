# Case summary

A threat actor recently brute forced a local administrator password using RDP and then dumped credentials using Mimikatz. They not only dumped LogonPasswords but they also exported all Kerberos tickets. The threat actor used Advanced IP Scanner to scan the environment before RDPing into multiple systems, including a Domain Controller. After an hour of moving around the environment, they deployed XMRig on the initial compromised system before logging off. The threat actor was active on the network for about 2 hours in total.

# analysis

# MITRE ATT&CK

The threat actor logged in using RDP from an IP (92.118.13[.]103) that hadn’t attempted any previous logins. The account was created the previous day using a source IP of 54.38.67[.]132, which had been trying to brute force a local admin password. The threat actor used a workstation named winstation. During the intrusion, the threat actors also used 5.122.15[.]138 to login to one of the systems.

# Execution

The threat actor copied svshost.exe to C:

az and then executed it. This PE creates “XMRig CPU mine.exe” and HideAll.bat in C:\Windows\PolicyDefinitions and then executes both of them.

The PE file that installs XMRig (svshost.exe) also has a script (HideAll.bat) imbedded in it, which is called at runtime. This is the contents of that batch file.


This script is copied to C:\Windows\PolicyDefitions\ and run, which causes the files specified to be hidden.

# Persistence

Before the threat actor disconnected, they changed the user password.

net user %USERNAME% ehs.123

# Credential Access

Mimikatz was used to dump credentials from memory, as well as, export Kerberos tickets using the following command:

The threat actors used a vbs script named launch to execute mimikatz. This is the content of launch.vbs


Since the log parameter was used, the output was saved to mimikatz.log

The Kerberos tickets were saved to disk, due to the threat actor using sekurlsa::tickets /export.

Advanced IP Scanner was used to scan the environment.

Task manager was opened multiple times. Possibly looking at logged in users and/or processes.

Net Accounts was used to review user policies.

net accounts

masscan and masscan gui were dropped but were not executed.

# Lateral Movement

RDP was used to move laterally to multiple machines in the environment, which included domain controllers, backup machines, etc.

RDP was used to access the environment, as well as move within the environment.

XMRig was running on the system, using some CPU but not enough to cause any issues. We tend to block mining endpoints, which may have lessened the impact of this intrusion. XMRig made connection attempts to 104.140.201[.]42 & 104.142.244[.]186.

The threat actors have been using the associated Monero wallet for 738+ days and have netted around $5,159.

Was the threat actors’ mission to mine Monero? Or was this a recon mission? Possibly both?

Enjoy our report? Please consider donating $1 or more to the project using Patreon. Thank you for your support!

We also have pcaps, files, and Kape packages available here. No memory captures are available for this case.
