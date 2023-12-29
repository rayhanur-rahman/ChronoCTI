# Case summary

We assess with moderate confidence that the initial vector used by the threat actor was a zip file, which included a malicious JavaScript file, delivered through a phishing campaign. The JavaScript file would eventually download and execute the IcedID malware. Discovered in 2017, what started as a commodity malware is now currently being deployed as an initial access broker by ransomware threat actors.

While there was some initial discovery activity from the IcedID malware, it went quiet, just beaconing to command and control but not performing any other activity. After being dormant for over two days, a Cobalt Strike Beacon was dropped and executed on the system infected with IcedID. The threat actors then ran another round of discovery activity with native windows utilities such as nltest.exe, whoami.exe, and net.exe. They then successfully escalated to SYSTEM privileges via Cobalt Strike’s built-in “named pipe impersonation” (GetSystem) functionality.

The threat actors continued by moving laterally to the domain controllers on the network using SMB to transfer and execute a Cobalt Strike Beacon. During that time, we observed port scanning activity from one of the domain controllers, to identify open ports such as SSH, SMB, MSSQL, RDP and WinRM. After a brief gap of 15 minutes, the threat actors used PsExec, to copy and execute a Cobalt Strike Beacon DLL on most of the systems in the network.

Later in the attack, the threat actor was seen establishing RDP connections from the beachhead host to the domain controller and other systems throughout the environment. This RDP activity was being proxied through the IcedID process running on that host, to a remote proxy over port 8080.

To establish persistence, the attackers created a new local user on one of the domain controllers and added it to the Administrators group. Additionally, in an effort to evade any detection and prevention mechanisms, they disabled Windows Defender via a group policy modification.

Within two and a half hours of Cobalt Strike showing up in the environment and just over two days after the initial IcedID infection, the threat actors completed their objective of encrypting all systems. Conti was executed in memory with the help of the Cobalt Strike Beacons domain wide. The ransomware note left by the infection included a link to their Tor site for further details.

After further review of the environment (post encryption), we realized multiple systems (including a domain controller) were unable to be accessed and would not have been restorable even if the ransom had been paid.

# analysis

# MITRE ATT&CK

# Initial Access

The IcedID DLL that we executed was most likely dropped through a zip file, which included a JavaScript file within it. Brad had a few posts about these around the time of this intrusion. 1 2 Thanks Brad!

Various attributes including the computer name and the OS version of the compromised system were sent through encoded cookie values.

IcedID was executed via rundll32.exe and ran command and control over port 443 for the duration of the intrusion.

# Discovery

IcedID ran initial discovery after being executed on the beachhead. Various commands were executed to gather more information about the compromised environment; including the currently logged on user, domain trusts, groups, etc .

Additional discovery commands were executed by Cobalt Strike.

After moving laterally to a domain controller, they began looking for what networks were present in the environment using dsquery.

Shortly thereafter, port scanning was observed coming from a domain controller looking for common ports (such as SSH, SMB, MSSQL, WinRM and RDP, etc.) on systems residing in the same subnet.

# Privilege Escalation

In order to obtain SYSTEM level privileges, Cobalt Strike’s built-in named piped impersonation (GetSystem) was used:


# Lateral Movement

The threat actor began lateral movement using remote execution of Cobalt Strike Beacon service binaries.


After this initial activity, Cobalt Strike was used to enable RDP, and allow it through the firewall, on the domain controllers.

Following this, the threat actors then copied a Cobalt Strike Beacon DLL to the ADMIN$ share; and then, distributed it throughout the environment using PsExec.

From here, RDP connections were established from the beachhead host to systems throughout the environment. The connections were proxied through the IcedID process.

The threat actor used a redirector (38.135.122[.]194:8080) to proxy the RDP traffic being passed through the IcedID process. The below traffic shows more details of the RDP session, including the username in the cookie.

This proxied traffic reported back the hostname of the threat actors machine as “mikespc”. We’re looking for you Mike! 😉

# Defense Evasion

To evade detection, the threat actors disabled Windows Defender by adding the below to an already linked GPO. They then force updated the GPO on all clients using Cobalt Strike.

In addition, other security services were stopped or uninstalled.


# Command and Control

# IcedID

# Persistence

An account named “nuuser” was created by one of the Cobalt Strike Beacons. As these commands were run on a domain controller, it essentially added the account to the Built-in Administrators domain group, granting it administrative privileges in the AD domain.

# Credential Access

LSASS was accessed by an unusual process “runonce.exe” on multiple hosts, including a domain controller.


The overpass-the hash technique was used to acquire a valid Kerberos ticket for the administrator user.

# Impact

About two and a half hours after initial hands on keyboard activity, the Cobalt Strike Beacon processes running across the target systems injected the Conti DLL into memory. Conti deployments using a DLL seem to have first started showing up in December 2020.

First time that I see #Conti ransomware spread as a DLL :




Some traces of this particular DLL were found in the memory dump taken from one of the compromised systems.

We were unable to reconstruct the DLL from memory but Maxime Thiebaut (@0xThiebaut) from NVISO helped us out. The Yara rule, located in the detections section below was made possible due to him reconstructing the DLL. Thanks Maxime!

Conti scans the network for 445/SMB, looking for machines to encrypt.

Ransom note

Which leads you here.

The threat actors asked for 150k and could have been talked down at least ~20%.

Multiple machines within the environment were not usable after being ransomed including a domain controller. The machines were left like this and you were not able to do anything but press control+alt+delete. Paying the ransom will not help you here.

