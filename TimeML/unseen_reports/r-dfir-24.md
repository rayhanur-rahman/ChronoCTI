# Case Summary

BazarLoader has continued to be one of the preeminent initial access brokers for ransomware threat actor access. For this intrusion we don’t know the initial campaign that deployed the malware but based on previous information, we can assess with high confidence that the delivery vector was a malicious email campaign. At the time of the intrusion, the group was favoring zip attachments with malicious javascript files to download the BazarLoader malware. However BazarLoader has also been used with Word and Excel documents as well.

In this case we observed the initial activity beginning with a BazarLoader DLL. Upon initial execution on the beachhead, the malware made an initial connection to command and control, and then a few minutes later it performed discovery tasks on the host using Microsoft utilities like Net and Nltest to discover the domain and users of interest. like domain administrators. After this activity, the host went quiet for about one hour before downloading and executing a Cobalt Strike beacon DLL.

The threat actors used Cobalt Strike to run additional discovery tasks using Microsoft utilities like net, ping, systeminfo, and taskmanager. The threat actors then began using pass the hash with various accounts which continued several times throughout the intrusion. To see what machines were active in the environment, the threat actors scanned the network for SMB.

Around two and a half hours into the intrusion the threat actors began lateral movement. Lateral movement began by the threat actor transferring an executable to a remote system and then executing it using wmic. This was the primary lateral movement option favored by the threat actor, however PowerShell Cobalt Strike beacons, service executable Cobalt Strike beacons, and RDP were all used, but less commonly. Once on remote systems the threat actor used Cobalt Strike to dump lsass memory for further credentials.

After this phase completed, the threat actor’s activity faded but the Cobalt Strike continued to beacon out to the C2 server. About 12 hours later the threat actors became active again. From the domain controller the threat actors continued further lateral movement to more servers in the environment. They also continued further discovery activity running PowerShell scripts to discover the disk utilization of hosts, review user last login time per host, assess the installed anti-virus software, and track which hosts were online for the threat actors to target.

When the threat actors identified the file server, their method for data exfiltration was straightforward to a fault. They downloaded WinSCP from the project website, installed it on the file server and proceeded to exfiltrate data from the server using SCP to a VPS host they controlled in Romania.

Around 31 hours after initial access to the environment, the threat actors felt they were ready to complete their final objectives. RDP activity was seen from several hosts and an executable named test.exe was transferred to several endpoints. This test file was the Conti ransomware executable, and the threat actors decided to test in a controlled manner before running the full domain ransomware deployment. Like before, these “unit tests,” were performed using wmic to execute the files remotely on the endpoints.

The threat actors must have confirmed quickly that their tests were successful as within minutes they dropped test.exe renamed to backup.exe on two servers in the environment and executed manually via their RDP sessions. When executed in this manner the ransomware mounts all remote C$ drives in the local network and proceeds to encrypt the contents over the SMB connection. At this point, the Time to Ransom (TTR) for the threat actors was just shy of 32 hours since initial access.

# Analysis

In this case we did not observe the initial delivery for the malware. BazarLoader however tends to arrive in an environment via malicious email campaigns and in a few cases its been reported via call centers social engineering users to load the malware. Seeing that this starts with a DLL file it is more likely that this was related to an email campaign using malicious zipped Javascript files.

# Execution

Initial execution occurred via the Bazarloader DLL being executed by rundll32.

About an hour after the initial execution on the beachhead, a Cobalt Strike beacon was executed also with rundll32.

# Privilege Escalation

The threat actors made use of pass the hash techniques to try to escalate privileges during the intrusion. Various accounts were targeted including a Guest account initially.



Process injection was seen from the Cobalt Strike beacon into a svchost process running with System level privilege.


# Defense Evasion

While in the environment they injected Cobalt Strike beacons into many processes.

Processes with CS beacon injected or running


# Credential Access

The threat actors were seen dumping credentials out of lsass memory across the domain.

# Discovery

The BazarLoader malware on the beachhead began discovery actions around 20 minutes after the initial execution. The discovery commands utilize the familiar built in Microsoft utilities.

- nltest /domain_trusts /all_trusts 
- net localgroup "administrator" 
- net group "domain admins" /dom C:\Windows\system32
- net group "domain admins" /dom

The Cobalt Strike beacon ran additional discovery tasks on the beachhead. Again built in Microsoft utilities were utilized.
- C:\Windows\system32\cmd.exe /C systeminfo 
- C:\Windows\system32\cmd.exe /C ping DOMAINCONTROLLER 
- C:\Windows\system32\cmd.exe /C ping ENDPOINT 
- C:\Windows\system32\cmd.exe /C net localgroup Administrators 
- C:\Windows\System32\Taskmgr.exe

Throughout the intrusion the threat actor checked the time of systems with:

C:\Windows\system32\cmd.exe /C time

From an svchost process injected with a Cobalt Strike beacon, SMB scanning was performed across the environment.

From the domain controller the threat actor ran an encoded PowerShell command to review the size and condition of hard drives across the environment.


Powersploit modules like Get-NetComputer were seen used by the threat actor from the domain controller

IEX (New- Object Net.Webclient).DownloadString( 'http://127.0.0.1:36595/' ); Get-NetComputer -ping -operatingsystem *server*

The script Get-DataInfo.ps1, which has been used in many intrusions this past year, was also employed. This file was started by the use of start.bat, which has been seen paired with this script repeatedly.

C :\Windows\system32\cmd.exe /c "C:\\Users\\info\\start.bat"

powershell .exe -executionpolicy remotesigned -File .\ Get-DataInfo .ps1 method

The contents of Get-DataInfo.ps1 provide the threat actor with very specific details of the environment. This includes things like disk size, connectivity, antivirus software, and backup software.

This script was first reported used by threat actors deploying the Ryuk ransomware strain.

The Microsoft Active Directory PowerShell module was also imported and used for discovery tasks.

# Lateral Movement

For lateral movement the threat actors relied heavily on copying executable files over SMB and then executing them via remote WMIC calls

C:\Windows\system32\cmd.exe /C wmic /node:"DOMAINCONTROLLER" process call create "C:\3.exe"

While executables and wmic were the preferred options for the threat actor, they did employ several other techniques.

Remote Cobalt Strike beacons were started with services and PowerShell several times in the environment.

During the final stages the threat actor used RDP to move between a few servers as part of their final actions.

At that time, a Cobalt Strike beacon executable was executed as a service on a remote host for testing the final ransom deployment.

# Command and Control

# BazarLoader:


This server was seen communicating with multiple internal systems:

In addition to these command and control methods, one more network anomaly was observed. This was not used for primary command and control and the amount of data sent was small so we do not know the full intentions of the activity but several critical systems like domain controllers and file servers made connections to TOR nodes initiated by the threat actors.

# Exfiltration
The threat actor on the second day of the intrusion downloaded WinSCP to the file server and proceeded to install the program there.

C:\Users\REDACTED\AppData\Local\Temp\1\is-HCFKT.tmp\WinSCP-5.19.1-Setup.tmp" /SL5="$A02B0,10288106,864256,C:\Users\USER\Desktop\WinSCP-5.19.1-Setup.exe"

The threat actor then proceeded to connect over port 22 to a server in Romania.

As the traffic was encrypted we can’t conclusively determine what data was exfiltrated. However we can infer that the choice to deploy on the file server was due to the data present and ease to move the data.

Another data point is that following the exfiltration canary documents present in the shares reported in as being opened from an IP on a Virtual Private Host provider in New York, USA.

# Impact
During the overnight hours of the 2nd day the threat actors began moving on their final objectives. This included testing their ransomware in the compromised environment before deploying across the domain.

They initiated RDP connections and a Cobalt Strike beacon executable file to a endpoint not yet interacted with by the threat actors. The threat actor then transferred a Conti executable file to several endpoints named test.exe.

These test ransom files were then called remotely using wmic as seen in the previous lateral movement activity.

C:\Windows\system32\cmd.exe /C wmic /node:"ENDPOINT" process call create "C:\test.exe"

After testing on several endpoints, the threat actors dropped a renamed version of the file on several servers in the environment and executed by hand using their RDP session.

When executed in this manner, the ransomware payload attempts to spread laterally over SMB.

From there, the threat actors left the environment with this note and domain wide encryption completed about 32 hours after the initial beachhead BazarLoader was executed.

# MITRE ATT&CK DATASET
Pass the Hash – T1550.002
Process Injection – T1055
PowerShell – T1059.001
Remote System Discovery – T1018
Service Execution – T1569.002
Windows Command Shell – T1059.003
Account Discovery – T1087
Domain Trust Discovery – T1482
System Information Discovery – T1082
Remote Services – T1021
Windows Management Instrumentation – T1047
Exfiltration Over Alternative Protocol – T1048
Remote Desktop Protocol – T1021.001
SMB/Windows Admin Shares – T1021.002
Data Encrypted for Impact – T1486
Security Software Discovery – T1518.001
Query Registry – T1012