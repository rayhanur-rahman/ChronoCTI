# Case Summary

The threat actor was able to enter the network when a user endpoint was compromised by an IcedID payload contained within an ISO image. We have high confidence this payload was delivered via email, however we were not able to identify the delivery email.

The ISO contained a DLL file (IcedID malware) and a LNK shortcut to execute it. The end user after clicking into the ISO file, could see just a single file named “document”, which is a LNK shortcut to a hidden DLL packaged in the ISO. When the user clicks on the LNK file, the IcedID DLL is executed.

Upon this execution of the IcedID DLL, a battery of discovery tasks were executed using built-in Windows utilities like ipconfig, systeminfo, nltest, net, and chcp. The IcedID malware also created a scheduled task as a means of persistence on the beachhead host.

Around two hours later, Cobalt Strike was deployed using process hollowing and injection techniques. This marked the start of “hands-on-keyboard” activity by the threat actors. This activity included using AdFind through a batch script called adfind.bat to perform discovery of the target organizations active directory structure. The threat actors gathered host based network information by running a batch script named ns.bat , which ran nslookup for each host in the environment.

The Cobalt Strike process then proceeded to access LSASS memory to extract credentials, which a few minutes later were tested to run remote WMI discovery tasks on a server. After confirming their credentials worked with the WMI actions, the threat actor proceeded to RDP into that server, and attempted to drop and execute a Cobalt Strike DLL beacon on that server. This appeared to fail so the threat actor then opened cmd and proceeded to execute a PowerShell Cobalt Strike Beacon. This Beacon was successful in connecting to the same command and control server observed on the beachhead host.

For the next hour, the threat actor proceeded to make RDP connections to other servers in the environment. Once the threat actor had a handle on the layout of the domain, they prepared to deploy the ransomware by copying the ransomware (named ttsel.exe ) to each host through the C$ share folder. They used two methods of remote execution to detonate the ransomware binary, WMI and PsExec. This ransomware deployment concluded less than four hours from the initial IcedID execution.

While the ransom note indicated the threat actor stole data, we did not observe any overt exfiltration of data; however, it is possible that the threat actors used IcedID or Cobalt Strike to transmit sensitive data.

# Analysis

The threat actor gained initial access through the common malware, IcedID. The payload was delivered within an ISO file, docs_invoice_173.iso , via email, where a user opened and executed the malware. Shout out to @k3dg3 for making these ISOs available. We were able to determine the user mounted the ISO using the Event ID 12 in Microsoft-Windows-VHDMP-Operational.evtx as shown below:

When mounted, the ISO contained two files:


Typical end user perspective after opening the ISO file:

The file document.lnk is a shortcut or lnk file and dar.dll was the IcedID payload.

# Execution

A quick look at document.lnk ‘s properties highlight the command line that is executed on launch:



But we can do a lot better than that with a .lnk file! These .lnk files provide a wealth of knowledge to investigators. For example, below is a partial output of the tool LECmd.exe (by Eric Zimmerman). When used on the file document.lnk , it parses out metadata such as when the shortcut file was made, what hostname and the MAC Address of the device it was created on and even the directory path of the user that created it!

We were able to determine when the user clicked on the lnk file and when a new process was created with the command line mentioned above. Furthermore, the Event ID 4663 in Security.evtx highlighted when explorer.exe accessed document.lnk :

Additionally, the context of execution location and parent process can also be used to follow the user execution process.

Shortly after execution of the payload, several child processes were spawned that created persistence and began discovery on the host.

This included an instance of C:\Windows\SysWOW64\cmd.exe , which the IcedID malware used to hollow out and then inject a Cobalt Strike beacon into. There were several additional indications of Cobalt Strike we observed to verify it was utilized by the threat actor. The cmd.exe process spawned a suspicious instance of rundll32.exe . There were no command line arguments for this process which is atypical for rundll32.exe. A further indication was the rundll32.exe process creating a named pipe, postex_304a. This behavior of rundll32.exe and a named pipe that matches postex_[0-9a-f]{4} , is the default behavior used by Cobalt Strike 4.2+ post exploitation jobs. For more information on Cobalt Strike, you can read our article Cobalt Strike, a Defender’s Guide.

When we reviewed the memory of this process, we were able to confirm it was in fact Cobalt Strike when we successfully extracted the beacon configuration (additional details can be found in the Command and Control section). The threat actor also executed a PowerShell Cobalt Strike payload on some servers:

This payload is using the default Cobalt Strike obfuscation scheme (XOR 35), and can easily be decoded using CyberChef:

The output can be analyzed using scdbg to highlight what Windows API calls the shellcode makes:

Prior to using the PowerShell beacon the threat actor dropped a DLL beacon on the server (p227.dll), but this appears to have failed for unknown reasons after which, the threat actor moved on to the PowerShell beacon which executed successfully.

# Persistence

After the initial execution of the IcedID malware, it established persistence by creating a copy of the malware (Ulfefi32.dll) in the AppData directory of the affected user and created a scheduled task to execute it every hour. The task \kajeavmeva_{B8C1A6A8-541E-8280-8C9A-74DF5295B61A} was created with the execution action below:

# Defense Evasion

Process injection was observed during the intrusion by both IcedID and Cobalt Strike. On one system, the threat actor injected into the winlogon process.

Cobalt Strike Processes Identified by in Memory Yara Scanning.

Volatility Malfind output shows the embedded MZ header in the winlogon process with the setting PAGE_EXECUTE_READWRITE protection settings on the memory space, a commonly observed attribute of process injection.

Network connections to the Cobalt Strike server by winlogon were also observed in the process logs.

# Credential Access

# LSASS Access

Suspicious accesses to LSASS process memory were observed during this intrusion. As illustrated below, those accesses have been made using both Windows Task Manager and rundll32.exe which is assessed to be a Cobalt Strike temporary beacon (as shown in the Execution graph):

The threat actors managed to steal administrator account credentials, allowing them to move laterally across the Active Directory domain.

# Discovery

As mentioned in the Execution section, the IcedID process ran several initial discovery commands that provided environmental information about the host, network, and domain, to the threat actor. Given the timing of these commands were immediately after the execution of IcedID, we believe these commands were executed automatically upon check-in.



A cmd.exe process spawned from IcedID which ran additional discovery queries. The threat actor dropped the following files in C:\Windows\Temp directory:

The actor used the Active Directory enumeration tool AdFind to collect information such as the users, computers and subnets in the domain.

The file ad.7z , was the resulting output of the AdFind commands above. After that, an additional batch script was created, ns.bat , which enumerated all host names in the domain with nslookup to identify the IP address of the host.

Prior to the first lateral movement from the beachhead host, the threat actor tested credentials and gathered information from their targeted remote server using WMI


# Lateral Movement

# Remote Desktop Protocol

The threat actor used RDP to move laterally to critical hosts. In particular, we have evidence on multiple machines of RDP using the Administrator account.

The attacker in this intrusion initiated RDP connections from a workstation, named TERZITERZI. See the screenshot below:

The RDP connections were established from the Cobalt Strike process running the beacon indicating the threat actor utilizing proxy on the beachhead host to facilitate the RDP traffic.:

# PsExec

PsExec was used to facilitate the ransomware execution. The threat actor utilized the “-r” option in PsExec to define a custom name ( mstdc ) of the remote service created on the target host (by default it’s PSEXESVC).

# WMI

Through-out the intrusion the threat actor was also observed using WMIC to perform lateral activities including discovery actions remotely, and as a second option, to ensure all the remote hosts successfully executed the final ransomware payload. The WMIC commands prefaced with /node:IP Address allowed the threat actor to run commands on remote hosts.

# Command and Control

# IcedID

As we saw from the execution section, dar.dll was used to contact the below domains:


# Cobalt Strike


# Exfiltration

While the ransom note indicated the threat actor stole data, we did not observe any overt exfiltration of data; however, it is possible that the threat actors used IcedID or Cobalt Strike to transmit sensitive data.

# Impact

Just shy of four hours into the intrusion, the threat actors began acting on their final objectives, domain wide ransomware deployment. With their pivot point from one of the domain controllers, the actor used a combination of both PsExec and WMI to remotely execute the ransomware.

They first copied the payload, ttsel.exe , to the C$ share of each host on the network.


# PsExec

The threat actor utilized the “-r” option in PsExec to define a custom name (“mstdc”) of the remote service created on the target host (by default is PSEXESVC).

This resulted in the file C:\Windows\mstdc.exe being created on the target endpoint when PsExec was executed.

# WMI

The alternate execution method the actor employed was a WMI call to start a remote process on the target host.

The Quantum ransomware began to encrypt files across all hosts in the environment which then dropped the following ransom note: README_TO_DECRYPT.html

The Quantum portal had a unique option to create and set a password to the negotiation chat.

Once authenticated, it displays the chat window with the threat actor.



