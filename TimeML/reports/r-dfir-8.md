# Case Summary

In this intrusion, a threat actor abused the CVE-2022-30190 (Follina) vulnerability, where exploit code was embedded inside a malicious Word document to gain initial access. We assess with medium to high confidence that the documents likely arrived by the means of thread-hijacked emails from distribution channels used by TA570.

Upon execution of the weaponized Word document, a HTML file was retrieved from a remote server containing a PowerShell payload. The payload contains base64-encoded content and is used to download Qbot DLLs inside the user’s Temp directory. The Qbot DLL was executed via regsvr32.exe and the activity was immediately followed by injection into legitimate processes (explorer.exe) on the host.

The injected process spawned Windows utilities such as whoami , net.exe and nslookup , to perform discovery activity and also established connection to Qbot C2 servers. Almost an hour later, the threat actors leveraged a Windows built-in utility, esentutl.exe , to extract browser data, a technique also observed in earlier cases. [1][2]

Qbot used scheduled task creation as a persistence mechanism. The scheduled task contained a PowerShell command referencing multiple C2 IP addresses stored as base64-encoded blob in randomly named keys under the HKCU registry hive.

After this activity, the threat actor proceeded with the remote creation of Qbot DLLs over SMB on multiple hosts throughout the environment. They then added multiple folders to the Windows Defender exclusions list on each of the infected machines to evade defenses, as we have seen before with Qbot. Remote services were then used to execute the DLLs.

A Cobalt Strike server connection was witnessed within the first hour, but it wasn’t until after lateral movement occurred that activity from that server began. Utilities such as nltest.exe and AdFind were executed by the injected Cobalt Strike process (explorer.exe). The injected process was also used to access the LSASS system process. Then, the threat actors installed a remote management tool named NetSupport Manager. Within 20 minutes of the installation, the threat actor moved laterally to the domain controller via a Remote Desktop session.

On the domain controller, the tool Atera Remote Management was deployed, a popular tool used by attackers for controlling victim machines. This was the last adversarial activity observed for the day.

The threat actors checked-in early the next day and downloaded a tool named Network Scanner by SoftPerfect on a domain controller. The tool was executed, which ran a port scan across the network. Finally, the threat actors connected to one of the file share servers via RDP and accessed sensitive documents.

No further attacker activity was observed before the threat actors were evicted from the environment.

# Initial Access

Ever since the disclosure of the Follina vulnerability (CVE-2022-30190) earlier this year, threat actors have been known to leverage the flaw in various phishing campaigns. Delivery of this intrusion was linked to TA570, using hijacked email threads to deliver the initial payload. This intrusion started after a Word document, weaponized with Follina exploit code, was used to deliver and infect the host with Qbot malware.

When dealing with a Word document based on the OOXML format, associated files and folders are stored within a compressed ZIP archive. These items can be easily extracted by using an arbitrary zip utility like unzip . One of the embedded files that requires inspection during the analysis of a Follina maldoc, is named document.xml.rels

This “relationship” (RELS) file contained an external reference to a remote HTML file, configured to be retrieved and loaded when the Word document is opened, or viewed in Preview Mode.

At the bottom of the retrieved HTML page source, the script tag was defined and contained malicious JavaScript code that called the ms-msdt scheme.

When a system is vulnerable to Follina (CVE-2022-30190), the code will be interpreted and executed by msdt.exe (Microsoft Support Diagnostic Tool). A good detection opportunity is to monitor for this process being spawned by a Microsoft Office application such as WINWORD.EXE

In our case, the payload contained base64-encoded PowerShell code. The decoded payload is also logged in EventID 4104 (script block logging) upon execution by the PowerShell engine.

The Follina payload was designed to download Qbot libraries from three different URLs, drop the files inside the user’s temp directory, and finally execute the DLLs using regsvr32.exe


# Execution

Upon execution of the MSDT payload, a new instance of the sdiagnhost.exe (Scripted Diagnostics Native Host) was spawned. This process was ultimately responsible for invoking the Follina payload, starting, in our case, three child instances of regsrv32.exe .

After execution of the payload, the XML file PCW.debugreport.xml was created in the %localappdata%\Diagnostics. directory. This file can serve as a valuable artifact when analyzing Follina exploitation (attempts). The payload, preceded by its recursive path, can be found in the TargetPath element of this XML-file. The payload configured to execute on the system is embedded in this file.

# Persistence

Qbot maintained persistence by creating scheduled tasks across multiple endpoints. An example of a command that was executed can be seen below:

The scheduled task creation events were recorded in the Microsoft-Windows-TaskScheduler/Operational log.

Inspection of the scheduled task showed that PowerShell referenced a registry key with a random generated value. This value differed from endpoint to endpoint:

The data of this registry key consisted of a base64-encoded string:

Decoding the base64-encoded string revealed a significant number of QBot’s C2 IPv4 addresses and ports:

C2 IPv4s are provided in the IoC section of this report.

The SysWow64\Explorer.exe process was also observed cycling through a number of domains – indicated by the DNS requests with a QueryStatus of RCODE:0 (NO ERROR).

In addition, several connectivity checks were made to email relay services:

# Defense Evasion

As reported earlier this year, QBot is known for using process hollowing. In this case, the 32-bit version of explorer.exe (indicated by the use of C:\Windows\SysWOW64) was started in a suspended state, which was then used as a target for injection.

Inspecting memory dumped from the host, the injected processes were easy to discover using Volatility and the malfind module. Looking for output that included explorer.exe and contains the VAD tag PAGE_EXECUTE_READWRITE and MZ headers in the memory space, common attributes observed for process injection in memory.

The injected explorer.exe process was used to spawn and inject into additional instances of explorer.exe (32-bit). An example event can be seen below. Source PID 11672 belonging to QBot, injected a DLL into PID 3592, which we discovered was part of Cobalt Strike C2 communication

Using the injected process id’s, and process names, we can then match that to the network connections observed using the volatility netscan module, discovering both the injected Qbot (PID 3992) and Cobalt strike (PID 5620) explorer processes. (The data below comes from a different host than the prior log.)

Various folders were added as an exclusion for Windows Defender, commonly used by QBot, as a ‘drop zone’ for both execution and persistence.

# Credential Access

Qbot attempted to steal credentials from the Credentials Manager.

On one of the targeted systems, the injected explorer process opened a handle with suspicious access rights to a thread in the LSASS process. Credential dumping tools like Mimikatz often request this level of access and corresponds to the following access rights:



We observed the LSASS process interaction from the injected Explorer process at two different access levels, 0x1410:

In addition, on one host, the average LSASS interaction, with access right 0x1FFFFF (PROCESS_ALL_ACCESS) by the explorer process was ~13K every two hours. A significant volume of events.

The article “You Bet Your Lsass: Hunting LSASS Access” by Splunk details examples of LSASS credential dumping.

# Discovery

The following discovery commands were initiated by Qbot through the injected process on the beachhead system:

Later, more discovery commands were observed from the Cobalt Strike injected process on another victim system:

On the same host, AdFind was executed to enumerate all computer objects in the Active Directory domain:

On second day of the intrusion, threat attackers downloaded a tool named Network Scanner (netscan.exe) by SoftPerfect on the domain controller, using Internet Explorer.

The tool was used to trigger another port scan, this time targeting TCP ports 445 and 3389.

Periodic requests to api.ipify.org were observed throughout the intrusion by the SysWOW64\Explorer process and by the ATERA agent. Ipify.org can be used to determine the public facing IPv4 address of the network. We’ve observed the use of ipify.org in previous cases.

# Lateral Movement

Qbot DLLs were created remotely from the beachhead host and saved in the administrative C$ share of other hosts within the network.

This activity was also clearly visible in Zeek SMB File data in the network.

A local service was also registered on each of the targeted systems, configured to execute the Qbot DLL using regsvr32.exe

The following Suricata signatures identified both the remote file creation and service registration events:

Execution of the new service was observed shorty after invoking the Qbot DLL.

The threat actor also used RDP to pivot between systems on the network such as a domain controller and a file server.

The creation of the rdpclip.exe process on the target host is another indication that a RDP connection was successful. The start of this process by a non-human account is another great detection opportunity.

# Collection

Qbot used various information stealing modules to extract sensitive information from the beachhead host.

Outlook was started, possibly to steal e-mail messages. However, we could not find evidence to conclusively support this.

Qbot also used the Windows built-in utility esentutl.exe to extract browser data from Internet Explorer and Microsoft Edge:

On a file server, we observed the threat actor manually inspecting files using various built-in viewers. For example, for viewing PDF files, Internet Explorer was used to view these files. For DOCX files, WordPad was used.

An indication that these files were viewed locally on the network, was the presence of the ‘OpenWith’ process:

# Command and Control

The following C2 IP-addresses/domains belonging to Qbot were recorded during this intrusion:

The (default) named pipe postex_4c14 was observed from a Cobalt Strike injected explore.exe process.

After dumping one of the injected explorer.exe processes, we were able to extract the beacon configuration using the 1768.py tool, by Didier Stevens.

More details about this IP-address:

Cobalt Strike config:

The remote admin tool named client32.exe (NetSupport Manager) and its associated libraries were dropped on a workstation in the C:\ProgramData\MSN Devices directory.

The exchanged network traffic was unencrypted and contained the custom user-agent NetSupport Manager/1.3

The threat actor installed and enabled the Atera RMM agent on the domain controller.

The MSI installer, named setup_undefined.msi was configured to drop the installation files in the C:\Program Files\ATERA Networks\AteraAgent directory.

Atera integrated with another remote admin tool known as “SplashTop“, which it dropped on the file system.

Periodic ‘heartbeat’ process events of Atera were observed:


The “Splashtop” remote admin tool was started as a background process.

Both remote admin tools allowed the threat actors to persist and obtain remote access to the environment, without relying on RDP.

The Atera Agent account used was retained in the host Software registry hive:

# Exfiltration

No exfiltration observed.

# Impact

Sensitive documents (.pdf, .docx) were viewed in a RDP session on the file server using Notepad++ and Wordpad. After this, no further activity from the threat actor was observed.
