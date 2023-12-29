# Case Summary
 This campaign, observed in May 2023, leveraged email for the initial delivery mechanism. After clicking-through the link in an email, the victim would be redirected through a series of URLs before being presented a file download at the final landing page.

The file download was a Truebot executable, which appeared as a fake Adobe Acrobat document. After executing the file, Truebot copied and renamed itself. Minutes later, Truebot loaded FlawedGrace onto the host. While loading this malware, it used a series of modifications to the registry and Print Spooler service to both escalate privileges and establish persistence. From there, FlawedGrace’s execution routine involved storing as well as extracting, encoded and encrypted payloads in registry; the creation of temporary scheduled tasks and the injection of the final payload into msiexec.exe and svchost.exe.

After this execution, the threat actors proceeded to disable Windows Defender Real-Time monitoring and added exclusions for executable files on the host. We later observed FlawedGrace creating a temporary user within the local Administrators and Remote Desktop Users groups. With this user, a tunneled RDP connection was attempted from FlawedGrace’s C2 servers. Seemingly without success, the threat actors removed the user after 15 minutes before repeating the procedure a second time. After the second failed attempt, the threat actors removed the user and did not attempt further RDP communications. The FlawedGrace process then performed discovery surrounding the domain administrators and domain controllers.

Approximately two hours after the initial execution, Truebot loaded Cobalt Strike into memory and then went dormant for the next two hours. This ended the use of Truebot for the rest of the intrusion, with FlawedGrace and Cobalt Strike being leveraged for the rest of the threat actors activity. Now, four hours into the intrusion the threat actors, through the Cobalt Strike beacon, started another round of discovery commands using net, nltest, tasklist and AdFind.exe.

After having accessed LSASS memory on the beachhead host, the threat actors leveraged a local administrator hash to perform pass-the-hash lateral movement through the environment. The threat actors used Impacket’s atexec to execute discovery commands on remote hosts. These discovery commands included the PowerShell, cmdlet Get-MpComputerStatus, and quser. After these discovery commands, the threat actors used Cobalt Strike’s jump psexec module to further move between hosts. Following each lateral movement action, Cobalt Strike loaded FlawedGrace in memory on all hosts accessed by the adversary.

Around five hours post initial access, the threat actors went silent. FlawedGrace and Cobalt Strike went dormant on all hosts except the beachhead system. Seventeen hours later, the threat actors returned to the network and issued enumeration commands to discover network shares. Around that time, we observed signs of data exfiltration from the environment.

Roughly four hours after the exfiltration began, merely 29 hours into the intrusion, the threat actors deployed the MBR Killer wiper on all hosts where FlawedGrace had been running, including a file server. This executable overwrote the MBR (Master Boot Record) and triggered a reboot, rendering the hosts unusable. Numerous systems were left at the boot screen, inoperable.

Following these actions, the threat actors lost all footholds to the network. While data has been exfiltrated, no responsibility has been claimed and no extortion notes were found.

# Analysis

As is the case for many intrusions, initial access was obtained through an email campaign. Reports by Proofpoint point to this campaign using the 404 Traffic Distribution System (TDS) service. The following Proofpoint screenshots highlight how “404 TDS” is leveraged to turn email campaigns into drive-by downloads.

During this intrusion, the TDS redirection was reported by Proofpoint as follows:

The resulting hxxps[://]ecorfan[.]org/base/sj/Document_may_24_16654[.]exe URL performed a drive-by download, delivering the initial Truebot payload Document_may_24_16654.exe.

The usage of the deceptive Document_may_24_16654.exe naming would then entice fooled users to open what they believe is a recent document.

Truebot was used to load both Cobalt Strike and FlawedGrace on the initial host.

# Truebot

The payload, Document_may_24_16654.exe, imitated a PDF document by using an icon of an Adobe Acrobat document.

This was further enforced upon the user when the malware created the following message claiming Adobe Acrobat failed to open the file (even if Acrobat was not installed on the target system).

Truebot’s first action was to create an exact copy of itself in the following path and then execute it.

The newly created copy reached out to the Truebot C2 of essadonio[.]com (45.182.189[.]71).

# Cobalt Strike

Truebot spawned an instance of C:\Windows\system32\cmd.exe which was followed-up by a remote thread created in the new process. The memory of cmd.exe clearly indicated signs of injection, as seen below, where a section of memory was set to execute and read write as well as the telltale MZ (0x4d5a) header of a PE binary.

Further investigation identified the injected module beacon.dll at the same offset as above (0x164a2fb0000) in the loaded modules of the target process.

This is the default naming convention for generating payloads from Cobalt Strike, and stands out further as the DLL did not have a path on disk.

This Cobalt Strike beacon was used both to query information and move around the network which will be discussed in later sections.

During the intrusion, the process running the beacon spawned the following process command line:


As we have observed in previous cases, threat actors make mistakes too! In this case, the shell argument is a beacon command to spawn a new process. Here, we see it mashed between two commands indicating human error.

# FlawedGrace

Truebot loaded another more complicated payload alongside Cobalt Strike, the Remote Access Trojan (RAT) “FlawedGrace.” The initial execution chain of this malware was observed across multiple endpoints when they were first infected.

The first observed behavior of this chain was to create a new instance of spoolsv.exe that was shortly accessed by the Truebot process (RuntimeBroker.exe). This process would then spawn instances of msiexec.exe, which would reach out to the initial FlawedGrace C2 of 92.118.36[.]199.

Instead of creating a task through schtasks.exe, FlawedGrace used three different methods to create new scheduled tasks. The first was to import the taskschd.dll library into the main host process to create a new task called 2. The task was removed as soon as the new command gained SYSTEM-level privileges.

The second was observed within obfuscated PowerShell, where the Schedule.Service COM Object was used to create a new task.

The last method was to use native PowerShell cmdlets to register a task.

The initial task \2 ran the following command which was scheduled for the next minute after creation:

The first working part of the command decodes the obfuscated string and results in the following PowerShell code:

The decoded code sets the variable $j to the value {8D81676C-7F63-8F81-676E-666B6C67818D}. It then reads a value from the Windows Registry under the SOFTWARE\2\CLSID\{8D81676C-7F63-8F81-676E-666B6C67818D}\Type key, converts the value to a UTF-8 string, and executes it.

Based on script block logging, the PowerShell script contained in the registry would manipulate and populate further registry keys in the HKLM:\Software\Classes\CLSID\ key using HKLM:\Software\2\CLSID as a staging location. The malware created specific key names attempting to blend in with other COM objects which were also kept within this location. The malware would create additional scheduled tasks using one of the following names selected randomly:

The final loaded PowerShell script was stored here:

The PowerShell code in TypeLib would decrypt the RC4 encrypted payload stored in ProgID using a key based on the hostname ($env:COMPUTERNAME) of the target host and then inject the DLL into the FlawedGrace msiexec.exe and svchost.exe processes.



We manually reversed the RC4 function to decrypt the DLL, which matched the same hash as the FlawedGrace processes in memory (c.dll)

The PE details of the injected module c.dll was of a DLL with an original name of icuin.dll, claiming to be part of the International Components for Unicode libraries, as see below:

When FlawedGrace attempted to run certain commands on the target host, it displayed the specific behavior of spawning an instance of cmd.exe as a sacrificial intermediate process.

Shortly after these instances of cmd.exe were spawned, they would be accessed by the FlawedGrace process svchost.exe.

Of note, the arguments in these processes command lines used flags that do not exist (/I, /SI, /O, /SO):

A Sigma rule to detect this activity can be found at the end of the report.

Threat actors established persistence on all infected hosts they pivoted to in the network. The scheduled tasks were configured to load FlawedGrace using PowerShell. While the tasks created initially to run FlawedGrace were registered with the task name of \2 , tasks created for persistence used a naming convention mimicking various system tasks and placed under the \Microsoft\Windows\ task path.

These tasks were then set up for a BootTrigger to restart the malware.

Please refer to the “FlawedGrace” portion of the Execution section for details on the different execution methods threat actors used to register these scheduled tasks.

On the beachhead host, the threat actors added a user account named adminr. This account was then added to the Local Administrators group and Remote Desktop Users group. The account was observed being used to test RDP tunneling in the environment. This account was added and removed several times, but after the first three hours of access, it was deleted and not re-added by the threat actors.

We believe that to elevate their privileges, the threat actor might have abused an odd default Windows behavior surrounding changing service permissions:

The change in required [service] privileges takes effect the next time the service is started. […] If you do not set the required privileges, the SCM uses all the privileges assigned by default to the process token. – Source

To abuse this SCM behavior, the threat actors were seen stopping the Spooler service before deleting the service’s HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Spooler\RequiredPrivileges registry entry, restarting the service and injecting into the newly created spoolsv.exe process.

The effect of deleting the RequiredPrivileges registry entry can be observed in the following screenshots where the post-modification spoolsv.exe process is seen with a flurry of additional permissions, all of which the threat actors may enjoy post-injection.

Scheduled tasks were used by the threat actors to run much of their malware as SYSTEM. The initial execution tasks for FlawedGrace used the \2 registered task were created to run under SYSTEM as seen by the Author in the task details.

This could then be seen with the user NT AUTHORITY\SYSTEM running the task command and arguments in process creation logs.

Shortly after execution, the Truebot malware copied the initial malware to a new location renaming itself to RuntimeBroker.exe, masquerading as an executable responsible for managing certain application permissions.

As covered in the execution section, FlawedGrace uses a number of techniques to perform evasion, including encoding, encryption, and storing payloads in the registry. When executing, command-line data was encoded. See the Execution section for a breakdown of the encoding.

During runtime, the FlawedGrace malware decrypts the RC4 encrypted registry stored payload:

We observed process injection by all three malware families in this intrusion. First, Truebot used it to inject the Cobalt Strike payload into a cmd.exe process.

Reviewing memory dumps, the injected MZ header for the Cobalt Strike beacon is easily observable in the injected cmd.exe process.

Cobalt Strike was not the only injection with observable headers, each svchost.exe and msiexec.exe also contained telltale injection signs like PAGE_EXECUTE_READWRITE protection and MZ file headers.

Standard Cobalt Strike named pipes using the postex_* patterns were observed throughout the intrusion.

Some Registry Items were removed during the FlawedGrace PowerShell execution, specifically the items stored in HKLM:\SOFTWARE\2\:

File removal was observed with AdFind.exe being removed by the threat actors as well as Cobalt Strike beacon removal, after being used for lateral movement.

Approximately one hour after the initial infection, we observed the threat actors using a remote dumping tool to extract credentials via the registry hives. At this time, we cannot confidently name the tool that they used. The logs of the credential access activity resemble those of secretsdump , which is a tool that is part of the Impacket library.

We noticed the creation of two temporary files in the C:\Windows\System32\ directory. The names of these files consisted of eight randomly generated characters. Prior to that, a service called “RemoteRegistry” was instructed to start. The Remote Registry allows administrators to access, modify, and manage the registry settings of other computers on a network. Once again, an example of this approach can be seen through secretsdump ( secretsdump.py#L374 ).

We believe that the threat actors utilized an older version of the impacket Library. This is because as of May 4th, 2023, version 0.10.0 modified the location where the registry hives would extract. They are now saved as temp files under C:\Windows\Temp directory. However, as with this case, we observed the temp files under C:\Windows\System32, which indicates the use of an older version of impacket.

After reviewing the Security event logs for event ID 4624 and the Sysmon event logs (event ID 1 & 10) on the beachhead host, we have determined that the attackers utilized Pass-The-Hash to run commands on remote hosts as the local administrator user.



When considering this evidence, the time sequence is a crucial factor. To prevent false positives, defenders can group related events together based on their time of execution. However, we have also included specific Sigma rules that are capable of identifying these execution patterns in isolation. Please refer to these rules in the Detections section of this report.

We also observed the threat actors utilizing for loops to iterate through text files located in the C:\ProgramData directory. These files contained the hostname of all workstations and servers within the network environment. The aim of this loop was to execute discovery commands using ping to locate live endpoints and net view to enumerate their open shares. In addition, they used the dir command to test the feasibility of connecting to remote servers within the network through the local administrator’s account.

In addition to using net view to find open shares, the attackers also examined the registry of the local host and saved a list of all mapped shares in a text file called 1.txt. We also observed them using the wmic command to execute the same action on a remote host.

They later viewed and deleted the text file using the type and del commands respectively.

To check the status of the antimalware software that is installed, they used PowerShell along with the Get-MpComputerStatus cmdlet. This command was run on multiple hosts in the environment. We believe the execution of this command came through atexec.py, which is part of the impacket collection.

AdFind was used in this intrusion, however, the threat actors limited the output only to collect operating system information and specific attributes from the domain user objects.

We also observed some other miscellaneous commands that we tend to see in every intrusion. These discovery commands collected information about the administrator groups and users. Although, there was one notable use of the tasklist command where threat actors used the /S parameter to retrieve the list of currently running processes from remote hosts.


The threat actors predominately used Cobalt Strike’s jump psexec module to move to new hosts. The event ID 7045 (A new service was installed in the system) in System.evtx showed clear evidence of the malicious service being installed.

The DFIR Report’s defender’s guide to Cobalt Strike discusses this in further detail.

As seen below, when filtered to these events, we observed the threat actor moving to a new system every 5-20 minutes.

As we mentioned in the discovery phase, threat actors also used atexec to execute commands on remote hosts. Impacket’s atexec module allows the remote execution of commands on a Windows system by leveraging the Task Scheduler service. The module registers a task on a remote system that would execute the instructed command. The task would then be deleted upon successful execution. The example below is from the Security event logs, event ID 4698.

To showcase the hardcoded lines of code responsible for the observed execution flow, we have included a snippet from atexec’s official GitHub page in the screenshot above. Threat actors used Cobalt Strike to facilitate the execution of this module.

In some other cases, we saw threat actors executing the below command from the beachhead host toward a number of remote hosts.

This command uses Windows Management Instrumentation CommandLine (WMIC) to remotely retrieve the executable paths of all running processes from a number of remote hosts.

/node:<remote host>: specifies the remote host. process: represents the WMI class to be queried; in this case, it’s related to running processes on the target system. get executablepath: is to retrieve the property ‘ExecutablePath’, which contains the complete path to the executable for each running process.

We’ve created a chart displaying the times (UTC) when threat actors were active in the network. The data is based on a sample of affected hosts, but the pattern of activity remained consistent throughout the intrusion.

Throughout the intrusion, the attackers staged results from their discovery within either the temporary directory or C:\ProgramData. As a reminder, the following discovery commands redirected their results to C:\ProgramData\hosts_live.txt and C:\ProgramData\servers_live.txt.

Additionally, populated and collected files included:

The extensive creation of text files (.txt and .csv) within the C:\ProgramData directory provides detection and hunting opportunities as legitimate software commonly leverages sub-folders of this directory.

# Truebot

Communication to the Truebot C2 server at 45.182.189[.]71 began shortly after the execution of the initial access executable. This connection, however, only lasted for around two hours on the beachhead host, and activity ceased after the Cobalt Strike beacon payload was loaded on the host.

Looking at memory collected from the beachhead host, we can observe the connection to the Truebot command and control server made by Runtimebroker.exe, the renamed executable copied from the initial malware payload.

# Flawed Grace

The FlawedGrace malware is unlike any command and control we’ve covered in previous reports as it uses a custom binary protocol as opposed to the more common usage of application layer protocols like HTTP/s, RDP, or SSH.

Over the course of the intrusion, the threat actors pivoted to several command and control addresses with times of overlap between several C2 addresses. This activity took place several times over the course of the intrusion.

As well as pivoting between command and control servers, the threat actors started communication from various hosts over the course of the intrusion with no host maintaining constant beaconing.

As this malware uses a custom protocol, normal indicators like SSL certificate or JA3 were not present.

Traces of command and control activity were present in memory on several hosts from the beachhead to multiple servers. Most no longer showed the responsible process, but at least one host had an active connection from an injected svchost.exe process to FlawedGrace command and control visible.

During the first day of the intrusion, we observed a network signature hit for RDP tunneling from one of the FlawedGrace command and control servers, but due to no follow-up activity, it would appear that this did not function properly for the threat actors.

This likely also explains the removal of the local user account that had been added to the Remote Desktop Users group.

# Cobalt Strike

Cobalt Strike, unlike the other two malware families observed, remained in constant communication with its command and control server after the first beacon was loaded until the end of the intrusion.

While the Cobalt Strike command and control stayed active over the intrusion the threat actors did selectively deploy and remove it on hosts with only the beachhead host maintaining beaconing activity for the whole duration.


Cobalt Strike beacon configuration:

On the second day of the intrusion, a connection from a file server began to the IP 139.60.160[.]166 over port 4433. The process tree indicates the FlawedGrace malware injected into svchost and msiexec on the file server and initiated the transfer. Other reports have indicated Truebot/FlawedGrace intrusions have deployed custom tools for exfiltration. We did not observe any additional binary dropped to disk to perform the exfiltration. As the FlawedGrace process established the TCP connection, we assess with moderate confidence the capability was included in the FlawedGrace malware itself.

Two distinct exfiltration periods were observed taking place around two hours apart.

The network traffic was not sent over a TLS connection but just the TCP protocol.

This data was not observable in plain text, indicating likely other obfuscation/encryption methods in use. Using flow data between the two sessions, we were able to verify gigabytes of data were exfiltrated.

Within four hours of the completed exfiltration, merely 29 hours after initial execution, the threat actors started deploying MBR Killer (aka KillDisk), well-known for its usage during the 2016 Banco de Chile attack. As documented by Flashpoint, the wiper is an NSIS (Nullsoft Scriptable Install System) script capable of wiping a device’s MBR (Master Boot Record), MFT (Master File Table), VBR (Volume Boot Record) and EBR (Extended Boot Record) before forcing a reboot to render a device inoperable. During this destructive stage, the threat actors named the file C:\ProgramData\chrome.exe on the beachhead, while on other servers the C:\Windows\Temp\[0-9a-f]{32}.exe naming pattern was used.

As a defense-evasion technique, MBR Killer has been observed using patched NSIS installers relying on non-standard headers. Once the payload signature is corrected, NSIS decompilers such as 7zip (9.34 – 15.05) are able to extract the malicious NSIS script.


This customization provides defenders with a detection opportunity as outlined within the hereafter-provided YARA rules.

During initialization, MBR Killer visually hides itself by moving off-screen.


Once hidden, the malicious installer verifies whether it is being emulated by temporarily patching the native Windows ZwClose function (part of ntdll.dll) to immediately succeed with STATUS_SUCCESS before closing a dummy handle through kernel32::CloseHandle(0x12345678) and validating that, although the handle was invalid, the CloseHandle method succeeded.


If the anti-analysis check succeeds, the script issues the HideWindow NSIS call, which hides the installer and proceeds to validate the existence of the first physical drive \\.\PHYSICALDRIVE0 by opening it.

Once the first \\.\PHYSICALDRIVE0 drive opened, MBR Killer conditionally attempts to wipe:
- MFT (Master File Table) contains metadata about files and directories, such as names, dates and sizes.
- VBR (Volume Boot Record) contains, amongst others, code required to bootstrap the operating system.
- EBR (Extended Boot Record) contains information to describe logical partitions.

MBR Killer then proceeds to wipe the MBR (Master Boot Record) three times by writing 512 empty bytes at offset 0 and attempts to repeat the wiping on the next available disk (\\.\PHYSICALDRIVE1, \\.\PHYSICALDRIVE2, …).

Once the MBR Killer wiper has done its damage, the script attempts to modify its process privileges to enable the SeShutdownPrivilege and initiates a reboot.


To initiate the reboot, MBR Killer calls ExitWindowsEx with:
- EWX_REBOOT (0x2) to cause a reboot
- EWX_FORCE (0x4) to try to force the operation
- SHTDN_REASON_MAJOR_SOFTWARE (0x00030000) to indicate it was software-caused
- SHTDN_REASON_MINOR_UPGRADE (0x00000003) to indicate the software reason is an upgrade.

Worth noting is that even-though the MBR Killer script attempts a reboot, the same functionality is implemented within the NSIS installer itself. Upon reboot, the affected machines were rendered inoperable.

While the wiper we observed was not packed using VM-Protect, the decompiled script is near-similar to the 2016 Banco de Chile wiper component and indicates the source-code was likely shared.

Supporting this theory was the change in NSIS version from v3.0b2 (Released on August 4th, 2015) to v3.04 (Released on December 15th, 2018) alongside the removal of the MBR Killer branding.

While the 2016 sample was bzip2-compressed, the recompiled version now uses the more performant zlib compression.

Functionality-wise, our newly observed wiper performs a justified reboot (0x2, EWX_REBOOT) whereas the Banco de Chile variant merely performed an unjustified shut-down (0x8, EWX_POWEROFF).
