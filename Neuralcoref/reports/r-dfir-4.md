# Collect, Exfiltrate, Sleep, Repeat

In this intrusion from August 2022, we observed a compromise that was initiated with a Word document containing a malicious VBA macro, which established persistence and communication to a command and control server (C2). Upon performing initial discovery and user enumeration, the threat actor used AutoHotkey to launch a keylogger.

AutoHotkey is an open-source scripting language for Microsoft Windows machines that was introduced to provide easy keyboard shortcuts and automation. As described in AutoHotkey documentation, the AHK script can be executed in a number of ways. As observed in this intrusion, the adversary executed the AHK keylogger script by calling a renamed version of AutoHotkey.exe (module.exe) and passing the script’s filename (module.ahk) as a command-line parameter.

The intrusion began with the execution of a malicious macro within a Word document. The document was themed as a job application for the firm Lumen. This tactic has been observed by many threat actor groups, including state sponsored actors in North Korea and Iran. Upon opening the file, the user was prompted to enable macros to complete the form, which began execution of the malware.

Once executed, the macro created a VBS script (Updater.vbs), two PowerShell scripts (temp.ps1 and Script.ps1), and installed persistence through a scheduled task. The implant was fully implemented in PowerShell, which is uncommon compared to many initial access tools today.

Following the execution of the VBA embedded macros, the PowerShell script, Script.ps1, began to connect to the C2 server through an encrypted channel. Around a day after execution, the server became live and began sending instructions to the implant. The instructions obtained from the server were then executed through the temp.ps1 PowerShell script.

The threat actors began executing basic discovery commands, all of which were executed via PowerShell cmdlets or built-in Windows utilities like whoami, net, time, tzutil and tracert; one exception to this was when the threat actors extracted a specific function from the PowerSploit framework, Convert-LDAPProperty, to enumerate domain accounts in the environment. All data collected was then exfiltrated over the existing C2 channel.

On the fourth day of the intrusion, the threat actors became active again by dropping of a set of files that performed keylogger functions. A scheduled task was then created to assist in execution of the keylogger. The keylogger itself was comprised of an executable, module.exe, which was a renamed AutoHotkey binary. This would run the AutoHotkey script module.ahk. Additionally, a PowerShell script called readKey.ps1 would execute in the same task.

On the sixth day of the intrusion, the threat actors returned and collected the data compiled by the keylogger. This was performed using the makecab.exe Windows utility to compress the keylogger files before exfiltrating them to the C2 server. They then dropped another PowerShell script. This script would take a screenshot of the desktop of the infected host. After this data was exfiltrated, the threat actors reviewed the antivirus service status and some additional host data.

The threat actors returned again on the seventh and ninth days to collect the keylogger data. The threat actors were not observed performing any further actions before being evicted from the environment.

One interesting fact about this case is that the initial implant was fully implemented using PowerShell, and no executables were dropped to the victim’s workstation for the implant. It’s also interesting to note that the PowerShell implant was and stayed fully undetectable for a significant period of time. This is contrary to many of our reported cases where the initial access relies on initial access brokers and common malware used by those groups such as Emotet, IcedID, or Qbot.

The use of custom tailored malware points to a more targeted or discerning organization compared to the spray-and-pray approach performed by many access brokers. Reviewing the network traffic, we observed two signatures fire on the C2 traffic – ET MALWARE TA452 Related Backdoor Activity (GET)/(POST). TA452 is an activity group tracked by Proofpoint that translates to the OilRig group. Under other classifications there is overlap with COBALT GYPSY, IRN2, APT34, and Helix Kitten.

Oilrig is suspected of being an Iran based and state sponsored group. This group is widely credited with creating and utilizing various home grown PowerShell frameworks to perform their intrusions. Finally, analyzing the time of the threat actor hands on keyboard actions, the threat actors operated between Saturday and Thursday and no activity on Friday. All activity took place place between 0300-1600 UTC which aligns with 0630-1930 (GMT +3:30) Tehran local time. All of these factors together align to point to the Iranian Oilrig group as the likely threat actors behind this intrusion.

# Analysis

The initial access used in this intrusion was a malicious word document dubbed “Apply Form.docm“. This document purported to be an application form for the technology and telecommunications company Lumen.

This was originally found and shared by @StopMalvertisin in a tweet detailing the lure and the payload. The precise delivery method remains unknown as we do not have direct evidence on how this malicious document was delivered. We assert with a medium level of confidence, based on the previous similar reports, that those documents were likely delivered through spearphishing attachments in emails (T1566).

This intrusion began with the execution of a malicious VBA macro embedded in a word document.

A first look at “Apply Form.docm” with olevba.py, immediately highlights some suspicious behaviors.

First off, the macro gets the name of the user executing the Word document and creates a directory in AppData, if it doesn’t exist:



The malicious VBA macro then created two PowerShell scripts and one VBScript file in “C:\Users\<USER>\AppData\Local\Microsoft\Windows\Update\”



With Sysmon and FileCreate event 11, we can see that WINWORD.EXE successfully created these files:

Then, in order to execute the script and install persistence, a new scheduled task was registered:



The XML above describing the scheduled task was directly embedded in the VBA macro.



The first scheduled task installed using the malicious VBA macro, executed a VBS script, which in turn executed a PowerShell script named Script.ps1.

Script.ps1 contacts the C2 server and executed the base64 commands using temp.ps1.

Event 201 from Microsoft-Windows-TaskScheduler/Operational highlights the successful execution of this scheduled task.

Another scheduled task named MicrosoftEdgeUpdateTaskMachineUC was registered using schtasks.exe on the command line:

The scheduled task was then started manually:

The scheduled task was designed to execute module.exe and a PowerShell script named readKey.ps1. These components will be explained later in the collection section of this report.



The threat actor’s keylogger used in the intrusion implemented a XOR operation to encode the contents of data written to logFileuyovaqv.bin.

The threat actor removed various files created by the discovery actions during the intrusion.

Multiple discovery commands were executed by the threat actors. Each command was executed via the temp.ps1 file with the input commands via base64 command line arguments.

During the intrusion, the threat actors executed the following for discovery tasks.
- List disk information: "C:\Windows\System32\Wbem\WMIC.exe" logicaldisk
- List process: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -command Get-Process
- Get information about Windows Defender service: "C:\Windows\system32\cmd.exe" /c sc query WinDefend
- Get current time on the victim’s workstation: "C:\Windows\system32\cmd.exe" /c time
- Get time zone: "C:\Windows\system32\cmd.exe" /c tzutil /g
- Use TRACERT in order to discover network infrastructure: "C:\Windows\system32\cmd.exe" /c tracert 8.8.8.8
- Enumerate local accounts: "C:\Windows\system32\net.exe" accounts
- Get information on current user: "C:\Windows\system32\whoami.exe" /all
Enumerate files

A PowerShell function based on the PowerSploit Convert-LDAPProperty code was used in order to retrieve information on domain accounts:

Query AD & SAM account name



Computer and network information discovery



Get the account information for logged-on user of a Windows machine


Gets the status of antimalware software on the computer.


List environment variables: ls $env:temp get-childitem $env:temp | out-string

Get public IP address: Invoke-WebRequest -UseBasicParsing -Uri http://ident.me | out-string

Before exfiltration, the data collected from LDAP discovery was written out to an XML file.



Threat actors also dropped and executed a PowerShell script using their temp.ps1 C2 script:

The sc.ps1 file contained PowerShell code to capture a screenshot of the system. The screenshots were taken upon the execution of this PowerShell script and then they were saved in the same directory as sc.png files.

A scheduled task named MicrosoftEdgeUpdateTaskMachineUC was created by the threat actors. The program executed by this task was a keylogger. This keylogger relied on the files module.exe, module.ahk, and readkey.ps1. The file t.xml contained the task used to execute these files.

The executable, module.exe, is a renamed binary of AutoHotkey. This is one of the ways in which you can execute an AutoHotkey (AHK) script.

The actual keylogger is the AHK script, module.ahk.

Navigating through the AHK script, we discovered artifacts of acquiring the keyboard layout and capturing pressed keys. In addition, we notice there is a function named UpdateReg that accepts a text parameter. This registry key is also found within the readkey.ps1 script and turns out to be where the keylogger saved captured keystrokes.

The readkey.ps1 file grabbed the keystrokes from the KeypressValue registry key, XOR’s the data, and saves it to a log (logFileuyovaqv.bin) file.

The threat actors then made a cab file out of the collected keystrokes in preparation for exfiltration.

Activity to the C2 is established via execution of the Script.ps1 and temp.ps1 files. Communication between the victim and C2 is encrypted using AES-CBC with the following Key and IV:



First communication to the C2 (hxxp[:]//45[.]89[.]125[.]189/get) began on day one and beaconed in roughly 10-minute increments. All requests return a 502 Bad Gateway error until day two.

First C2 communication breakdown:

AES encrypted PowerShell command example:



SafeBreach published similar findings from this C2 infrastructure, where they described the format in detail. You can review their research here.

Several files collected during discovery tasks, such as domain user account information and later the keylogger collected data, were exfiltrated to the C2 server via POST requests.

During the intrusion, no final actions beyond data collection and discovery tasks were observed.
