# Case summary
In this intrusion, a malicious ISO file was delivered to a user which contained Ursnif malware. The malware displayed an interesting execution flow, which included using a renamed copy of rundll32. Once executed, the malware conducted automatic discovery on the beachhead host, as we have observed with other loaders such as IcedID. The malware also established persistence on the host with the creation of a registry run key.

Approximately 4 days after the initial infection, new activity on the host provided a clear distinction of a threat actor performing manual actions (hands on keyboard). The threat actor used a Background Intelligent Transfer Service (BITS) job to download a Cobalt Strike beacon, and then used the beacon for subsequent actions.

The threat actor first ran some initial discovery on the host using built-in Windows utilities like ipconfig, systeminfo, net, and ping. Shortly afterwards, the threat actor injected into various processes and then proceeded to access lsass memory on the host to extract credentials.

Using the credentials extracted from memory, the threat actors began to move laterally. They targeted a domain controller and used Impacket’s wmiexec.py to execute code on the remote host. This included executing both a msi installer for the RMM tools Atera and Splashtop, as well as a Cobalt Strike executable beacon. These files were transferred to the domain controller over SMB.

After connecting to the Cobalt Strike beacon on the domain controller, the threat actor executed another round of discovery tasks and dumped lsass memory on the domain controller. Finally, they dropped a script named adcomp.bat which executed a PowerShell command to collect data on computers in the Windows domain.

The following day, there was a short check-in on the beachhead host from a Cobalt Strike beacon, no other activity occurred until near the end of the day. At that time, the threat actor became active by initiating a proxied RDP connection via the Cobalt Strike beacon to the domain controller. From there, the threat actor began connecting to various hosts across the network.

One host of interest was one of the backup servers, which was logged into, the state of backups were checked and running processes were reviewed before exiting the session. The threat actor was later evicted from the network.

# Analysis

In this case, the user had saved the file 3488164.iso to the their downloads folder and mounted it.

Once mounted, the new drive contained a LNK file 6570872.lnk and hidden folder “me”.

If we parse this LNK file with LECmd (by Eric Zimmerman), it highlights the execution path and the icon it appears as:

The contents of hidden folder “me”, included several files and folders that were used for the execution of Ursnif. Of interest, the folder included a legitimate copy of rundll32.exe (renamed to 123.com ).

Summary of the files found in 3488164.iso (a detailed break down of these can be found in Execution):


Once the user had mounted the ISO and the LNK file was executed by the user, the complex execution flow started.

# Ursnif Malware

Highlighted in Initial Access, the LNK file would execute a batch script alsoOne.bat . This script called a JavaScript file canWell.js in the same directory and provided a number of strings as arguments.
- alsoOne.bat
- canWell.js


The JS file was then executed with wscript.exe and used the provided command line arguments, which created and executed the following command using WScript.Shell.Exec():

Using the SRUM database, we were able to determine that the custom rundll32.exe binary downloaded approximately 0.4 MB of data.

Once the malware was executed, the parent instance of explorer launched MSHTA with the following command:

This oneliner created a new ActiveX object to eval() the content stored in the registry key in the users registry hive. The content of the value “ActiveDevice”:

The payload used another ActiveX object to run a PowerShell command. This command created additional aliases of common default PowerShell aliases gp (Get-ItemProperty) and iex (Invoke-Expression). These two new aliases were used to get and execute the content in another registry value “MemoryJunk”:

Analyst Note: The names of the registry values changed when we ran the payload in a sandbox during analysis, and hence suspected to be generated at random at execution.

The last registry key was used to store additional PowerShell code. This script called a combination of QueueUserAPC, GetCurrentThreadId, OpenThread, and VirtualAlloc to perform process injection of shellcode stored in Base64.

When Add-Type cmdlet is executed, the C# compiler csc.exe is invoked by PowerShell to compile this class definition, which results in the creation of temporary files in %APPDATA%\Local\Temp.

Finally, a unique command spawned from the parent explorer.exe process that was called pause.exe with multiple arguments, which appeared to not provide any additional functionality.

A sigma rule for this cmdline can be found in the Detections section of this report.

At this point in time, less than a minute of time has elapsed since the user first opened the malware.

Once the malware was established on the host, there was limited malicious activity, until around 3 days later. That is when we began to observe evidence indicative of “hands-on-keyboard” activity.

# Cobalt Strike

An instance of cmd.exe was launched through explorer.exe which ran the following command:

Analyst Note: Ursnif has been known to have VNC-like capabilities. It is possible this explorer.exe ➝ cmd.exe session was through a VNC session.

This PowerShell command started a BITS job to download a Cobalt Strike beacon from 193.201.9[.]199 and saved it with a random name to %TEMP%. It then read the file into a variable, and deleted it before executing content with IEX .

The event log Microsoft-Windows-Bits-Client%254Operational.evtx corroborated this activity:

The activity following this event demonstrated a clear distinction of the threat actor performing discovery manually.

Once the foothold had been achieved, after execution of Ursnif on the beachhead host, persistence was achieved by creating a ‘Run’ key named ManagerText which was configured to execute a LNK file which executed a PowerShell script.

We observed a process created by Cobalt Strike accessing lsass.exe. The GrantedAccess code of 0x1010 is a known indicator of such tools as Mimikatz. This was observed on both the beachhead host and a domain controller.

# Ursnif related discovery

As we have observed in other malware, Ursnif ran a number of automated discovery commands to gain information about the environment. The following commands were executed and their standard output was redirected to append to a file in the user’s %APPDATA%\Local\Temp\

# Manual discovery

Once the threat actor had Cobalt Strike running on the beachhead host, they ran the following commands:

The threat actor quickly took interest in a support account. This account belonged to the Domain Admin group.

The threat actor also used a batch script to collect a list of all computer objects on the domain using C:\Windows\system32\cmd.exe /C adcomp.bat which contained the PowerShell command:

During the final actions taken by the threat actors before eviction, after completing RDP connections to various hosts on the network, the threat actors checked running processes on the accessed hosts via taskmanager, which were started via their interactive RDP session as noted by the /4 command line argument.

WMI was used to pivot to a domain controller on the network. The actor leveraged Impacket’s wmiexec.py to execute commands with a semi-interactive shell, most likely using credentials gathered by the previous LSASS access.

The commands executed included directory traversal, host discovery, and execution of tools on the DC.

A breakdown of the parent and child processes invoked:

The command can be broken down as follows:
- ‘Q’ indicates turn off echo – no response.
- ‘C’ indicates to stop after command execution.
- The 127.0.01 and ADMIN$ indicates C:\Windows.

Output is achieved via the parameter ‘2>&1’, to redirect errors and output to one file:

This command line closely resembles the code within the wmiexec.py as part of the Impacket tool maintained by Fortra.

As Impacket interacts with remote endpoints via WMI over TCP via DCERPC, its possible to inspect network level packets:

The use of Impacket by threat actors has been recently detailed by CISA in alert AA22-277A – Impacket and Exfiltration Tool Used to Steal Sensitive Information from Defense Industrial Base Organization.

The Impacket process hierarchy in this case can be visualized as:

At the network level, commands are issued by DCOM/RPC port 135, with responses by SMB using port 445. We can observe a number of WMI requests via DCERPC from one endpoint to a target endpoint based on the ports.

Correlating the network activity to the host activity confirms that the ‘Powershell.exe’ process initiated the WMI requests.

The destination port is within the ephemeral port range 49152–65535, which is for short-lived, time based, communications RFC 6335.

13Cubed (Richard Davis) also released an amazing resource to investigate Impacket related incidents here: https://www.13cubed.com/downloads/impacket_exec_commands_cheat_sheet_poster.pdf

One of the observed commands invoked via WMI was ‘firefox.exe’.

This was dropped on the DC and spawned a number of processes and invoked a number of hands-on commands.

The process generated a significant volume of network connections to 193.201.9[.]199, averaging ~6K requests per hour, equating to >150K connections throughout the duration of the intrusion.

RDP was also used by the threat actor on the final two days of the intrusion to connect to various hosts from a domain controller proxying the traffic via the firefox.exe Cobalt Strike beacon.

# Ursnif

Ursnif was seen using the following domains and IPs:

We also observed several modules for Ursnif downloaded from the following IP:

JoeSandbox reported this sample having the following configuration:

Pivoting on domains registered in WHOIS with the email [email protected] or organization Rus Lak , reveals many similar domains as seen in this intrusion.

# Cobalt Strike

The following Cobalt Strike C2 server was observed:

The following Cobalt Strike configuration was observed:

Checking the certificate used, reveals that it is a default SSL certificate for Cobalt Strike, 83cd09b0f73c909bfc14883163a649e1d207df22 .

# Atera & SplashTop

Even though the threat actor installed these agents, we did not observe any activity with these tools.

Several HTTP Post events were observed to the identified domains denterdrigx[.]com, superliner[.]top and 5.42.199[.]83, masquerading as image uploads.

The user agent ‘Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 10.0; Win64; x64)’, an unusual browser configuration to masquerade as, which indicates use of Internet Explorer 8.0 (that was released ~2009).

The POST event included a MIME part indicating file upload activity

The example HTTP stream containing the content

The file that was uploaded 775E.bin was deleted by the injected ‘Explorer.exe’ process from the target endpoint in folder ‘\Users\<REDACTED>\AppData\Local\Temp’

The exfiltration activity along with the beacon activity can be detected using the following network signatures: ET MALWARE Ursnif Variant CnC Data Exfil and ET MALWARE Ursnif Variant CnC Beacon. In this example, the mix of activity can be observed as:

The threat actor was able to RDP to a backup server using the admin credentials they acquired. Using the logs in Microsoft-Windows-TerminalServices-LocalSessionManager/Operational we were able to determine the threat actor spent approximately 10 minutes on the backup server before disconnecting their RDP session. By doing this, they revealed the workstation name of the client: WIN-RRRU9REOK18 .

During that time, the threat actor undertook a number of hands-on keyboard actions; this included reviewing backups in a backup console, checking on running tasks, and using notepad to paste in the following content.

# Process execution: