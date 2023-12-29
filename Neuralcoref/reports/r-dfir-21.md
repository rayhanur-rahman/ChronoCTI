# Case summary

Like with many infections today, the threat actors gained initial access on a system through a malicious document email campaign, which made use of the Hancitor downloader. The document, upon opening and enabling of macros, would write and then execute a dll file from the users appdata folder.

The Hancitor dll downloaded and executed multiple payloads including a Cobalt Strike stager and Ficker Stealer. The threat actors then began port scanning for SMB and a few backup systems such as Synology, Veeam and Backup Exec.

After that, a battery of Windows utilities were run to check the windows domain trusts, domain administrators, domain controllers, and test connectivity. They then checked access to remote systems by connecting to the C$ share.

The threat actors proceeded to move laterally to multiple other servers on the network by making use of existing local administrative rights of a compromised user. Cobalt Strike beacons were deployed to each server to facilitate remote access. Furthermore, the threat actors dropped an obfuscated PowerShell script on one of the machines to further their access. The PowerShell script loaded the malicious code into memory and started beaconing out to the remote command and control server.

Next, the threat actors used a custom implementation of the Zerologon (CVE-2020-1472) exploit (zero.exe) against one of the domain controllers. The domain controllers were vulnerable, and as a result, the operators managed to dump the domain administrator’s NTLM hash. The threat actors then pivoted to the two domain controllers and deployed Cobalt Strike beacons.

The threat actors continued pivoting to key systems including additional domain controllers, backup servers, and file shares, using Cobalt Strike. Once on these systems, additional scanning occurred using a binary called check.exe that ran ICMP sweeps across the network.

Within two hours of the initial malicious document execution, the threat actors had a foothold on all key systems in the environment. Similar to a previous case, the threat actors were evicted before completing their mission and as a result their final actions could not be observed.

# analysis

Initial access was gained through a malicious document email campaign that aimed to trick the user into enabling Macros.

The document was delivered via an email that included a link to Google’s Feed Proxy service which was hosting a malicious document as shared by @James_inthe_box . Thanks for sharing James!

Initial access was gained through a malicious document email campaign that aimed to trick the user into enabling Macros.

We also have artifacts and IOCs available from this case such as pcaps, memory captures, files, event logs including Sysmon, Kape packages, and more, under our Security Researcher and Organization services.

The Cobalt Strike servers in this case were added to the Threat Feed on 5/16 and 7/15 .

We offer multiple services including a Threat Feed service which tracks Command and Control frameworks such as Cobalt Strike, Metasploit, Empire, PoshC2, BazarLoader, etc. More information on this service and others can be found here .

Within two hours of the initial malicious document execution, the threat actors had a foothold on all key systems in the environment. Similar to a previous case , the threat actors were evicted before completing their mission and as a result their final actions could not be observed.

The threat actors continued pivoting to key systems including additional domain controllers, backup servers, and file shares, using Cobalt Strike. Once on these systems, additional scanning occurred using a binary called check.exe that ran ICMP sweeps across the network.

Next, the threat actors used a custom implementation of the Zerologon (CVE-2020-1472) exploit (zero.exe) against one of the domain controllers. The domain controllers were vulnerable, and as a result, the operators managed to dump the domain administrator’s NTLM hash. The threat actors then pivoted to the two domain controllers and deployed Cobalt Strike beacons.

The threat actors proceeded to move laterally to multiple other servers on the network by making use of existing local administrative rights of a compromised user. Cobalt Strike beacons were deployed to each server to facilitate remote access. Furthermore, the threat actors dropped an obfuscated PowerShell script on one of the machines to further their access. The PowerShell script loaded the malicious code into memory and started beaconing out to the remote command and control server.

After that, a battery of Windows utilities were run to check the windows domain trusts, domain administrators, domain controllers, and test connectivity. They then checked access to remote systems by connecting to the C$ share.

The Hancitor dll downloaded and executed multiple payloads including a Cobalt Strike stager and Ficker Stealer. The threat actors then began port scanning for SMB and a few backup systems such as Synology, Veeam and Backup Exec.

Like with many infections today, the threat actors gained initial access on a system through a malicious document email campaign, which made use of the Hancitor downloader. The document, upon opening and enabling of macros, would write and then execute a dll file from the users appdata folder.

Various different enumeration and lateral movement tactics were observed on the network, along with the exploitation of Zerologon to elevate to domain administrator and gain full control over the domain. The threat actor was able to go from zero access to domain admin, in just under one hour.

This report will go through an intrusion from July that began with an email, which included a link to Google’s Feed Proxy service that was used to download a malicious Word document. Upon the user enabling macros, a Hancitor dll was executed, which called the usual suspect, Cobalt Strike.

Reviewing the document we can see the expected malicious macro and identify the location of a dll to be dropped in the:


We can see that this relates to the path:


And once the dll “ier” is written there, the macro proceeds to execute it.

# Execution

Three files were downloaded by Hancitor from 4a5ikol[.]ru (8.211.241.0) including two Cobalt Strike stagers and Ficker Stealer.

Hancitor then launched multiple instances of svchost.exe and process injected them with Cobalt Strike.

The following diagram shows the initial execution process from the WINWORD.exe to the Cobalt Strike Beacons that were injected into memory by Hancitor.

Lastly, a Cobalt Strike command and control server was pinged before they copied the Cobalt Strike DLL and batch file, which were used to facilitate lateral movement.

The batch file (cor.bat) is a 3-line script that will execute the Cobalt Strike DLL using rundll32.exe with a specific parameter.

The Cobalt Strike DLL used in this case resembles the same Cobalt Strike DLL seen in case 4301 based on the YARA rule associated to that case, indicating likely links between the actors in the two cases.

# Privilege Escalation

The threat actor made use of a custom developed implementation of Zerologon (CVE-2020-1472) executed from a file named “zero.exe”.

Once “zero.exe” is run it will provide the threat actor with the NTLM hash of the specified username, a Domain Administrator account in this case.

On the Domain Controller a service (Event ID 7045) will be created that will run the Reset-ComputerMachinePassword PowerShell Cmdlet.

The service will then be executed and the machine account password will be reset.

Zerologon will create an Event ID 4624 for the domain controller computer account attempting to authenticate. The main red flag is the source network address IP differing from the IP of the domain controller, which in this case is set to the beachhead workstation on which zero.exe was executed.

Lastly, Event ID 4648 will be logged on the beachhead machine indicating the zero.exe process was used to connect to a domain controller.

A blog post by Blackberry can be referenced to learn more about this custom developed Zerologon file used: https://blogs.blackberry.com/en/2021/03/zerologon-to-ransomware.

For more information on detecting Zerologon check out Kroll’s Zerologon Exploit Detect Cheat Sheet.

# Defense Evasion

Upon Hancitor launching on the system, it process injected into multiple instances of svchost.exe and rundll32.exe. Memory segments can be seen allocated with Execute, Read, and Write permissions, indicating that executable code is stored.

Anomalous parent and child process relationships can be seen on the system that Hancitor was executed on, including rundll32.exe spawning svchost.exe and svchost.exe spawning cmd.exe.

Moreover, the Cobalt Strike DLL stager was executed with a specific command line parameter which is used as a sandbox evasion feature. In this case it is the number 11985756.

Lastly, a PowerShell loader named agent1.ps1 used heavy obfuscation to conceal the execution flow and hide the final shellcode. After many iterations, the script would deobfuscate and run-in memory. The shellcode is responsible for loading a PE file into memory and calling out to 64.235.39[.]32 for further instructions.

# Credential Access

The only credential access observed was through Zerologon, which was used to retrieve the domain administrator’s NTLM hash.

# Discovery

Discovery started with a port scan initiated by the Hancitor dll.

After SMB was scanned we saw scans of 5000/tcp, 9392/tcp, 6106/tcp. The threat actors were scanning for backup products such as Synology, Backup Exec and Veeam.

This was followed by a battery of discovery command using the built in Microsoft utilities to discover domain controllers, administrators, connectivity checks and other items.

Notice above, the threat actors pinged 190.114.254[.]116 which is one of the Cobalt Strike servers they later used.

The threat actors enumerated local administrative access on remote systems by checking access to the C$ share for hosts discovered after the port scan.

We observed a PowerShell script named comp2.ps1 that was executed on every Domain Controller in the environment. This script used the Active Directory RSAT module to get a list of computers and place them in a file named ‘comps.txt.’

A program named check.exe was observed using the comps.txt text file. This program will take a list of IP addresses and hostnames from comps.txt and check if they are online using ICMP. The online hosts will then be directed to the check.txt text file.

The check.exe file contains three parameters that can be used one at a time:

check .exe comps.txt check .txt -ip ( Check which hosts in comps.txt are alive, and write the IP to check .txt) check .exe comps.txt check .txt - name ( Check which hosts in comps.txt are alive, and write the hostname to check .txt) check .exe comps.txt check .txt - full ( Check which hosts in comps.txt are alive, and write the IP and hostname to check .txt)

# Lateral Movement

The threat actors pivoted towards multiple hosts on the domain from the beachhead. The main actions involved copying a Cobalt Strike DLL beacon and a batch script to run the DLL (cor.dll, cor.bat, GAS.dll, GAS.bat). Operators executed the batch script through a remotely created service on the target system.

The following shows one of the batch scripts used to run a Cobalt Strike payload.

An obfuscated PowerShell script named ‘agent1.ps1’ was dropped on a machine through a Cobalt Strike Beacon. The PowerShell script had instructions to deobfuscate shellcode and run it in memory as a thread in the same PowerShell process.

The shellcode itself also has a PE file embedded inside of itself. Once the shellcode is running this PE file will be loaded into memory and executed. You can see this from the memory dump MZ header denoting the PE binary loaded into the PowerShell process.

The PE file is of a small size and has the capability to beacon out at regular intervals to a command-and-control server on 64.235.39[.]32 to retrieve instructions.

The Visual C# Command Line Compiler was observed being invoked by the PowerShell script where the shellcode was executed. This is most likely instructions that the previously discussed PE file retrieved from the remote command and control server.

# Command and Control

Hancitor contacted its servers over HTTP and advertised details about the compromised machine, user, and domain while also retrieving instructions from the command and control server (1). From another dedicated location, 4a5ikol[.]ru, two Cobalt Strike beacons and Ficker Stealer malware were downloaded through HTTP (2).

A successful connection from Ficker Stealer was not observed. A domain was queried; however, the response returned an error.

Cobalt Strike was also observed to be making use of HTTP.

Lastly, the shellcode executed by the agent1.ps1 PowerShell loader, was observed loading a PE file into memory that would beacon out at consistent intervals to 64.235.39[.]32. Further encrypted network activity was also observed to this IP address. Unfortunately, the tool sending these connections could not be definitively determined.

The user agent for this was curl/7.55.1

# Hancitor

# Impact

Similar to a previous case, the threat actors were evicted before completing their mission and as a result their final actions could not be observed.
