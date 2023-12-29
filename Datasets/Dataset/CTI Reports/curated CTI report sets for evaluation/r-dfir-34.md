# Case Summary

In this case we started with a DocuSign themed Excel maldoc. The excel file failed to bring down the payload but to follow the infection chain we executed the follow on loader. Once Bazar was established the malware quickly injected into the Werfault process to avoid detection. As seen in many intrusions the malware then performed some initial discovery with built-in Microsoft utilities such as Nltest.

About an hour after initial execution, a Cobalt Strike beacon was loaded, followed shortly by Anchor. Shortly after Cobalt Strike and Anchor were running, the attackers dumped credentials and began moving laterally, starting with a domain controller.

Once on the domain controller, the threat actors ran additional discovery but then went quiet. Active command and control was maintained by all three malware samples (Bazar, Cobalt Strike, Anchor DNS) over the next 4 days.

During that timeframe, honey documents were interacted with and additional discovery scans were executed. The threat actors were briefly active on day 3 to execute their Get-DataInfo script to collect additional information, which is usually followed closely by Ryuk ransomware.

However, on the fifth day the threat actors access was cut off before final objectives could be accomplished. We assess that the end goal of this intrusion was to execute domain wide ransomware.

# analysis

# MITRE ATT&CK

A DocuSign themed Excel xls was opened and macros were enabled. Thanks to @ffforward for the document as well as the sandbox run leading up to the xls file.

The macro in this maldoc is using Excel 4 Macros.

DocuSign was again the social engineering format of choice.

After execution, Excel called out to:



We saw no further follow on activity from the above execution, potentiality due to the loader site being offline or some other condition not being met. We then executed the follow on malware manually.



About an hour after execution of the above Bazar Loader, Cobalt Strike was executed by the injected Werfault process.

Shortly after Cobalt Strike was executed, it dropped several Anchor executable files.

AnchorDns was then executed via Cobalt Strike which called cmd and then anchorAsjuster. Notice Asjuster passing two domains to anchor_x64.exe which will be used for C2.





Bazar quickly moved into a Werfault process to handle command and control communication avoiding making any network connections directly.

Process injection was also seen in other key system executables such as winlogon.exe.

Cobalt Strike was seen locking access to SMB beacons.

Anchor was also seen triggering process tampering.

# Credential Access

The threat actors were seen using remote thread creation to inject into lsass to extract credentials.

The same activity as seen via a the larger process tree.

# Discovery

Bazar initiated some discovery activity within 10 minutes of executing.

Cobalt Strike initiated the following discovery commands:

On the domain controller the following discovery was run:


The following PowerShell command was executed from the domain controller.

Systems were pinged from the domain controller to confirm connectivity.


Four days into the intrusion the threat actors dropped and executed Advanced_IP_Scanner_2.5.3850.exe which kicked off a scan of the network.

AWS was used to get the public IP of the infected machine, multiple times.


Minutes before deployment of Ryuk the threat actors usually drop the following files, usually on a domain controller. This time they dropped the files on a domain controller in C:\info

The exact files were mentioned in our Bazar, No Ryuk report.

start.bat was executed with the following:

C:\Windows\system32\cmd.exe /c ""C:\info\start.bat"" This script contents show it to be a wrapper for the PowerShell script Get-DataInfo.ps1 The contents of Get-DataInfo.ps1 show a detailed information collector to provide the threat actor with very specific details of the environment. This includes things like disk size, connectivity, antivirus software, and backup software. The Ryuk group has used this script for at least a year as we’ve seen them use it multiple times.

This script and files are available @ https://thedfirreport.com/services/

# Lateral Movement

Two hours post initial access the threat actors began lateral movement to one of the domain controllers using PowerShell, which was executed via a remote service, which launched Cobalt Strike

Reviewing the PowerShell script we can extract the shellcode and run it through scdbg to find the pipe used by the beacon.

Thanks to 0xtornado and @mattnotmax for this recipe!

The threat actors also used SMB beacons executed by remote services as well. We saw this across most machines in the domain.

The threat actors also used RDP to login to multiple machines within the domain.

# Collection

We did not witness collection events but we do believe files were collected and exfiltrated over encrypted C2 channels.

# Bazar:

We observed the Bazar malware inject into a WerFault process to perform ongoing command and control communication.

# Anchor:

The AnchorDNS malware performed C2 over DNS to the following domains:


# Cobalt Strike:

No exfiltration was observed but honey docs were taken off network and opened by the threat actors from remote locations. We assess that this exfiltration was performed over an encrypted C2 channel. This exfiltration has been going on for months and is rarely talked about when it comes to Wizard Spider.

We believe this intrusion would have ended with domain wide ransomware. The deployment of the Get-DataInfo.ps1 script and overall TTP’s used in the intrustion are consistent with threat actors associated with deployments of the Ryuk ransomware family.

Enjoy our report? Please consider donating $1 or more using Patreon. Thank you for your support!

We also have pcaps, memory captures, scripts, executables, and Kape packages available here
