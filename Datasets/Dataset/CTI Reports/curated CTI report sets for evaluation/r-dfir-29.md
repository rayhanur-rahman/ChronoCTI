# Summary

We assess with medium confidence that the initial IcedID infection was delivered via a malspam campaign, which included an attachment with a password protected zip archive. Once extracted, the user would find a Word document with a macro, which upon execution, would deliver the initial DLL loader. Discovered in 2017, what started as a commodity malware, IcedID is now currently being deployed as an initial access broker by ransomware threat actors.

In this case, the threat actor appeared to have specific goals, and did not waste any time. Within 35 minutes after the initial infection, they made their way in to the network via a Cobalt Strike Beacon deployed from the IcedID infected host.

The first task of the threat actor was to enumerate the network by establishing a list of the domain admins using living off the land techniques, such as net.exe. A freely available tool Adfind.exe was also utilized to further enumerate the domain. The threat actor was also observed stealing credentials from the lsass.exe process.

Five minutes after the above discovery activity, we observed the actors moving laterally to other hosts on the network with the credentials of a domain administrator account. In this case, Cobalt Strike was also used to create the administrative token, and attempted to install a service using a windows service executable. The service was tasked to run an encoded PowerShell command which would download and execute the Cobalt Strike beacon over HTTP.

Based on the name of the hosts that the threat actors decided to pivot, we judge that they were able to digest the ‘AdFind’ results and focus on, what they believed to be, important targets – critical assets such as file servers, domain controllers, etc. It is also worth mentioning that even after the unsuccessful remote execution attempt against a few servers due to AV, the actors decided to connect via RDP and spend over an hour looking for valuable data before disconnecting and leaving the network.

No exfiltration of data or impact to the systems was observed but at least one command and control. It is unclear why the actors decided not to continue with their operation. No attempt was made to clean up the intrusion by the actors – artifacts that were deployed were still in operation, including C2 implants.

# analysis


# Initial Access

The first stage of the IcedID malware that was executed on the host was dropped via a macro enabled Word document – as seen by Unit42.

IOCs from Brad here.

In our case, the IcedID dll loader was manually executed using regsvr32.

# Persistence

From the initial access, a scheduled task was created. This can be observed by EventID 106: New task registered:

Inspection of the task file located under ‘c:\windows\system32\tasks’:

‘License.dat’ is an encrypted binary file and is a tell-tale indication of an IcedID compromise. The corresponding DLL (upefkuin4.dll) is used with license.dat to maintain persistence using the Task Scheduler. After decrypting License.dat using Binary Defense’s decryption tool, we can see some information stealing functionality:

EventID 200: Task executed shows the persistent IcedID core being executed, on average every 1 hour via Rundll32.exe.

# Credential Access

The LSASS process was accessed by an unusual process “wuauclt.exe” on the beachhead host. This was the Cobalt Strike Beacon and was used to access the credentials.

This is not the first time we have observed this process (wuauclt.exe) being used. In our previous report with another IcedID infection leading to Sodinokibi ransomware we also observed the same process being used.

The same process was also observed invoking PowerShell scripts:

“Wuauclt.exe” is normally used for the Microsoft Windows Update Service and this was an attempt to blend into the OS environment.

# Discovery

Discovery commands were run by IcedID during the initial execution on the beachhead. These commands use the Microsoft Windows built-in commands and utilities, such as WMIC, ipconfig, etc. The aim was to determine the installed Anti-virus software, network configuration, domain configuration and user accounts. The following are the commands that were executed:

Using the information gathered, the IcedID operator was able to focus on specific targets, obtaining access to the privileged accounts and the high value hosts.

Once the IcedID operators were able to establish a C2 session to the initial compromised host, the operators were observed executing the following command:

Interestingly, we observed the operator deploying and utilizing AdFind to collect information about the hosts on the network. AdFind is an Active Directory query tool developed by JoeWare, a useful utility for system administrators, but also popular among threat actors.

AdFind was transferred and executed on the beachhead host. The threat actor placed the AdFind binary and the results in the ‘C:\Recovery’ folder. We assess this folder location was chosen to avoid raising suspicion, as compared to executing from a user or temporary folder location.

# Lateral Movement

The threat actors attempted and successfully managed to pivot laterally to various hosts on the domain. This was achieved by connecting via SMB and starting a service that would execute an encrypted PowerShell command with embedded Cobalt Strike SMB beacons.

The PowerShell is base64 encoded. Decoding the PowerShell shows that the SMB pipe is named \\.\pipe\halfduplux_9e.

Using the ‘Administrator’ account, SMB sessions were established to the hosts, primarily using ADMIN$, but IPC$ was also observed.

This activity triggered two Emerging Threat (ET) alerts related to RPC access and binary execution, “ET RPC DCERPC SVCCTL – Remote Service Control Manager Access” and “ET POLICY SMB2 NT Create AndX Request For an Executable File”.

# Command and Control

# IcedID:

Throughout the intrusion the threat actor used a mix of Port 80 and 443 for C2. Port 80 was observed in the communication to testsubnet[.]com which contains a HTTP Cookie in the format: wordpress_<Base64EncodedString>. This activity was observed at a rate of every 2-4 seconds.


# Exfiltration

No exfiltration was observed; however, we were able to determine that access to the File server was achieved, with multiple access attempts and successes.

# Impact

No impact was observed nor any follow-on activities to deny, disrupt or destroy data or systems.
