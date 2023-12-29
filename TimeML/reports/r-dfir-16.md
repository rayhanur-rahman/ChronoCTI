# Case Summary

We assess with high confidence that the “Stolen Image Evidence” email campaign was used to deliver the IcedID DLL. This was first reported by Microsoft in April 2021.

Upon execution of the IcedID DLL, a connection to a C2 server was established. This was followed by the creation of a scheduled task on the beachhead host to establish persistence. The task executed the IcedID payload every one 1 hour. The IcedID malware then used Windows utilities such as net, chcp, nltest, and wmic, to perform discovery activity on the host.

After a gap of almost an hour, a Cobalt Strike beacon was dropped and executed on the beachhead host. Soon after, another round of discovery was performed from the Cobalt Strike beacon focusing on the Windows domain. Nltest and net group were utilized to look for sensitive groups such as Domain Admins and Enterprise Admins. Process injection into explorer.exe was then observed from the Cobalt Strike Beacon.

The threat actors proceeded to install remote management tools such as Atera Agent and Splashtop. Use of these 3rd party administrative tools allow the threat actors another “legitimate” means of persistence and access if they were to lose their malware connection. In this intrusion, we observed usage of gmail[.]com and outlook[.]com email accounts for Atera agent registration. Soon after, one of the injected Cobalt Strike processes accessed LSASS memory to dump credentials from the beachhead.

On the sixth day of the intrusion, the beachhead host saw new discovery activity with a quick nltest followed by the PowerView script Invoke-ShareFinder. On the following day, the seventh day of the intrusion, the threat actors made their next move. On that day, a new Cobalt Strike server was observed, in fact over the course of the intrusion, four different Cobalt Strike servers were used. From the beachhead host, a DLL was transferred to a domain controller over SMB and then a remote service was created on the domain controller to execute the Cobalt Strike DLL.

After getting a foothold on the domain controller, we saw more process injection followed by the same pattern of installing Atera for additional persistent access. From the domain controller, the threat actors proceeded with more discovery tasks including AdFind and Invoke-ShareFinder again. After this, the threat actors went quiet.

On day nine of the intrusion, the next Cobalt Strike server, which would ultimately be used until the end of the intrusion, was observed for the first time. On the tenth day, little activity was observed but the threat actors connected to the beachhead host via the Atera agent and executed another Cobalt Strike DLL. A little discovery check-in was observed on the 14th day, but little else.

On the 19th day, the threat actors moved towards their final objectives. They reviewed the directory structure of several hosts including domain controllers and backup servers. They then dropped their final ransomware payload on the beachhead host and attempted to execute it using a batch file named backup.bat. However, they found that their execution failed.

They left for a few hours, and then returned, and attempted to exploit a couple of CVE’s in an attempt to escalate privileges. The threat actors had already secured domain admin access but it’s possible the operator may have thought they lacked permissions when their first ransomware execution failed.

While these exploits appear to have failed the threat actors found their previously captured domain admin credentials and launched two new Cobalt Strike beacons on the domain controllers. Finally, twenty minutes after accessing the domain controllers, the threat actors dropped the ransomware DLL and the batch script and executed it from the domain controller. This time the execution worked as intended and resulted in domain wide ransomware.

# Analysis

The IcedID DLL, which gave the threat actors a foothold into the environment, was likely delivered by a “Stolen Image Evidence” email campaign.

These initial access campaigns reportedly utilize contact forms to send malicious emails to intended targets.

The emails contain a link to a legitimate storage service like those offered by Google and Microsoft. In this example, “http://storage.googleapis.com” was used to host a zip file. The zip archive contains an ISO file, which once clicked and mounted, shows a document-like LNK file. Once the victim opens that LNK file, the IcedID DLL loader executes, downloads, and runs the second stage of IcedID.

Below is a configuration extraction of that initial IcedID malware from an automated sandbox analysis of the sample:



# Execution

The graph below shows detailed actions performed through IcedID, including reconnaissance and Cobalt Strike beacons drops:

# Persistence

# Scheduled Tasks

Only one scheduled task was created during this intrusion. The scheduled task was created on the beachhead host upon the execution of IcedID DLL, which executed every hour:


# Atera Agent

Threat actors dropped and installed Atera agent (T1219), using two MSI packages “sql.msi” and “mstsc.msi”, from the Cobalt Strike beacons, which allowed them to have a non-malware backdoor in the environment.

The installation of those two packages reveals two emails potentially belonging to the ransomware operators or affiliates:

Atera agent is a remote monitoring and management system.

At one point in the intrusion the threat actors utilized Atera to download and launch a new Cobalt Strike beacon on one of the hosts they had installed the agent on.

# Privilege Escalation

There were attempts to exploit Active Directory vulnerabilities CVE-2021-42278 and CVE-2021-42287 in order to create privileged accounts. This attempt failed, however, there were indicators through DNS requests enumerating accounts for the existence of SAMTHEADMIN-XX (XX being a random number). The query status 9003 indicates that this does not exist.

The injected process dllhost.exe requesting SAMTHEADMIN-92 and SAMTHEADMIN-20 accounts:

We believe the operator used the publicly available script ‘sam_the_admin‘ or a variant based on it. Part of the script generates a new computer name account in the form SAMTHEADMIN- followed by a random value between 0 to 100, as indicated below.

The exploitation involves invoking lookups to ensure that the new accounts were successful, explaining why failed DNS requests were observed.

# Defense Evasion

# Disable Defender

A base64 encoded PowerShell command was executed on the beachhead which disabled Windows Defender AV (T1562.001).

The decoded base64 PowerShell command uses Set-MpPreference cmdlet to disable Defender’s real time monitoring: Set-MpPreference -DisableRealtimeMonitoring $true

# Process Injection

A number of process injections were seen during this intrusion. The Cobalt Strike beacon used the CreateRemoteThread Win32 function in order to inject code into running processes. The usage of this function triggers the Sysmon Event ID 8, a well known pattern of CS beacon activity.

Remote threads were created in Winlogon and Explorer processes.

# Credential Access

# LSASS Access

The threat actors accessed LSASS process memory (T1003.001) on different hosts, including domain controllers, using multiple techniques.

The screenshot below shows the different “DesiredAccess” to the LSASS process object from different beacons (dllhost.exe, Edebef4.dll, etc.) or Task Manager:

The table below maps the “DesiredAccess” values with the actual corresponding access rights, and examples of credentials dumping tools requesting those accesses:

*A handle that has the PROCESS_QUERY_INFORMATION access right is automatically granted PROCESS_QUERY_LIMITED_INFORMATION.

Those “DesiredAccess” values could be interesting to build detections or hunting queries if you are using Sysmon or such a verbose monitoring tool.

In our case, the access to LSASS process allowed the threat actors to compromise a domain admin account, which was then used to move laterally and deploy ransomware.

# Discovery
Multiple discovery techniques were observed throughout the case. The initial discovery techniques were conducted on the beachhead host by the IcedID malware – focusing on determining the system language and security products installed (T1518.001). Other familiar discovery techniques were then leveraged to establish situational awareness, such as network configurations and Windows domain configuration.

Discovery was achieved using a combination of living off the land techniques (WMIC and CMD) and via third-party tools.

Threat actors also used “chcp” for discovery of the system locale/language (T1614.001). Change Control Page (ChCP) is a Microsoft utility for changing the console control page (language). In this case, the existing control page language was collected using the following command:

As a test, entering this on a command prompt shows a numeric value. The Microsoft link shows the number of the language used (437 – United States).

It is highly likely that the threat actors were establishing the country of origin based on the language used – an extra fail-safe check to ensure certain users or regions were not targeted. The >&2 parameter could indicate a parameter was expected as part of a script, or possibly a redirect using stderr.

The second discovery was from a different Cobalt Strike beacon “Faicuy4.exe” which focused on domain discovery and user groups using the net command.

Once the threat actors had achieved lateral movement to domain controllers, the AdFind utility was employed to enumerate active directory objects (T1018).

‘adf.bat’ is a common batch file that we have observed in previous cases, we saw this script in 2020 as part of a Ryuk intrusion. The recent Conti leaks indicate that Conti operators were surprised Ryuk operators were using their file.

The PowerView module Invoke-ShareFinder was executed from the beachhead host and a domain controller.

Some network discovery was conducted using the ping utility to check the existence of hosts on the network (T1049).

Filesystem discovery (T1083) was conducted to collect directory lists to a text file.

Other variations included:

# Lateral Movement

On the 6th day, the threat actors began their lateral movement activity using SMB to transfer Cobalt Strike DLL’s onto a domain controller and another server.

Services were then created on the hosts to execute the uploaded Cobalt Strike Beacons.

On the final day, right before execution of the ransomware, SMB was again used to transfer Cobalt Strike Beacon executable to the domain controllers.

The beacons were then executed using a remote service.

Known Cobalt Strike named pipes were observed on the Domain Controllers with these executable beacons. Named pipes connections can be observed through Sysmon Event ID 18.

Note that the named pipes followed MSSE-[0-9]{4}-server pattern, which indicates that the threat actors were using the default Cobalt Strike Artifact Kit binaries:

# Command and Control

We observed the IcedID DLL dropping multiple CS beacons on the beachhead.

# Splashtop Streamer

Threat actors used Splashtop Streamer via Atera agent, allowing them to remotely connect to machines without using RDP tunneling or other techniques previously seen in our cases.

By default, the Splashtop Streamer is automatically installed together with the AteraAgent.

Splashtop Streamer usage leaves many network connections to *.api.splashtop.com and *.relay.splashtop.com on port 443:

# Cobalt Strike

We observed a default Cobalt Strike malleable C2 profile, using the jquery agent string. This activity can be detected with relative ease by the ET rules.

There appeared to be no jitter configured, resulting in a constant stream of HTTP requests, and if using ET rules, constant alerts would be generated.

Just based on the ET Cobalt Strike rule, ‘ET MALWARE Cobalt Strike Malleable C2 JQuery Custom Profile Response’, there were in excess of 6K alerts generated.

Due to the length of this intrusion, we observerd the threat actors handing off between C2 servers. We also observed one Cobalt Strike domain change IP resolutions three times, over the length of the case.

A configuration was not obtained for this server.

# Exfiltration

We did not observe any exfiltration indicators while analyzing host and network forensic artifacts.

This does not mean that there was no exfiltration, as this could have been performed via Cobalt Strike beacons over encrypted channels.

# Impact

On the 19th day of the intrusion, the threat actors prepared for their final objectives. From the beachhead host, the directory listings of the domain controllers were checked again, followed by the backup server. On the beachhead host, we observed the threat actors attempt to execute the final ransomware payload. From that host however the attempt failed.

The threat actors then proceeded to look for other elevation paths. After a failed attempt with CVE-2021-42278 and CVE-2021-42287, the threat actors executed Cobalt Strike beacons on a couple of domain controllers. Once they established this access, around twenty minutes later, they again attempted the ransomware deployment and this time the payload executed properly and began spreading across the network via SMB.

The threat actors deployed ransomware payload in a DLL, named x64.dll, which was executed using backup.bat batch script.

This x64.dll DLL contains fingerprints, “conti_v3.dll”, seen in our previous cases:

We didn’t dig into reversing this DLL, as a detailed step-by-step analysis already exists, and gives an excellent explanation of command line parameters used during the execution of Conti ransomware.

Once the threat actors pushed the encryptor to C$, an excessive SMB network activity were generated in a short period of time (~7K) as indicated by the chart.

This resulted in files being encrypted and a ‘readme.txt’ ransom note generated on the hosts:

The ransom note has slightly been modified from our last Conti cases:

