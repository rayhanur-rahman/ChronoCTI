# case summary

The malware (BazarLoader) was delivered to an endpoint via email, which included a link to OneDrive. The OneDrive link, directed the user to download a file that was a zip, which included an ISO inside. Once opened (mounted) on the users system, it was determined the ISO contained a LNK file and a DLL. The LNK file masqueraded as a Document enticing the user to click/open it. Once the user executed the LNK file, the BazarLoader infection was initiated.

As seen in previous cases, the BazarLoader infection began with internal reconnaissance of the environment using Windows utilities such as net, nltest, and ipconfig. After being inactive for one hour, the intrusion continued with dropping of multiple Cobalt Strike beacon DLL’s on the beachhead. This was followed by another round of discovery from the compromised machine. The threat actor then proceeded with execution of adf.bat, which is a script that queries various Active Directory objects using the AdFind tool. The first run was using a renamed binary named qq.exe and then the threat actor later dropped a properly named AdFind binary and executed the same discovery commands again. Soon after that, with the use of another simple batch script named fodhelper_reg_hashes.bat, they performed credentials acquisition via dumping of SAM, SECURITY and SYSTEM registry hives.

Returning after a gap of almost 18 hours, the threat actor performed another round of network scanning from the beachhead. This was then followed by attempts to Kerberoast and “AS-REProast” using the tool Rubeus. The threat actor then moved laterally via RDP to a server that contained file shares. After gaining access to the system they installed a remote access application, AnyDesk, as well as Filezilla.

The threat actors used FileZilla to exfiltrate data out of the environment. They then pivoted towards critical systems, such as domain controllers and a server that held backups. The threat actor then dumped LSASS from one of the domain controllers, using task manager, and then uploaded the dump file to ufile.io using Internet Explorer.

On the backup server, the threat actors attempted to dump databases associated with the backup solution. In one attempt, they used a documented technique to recover the encoded password and decode it using the Microsoft Data Protection API (DPAPI).

After around 42 hours post initial intrusion, the threat actors pushed towards completion of their final objective. RDP access was established from the central file server that the threat actors had compromised to all endpoints and a batch script named “kill.bat” was executed on all of the targeted machines.

The script consists of commands that removes Volume Shadow copies, disables Windows automatic startup repair, and stops all the running services on the host. Once the script completed execution, the Diavol Ransomware was deployed via the RDP connection on each machine by running the executable manually. From initial access, to ransomware deployment, the threat actors took about 42 hours to deploy ransomware domain wide, but from the login on the third day, to the last host ransom execution, only about an hour passed for the actors to finish their deployment.

# analysis

Initial access was via a OneDrive link that arrived via malicious emails that was reported via @ankit_anubhav.


Upon accessing the link, a zip file was downloaded.



The original URL of the file can be traced from the file stream log data (Sysmon Event ID 15) as well.



Reviewing the file stream data from Sysmon we can see that the zip contains an ISO file.



TheAnalyst reported similar BazarLoader activity via malicious emails around the same time frame.


# Execution
The BazarLoader ISO downloaded from the OneDrive link, consists of a malicious DLL and shortcut file named “Documents.lnk” which executes the DLL via rundll32.exe.

LNK File

After the initial execution, the malware contacted two of its C2 IPs:


We then observed threat actors dropping multiple Cobalt Strike Beacon DLL’s on the host in the following file paths:




# Persistence
A new BITS job, named “Microsoft Office Manager upgrade v24.24” was created on the beachhead host.



The BITS job failed because the requested URL does not exist.


While reporting failure in the logs, the BITS job did re-execute the mounted ISO files every 3 hours, for the length of the intrusion on the beachhead host.



After the threat actor moved laterally, we observed them installing Anydesk on multiple clients to create additional means of keeping access.

They used PowerShell and cmd to automate the download and installation of AnyDesk. In order to install Anydesk for unattended access you have to set a password. The password here was set to J9kzQ2Y0qO



The threat actor not only leaked their password when installing AnyDesk, but they also temporarily copied the password to the machine as the name of a text file.


This password also matches one from the leaked Conti manuals back in August.


From the Anydesk logs, we can also see the Client-ID and the IP used to access the clients. Logs can be found at %programdata%\AnyDesk\ad_svc.trace


# Defense Evasion
The threat actors made use of process injection through-out the intrusion. The BazaLoader malware injected into an Edge browser process, as observed by the discovery activity, and Cobalt Strike DLL’s activity.





Cobalt Strike processes were also observed injecting into various other processes.





# Credential Access
Threat actors performed dumping of SAM, SECURITY and SYSTEM registry hives using a batch script named “fodhelper_reg_hashes.bat”.

Contents of fodhelper_reg_hashes.bat are as follows:



They also performed enumeration of the web browser information using more.



The following files were accessed:



Using a well known technique documented on the Veeam backup forum, the threat actor managed to decrypt passwords used by Veeam. The encryption method used by Veeam is Data Protection API/DPAPI.

All the activity was done using RDP on the server with backups.

Dump the credentials using sqlcmd.exe to base64 passwords.



Via RDP and notepad, they created a new file containing the code for the decryption routine.




Execute, which gave the threat actors passwords that were used by Veeam.


We also observed the threat actor using Rubeus to kerberoast and asreproast the environment.



# Discovery
BazaLoader was observed executing the well known battery of Windows discovery commands around 10 minutes after execution on the beachhead host.



Shortly after the Cobalt Strike beacon was executed, we can see that they uploaded and ran the well known script adf.bat. This has been observed multiple times by different ransomware groups. The threat actor ran AdFind twice, once using adf.bat file with AdFind renamed to qq.
The second time, they copy/pasted commands from adf.bat and executed them with AdFind.exe.

On the second day, the following commands were executed before they started working on moving laterally in the domain.



During the course of the intrusion, we observed execution of the utility “Advanced IP Scanner” to perform network scanning (over ports 21,80,445,4899,8080).


Advanced IP Scanner was downloaded using Internet Explorer on a server:


and then run with the portable option:


We also saw “MSSQLUDPScanner.exe” used for discovery of MSSQL instances across the environment.


We believe the tool used is rvrsh3ll’s MSSQLUDPScanner


Comparing compiled version to executable from this intrusion


Before execution of AdFind.exe, adf.bat was run.


Via RDP they manually ran @carlos_perez‘s Invoke-Sharefinder.ps1 on a server. It then looks like they manually copied the output to a file named shares.txt.


After each RDP connection to a server on the second day, the threat actor also made sure to open up task manager to review running processes and possibly logged in users on these systems.


# Lateral Movement
We observed the threat actor using RDP as their main tool to do lateral movement in the environment. Most likely using credentials gathered through dumping of either lsass, or the registry hives. The first instance was through the beachhead where they used Cobalt Strike as a reverse proxy. This also revealed their Workstation Name which is WIN-799RI0TSTOF.

# rdp
After they installed AnyDesk, they used that access to RDP to other servers in the environment as well as eventually executing their final objective using this access.

# Collection
The threat actors attempted to dump a database using sqlcmd.exe but the connection to the MSSQL server failed.



Command and Control
BazarLoader:

# Exfiltration
On the second day of the intrusion, FileZilla was installed on one of the servers which used SFTP to exfiltrate data to a remote computer at IP address 192.52.167.210.

Using Netflow, we were able to confirm that some amount of data (~200MB) was exfiltrated out of the environment.


Here we can see the threat actor actively exfiltrating our information using FileZilla.



We also saw the threat actors exfiltrate databases by dragging and dropping information into FileZilla.


After pivoting to a Domain Controller, the threat actors dumped lsass using Task Manager:


And then uploaded the dump file to ufile.io using Internet Explorer on a server. Eyes on Apple iOS 14.6


# Impact
On the third day, the threat actors began their final actions. The final actions took place from a compromised file server. They began with a ping sweep to locate all live hosts. After that completed, they reviewed the results on the host.



From a file server, the threat actors then established RDP connections to all the machines in the environment.  The threat actors transferred 2 files onto the machines they connected to. A batch script named kill.bat and a ransomware executable CryptoLocker64.exe.

The batch script is responsible for deletion of volume shadow copies, turning off automatic repairs and stopping all the running services on the host. Some of the commands are as follows:


After completion of this activity, the ransomware binary was executed manually over the RDP connections.



From the threat actors starting their ping sweep, to final host encryption, about an hour passed leaving behind the ransom note for the organization to find. The threat actors went from initial access to domain wide ransomware in just under two days.

