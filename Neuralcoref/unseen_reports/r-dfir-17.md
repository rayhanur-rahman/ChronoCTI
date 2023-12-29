# Summary

The threat actors gained initial access to a Windows workstation through the execution of a malicious DLL. The first activity of QBot was seen 5 minutes after the DLL was executed. Various automated discovery commands were used to

Following the first discovery stage, Qbot dropped another malicious DLL and created a scheduled task to obtain persistence.

Once the threat actors established persistence, they continued with enumerating the environment by mapping out the Active Directory environment using tools such as N

The executable named cool.exe to an empty string, retrieves the Domain Admin password Hash, and Upon the identification of one of the domain controllers, the attackers proceeded to exploit the ZeroLogon vulnerability. The executable used bears striking similarity to the one used in a previous case cool.exe to an empty string, retrieves the Domain Admin password Hash, and

The domain admin hash was then used on the beachhead through an over-pass-the-hash attack . After having domain admin privileges, they proceeded with deploying Cobalt Strike Beacons on a file server and another domain controller, which allowed them to pivot to those servers.

. To conclude this case, the threat actors were evicted from the network before they completed any further objectives.


# Analysis

. The threat actor gained their initial access through the execution of a malicious DLL. Traditionally Qbot is delivered via email using malicious documents that then downloads the malicious DLL. In this case, however, the execution started directly from the qbot DLL found here

The execution chain for this QBot infection can be seen below:

# Execution

# QBot PowerShell analysis

We analyzed the registry path and associated keys that were queried by the scheduled task HKCU:\SOFTWARE\Pvoeooxf and discovered that three keys were created containing base64 encoded values. Decoding the values resulted in:
- Copy of QBot DLL
- obfuscated PowerShell script that is referenced by the scheduled task.

The PowerShell script (triggered by the scheduled task) starts off a chain of events which is illustrated below:

When run for the first time, the script creates a new registry key entry in the same path, saving the date of execution. It then verifies upon execution if the creation date key of this registry key is older than 4 hours.

Based on the outcome, it will either: (1) retrieve the base64-encoded Qbot payload from the Windows Registry, decode it, save it on the file system and execute it.

OR (2) Fetch the QBot payload remotely using one of the active C2 IPs using the Invoke-WebRequest PowerShell module:

The PS script contains built-in logic to execute various types of payloads including batch and Visual Basic files.

The encoded QBot DLL that was stored in the registry, was dropped in the directory %APPDATA%\Roaming\Microsoft\Fdopitcu . The unsigned DLL, with descriptor Cancel Autoplay 2 was executed using regsvr32.exe

Upon execution of this second-stage DLL, various registry keys were created in HKCU\Software\Microsoft\Yerqbqokc. In addition, a new instance of explorer.exe (32-bit) was started and injected into.

The registry keys contain eight-character long hex strings for which we believe is part of the malware’s encrypted config.

# Persistence

# Scheduled Task/Job – Scheduled Task On Beachhead

The scheduled task created by Qbot was set to run every 30 minutes and executes a base64 encoded payload stored in the Windows Registry.

# Privilege Escalation

Thirty minutes after gaining initial access, the threat actors ran an executable file on the beachhead to exploit CVE-2020-1472, Zerologon.

C:\Windows\system32\cmd.exe /C cool.exe [DC IP ADDRESS] [DOMAIN NAME] Administrator -c "taskkill /f /im explorer.exe"

Three milliseconds after the exploit, an event 4742 “A computer account was changed.” was generated on the targeted Domain Controller.

As explained in a detailed blog from CrowdStrike, the ZeroLogon CVE relies on the AES-CFB8 algorithm used with a zero IV :

“In order to use AES-CFB8 securely, a random initialization vector (IV) needs to be generated for every plaintext to be encrypted using the same key. However, the ComputeNetlogonCredential function sets the IV to a fixed value of 16 zero bytes. This results in a cryptographic flaw in which encryption of 8-bytes of zeros could yield a ciphertext of zeros with a probability of 1 in 256. Another implementation issue that allows this attack is that unencrypted Netlogon sessions aren’t rejected by servers (by default). The combination of these two flaws could allow an attacker to completely compromise the authentication, and thus to impersonate a server of their choice.”

As we can see on the network captures, a brute-force attack was performed in order to spoof the identity of the domain controller :

After the end of the brute force traffic, we can see a single instance where a the exploit has completed successfully.

After being successfully authenticated, the DC password was set:

We can also see that the SubjectUserName is ANONYMOUS LOGON.

After authenticating to the DC with the DC account, the threat actors dumped the Domain Admin hash, and then reset the DC password in order to unbreak the Active Directory Domain.

The explorer shell was also restarted by the threat actor:

# Defense Evasion

Upon execution of the initial DLL, QBot uses process hollowing to start a suspended instance of explorer.exe (32-bit) and then injects itself into this process.

The injected explorer.exe process was used to spawn and inject into additional instances of explorer.exe (32-bit). An example event can be seen below. Source PID 10492 belonging to QBot, injected a DLL into PID 4072 which we discovered was part of Cobalt Strike C2 communication.

# Over-Pass-the-Hash from Beachhead

The threat actor obtained the NTLM hash value of the administrator account through the Zerologon exploit and used over-pass-the-hash We have seen the use of over-pass-the-hash several times before. For example, our Cobalt Strike Defender Guide covers detection of this technique in more detail.

Soon after, a TGT for the administrator account was requested:

# Discovery

QBot initially starts a number of processes to collect information about the affected system. This is part of the “SYSTEM INFO” bot request, as described in a recent article from SecureList.



Later, more discovery commands were executed via the Cobalt Strike beacon, which gathered information about the active directory environment.
- C:\redacted\find.exe -f objectcategory=computer -csv name cn OperatingSystem dNSHostName
- C:\Windows\system32\cmd.exe /C wmic /namespace:\\root\SecurityCenter2 PATH AntiSpywareProduct GET /value
- C:\Windows\system32\cmd.exe /C wmic /namespace:\\root\SecurityCenter2 PATH AntiVirusProduct GET /value
- C:\Windows\system32\cmd.exe /C wmic /namespace:\\root\SecurityCenter2 PATH FirewallProduct GET /value

Ping was used to verify machines were online

ping -n 1 [REDACTED]

# Lateral Movement

Through the creation of Windows services, Cobalt Strike Beacons (psexec_psh function) were deployed on multiple hosts within the environment.


Multiple services were installed by Cobalt Strike across the environment, here are a few examples:
- HKLM\System\CurrentControlSet\Services\3141131\ImagePath 
- HKLM\System\CurrentControlSet\Services\af5ff02\ImagePath 
- HKLM\System\CurrentControlSet\Services\c46234f\ImagePath

first calls to create the service remotely, then starts it with StartServiceA function:

RDP/interactive Logins

Increase the max RDP connections allowed, in this case a arbitrarily large number.

REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /t REG_DWORD /v "MaxInstanceCount" /d 0xffffffff /f

Makes sure the RDP listener is enabled.

REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /t REG_DWORD /v "fEnableWinStation" /d 1 /f

Makes sure the user is allowed to RDP to the terminal server.

REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /t REG_DWORD /v "TSUserEnabled" /d 0 /f

Makes sure the terminal server is set to enabled.

REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /t REG_DWORD /v "TSEnabled" /d 1 /f

Makes sure terminal services is set to remote admin mode.

REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /t REG_DWORD /v "TSAppCompat" /d 0 /f

Makes sure that the terminal service will start idle sessions.

REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /t REG_DWORD /v "IdleWinStationPoolCount" /d 1 /f

Enables advertisement of the terminal server.

REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /t REG_DWORD /v "TSAdvertise" /d 1 /f

Makes sure terminal server is set to allow connections.

REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /t REG_DWORD /v "AllowTSConnections" /d 1 /f

Makes sure terminal server is set to simultaneous sessions.

REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Licensing Core" /t REG_DWORD /v "EnableConcurrentSessions" /d 1 /f

Makes sure multiple sessions are allowed.

REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /t REG_DWORD /v "fSingleSessionPerUser" /d 0 /f

Starts the terminal services and sets service to autostart.

sc config termservice start= auto net start termservice /y

LogName=Security EventCode=4624 Logon Type=10 (Remote Interactive Logon - RDP)

# Named pipe (SMB)

The base64 encoded payload can be decoded using this Cyberchef recipe (shout out @0xtornado) which represents a SMB beacon that creates the named pipe “dce_3d”.

# Command and Control

Here is the initial access DLL (Qbot) information from Tria.ge


# Exfiltration

While the threat actors were active in the environment, we received 3 different alerts stating that someone had opened canary documents from the IP address 91.193.182[.]165. These alerts tell us that data was indeed exfiltrated from the environment.

The threat actors were most interested in files concerning financial statements, ransomware reports, and salary data.

The C2 channel was encrypted and multiple connections were established with the internal file server. No other traffic was observed for possible exfiltration leading us to the conclusion that the command and control channel was used for the exfiltration.

At 17:35 UTC, the Cobalt Strike Beacon was deployed on the File Server.

Spike in traffic from file share server to Cobalt Strike command and control server.


# MITRE ATT&CK DATASET
Exploitation for Privilege Escalation – T1068

Service Execution – T1569.002

Network Share Discovery – T1135

Pass the Hash – T1550.002

PowerShell – T1059.001

Windows Command Shell – T1059.003

Network Share Discovery – T1135

Obfuscated Files or Information – T1027

Scheduled Task – T1053.005

Process Injection – T1055

Remote System Discovery – T1018

Obfuscated Files or Information – T1027

Domain Trust Discovery – T1482

Domain Groups – T1069.002

System Owner/User Discovery – T1033

Network Share Discovery – T1135

Remote Services – T1021

Local Account – T1087.001

Security Software Discovery – T1518.001
