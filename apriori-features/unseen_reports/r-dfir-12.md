# Summary

Over the month of March, we observed a cluster of activity targeting MSSQL servers. The activity started via password brute force attempts for the MSSQL SA account. These brute force attempts were observed repeatedly over the month. Examples included one cluster of 24,000 failed attempts from the same source, over a 27 hour effort, before they finally managed to guess the password. After having the correct credentials in their possession, the attackers then spawned a command shell via xp_cmdshell. According to Microsoft documentation, xp_cmdshell spawns a Windows command shell and passes in a string for execution.

Using xp_cmdshell, the threat actors were able to execute any command against the compromised server. They attempted to kill a bunch of AV programs by using taskkill.exe. The threat actors then wrote multiple commands to a batch file by using echo and redirecting the strings to a file named 1.bat. After the batch file was written they then proceeded to perform the same action echoing data into a file named bigfile.txt. After they finished writing to that file, they ran certutil to decode the base64 data into an executable file. This executable was a privilege escalation tool that was used to execute the batch file to make sure it executed with high enough permissions. They then executed the batch script. The commands included adding new users to the local administrators group, enabling RDP, enabling WDigest, and hiding the newly created admin accounts using the registry.

Once the threat actors had established persistence on the compromised host, they moved to their final objective, which was to install and run the XMRig miner. They dropped a Binary Managed Object Format (BMOF) file along with the miner itself, to do that. The threat actors used mofcomp.exe to decompile the BMOF binary and register a malicious class in the WMI repository. The event consumer of the newly created classes included a VBE script responsible for setting up and executing the XMRig miner with the correct settings.

No other activity beyond the mining was observed before the threat actors were evicted.

# Analysis

The initial access took place via a brute-force attack, where the threat actors mainly targeted the System Admin (SA) account.

During the intrusions, we could see SQL Server event ID 18456 Failure Audit Events in the Windows application logs. We witnessed more than 24,000 attempts from the same source before the threat actors successfully guessed the username and password for the open SQL database.

Example of the failed brute force attempts:

Followed by eventual successful logins.

It it likely that multiple successful logins were observed due to the automated access script that the threat actor was using.

# Execution

In the next attack stage, the threat actors established a cmd shell via Extended SQL Stored Procedure (xp_cmdshell). This process allows you to issue operating system commands directly to the Windows command shell using T-SQL code. An example of command execution following a successful authentication to SQL database using xp_cmdshell:

#Executing 'whoami' command on the remote host

EXEC xp_cmdshell ‘whoami’

At a high level, the overall execution events can be depicted in the below diagram:

If we look into the Windows Application logs, specifically, the SQL Server event ID 15457, captures this as an ‘xp_cmdshell’ event. Additionally, the SQL Server audit collection also captures similar events. The first commands executed by the threat actors included using taskkill for various anti-virus software.
- taskkill /f /im egui.exe 
- taskkill /f /im QQPCTray.exe 
- taskkill /f /im SafeDogGuardCenter.exe 
- taskkill /f /im 360safe.exe 
- taskkill /f /im net1895.exe 
- taskkill /f /im ekrn.exe 
- taskkill /f /im 360rp.exe 
- taskkill /f /im QQPCMgr.exe 
- taskkill /f /im SafeDogServerUI.exe 
- taskkill /f /im SafeDogSiteIIS.exe

The threat actors also favored the execution of batch scripts on the compromised host. They used xp_cmdshell to write a batch script (1.bat) to disk by redirecting strings to the file using echo commands.

A second set of commands were also echoed into a file named bigfile.txt.

Once complete, certutil was used to decode the text and create an executable file.

"cmd.exe" /c certutil -decode %USERPROFILE%\AppData\bigfile.txt %USERPROFILE%\AppData\bigfile.exe

This executable was then used in executing the 1.bat batch file.

"cmd.exe" /c %USERPROFILE%\AppData\bigfile.exe -i -c %USERPROFILE%\AppData\1.bat

Pulling the hash of the file that was written, matches what appears to be a privilege escalation tool as seen in the hits from THOR scanner: https://www.virustotal.com/gui/file/b67dfd4a818d10a017a4d32386cf4cd2a3974636bed04f27e45de6ada86a56d2/community

We believe this tool may be a variation of NetworkServiceExploit.exe, which attempts to use NetworkService for privilege escalation.

Additionally, we noticed the attackers dropping a file named “xitmf”. Looking into the file’s content, we noticed that the header began with “FOMB”. When flipping the header, it spells BMOF, which indicates a Binary Managed Object Format file. BMOF is a compiled version of a Managed Object Format (MOF) file. As per Microsoft’s official documentation:

“Managed Object Format (MOF) is the language used to describe Common Information Model (CIM) classes.”

MOF files are compiled using the Windows compiler tool mofcomp. Mofcomp.exe is also used to execute scripts by parsing the MOF statements and creates new classes as part of the WMI repository.

cmd.exe /c mofcomp.exe C:\Windows\SERVIC~1\MSSQL$~1\AppData\Local\Temp\xitmf

Using the same mofcomp utility, its possible to decompile the BMOF to extract the script, using this command provided by Matt Graeber:

Threat actors also transferred a Visual Basic Encoded (VBE) file that is executed on the host using cscript.exe. Once run, the script would set up and execute the XMRig CoinMiner. During the execution, the password 579562847 is provided as an argument.

cscript.exe /b /e:VBScript.Encode C:\Windows\SERVIC~1\MSSQL$~1\AppData\Local\Temp\xit 579562847

We recognize that this is a VBE file from the file signature (“magic bytes”) at the first four bytes of the top of the file.

We can decode the VBE file using CyberChef:

The script has several functions, one to control the coin miner software on the host, and two, to configure the parameters such as user-agent strings through randomization:

Command interactions are done via WMI, for process discovery:

# Process creation:

In the code, we observed further attempts to obfuscate sensitive attributable values:

Using the original password and some further de-obfuscation, we could decipher the values, in this case, the email address is:

[email protected]

Some other deciphered values relate to coin mining pools:

crypto-pool[.]fr minergate[.]com

We also observed another dropper. Threat actors transferred the file ex.exe. Ex.exe is an Unrar application that they used to extract more malicious artifacts:

# CommandLine:

ex.exe x -prootBRUCE -y C:\Windows\<REDACTED>\AppData\Local\Temp\istx64f.rar C:\Windows\<REDACTED>\AppData\Local\Temp\mstrx\<file>

# File Extracted:

WinRing0x64.sys - XMRig cryptominer windows driver smss.exe - XMRig coin miner kit.bat

The kit.bat script included instructions for executing the miner as well as for creating persistence via a schedule task. See the contents of the script below:

Something to note here, regarding the kit.bat script, is that we discovered that its contents were the topic of discussion in a Chinese forum back in 2018.

Link: hxxp://www[.]bathome[.]net/thread-48526-1-1.html

# Persistence

The threat actors wrote a batch script (1.bat) that contained commands for establishing persistence on the compromised host. We see the creation of a new account and adding this account to the local administrators group.

NET USER Adminv$ !67hCS14ORVg /ADD /expires:never NET LOCALGROUP Administrators /ADD Adminv$

They also made remote RDP connections possible by changing the fDenyTSConnections and UserAuthentication values to 0.

# Full Contents of 1.bat

We later see the threat actors writing another batch file to disk and executing it. The kit.bat script contained a scheduled task that would run the kit.bat script on an hourly basis.

schtasks /create /tn ngm /tr "%~dps0kit.bat -s" /sc hourly /ru "" schtasks /run /tn ngm

As explained in the execution tactic above, the threat actors installed a malicious WMI event subscription by including a VBScript that would execute on the compromised host. This was used as a method of persistence. The VBScript would execute every day at 23:00 of the host local time.

Decompiled .mof file containing the WMI event subscription.

Breaking down the above screenshot, the WMI event subscription contains the below malicious EventConsumer and EventFilter classes:


Looking into the VBScript, we notice that it is reaching out to the domain mymst007[.]info on port 4000 to download one more file and save it as temp file.

# WMI EventConsumer VBScript:

We used the below python code to emulate the VBScript and download the next stage payload:

# Second stage payload downloaded and executed:

The final method of persistence we observed was the addition of an entry into the Image File Execution Option (IFEO) registry key. By changing the Debugger value to a different executable, an attacker used IFEO to launch a program other than the intended one. In this case, threat actors modified the below registry key to launch the miner executable (smss.exe) instead of the svchost.exe binary.

"cmd.exe" /c REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\smss.exe" /f /v Debugger /t REG_SZ /d "C:\windows\system32\svchost.exe

# Privilege Escalation

The threat actors dropped a file named bigfile.txt which they used certutil to convert to bigfile.exe which we believe is a variation of NetworkServiceExploit.exe as seen below.

This was used in this intrusion to run the batch file with the following command:

"cmd.exe" /c %USERPROFILE%\AppData\bigfile.exe -i -c %USERPROFILE%\AppData\1.bat

# Defense Evasion

The threat actors attempted to kill antivirus tasks that could be running on the host. The commands targeted the below processes:


The privilege escalation tool the threat actors brought with them was written as a text file and then decoded using certutil into a binary file.

"cmd.exe" /c certutil -decode %USERPROFILE%\AppData\bigfile.txt %USERPROFILE%\AppData\bigfile.exe

As we can see from the contents of the 1.bat script, the threat actors are adding a new local administrator user and they proceed with hiding the user account by adding it to the registry using “Special Accounts“.

REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist" /v Adminv$ /t REG_DWORD /d 0

Through the execution of the initial batch script, 1.bat, they also disabled the User Access Control(UAC) remote restriction by setting the registry key value to “1”.

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f

Threat actors also enabled Wdigest.

reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f

After many files were added to the system the threat actors included commands to remove them once their execution was finished.
- "cmd.exe" /c DEL %USERPROFILE%\AppData\1.bat
- "cmd.exe" /c DEL %USERPROFILE%\AppData\bigfile.txt
- "cmd.exe" /c DEL %USERPROFILE%\AppData\bigfile.exe

# Credential Access

During the initial access credentials were obtained via a brute-force attack against the exposed MSSQL server. No other credential access was observed during this intrusion, although the threat actors did enable WDigest to make later credential access easier.

# Command and Control

We observed that the domain mymst007[.]info is used to download further payloads. The domain was created five years ago. We have seen similar reports that make mention of the same infrastructure. Attacks associated with this domain include the same or similar tactics techniques and procedures (TTPs).

Connections related to the domain – mymst007[.]info

# Impact

The impact was concentrated on this one host. We did not see any further activity in this case. The compromised host had XMRig miner installed and running. The miner was also connecting to cryptomining pool such as minergate[.]com.



# MITRE ATT&CK DATASET
T1053.005 - Scheduled Task/Job: Scheduled Task T1136.001 - Create Account: Local Account T1546.003 - Event Triggered Execution: Windows Management Instrumentation Event Subscription T1564.002 - Hide Artifacts: Hidden Users T1059.003 - Command and Scripting Interpreter: Windows Command Shell T1027.004 - Obfuscated Files or Information: Compile After Delivery T1110.001 - Brute Force: Password Guessing T1070.004 - Indicator Removal on Host: File Deletion T1562.001 – Impair Defenses: Disable or Modify Tools T1546.012 - Event Triggered Execution: Image File Execution Options Injection T1140 - Deobfuscate/Decode Files or Information T1112 - Modify Registry T1078 - Valid Accounts

T1134.001 - Token Impersonation/Theft

Internal case #12780

Share this: Twitter

LinkedIn

Reddit

Facebook

WhatsApp

