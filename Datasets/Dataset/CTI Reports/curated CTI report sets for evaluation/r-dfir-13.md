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



The second request, attempted to install Zoho’s Site24x7 performance monitoring tool but indirectly invoked the uploaded msiexec.exe file. More details regarding this are covered in the Execution section.


The exploitation attempts against the internet-facing server arrived from two Tor exit nodes. Each step of the exploit was observed originating from a different TOR exit node.


# Execution

The second stage of the CVE-2021-44077 exploit involved initiating the installation of Zoho’s Site24x7 performance monitoring tool. Support Center Plus will do this by invoking the installation via msiexec.exe by running:


The running path of Support Center Plus at the time this command runs is C:\Program Files\ManageEngine\SupportCenterPlus\bin\ which means the msiexec.exe uploaded by the threat actor will be favored rather than the legitimate Microsoft utility.



Once the malicious msiexec.exe is executed an embedded Java payload will be decoded and written to:

The parameters passed to msiexec.exe are never used and the Site24x7 performance monitoring tool is never installed.



The web shell was written to:

This location is web accessible which means the threat actors can interact with the web shell through a web browser from the internet. Here are a few commands run through the web shell.

The following diagram visually illustrates the CVE-2021-44077 exploitation and execution process.

The threat actors had previously uploaded a different file, named the same thing minutes before the web shell was created. After the execution of that file seemed to fail, the threat actors uploaded the msiexec.exe file from above which created the web shell seconds later.


The two msiexec files included the same web shell but had some differing characteristics. Here is some information on the first attempted msiexec file which failed.


The main difference being the interesting PDB path m:\work\shellll\ and the differing .NET versions.

# Application logs
We can see from the Catalina.txt log that when the threat actors run certain commands such as fxs.bat (RDP tunneling) the application thinks the process is hung (runs for 30+ seconds) and creates a warning message:

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

WDigest allows for credential caching in LSASS which will result in a users plaintext password being stored in memory. The intended purpose of WDigest credential caching is to facilitate clear text authentication with HTTP and SASL, however, this can be misused by the threat actor to retrieve the plaintext credentials of a user.

Here’s the command executed from the web shell:

This registry value was not present on the system, which informed the attacker that WDigest was disabled on the beachhead.

Twenty-two seconds later, the threat actor enabled WDigest using the following command, via the web shell:


# Credential Access
After enabling WDigest, the attacker checked back numerous times over multiple days to see who was signed in. During this period, a privileged user logged onto the system for maintenance work and after which, the threat actor dumped LSASS using comsvcs.dll. The threat actor listed the running processes via the tasklist command and used the PID of LSASS from the output to pass to the credential dumping command.


The LSASS dump was then exfiltrated out of the environment for offline analysis and rest of the actions were conducted from the account whose password was extracted from the LSASS dump.

# Discovery
The threat actor used the web shell fm2.jsp to conduct their initial discovery on the host. Below are the GET requests sent to the web shell with the discovery commands passed to the cmd parameter, which runs as PowerShell.

They also used the web shell to review directories, here’s a few examples

# Lateral Movement
The threat actor used the web shell to download file.exe onto the beachhead and save it as ekern.exe using a PowerShell download cradle.

The file ekern.exe was a renamed copy of Plink.exe, a command-line SSH client.



Plink was used in conjunction with a batch script named FXS.bat to establish an SSH connection with the threat actor’s server.





Let’s break down what this command means:

Providing “y” as standard input to the executable. To confirm when plink asks if they would like the public key added to known hosts.


Plink executable

Force the use of SSH (Plink can support other protocols)

Define a specific target port for SSH connection

Connect with the specified username

Password to authenticate with

Listen on 23.81.246.84:49800 and forward it to 127.0.0.1:3389. This effectively proxies the request to the host running the command

Target server to SSH

The actor defined a custom target port to Plink (-P 443) instead of the default SSH port of 22.

The actor used the technique of port forwarding to listen on the remote port, 23.81.246[.]84:49800, and forward the requests to 127.0.0.1:3389. This resulted in the actor being able to RDP to the beachhead server via the SSH tunnel.



The script FXS.bat was re-used multiple times to establish connections to various hosts.

The actor then replaced the loopback address with various internal hosts. The ManageEngine server acted as a proxy that forwarded the RDP traffic between the target host and the threat actor’s server:


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
