# Case Summary

In the attack, the threat actor took around 2 minutes from initial access, to running a persistent coin miner. The speed and number of times the exploit was ran against the target make it likely that this was an automated attack, rather than human operated intrusion.

The threat actor exploited CVE-2020-14882 by making a request to the WebLogic server, which allowed the attacker to execute code. The payload then ran a PowerShell command to download a PowerShell script from a remote server. This script downloaded a loader and executed it, then it enabled persistence mechanisms. Next, the loader downloaded XMRig, and started the mining process.

While this attack took place around a month ago the payloads used in the intrusion continue to be hosted as of this publication, indicating that this threat is still active and finding vulnerable WebLogic hosts to continue exploiting.

Analysis and reporting completed by @tas_kmanager and @TheDFIRReport

Reviewed by @iiamaleks and @samaritan_o

# Analysis

# Initial Access

Before jumping into the details of the attack, it is pertinent to understand CVE-2020-14882. This vulnerability was discovered back in October 2020, which effects Oracle’s WebLogic product. [1] We previously reported on an intrusion that also used this exploit and ended in a coin miner. This vulnerability is easy to exploit, and leads to remote code execution (RCE) without authentication.

Just by invoking URL path /console/images/%252E%252E%252Fconsole.portal and a little bit of tweaking of the packet sent to the server, the threat actor will be able to run their code on the server.

In this case, we can clearly see from network logs that the attacker was probing the portal page and followed that by sending the crafted URL request.

The detailed payload in the header can be observed below:

Interestingly, we can see the threat actor chose the FileSystemXmlApplicationContext class to carry out this attack, executing a file named poc.xml. This technique is listed in PoC developed by Jang. [2]

Below we can see the payload inside of the xml file hosted in the attacker server. The payload will execute the PowerShell command on the vulnerable system.

# Execution

The threat actor leveraged the WebLogic vulnerability to spawn a command shell from the server running in the Java process, which then in turn, was used to run PowerShell and collect the final payload that the threat actor wished to run on the system.

Next, let us investigate the content of the PowerShell script (ldr.ps1)

On line one, we can see var $cc (can be pronounced as C2?) that indicates the server where it will get all the other components such as the payload sys.exe. The next line sets up random characters to be appended to the payload executable.

This binary (renamed to sysvr013.exe) was then executed by the same script.

# Persistence

There are several persistence mechanisms observed. The first one utilizes schtasks to create a task called “BrowserUpdate”.

It also created a registry run key to execute the miner binary on reboot.

We also observed the Loader binary adding npf.sys (WinPcap binary) as a scheduled task.

# Privilege Escalation

No privilege escalation was observed, but note that the Java.exe process was running as a high integrity process from the start.

# Defense Evasion

From the PowerShell script above (ldr.ps1), we can see that name is being randomized to avoid detection by blue team. We can also see that the attacker disabled firewall rules to make sure connection to the mining pool was not blocked.

As noted above, the attacker created a task called “BrowserUpdate” to masquerade the scheduled task as a web browser update task.

# Discovery

We can see several local discovery commands executed from the PowerShell script. They are looking for existing mining process on the machine, such as kthreaddi, sysrv, etc. They also utilize netstat to find if any process is using mining related ports, such as 3333, 4444, etc.

This is likely partially to kill other rival miners but also to prevent duplicate miners on the same host as the exploit was executed against the target repeatedly in quick succession, at least 12 times.

# Impact

We saw that the additional sys.exe binary and ldr.ps1 PowerShell script was brought in to support the Mining operation from IP address 194[.]145[.]227[.]21

We also observed connection from [kthreaddi].exe talking to crypto mining pools

Eventually, the crypto mining operation will cause performance issue with the WebLogic server.
