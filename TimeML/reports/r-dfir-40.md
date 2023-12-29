# Case Summary

A threat actor exploited CVE-2020-14882 by making a call to the images directory, which allowed them to execute code on the server. Using this exploit, they downloaded and executed an xml file, which included a PowerShell command to download and execute a script. The script does multiple things, such as download XMRig and its config, rename XMRig to sysupdate, schedule a task for it’s update process, and confirm the miner is running.

# analysis

# MITRE ATT&CK

The threat actor executed an xml file named wbw hosted at 95.142.39[.]135 by exploiting CVE-2020-14882.

In the above screenshot, the threat actor executes wbw.xml which then downloads and executes 1.ps1.



The script starts off by setting parameters, such as the download locations for XMRig and its config.

The script then downloads and executes XMRig, renames it to sysupdate and then sets a schedule task, which runs update.ps1. There was no script located in this directory but we assume one would show up when the miner needed to be updated, if the threat actor still had access.



The script renamed xmrig.exe to sysupdate in attempt to hide itself.

The server’s CPU was maxed out at 100% and likely would have caused issues in an enterprise environment. At the time of this writing the wallet used for mining barely had anything in it and appears to be dedicated to us.

