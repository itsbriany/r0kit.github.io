## OSCP

* [Buffer Overflows](./oscp/buffer-overflow.html)
* [Brainpan Level 1 (More Buffer Overflows)](./oscp/brainpan1.html)
* [Metasploitable3 Windows Server 2008 R2](./oscp/metasploitable3-win2k8.html)
* [MySQL Injection Cheatsheet](./web/mysqlinjection.html)
* [OSCP Voucher Box](./oscp/oscp.html)
    * User Own -> Leaked user and private SSH key
    * Root Own -> Abusing Linux lxd group

## Web

* [Web Hacking](./web/web.html)
    * [Hacking Django Apps](./web/django.html)
    * [Local and Remote File Inclusions (LFI/RFI)](./web/lfi.html)

## Bug Hunting

* [Bug Hunting Methodology](./bug-hunting/methodology.html)
    * [Recon](./bug-hunting/recon.html)
    * [XSS Hunting](./bug-hunting/xss.html)
    * [IDORF Hunting](./bug-hunting/idorf.html)
    * [Open Redirect Hunting](./bug-hunting/open-redirect.html)
    * [Rate Limiting Hunting](./bug-hunting/rate-limiting.html)
    * [Android](./bug-hunting/android.html)

## Hack The Box Writeups

* [My YouTube Channel](https://www.youtube.com/channel/UCjjPQZM-DNqCNbcLkFkYprQ/videos) -> Don't forget to subscribe! ;)

### Easy Machines

* [Shocker](./htb/shocker.html)
    * User Own -> Shellshock CVE on Apache mod_cgi
    * Root Own -> sudo permission abuse
* [Grandpa/Granny](./htb/grandpa.html)
    * Foothold      -> CVE-2017-7269
    * User/root own -> MS09-012
* [Bastion](./htb/bastion.html)
    * User own -> SMB enumeration + SAM/SYSTEM registry dump
    * Root own -> Sensitive information disclosed in outdated third party software
* [Beep](./htb/beep.html)
    * User own -> Elastix 2.2.0 - 'graph.php' Local File Inclusion
    * Root own -> Credential Reuse
* [Nibbles](./htb/nibbles.html)
    * User own -> Weak Credential Guessing + CVE-2015-6967
    * Root own -> Arbitrary Sudo Without Password
* [Netmon](./htb/netmon.html)
    * User own -> Mounted C:\ Drive w/Anonymous Access
    * Root own -> Sensitive Information Disclosure + CVE-2018-9276
* [Forest](./htb/forest.html)
    * User own -> AS-REP Roast Attack
    * Root own -> Implicit Permissions to Domain Admin via Exchange Windows Permissions
* [Active](./htb/active.html)
    * User Own -> Sensitive Groups.xml leaked from SYSVOL Replication
    * Root Own -> Kerberoasting the Service Account
* [Irked](./htb/irked.html)
    * Foothold -> CVE-2010-2075
    * User Own -> World Readable Password Hint
    * Root Own -> Abusing Arbitrary Commands Invoked by SUID Binaries

### Medium Machines

* [October](./htb/october.html)
    * User Own -> CMS Enumeration + CVE
    * Root Own -> Buffer overflow with ASLR enabled
* [Bastard](./htb/bastard.html)
    * User Own -> Drupal CVE
    * Root Own -> Juicy Potato
* [Popcorn](./htb/popcorn.html)
    * User Own -> File Upload MIME filter bypass
    * Root Own -> Outdated Linux Kernel -> Dirty Cow - CVE-2016-5195, Non-default artifacts left in user's directory -> CVE-2010-0832
* [Jeeves](./htb/jeeves.html)
    * User Own -> Web brute forcing + Jenkins Script Console RCE (Windows)
    * Root Own -> Juicy Potato/Sensitive Information Disclosure + Alternate Data Streams
