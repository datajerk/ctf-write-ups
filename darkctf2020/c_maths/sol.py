#!/usr/bin/env python3

from pwn import *

binary = ELF('./c_maths')

r = remote('cmaths.darkarmy.xyz', 7001)

d = process(['gdb',binary.path])
d.sendlineafter('gdb) ','b *0x555555554000+0x13bf')
d.sendlineafter('gdb) ','b *0x555555554000+0x150d')
d.sendlineafter('gdb) ','b *0x555555554000+0x161c')
d.sendlineafter('gdb) ','r')
d.sendlineafter('gdb) ','x/s $rbp-0x95+8')
a1 = d.recvline().strip().split(b'"')[1]
d.sendlineafter('gdb) ','c')
d.sendlineafter('Continuing.\n',a1)
d.sendlineafter('gdb) ','p/d $rax')
a2 = d.recvline().strip().split()[-1]
d.sendlineafter('gdb) ','c')
d.sendlineafter('Continuing.\n',a2)
d.sendlineafter('gdb) ','p/d $rax')
a3 = d.recvline().strip().split()[-1]
d.sendlineafter('gdb) ','c')
d.sendlineafter('Continuing.\n',a3)
d.sendlineafter('gdb) ','q')
d.close()

log.info(b'sending: ' + a1)
r.sendline(a1)
for i in range(9): log.info(r.recvline())
log.info(b'sending: ' + a2)
r.sendline(a2)
for i in range(3): log.info(r.recvline())
log.info(b'sending: ' + a3)
r.sendline(a3)
log.info(r.recvline())

