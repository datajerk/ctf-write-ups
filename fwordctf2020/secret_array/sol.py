#!/usr/bin/env python

from pwn import *

p = remote('secretarray.fword.wtf', 1337)
context.log_level = 'INFO'
context.log_file = 'foo.log'
p.recvuntil('START:\n')

n = 1337 * [0]

p.sendline('0 1')
a = int(p.recvline().strip())
p.sendline('0 2')
b = int(p.recvline().strip())
p.sendline('1 2')
c = int(p.recvline().strip())

n[1] = (b - c - a) / -2
n[0] = a - n[1]
n[2] = c - n[1]

log.info('n[0] = ' + str(n[0]))
log.info('n[1] = ' + str(n[1]))
log.info('n[2] = ' + str(n[2]))
log.info('going for it')

ans = 'DONE ' + str(n[0]) + ' ' + str(n[1]) + ' ' + str(n[2])
for i in range(3,1337):
	log.info(str(i))
	p.sendline('0 ' + str(i))
	n[i] = int(p.recvline().strip()) - n[0]
	ans += ' '
	ans += str(n[i])

context.log_level = 'DEBUG'
p.sendline(ans)
print(p.stream())

