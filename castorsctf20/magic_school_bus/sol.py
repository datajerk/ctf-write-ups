#!/usr/bin/python3

from pwn import *

p = remote('chals20.cybercastors.com',14421)

p.recvuntil('Your choice: ')
p.sendline('2')
p.recvuntil('Flag bus seating: ')
_ = p.recvline().strip()

print(_)

while True:
	p.recvuntil('Your choice: ')
	p.sendline('1')
	p.recvuntil("Who's riding the bus?: ")
	p.sendline(_)
	p.recvuntil('Bus seating: ')
	_ = p.recvline().strip()
	print(_)

	if _.find(b'CASTORSCTF') != -1:
		print()
		print(_)
		break

