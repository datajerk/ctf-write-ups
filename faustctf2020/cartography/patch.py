#!/usr/bin/python3

from pwn import *

binary = ELF('./cartography')
context.update(arch='amd64',os='linux')

binary.asm(0x400dfe,'''
jnz ok
nop
mov QWORD PTR [rsp+0x10],rax
jmp 0x400c7a
ok:
''')

binary.save(binary.path + '_patched')
os.chmod(binary.path + '_patched',0o755)

