#!/usr/bin/env python3

from pwn import *

binary = ELF('rrop')
binary.asm(binary.symbols['alarm'], 'ret')
binary.save('rrop_noalarm')
os.chmod('rrop_noalarm',0o755)

