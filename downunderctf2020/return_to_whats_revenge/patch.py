#!/usr/bin/env python3

from pwn import *

binary = ELF('return-to-whats-revenge')
binary.asm(binary.symbols['alarm'], 'ret')
binary.save('return-to-whats-revenge_noalarm')
os.chmod('return-to-whats-revenge_noalarm',0o755)

