#!/usr/bin/env python3

from pwn import *

binary = ELF('./environment')
binary.write(0x401214,5*b'\x90') # alarm
binary.save('./environment_noalarm')
os.chmod('./environment_noalarm',0o755)

