#!/usr/bin/env python3

from pwn import *

binary = ELF('./challenge')

binary.write(0x1113,5 * b'\x90')

binary.save('hash_it')
os.chmod('hash_it',0o755)
