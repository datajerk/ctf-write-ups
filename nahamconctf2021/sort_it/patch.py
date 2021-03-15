#!/usr/bin/env python3

from pwn import *

binary = ELF('sort_it')
binary.write(0x1208,5*b'\x90')
binary.save('sort_it_patched')
os.chmod('sort_it_patched',0o755)
