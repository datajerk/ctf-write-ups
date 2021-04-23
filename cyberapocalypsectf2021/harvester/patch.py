#!/usr/bin/env python3

from pwn import *

binary = ELF('./harvester')
binary.write(0xa1c,5*b'\x90') # usleep
binary.write(0xf74,5*b'\x90') # alarm
binary.save('./harvester_no_usleep')
os.chmod('./harvester_no_usleep',0o755)

