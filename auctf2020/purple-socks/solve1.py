#!/usr/bin/env python3

from itertools import cycle

binary = 'purple_socks'
f = open(binary,'rb')
encrypted = f.read()
f.close()

decrypted = [ a ^ b if not a == 0 else a for (a,b) in zip(encrypted,cycle([78])) ]

binary = 'purple_socks_elf'
f = open(binary,'wb')
f.write(bytearray(decrypted))
f.close()
