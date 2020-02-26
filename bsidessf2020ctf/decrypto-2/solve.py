#!/usr/bin/env python3

import hashlib
import struct

xml_header='<?xml version="1.0" encoding="UTF-8" standalone="no"?>'.encode("utf-8")
buf=open("flag.svg.enc", "rb").read()
hash=(bytes(a ^ b for a,b in zip(xml_header[:32], buf)))
key=hash

for i in range(int(len(buf) / 32) + 1):
    hash=hashlib.sha256(hash + struct.pack('<I', i+1)).digest()
    key+=hash

print(bytes(a ^ b for a, b in zip(buf, key)).decode("utf-8"))
