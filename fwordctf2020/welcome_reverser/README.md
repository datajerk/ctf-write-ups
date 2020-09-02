# FwordCTF 2020

## Welcome Reverser

> 374
>
> Hello and welcome to FwordCTF2k20 Let's start with something to warmup GOOD LUCK and have fun
>
> `nc welcome.fword.wtf 5000`
>
> Author: H4MA
>
> [`welcome`](welcome)

Tags: _rev_ _x86-64_ _angr_


## Summary

```
# ./welcome
Hello give me the secret number so i can get the flag:
0
no Flag for u
```

Free points with the help of [angr.io](angr.io).


## Analysis

### Decompile with Ghidra

This binary is stripped, so start by searching for `get the flag`:

```c
undefined8 FUN_00101591(void)
{
  char *__s;
  undefined8 uVar1;
  size_t sVar2;
  ulong uVar3;
  ulong uVar4;
  
  FUN_00101249();
  __s = (char *)malloc(0x10);
  puts("Hello give me the secret number so i can get the flag:");
  __isoc99_scanf(&DAT_0010208f,__s);
  uVar1 = FUN_00101335(__s);
  if (((int)uVar1 != 0) && (sVar2 = strlen(__s), sVar2 == 0x10)) {
    uVar3 = FUN_00101391(__s);
    uVar4 = FUN_00101421(__s);
    if (((int)uVar3 + (int)uVar4) % 10 == 0) {
      FUN_001012ae();
      return 0;
    }
    puts("no thats not my number:(");
  }
  puts("no Flag for u");
  return 0;
}
```

The `malloc` gives away the size, 16.  And the call to `FUN_001012ae()`:

```
0010165d e8 4c fc ff ff        CALL       FUN_001012ae
```

at address `0x165d` is a promising target.  I.e. it's not emitting an error before returning.


## Solve

```python
#!/usr/bin/python3

import angr, time, io

FIND_ADDR=0x40165d
t=time.time()
binary = open('./welcome','rb').read()
proj = angr.Project(io.BytesIO(binary),auto_load_libs=False)
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)
simgr.use_technique(angr.exploration_techniques.DFS())
simgr.explore(find=FIND_ADDR)
print(simgr.found[0].posix.dumps(0))
print(time.time() - t,end="")
print(" seconds")
```

Take the first 16 bytes and plug it into `./welcome` and you get the flag, e.g.:

```python
from pwn import *

p = remote('welcome.fword.wtf', 5000)
p.recvuntil('Hello give me the secret number so i can get the flag:')
p.sendline(simgr.found[0].posix.dumps(0)[:16])
print(p.recvuntil('FwordCTF{') + p.recvuntil('}'))
```

Output:

```bash
WARNING | 2020-08-30 06:12:55,054 | cle.loader | The main binary is a position-independent executable. It is being loaded with a base address of 0x400000.
WARNING | 2020-08-30 06:12:56,025 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2020-08-30 06:12:56,026 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2020-08-30 06:12:56,026 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state
WARNING | 2020-08-30 06:12:56,026 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2020-08-30 06:12:56,026 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.
WARNING | 2020-08-30 06:12:56,026 | angr.state_plugins.symbolic_memory | Filling memory at 0xc0000f5d with 195 unconstrained bytes referenced from 0x10002b0 (strlen+0x0 in extern-address space (0x2b0))
b'i\x04W\x01]\x02k\x024\x10+\x88b(\xd6!\x00\x00*J*\x00\x02\x89J)\x00\x1a\x0e\x08\x02\x89\x08J\x02\x89\x00\x00\x01\x01\x89\x00\x08*\x00\x00\x02JJ\x00\x08\x1a\x08)I\x0e\x00)\x02\x00'
10.467919826507568 seconds
[q] Opening connection to welcome.fword.wtf on port 5000
INFO    | 2020-08-30 06:13:05,625 | pwnlib.tubes.remote.remote.140285668858064 | Opening connection to welcome.fword.wtf on port 5000  Opening connection to welcome.fword.wtf on port 5000: Trying 54.92.137.14
INFO    | 2020-08-30 06:13:05,689 | pwnlib.tubes.remote.remote.140285668858064 | Opening connection to welcome.fword.wtf on port 50[+] Opening connection to welcome.fword.wtf on port 5000: Done
INFO    | 2020-08-30 06:13:05,770 | pwnlib.tubes.remote.remote.140285668858064 | Opening connection to welcome.fword.wtf on port 5000: Done
b'\nFwordCTF{luhn!_wh4t_a_w31rd_n4m3}'
```

## Solve with constraints

But what if you wanted just numbers?

```python
#!/usr/bin/env python3

import angr, time, claripy

BINARY='./welcome'
t=time.time()
proj = angr.Project(BINARY, auto_load_libs=False)
FIND=0x40165d
input_len=16
flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(input_len)]
flag = claripy.Concat( *flag_chars  + [claripy.BVV(b'\n')])
state = proj.factory.entry_state(args=[BINARY], stdin=flag)

for k in flag_chars:
    state.solver.add(k < 0x3a)
    state.solver.add(k > 0x2f)

simgr = proj.factory.simulation_manager(state)
simgr.use_technique(angr.exploration_techniques.DFS())
simgr.explore(find=FIND)
print(simgr.found[0].posix.dumps(0))
print(time.time() - t, "seconds")
```

Output:

```bash
# ./sol_w_constraints.py
WARNING | 2020-09-02 04:40:58,794 | cle.loader | The main binary is a position-independent executable. It is being loaded with a base address of 0x400000.
WARNING | 2020-09-02 04:41:00,131 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2020-09-02 04:41:00,131 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2020-09-02 04:41:00,131 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state
WARNING | 2020-09-02 04:41:00,131 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2020-09-02 04:41:00,131 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.
WARNING | 2020-09-02 04:41:00,131 | angr.state_plugins.symbolic_memory | Filling memory at 0xc0000f31 with 239 unconstrained bytes referenced from 0x10002b0 (strlen+0x0 in extern-address space (0x2b0))
b'1168111112111118\n'
7.1642327308654785 seconds
```

Flag:

```bash
# nc welcome.fword.wtf 5000
Hello give me the secret number so i can get the flag:
1168111112111118
FwordCTF{luhn!_wh4t_a_w31rd_n4m3}
```

How about only 1s and 2s?

```python
#!/usr/bin/env python3

import angr, time, claripy

BINARY='./welcome'
t=time.time()
proj = angr.Project(BINARY, auto_load_libs=False)
FIND=0x40165d
input_len=16
flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(input_len)]
flag = claripy.Concat( *flag_chars  + [claripy.BVV(b'\n')])
state = proj.factory.entry_state(args=[BINARY], stdin=flag)

for k in flag_chars:
    state.solver.add(k < 0x33)
    state.solver.add(k > 0x30)

simgr = proj.factory.simulation_manager(state)
simgr.use_technique(angr.exploration_techniques.DFS())
simgr.explore(find=FIND)
print(simgr.found[0].posix.dumps(0))
print(time.time() - t, "seconds")
```

Output:

```bash
# ./sol_w_constraints.py
WARNING | 2020-09-02 04:43:38,363 | cle.loader | The main binary is a position-independent executable. It is being loaded with a base address of 0x400000.
WARNING | 2020-09-02 04:43:39,670 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2020-09-02 04:43:39,670 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2020-09-02 04:43:39,670 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state
WARNING | 2020-09-02 04:43:39,670 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2020-09-02 04:43:39,670 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.
WARNING | 2020-09-02 04:43:39,670 | angr.state_plugins.symbolic_memory | Filling memory at 0xc0000f31 with 239 unconstrained bytes referenced from 0x10002b0 (strlen+0x0 in extern-address space (0x2b0))
b'1112121211121212\n'
7.7123801708221436 seconds
```

Flag:

```bash
# nc welcome.fword.wtf 5000
Hello give me the secret number so i can get the flag:
1112121211121212
FwordCTF{luhn!_wh4t_a_w31rd_n4m3}
```

