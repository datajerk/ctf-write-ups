# DarkCTF 2020

## rev/jack

> 32 solves / 475 points
>
> Author: z3phyr
>
> Just another crackme....
>
> `Enclose the key with darkCTF{}`
>  
> [jack](jack)

Tags: _rev_ _x86-64_ _angr_


## Summary

Just solve with [angr.io](http://angr.io).

## Analysis

### Decompile with Ghidra

```
  sVar2 = strlen(&local_28);
  if (sVar2 != 0x10) {
    puts("Try Harder");
  }
```

Above is the first check, must be 16 (`0x10`) bytes in length.

```
void check_flag(uint *param_1)
{
  if ((((*param_1 == 0xcb9f59b7) && (param_1[1] == 0x5b90f617)) && (param_1[2] == 0x20e59633)) &&
     (param_1[3] == 0x102fd1da)) {
    puts("Good Work!");
    return;
  }
  puts("Try Harder");
  return;
}
```

We need to tell _angr_ what to look for.  Highlight `puts` and get the address:

```
00101489 e9 a2 fb        JMP        puts
         ff ff
```

## Solve

```
#!/usr/bin/env python3

import angr, time, claripy

t=time.time()
BINARY='./jack'
proj = angr.Project(BINARY, auto_load_libs=False)
print("Entry: 0x%x" % proj.entry)
FIND=0x00401489
input_len=16
flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(input_len)]
flag = claripy.Concat(*flag_chars)

state = proj.factory.entry_state(args=[BINARY], stdin=flag)

for k in flag_chars:
    state.solver.add(k < 0x7f)
    state.solver.add(k > 0x20)

simgr = proj.factory.simulation_manager(state)
simgr.use_technique(angr.exploration_techniques.DFS())
simgr.explore(find=FIND)
print(simgr.found[0].posix.dumps(0))
print(time.time() - t, "seconds")
```

_angr_ will use `0x400000` as a base if binary PIE (and it is), so add `0x400000` to the address we're looking for.

Next, just set `input_len` to `16` and setup constraints for printable ASCII only, and run it:

```bash
# ./sol.py
WARNING | 2020-09-28 01:19:42,878 | cle.loader | The main binary is a position-independent executable. It is being loaded with a base address of 0x400000.
Entry: 0x4012d0
WARNING | 2020-09-28 01:19:43,913 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2020-09-28 01:19:43,913 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2020-09-28 01:19:43,913 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state
WARNING | 2020-09-28 01:19:43,913 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2020-09-28 01:19:43,913 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.
WARNING | 2020-09-28 01:19:43,914 | angr.state_plugins.symbolic_memory | Filling memory at 0x7fffffffffefff8 with 72 unconstrained bytes referenced from 0x500018 (strlen+0x0 in extern-address space (0x18))
WARNING | 2020-09-28 01:19:43,914 | angr.state_plugins.symbolic_memory | Filling memory at 0x7fffffffffeff70 with 8 unconstrained bytes referenced from 0x500018 (strlen+0x0 in extern-address space (0x18))
b'n0_5ymb0l1c,3x30'
1.8037035465240479 seconds
```

Flag: `darkCTF{n0_5ymb0l1c,3x30}`