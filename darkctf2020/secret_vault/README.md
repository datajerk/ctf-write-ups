# DarkCTF 2020

## linux/secret vault

> 63 solves / 446 points
>
> Author: Wolfy
>
> There's a vault hidden find it and retrieve the information. Note: Do not use any automated tools.
>
> `ssh ctf@vault.darkarmy.xyz -p 10000`
>
> Alternate: `ssh ctf@13.126.135.177 -p 10000 password: wolfie`

Tags: _linux_ _rev_


## Session

```bash
# ssh ctf@vault.darkarmy.xyz -p 10000
The authenticity of host '[vault.darkarmy.xyz]:10000 ([23.101.25.254]:10000)' can't be established.
ECDSA key fingerprint is SHA256:MS7Zz6kEilIJH832qKHwAiXH0iYqRUeAFpLNL4kejkA.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[vault.darkarmy.xyz]:10000,[23.101.25.254]:10000' (ECDSA) to the list of known hosts.
  ___           _      _
 |   \ __ _ _ _| |__  /_\  _ _ _ __ _  _
 | |) / _` | '_| / / / _ \| '_| '  \ || |
 |___/\__,_|_| |_\_\/_/ \_\_| |_|_|_\_, |
                                    |__/
ctf@vault.darkarmy.xyz's password:
DISCLAIMER: Please don't abuse the server !

These Tasks were done to practice some Linux

Author: wolfie, Contact me for any problems


** Please wait a little! Wolfie cooking the environment for you! Have Fun **

dark@491454fa2b59:/home/dark$ find / -name "*vault*" -print 2>/dev/null
/home/.secretdoor/vault

dark@491454fa2b59:/home/dark$ /home/.secretdoor/vault

wrong pin: (null)

dark@491454fa2b59:/home/dark$ /home/.secretdoor/vault 1234

wrong pin: 1234
```

At this point I should have just looped all 4 digit numbers, but pins can be longer so I opted to exfiltrate and work with it offline.  For me, just as easy.

There was no `base64`, `strings`, `hexdump`, etc... to make this easier, but `od` was left behind (I was already on the system, might as well just grab it):

```bash
dark@491454fa2b59:/home/dark$ od -v -t x1 /home/.secretdoor/vault
```

Output:

```
0000000 7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
0000020 03 00 3e 00 01 00 00 00 70 10 00 00 00 00 00 00
0000040 40 00 00 00 00 00 00 00 c0 39 00 00 00 00 00 00
0000060 00 00 00 00 40 00 38 00 0b 00 40 00 1e 00 1d 00
...
```

After buffer cut/paste, run locally:

```
cat vault.hex | sed 's/^........//' | tr '\n' ' ' | xxd -r -p >vault
```

Then decompile with Ghidra:

```c
  local_c = 8000;
  local_10 = 600;
  local_14 = 200;
  local_18 = 6;
  local_1c = 0x225a;
  sprintf(local_26,"%d",0x225a);
  local_58 = 0x3f57366f4c393741;
  local_50 = 0x3168513b443b254f;
  local_48 = 0x5d706c304a62494e;
  local_40 = 0x29463b6f6e5e4623;
  local_38 = 0x2870216943397274;
  local_30 = 0x403729582b;
  local_28 = 0;
  if ((1 < param_1) && (iVar1 = strcmp(*(char **)(param_2 + 8),local_26), iVar1 == 0)) {
    printf("\nVault Unlocked :%s \n",&local_58);
    return 0;
  }
  printf("\nwrong pin: %s\n",*(undefined8 *)(param_2 + 8));
  return 0;
```

```
# echo $((0x225a))
8794
```

There's your pin.  You can run `strings` to get the secret, or just run `vault` locally:

```bash
# ./vault $((0x225a))

Vault Unlocked :A79Lo6W?O%;D;Qh1NIbJ0lp]#F^no;F)tr9Ci!p(+X)7@
```

Flag:

```bash
# python3 -c 'import base64; print(base64.a85decode("A79Lo6W?O%;D;Qh1NIbJ0lp]#F^no;F)tr9Ci"))'
b'darkCTF{R0bb3ry_1s_Succ3ssful'
```

