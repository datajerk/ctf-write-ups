# DawgCTF 2020

## Nash

> 150
>
> Welcome to Nash! It’s a NoSpaceBash! All you have to do is display the flag. It’s right there.
>
> `cat flag.txt`
>
> Oh yeah…you can’t use any spaces… Good luck!
>
> `nc ctf.umbccd.io 4600`
>
> Author: BlueStar

Tags: _pwn_ _shell_


### Solution

Easy...

```
nash> cat<flag.txt
DawgCTF{L1k3_H0W_gr3a+_R_sp@c3s_Th0uGh_0mg}
```

Then...

_[9:38 AM] trashcanna: @everyone We noticed an unintended solution in nash so now presenting nash version 2 electric boogaloo written by @quantumite of BlueStar!_


## Nash2

> 200
>
> It's nospacebash for real this time!
>
> `nc ctf.umbccd.io 5800`
>
> Author: BlueStar

### Solution

```
nash> FOO=$'\\x20flag.txt'&&cat$FOO
DawgCTF{n0_n0_eZ_r3d1r3ct10n_4_u_tR0LL$}
```

There's probably 100 ways to solve this.  This was the first that occurred to me.



