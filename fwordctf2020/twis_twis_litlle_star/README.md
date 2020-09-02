# FwordCTF 2020

## Twis Twis Litlle Star

>  470
>
> Randomness is a power ! You don't have a chance to face it.
>
> `nc twistwislittlestar.fword.wtf 4445`
>
> Author: Semah BA

Tags: _misc_


## Summary

```
Welcome Everyone to our Land !!
The good thing about Randomness that it is unpredictable !
Unless you say otherwise , prouve me wrong and predict 20 consecutive randoms!

Random Number is : 959406118
Random Number is : 2452355895
Random Number is : 3891904161

Can you predict the next ones ?
Your Prediction For the next one :
```

_Twis Twis_ was the hint, and if you google for _mersenne twister predictor_, your first hit will be the [Predict MT19937 PRNG](https://github.com/kmyk/mersenne-twister-predictor) project.

Just follow the instructions, harvest 624 "random" numbers, and supply 20 predictions to get the flag.


## Solve

```
!/usr/bin/env python3

from pwn import *
import random
from mt19937predictor import MT19937Predictor

max_n = 624
predictor = MT19937Predictor()

p = remote('twistwislittlestar.fword.wtf',4445)
context.log_level = 'INFO'
context.log_file = 'log.log'

p.recvuntil('Random Number is : ')
predictor.setrandbits(int(p.recvline().strip()),32)
p.recvuntil('Random Number is : ')
predictor.setrandbits(int(p.recvline().strip()),32)
p.recvuntil('Random Number is : ')
predictor.setrandbits(int(p.recvline().strip()),32)

for i in range(3,max_n):
    log.info('learning ' + str(i))
    p.recvuntil('Your Prediction For the next one : ')
    p.sendline('1')
    p.recvuntil('The number was : ')
    predictor.setrandbits(int(p.recvline().strip()),32)

while True:
    log.info('predicting ' + str(i))
    i += 1
    _ = p.recvuntil(['FwordCTF','Your Prediction For the next one : '])
    if b'FwordCTF' in _:
        flag = _ + p.recvuntil('}')
        log.info('flag: ' + flag.decode())
        break
    p.sendline(str(predictor.getrandbits(32)))
```

Final output:

```
Well you prouved me wrong , After all every thing is crackable !!
Take your flag
FwordCTF{R4nd0m_isnT_R4nd0m_4ft3r_4LL_!_Everyhthing_is_predict4bl3_1f_y0u_kn0w_wh4t_Y0u_d01nGGGG}
```
