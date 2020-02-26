# BSidesSF 2020 CTF

## mentalist

> Can you read the mind of a computer?
> 
> mentalist-a05ae893.challenges.bsidessf.net:12345
> 
> (author: symmetric)

Tags: _crypto_

### Research

```
$ nc mentalist-a05ae893.challenges.bsidessf.net 12345
```

Output:

```
                                         ____
                                       .'* *.'
                                    __/_*_*(_
                                   / _______ \
                                  _\_)/___\(_/_
                                 / _((\- -/))_ \
                                 \ \())(-)(()/ /
                                  ' \(((()))/ '
                                 / ' \)).))/ ' \
                                / _ \ - | - /_  \
                               (   ( .;''';. .'  )
                               _\"__ / HA )\ __"/_
                                 \/  \  CK /  \/
                                  .'  '...' ' )
                                   / /  |  \ \
                                  / .   .   . \
                                 /   .     .   \
                                /   /   |   \   \
                              .'   /    .    '.  '.
                          _.-'    /     ..     '-. '-._
                      _.-'       |      ...       '-.  '-.
                     (___________\____......'________)____)
 _  _ ____ __   ___ __  _  _ ___    ___ _  _  __  ___ ___ __ _    __  __ _ ___
/ )( (  __|  ) / __)  \( \/ | __)  / __) )( \/  \/ __| __|  ( \  /  \(  ( ( __)
\ /\ /) _)/ (_( (_(  O ) \/ \)_)  ( (__) __ (  O )__ \)_)/    / (  O )    /)_)
(_/\_|____)___/\___)__/\_)(_(___)  \___)_)(_/\__/(___(___)_)__)  \__/\_)__|___)

Welcome Chosen One! I have been waiting for you...
The legend fortold of one that could read minds.
If you can read my mind I will reveal my great knowledge.

What number am I thinking of?
```

I never get tired of this ASCII art.

Alright, I'll play:

```
What number am I thinking of? 1
Actually I was thinking of 92418533065569, try again
What number am I thinking of? 1
No I'm sorry, I was thinking of 1639107449626
What number am I thinking of? 1
Hmmm no. My number was 13035510828923, are you sure you're okay?
What number am I thinking of? 1
I'm getting worried. I was thinking of 78961393252260; you're not doing so well.
What number am I thinking of? 1
I grow tired of your failures. My number was 17151971218837
What number am I thinking of? 1
Nope. 38272744573454 Perhaps you aren't the one I was waiting for?
What number am I thinking of? 1
WRONG! It was 75790045315311
What number am I thinking of? 1
My patience thins... 14100212471608 was my number
What number am I thinking of? 1
You're getting on my nerves. It was 16465280978345
What number am I thinking of? 1
I'm only going to give you one more chance. I was thinking of 54496558503522
```

Assuming this is a [pseudorandom number generator](https://en.wikipedia.org/wiki/Pseudorandom_number_generator) (PRNG), and I hope something like _n<sub>1</sub> = n<sub>0</sub> * a + b mod c_, which is quite common and something I've used before.

Moving on...

```
What number am I thinking of? 1
I see now that you aren't who I was looking for.
It's too late now but I was thinking of 36477286313539
In case you were wondering how I was thinking of these numbers,
they were for the form x_n+1 = x_n * 39885462937321 + 8746786088977 % 99806514007200
And my initial seed x_0 was 70079043211952
With this you can verify that I wasn't cheating.
Good luck in your future endeavors!
```

_The Mentalist_ just got annoyed and gave up the secret, and, _it is_, in the form _n<sub>1</sub> = n<sub>0</sub> * a + b mod c_.

#### Actual Research

Google for _cracking prng python_.

3rd hit (your results may vary, you know, Google spying on you, ...):

[https://tailcall.net/blog/cracking-randomness-lcgs/](https://tailcall.net/blog/cracking-randomness-lcgs/)

Yep, take the code and run...

> This is a _very_ good article, and I encourage you to read it.  There is no point duplicating it here.

#### PoC||GTFO

> The code from the URL didn't work right out of the box with Python 2 or 3--I made a few minor changes:

```
#!/usr/bin/env python3

from math import gcd
from functools import reduce

def crack_unknown_increment(states, modulus, multiplier):
    increment = (states[1] - states[0]*multiplier) % modulus
    return modulus, multiplier, increment

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, x, y = egcd(b % a, a)
        return (g, y - (b // a) * x, x)

def modinv(b, n):
    g, x, _ = egcd(b, n)
    if g != 1:
        raise Exception('oops')
    else:
        return x % n

def crack_unknown_multiplier(states, modulus):
    multiplier = (states[2] - states[1]) * modinv(states[1] - states[0], modulus) % modulus
    return crack_unknown_increment(states, modulus, multiplier)

def crack_unknown_modulus(states):
    diffs = [s1 - s0 for s0, s1 in zip(states, states[1:])]
    zeroes = [t2*t0 - t1*t1 for t0, t1, t2 in zip(diffs, diffs[1:], diffs[2:])]
    modulus = abs(reduce(gcd, zeroes))
    return crack_unknown_multiplier(states, modulus)

numbers = [92418533065569,1639107449626,13035510828923,78961393252260,17151971218837,38272744573454,75790045315311,14100212471608,16465280978345]

p, m, i = crack_unknown_modulus(numbers[1:7])

print((numbers[-1] * m + i) % p)
```

This code is pretty much a cut/paste job from the article with a few changes for Python 3.  All that was left to do was collect some numbers from _The Mentalist_ previous run and see if this code could predict the next number.

Output:

```
54496558503522
```

Yep! (See for yourself (above)).

### Solve

Ok Mentalist, you're mine now:

```
$ nc mentalist-a05ae893.challenges.bsidessf.net 12345

                                         ____
                                       .'* *.'
                                    __/_*_*(_
                                   / _______ \
                                  _\_)/___\(_/_
                                 / _((\- -/))_ \
                                 \ \())(-)(()/ /
                                  ' \(((()))/ '
                                 / ' \)).))/ ' \
                                / _ \ - | - /_  \
                               (   ( .;''';. .'  )
                               _\"__ / HA )\ __"/_
                                 \/  \  CK /  \/
                                  .'  '...' ' )
                                   / /  |  \ \
                                  / .   .   . \
                                 /   .     .   \
                                /   /   |   \   \
                              .'   /    .    '.  '.
                          _.-'    /     ..     '-. '-._
                      _.-'       |      ...       '-.  '-.
                     (___________\____......'________)____)
 _  _ ____ __   ___ __  _  _ ___    ___ _  _  __  ___ ___ __ _    __  __ _ ___
/ )( (  __|  ) / __)  \( \/ | __)  / __) )( \/  \/ __| __|  ( \  /  \(  ( ( __)
\ /\ /) _)/ (_( (_(  O ) \/ \)_)  ( (__) __ (  O )__ \)_)/    / (  O )    /)_)
(_/\_|____)___/\___)__/\_)(_(___)  \___)_)(_/\__/(___(___)_)__)  \__/\_)__|___)

Welcome Chosen One! I have been waiting for you...
The legend fortold of one that could read minds.
If you can read my mind I will reveal my great knowledge.

What number am I thinking of? 1
Actually I was thinking of 37804865295138, try again
What number am I thinking of? 1
No I'm sorry, I was thinking of 1600201343597
What number am I thinking of? 1
Hmmm no. My number was 31538457104926, are you sure you're okay?
What number am I thinking of? 1
I'm getting worried. I was thinking of 15197976081975; you're not doing so well.
What number am I thinking of? 1
I grow tired of your failures. My number was 24516768769094
What number am I thinking of? 1
Nope. 31441161868633 Perhaps you aren't the one I was waiting for?
What number am I thinking of? 1
WRONG! It was 6355112023692
```

From the _learning_ attempt we know that we get 10 tries before he gives up on us, so I just went for the first 7 and updated `solve.py` with:

```
numbers = [37804865295138,1600201343597,31538457104926,15197976081975,24516768769094,31441161868633,6355112023692
```

then ran it.  Output:

```
16509519550871
```

Back to _The Mentalist_:

```
What number am I thinking of? 16509519550871
Incredible! I WAS thinking of that number! But can you do it again?
```

Doh!! Really?

Ok, just update `solve.py`, add `16509519550871` to the end of `numbers`, and run again, output:

```
18227010560020
```

Here you go _Mentalist_:

```
What number am I thinking of? 18227010560020
You really are the one that was foretold. Please accept this knowldege:
CTF{rand_should_be_enough_for_anyone}
```

Flag: `CTF{rand_should_be_enough_for_anyone}`

> First to solve :-)
