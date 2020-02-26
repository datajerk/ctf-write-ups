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

#numbers = [92418533065569,1639107449626,13035510828923,78961393252260,17151971218837,38272744573454,75790045315311,14100212471608,16465280978345]
numbers = [37804865295138,1600201343597,31538457104926,15197976081975,24516768769094,31441161868633,6355112023692,16509519550871]

p, m, i = crack_unknown_modulus(numbers[1:7])

print((numbers[-1] * m + i) % p)
