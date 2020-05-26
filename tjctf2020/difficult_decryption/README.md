# TJCTF 2020

## Difficult Decryption

> 100
>
> We intercepted some communication between two VERY important people, named Alice and Bob. Can you figure out what the encoded message is?
>
> Written by saisree
> 
> [intercepted.txt](intercepted.txt)

Tags: _crypto_ _discrete-log_


## Summary

Weak crypto, nothing more than a discrete log solve.


## Analysis

From [intercepted.txt](intercepted.txt):

```
Alice:

Modulus: 491988559103692092263984889813697016406
Base: 5
Base ^ A % Modulus: 232042342203461569340683568996607232345
-----
Bob:

Here's my Base ^ B % Modulus: 76405255723702450233149901853450417505
-----
Alice:

Here's the encoded message:
12259991521844666821961395299843462461536060465691388049371797540470

I encoded it using this Python command:

message ^ (pow(your_key, A,modulus))

Your_key is Base ^ B % Modulus.
After you decode the message, it will be a decimal number. Convert it to hex.
You know what to do after that.
```

To decrypt, just provide `A` to `message ^ (pow(your_key, A,
modulus))` where `your_key` is provided from Bob as `76405255723702450233149901853450417505`.

To get `A`, just use your favorite discrete log function.


## Solve

```python
#!/usr/bin/python3

from sympy.ntheory.residue_ntheory import discrete_log

M=491988559103692092263984889813697016406
P=232042342203461569340683568996607232345
B=5
A=discrete_log(M,P,B)
message = 12259991521844666821961395299843462461536060465691388049371797540470
bobkey = 76405255723702450233149901853450417505

text = bytes.fromhex(hex(pow(bobkey, A, M) ^ message)[2:]).decode('ASCII')
print(text)
```

One-liner, if you're into brevity:

```
python3 -c "print(bytes.fromhex(hex(pow(76405255723702450233149901853450417505,__import__('sympy.ntheory.residue_ntheory').discrete_log(491988559103692092263984889813697016406,232042342203461569340683568996607232345,5),491988559103692092263984889813697016406) ^ 12259991521844666821961395299843462461536060465691388049371797540470)[2:]).decode('ASCII'))"
```

This runs in less than one second and outputs:

```
tjctf{Ali3ns_1iv3_am0ng_us!}
```