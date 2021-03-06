# BSidesSF 2020 CTF

## eccmul

> Never done ECC before? Now you can!
>
> eccmul-3e426cd0.challenges.bsidessf.net:25519
>
> (author: symmetric)

Tags: _crypto_ _ecc_

### Analysis

```
$ nc eccmul-3e426cd0.challenges.bsidessf.net 25519
```

Output:

```
Elite                                   |                               *     .
Crypto                                  |                              *   .
Club                                    |                            *  .
                                        |                          **.
                                        |                         *R'
                                        |                      . *`
                                        |                   .  *  `
                                *       |                .   **   `
                          * **     **   |             .     *     `
                       **               **         .     **       `
                    *                   |  **   .     **          `
                  **                    |    . *Q   *             `
                 *                      | .                       `
                *                      .|                         `
                *                   .   |                         `
                *                .      |                         `
------------------------------.-----------------------------------`-------------
                *          .            |                         `
                *       .               |                         `
                 *   .                  |                         `
                 *.                     |                         `
               .  P*                    |       *  *              `
            .       **                  |  *           **         `
         .             ***             **                 *       `
      .                      *   * *    |                   *     `
   .                                    |                     *   `
.                                       |                      ** `
                                        |                        *`
                                        |                         `*R
                                        |                           *
                                        |                             *
                                        |                               *

Curve Generated: y^2 = x^3 + 2557469063*x + 3368387639 mod 14976980263601993881
Point `P` on curve: [2342304216201758750,762803873429369431]
Scalar `s`: 6921481148
Please compute `R` = `s*P`

R? (enter in form [1234,5678])>
```

ASCII!  Cool!

Clearly all we have to do is compute _s*P_.  But how?

#### Research

Read: [Elliptic-curve cryptography](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography)

Nice, but not really helpful, how about Googling for _ecc scalar multiplication python_.

First hit (your results may vary, you know, Google spying on you, ...):

[https://crypto.stackexchange.com/questions/11743/scalar-multiplication-on-elliptic-curves](https://crypto.stackexchange.com/questions/11743/scalar-multiplication-on-elliptic-curves)

Yep, take the code and run...

### Solve

```
# Extended Euclidean algorithm
def extended_gcd(aa, bb):
   lastremainder, remainder = abs(aa), abs(bb)
   x, lastx, y, lasty = 0, 1, 1, 0
   while remainder:
       lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
       x, lastx = lastx - quotient*x, x
       y, lasty = lasty - quotient*y, y
   return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)
# calculate `modular inverse`
def modinv(a, m):
   g, x, y = extended_gcd(a, m)
   if g != 1:
       raise ValueError
   return x % m

# double function
def ecc_double(x1, y1, p, a):
   s = ((3*(x1**2) + a) * modinv(2*y1, p))%p
   x3 = (s**2 - x1 - x1)%p
   y3 = (s*(x1-x3) - y1)%p
   return (x3, y3)
# add function
def ecc_add(x1, y1, x2, y2, p, a):
   s = 0
   if (x1==x2):
       s = ((3*(x1**2) + a) * modinv(2*y1, p))%p
   else:
       s = ((y2-y1) * modinv(x2-x1, p))%p
   x3 = (s**2 - x1 - x2)%p
   y3 = (s*(x1 - x3) - y1)%p
   return (x3, y3)
def double_and_add(multi, generator, p, a):
   (x3, y3)=(0, 0)
   (x1, y1) = generator
   (x_tmp, y_tmp) = generator
   init = 0
   for i in str(bin(multi)[2:]):
       if (i=='1') and (init==0):
          init = 1
       elif (i=='1') and (init==1):
          (x3,y3) = ecc_double(x_tmp, y_tmp, p, a)
          (x3,y3) = ecc_add(x1, y1, x3, y3, p, a)
          (x_tmp, y_tmp) = (x3, y3)
       else:
          (x3, y3) = ecc_double(x_tmp, y_tmp, p, a)
          (x_tmp, y_tmp) = (x3, y3)
   return (x3, y3)
```

Append the following based on the challenge output _Curve Generated: y^2 = x^3 + 2557469063*x + 3368387639 mod 14976980263601993881_, _Point `P` on curve: [2342304216201758750,762803873429369431]_, and _Scalar `s`: 6921481148_:

```
p = 14976980263601993881
a = 2557469063
b = 3368387639
generator=(2342304216201758750, 762803873429369431)
print("6921481148*P = ", double_and_add(6921481148, generator, p, a))
```

Run.  Output:

```
6921481148*P =  (6167228802628474017, 9577545602002795282)
```

Get the flag:

```
R? (enter in form [1234,5678])> [6167228802628474017,9577545602002795282]
Great!
CTF{babys_first_scalar_multiplication}
```

Flag: `CTF{babys_first_scalar_multiplication}`
