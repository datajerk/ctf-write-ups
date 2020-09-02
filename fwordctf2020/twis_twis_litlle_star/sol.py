#!/usr/bin/env python3

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

