#!/usr/bin/env python

import sys
from z3 import *
from subprocess import Popen,PIPE,STDOUT

s = Solver()

flag_len=32

vec=""
for i in range(0,flag_len):
	vec += "flag[{}] ".format(i)

m = BitVecs(vec, 32)

# constraints

# check 1,2,3, skip


# check 4 row sum/xor

DAT_00400f40 = [
0x5e + 256 * 0x01,
0xda + 256 * 0x00,
0x2f + 256 * 0x01,
0x31 + 256 * 0x01,
0x00 + 256 * 0x01,
0x31 + 256 * 0x01,
0xfb + 256 * 0x00,
0x02 + 256 * 0x01
]

s.add(m[0]  +  m[1] +  m[2] +  m[3] == DAT_00400f40[0])
s.add(m[4]  +  m[5] +  m[6] +  m[7] == DAT_00400f40[1])
s.add(m[8]  +  m[9] + m[10] + m[11] == DAT_00400f40[2])
s.add(m[12] + m[13] + m[14] + m[15] == DAT_00400f40[3])
s.add(m[16] + m[17] + m[18] + m[19] == DAT_00400f40[4])
s.add(m[20] + m[21] + m[22] + m[23] == DAT_00400f40[5])
s.add(m[24] + m[25] + m[26] + m[27] == DAT_00400f40[6])
s.add(m[28] + m[29] + m[30] + m[31] == DAT_00400f40[7])

DAT_00400f60 = [ 0x52, 0x0c, 0x01, 0x0f, 0x5c, 0x05, 0x53, 0x58 ]

s.add(m[0]  ^  m[1] ^  m[2] ^  m[3] == DAT_00400f60[0])
s.add(m[4]  ^  m[5] ^  m[6] ^  m[7] == DAT_00400f60[1])
s.add(m[8]  ^  m[9] ^ m[10] ^ m[11] == DAT_00400f60[2])
s.add(m[12] ^ m[13] ^ m[14] ^ m[15] == DAT_00400f60[3])
s.add(m[16] ^ m[17] ^ m[18] ^ m[19] == DAT_00400f60[4])
s.add(m[20] ^ m[21] ^ m[22] ^ m[23] == DAT_00400f60[5])
s.add(m[24] ^ m[25] ^ m[26] ^ m[27] == DAT_00400f60[6])
s.add(m[28] ^ m[29] ^ m[30] ^ m[31] == DAT_00400f60[7])


# check 5 row sum/xor

DAT_00400fa0 = [
0x29 + 256 * 0x01,
0x03 + 256 * 0x01,
0x2b + 256 * 0x01,
0x31 + 256 * 0x01,
0x35 + 256 * 0x01,
0x0b + 256 * 0x01,
0xff + 256 * 0x00,
0xff + 256 * 0x00
]

s.add(m[0] +  m[8] + m[16] + m[24] == DAT_00400fa0[0])
s.add(m[1] +  m[9] + m[17] + m[25] == DAT_00400fa0[1])
s.add(m[2] + m[10] + m[18] + m[26] == DAT_00400fa0[2])
s.add(m[3] + m[11] + m[19] + m[27] == DAT_00400fa0[3])
s.add(m[4] + m[12] + m[20] + m[28] == DAT_00400fa0[4])
s.add(m[5] + m[13] + m[21] + m[29] == DAT_00400fa0[5])
s.add(m[6] + m[14] + m[22] + m[30] == DAT_00400fa0[6])
s.add(m[7] + m[15] + m[23] + m[31] == DAT_00400fa0[7])

DAT_00400f80 = [ 0x01, 0x57, 0x07, 0x0d, 0x0d, 0x53, 0x51, 0x51 ]

s.add(m[0] ^  m[8] ^ m[16] ^ m[24] == DAT_00400f80[0])
s.add(m[1] ^  m[9] ^ m[17] ^ m[25] == DAT_00400f80[1])
s.add(m[2] ^ m[10] ^ m[18] ^ m[26] == DAT_00400f80[2])
s.add(m[3] ^ m[11] ^ m[19] ^ m[27] == DAT_00400f80[3])
s.add(m[4] ^ m[12] ^ m[20] ^ m[28] == DAT_00400f80[4])
s.add(m[5] ^ m[13] ^ m[21] ^ m[29] == DAT_00400f80[5])
s.add(m[6] ^ m[14] ^ m[22] ^ m[30] == DAT_00400f80[6])
s.add(m[7] ^ m[15] ^ m[23] ^ m[31] == DAT_00400f80[7])


# check 6 is alpha or digit

def is_valid_alpha(x):
	return And(
		(x >= ord('a')),
		(x <= ord('f')))

def is_valid_digit(x):
	return And(
		(x >= ord('0')),
		(x <= ord('9')))

DAT_00400fc0 = [
0x80, 0x80, 0xff, 0x80, 0xff, 0xff, 0xff, 0xff,
0x80, 0xff, 0xff, 0x80, 0x80, 0xff, 0xff, 0x80,
0xff, 0xff, 0x80, 0xff, 0x80, 0x80, 0xff, 0xff,
0xff, 0xff, 0x80, 0xff, 0xff, 0xff, 0x80, 0xff
]

for i in range(0,flag_len):
	if DAT_00400fc0[i] == 0x80:
		s.add(is_valid_alpha(m[i]))
	else:
		s.add(is_valid_digit(m[i]))


# check 7 every other sum

s.add(m[0]+m[2]+m[4]+m[6]+m[8]+m[10]+m[12]+m[14]+m[16]+m[18]+m[20]+m[22]+m[24]+m[26]+m[28]+m[30] == 0x488)


# check 8 check:

s.add(m[0x25-6] == ord('5'))
s.add(m[0x07-6] == ord('f'))
s.add(m[0x0b-6] == ord('8'))
s.add(m[0x0c-6] == ord('7'))
s.add(m[0x17-6] == ord('2'))
s.add(m[0x1f-6] == ord('4'))


# finally, solve it

while s.check() == z3.sat:
	model = s.model()
	nope = []

	flag = 'TWCTF{'
	for i in m:
		if model[i] != None:
			flag+=chr(model[i].as_long()&0xff)
			nope.append(i!=model[i])
	flag+='}'

	print flag
	popen = Popen(["./easy_crack_me", flag],stderr=STDOUT,stdout=PIPE)
	output = popen.stdout.readline()
	if output.find('incorrect') == 0:
		popen.terminate()
		s.add(Or(nope))	# exclude from search
		continue

	print output
	break

