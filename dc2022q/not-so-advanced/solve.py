#!/usr/bin/env python3

from itertools import product

for i in product('abcdefghijklmnopqrstuvwxyz_', repeat = 9):
	local_12 = 1
	local_14 = 0
	for j in i:
		local_12 += ord(j)
		local_14 += local_12
	if local_12 ^ local_14 == 0x12e1:
		print(''.join(i))
		break
