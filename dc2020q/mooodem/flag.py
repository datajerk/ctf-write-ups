#!/usr/bin/python3 

from pwn import *
import os

def getsome(filename,p,n,d):
	c = 0
	if os.path.exists(filename):
		os.remove(filename)
	f = open(filename,'wb+')
	while c < n:
		_ = p.recv(4096)
		c += len(_)
		f.write(_)
		print('.',end='')
		if d == 1:
			print(c, len(_))
	print()
	f.close()
	return

p = remote('mooodem.challenges.ooo', 5000)


'''
./payload.py
cat payload.bin | minimodem -t -8 -f in1.wav 1200
./wav2bin in1.wav in1.bin
'''

r = open('in1.bin','rb').read()
p.send(r)

getsome('out1.bin',p,15282112,0)
os.system('./bin2wav out1.bin out1.wav; minimodem -r -8 -f out1.wav 1200')

