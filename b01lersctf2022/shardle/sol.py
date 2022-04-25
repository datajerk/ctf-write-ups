#!/usr/bin/env python

from pwn import *
import re
from Crypto.Hash import SHA256

startword = 'blah'
flag = b'bctf{'
dictlist = 'dict3'

if not os.path.exists(dictlist):
	wordlist = 'words2.txt'
	if not os.path.exists(wordlist):
		print(
		'''
run this, then try again:

apt-get install wamerican-insane
cat /usr/share/dict/american-english-insane | grep -v '[^[:lower:]]' | sort -u >words2.txt
		''')
		sys.exit(1)

	f = open(wordlist,'r')
	o = open(dictlist,'w')

	for i in f:
		word = i.strip().lower()
		h = SHA256.new()
		h.update(word.encode())
		o.write(h.hexdigest() + ' ' + word + '\n')

	f.close()
	o.close()

def guess(g):
	_ = p.recvuntil([flag, b'choose: '])
	if flag in _: return None, -1
	print('\nguess:',g)
	p.sendline(b'1')
	p.sendlineafter(b'guess: ',g.encode())
	_ = p.recvuntil([b'INVALID GUESS',b'score: '])
	if b'INVALID GUESS' in _: return None, 0

	_ = p.recvline().strip().decode()
	_ = _.replace('\033[42m','>')
	_ = _.replace('\033[40m','')
	_ = _.replace('\033[43m','')
	_ = _.replace('\033[0m','')

	if '>' not in _: return None, 0
	pos = []
	last = 0
	while '>' in _:
		last = _.find('>',last)
		pos += [last]
		_ = _.replace('>','',1)

	print(_)

	if len(pos) == 64: return None, len(pos)

	s = 64 * ['.']
	for i in pos: s[i] = _[i]
	s = ''.join(s)

	print(s)

	s = '^' + s + ' '
	f = open(dictlist,'r')
	r = []
	for i in f:
		if re.search(s,i):
			w = i.strip().split()[1]
			if w != g: r += [w]
	f.close()

	print('number of partial sha word matches: {x}'.format(x = len(r)))
	print(r) if len(r) < 20 else print('word list too long [to print]')
	print(len(pos))

	return r, len(pos)

def solve(words,guesses,usedwords):
	for i in words:
		if i in usedwords: continue
		guesses -= 1
		(r, m) = guess(i)
		if m == -1: return 1, guesses, usedwords
		if m == 64:
			log.info('word: {x}'.format(x = i))
			usedwords = []
			r = [startword]
		if guesses < 1:
			log.critical('out of guesses')
			return 0, guesses, usedwords
		if r == None:
			log.info('got none')
			continue
		if r == []:
			log.info('got empty set')
			continue
		break

	if r is not None and len(r) > 0:
		(ret, guesses, usedwords) =  solve(r,guesses,usedwords)
		if ret: return 1, guesses, usedwords

	return 0, guesses, usedwords

while True:
	p = remote('ctf.b01lers.com', 9102)
	(ret, guesses, usedwords) = solve([startword],15,[])
	if ret: break
	p.close()

flag += p.recvuntil(b'}')
p.close()
print()
print(flag.decode())
print()
