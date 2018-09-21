import base64
import string
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
	Cipher, algorithms, modes
)
from cryptography.hazmat.primitives import padding

def hex_to_base64(hexstr):
	return base64.b64encode(hexstr.decode('hex'))

def xor_hexstr(hstr1, hstr2):
	bin1 = hstr1.decode('hex')
	bin2 = hstr2.decode('hex')
	return ''.join([chr(ord(a) ^ ord(b)).encode('hex') for a,b in zip(bin1,bin2)])

def repeating_xor(data, key):
	return ''.join([chr(ord(c) ^ ord(key[i % len(key)])) for i,c in enumerate(data)])

def score_text(text):
	score = 0
	for c in text:
		if c.upper() in "ETAOIN":
			score += 5
		elif c.upper() in "SHRDLU":
			score += 3
		elif c.upper() in string.uppercase:
			score += 1
		elif c in "\x00*":
			score -= 2
		elif ord(c) > 0x80:
			score -= 5
	return score

def break_single_xor(xorbin):
	best = 0
	key = None
	for i in range(255):
		attempt = repeating_xor(xorbin, chr(i))
		score = score_text(attempt)
		if score > best:
			best = score
			key = chr(i)
	return key

def detect_single_xor(xorbin_list):
	best = 0
	text = None
	for xorbin in xorbin_list:
		for i in range(255):
			attempt = repeating_xor(xorbin, chr(i))
			score = score_text(attempt)
			if score > best:
				best = score
				text = xorbin
	return text

def hamming(str1, str2):
	distance = 0
	for a,b in zip(str1, str2):
		res = ord(a) ^ ord(b)
		for i in range(8):
			distance += (res >> i) & 1
	return distance

def break_repeating_xor(ctext):
	distances = {}
	for keysize in range(2,41):
		blocks = [ctext[i:i+keysize] for i in range(0, keysize*4, keysize)]
		distances[keysize] = (hamming(blocks[0], blocks[1]) +
		                      hamming(blocks[0], blocks[2]) +
		                      hamming(blocks[0], blocks[3]) +
		                      hamming(blocks[1], blocks[2]) +
		                      hamming(blocks[1], blocks[3]) +
		                      hamming(blocks[2], blocks[3])
		                     ) / (6.0 * keysize)
		#d[0] = hamming(ctext[0:keysize], ctext[keysize:2*keysize])
		#d[1] = hamming(ctext[keysize*2:keysize*3], ctext[keysize*3:keysize*4]) / float(keysize)
		#d[2] = hamming(ctext[keysize*4:keysize*5], ctext[keysize*5:keysize*6])
		#print "%d:, %.2f, %.2f, %.2f, %.2f" % (keysize, d[0], d[1], d[2], sum(d) / 3)
		#distances[keysize] = sum(d) / 3
		#print "%d: %.2f" % (keysize, distances[keysize])
	working_keysize = 0
	score = 10 # max is mathematically 8 so
	for keysize in distances:
		if distances[keysize] < score:
			score = distances[keysize]
			working_keysize = keysize
		#print "%d: %.3f" % (keysize, distances[keysize])
	#print "Proceeding with %d as keysize" % working_keysize
	blocks = [ctext[i:i+working_keysize] for i in range(0, len(ctext), working_keysize)]
	blocks[-1] += (working_keysize - len(blocks[-1])) * "A" # adhoc padding
	#for b in blocks: print(repr(b))
	transposed = [''.join(block[i] for block in blocks) for i in range(working_keysize)]
	#for t in transposed: 
	#	print(repr(t))
	key = ''.join(map(break_single_xor, transposed))
	return key
	#print repeating_xor(ctext, key)

def aes_ecb_encrypt(plaintext, key):
	padder = padding.PKCS7(128).padder()
	padded_data = padder.update(plaintext) + padder.finalize()
	cryptor = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend()).encryptor()
	return cryptor.update(padded_data) + cryptor.finalize()

def aes_ecb_decrypt(ciphertext, key):
	unpadder = padding.PKCS7(128).unpadder()
	cryptor = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend()).decryptor()
	padded_plaintext = cryptor.update(ciphertext) + cryptor.finalize()
	return unpadder.update(padded_plaintext) + unpadder.finalize()

def detect_ecb(ctext_list):
	best = 0
	ecb_text = None
	for ctext in ctext_list:
		blocks = [ctext[i:i+16] for i in range(0, len(ctext), 16)]
		uniq_blocks = set(blocks)
		score = len(blocks) - len(uniq_blocks)
		if score > best:
			best = score
			ecb_text = ctext
	return ecb_text