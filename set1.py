import base64
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

def single_xor(data, key):
	return ''.join([chr(ord(c) ^ ord(key[i % len(key)])) for i,c in enumerate(data)])

def break_single_xor(xorbin):
	best = 0
	key = None
	for i in range(255):
		attempt = single_xor(xorbin, chr(i))
		score = 0
		for c in attempt:
			if c.upper() in "ETAOIN":
				score += 2
			elif c.upper() in "SHRDLU":
				score += 1
			elif c in "\x00*":
				score -= 4
		if score > best:
			best = score
			key = chr(i)
	return key

def detect_single_xor(xorbin_list):
	best = 0
	text = None
	for xorbin in xorbin_list:
		for i in range(255):
			attempt = single_xor(xorbin, chr(i))
			score = 0
			for c in attempt:
				if c.upper() in "ETAOIN":
					score += 2
				elif c.upper() in "SHRDLU":
					score += 1
				elif c in "\x00*":
					score -= 4
			if score > best:
				best = score
				text = xorbin
	return text

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