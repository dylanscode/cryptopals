import base64

def hex_to_base64(hexstr):
	return base64.b64encode(hexstr.decode('hex'))

def xor_hexstr(hstr1, hstr2):
	bin1 = hstr1.decode('hex')
	bin2 = hstr2.decode('hex')
	return ''.join([chr(ord(a) ^ ord(b)).encode('hex') for a,b in zip(bin1,bin2)])

def single_xor(data, key):
	return ''.join([chr(ord(a) ^ key) for a in data])

def break_single_xor(xorbin):
	best = 0
	key = None
	for i in range(255):
		attempt = single_xor(xorbin, i)
		score = 0
		for c in attempt:
			if c.upper() in "ETAOIN":
				score += 2
			elif c.upper() in "SHRDLU":
				score += 1
		if score > best:
			best = score
			key = chr(i)
	return key