import base64

def hex_to_base64(hexstr):
	return base64.b64encode(hexstr.decode('hex'))

def xor_hexstr(hstr1, hstr2):
	bin1 = hstr1.decode('hex')
	bin2 = hstr2.decode('hex')
	return ''.join([chr(ord(a) ^ ord(b)).encode('hex') for a,b in zip(bin1,bin2)])