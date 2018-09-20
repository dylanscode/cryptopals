import unittest
import set1

class Set1(unittest.TestCase):

	def test_chal1(self):
		hexstr = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
		b64str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
		self.assertEqual(b64str, set1.hex_to_base64(hexstr))

	def test_chal2(self):
		hstr1 = "1c0111001f010100061a024b53535009181c"
		hstr2 = "686974207468652062756c6c277320657965"
		hout = "746865206b696420646f6e277420706c6179"
		self.assertEqual(hout, set1.xor_hexstr(hstr1, hstr2))

	def test_chal3(self):
		with open("secret/chal3.txt") as f:
			key = f.readline()
		ctext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".decode('hex')
		self.assertEqual(key, set1.break_single_xor(ctext))

	def test_chal5(self):
		data = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
		ctext = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f".decode('hex')
		self.assertEqual(ctext, set1.single_xor(data, "ICE"))
if __name__ == "__main__":
	unittest.main()