import collections
import base64
from Crypto.Cipher import AES

print("Challenge 1: Hex to Base64")
def hex_2_64(hex):
	return (base64.b64encode(bytes.fromhex(hex))).decode()

print(hex_2_64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
#shoud return SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

print("Challenge 2: XOR")
def xor(buf1, buf2):
	out = str(hex(int(buf1, 16) ^ int(buf2, 16)))
	return out[2:]

print(xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"))
#should return 746865206b696420646f6e277420706c6179

print("Challenge 3: Single Byte XOR Cipher")
def decrypt_xor(C):
	englishLetterFreq = {" ": 13, "E": 12.70, "T": 9.06, "A": 8.17, "O": 7.51, "I": 6.97, "N": 6.75, "S": 6.33, "H": 6.09, "R": 5.99, "D": 4.25, "L": 4.03, "C": 2.78, "U": 2.76, "M": 2.41, "W": 2.36, "F": 2.23, "G": 2.02, "Y": 1.97, "P": 1.93, "B": 1.29, "V": 0.98, "K": 0.77, "J": 0.15, "X": 0.15, "Q": 0.10, "Z": 0.07}
	ret = ""
	max_score = 0
	best_key = ""
	for i in range(0, 255):
		h = str(hex(i))
		if i < 16:
			k = "0" + h[2:]
		else:
			k = h[2:]
		key = k*(len(C)//2)
		P_hex = xor(C, key)
		P = ""
		score = 0
		for j in range(0, len(P_hex), 2):
			c = chr(int(P_hex[j:j+2], 16))
			P += c
			if (ord(c) >= 65 and ord(c) <= 90) or (ord(c) >= 97 and ord(c) <= 122) or ord(c) == 32:
				score += englishLetterFreq[c.upper()]
		if score > max_score:
			ret = P
			max_score = score
			best_key = k

	return ret, max_score, best_key

print(decrypt_xor("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))

print("Challenge 4: Detect XOR Cipher")
def detect_cipher(filename):
	file = open(filename)
	lines = file.readlines()
	max_score = 0
	ret = ""
	for line in lines:
		text, score, _ = decrypt_xor(line)
		if score > max_score:
			ret = text
			max_score = score
	file.close()
	return ret

print(detect_cipher("input_4.txt"))

print("Challenge 5: Repeating Key XOR Cipher")
def repeating_key_xor(text, key):
	ret = ""
	key_index = 0
	for c in text:
		h = str(hex(ord(c)))
		k = str(hex(ord(key[key_index])))
		x = xor(h[2:], k[2:])
		if len(x) == 1:
			ret += "0"
		ret += x
		key_index += 1
		key_index %= len(key)
	return ret

print(repeating_key_xor("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ICE"))
#should return 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
#a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f

print("Challenge 6: Break Repeating Key XOR Cipher")
def hamming(str1, str2):
	hamming = 0
	for a, b in zip(str1, str2):
		for b in bin(ord(a)^ord(b)):
			if b == '1':
				hamming += 1
	return hamming

print(hamming("this is a test", "wokka wokka!!!")) #shoud return 37

def get_key(samp):
	KEY_SIZE = 0
	min_ham = -1
	for key_size in range(2, 40):
		h1 = hamming(samp[:key_size], samp[key_size:key_size*2])/key_size
		h2 = hamming(samp[key_size*2:key_size*3], samp[key_size*3:key_size*4])/key_size
		h3 = hamming(samp[key_size*4:key_size*5], samp[key_size*5:key_size*6])/key_size
		h4 = hamming(samp[key_size*6:key_size*7], samp[key_size*7:key_size*8])/key_size
		h5 = hamming(samp[key_size*8:key_size*9], samp[key_size*9:key_size*10])/key_size
		h6 = hamming(samp[key_size*10:key_size*11], samp[key_size*11:key_size*12])/key_size
		h = (h1 + h2 + h3 + h4 + h5 + h6)/6
		if min_ham == -1 or h < min_ham:
			KEY_SIZE = key_size
			min_ham = h
	return KEY_SIZE

def break_rkx(filename):
	text = ""
	for line in open(filename):
		text += line.rstrip('\n')
	text = base64.b64decode(text).decode()

	key_size = get_key(text)

	blocks = [""]*(len(text)//key_size+1)
	index = 0

	for i in range(0, len(text), key_size):
		blocks[index] = text[i:i+key_size]
		index += 1

	blocks_t = [""]*key_size

	for i in range(len(text)//key_size):
		for j in range(key_size):
			blocks_t[j] += (blocks[i])[j]
	
	key = ""
	for block in blocks_t:
		_, _, k = decrypt_xor(block.encode().hex())
		key += k	
	return bytes.fromhex(key).decode()

key = break_rkx("input_6.txt")
print(key)

text = ""
for line in open("input_6.txt"):
	text += line.rstrip('\n')
text = base64.b64decode(text).decode()
 
print(bytes.fromhex(repeating_key_xor(text, key)).decode())

print("Challenge 7: AES in ECB mode")
def breakAES(filename):
	text = ""
	for line in open(filename):
		text += line.rstrip('\n')

	text = base64.b64decode(text)
	key = "YELLOW SUBMARINE"

	aes = AES.new(key, AES.MODE_ECB)
	return aes.decrypt(text).decode()

print(breakAES("input_7.txt"))

print("Challenge 8: Detect AES in ECB mode")
def detect_ECB(filename):
	ECB_line = ""
	max_freq = 0
	for line in open(filename):
		chunks = [line[i:i+32] for i in range(0, len(line), 32)] #16???
		d = collections.defaultdict(int)
		for chunk in chunks:
			d[chunk] += 1
			freq = max(d.values())
			if freq > max_freq:
				ECB_line = line
				max_freq = freq
	return ECB_line

print(detect_ECB("input_8.txt"))