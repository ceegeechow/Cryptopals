import binascii
import base64
from Crypto.Cipher import AES

#challenge1:
def hex_2_64(hex):
	hex_2_bin = ["0000", "0001", "0010", "0011", "0100", "0101", "0110", "0111", "1000", "1001", "1010", "1011", "1100", "1101", "1110", "1111"]
	dec_2_base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	bin_str = ""
	for c in hex:
		if ord(c) >= 48 and ord(c) <= 57:
			index = ord(c) - 48
		else:
			c = c.upper()
			index = ord(c) - 55;
		bin_str += hex_2_bin[index]

	base64 = ""
	for i in range(0, len(bin_str), 6):
		ind = int(bin_str[i:i+6],2)
		base64 += dec_2_base64[ind]

	return base64
	#return hex.encode('base64','strict');

# print(hex_2_64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))

#challenge2:
def xor(buf1, buf2):
	out = str.format(hex(int(buf1, 16) ^ int(buf2, 16)))
	return out[2:]

# print(xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"))

#challenge3:
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

# print(decrypt_xor("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))

#challenge4:
def detect_cipher(filename):
	file = open(filename)
	lines = file.readlines()
	max_score = 0
	ret = ""
	for line in lines:
		text, score = decrypt_xor(line)
		if score > max_score:
			ret = text
			max_score = score
	file.close()
	return ret

# print(detect_cipher("samput_4.txt"))

#challenge5:
def repeating_key_xor(text, key):
	ret = ""
	# text = ""
	# for line in open(filename):
	# 	text += line.rstrip('\n')
	key_index = 0
	for c in text:
		h = str.format(hex(ord(c)))
		k = str.format(hex(ord(key[key_index])))
		x = xor(h[2:], k[2:])
		if len(x) == 1:
			ret += "0"
		ret += x
		key_index += 1
		key_index %= len(key)

	return ret

# print(repeating_key_xor("input_5.txt", "ICE"))

#challenge6:
def hamming(str1, str2):
	hamming = 0
	for a, b in zip(str1, str2):
		for b in bin(ord(a)^ord(b)):
			if b == '1':
				hamming += 1
	return hamming

#print(hamming("this is a test", "wokka wokka!!!")) #37

def get_key(samp): 				#make better later
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
		# print(key_size, h)
	return KEY_SIZE

def break_rkx(filename):
	text = ""
	for line in open(filename):
		text += line.rstrip('\n')
	text = base64.b64decode(text).decode('ASCII')

	key_size = get_key(text)
	#key_size = 5

	blocks = [""]*(len(text)//key_size+1)
	index = 0

	for i in range(0, len(text), key_size):
		blocks[index] = text[i:i+key_size]
		index += 1

	blocks_t = [""]*key_size

	for i in range(len(text)//key_size):
		for j in range(key_size):
			blocks_t[j] += (blocks[i])[j]
	

	# #print(blocks_t)
	key = ""
	for block in blocks_t:
		#print("block: ", block)
		#print(str(binascii.hexlify(b'<block>')))
		#print(block)
		_, _, k = decrypt_xor(block.encode().hex())
		#print(bytes.fromhex(k))
		key += k
	
	return bytes.fromhex(key).decode()

key = break_rkx("input_6.txt")
print(key)

text = ""
for line in open("input_6.txt"):
	text += line.rstrip('\n')
text = base64.b64decode(text).decode('ASCII')
 
print(bytes.fromhex(repeating_key_xor(text, key)).decode())
