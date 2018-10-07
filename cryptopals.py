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
	return ret, max_score

# print(decrypt_xor("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))

#challenge4:
def detect_cipher(filename):
	file = open(filename, "r+")
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

# print(detect_cipher("input.txt"))

#challenge5:
def repeating_key_xor(text, key):
	ret = ""
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

print(repeating_key_xor("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ICE"))
# c = "B"
# key = "I"
# h = str.format(hex(ord(c)))
# k = str.format(hex(ord(key)))

# print(h, k, xor(h[2:],k[2:]))