//Cryptopals challenge set #1
//Camille Chow
//ECE 445

#include <string>
#include <iostream>
#include <vector>
#include <bitset>
using namespace std;

//Challenge 1: Convert hex to base64
string hex2b64(string hex) {
	int sizeH = hex.length();

	string hex_2_bin[16] = { "0000", "0001", "0010", "0011", "0100", "0101", "0110", "0111", "1000", "1001", "1010", "1011", "1100", "1101", "1110", "1111" };
  	string dec_2_base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	
	//convert hex string to binary string
	string bin_str;
	int index;
	for(int i = 0; i < sizeH; i++) {
		if(hex[i] >= 48 && hex[i] <= 57) {
			index = hex[i] - 48;
		}
		else {
			int c = toupper(hex[i]);
			index = c - 55;
		}
		bin_str += hex_2_bin[index];
	}
//	printf("Binary string: %s \n", bin_str);
	//convert binary string to base 64 in chunks of 6 bits
	string base64;
	//printf("sizeH*2/3 = %d\n", sizeH*2/3);
	//memset(base64, '0', strlen(base64));
	index = 0;
	string chunk;

	for (int j = 0; j < bin_str.length(); j+=6) {
		chunk = bin_str.substr(j, 6);
		//printf("chunk: %s, character: %c\n", chunk, dec_2_base64[strtol(chunk, NULL, 2)]);
		base64[index] = dec_2_base64[bitset<6>(chunk).to_ulong()];
		//printf("%s, size = %lu\n", base64, strlen(base64));
		index++;
	}
	//cout << "here: " << base64 << endl;
	base64[index] = '\0';
	return base64;

}

int main(void) {
	string input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
	cout << hex2b64(input);
	return 0;
}