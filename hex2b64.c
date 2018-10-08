//Cryptopals challenge set #1
//Camille Chow
//ECE 445

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

//Challenge 1: Convert hex to base64
char* hex2b64(char* hex, int bin) {
	int sizeH = strlen(hex);
	char *hex_2_bin[16] = { "0000", "0001", "0010", "0011", "0100", "0101", "0110", "0111", "1000", "1001", "1010", "1011", "1100", "1101", "1110", "1111" };
  	char *dec_2_base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";	
	//convert hex string to binary string
	char* bin_str = malloc(sizeH*4);
	int index;
	for(int i = 0; i < sizeH; i++) {
		if(hex[i] >= 48 && hex[i] <= 57) {
			index = hex[i] - 48;
		}
		else {
			int c = toupper(hex[i]);
			index = c - 55;
		}
		strcat(bin_str, hex_2_bin[index]);
	}
	//return binary string if bin = True
	if (bin == 1) {
		return bin_str;
	}
	//convert binary string to base 64 in chunks of 6 bits
	char* base64 = malloc(sizeH*2/3 + 1);
	index = 0;
	char* chunk = malloc(6);
	for (int j = 0; j < strlen(bin_str); j+=6) {
		memcpy(chunk, &bin_str[j], 6);
		printf("chunk: %s, character: %c\n", chunk, dec_2_base64[strtol(chunk, NULL, 2)]);
		base64[index] = dec_2_base64[strtol(chunk, NULL, 2)];
		printf("%s, size = %lu\n", base64, strlen(base64));
		index++;
	}
	base64[index] = '\0';
	free(bin_str);
	free(chunk);
	return base64;
}

//Challenge #2: XOR
// char* xor(char* buf1, char* buf2) {
// 	char* bin1 = hex2b64(buf1, 1);
// 	char* bin2 = hex2b64(buf2, 1);
// }

int main(void) {
	char* input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"; //should return SS
	printf("base 64: %s\n", hex2b64(input, 0));
	char* buf1 = "1010";
	char* buf2 = "1100";
	printf("%s\n", buf1^buf2);
	return 0;
}