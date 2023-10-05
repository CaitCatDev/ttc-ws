#include <utils.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <time.h>

/*byteN refers to that byte position in a multi byte number
 * going left to right
 * E.G. 0x1020 
 * 0x10 would be byte 0 
 * 0x20 would be byte 1
 */
uint16_t endian_swap16(uint16_t innum) {
	uint16_t byte0, byte1;
	uint16_t ret;

	byte0 = innum >> 8;
	byte1 = innum & 0xff;
	
	ret = byte0 | (byte1 << 8);

	return ret;
}


uint32_t endian_swap32(uint32_t innum) {
	uint32_t hbyte, lbyte, lmid_byte, hmid_byte;
	uint32_t ret;
	
	hbyte = (innum >> 24) & 0xff;
	hmid_byte = (innum >> 16) & 0xff;
	lmid_byte = (innum >> 8) & 0xff;
	lbyte = (innum) & 0xff;

	ret = hbyte | (hmid_byte << 8) | (lmid_byte << 16) | lbyte << 24;

	return ret;
}

uint64_t endian_swap64(uint64_t innum) {
	uint64_t byte0, byte1, byte2, byte3, byte4, byte5, byte6, byte7;
	uint64_t ret;
	
	byte0 = (innum >> 56) & 0xff;
	byte1 = (innum >> 48) & 0xff;
	byte2 = (innum >> 40) & 0xff;
	byte3 = (innum >> 32) & 0xff;
	byte4 = (innum >> 24) & 0xff;
	byte5 = (innum >> 16) & 0xff;
	byte6 = (innum >> 8) & 0xff;
	byte7 = innum & 0xff;


	ret = byte0 | byte1 << 8 | byte2 << 16 | byte3 << 24 | 
		byte4 << 32 | byte5 << 40 | byte6 << 48 | byte7 << 56;

	return ret;
}

static const char b64table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; 

/* base 64 writes in 24-bit chunks with 6-bit chars
 * so every length needs to rounded up to to the nearest 
 * 24bits example 16-bytes is 128 bits / 24 is 5.3333
 * So to make a valid base64 number we need to round 128 upto
 * 144bits or 18bytes then because we have to output characters
 * 144 / 24 = 6. Six is the number of 24 bit base64 chunks to 
 * be outputted so we times it by four to get the actual byte 
 * length the extra length is due to the fact 8 bit chars 
 * represent as 6 bit letters will inherntly take more space
 * due to the fact that chars such as "A" will become QQ== due 
 * to the fact 2 bits are left over producing the "extra" char 
 * and base64 needs to pad to 4 characters thus the two equals 
 * signs
 */
size_t b64_encode_len(size_t lenin) {
	size_t lenout = lenin;
	
	/*input needs to be cleanly divisable by three we could do floating
	 * point instead. But I think it's best to just round the number up 
	 * to the nearest number cleanly divisable by 3*/
	if(lenout % 3) {
		lenout -= (lenout % 3); /*take away remainder to make number cleanly divisible*/
		lenout += 3; /*add 3 to make sure the number accounts for the extra space the remainder bytes need*/
	}

	lenout /= 3; /*3 bytes is 24bits length in to number of blocks*/
	lenout *= 4; /*get actual byte length of output*/
	return lenout;
}

char *b64_encode(const uint8_t *data, size_t len) {
	size_t index, outindex;
	uint32_t block;
	size_t outlen; 
	char *outstr;

	outlen = b64_encode_len(len);
	outstr = calloc(sizeof(char), outlen + 1);
	
	if(outstr == NULL) {
		printf("%s: calloc error %m\n", __func__); 
		return NULL;
	}

	for(index = 0, outindex = 0; index < len; index += 3, outindex += 4) {
		/*construct a 24-bit int*/
		block = data[index];
		block = index+1 < len ? block << 8 | data[index+1] : block << 8;	
		block = index+2 < len ? block << 8 | data[index+2] : block << 8;
	
		/*output the first two characters*/
		outstr[outindex] = b64table[(block >> 18) & 0x3F];
		outstr[outindex + 1] = b64table[(block >> 12) & 0x3f];
		
		/*Either set the next two characters or pad them if there are none*/
		outstr[outindex + 2] = index + 1 < len ? b64table[(block >> 6) & 0x3F] :  '=';
		outstr[outindex + 3] = index + 2 < len ? b64table[block & 0x3F] :  '=';	
	}
	
	return outstr;
}

uint8_t *random_array(size_t len) {
	size_t index;
	uint8_t *output = calloc(sizeof(uint8_t), len);

	if(len == 0) {
		printf("%s: Invalid parameter passed in\n", __func__);
		return NULL;
	}

	if(output == NULL) {
		printf("%s: calloc failed %m\n", __func__);
		return NULL;
	}

	srand(time(NULL));

	for(index = 0; index < len; ++index) {
		output[index] = ((uint8_t)rand() % 0xff);
	}

	return output;
}



