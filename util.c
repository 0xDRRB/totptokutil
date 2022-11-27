/*
 * Utility functions
 *
 * Base32 verification and decoding come from fmount's "c_otp" project
 * https://github.com/fmount/c_otp
 *
 */

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "sm4.h"
#include "util.h"

static const int8_t base32_vals[256] = {
    //    This map cheats and interprets:
    //       - the numeral zero as the letter "O" as in oscar
    //       - the numeral one as the letter "L" as in lima
    //       - the numeral eight as the letter "B" as in bravo
    // 00  01  02  03  04  05  06  07  08  09  0A  0B  0C  0D  0E  0F
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x00
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x10
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x20
    14, 11, 26, 27, 28, 29, 30, 31,  1, -1, -1, -1, -1,  0, -1, -1, // 0x30
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, // 0x40
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, // 0x50
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, // 0x60
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, -1, -1, -1, -1, // 0x70
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x80
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x90
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xA0
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xB0
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xC0
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xD0
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xE0
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xF0
};

int hex2array(const char *line, uint8_t *passwd, size_t len)
{
	size_t passlen = 0;
	uint32_t temp;
	int indx = 0;
	char buf[5] = {0};

	if (strlen(line) < len*2)
		return(-1);

	while(line[indx]) {
		if (line[indx] == '\t' || line[indx] == ' ') {
			indx++;
			continue;
		}

		if (isxdigit(line[indx])) {
			buf[strlen(buf) + 1] = 0x00;
			buf[strlen(buf)] = line[indx];
		} else {
			// we have symbols other than spaces and hex
			return(-1);
		}

		if (strlen(buf) >= 2) {
			sscanf(buf, "%x", &temp);
			passwd[passlen] = (uint8_t)(temp & 0xff);
			*buf = 0;
			passlen++;
			if (passlen > len)
				return(-1);
		}

		indx++;
	}

	// no partial hex bytes and need exact match
	if (strlen(buf) > 0 || passlen != len)
		return(-1);

	return(0);
}

void print_hex(const uint8_t *pbtData, const size_t szBytes)
{
	size_t  szPos;

	for(szPos = 0; szPos < szBytes; szPos++) {
		printf("%02X", pbtData[szPos]);
	}
}

void printhelp(char *binname)
{
	printf("TOTP Token utility v0.0.1\n");
	printf("Copyright (c) 2022 - Denis Bodor\n\n");
	printf("Usage : %s [OPTIONS]\n", binname);
	printf(" -i              get info on token\n");
	printf(" -k seed         use this base32 encoded secret key / seed\n");
	printf(" -t unix_time    set date/time in UNIX epoch format or system time if value is \"now\"\n");
	printf(" -m n            set HMAC method (1=SHA-1, 2=SHA-256)\n");
	printf(" -s n            set step time (1=30s, 2=60s)\n");
	printf(" -o n            set display time out (0=15s, 1=30s, 2=60s, 3=120s)\n");
	printf(" -a              autoconf with default (sync time, SHA-1, 30s step, 30s display timeout)\n");
	printf(" -l              list available readers\n");
	printf(" -d connstring   use this device (default: use the first available device)\n");
	printf(" -v              verbose mode\n");
	printf(" -h              show this help\n");
}

int validate_b32key(unsigned char *k, size_t len)
{
	size_t pos;

	// validates base32 key
	if (((len & 0xF) != 0) && ((len & 0xF) != 8))
		return 1;

	for (pos = 0; (pos < len); pos++) {
		if (base32_vals[k[pos]] == -1)
			return 1;
		if (k[pos] == '=') {
			if (((pos & 0xF) == 0) || ((pos & 0xF) == 8))
				return(1);
			if ((len - pos) > 6)
				return 1;
			switch (pos % 8) {
			case 2:
			case 4:
			case 5:
			case 7:
				break;
			default:
				return 1;
			}
			for ( ; (pos < len); pos++) {
				if (k[pos] != '=')
					return 1;
			}
		}
	}
	return 0;
}

size_t decode_b32key(uint8_t **k, size_t len)
{

    size_t keylen;
    size_t pos;
    // decodes base32 secret key
    keylen = 0;
    for (pos = 0; pos <= (len - 8); pos += 8) {
    // MSB is Most Significant Bits  (0x80 == 10000000 ~= MSB)
    // MB is middle bits             (0x7E == 01111110 ~= MB)
    // LSB is Least Significant Bits (0x01 == 00000001 ~= LSB)

    // byte 0
    (*k)[keylen+0]  = (base32_vals[(*k)[pos+0]] << 3) & 0xF8; // 5 MSB
    (*k)[keylen+0] |= (base32_vals[(*k)[pos+1]] >> 2) & 0x07; // 3 LSB
    if ((*k)[pos+2] == '=') {
        keylen += 1;
        break;
    }

    // byte 1
    (*k)[keylen+1]  = (base32_vals[(*k)[pos+1]] << 6) & 0xC0; // 2 MSB
    (*k)[keylen+1] |= (base32_vals[(*k)[pos+2]] << 1) & 0x3E; // 5  MB
    (*k)[keylen+1] |= (base32_vals[(*k)[pos+3]] >> 4) & 0x01; // 1 LSB
    if ((*k)[pos+4] == '=') {
        keylen += 2;
        break;
    }

    // byte 2
    (*k)[keylen+2]  = (base32_vals[(*k)[pos+3]] << 4) & 0xF0; // 4 MSB
    (*k)[keylen+2] |= (base32_vals[(*k)[pos+4]] >> 1) & 0x0F; // 4 LSB
    if ((*k)[pos+5] == '=') {
        keylen += 3;
        break;
    }

    // byte 3
    (*k)[keylen+3]  = (base32_vals[(*k)[pos+4]] << 7) & 0x80; // 1 MSB
    (*k)[keylen+3] |= (base32_vals[(*k)[pos+5]] << 2) & 0x7C; // 5  MB
    (*k)[keylen+3] |= (base32_vals[(*k)[pos+6]] >> 3) & 0x03; // 2 LSB
    if ((*k)[pos+7] == '=') {
        keylen += 4;
        break;
    }

    // byte 4
    (*k)[keylen+4]  = (base32_vals[(*k)[pos+6]] << 5) & 0xE0; // 3 MSB
    (*k)[keylen+4] |= (base32_vals[(*k)[pos+7]] >> 0) & 0x1F; // 5 LSB
    keylen += 5;
    }
    (*k)[keylen] = 0;

    return keylen;
}

size_t padarray(unsigned char *msg, size_t msglen, unsigned char **padmsg, size_t padto)
{
	size_t padlen;
	unsigned char *tmppadmsg;

	if (!padto)
		return(0);

	padlen = msglen;

	if (msglen % padto)
		padlen += padto-(msglen % padto);

	if ((tmppadmsg = (unsigned char *) malloc(padlen * sizeof(unsigned char))) == NULL) {
		fprintf(stderr, "malloc error!\n");
		exit(EXIT_FAILURE);
	}

	if (padlen != msglen) {
		memset(tmppadmsg, 0, padlen * sizeof(unsigned char));
		memcpy(tmppadmsg, msg, msglen);
		tmppadmsg[msglen] = 0x80;
	} else {
		memcpy(tmppadmsg, msg, msglen);
	}

	*padmsg = tmppadmsg;
	return(padlen);
}

// Compute MAC - ISO/IEC 9797-1 algorithm 1 with padding method 2
void makemac(unsigned char *msg, size_t msglen, unsigned char *key, unsigned char *mac)
{
	unsigned char iv[16] = { 0x00 };
	size_t padlen;
	unsigned char *padmessage;
	unsigned char *cpadmessage;

	sm4_context ctx;

	sm4_setkey_enc(&ctx, key);

	if ((padlen = padarray(msg, msglen, &padmessage, 16)) == 0) {
		fprintf(stderr, "Padding error!\n");
		return;
	}

	if ((cpadmessage = (unsigned char *) malloc(padlen * sizeof(unsigned char))) == NULL) {
		fprintf(stderr, "malloc error!\n");
		exit(EXIT_FAILURE);
	}

	sm4_crypt_cbc(&ctx, SM4_ENCRYPT, padlen, iv, padmessage, cpadmessage);

	mac[0] = cpadmessage[padlen-16];
	mac[1] = cpadmessage[padlen-15];
	mac[2] = cpadmessage[padlen-14];
	mac[3] = cpadmessage[padlen-13];

	free(cpadmessage);
	free(padmessage);
}
