#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <nfc/nfc.h>

#include "main.h"
#include "color.h"
#include "util.h"
#include "statusres.h"
#include "sm4.h"
#include "secret.h"

#define S_SUCCESS         0x9000  // Command completed successfully
#define S_OK              0x9100  // OK (after additional data frame)
#define S_MORE            0x91af  // Additional data frame is expected to be sent

#define RAPDUMAXSZ 512
#define CAPDUMAXSZ 512
#define DEBUG        0

nfc_device *pnd;
nfc_context *context;
int optverb = 0;

static void sighandler(int sig)
{
    printf("Caught signal %d\n", sig);
    if (pnd != NULL) {
        nfc_abort_command(pnd);
        nfc_close(pnd);
    }
    nfc_exit(context);
    exit(EXIT_FAILURE);
}

int cardtransmit(nfc_device *pnd, uint8_t *capdu, size_t capdulen, uint8_t *rapdu, size_t *rapdulen, int notimeerr)
{
    int res;
	uint16_t status;
    size_t  szPos;

	if (DEBUG || optverb) {
		printf(YELLOW "=> ");
		for (szPos = 0; szPos < capdulen; szPos++) {
			printf("%02x ", capdu[szPos]);
		}
		printf(RESET "\n");
	}

    if ((res = nfc_initiator_transceive_bytes(pnd, capdu, capdulen, rapdu, *rapdulen, -1)) < 0) {
		if (notimeerr && nfc_device_get_last_error(pnd) == NFC_ETIMEOUT)
			return(0);
        fprintf(stderr, "nfc_initiator_transceive_bytes error! %d %s\n", nfc_device_get_last_error(pnd), nfc_strerror(pnd));
        return(-1);
    }

	if (DEBUG || optverb) {
		printf(GREEN "<= ");
		for (szPos = 0; szPos < res; szPos++) {
			printf("%02x ", rapdu[szPos]);
		}
		printf(RESET "\n");
	}

	if (res < 2) {
		fprintf(stderr, "Bad response !\n");
		return(-1);
	}

	status = (rapdu[res-2] << 8) | rapdu[res-1];
	if (status != S_SUCCESS) {
		fprintf(stderr, "Bad response ! 0x%04x:%s\n", status, strstatus(status));
		return(-1);
	}

	*rapdulen = (size_t)res;

	return(0);
}

// Transmit ADPU from hex string
int strcardtransmit(nfc_device *pnd, const char *line, uint8_t *rapdu, size_t *rapdulen)
{
    int res;
    size_t szPos;
	uint8_t *capdu = NULL;
	size_t capdulen = 0;
	*rapdulen = RAPDUMAXSZ;

	uint32_t temp;
	int indx = 0;
	char buf[5] = {0};

	uint16_t status;

	// linelen >0 & even
	if (!strlen(line) || strlen(line) > CAPDUMAXSZ * 2)
		return(-1);

	if (!(capdu = malloc(strlen(line) / 2))) {
		fprintf(stderr, "malloc list error: %s\n", strerror(errno));
		nfc_close(pnd);
		nfc_exit(context);
		exit(EXIT_FAILURE);
	}

    while (line[indx]) {
        if (line[indx] == '\t' || line[indx] == ' ') {
            indx++;
            continue;
        }

        if (isxdigit(line[indx])) {
            buf[strlen(buf) + 1] = 0x00;
            buf[strlen(buf)] = line[indx];
        } else {
            // if we have symbols other than spaces and hex
			free(capdu);
            return(-1);
        }

        if (strlen(buf) >= 2) {
            sscanf(buf, "%x", &temp);
            capdu[capdulen] = (uint8_t)(temp & 0xff);
            *buf = 0;
            capdulen++;
        }
        indx++;
    }

	// error if partial hex bytes
	if (strlen(buf) > 0) {
		free(capdu);
		return(-1);
	}

	if (DEBUG || optverb) {
		printf(YELLOW "=> " );
		for (szPos = 0; szPos < capdulen; szPos++) {
			printf("%02x ", capdu[szPos]);
		}
		printf(RESET "\n");
	}

    if ((res = nfc_initiator_transceive_bytes(pnd, capdu, capdulen, rapdu, *rapdulen, -1)) < 0) {
        fprintf(stderr, "nfc_initiator_transceive_bytes error! %s\n", nfc_strerror(pnd));
		*rapdulen = 0;
        return(-1);
    }

	if (capdu) free(capdu);

	if (DEBUG || optverb) {
		printf(GREEN "<= ");
		for (szPos = 0; szPos < res; szPos++) {
			printf("%02x ", rapdu[szPos]);
		}
		printf(RESET "\n");
	}

	status = (rapdu[res - 2] << 8) | rapdu[res - 1];
	if (status != S_SUCCESS) {
		fprintf(stderr, "Bad response ! 0x%04x:%s\n", status, strstatus(status));
		return(-1);
	}

	*rapdulen = (size_t)res;

	return(0);
}

void failquit()
{
	if (pnd)
		nfc_close(pnd);
	if (context)
		nfc_exit(context);
	exit(EXIT_SUCCESS);
}

int listdevices() {
	size_t device_count;
	nfc_connstring devices[8];

	// Scan readers/devices
	device_count = nfc_list_devices(context, devices, sizeof(devices) / sizeof(*devices));
	if (device_count <= 0) {
		fprintf(stderr, "Error: No NFC device found\n");
		return(0);
	}

	printf("Available readers/devices:\n");
	for(size_t d = 0; d < device_count; d++) {
		printf("  %lu: ", d);
		if (!(pnd = nfc_open (context, devices[d]))) {
			printf("nfc_open() failed\n");
		} else {
			printf("%s (connstring=\"%s\")\n", nfc_device_get_name(pnd), nfc_device_get_connstring(pnd));
			nfc_close(pnd);
		}
	}
	return(device_count);
}

int gettokeninfo(nfc_device *pnd, tokeninfo *info)
{
	uint8_t resp[RAPDUMAXSZ] = { 0 };
	size_t respsz;

	// get info
	if (strcardtransmit(pnd, "80 41 0000 02 0211", resp, &respsz) < 0) {
		fprintf(stderr, "The token does not respond! Make sure it is properly placed on the reader and switched on.\n");
		return(-1);
	}

	// get serial len
	info->seriallen = resp[3];

	// copy serial
	memcpy(info->serial, resp + 4, info->seriallen);

	// copy model code (?)
	memcpy(info->model, resp + 4 + info->seriallen, 2);

	// get unix time
	info->time =
		resp[4 + info->seriallen + 2]     << 24 |
		resp[4 + info->seriallen + 2 + 1] << 16 |
		resp[4 + info->seriallen + 2 + 2] <<  8 |
		resp[4 + info->seriallen + 2 + 3];

	return(0);
}

void printtokeninfo(tokeninfo *info)
{
	struct tm tm = *localtime(&info->time);
	time_t t = time(NULL);
	struct tm ltm = *localtime(&t);

	printf("Serial number:    %s\n", info->serial);
	printf("Model number (?): 0x%02x%02x\n", info->model[0], info->model[1]);
    printf("Date/Time:        %d-%02d-%02d %02d:%02d:%02d (local: %d-%02d-%02d %02d:%02d:%02d %c%lds)\n",
			tm.tm_year+1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
			ltm.tm_year+1900, ltm.tm_mon + 1, ltm.tm_mday, ltm.tm_hour, ltm.tm_min, ltm.tm_sec,
			t > info->time ? '+' : '-', t-info->time);

	return;
}

int authtoken(nfc_device *pnd)
{
	uint8_t resp[RAPDUMAXSZ] = { 0 };
	size_t respsz;
	uint8_t challenge[16] = { 0 };
	uint8_t response[16];
	uint8_t responseapdu[16 + 5];
	sm4_context ctx;

	// get info
	if (strcardtransmit(pnd, "80 4b 0800 00", resp, &respsz) < 0) {
		fprintf(stderr, "The token does not respond! Make sure it is properly placed on the reader and switched on.\n");
		return(-1);
	}

	if(respsz - 2 > 16) {
		fprintf(stderr, "Challenge too big (?). Giving up !\n");
		return(-1);
	}

	// copy and padding
	memcpy(challenge, resp, respsz - 2);

	sm4_setkey_enc(&ctx, customerkey);
	sm4_crypt_ecb(&ctx, SM4_ENCRYPT, 16, challenge, response);

	responseapdu[0] = 0x80;
	responseapdu[1] = 0xce;
	responseapdu[2] = 0x00;
	responseapdu[3] = 0x00;
	responseapdu[4] = 0x10;

	// copy response
	memcpy(responseapdu+5, response, 16);

	respsz = RAPDUMAXSZ;
	if(cardtransmit(pnd, responseapdu, 16 + 5, resp, &respsz, 0) < 0) {
		fprintf(stderr, "Authentication failed!\n");
		return(-1);
	}

	return(0);
}

int seedtoken(nfc_device *pnd, uint8_t *seed, size_t seedlen)
{
	uint8_t baseapdu[5] = { 0x84, 0xC5, 0x01, 0x00, 0x00 };
	//                                                ^^ MAC Lc = cipheredseed lenght
	//                                                   Real Lc = cipheredseed lenght + 4
	uint8_t *paddedseed;	// padded seed
	size_t paddedseedlen;
	uint8_t *cipheredseed;	// crypted padded seed
	uint8_t *apduseed;		// APDU start + crypted padded seed for MAC calculation (Lc = len(crypted padded seed))
	uint8_t *apdufinal;		// APDU start + crypted padded seed + MAC (Lc = len(crypted padded seed) + len(MAC))
	uint8_t mac[4] = { 0 };

	uint8_t resp[RAPDUMAXSZ] = { 0 };
	size_t respsz;

	sm4_context ctx;

	sm4_setkey_enc(&ctx, customerkey);

	// pad seed
	if ((paddedseedlen = padarray(seed, seedlen, &paddedseed, 16)) == 0) {
		fprintf(stderr, "Padding error!\n");
		return(-1);
	}

	if(optverb) {
		printf("Hex seed(%zu):                ", seedlen);
		print_hex(seed, seedlen);
		printf("\n");
		printf("Hex padded seed (%zu):        ", paddedseedlen);
		print_hex(paddedseed, paddedseedlen);
		printf("\n");
	}

	// cipher padded seed
	if ((cipheredseed = (unsigned char *) malloc(paddedseedlen * sizeof(unsigned char))) == NULL) {
		fprintf(stderr, "malloc error!\n");
		exit(EXIT_FAILURE);
	}
	// non-CBC ! no IV ! baaaaaad (?)
	for (int i = 0; i < paddedseedlen/16; i++) {
		sm4_crypt_ecb(&ctx, SM4_ENCRYPT, 16, paddedseed + (i * 16), cipheredseed + (i * 16));
	}

	if(optverb) {
		printf("Hex crypted padded Seed(%zu): ", paddedseedlen);
		print_hex(cipheredseed, paddedseedlen);
		printf("\n");
	}

	free(paddedseed);

	// Compose APDU for MAC
	if ((apduseed = (unsigned char *) malloc((paddedseedlen + 5) * sizeof(unsigned char))) == NULL) {
		fprintf(stderr, "malloc error!\n");
		exit(EXIT_FAILURE);
	}
	memcpy(apduseed, baseapdu, 5);
	memcpy(apduseed + 5, cipheredseed, paddedseedlen);
	apduseed[4] = paddedseedlen;  // set Lc for MAC
	apduseed[0] = 0x80;  // set class for MAC (yeah, it's not the real class code)

	// Compute MAC
	makemac(apduseed, paddedseedlen + 5, customerkey, mac);

	if(optverb) {
		printf("APDU message for MAC(%zu):    ", paddedseedlen + 5);
		print_hex(apduseed, paddedseedlen + 5);
		printf("\n");
		printf("MAC (%zu):                     ", (size_t)4);
		print_hex(mac, 4);
		printf("\n");
	}

	free(apduseed);

	if ((apdufinal = (unsigned char *) malloc((paddedseedlen + 5 + 4) * sizeof(unsigned char))) == NULL) {
		fprintf(stderr, "malloc error!\n");
		exit(EXIT_FAILURE);
	}
	memcpy(apdufinal, baseapdu, 5);
	memcpy(apdufinal + 5, cipheredseed, paddedseedlen);
	memcpy(apdufinal + 5 + paddedseedlen, mac, 4);
	apdufinal[4] = paddedseedlen + 4;

	if(optverb) {
		printf("Final APDU(%zu):              ", 5 + paddedseedlen + 4);
		print_hex(apdufinal, 5 + paddedseedlen + 4);
		printf("\n");
	}

	free(cipheredseed);

	if(cardtransmit(pnd, apdufinal, 5 + paddedseedlen + 4, resp, &respsz, 1) < 0) { // FIXME
		fprintf(stderr, "Error setting seed!\n");
		free(apdufinal);
		return(-1);
	}

	free(apdufinal);

	return(0);
}

int configtoken(nfc_device *pnd, uint8_t *seed)
{
	return(0);
}

int main(int argc, char **argv)
{
	nfc_target nt;
	const nfc_modulation mod = {
		.nmt = NMT_ISO14443A,
		.nbr = NBR_106
	};

	int retopt;
	char *endptr;
	int opt = 0;
	int optinfo = 0;
	int optauth = 0;
	int optlistdev = 0;
	char *optconnstring = NULL;

	char *b32seed = NULL;
	size_t b32len;
	char *b32seedpadded = NULL;
	size_t b32lenpadded;
	uint8_t *realseed = NULL;;
	size_t realseedlen;

	tokeninfo tokinfo = { 0 };

	while((retopt = getopt(argc, argv, "ivhlad:s:")) != -1) {
		switch (retopt) {
			case 'i':
				optinfo = 1;
				opt++;
				break;
			case 'l':
				optlistdev = 1;
				opt++;
				break;
			case 'a':
				optauth = 1;
				opt++;
				break;
			case 'd':
				optconnstring = strdup(optarg);
				opt++;
				break;
			case 's':
				b32seed = strdup(optarg);
				opt++;
				break;
			case 'v':
				optverb = 1;
				break;
			case 'h':
				printhelp(argv[0]);
				return(EXIT_FAILURE);
			default:
				printhelp(argv[0]);
				return(EXIT_FAILURE);
		}
	}

	if (!opt) {
		printhelp(argv[0]);
		return(EXIT_FAILURE);
	}

	// base32 input checks
	if (b32seed) {
		b32len = strlen(b32seed);

		if (!b32len) {
			fprintf(stderr, "Invalid base32 data!\n");
			return(EXIT_FAILURE);
		}

		if (optverb)
			printf("base32 input:   %s\n", b32seed);

		// key padding
		b32lenpadded = b32len;
		if (b32len % 8)
			b32lenpadded += 8 - (b32len % 8);

		if (b32lenpadded != b32len) {
			if ((b32seedpadded = (char *) malloc((b32lenpadded + 1) * sizeof(char))) == NULL) {
				fprintf(stderr, "malloc error!\n");
				return EXIT_FAILURE;
			}
			memset(b32seedpadded, 0, (b32lenpadded + 1) * sizeof(char));
			// fill with '='
			for (int i=0; i < b32lenpadded; i++) {
				b32seedpadded[i] = '=';
			}
			// copy undersized key
			for (int i=0; i < b32len; i++) {
				b32seedpadded[i] = b32seed[i];
			}
			// replace key
			free(b32seed);
			b32seed = b32seedpadded;
			b32len = b32lenpadded;
		}

		if (validate_b32key((unsigned char *)b32seed, b32len) == 1) {
			fprintf(stderr, "%s: invalid base32 data!\n", b32seed);
			return(EXIT_FAILURE);
		}

		if (optverb)
			printf("base32 padding: %s\n", b32seed);

		realseed = (uint8_t *)b32seed;
		realseedlen = decode_b32key(&realseed, b32len);

		// minimum 20 bytes, so pad with 0x00
		if (realseedlen < 20) {
			realseed = realloc(realseed, 20);
			memset(realseed+realseedlen, 0, (20 - realseedlen) * sizeof(uint8_t));
			realseedlen = 20;
		}

		if (realseedlen > 63) {
			fprintf(stderr, "Seed is too long (> 63 bytes)!\n");
			return(EXIT_FAILURE);
		}
	}

    if (signal(SIGINT, &sighandler) == SIG_ERR) {
        printf("Error: Can't catch SIGINT\n");
        return(EXIT_FAILURE);
    }

    if (signal(SIGTERM, &sighandler) == SIG_ERR) {
        printf("Error: Can't catch SIGTERM\n");
        return(EXIT_FAILURE);
    }

	// Initialize libnfc and set the nfc_context
	nfc_init(&context);
	if (context == NULL) {
		printf("Error: Unable to init libnfc (malloc)\n");
		exit(EXIT_FAILURE);
	}

	if (optlistdev) {
		listdevices();
		nfc_exit(context);
		return(EXIT_SUCCESS);
	}

	if (optconnstring) {
		// Open, using specified NFC device
		pnd = nfc_open(context, optconnstring);
	} else {
		// Open, using the first available NFC device which can be in order of selection:
		//   - default device specified using environment variable or
		//   - first specified device in libnfc.conf (/etc/nfc) or
		//   - first specified device in device-configuration directory (/etc/nfc/devices.d) or
		//   - first auto-detected (if feature is not disabled in libnfc.conf) device
		pnd = nfc_open(context, NULL);
	}

	if (pnd == NULL) {
		fprintf(stderr, "Error: Unable to open NFC device!\n");
		exit(EXIT_FAILURE);
	}

	// Set opened NFC device to initiator mode
	if (nfc_initiator_init(pnd) < 0) {
		nfc_perror(pnd, "nfc_initiator_init");
		exit(EXIT_FAILURE);
	}

	if (optverb)
		printf("NFC reader: %s opened\n", nfc_device_get_name(pnd));

	if (nfc_initiator_select_passive_target(pnd, mod, NULL, 0, &nt) > 0) {
		printf("%s (%s) tag found. UID: " CYAN,
				str_nfc_modulation_type(mod.nmt), str_nfc_baud_rate(mod.nbr));
		print_hex(nt.nti.nai.abtUid, nt.nti.nai.szUidLen);
		printf(RESET "\n");
	} else {
		fprintf(stderr, "Error: No ISO14443A tag found!\n");
		failquit();
	}

	if (optinfo) {
		if (gettokeninfo(pnd, &tokinfo) == 0) {
			printf("Token found:\n");
			printtokeninfo(&tokinfo);
		}
	}

	if (optauth) {
		if (authtoken(pnd) == 0) {
			printf("Authentication success :)\n");
		}
	}

	if (realseed) {
		authtoken(pnd);
		seedtoken(pnd, realseed, realseedlen);
	}

	if (realseed)
		free(realseed);

	// Close NFC device
	nfc_close(pnd);
	// Release the context
	nfc_exit(context);
	return(EXIT_SUCCESS);
}
