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

#define RAPDUMAXSZ           512
#define CAPDUMAXSZ           512
#define DEBUG                  0

#define CONF_SHA1           0x01
#define CONF_SHA256         0x02
#define CONF_DTIME15        0x00
#define CONF_DTIME30        0x01
#define CONF_DTIME60        0x02
#define CONF_DTIME120       0x03
#define CONF_STEP30         0x1e
#define CONF_STEP60         0x3c

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
    printf("Date/Time:        %d-%02d-%02d %02d:%02d:%02d (local: %d-%02d-%02d %02d:%02d:%02d %c%lds)\n",
			tm.tm_year+1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
			ltm.tm_year+1900, ltm.tm_mon + 1, ltm.tm_mday, ltm.tm_hour, ltm.tm_min, ltm.tm_sec,
			t > info->time ? '+' : '-', t-info->time);
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
		fprintf(stderr, "Bad challenge size (?). Giving up !\n");
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
	memcpy(responseapdu + 5, response, 16);

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

	if(cardtransmit(pnd, apdufinal, 5 + paddedseedlen + 4, resp, &respsz, 1) < 0) {
		fprintf(stderr, "Error setting seed!\n");
		free(apdufinal);
		return(-1);
	}

	free(apdufinal);

	return(0);
}

int configtoken(nfc_device *pnd, uint8_t *conftime, uint8_t confmac, uint8_t confstep, uint8_t confdisp)
{
	uint8_t apdu[5 + 19 + 4] = {
		0x80, 0xd4, 0x00, 0x00, 0x13,  // Class Cmd p1 p2 Lc
		0x81, 0x11,                    // TLV_TAG_SYS_CONFG header and length
		0x1f, 0x01,                    // TLV_TAG_SYSCLOSE_TIMEOUT header and length
		0x00,                          // [9] display timeout <<
		0x0f, 0x04,                    // TLV_TAG_UTC_TIME header and length
		0x00, 0x00, 0x00, 0x00,        // [12-15] time <<
		0x86, 0x06,                    // TLV_TAG_TOTP_PARAM header and length
		0x0a, 0x01,                    // TLV_TAG_TOTP_HMAC header and length
		0x00,                          // [20] hmac <<
		0x0d, 0x01,                    // TLV_TAG_TOTP_TIME_STEP header and length
		0x00,                          // [23] step <<
		0x00, 0x00, 0x00, 0x00         // MAC
	};
	uint8_t mac[4];
	uint8_t resp[RAPDUMAXSZ] = { 0 };
	size_t respsz;

	// set confuiguration
	apdu[9] = confdisp;
	memcpy(apdu+12, conftime, 4);
	apdu[20] = confmac;
	apdu[23] = confstep;

	// Compute MAC
	makemac(apdu, 5 + 19, customerkey, mac);
	// copye MAC
	memcpy(apdu+24, mac, 4);
	// real APDU
	apdu[0] = 0x84;
	apdu[4] = 0x17;

	if(cardtransmit(pnd, apdu, 5 + 19 + 4, resp, &respsz, 1) < 0) {
		fprintf(stderr, "Error setting configuration!\n");
		return(-1);
	}

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
	int optlistdev = 0;
	char *optconnstring = NULL;
	int optconftime = 0;
	int optconfmac = 0;
	int optconfdisp = 0;
	int optconfstep = 0;
	int optconfauto = 0;
	uint8_t confmac, confdisp, confstep;
	uint8_t conftime[4] = { 0 };
	uint32_t tmptime = 0;

	char *b32seed = NULL;
	size_t b32len;
	char *b32seedpadded = NULL;
	size_t b32lenpadded;
	uint8_t *realseed = NULL;;
	size_t realseedlen;

	time_t t = 0;

	tokeninfo tokinfo = { 0 };

	while((retopt = getopt(argc, argv, "ivhld:k:t:m:o:s:a")) != -1) {
		switch (retopt) {
			case 'i':	// get info
				optinfo = 1;
				opt++;
				break;
			case 'l':	// list NFC readers
				optlistdev = 1;
				opt++;
				break;
			case 'd':	// choose reader
				optconnstring = strdup(optarg);
				break;
			case 'k':	// set seed
				b32seed = strdup(optarg);
				opt++;
				break;
			case 't':	// set time
				if (strcmp(optarg, "now") == 0) {
					// FIXME : delai auth + reste -> +2s
					t = time(NULL);
					conftime[0] = (t & 0xff000000) >> 24;
					conftime[1] = (t & 0x00ff0000) >> 16;
					conftime[2] = (t & 0x0000ff00) >> 8;
					conftime[3] =  t & 0x000000ff;
				} else {
					tmptime = (uint32_t)strtol(optarg, &endptr, 10);
					if (endptr == optarg) {
						fprintf(stderr, "Error: Invalid epoch date/time\n");
						return(EXIT_FAILURE);
					}
					conftime[0] = (tmptime & 0xff000000) >> 24;
					conftime[1] = (tmptime & 0x00ff0000) >> 16;
					conftime[2] = (tmptime & 0x0000ff00) >> 8;
					conftime[3] =  tmptime & 0x000000ff;
				}
				optconftime = 1;
				opt++;
				break;
			case 'm':	// set HMAC
				if (strlen(optarg) != 1) {
					fprintf(stderr, "Error: invalid argument for HMAC method!\n");
					return(EXIT_FAILURE);
				}
				switch(optarg[0]) {
				case '1':
					confmac = CONF_SHA1;
					break;
				case '2':
					confmac = CONF_SHA256;
					break;
				default:
					fprintf(stderr, "Error: unknown HMAC method! Valid values are 1=SHA-1, 2=SHA-256\n");
					return(EXIT_FAILURE);
				}
				optconfmac = 1;
				opt++;
				break;
			case 'o':	// set display time
				if (strlen(optarg) != 1) {
					fprintf(stderr, "Error: invalid argument for display timeout!\n");
					return(EXIT_FAILURE);
				}
				switch(optarg[0]) {
				case '0':
					confdisp = CONF_DTIME15;
					break;
				case '1':
					confdisp = CONF_DTIME30;
					break;
				case '2':
					confdisp = CONF_DTIME60;
					break;
				case '3':
					confdisp = CONF_DTIME120;
					break;
				default:
					fprintf(stderr, "Error: unknown display timeout! Valid values are 0=15s, 1=30s, 2=60s, 3=120s\n");
					return(EXIT_FAILURE);
				}
				optconfdisp = 1;
				opt++;
				break;
			case 's':	// set step time
				if (strlen(optarg) != 1) {
					fprintf(stderr, "Error: invalid argument for step time!\n");
					return(EXIT_FAILURE);
				}
				switch(optarg[0]) {
				case '1':
					confstep = CONF_STEP30;
					break;
				case '2':
					confstep = CONF_STEP60;
					break;
				default:
					fprintf(stderr, "Error: unknown step time! Valid values are 1=30s, 2=60s\n");
					return(EXIT_FAILURE);
				}
				optconfstep = 1;
				opt++;
				break;
			case 'a':	// autoconf with default
				optconfauto = 1;
				opt++;
				break;
			case 'v':	// verbose mode
				optverb = 1;
				break;
			case 'h':	// help
				printhelp(argv[0]);
				return(EXIT_SUCCESS);
			default:
				printhelp(argv[0]);
				return(EXIT_FAILURE);
		}
	}

	if (!opt) {
		printhelp(argv[0]);
		return(EXIT_FAILURE);
	}

	if (optconftime || optconfmac || optconfdisp || optconfstep) {
		if (optconfauto) {
			fprintf(stderr, "You cannot autoconfig and define settings at the same time!\n");
			return(EXIT_FAILURE);
		}
		if (!optconftime || !optconfmac || !optconfdisp || !optconfstep) {
			fprintf(stderr, "You must specify all the settings at once (time + HMAC method + step + display timeout)!\n");
			return(EXIT_FAILURE);
		}
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
			// padding with '='
			memset(b32seedpadded, '=', b32lenpadded);
			// end string
			b32seedpadded[b32lenpadded] = 0;
			// copy undersized key
			memcpy(b32seedpadded, b32seed, b32len);
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
			memset(realseed + realseedlen, 0, (20 - realseedlen) * sizeof(uint8_t));
			realseedlen = 20;
		}

		if (realseedlen > 63) {
			fprintf(stderr, "Seed is too big (> 63 bytes)!\n");
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

	// if we have one conf* here, we have all
	if (realseed || confdisp || optconfauto) {
		authtoken(pnd);
		if (confdisp) {
			configtoken(pnd, conftime, confmac, confstep, confdisp);
		} else if (optconfauto) {
			t = time(NULL);
			conftime[0] = (t & 0xff000000) >> 24;
			conftime[1] = (t & 0x00ff0000) >> 16;
			conftime[2] = (t & 0x0000ff00) >> 8;
			conftime[3] =  t & 0x000000ff;
			configtoken(pnd, conftime, CONF_SHA1, CONF_STEP30, CONF_DTIME30);
		}
		if (realseed) {
			seedtoken(pnd, realseed, realseedlen);
		}
	}

	if (realseed)
		free(realseed);

	// Close NFC device
	nfc_close(pnd);
	// Release the context
	nfc_exit(context);
	return(EXIT_SUCCESS);
}
