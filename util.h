#pragma once

int hex2array(const char *line, uint8_t *passwd, size_t len);
void print_hex(const uint8_t *pbtData, const size_t szBytes);
void printhelp(char *binname);
int validate_b32key(unsigned char *k, size_t len);
size_t decode_b32key(uint8_t **k, size_t len);
size_t padarray(unsigned char *msg, size_t msglen, unsigned char **padmsg, size_t padto);
void makemac(unsigned char *msg, size_t msglen, unsigned char *key, unsigned char *mac);
