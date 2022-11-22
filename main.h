#pragma once

typedef struct tokeninfo_t {
	int seriallen;
	uint8_t model[2];
	char serial[32];
	time_t time;
} tokeninfo;
