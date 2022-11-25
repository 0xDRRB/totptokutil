#pragma once

typedef struct tokeninfo_t {
	int seriallen;
	char serial[32];
	time_t time;
} tokeninfo;
