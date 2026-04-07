CC      ?= gcc
CFLAGS   = -Wall -g -O3 -Wextra -Wpedantic
LDFLAGS  = -lcrypto
SRC      = fips202.c \
           hash.c \
           hash_address.c \
           params.c \
           randombytes.c \
           utils.c \
           wots.c \
           xmss.c \
           xmss_commons.c \
           xmss_core.c

ifndef XMSS_REFERENCE
$(error XMSS_REFERENCE is not set)
endif

.PHONY: run
run: wots
	./wots

wots: wots.c $(addprefix $(XMSS_REFERENCE)/,$(SRC))
	$(CC) -o $@ -I$(XMSS_REFERENCE) $(CFLAGS) $^ $(LDFLAGS)
