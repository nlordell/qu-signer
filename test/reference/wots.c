#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/sha.h>

#include <hash.h>
#include <hash_address.h>
#include <params.h>
#include <utils.h>
#include <wots.h>
#include <xmss_commons.h>

static void sha256(const char *s, unsigned char *out) {
	SHA256((const unsigned char *)s, strlen(s), out);
}

#define HEX(x) hex(#x, x, sizeof(x));
static void hex(const char *name, const unsigned char *ptr, size_t len) {
	printf("%s: ", name);
	for (size_t i = 0; i < len; i++) {
		printf("%02x", ptr[i]);
	}
	printf("\n");
}

int main() {
	xmss_params params;
	xmss_parse_oid(&params, 0x00000001);

	unsigned char sk[params.n];
	unsigned char seed[params.n];
	uint32_t oadrs[8] = {0};
	uint32_t ladrs[8] = {0};
	unsigned char m[params.n];

	sha256("secret", sk);
	sha256("seed", seed);
	set_tree_addr(oadrs, 42);
	set_tree_addr(ladrs, 42);
	set_type(ladrs, 1);
	sha256("Hello, WOTS+!", m);

	unsigned int ws[] = {4, 16};
	for (int i = 0; i < 2; i++) {
		params.wots_w = ws[i];
		xmss_xmssmt_initialize_params(&params);

		unsigned char pk[params.n];
		unsigned char sig[params.wots_sig_bytes];

		gen_leaf_wots(&params, pk, sk, seed, ladrs, oadrs);
		wots_sign(&params, sig, m, sk, seed, oadrs);

		printf("--- w=%d ---\n", ws[i]);
		HEX(pk);
		HEX(sig);
	}

	return 0;
}
