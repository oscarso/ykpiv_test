#include<stdio.h>
#include<ykpiv.h>

int main(void)
{
	ykpiv_rc	rc = 0;
	ykpiv_state	*state;
	int			verbosity=0;

	printf("ykpiv_init\n");
	if (ykpiv_init(&state, verbosity) != YKPIV_OK) {
		fprintf(stderr, "Failed initializing library.\n");
		return 1;
	}

	printf("ykpiv_connect\n");
	rc = ykpiv_connect(state, "Yubico Yubikey 4 CCID 0");
	if (rc != YKPIV_OK) {
		fprintf(stderr, "Failed ykpiv_connect.  rc=%d\n", rc);
		return 1;
	}

	printf("ykpiv_verify\n");
	int retries = 0;
	rc = ykpiv_verify(state, "YubicoRu", &retries);
	if (rc != YKPIV_OK) {
		fprintf(stderr, "Failed ykpiv_verify. retries=%d rc=%d\n", retries, rc);
		return 1;
	}

	printf("ykpiv_change_pin\n");
	retries = 0;
	rc = ykpiv_change_pin(state, "YubicoRu", 8, "YubicoRu", 8, &retries);
	if (rc != YKPIV_OK) {
		fprintf(stderr, "Failed ykpiv_change_pin. retries=%d rc=%d\n", retries, rc);
		return 1;
	}

	printf("\n\nALL PASSED\n");
	ykpiv_done(state);
	return 0;
}