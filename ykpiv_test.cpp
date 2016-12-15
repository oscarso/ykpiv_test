#include <stdio.h>
#include <winscard.h>
#include <ykpiv/ykpiv.h>
#include <internal.h>
#include "../cpdk/cardmod.h"
#include "helper.h"
#include "cardfilesys.h"


#if 0
#include <openssl/rsa.h>
#include <openssl/pem.h>
RSA* openssl_test(void) {
	int		ret = 0;
	RSA		*r = NULL;
	BIGNUM	*bne = NULL;
	BIO		*bp_public = NULL;
	BIO		*bp_private = NULL;
	int				bits = 2048;
	unsigned long	e = RSA_F4;
	unsigned char	hash[20];
	unsigned char	msg[] = "abcd";
	unsigned char	msglen = strlen(msg);
	unsigned char	sig[256];
	unsigned int	siglen = 0;

	bne = BN_new();
	ret = BN_set_word(bne, e);
	if (ret != 1) {
		return NULL;
	}

	r = RSA_new();
	ret = RSA_generate_key_ex(r, bits, bne, NULL);
	if (ret != 1) {
		return NULL;
	}

	if (!SHA1(msg, msglen, hash)) return NULL;
	memset(sig, 0, sizeof(sig));
	ret = RSA_sign(NID_sha1, hash, sizeof(hash), sig, &siglen, r);
	if (ret != 1) {
		return NULL;
	}

	ret = RSA_verify(NID_sha1, hash, sizeof(hash), sig, siglen, r);
	if (ret != 1) {
		return NULL;
	}
	return r;
}
#endif


static ykpiv_rc _send_data(ykpiv_state *state, APDU *apdu,
	unsigned char *data, unsigned long *recv_len, int *sw) {
	long rc;
	unsigned int send_len = (unsigned int)apdu->st.lc + 5;

	//LogInfo("_send_data");
	if (1) {
		//LogInfo("Data Sent:");
		//LogBuffer(apdu->raw, send_len);
	}
	rc = SCardTransmit(state->card, SCARD_PCI_T1, apdu->raw, send_len, NULL, data, recv_len);
	if (rc != SCARD_S_SUCCESS) {
		if (1) {
			//LogInfo("error: SCardTransmit failed, rc=%08lx\n", rc);
		}
		return YKPIV_PCSC_ERROR;
	}

	if (1) {
		//LogInfo("Data Received:");
		//LogBuffer(data, *recv_len);
	}
	if (*recv_len >= 2) {
		*sw = (data[*recv_len - 2] << 8) | data[*recv_len - 1];
	}
	else {
		*sw = 0;
	}
	return YKPIV_OK;
}


#if 0
void test_select_card(void) {
	SCARDCONTEXT     hSC;
	OPENCARDNAME_EX  dlgStruct;
	WCHAR            szReader[256];
	WCHAR            szCard[256];
	LONG             lReturn;

	// Establish a context.
	// It will be assigned to the structure's hSCardContext field.
	lReturn = SCardEstablishContext(SCARD_SCOPE_USER,
		NULL,
		NULL,
		&hSC);
	if (SCARD_S_SUCCESS != lReturn)
	{
		printf("Failed SCardEstablishContext\n");
		exit(1);
	}

	// Initialize the structure.
	memset(&dlgStruct, 0, sizeof(dlgStruct));
	dlgStruct.dwStructSize = sizeof(dlgStruct);
	dlgStruct.hSCardContext = hSC;
	dlgStruct.dwFlags = SC_DLG_FORCE_UI;
	dlgStruct.lpstrRdr = (LPSTR)szReader;
	dlgStruct.nMaxRdr = 256;
	dlgStruct.lpstrCard = (LPSTR)szCard;
	dlgStruct.nMaxCard = 256;
	dlgStruct.lpstrTitle = L"My Select Card Title";

	// Display the select card dialog box.
	lReturn = SCardUIDlgSelectCard(&dlgStruct);
	if (SCARD_S_SUCCESS != lReturn)
		printf("Failed SCardUIDlgSelectCard - %x\n", lReturn);
	else
		printf("Reader: %S\nCard: %S\n", szReader, szCard);

	// Release the context (by SCardReleaseContext - not shown here).
}
#endif


int main(void)
{
	ykpiv_rc		rc = YKPIV_OK;
	ykpiv_state	*	state_a;
	int				verbosity = 1;
	int				retries;

	printf("ykpiv_init - state_a\n");
	if (ykpiv_init(&state_a, verbosity) != YKPIV_OK) {
		fprintf(stderr, "Failed initializing library.\n");
		return 1;
	}

	printf("ykpiv_connect - state_a\n");
	rc = ykpiv_connect(state_a, NULL);//"Yubico Yubikey 4 CCID 0"
	if (rc != YKPIV_OK) {
		fprintf(stderr, "Failed ykpiv_connect.  rc=%d\n", rc);
		return 1;
	}

	char key[24] = { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08 };
	printf("ykpiv_authenticate - state_a\n");
	retries = 0;
	rc = ykpiv_authenticate(state_a, (const unsigned char *)key);
	if (rc != YKPIV_OK) {
		fprintf(stderr, "Failed ykpiv_authenticate. rc=%d\n", rc);
		return 1;
	}

#if 1 //Test generateKeyPairs
	BYTE			blobPublic[2000];
	unsigned long	blobLen = sizeof(blobPublic);

	for (int i = 1; i <= 4; i++) {
		rc = generateKeyPairs(
			state_a,
			(i % 2 == 0) ? 0x9c : 0x9a,
			AT_SIGNATURE,
			YKPIV_ALGO_RSA2048,
			2048,
			YKPIV_PINPOLICY_DEFAULT,
			YKPIV_TOUCHPOLICY_DEFAULT,
			(LPBYTE)&blobPublic,
			&blobLen
		);
		printf("generateKeyPairs(%s) #%d returns ykrc=%d\n", ((i % 2 == 0) ? "0x9c" : "0x9a"), i, rc);
	}
#endif

	char	pin[9] = { 0 };
	int		tries = 0;
	rc = ykpiv_verify(state_a, (const char *)"aaaaaaaa", &tries);
	printf("ykpiv_verify returns rc=%d\n", rc);
	if (YKPIV_OK != rc) {
		return rc;
	}

#if 1 //Test ykpiv_sign_data
	unsigned char pt[256];
	unsigned char sig[256];
	size_t        sigLen = sizeof(sig);

	for (int i = 1; i <= 4; i++) {
		rc = ykpiv_sign_data(
			state_a,
			pt, sizeof(pt),
			sig, &sigLen,
			YKPIV_ALGO_RSA2048,
			SLOT_SIGN
		);
		printf("ykpiv_sign_data #%d returns ykrc=%d\n", i, rc);
	}
#endif

	ykpiv_done(state_a);

	return 0;
}