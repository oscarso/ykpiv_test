#include <stdio.h>
#include <winscard.h>
#include <ykpiv.h>
#include <internal.h>
#include "clogger\clogger.h"


#define CHREF_ACT_CHANGE_PIN 0
#define CHREF_ACT_UNBLOCK_PIN 1
#define CHREF_ACT_CHANGE_PUK 2

static ykpiv_rc _send_data(ykpiv_state *state, APDU *apdu,
	unsigned char *data, unsigned long *recv_len, int *sw) {
	long rc;
	unsigned int send_len = (unsigned int)apdu->st.lc + 5;

	LogInfo("_send_data");
	if (1) {
		LogInfo("Data Sent:");
		LogBuffer(apdu->raw, send_len);
	}
	rc = SCardTransmit(state->card, SCARD_PCI_T1, apdu->raw, send_len, NULL, data, recv_len);
	if (rc != SCARD_S_SUCCESS) {
		if (1) {
			LogInfo("error: SCardTransmit failed, rc=%08lx\n", rc);
		}
		return YKPIV_PCSC_ERROR;
	}

	if (1) {
		LogInfo("Data Received:");
		LogBuffer(data, *recv_len);
	}
	if (*recv_len >= 2) {
		*sw = (data[*recv_len - 2] << 8) | data[*recv_len - 1];
	}
	else {
		*sw = 0;
	}
	return YKPIV_OK;
}

ykpiv_rc _transfer_data(ykpiv_state *state, const unsigned char *templ,
	const unsigned char *in_data, long in_len,
	unsigned char *out_data, unsigned long *out_len, int *sw) {
	const unsigned char *in_ptr = in_data;
	unsigned long max_out = *out_len;
	ykpiv_rc res;
	//long rc;
	*out_len = 0;

	LogInfo("_transfer_data");

	/*rc = SCardBeginTransaction(state->card);
	if (rc != SCARD_S_SUCCESS) {
	if (state->verbose) {
	fprintf(stderr, "error: Failed to begin pcsc transaction, rc=%08lx\n", rc);
	}
	return YKPIV_PCSC_ERROR;
	}*/

	do {
		size_t this_size = 0xff;
		unsigned char data[261];
		unsigned long recv_len = sizeof(data);
		APDU apdu;

		memset(apdu.raw, 0, sizeof(apdu.raw));
		memcpy(apdu.raw, templ, 4);
		if (in_ptr + 0xff < in_data + in_len) {
			apdu.st.cla = 0x10;
		}
		else {
			this_size = (size_t)((in_data + in_len) - in_ptr);
		}
		if (1) {
			LogInfo("Going to send %lu bytes in this go.\n", (unsigned long)this_size);
		}
		apdu.st.lc = (unsigned char)this_size;
		memcpy(apdu.st.data, in_ptr, this_size);
		res = _send_data(state, &apdu, data, &recv_len, sw);
		if (res != YKPIV_OK) {
			return res;
		}
		else if (*sw != SW_SUCCESS && *sw >> 8 != 0x61) {
			return YKPIV_OK;
		}
		if (*out_len + recv_len - 2 > max_out) {
			if (1) {
				LogInfo("Output buffer to small, wanted to write %lu, max was %lu.\n", *out_len + recv_len - 2, max_out);
			}
			return YKPIV_SIZE_ERROR;
		}
		if (out_data) {
			memcpy(out_data, data, recv_len - 2);
			out_data += recv_len - 2;
			*out_len += recv_len - 2;
		}
		in_ptr += this_size;
	} while (in_ptr < in_data + in_len);
	while (*sw >> 8 == 0x61) {
		APDU apdu;
		unsigned char data[261];
		unsigned long recv_len = sizeof(data);

		if (1) {
			LogInfo("The card indicates there is %d bytes more data for us.\n", *sw & 0xff);
		}

		memset(apdu.raw, 0, sizeof(apdu.raw));
		apdu.st.ins = 0xc0;
		res = _send_data(state, &apdu, data, &recv_len, sw);
		if (res != YKPIV_OK) {
			return res;
		}
		else if (*sw != SW_SUCCESS && *sw >> 8 != 0x61) {
			return YKPIV_OK;
		}
		if (*out_len + recv_len - 2 > max_out) {
			LogInfo("Output buffer to small, wanted to write %lu, max was %lu.", *out_len + recv_len - 2, max_out);
		}
		if (out_data) {
			memcpy(out_data, data, recv_len - 2);
			out_data += recv_len - 2;
			*out_len += recv_len - 2;
		}
	}

	/*rc = SCardEndTransaction(state->card, SCARD_LEAVE_CARD);
	if (rc != SCARD_S_SUCCESS) {
	if (state->verbose) {
	fprintf(stderr, "error: Failed to end pcsc transaction, rc=%08lx\n", rc);
	}
	return YKPIV_PCSC_ERROR;
	}*/
	return YKPIV_OK;
}

static ykpiv_rc _change_pin_internal(ykpiv_state *state, int action, const char * current_pin, size_t current_pin_len, const char * new_pin, size_t new_pin_len, int *tries) {
	int sw;
	unsigned char templ[] = { 0, YKPIV_INS_CHANGE_REFERENCE, 0, 0x80 };
	unsigned char indata[0x10];
	unsigned char data[0xff];
	unsigned long recv_len = sizeof(data);
	ykpiv_rc res;

	LogInfo("_change_pin_internal");

	if (current_pin_len > 8) {
		return YKPIV_SIZE_ERROR;
	}
	if (new_pin_len > 8) {
		return YKPIV_SIZE_ERROR;
	}
	if (action == CHREF_ACT_UNBLOCK_PIN) {
		templ[1] = YKPIV_INS_RESET_RETRY;
	}
	else if (action == CHREF_ACT_CHANGE_PUK) {
		templ[3] = 0x81;
	}
	memcpy(indata, current_pin, current_pin_len);
	if (current_pin_len < 8) {
		memset(indata + current_pin_len, 0xff, 8 - current_pin_len);
	}
	memcpy(indata + 8, new_pin, new_pin_len);
	if (new_pin_len < 8) {
		memset(indata + 8 + new_pin_len, 0xff, 8 - new_pin_len);
	}
	res = _transfer_data(state, templ, indata, sizeof(indata), data, &recv_len, &sw);
	if (res != YKPIV_OK) {
		return res;
	}
	else if (sw != SW_SUCCESS) {
		if ((sw >> 8) == 0x63) {
			*tries = sw & 0xf;
			return YKPIV_WRONG_PIN;
		}
		else if (sw == SW_ERR_AUTH_BLOCKED) {
			return YKPIV_PIN_LOCKED;
		}
		else {
			if (1) {
				LogInfo("Failed changing pin, token response code: %x.\n", sw);
			}
			return YKPIV_GENERIC_ERROR;
		}
	}
	return YKPIV_OK;
}

ykpiv_rc _change_pin(ykpiv_state *state, const char * current_pin, size_t current_pin_len, const char * new_pin, size_t new_pin_len, int *tries) {
	return _change_pin_internal(state, CHREF_ACT_CHANGE_PIN, current_pin, current_pin_len, new_pin, new_pin_len, tries);
}


int main(void)
{
	ykpiv_rc	rc = 0;
	ykpiv_state	*state;
	int			verbosity=0;
	int			retries = 0;

	printf("ykpiv_init\n");
	if (ykpiv_init(&state, verbosity) != YKPIV_OK) {
		fprintf(stderr, "Failed initializing library.\n");
		return 1;
	}

	printf("ykpiv_connect\n");
	rc = ykpiv_connect(state, NULL);//"Yubico Yubikey 4 CCID 0"
	if (rc != YKPIV_OK) {
		fprintf(stderr, "Failed ykpiv_connect.  rc=%d\n", rc);
		return 1;
	}

#if 0
	printf("ykpiv_verify\n");
	retries = 0;
	rc = ykpiv_verify(state, "YubicoRu", &retries);
	if (rc != YKPIV_OK) {
		fprintf(stderr, "Failed ykpiv_verify. retries=%d rc=%d\n", retries, rc);
		return 1;
	}
#endif

	printf("_change_pin\n");
	retries = 0;
	const char* pwd_a = "aaaaaaaa";
	const char* pwd_b = "bbbbbbbb";
	rc = _change_pin(state, pwd_b, 8, pwd_a, 8, &retries);
	if (rc != YKPIV_OK) {
		fprintf(stderr, "Failed ykpiv_change_pin. retries=%d rc=%d\n", retries, rc);
		return 1;
	}

	printf("\n\nALL PASSED\n");
	ykpiv_done(state);
	return 0;
}