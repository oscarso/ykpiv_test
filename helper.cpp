//#include "stdafx.h"
#include "../cpplogger/cpplogger.h"
#include "helper.h"
#include "cardfilesys.h"
#include <wincrypt.h>


#define	_USING_MSCAPI_	1
#define	_USING_OPENSSL_	(!_USING_MSCAPI_)
#if _USING_OPENSSL_
/*
	Manually set your MSVC project to use the followings:
	https://slproweb.com/products/Win32OpenSSL.html
	Tested with Win64OpenSSL-1_1_0b.exe with 33MB in size
*/
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#endif


#define	SZ_GUID_CARDID		16
#define	CHUID_GUID_OFFS		29

CPPLOGGER::CPPLogger*		logger = NULL;


DWORD	ykrc2mdrc(const ykpiv_rc ykrc) {
	DWORD	dwRet;
	switch (ykrc) {
	case YKPIV_OK:						dwRet = SCARD_S_SUCCESS;
		if (logger) { logger->TraceInfo("ykrc2mdrc: YKPIV_OK -> SCARD_S_SUCCESS"); }
		break;
	case YKPIV_MEMORY_ERROR:			dwRet = SCARD_E_NO_MEMORY;
		if (logger) { logger->TraceInfo("ykrc2mdrc: YKPIV_MEMORY_ERROR -> SCARD_E_NO_MEMORY"); }
		break;
	case YKPIV_PCSC_ERROR:				dwRet = SCARD_F_INTERNAL_ERROR;
		if (logger) { logger->TraceInfo("ykrc2mdrc: YKPIV_PCSC_ERROR -> SCARD_F_INTERNAL_ERROR"); }
		break;
	case YKPIV_SIZE_ERROR:				dwRet = SCARD_E_INVALID_PARAMETER;
		if (logger) { logger->TraceInfo("ykrc2mdrc: YKPIV_SIZE_ERROR -> SCARD_E_INVALID_PARAMETER"); }
		break;
	case YKPIV_APPLET_ERROR:			dwRet = SCARD_F_INTERNAL_ERROR;
		if (logger) { logger->TraceInfo("ykrc2mdrc: YKPIV_APPLET_ERROR -> SCARD_F_INTERNAL_ERROR"); }
		break;
	case YKPIV_AUTHENTICATION_ERROR:	dwRet = SCARD_W_CARD_NOT_AUTHENTICATED;
		if (logger) { logger->TraceInfo("ykrc2mdrc: YKPIV_AUTHENTICATION_ERROR -> SCARD_W_CARD_NOT_AUTHENTICATED"); }
		break;
	case YKPIV_RANDOMNESS_ERROR:		dwRet = SCARD_F_INTERNAL_ERROR;
		if (logger) { logger->TraceInfo("ykrc2mdrc: YKPIV_RANDOMNESS_ERROR -> SCARD_F_INTERNAL_ERROR"); }
		break;
	case YKPIV_GENERIC_ERROR:			dwRet = SCARD_F_INTERNAL_ERROR;
		if (logger) { logger->TraceInfo("ykrc2mdrc: YKPIV_GENERIC_ERROR -> SCARD_F_INTERNAL_ERROR"); }
		break;
	case YKPIV_KEY_ERROR:				dwRet = SCARD_F_INTERNAL_ERROR;
		if (logger) { logger->TraceInfo("ykrc2mdrc: YKPIV_KEY_ERROR -> SCARD_F_INTERNAL_ERROR"); }
		break;
	case YKPIV_PARSE_ERROR:				dwRet = SCARD_E_INVALID_PARAMETER;
		if (logger) { logger->TraceInfo("ykrc2mdrc: YKPIV_PARSE_ERROR -> SCARD_E_INVALID_PARAMETER"); }
		break;
	case YKPIV_WRONG_PIN:				dwRet = SCARD_W_WRONG_CHV;
		if (logger) { logger->TraceInfo("ykrc2mdrc: YKPIV_WRONG_PIN -> SCARD_W_WRONG_CHV"); }
		break;
	case YKPIV_INVALID_OBJECT:			dwRet = SCARD_F_INTERNAL_ERROR;
		if (logger) { logger->TraceInfo("ykrc2mdrc: YKPIV_INVALID_OBJECT -> SCARD_F_INTERNAL_ERROR"); }
		break;
	case YKPIV_ALGORITHM_ERROR:			dwRet = SCARD_F_INTERNAL_ERROR;
		if (logger) { logger->TraceInfo("ykrc2mdrc: YKPIV_ALGORITHM_ERROR -> SCARD_F_INTERNAL_ERROR"); }
		break;
	case YKPIV_PIN_LOCKED:				dwRet = SCARD_W_CHV_BLOCKED;
		if (logger) { logger->TraceInfo("ykrc2mdrc: YKPIV_PIN_LOCKED -> SCARD_W_CHV_BLOCKED"); }
		break;
	default:							dwRet = SCARD_F_UNKNOWN_ERROR;
		if (logger) { logger->TraceInfo("ykrc2mdrc: %d -> SCARD_F_UNKNOWN_ERROR", ykrc); }
	}
	return dwRet;
}


#define RSA_PKCS1_PADDING_SIZE	11
DWORD appendPaddingPKCS1v15(
	unsigned char			*to,
	int						tlen,
	const unsigned char		*from,
	int						flen
)
{
	int j;
	unsigned char *p;

	if (flen > (tlen - RSA_PKCS1_PADDING_SIZE)) {
		logger->TraceInfo("appendPaddingPKCS1v15: size error");
		return SCARD_E_INVALID_PARAMETER;
	}

	p = (unsigned char *)to;

	*(p++) = 0;
	*(p++) = 1;	/* Private Key BT (Block Type) */

	/* pad out with 0xff data */
	j = tlen - 3 - flen;
	memset(p, 0xff, j);
	p += j;
	*(p++) = '\0';
	memcpy(p, from, (unsigned int)flen);
	return SCARD_S_SUCCESS;
}


#if VERIFY_SIGNATURE_USING_OPENSSL
int base64Encode(const unsigned char* buffer, size_t length, char** b64text) {
	BIO *bio, *b64;
	BUF_MEM *bufferPtr;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
	BIO_write(bio, buffer, (int)length);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);

	*b64text = (*bufferPtr).data;

	return (0); //success
}


/*
	After rsa_public_key.pem has been generated, manually copy the bytes and Base 64 encoded it online.
	Paste the Base 64 result back into rsa_public_key.pem
*/
void writeRSAPublicKey2File(RSA* r, const unsigned char key) {
	char filename[MAX_PATH];
	const char	begin[] = "-----BEGIN PUBLIC KEY-----";
	const char	end[] = "-----END PUBLIC KEY-----";
	const char	prefix[] = "30820122300D06092A864886F70D01010105000382010F003082010A0282010100";
	const char	postfix[] = "0203010001";
	char*		pBuf;
	size_t		bufNLen;
	FILE*		fpN;

	snprintf(filename, MAX_PATH, "C:\\Logs\\rsa_public_key_%x.pem", key);
	pBuf = BN_bn2hex(r->n);
	if (logger) { logger->TraceInfo("writeRSAPublicKey2File"); }
	fpN = fopen(filename, "w");
	bufNLen = fwrite(begin, sizeof(char), sizeof(begin), fpN);
	bufNLen = fwrite(prefix, sizeof(char), sizeof(prefix), fpN);
	bufNLen = RSA_size(r);
	bufNLen = fwrite(pBuf, sizeof(char), bufNLen*2, fpN);
	bufNLen = fwrite(postfix, sizeof(char), sizeof(postfix), fpN);
	bufNLen = fwrite(end, sizeof(char), sizeof(end), fpN);
	fclose(fpN);
}
#endif


/*
	Note: this depends on SZ_MAX_LEN in cardfilesys.h
*/
DWORD	getLength(unsigned char* pBuf) {
	return *((DWORD *)&pBuf[0]);
}


int	getDataOffset(const BYTE bContainerIndex, const DWORD dwKeySpec) {
	/*
		If 1 key container can hold 2 key pairs (AT_SIGNATURE and AT_KEYEXCHANGE):
		return YKPIV_OBJ_RSAPUBKEYBLOB_OFFSET + ((bContainerIndex * MAX_KEY_PER_CONTAINER) + (dwKeySpec - 1))

		If 1 key container can only hold 1 key pairs (AT_SIGNATURE or AT_KEYEXCHANGE):
		return YKPIV_OBJ_RSAPUBKEYBLOB_OFFSET + bContainerIndex
	*/
	return YKPIV_OBJ_RSAPUBKEYBLOB_OFFSET + bContainerIndex;
}


ykpiv_rc selectAppletPiv(ykpiv_state *state) {
	APDU apdu;
	unsigned char data[0xff];
	unsigned long recv_len = sizeof(data);
	int sw;
	ykpiv_rc res = YKPIV_OK;

	if (logger) { logger->TraceInfo("selectAppletPiv: _send_data"); }

	memset(apdu.raw, 0, sizeof(apdu));
	apdu.st.ins = 0xa4;
	apdu.st.p1 = 0x04;
	apdu.st.lc = sizeof(aid);
	memcpy(apdu.st.data, aid, sizeof(aid));

	if ((res = _send_data(state, &apdu, data, &recv_len, &sw)) != YKPIV_OK) {
		if (logger) { logger->TraceInfo("selectAppletPiv: Failed communicating with card: %d", res); }
	}
	else if (sw == SW_SUCCESS) {
		res = YKPIV_OK;
	}
	else {
		if (logger) { logger->TraceInfo("selectAppletPiv: Failed selecting application: %04x\n", sw); }
	}
	if (logger) { logger->TraceInfo("selectAppletPiv returns %x\n", res); }
	return res;
}


ykpiv_rc selectAppletYubiKey(ykpiv_state *state) {
	APDU apdu;
	unsigned char data[0xff];
	unsigned long recv_len = sizeof(data);
	int sw;
	unsigned const char yk_applet[] = { 0xa0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x01 };
	ykpiv_rc res = YKPIV_OK;

	if (logger) { logger->TraceInfo("selectAppletYubiKey: _send_data"); }

	memset(apdu.raw, 0, sizeof(apdu));
	apdu.st.ins = 0xa4;
	apdu.st.p1 = 0x04;
	apdu.st.lc = sizeof(yk_applet);
	memcpy(apdu.st.data, yk_applet, sizeof(yk_applet));

	if ((res = _send_data(state, &apdu, data, &recv_len, &sw)) != YKPIV_OK) {
		if (logger) { logger->TraceInfo("selectAppletYubiKey: Failed communicating with card: %d", res); }
	}
	else if (sw == SW_SUCCESS) {
		res = YKPIV_OK;
	}
	else {
		if (logger) { logger->TraceInfo("selectAppletYubiKey: Failed selecting application: %04x\n", sw); }
	}
	if (logger) { logger->TraceInfo("selectAppletYubiKey returns %x\n", res); }
	return res;
}


BOOL shouldSelectAppletPiv(ykpiv_state *state) {
#if 0
	int tries = 0;
	ykpiv_rc ykrc = ykpiv_verify(state, NULL, &tries);
	if (logger) { logger->TraceInfo("shouldSelectAppletPiv: ykpiv_verify returns ykrc=%d\n", ykrc); }
	return (ykrc != YKPIV_OK);
#else
	return TRUE;
#endif
}


static ykpiv_rc _send_data(ykpiv_state *state, APDU *apdu,
	unsigned char *data, unsigned long *recv_len, int *sw) {
	long rc;
	unsigned int send_len = (unsigned int)apdu->st.lc + 5;

	if (logger) {
		logger->TraceInfo("_send_data");
		logger->TraceInfo("Data Sent:");
		logger->PrintBuffer(apdu->raw, send_len);
	}

	rc = SCardTransmit(state->card, SCARD_PCI_T1, apdu->raw, send_len, NULL, data, recv_len);
	if (rc != SCARD_S_SUCCESS) {
		if (logger) { logger->TraceInfo("error: SCardTransmit failed, rc=%08lx\n", rc); }
		return YKPIV_PCSC_ERROR;
	}

	if (logger) {
		logger->TraceInfo("Data Received:");
		logger->PrintBuffer(data, *recv_len);
	}
	if (*recv_len >= 2) {
		*sw = (data[*recv_len - 2] << 8) | data[*recv_len - 1];
	}
	else {
		*sw = 0;
	}
	return YKPIV_OK;
}


int getRetryCount(ykpiv_state *state) {
	int tries = 0;
	ykpiv_rc ykrc = ykpiv_verify(state, NULL, &tries);
	if (logger) { logger->TraceInfo("getRetryCount: ykpiv_verify returns ykrc=%d\n", ykrc); }
	if (YKPIV_OK == ykrc) {
		return tries;
	}
	return -1;
}


ykpiv_rc authenticatePin(
	ykpiv_state*	state,
	unsigned char*	pPin,
	unsigned long	pinLen,
	unsigned long*	pRetry
)
{
	ykpiv_rc	ykrc;
  char		key[24] = { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08 };
	char		pin[9] = { 0 };
	int			tries = 0;

 // NOTE: We have to check if the PIV applet is selected here.  Sometimes the multithreaded basecsp/ksp 
 // will make oob calls that end up changing the applet or resetting the card after CardAcquireContext
 // (and implicit selection of the PIV applet) has completed.
 if (shouldSelectAppletPiv(state)) {
		ykrc = selectAppletPiv(state);
	}

	ykrc = ykpiv_authenticate(state, (const unsigned char *)key);
	if (ykrc != YKPIV_OK) {
		return ykrc;
	}

#if 1 //Test generateKeyPairs
	BYTE			blobPublic[2000];
	unsigned long	blobLen = sizeof(blobPublic);

	for (int i = 1; i <= 4; i++) {
		ykrc = generateKeyPairs(
			state,
			(i % 2 == 0) ? SLOT_SIGN : SLOT_AUTH_PIV,
			AT_SIGNATURE,
			YKPIV_ALGO_RSA2048,
			2048,
			YKPIV_PINPOLICY_DEFAULT,
			YKPIV_TOUCHPOLICY_DEFAULT,
			(LPBYTE)&blobPublic,
			&blobLen
		);
		if (logger) { logger->TraceInfo("authenticatePin: generateKeyPairs(%s) #%d returns ykrc=%d\n", ((i % 2 == 0) ? "SLOT_SIGN" : "SLOT_AUTH_PIV"), i, ykrc); }
	}
#endif

	memcpy(pin, (const char *)pPin, (pinLen > 8) ? 8 : pinLen);
	ykrc = ykpiv_verify(state, (const char *)pin, &tries);
	if (logger) { logger->TraceInfo("authenticatePin: ykpiv_verify returns ykrc=%d\n", ykrc); }
	if (YKPIV_OK != ykrc) {
		return ykrc;
	}

    //TODO: incorporate keyed hash of mgm key from PIV Manager

#if 1 //Test ykpiv_sign_data
	unsigned char pt[256];
	unsigned char sig[256];
	size_t        sigLen = sizeof(sig);

	for (int i = 1; i <= 4; i++) {
		ykrc = ykpiv_sign_data(
			state,
			pt, sizeof(pt),
			sig, &sigLen,
			YKPIV_ALGO_RSA2048,
			SLOT_SIGN
		);
		if (logger) { logger->TraceInfo("authenticatePin: ykpiv_sign_data #%d returns ykrc=%d\n", i, ykrc); }
	}
#endif

	if (pRetry) {
		*pRetry = (unsigned int)getRetryCount(state);
	}

	return ykrc;
}


ykpiv_rc getSerialNumber(ykpiv_state *state, char* pSerial) {
	ykpiv_rc		res = YKPIV_OK;
	APDU			apdu;
	int				sw;
	unsigned char	data[0xff];
	unsigned long	recv_len = sizeof(data);
	unsigned const char	get_serial[] = { 0x00, 0x01, 0x10, 0x00 };
	union {
		unsigned int ui;
		unsigned char uc[4];
	} uSerial;

	if (logger) { logger->TraceInfo("getSerialNumber"); }

	memset(apdu.raw, 0, sizeof(apdu.raw));
	memcpy(apdu.raw, get_serial, sizeof(get_serial));

	if ((res = _send_data(state, &apdu, data, &recv_len, &sw)) != YKPIV_OK) {
		if (logger) { logger->TraceInfo("getSerialNumber: Failed communicating with card: %d", res); }
	}
	else if (sw == SW_SUCCESS) {
		res = YKPIV_OK;
		uSerial.uc[0] = data[3];
		uSerial.uc[1] = data[2];
		uSerial.uc[2] = data[1];
		uSerial.uc[3] = data[0];
		if (logger) { logger->TraceInfo("getSerialNumber: uSerial.ui = %u", uSerial.ui); }
		memset(data, 0, sizeof(data));
		sprintf((char *)data, "%u", uSerial.ui);
		size_t len = strlen((const char *)data);
		memcpy(pSerial, data, len);
		pSerial[len] = 0;
		return YKPIV_OK;
	}
	else {
		if (logger) { logger->TraceInfo("getSerialNumber: Failed selecting application: %04x\n", sw); }
	}

	return YKPIV_GENERIC_ERROR;
}


ykpiv_rc getChuid(ykpiv_state *state, unsigned char* pCardID) {
	ykpiv_rc		ykrc = YKPIV_OK;
	unsigned char	buf[3072];
	unsigned long	buflen = sizeof(buf) - 1;

	memset(buf, 0, sizeof(buf));

	ykrc = ykpiv_fetch_object(state, YKPIV_OBJ_CHUID, buf, &buflen);
	if (ykrc != YKPIV_OK || 0 == buflen) {
		logger->TraceInfo("getChuid: ykpiv_fetch_object failed. ykrc=%d  buflen=%d", ykrc, buflen);
		ykrc = YKPIV_PCSC_ERROR;
	}
	memcpy(pCardID, &buf[CHUID_GUID_OFFS], SZ_GUID_CARDID);
	return ykrc;
}


/*
	This function cannot be called by CardAcquireContext
	since pCardData->pvCacheContext is not yet initialized
*/
ykpiv_rc getUUID(ykpiv_state *state, PCARD_DATA pCardData, UUID* pUUID) {
	ykpiv_rc ykrc = YKPIV_OK;
	DWORD    dwRet = NO_ERROR;
	PBYTE    pbTmpLookup = NULL;
	PBYTE    pbTmpAdd = NULL;
	DWORD    cbTmpLen = 0;

	if (logger) { logger->TraceInfo("getUUID"); }

	//check cache for UUID first
	dwRet = pCardData->pfnCspCacheLookupFile(pCardData->pvCacheContext, L"CP_CARD_UUID", 0, &pbTmpLookup, &cbTmpLen);
	if (SCARD_S_SUCCESS == dwRet) {
		//found UUID, return
		memcpy(pUUID, (UUID *)pbTmpLookup, cbTmpLen);
		ykrc = YKPIV_OK;
		if (logger) { logger->TraceInfo("getUUID - found UUID, return"); }
		goto EXIT;
	}

	//if UUID NOT found, convert it from cardid, write cache and return
	ykrc = cardId2UUID(state, state->cardid, pUUID);
	if (YKPIV_OK != ykrc) {
		goto EXIT;
	}

	//write cache
	pbTmpAdd = (PBYTE)pCardData->pfnCspAlloc(sizeof(UUID));
	if (!pbTmpAdd) {
		ykrc = YKPIV_MEMORY_ERROR;
		goto EXIT;
	}
	CopyMemory(pbTmpAdd, pUUID, sizeof(UUID));
	dwRet = pCardData->pfnCspCacheAddFile(pCardData->pvCacheContext, L"CP_CARD_UUID", 0, pbTmpAdd, sizeof(UUID));
	if (NO_ERROR != dwRet) {
		//no need to report error if write cache fails here; continue instead
		ykrc = YKPIV_OK;
		if (logger) { logger->TraceInfo("getUUID - pfnCspCacheAddFile FAILS; report no error, and continue"); }
		goto EXIT;
	}

EXIT:
	if (pbTmpLookup) pCardData->pfnCspFree(pbTmpLookup);
	if (pbTmpAdd) pCardData->pfnCspFree(pbTmpAdd);
	return ykrc;
}


/*
	cardId2UUID
	https://msdn.microsoft.com/en-us/library/windows/desktop/aa373931(v=vs.85).aspx
*/
ykpiv_rc cardId2UUID(ykpiv_state *state, unsigned char* pCardID, UUID* pUUID) {
	unsigned char	chuid[16];
	ykpiv_rc		ykrc = YKPIV_OK;

	memset(chuid, 0, sizeof(chuid));
	memcpy(chuid, pCardID, sizeof(chuid));

	//Data1 - first 8 hexadecimal digits of the GUID
	unsigned long ulTemp = chuid[0];
	ulTemp = ulTemp << 24;
	pUUID->Data1 |= ulTemp;
	ulTemp = chuid[1];
	ulTemp = ulTemp << 16;
	pUUID->Data1 |= ulTemp;
	ulTemp = chuid[2];
	ulTemp = ulTemp << 8;
	pUUID->Data1 |= ulTemp;
	ulTemp = chuid[3];
	pUUID->Data1 |= ulTemp;

	//Data2 - the first group of 4 hexadecimal digits
	unsigned short usTemp = chuid[4];
	usTemp = usTemp << 8;
	pUUID->Data2 |= usTemp;
	usTemp = chuid[5];
	pUUID->Data2 |= usTemp;

	//Data3 - the second group of 4 hexadecimal digits
	usTemp = chuid[6];
	usTemp = usTemp << 8;
	pUUID->Data3 |= usTemp;
	usTemp = chuid[7];
	pUUID->Data3 |= usTemp;

	//Data4 - Array of 8 bytes.
	//        The first 2 bytes contain the third group of 4 hexadecimal digits.
	//        The remaining 6 bytes contain the final 12 hexadecimal digits
	for (int i = 0; i < 8; i++) {
		pUUID->Data4[i] = chuid[i + 8];
	}

	return ykrc;
}


void getFreeSpace(PCARD_FREE_SPACE_INFO	pcfsi) {
	pcfsi->dwVersion = CARD_FREE_SPACE_INFO_CURRENT_VERSION;
	pcfsi->dwBytesAvailable = CARD_DATA_VALUE_UNKNOWN;
	pcfsi->dwKeyContainersAvailable = CARD_DATA_VALUE_UNKNOWN;
	pcfsi->dwMaxKeyContainers = CARD_DATA_VALUE_UNKNOWN;
	return;
}


void getPinInfo(PPIN_INFO	ppi) {
	//PIN_CACHE_POLICY
	PIN_CACHE_POLICY_TYPE	pcpt = PinCacheNormal;

	//PIN_INFO
	SECRET_TYPE	st = AlphaNumericPinType;
	SECRET_PURPOSE	sp = PrimaryCardPin;
	ppi->dwVersion = PIN_INFO_CURRENT_VERSION;
	ppi->PinType = st;
	ppi->PinPurpose = sp;
	ppi->dwChangePermission = CREATE_PIN_SET(ROLE_USER);
	ppi->dwUnblockPermission = CREATE_PIN_SET(5);
	ppi->PinCachePolicy.dwVersion = PIN_CACHE_POLICY_CURRENT_VERSION;
	ppi->PinCachePolicy.PinCachePolicyType = pcpt;
	ppi->PinCachePolicy.dwPinCachePolicyInfo = 0;
	ppi->dwFlags = 0;

	return;
}


void getCapabilities(PCARD_CAPABILITIES pcc) {
	pcc->dwVersion = CONTAINER_INFO_CURRENT_VERSION;
	pcc->fCertificateCompression = TRUE;
	pcc->fKeyGen = TRUE;

	return;
}


void reverseBuffer(LPBYTE pbData, DWORD cbData)
{
	DWORD i;
	for (i = 0; i<(cbData / 2); i++)
	{
		BYTE t = pbData[i];
		pbData[i] = pbData[cbData - 1 - i];
		pbData[cbData - 1 - i] = t;
	}
}


BOOL isValidKeySize(DWORD dwKeySize) {
	switch (dwKeySize) {
	case 128: return TRUE;
	case 256: return TRUE;
	case 512: return TRUE;
	case 1024: return TRUE;
	case 2048: return TRUE;
	case 4096: return TRUE;
	default:
		return FALSE;
	}
}


#if _USING_OPENSSL_
RSA* CSPPubKeyBlob2OpenSSL(
	LPBYTE			pCspPubKeyBlob,
	DWORD			dwCspPubKeyBlobLen
)
{
	BLOBHEADER*		pBlobHeader = { 0 };
	RSAPUBKEY*		pRsaPubKey = { 0 };
	LPBYTE			pBufWalker = pCspPubKeyBlob;
	RSA*			r = NULL;

	pBlobHeader = (BLOBHEADER *)pBufWalker;
	pBufWalker += sizeof(BLOBHEADER);
	pRsaPubKey = (RSAPUBKEY *)pBufWalker;
	if (0x010001 != pRsaPubKey->pubexp) {
		goto EXIT;//quick and dirty check
	}
	pBufWalker += sizeof(RSAPUBKEY);

	BIGNUM*		bne = BN_new();
	BIGNUM*		bnn = BN_new();
	int			ret;

	ret = BN_set_word(bne, RSA_F4);
	if (ret != 1) {
		r = NULL;
		goto EXIT;
	}

	bnn = BN_bin2bn(&pBufWalker[0], (pRsaPubKey->bitlen/8), bnn);
	if (NULL == bnn) {
		r = NULL;
		goto EXIT;
	}

	RSA_set0_key()

EXIT:
	return r;
}
#endif


ykpiv_rc ykPubKey2CSPPubKeyBlob(
	const DWORD				dwKeySpec,
	const DWORD				dwKeyLenBits,
	const unsigned char*	pykPubKey,
	const unsigned long		ypPubKeyLen,
	LPBYTE					pCspPubKeyBlob,
	unsigned long*			pCspBlobLen
)
{
	ykpiv_rc		ykrc = YKPIV_OK;
	unsigned long	OFFSET_N = 9;
	BLOBHEADER		blobHeader = { 0 };
	RSAPUBKEY		rsaPubKey = { 0 };
	LPBYTE			pBufWalker = pCspPubKeyBlob;
	unsigned long	requiredLen;

	if (logger) {
		logger->TraceInfo("ykPubKey2CSPPubKeyBlob");
		logger->TraceInfo("IN    dwKeySpec: %d", dwKeySpec);
		logger->TraceInfo("IN dwKeyLenBits: %d", dwKeyLenBits);
		logger->TraceInfo("IN  ypPubKeyLen: %d", ypPubKeyLen);
		logger->TraceInfo("IN  *pCspBlobLen: %d", pCspBlobLen ? *pCspBlobLen : -1);
	}

	if ((NULL == pykPubKey)
		||
		(0 == ypPubKeyLen)
		||
		(NULL == pCspBlobLen)
		||
		(ypPubKeyLen < (dwKeyLenBits/8))) {
		return YKPIV_GENERIC_ERROR;
	}

	blobHeader.bType = PUBLICKEYBLOB;
	blobHeader.bVersion = CUR_BLOB_VERSION;
	blobHeader.reserved = 0;
	blobHeader.aiKeyAlg = (dwKeySpec == AT_SIGNATURE) ? CALG_RSA_SIGN : CALG_RSA_KEYX;

	rsaPubKey.magic = 0x31415352;//RSA1
	rsaPubKey.bitlen = dwKeyLenBits;
	rsaPubKey.pubexp = 65537;

	//BLOBHEADER is same as PUBLICKEYSTRUC
	requiredLen = sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) + (rsaPubKey.bitlen / 8);

	if ((*pCspBlobLen == 0) || (*pCspBlobLen < requiredLen)) {
		//Not enough allocated space
		ykrc = YKPIV_SIZE_ERROR;
		*pCspBlobLen = requiredLen;
	}
	if (NULL == pCspPubKeyBlob) {
		//pPubKeyBlob should have been allocated with *pPubKeyBlobLen bytes
		return YKPIV_GENERIC_ERROR;
	}
	*pCspBlobLen = requiredLen;
	memcpy(pBufWalker, &blobHeader, sizeof(BLOBHEADER));
	pBufWalker += sizeof(BLOBHEADER);
	memcpy(pBufWalker, &rsaPubKey, sizeof(RSAPUBKEY));
	pBufWalker += sizeof(RSAPUBKEY);
	memcpy(pBufWalker, &pykPubKey[OFFSET_N], (rsaPubKey.bitlen / 8));

	if (logger) { logger->PrintBuffer(pCspPubKeyBlob, *pCspBlobLen); }

	return ykrc;
}


ykpiv_rc	getContainerInfo(
	PCARD_DATA			pCardData,
	ykpiv_state*		state,
	BYTE				bContainerIndex,
	PCONTAINER_INFO		pContainerInfo,
	DWORD*				pdwDataLen
)
{
	ykpiv_rc	ykrc = YKPIV_OK;
	int			offsetData;

	if ((NULL == pdwDataLen)
		||
		(NULL == state)) {
		return YKPIV_GENERIC_ERROR;
	}

	BYTE			cspPubKeyBlob[1024];
	unsigned long	cspBlobLen = sizeof(cspPubKeyBlob);

	*pdwDataLen =
		sizeof(pContainerInfo->dwVersion) +
		sizeof(pContainerInfo->dwReserved) +
		sizeof(pContainerInfo->cbSigPublicKey) +
		sizeof(pContainerInfo->cbKeyExPublicKey);

	//Version
	pContainerInfo->dwVersion = CONTAINER_INFO_CURRENT_VERSION;

	pContainerInfo->cbSigPublicKey = 0;
	pContainerInfo->pbSigPublicKey = NULL;
	pContainerInfo->cbKeyExPublicKey = 0;
	pContainerInfo->pbKeyExPublicKey = NULL;
	memset(&cspPubKeyBlob, 0, sizeof(cspPubKeyBlob));

	offsetData = getDataOffset(bContainerIndex, 0);
	if (logger) { logger->TraceInfo("getContainerInfo: exportCSPPubKeyBlob(bContainerIndex: %d , offsetData: %x)", bContainerIndex, offsetData); }
	ykrc = exportCSPPubKeyBlob(state, offsetData, (LPBYTE)&cspPubKeyBlob, &cspBlobLen);
	if (YKPIV_OK == ykrc) {
		BLOBHEADER	*pBlobHdr = (BLOBHEADER *)&cspPubKeyBlob[0];
		logger->TraceInfo("getContainerInfo: cspPubKeyBlob");
		logger->PrintBuffer(cspPubKeyBlob, cspBlobLen);
		if (CALG_RSA_SIGN == pBlobHdr->aiKeyAlg) {
			pContainerInfo->cbSigPublicKey = cspBlobLen;
			pContainerInfo->pbSigPublicKey = (PBYTE)pCardData->pfnCspAlloc(cspBlobLen);
			memcpy(pContainerInfo->pbSigPublicKey, cspPubKeyBlob, cspBlobLen);
			*pdwDataLen += pContainerInfo->cbSigPublicKey;
		} else if (CALG_RSA_KEYX == pBlobHdr->aiKeyAlg) {
			pContainerInfo->cbKeyExPublicKey = cspBlobLen;
			pContainerInfo->pbKeyExPublicKey = (PBYTE)pCardData->pfnCspAlloc(cspBlobLen);
			memcpy(pContainerInfo->pbKeyExPublicKey, cspPubKeyBlob, cspBlobLen);
			*pdwDataLen += pContainerInfo->cbKeyExPublicKey;
		}
	}

	return ykrc;
}


ykpiv_rc exportCSPPubKeyBlob(
	ykpiv_state*		state,
	const int			indexPubKey,
	LPBYTE				pbBlobPublic,
	unsigned long*		pBlobLen
)
{
	ykpiv_rc	ykrc = YKPIV_OK;

	if (logger) {
		logger->TraceInfo("exportCSPPubKeyBlob");
		logger->TraceInfo("IN data_addr: %x", indexPubKey);
		logger->TraceInfo("IN *pBlobLen: %d", pBlobLen ? *pBlobLen : -1);
	}

	if (NULL == pBlobLen || 0 == *pBlobLen) {
		logger->TraceInfo("exportCSPPubKeyBlob: bad blob length");
		ykrc = YKPIV_PCSC_ERROR;
		return ykrc;
	}

	unsigned char	pubKey[2048 + SZ_MAX_LEN];
	unsigned long	pubKeyLen = sizeof(pubKey);
	ykrc = ykpiv_fetch_object(state, indexPubKey, pubKey, &pubKeyLen);
	if (ykrc != YKPIV_OK || 0 == pubKeyLen) {
		logger->TraceInfo("exportCSPPubKeyBlob: ykpiv_fetch_object failed. ykrc=%d  pubKeyLen=%d", ykrc, pubKeyLen);
		ykrc = YKPIV_PCSC_ERROR;
		return ykrc;
	}

	*pBlobLen = getLength(&pubKey[0]);
	memcpy(pbBlobPublic, &pubKey[SZ_MAX_LEN], *pBlobLen);
	if (logger) { logger->PrintBuffer(pbBlobPublic, *pBlobLen); }

	return ykrc;
}


ykpiv_rc importKeyPairs(
	ykpiv_state*			state,
	const unsigned char		key,
	const LPBYTE			pbBlobPrivate,
	LPBYTE					pbBlobPublic,
	unsigned long*			pBlobLen
)
{
	ykpiv_rc	ykrc = YKPIV_OK;
	LPBYTE		pbModulus, pbPrime1, pbPrime2, pbExp1, pbExp2, pbCoeff, pbPriExp;
	DWORD		cbModulus, cbPrime1, cbPrime2, cbExp1, cbExp2, cbCoeff, cbPriExp;
	RSAPUBKEY*	pRsa = (RSAPUBKEY *)(pbBlobPrivate + sizeof(BLOBHEADER));
	LPBYTE		pbKeyData = pbBlobPrivate + sizeof(BLOBHEADER) + sizeof(RSAPUBKEY);

	if (logger) {
		logger->TraceInfo("importKeyPairs");
		logger->TraceInfo("IN       key: %x", key);
	}

	cbModulus = (pRsa->bitlen + 7) / 8;
	cbPriExp = cbModulus;
	cbPrime1 = cbPrime2 = cbExp1 = cbExp2 = cbCoeff = cbModulus / 2;
	pbModulus = pbKeyData;
	pbPrime1 = pbModulus + cbModulus;
	pbPrime2 = pbPrime1 + cbPrime1;
	pbExp1 = pbPrime2 + cbPrime2;
	pbExp2 = pbExp1 + cbExp1;
	pbCoeff = pbExp2 + cbExp2;
	pbPriExp = pbCoeff + cbCoeff;

	reverseBuffer(pbModulus, cbModulus);
	reverseBuffer(pbPrime1, cbPrime1);
	reverseBuffer(pbPrime2, cbPrime2);
	reverseBuffer(pbExp1, cbExp1);
	reverseBuffer(pbExp2, cbExp2);
	reverseBuffer(pbCoeff, cbCoeff);
	reverseBuffer(pbPriExp, cbPriExp);

	//if (logger) { logPrivateKeyBlob(pbBlob); }

	unsigned char	algo = (pRsa->bitlen == 1024) ? YKPIV_ALGO_RSA1024 : YKPIV_ALGO_RSA2048;

	ykrc = ykpiv_import_private_key(
		state,
		key,
		algo,
		pbPrime1, cbPrime1,
		pbPrime2, cbPrime2,
		pbExp1, cbExp1,
		pbExp2, cbExp2,
		pbCoeff, cbCoeff,
		NULL, 0,
		YKPIV_PINPOLICY_DEFAULT,
		YKPIV_TOUCHPOLICY_DEFAULT
	);
	if (ykrc != YKPIV_OK) {
		logger->TraceInfo("importKeyPairs: ykpiv_import_private_key failed with error %d", ykrc);
		return ykrc;
	}

	/*
		Note:
		Treat this imported key pairs as AT_KEYEXCHANGE for now,
		it should be treated as both AT_KEYEXCHANGE and AT_SIGNATURE
	*/
	ykrc = ykPubKey2CSPPubKeyBlob(AT_KEYEXCHANGE, pRsa->bitlen, (unsigned char *)pbModulus, cbModulus, pbBlobPublic, pBlobLen);
	if (YKPIV_OK != ykrc) {
		logger->TraceInfo("importKeyPairs: ykPubKey2CSPPubKeyBlob failed with error %d", ykrc);
		return ykrc;
	}

	return ykrc;
}


ykpiv_rc generateKeyPairs(
	ykpiv_state*			state,
	const unsigned char		key,
	const DWORD				dwKeySpec,
	const unsigned char		algorithm,
	const unsigned long		keyLenBits,
	const unsigned char		pin_policy,
	const unsigned char		touch_policy,
	LPBYTE					pbBlobPublic,
	unsigned long*			pBlobLen
)
{
	unsigned char data_in[11];
	unsigned char *ptr_in = data_in;
	unsigned char templ[] = { 0, YKPIV_INS_GENERATE_ASYMMETRIC, 0, 0 };
	unsigned char	pubKey[1024];
	unsigned long	pubKeyLen = sizeof(pubKey) - 1;
	//unsigned char *certptr;
	//int len_bytes;
	int sw;

	ykpiv_rc	ykrc = YKPIV_OK;

	if (logger) { logger->TraceInfo("generateKeyPairs"); }

	if (pin_policy != YKPIV_PINPOLICY_DEFAULT &&
		pin_policy != YKPIV_PINPOLICY_NEVER &&
		pin_policy != YKPIV_PINPOLICY_ONCE &&
		pin_policy != YKPIV_PINPOLICY_ALWAYS)
		return YKPIV_GENERIC_ERROR;

	if (touch_policy != YKPIV_TOUCHPOLICY_DEFAULT &&
		touch_policy != YKPIV_TOUCHPOLICY_NEVER &&
		touch_policy != YKPIV_TOUCHPOLICY_ALWAYS &&
		touch_policy != YKPIV_TOUCHPOLICY_CACHED)
		return YKPIV_GENERIC_ERROR;

	templ[3] = key;

	*ptr_in++ = 0xac;
	*ptr_in++ = 3;
	*ptr_in++ = YKPIV_ALGO_TAG;
	*ptr_in++ = 1;

	switch (keyLenBits) {
	case 2048:
		if (YKPIV_ALGO_RSA2048 == algorithm)
			*ptr_in++ = YKPIV_ALGO_RSA2048;
		else
			return YKPIV_GENERIC_ERROR;
		break;

	case 1024:
		if (YKPIV_ALGO_RSA1024 == algorithm)
			*ptr_in++ = YKPIV_ALGO_RSA1024;
		else
			return YKPIV_GENERIC_ERROR;
		break;

	default:
		return YKPIV_GENERIC_ERROR;
	}

	// PIN policy and touch
	if (YKPIV_PINPOLICY_DEFAULT != pin_policy) {
		data_in[1] += 3;
		*ptr_in++ = YKPIV_PINPOLICY_TAG;
		*ptr_in++ = 0x01;
		*ptr_in++ = pin_policy;
	}

	if (YKPIV_TOUCHPOLICY_DEFAULT != touch_policy) {
		data_in[1] += 3;
		*ptr_in++ = YKPIV_TOUCHPOLICY_TAG;
		*ptr_in++ = 0x01;
		*ptr_in++ = touch_policy;
	}

	if (ykpiv_transfer_data(state, templ, data_in, (long)(ptr_in - data_in), pubKey, &pubKeyLen, &sw) != YKPIV_OK ||
		sw != 0x9000)
		return YKPIV_GENERIC_ERROR;

	if (logger) {
		logger->TraceInfo("generateKeyPairs: RSA public key returned, and to be converted to MS PubKeyBlob:");
		logger->PrintBuffer(&pubKey, pubKeyLen);
	}

	//Convert Yubico public key format to MS CSP PUBLICKEYBLOB, and return
	ykrc = ykPubKey2CSPPubKeyBlob(dwKeySpec, keyLenBits, (unsigned char *)&pubKey, pubKeyLen, pbBlobPublic, pBlobLen);
	if (YKPIV_OK != ykrc) {
		logger->TraceInfo("generateKeyPairs: ykPubKey2CSPPubKeyBlob failed with error %d", ykrc);
		return ykrc;
	}

#if VERIFY_SIGNATURE
	BOOL	bIsValidBlob = verifySignature(state, key, &pubKeyBlob[SZ_MAX_LEN], pubKeyBlobLen);
	if (!bIsValidBlob) {
		if (logger) { logger->TraceInfo("generateKeyPairs: verifySignature fails"); }
	}
#endif

	/*
	// Create a new empty certificate for the key
	recv_len = sizeof(data);
	if ((rv = do_create_empty_cert(data, recv_len, rsa, data, &recv_len)) != CKR_OK)
	return rv;

	if (recv_len < 0x80)
	len_bytes = 1;
	else if (recv_len < 0xff)
	len_bytes = 2;
	else
	len_bytes = 3;

	certptr = data;
	memmove(data + len_bytes + 1, data, recv_len);

	*certptr++ = 0x70;
	certptr += set_length(certptr, recv_len);
	certptr += recv_len;
	*certptr++ = 0x71;
	*certptr++ = 1;
	*certptr++ = 0;
	*certptr++ = 0xfe;
	*certptr++ = 0;

	// Store the certificate into the token
	if (ykpiv_save_object(state, key_to_object_id(key), data, (size_t)(certptr - data)) != YKPIV_OK)
	return CKR_DEVICE_ERROR;
	*/

	return YKPIV_OK;
}


#if VERIFY_SIGNATURE
/*
	Verifying Signature
	 Input: MS-CAPI public key blob and its blob length
	Output: TRUE if the public key blob is valid according to MS Enhanced CSP, and it can be used to verify signature
			FALSE otherwise
*/
BOOL	verifySignature(
	ykpiv_state*		state,
	const unsigned char	key,
	const LPBYTE		pPubKeyBlob,
	const unsigned long	blobLen
)
{
	ykpiv_rc	ykrc = YKPIV_OK;
	BOOL		bIsValid = FALSE;
	DWORD		dwErr;
	HCRYPTPROV	hProv = 0;

	if (logger) {
		logger->TraceInfo("verifySignature");
		logger->TraceInfo("verifySignature - pPubKeyBlob:");
		logger->PrintBuffer(pPubKeyBlob, blobLen);
	}

	if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_DELETEKEYSET)) {
		dwErr = GetLastError();
	}
	if (hProv) { CryptReleaseContext(hProv, 0); }

	if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
		dwErr = GetLastError();
		return FALSE;
	}

	//ykpiv_sign_data and CryptVerifySignature
	unsigned char	hash[20];
	DWORD			hashLen = sizeof(hash);
	unsigned char	sig[1024];
	size_t			siglen = sizeof(sig);
	HCRYPTKEY		hNewKey = 0;
	HCRYPTKEY		hPubKey = 0;
	HCRYPTHASH		hHash = 0;
#if VERIFY_SIGNATURE_USING_OPENSSL
	EVP_PKEY		*pk = NULL;
#endif

	if (!CryptCreateHash(hProv, CALG_SHA1, NULL, 0, &hHash)) {
		dwErr = GetLastError();
		bIsValid = FALSE;
		goto EXIT;
	}

	if (!CryptHashData(hHash, (const BYTE *)"0123456789", (DWORD)10, 0)) {
		dwErr = GetLastError();
		bIsValid = FALSE;
		goto EXIT;
	}

	if (!CryptGetHashParam(hHash, HP_HASHVAL, &hash[0], &hashLen, 0)) {
		dwErr = GetLastError();
		bIsValid = FALSE;
		goto EXIT;
	}

	DWORD	dwDataLen = sizeof(DWORD);

#if VERIFY_SIGNATURE_USING_MSCAPI
	if (!CryptGenKey(hProv, AT_SIGNATURE, 0, &hNewKey)) {
		dwErr = GetLastError();
		bIsValid = FALSE;
		goto EXIT;
	}

	BYTE	bufNewPubKey[1024];
	DWORD	bufNewPubKeyLen = sizeof(bufNewPubKey);
	if (!CryptExportKey(hNewKey, 0, PUBLICKEYBLOB, 0, &bufNewPubKey[0], &bufNewPubKeyLen)) {
		dwErr = GetLastError();
		bIsValid = FALSE;
		goto EXIT;
	}
	if (logger) {
		logger->TraceInfo("verifySignature - bufNewPubKey:");
		logger->PrintBuffer(bufNewPubKey, bufNewPubKeyLen);
	}
#endif

#if VERIFY_SIGNATURE_USING_OPENSSL
	if (!CryptImportKey(hProv, pPubKeyBlob, blobLen, 0, 0, &hPubKey)) {
		dwErr = GetLastError();
		bIsValid = FALSE;
		goto EXIT;
	}

	//KP_KEYLEN
	PBYTE	keySizeBits[sizeof(DWORD)];
	memset(keySizeBits, 0, sizeof(keySizeBits));
	if (!CryptGetKeyParam(hPubKey, KP_KEYLEN, (PBYTE)&keySizeBits, &dwDataLen, 0)) {
		dwErr = GetLastError();
		bIsValid = FALSE;
		goto EXIT;
	}
	//KP_ALGID
	PBYTE	algID[sizeof(DWORD)];
	DWORD	dwAlgID = sizeof(DWORD);
	memset(algID, 0, sizeof(algID));
	if (!CryptGetKeyParam(hPubKey, KP_ALGID, (PBYTE)&algID, &dwAlgID, 0)) {
		dwErr = GetLastError();
		bIsValid = FALSE;
		goto EXIT;
	}

	unsigned char	pt_padded[256];
	size_t			pt_paddedLen = 0;

	memset(pt_padded, 0, sizeof(pt_padded));
	memset(sig, 0, sizeof(sig));

	pt_paddedLen = *((size_t *)&keySizeBits) / 8;
	dwErr = appendPaddingPKCS1v15(pt_padded, (int)pt_paddedLen, hash, (int)hashLen);
	if (SCARD_S_SUCCESS != dwErr) {
		if (logger) { logger->TraceInfo("verifySignature: appendPaddingPKCS1v15 failed with error %d", osslrc); }
		bIsValid = FALSE;
		goto EXIT;
	} else {
		if (1024 == pt_paddedLen * 8) {
			memmove(&pt_padded[0], &pt_padded[sizeof(pt_padded) / 2], sizeof(pt_padded) / 2);
		}
		logger->TraceInfo("verifySignature: appendPaddingPKCS1v15 succeed - pt_padded:");
		logger->PrintBuffer(pt_padded, sizeof(pt_padded));
	}

#if 1
	RSA				*r = RSA_new();
	BIGNUM			*bne = BN_new();
	BIGNUM			*bnn = BN_new();
	unsigned char	pt[256];
	int				nlen = (int)pt_paddedLen;
	int				ret;

	ret = BN_set_word(bne, RSA_F4);
	if (ret != 1) {
		bIsValid = FALSE;
		goto EXIT;
	}

	//sizeof(BLOBHEADER) + sizeof(RSAPUBKEY)
	bnn = BN_bin2bn(&pPubKeyBlob[sizeof(BLOBHEADER) + sizeof(RSAPUBKEY)], nlen, bnn);
	if (bnn == NULL) {
		bIsValid = FALSE;
		goto EXIT;
	}
	r->e = bne;
	r->n = bnn;
	r->d = NULL;
	r->dmp1 = NULL;
	r->dmq1 = NULL;
	r->p = NULL;
	r->q = NULL;

	writeRSAPublicKey2File(r, key);
#endif

	ykrc = ykpiv_sign_data(
		state,
		pt_padded, pt_paddedLen,
		sig, &siglen,
		(128 == pt_paddedLen) ? YKPIV_ALGO_RSA1024 : YKPIV_ALGO_RSA2048,
		key
	);
	if (ykrc != YKPIV_OK) {
		logger->TraceInfo("verifySignature: ykpiv_sign_data failed with error %d", ykrc);
		bIsValid = FALSE;
		goto EXIT;
	}
	else {
		logger->TraceInfo("verifySignature: ykpiv_sign_data succeed - sig:");
		logger->PrintBuffer(sig, (const long)siglen);
	}

	memset(pt, 0, sizeof(pt));
	ret = RSA_public_decrypt(nlen, sig, pt, r, RSA_PKCS1_PADDING);
	if (logger) { logger->TraceInfo("pt:"); }
	if (logger) { logger->PrintBuffer(pt, nlen); }
	if (ret == -1) {
		if (logger) { logger->TraceInfo("verifySignature: RSA_public_decrypt - err=%s", ERR_error_string(ERR_get_error(), NULL)); }
		bIsValid = FALSE;
		goto EXIT;
	}
#endif

#if VERIFY_SIGNATURE_USING_MSCAPI
	memset(sig, 0, sizeof(sig));
	siglen = sizeof(sig);
	if (!CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, &sig[0], (DWORD *)&siglen)) {
		dwErr = GetLastError();
		bIsValid = FALSE;
		goto EXIT;
	}
	if (!CryptVerifySignature(hHash, sig, (DWORD)siglen, hNewKey, NULL, 0)) {
		dwErr = GetLastError();
		bIsValid = FALSE;
		goto EXIT;
	}
	
#endif

	bIsValid = TRUE;

EXIT:
#if VERIFY_SIGNATURE_USING_OPENSSL
	if (pk) { EVP_PKEY_free(pk); }
#endif
	if (hNewKey) { CryptDestroyKey(hNewKey); }
	if (hPubKey) { CryptDestroyKey(hPubKey); }
	if (hHash) { CryptDestroyHash(hHash); }
	if (hProv) { CryptReleaseContext(hProv, 0); }
	return bIsValid;
}
#endif


void printCardcf(const CARD_CACHE_FILE_FORMAT* pCardcf) {
	if (logger) {
		logger->TraceInfo("Cache File: cardcf");
		logger->TraceInfo("            bVersion: %d", pCardcf->bVersion);
		logger->TraceInfo("      bPinsFreshness: %d", pCardcf->bPinsFreshness);
		logger->TraceInfo("wContainersFreshness: %d", pCardcf->wContainersFreshness);
		logger->TraceInfo("     wFilesFreshness: %d", pCardcf->wFilesFreshness);
	}
}


/*
	Return key size in bytes
*/
DWORD getKeySize(PCARD_DATA pCardData, BYTE bIndex, DWORD dwKeySpec) {
	return 256; //hardcoded for now
}


BOOL isSupportedPadding(DWORD dwPadding) {
	if ((0 != dwPadding)
		&& (CARD_PADDING_NONE != dwPadding)
		&& (CARD_PADDING_PKCS1 != dwPadding)) {
		return FALSE;
	}
	return TRUE;
}


BOOL isSupportedAlgoID(ALG_ID algID) {
	if ((0 != algID)
		&& (CALG_MD5 != algID)
		&& (CALG_SHA1 != algID)
		&& (CALG_SHA_256 != algID)
		&& (CALG_SHA_384 != algID)
		&& (CALG_SHA_512 != algID)
		&& (CALG_RSA_SIGN != algID)
		&& (CALG_RSA_KEYX != algID)) {
		return FALSE;
	}
	return TRUE;
}


DWORD getHash(
	PCARD_DATA	pCardData,
	ALG_ID		algID,
	PBYTE		pbData,
	DWORD		cbData,
	PBYTE		pbHash,
	DWORD*		pcbHash
)
{
	HCRYPTPROV	hProv = NULL;
	HCRYPTHASH	hHash = NULL;
	DWORD		dwHashLen = 0;
	DWORD		dwErr = SCARD_S_SUCCESS;

	if ((NULL == pCardData)
		|| (NULL == pbData)
		|| (0 == cbData)
		|| (NULL == pcbHash)
		|| (!isSupportedAlgoID(algID))) {
		return SCARD_E_INVALID_PARAMETER;
	}

	if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		dwErr = GetLastError();
		goto EXIT;
	}

	if (!CryptCreateHash(hProv, algID, NULL, 0, &hHash)) {
		dwErr = GetLastError();
		goto EXIT;
	}

	if (!CryptHashData(hHash, (const BYTE *)pbData, cbData, 0)) {
		dwErr = GetLastError();
		goto EXIT;
	}

	if (!CryptGetHashParam(hHash, HP_HASHVAL, NULL, &dwHashLen, 0)) {
		dwErr = GetLastError();
		goto EXIT;
	}

	if (NULL == pbHash) {
		pbHash = (PBYTE)pCardData->pfnCspAlloc(dwHashLen);
		if (NULL == pbHash) {
			dwErr = SCARD_E_NO_MEMORY;
			goto EXIT;
		}
	}
	else {
		if (*pcbHash < dwHashLen) {
			dwErr = SCARD_E_INSUFFICIENT_BUFFER;
			goto EXIT;
		}
	}

	if (!CryptGetHashParam(hHash, HP_HASHVAL, pbHash, &dwHashLen, 0)) {
		dwErr = GetLastError();
		goto EXIT;
	}

	*pcbHash = dwHashLen;

EXIT:
	//release or free resources
	if (hHash) { CryptDestroyHash(hHash); }
	if (hProv) { CryptReleaseContext(hProv, 0); }

	return dwErr;
}


DWORD rsaSign(
	PCARD_DATA		pCardData,
	BYTE			bIndex,
	unsigned char	key,
	ALG_ID			hashAlgID, //CALG_SHA1
	DWORD			dwPadding, //CARD_PADDING_PKCS1
	LPBYTE			pbData,
	DWORD			cbData,
	LPBYTE			pbSig,
	DWORD*			pcbSig
)
{
	DWORD	dwErr = SCARD_S_SUCCESS;
	PBYTE	pbHash = NULL;
	DWORD	cbHash = 0;

	if ((NULL == pCardData)
		|| (!isSupportedAlgoID(hashAlgID))
		|| (!isSupportedPadding(dwPadding))
		|| (NULL == pbData)
		|| (0 == cbData)
		|| (NULL == pcbSig)) {
		return SCARD_E_INVALID_PARAMETER;
	}

	ykpiv_state*	pykState = (ykpiv_state *)pCardData->pvVendorSpecific;
	ykpiv_rc		ykrc;
	unsigned char*	pHashedData = NULL;
	size_t			dwKeySize = getKeySize(pCardData, bIndex, AT_SIGNATURE);
	size_t			hashedDataLen = dwKeySize; //use key size to ensure enough space
	unsigned char*	pPaddedData = NULL;
	size_t			paddedDataLen = 0;

	pHashedData = (LPBYTE)pCardData->pfnCspAlloc(hashedDataLen);
	if (NULL == pHashedData) {
		dwErr = SCARD_E_NO_MEMORY;
		goto EXIT_ERROR;
	}
	ZeroMemory(pHashedData, dwKeySize);

	if (hashAlgID != 0) {
		//sign hash is required
		dwErr = getHash(pCardData, hashAlgID, pbData, cbData, pHashedData, (DWORD *)&hashedDataLen);
		if (SCARD_S_SUCCESS != dwErr)
			goto EXIT_ERROR;
	} else {
		//hashing not needed
		if (cbData > dwKeySize) {
			//if hashing not needed, and data length is larger than sig length, return error
			dwErr = SCARD_E_INVALID_PARAMETER;
			//also return expected key size
			*pcbSig = (DWORD)dwKeySize;
			goto EXIT_ERROR;
		}
		CopyMemory(pHashedData, pbData, cbData);
		hashedDataLen = cbData;
	}

	//padded data
	pPaddedData = (LPBYTE)pCardData->pfnCspAlloc(dwKeySize);
	if (NULL == pPaddedData) {
		dwErr = SCARD_E_NO_MEMORY;
		goto EXIT_ERROR;
	}
	ZeroMemory(pPaddedData, dwKeySize);

	if (CARD_PADDING_NONE == dwPadding) {
		//padding NOT needed
		CopyMemory(pPaddedData, pHashedData, hashedDataLen);
		paddedDataLen = hashedDataLen;
	} else if (CARD_PADDING_PKCS1 == dwPadding) {
		//padding needed
		dwErr = appendPaddingPKCS1v15(pPaddedData, (int)dwKeySize, pHashedData, (int)hashedDataLen);
		if (SCARD_S_SUCCESS != dwErr) {
			goto EXIT_ERROR;
		}
		paddedDataLen = dwKeySize;
	}

	pbSig = (LPBYTE)pCardData->pfnCspAlloc(dwKeySize);
	if (NULL == pbSig) {
		dwErr = SCARD_E_NO_MEMORY;
		goto EXIT_ERROR;
	}
#if 0
	int tries = 0;
	logger->TraceInfo("rsaSign: calling ykpiv_verify ...");
	ykrc = ykpiv_verify(pykState, "aaaaaaaa", &tries);
	if (logger) { logger->TraceInfo("rsaSign: ykpiv_verify returns ykrc=%d\n", ykrc); }
#endif
#if 1
	//sign at 9c
	*pcbSig = dwKeySize * 2;
	logger->TraceInfo("rsaSign: calling ykpiv_sign_data ...");
	ykrc = ykpiv_sign_data(
		pykState,
		pPaddedData, paddedDataLen,
		pbSig, (size_t *)pcbSig,
		(128 == dwKeySize) ? YKPIV_ALGO_RSA1024 : YKPIV_ALGO_RSA2048,
		key //hardcoded for now since we only support default key container
	);
#endif
	if ((ykrc != YKPIV_OK)
		|| (0 == *pcbSig)) {
		logger->TraceInfo("rsaSign: ykpiv_sign_data failed with error %d", ykrc);
		dwErr = ykrc2mdrc(ykrc);
		goto EXIT_ERROR;
	}

EXIT:
	if (pPaddedData) pCardData->pfnCspFree(pPaddedData);
	if (pHashedData) pCardData->pfnCspFree(pHashedData);

	return dwErr;

EXIT_ERROR:
	if (pbSig) pCardData->pfnCspFree(pbSig);

	goto EXIT;
}


DWORD createSelfSignedCert(
		PCARD_DATA		pCardData,
		BYTE			bIndex,
		LPBYTE			pbBlobPublic,
		DWORD			dwBlobLen,
		BYTE*			pbEncodedCert,
		DWORD*			pdwEncodedCertLen
)
{
		PCERT_INFO	pCertInfo = NULL;
		DWORD		dwRet = SCARD_S_SUCCESS;

		if ((NULL == pCardData)
			|| (NULL == pdwEncodedCertLen)) {
			return SCARD_E_INVALID_PARAMETER;
		}

		ykpiv_state*	pykState = (ykpiv_state *)pCardData->pvVendorSpecific;

		char *certIssuerName = "Test";
		CERT_RDN_ATTR rgNameAttr =
		{
			szOID_COMMON_NAME,                 // the OID
			CERT_RDN_PRINTABLE_STRING,         // type of string
			(DWORD)strlen(certIssuerName) + 1, // string length including
			(BYTE *)certIssuerName             // pointer to the string
		};
		CERT_RDN rgRDN[] =
		{
			1,           // number of elements in the array
			&rgNameAttr  // pointer to the array
		};
		CERT_NAME_INFO certName =
		{
			1,     // number of elements in the CERT_RND's array
			rgRDN
		};

		pCertInfo = (PCERT_INFO)pCardData->pfnCspAlloc(sizeof(CERT_INFO));
		if (NULL == pCertInfo) {
			dwRet = SCARD_E_NO_MEMORY;
			goto EXIT_ERROR;
		}
		ZeroMemory(pCertInfo, sizeof(CERT_INFO));

		// 1. Version
		pCertInfo->dwVersion = 2;

		// 2. SerialNumber = 16 bytes of cardid
		BYTE *pbSerialNum = NULL;
		pCertInfo->SerialNumber.cbData = sizeof(pykState->cardid);
		pbSerialNum = (PBYTE)pCardData->pfnCspAlloc(pCertInfo->SerialNumber.cbData);
		if (NULL == pbSerialNum) {
			dwRet = SCARD_E_NO_MEMORY;
			goto EXIT_ERROR;
		}
		CopyMemory(pbSerialNum, pykState->cardid, sizeof(pykState->cardid));
		pCertInfo->SerialNumber.pbData = pbSerialNum;

		// 3. Algorithm
		pCertInfo->SignatureAlgorithm.pszObjId = szOID_RSA_SHA1RSA;
		pCertInfo->SignatureAlgorithm.Parameters.cbData = 0;

		// 4. Issuer - Encode the Issuer name with ASN.1
		BOOL bRet;

		DWORD cbEncodedIssuer;
		BYTE *pbEncodedIssuer = NULL;
		bRet = CryptEncodeObjectEx(X509_ASN_ENCODING, X509_NAME, &certName, 0, NULL, NULL, &cbEncodedIssuer);
		if (FALSE == bRet) {
			dwRet = GetLastError();
			goto EXIT_ERROR;
		}
		pbEncodedIssuer = (BYTE *)pCardData->pfnCspAlloc(cbEncodedIssuer);
		if (NULL == pbEncodedIssuer) {
			dwRet = SCARD_E_NO_MEMORY;
			goto EXIT_ERROR;
		}
		bRet = CryptEncodeObjectEx(X509_ASN_ENCODING, X509_NAME, &certName, 0, NULL, pbEncodedIssuer, &cbEncodedIssuer);
		if (FALSE == bRet) {
			dwRet = GetLastError();
			goto EXIT_ERROR;
		}
		pCertInfo->Issuer.cbData = cbEncodedIssuer;
		pCertInfo->Issuer.pbData = pbEncodedIssuer;

		// 5. UTCTime
		SYSTEMTIME sysTime;
		GetSystemTime(&sysTime);
		SystemTimeToFileTime(&sysTime, &(pCertInfo->NotBefore));
		sysTime.wYear += 10;
		SystemTimeToFileTime(&sysTime, &(pCertInfo->NotAfter));

		// 6. Subject
		char *certSubjName = "Test";
		DWORD cbEncodedSubj;
		BYTE *pbEncodedSubj = NULL;
		rgNameAttr.pszObjId = szOID_COMMON_NAME;
		rgNameAttr.dwValueType = CERT_RDN_PRINTABLE_STRING;
		rgNameAttr.Value.cbData = (DWORD)strlen(certSubjName) + 1;
		rgNameAttr.Value.pbData = (PBYTE)certSubjName;

		bRet = CryptEncodeObjectEx(X509_ASN_ENCODING, X509_NAME, &certName, 0, NULL, NULL, &cbEncodedSubj);
		if (FALSE == bRet) {
			dwRet = GetLastError();
			goto EXIT_ERROR;
		}
		pbEncodedSubj = (BYTE *)pCardData->pfnCspAlloc(cbEncodedSubj);
		if (NULL == pbEncodedSubj) {
			dwRet = SCARD_E_NO_MEMORY;
			goto EXIT_ERROR;
		}
		bRet = CryptEncodeObjectEx(X509_ASN_ENCODING, X509_NAME, &certName, 0, NULL, pbEncodedSubj, &cbEncodedSubj);
		if (FALSE == bRet) {
			dwRet = GetLastError();
			goto EXIT_ERROR;
		}
		pCertInfo->Subject.cbData = cbEncodedSubj;
		pCertInfo->Subject.pbData = pbEncodedSubj;

		// 7. PublicKey
		PCERT_PUBLIC_KEY_INFO pubKeyBuf = NULL;
		DWORD cbEncodedPubKey;
		BYTE *pbEncodedPubKey = NULL;

		//convert PUBLICKEYBLOB into CRYPT_BIT_BLOB
		bRet = CryptEncodeObjectEx(X509_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, pbBlobPublic, 0, NULL, NULL, &cbEncodedPubKey);
		if (FALSE == bRet) {
			dwRet = GetLastError();
			goto EXIT_ERROR;
		}
		pbEncodedPubKey = (BYTE *)pCardData->pfnCspAlloc(cbEncodedPubKey);
		if (NULL == pbEncodedPubKey) {
			dwRet = SCARD_E_NO_MEMORY;
			goto EXIT_ERROR;
		}
		bRet = CryptEncodeObjectEx(X509_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, pbBlobPublic, 0, NULL, pbEncodedPubKey, &cbEncodedPubKey);
		if (FALSE == bRet) {
			dwRet = GetLastError();
			goto EXIT_ERROR;
		}

		//create PCERT_PUBLIC_KEY_INFO (pubKeyBuf)
		pubKeyBuf = (PCERT_PUBLIC_KEY_INFO)pCardData->pfnCspAlloc(sizeof(CERT_PUBLIC_KEY_INFO));
		if (NULL == pubKeyBuf) {
			dwRet = SCARD_E_NO_MEMORY;
			goto EXIT_ERROR;
		}

		LPSTR pbObjId = NULL;
		pbObjId = (LPSTR)pCardData->pfnCspAlloc(strlen(szOID_RSA) + 1);
		if (NULL == pbObjId) {
			dwRet = SCARD_E_NO_MEMORY;
			goto EXIT_ERROR;
		}
		CopyMemory(pbObjId, szOID_RSA, strlen(szOID_RSA));
		pubKeyBuf->Algorithm.pszObjId = pbObjId;
		pubKeyBuf->Algorithm.Parameters.cbData = 0;
		pubKeyBuf->Algorithm.Parameters.pbData = NULL;
		pubKeyBuf->PublicKey.cbData = cbEncodedPubKey;
		pubKeyBuf->PublicKey.pbData = pbEncodedPubKey;
		pubKeyBuf->PublicKey.cUnusedBits = 0;

		pCertInfo->SubjectPublicKeyInfo = *pubKeyBuf;

		//Extension
		pCertInfo->cExtension = 0;
		pCertInfo->rgExtension = NULL;
		pCertInfo->IssuerUniqueId.cbData = 0;
		pCertInfo->SubjectUniqueId.cbData = 0;

		//Make Certificate
		CRYPT_ALGORITHM_IDENTIFIER algId;
		BYTE paraData[16];
		paraData[0] = 0x05; paraData[1] = 0x00;

		algId.pszObjId = szOID_RSA_SHA1RSA;
		algId.Parameters.cbData = 2;
		algId.Parameters.pbData = paraData;

		/*
		Cannot call CryptSignAndEncodeCertificate; so:
		Calls CryptEncodeObject using lpszStructType to encode the "to be signed" information.
		Calls libykpiv to sign this encoded information.
		Calls CryptEncodeObject again, with lpszStructType set to X509_CERT, to further encode the resulting signed
		*/
		DWORD cbEncodedDataToBeSigned;
		BYTE *pbEncodedDataToBeSigned = NULL;
		bRet = CryptEncodeObjectEx(X509_ASN_ENCODING, X509_CERT_TO_BE_SIGNED, pCertInfo, 0, NULL, NULL, &cbEncodedDataToBeSigned);
		if (FALSE == bRet) {
			dwRet = GetLastError();
			goto EXIT_ERROR;
		}
		pbEncodedDataToBeSigned = (BYTE *)pCardData->pfnCspAlloc(cbEncodedDataToBeSigned);
		if (NULL == pbEncodedDataToBeSigned) {
			dwRet = SCARD_E_NO_MEMORY;
			goto EXIT_ERROR;
		}
		bRet = CryptEncodeObjectEx(X509_ASN_ENCODING, X509_CERT_TO_BE_SIGNED, pCertInfo, 0, NULL, pbEncodedDataToBeSigned, &cbEncodedDataToBeSigned);
		if (FALSE == bRet) {
			dwRet = GetLastError();
			goto EXIT_ERROR;
		}

		//Calls libykpiv to sign this encoded information
		PCARD_SIGNING_INFO	pSignInfo = (PCARD_SIGNING_INFO)pCardData->pfnCspAlloc(sizeof(CARD_SIGNING_INFO));
		pSignInfo->dwVersion = CARD_SIGNING_INFO_CURRENT_VERSION;
		pSignInfo->bContainerIndex = bIndex;
		pSignInfo->dwKeySpec = AT_SIGNATURE;
		pSignInfo->dwSigningFlags = CARD_PADDING_PKCS1;
		pSignInfo->aiHashAlg = CALG_SHA1;
		pSignInfo->cbData = cbEncodedDataToBeSigned;
		pSignInfo->pbData = (PBYTE)pCardData->pfnCspAlloc(cbEncodedDataToBeSigned);
		if (NULL == pSignInfo->pbData) {
			dwRet = SCARD_E_NO_MEMORY;
			goto EXIT_ERROR;
		}
		CopyMemory(pSignInfo->pbData, pbEncodedDataToBeSigned, cbEncodedDataToBeSigned);

		pSignInfo->dwPaddingType = CARD_PADDING_PKCS1;
		pSignInfo->pPaddingInfo = NULL;
		dwRet = rsaSign(
			pCardData,
			pSignInfo->bContainerIndex,
			0x9c,
			pSignInfo->aiHashAlg,
			pSignInfo->dwSigningFlags,
			pSignInfo->pbData,
			pSignInfo->cbData,
			pSignInfo->pbSignedData,
			&(pSignInfo->cbSignedData));
		if (SCARD_S_SUCCESS != dwRet) {
			goto EXIT_ERROR;
		}

		//Calls CryptEncodeObject again, with lpszStructType set to X509_CERT
		DWORD cbEncodedSig;
		BYTE *pbEncodedSig = NULL;
		//convert signature into X509_CERT
		bRet = CryptEncodeObjectEx(X509_ASN_ENCODING, X509_CERT, pbEncodedSig, 0, NULL, NULL, &cbEncodedSig);
		if (FALSE == bRet) {
			dwRet = GetLastError();
			goto EXIT_ERROR;
		}
		pbEncodedSig = (BYTE *)pCardData->pfnCspAlloc(cbEncodedSig);
		if (NULL == pbEncodedSig) {
			dwRet = SCARD_E_NO_MEMORY;
			goto EXIT_ERROR;
		}
		bRet = CryptEncodeObjectEx(X509_ASN_ENCODING, X509_CERT, pbEncodedSig, 0, NULL, pbEncodedSig, &cbEncodedSig);
		if (FALSE == bRet) {
			dwRet = GetLastError();
			goto EXIT_ERROR;
		}

		//Attach the encoded signature (pbEncodedSig) to CERT_INFO
		PBYTE	pCert = (PBYTE)pCardData->pfnCspAlloc(sizeof(CERT_INFO) + cbEncodedSig);
		if (NULL == pCert) {
			dwRet = SCARD_E_NO_MEMORY;
			goto EXIT_ERROR;
		}
		CopyMemory(pCert, &pCertInfo, sizeof(CERT_INFO));
		CopyMemory(&pCert[sizeof(CERT_INFO)], pbEncodedSig, cbEncodedSig);

		DWORD cbEncodedCertTmp;
		BYTE *pbEncodedCertTmp = NULL;
		bRet = CryptEncodeObjectEx(X509_ASN_ENCODING, X509_CERT, pCert, 0, NULL, NULL, &cbEncodedCertTmp);
		if (FALSE == bRet) {
			dwRet = GetLastError();
			goto EXIT_ERROR;
		}
		pbEncodedCertTmp = (BYTE *)pCardData->pfnCspAlloc(cbEncodedCertTmp);
		if (NULL == pbEncodedCertTmp) {
			dwRet = SCARD_E_NO_MEMORY;
			goto EXIT_ERROR;
		}
		bRet = CryptEncodeObjectEx(X509_ASN_ENCODING, X509_CERT, pbEncodedSig, 0, NULL, pbEncodedCertTmp, &cbEncodedCertTmp);
		if (FALSE == bRet) {
			dwRet = GetLastError();
			goto EXIT_ERROR;
		}

		*pdwEncodedCertLen = cbEncodedCertTmp;
		if (NULL == pbEncodedCert) {
			dwRet = SCARD_S_SUCCESS;
			goto EXIT;
		}
		if (*pdwEncodedCertLen < cbEncodedCertTmp) {
			dwRet = SCARD_E_INSUFFICIENT_BUFFER;
			goto EXIT_ERROR;
		}
		CopyMemory(pbEncodedCert, pbEncodedCertTmp, cbEncodedCertTmp);

EXIT:
		return dwRet;

EXIT_ERROR:
		//free allocated memory
		if (pbEncodedIssuer) pCardData->pfnCspFree(pbEncodedIssuer);
		if (pbEncodedSubj) pCardData->pfnCspFree(pbEncodedSubj);
		if (pbEncodedPubKey) pCardData->pfnCspFree(pbEncodedPubKey);
		if (pbSerialNum) pCardData->pfnCspFree(pbSerialNum);
		if (pbObjId) pCardData->pfnCspFree(pbObjId);
		if (pubKeyBuf) pCardData->pfnCspFree(pubKeyBuf);
		if (pbEncodedSig) pCardData->pfnCspFree(pbEncodedSig);
		if (pSignInfo) {
			if (pSignInfo->pbSignedData) pCardData->pfnCspFree(pSignInfo->pbSignedData);
			pCardData->pfnCspFree(pSignInfo);
		}

		goto EXIT;
}


void test(PCARD_DATA pCardData) {
	/*
	This is the internal unit test function.
	There is no need to keep the code below, and the code below could changed at anytime.
	*/
	return;
}
