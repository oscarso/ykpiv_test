#include "../cpdk/cardmod.h"
#include <ykpiv/ykpiv.h>
#include <internal.h>


//Test related
void		test(PCARD_DATA pCardData); /* internal unit test of minidriver APIs */

//APDU related
#define	SLOT_AUTH_PIV		0x9a	//AT_KEYEXCHANGE
#define	SLOT_SIGN			0x9c	//AT_SIGNATURE
#define	SLOT_KEY_MAN		0x9d
#define	SLOT_AUTH_CARD		0x9e

BOOL		shouldSelectAppletPiv(ykpiv_state *state);
DWORD		getLength(unsigned char* pBuf);
int			getDataOffset(const BYTE bContainerIndex, const DWORD dwKeySpec);
int			getRetryCount(ykpiv_state *state);
ykpiv_rc	getSerialNumber(ykpiv_state *state, char* pSerial);
ykpiv_rc	getChuid(ykpiv_state *state, unsigned char* pCardID);
ykpiv_rc	getUUID(ykpiv_state *state, PCARD_DATA pCardData, UUID* pUUID);
ykpiv_rc	_send_data(ykpiv_state *state, APDU *apdu, unsigned char *data, unsigned long *recv_len, int *sw);
ykpiv_rc	selectAppletPiv(ykpiv_state *state);
ykpiv_rc	selectAppletYubiKey(ykpiv_state *state);
ykpiv_rc	authenticatePin(ykpiv_state* state, unsigned char* pPin, unsigned long pinLen, unsigned long* pRetry);

//Crypto related
BOOL		isValidKeySize(DWORD dwKeySize);
BOOL		isSupportedAlgoID(ALG_ID algID);
DWORD		getKeySize(PCARD_DATA pCardData, BYTE bIndex, DWORD dwKeySpec);
DWORD		getHash(PCARD_DATA pCardData, ALG_ID algID, PBYTE pbData, DWORD cbData, PBYTE pbHash, DWORD* pcbHash);
DWORD		appendPaddingPKCS1v15(unsigned char *to, int tlen, const unsigned char *from, int flen);
ykpiv_rc	cardId2UUID(ykpiv_state *state, unsigned char* pCardID, UUID* pUUID);
ykpiv_rc	importKeyPairs(ykpiv_state* state, const unsigned char key, const LPBYTE pbBlobPrivate, LPBYTE pbBlobPublic, unsigned long* pBlobLen);
ykpiv_rc	generateKeyPairs(ykpiv_state* state, const unsigned char key, const DWORD dwKeySpec, const unsigned char algorithm, const unsigned long keyLenBits, const unsigned char pin_policy, const unsigned char touch_policy, LPBYTE pbBlobPublic, unsigned long* pBlobLen);
BOOL		verifySignature(ykpiv_state* state, const unsigned char key, const LPBYTE pubKeyBlob, const unsigned long blobLen);
DWORD		rsaSign(PCARD_DATA pCardData, BYTE bIndex, unsigned char key, ALG_ID hashAlgID, DWORD padding, LPBYTE pbData, DWORD cbData, LPBYTE pbSig, DWORD* pcbSig);
DWORD		createSelfSignedCert(PCARD_DATA pCardData, BYTE bIndex, LPBYTE pbBlobPublic, DWORD dwBlobLen, BYTE* pbEncodedCert, DWORD* pdwEncodedCertLen);

//CardMod (minidriver) related
DWORD		ykrc2mdrc(const ykpiv_rc ykrc);
void		getFreeSpace(PCARD_FREE_SPACE_INFO	pcfsi);
void		getPinInfo(PPIN_INFO ppi);
void		getCapabilities(PCARD_CAPABILITIES pcc);
ykpiv_rc	getContainerInfo(PCARD_DATA pCardData, ykpiv_state* state, BYTE bContainerIndex, PCONTAINER_INFO pContainerInfo, DWORD* pdwDataLen);
ykpiv_rc	exportCSPPubKeyBlob(ykpiv_state* state, const int indexPubKey, LPBYTE pbBlobPublic, unsigned long* pBlobLen);
void		printCardcf(const CARD_CACHE_FILE_FORMAT* pCardcf);
