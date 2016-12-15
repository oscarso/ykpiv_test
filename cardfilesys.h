#define	SZ_MAX_PAGE				2048 //max size in bytes per flash page
#define	SZ_MAX_LEN				sizeof(DWORD) //max size in bytes to store the length of write data
#define	MAX_KEY_PER_CONTAINER	2

// Move into ykpiv.h later
#define	szCARD_APPS						"cardapps"
#define	YKPIV_OBJ_MSMD					0x5fd000
#define YKPIV_OBJ_MSMDMSROOTS			(YKPIV_OBJ_MSMD + 1)
#define	YKPIV_OBJ_MSMDCARDCF			(YKPIV_OBJ_MSMD + 2) // Variable Size:  6 bytes - 8KB or more
#define	YKPIV_OBJ_MSMDCMAPFILE			(YKPIV_OBJ_MSMD + 3) // Variable Size:  6 bytes - 8KB or more
#define	YKPIV_OBJ_RSAPUBKEYBLOB_OFFSET	(YKPIV_OBJ_MSMD + 4) // Variable Size:
