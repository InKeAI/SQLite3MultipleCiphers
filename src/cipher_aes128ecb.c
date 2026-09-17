/*
** Name:        cipher_aes128ecb.c
** Purpose:     AES-128-ECB compatibility cipher
** License:     MIT
*/

#include "cipher_common.h"

#if HAVE_CIPHER_AES_128_ECB

#define CIPHER_NAME_AES128ECB "aes128ecb"

/*
** AES-128-ECB is retained for compatibility with legacy databases that use
** a literal 16-byte key and have no IV, salt, page-key derivation, or HMAC.
*/
SQLITE_PRIVATE CipherParams mcAES128ECBParams[] =
{
  { "legacy_page_size", 4096, 4096, 512, SQLITE_MAX_PAGE_SIZE },
  CIPHER_PARAMS_SENTINEL
};

typedef struct _AES128ECBCipher
{
  int       m_pageSize;
  int       m_keyLength;
  uint8_t   m_key[KEYLENGTH_AES128];
  Rijndael* m_aes;
} AES128ECBCipher;

static void*
AllocateAES128ECBCipher(sqlite3* db)
{
  AES128ECBCipher* aesCipher = (AES128ECBCipher*) sqlite3_malloc(sizeof(AES128ECBCipher));
  if (aesCipher != NULL)
  {
    aesCipher->m_aes = (Rijndael*) sqlite3_malloc(sizeof(Rijndael));
    if (aesCipher->m_aes != NULL)
    {
      CipherParams* cipherParams;
      aesCipher->m_pageSize = 4096;
      aesCipher->m_keyLength = KEYLENGTH_AES128;
      memset(aesCipher->m_key, 0, KEYLENGTH_AES128);
      RijndaelCreate(aesCipher->m_aes);
      cipherParams = sqlite3mcGetCipherParams(db, CIPHER_NAME_AES128ECB);
      if (cipherParams != NULL)
      {
        int pageSize = sqlite3mcGetCipherParameter(cipherParams, "legacy_page_size");
        if (pageSize >= 512 && pageSize <= SQLITE_MAX_PAGE_SIZE && ((pageSize - 1) & pageSize) == 0)
        {
          aesCipher->m_pageSize = pageSize;
        }
      }
    }
    else
    {
      sqlite3_free(aesCipher);
      aesCipher = NULL;
    }
  }
  return aesCipher;
}

static void
FreeAES128ECBCipher(void* cipher)
{
  AES128ECBCipher* aesCipher = (AES128ECBCipher*) cipher;
  sqlite3mcSecureZeroMemory(aesCipher->m_aes, sizeof(Rijndael));
  sqlite3_free(aesCipher->m_aes);
  sqlite3mcSecureZeroMemory(aesCipher, sizeof(AES128ECBCipher));
  sqlite3_free(aesCipher);
}

static void
CloneAES128ECBCipher(void* cipherTo, void* cipherFrom)
{
  AES128ECBCipher* aesCipherTo = (AES128ECBCipher*) cipherTo;
  AES128ECBCipher* aesCipherFrom = (AES128ECBCipher*) cipherFrom;
  aesCipherTo->m_pageSize = aesCipherFrom->m_pageSize;
  aesCipherTo->m_keyLength = aesCipherFrom->m_keyLength;
  memcpy(aesCipherTo->m_key, aesCipherFrom->m_key, KEYLENGTH_AES128);
  RijndaelInvalidate(aesCipherTo->m_aes);
  RijndaelInvalidate(aesCipherFrom->m_aes);
}

static int
GetLegacyAES128ECBCipher(void* cipher)
{
  return 1;
}

static int
GetPageSizeAES128ECBCipher(void* cipher)
{
  AES128ECBCipher* aesCipher = (AES128ECBCipher*) cipher;
  return aesCipher->m_pageSize;
}

static int
GetReservedAES128ECBCipher(void* cipher)
{
  return 0;
}

static unsigned char*
GetSaltAES128ECBCipher(void* cipher)
{
  return NULL;
}

static void
GenerateKeyAES128ECBCipher(void* cipher, char* userPassword, int passwordLength, int rekey, unsigned char* cipherSalt)
{
  AES128ECBCipher* aesCipher = (AES128ECBCipher*) cipher;
  int keyLength = passwordLength;
  if (keyLength > KEYLENGTH_AES128)
  {
    keyLength = KEYLENGTH_AES128;
  }
  memset(aesCipher->m_key, 0, KEYLENGTH_AES128);
  if (userPassword != NULL && keyLength > 0)
  {
    memcpy(aesCipher->m_key, userPassword, keyLength);
  }
}

static int
CryptPageAES128ECBCipher(void* cipher, int encrypt, unsigned char* data, int len)
{
  AES128ECBCipher* aesCipher = (AES128ECBCipher*) cipher;
  int direction = encrypt ? RIJNDAEL_Direction_Encrypt : RIJNDAEL_Direction_Decrypt;
  int result;

  if (len <= 0 || (len % 16) != 0)
  {
    return SQLITE_ERROR;
  }
  result = RijndaelInit(aesCipher->m_aes,
                        RIJNDAEL_Direction_Mode_ECB,
                        direction,
                        aesCipher->m_key,
                        RIJNDAEL_Direction_KeyLength_Key16Bytes,
                        NULL);
  if (result != RIJNDAEL_SUCCESS)
  {
    return SQLITE_ERROR;
  }
  if (encrypt)
  {
    result = RijndaelBlockEncrypt(aesCipher->m_aes, data, len * 8, data);
  }
  else
  {
    result = RijndaelBlockDecrypt(aesCipher->m_aes, data, len * 8, data);
  }
  return result < 0 ? SQLITE_ERROR : SQLITE_OK;
}

static int
EncryptPageAES128ECBCipher(void* cipher, int page, unsigned char* data, int len, int reserved)
{
  return CryptPageAES128ECBCipher(cipher, 1, data, len);
}

static int
DecryptPageAES128ECBCipher(void* cipher, int page, unsigned char* data, int len, int reserved, int hmacCheck)
{
  return CryptPageAES128ECBCipher(cipher, 0, data, len);
}

SQLITE_PRIVATE const CipherDescriptor mcAES128ECBDescriptor =
{
  CIPHER_NAME_AES128ECB,
  AllocateAES128ECBCipher,
  FreeAES128ECBCipher,
  CloneAES128ECBCipher,
  GetLegacyAES128ECBCipher,
  GetPageSizeAES128ECBCipher,
  GetReservedAES128ECBCipher,
  GetSaltAES128ECBCipher,
  GenerateKeyAES128ECBCipher,
  EncryptPageAES128ECBCipher,
  DecryptPageAES128ECBCipher
};

#endif
