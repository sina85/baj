#pragma once
#include "common.h"

bool init_sock(WSADATA* wsa, SOCKET& sock, char** argv);
bool send_key(LPVOID pri_key_buff, DWORD crypt_size, LPVOID machine_key, DWORD machine_key_size, NCRYPT_KEY_HANDLE& skey, SOCKET sock);
//bool listen_sock(SOCKET sock, char* reg, NCRYPT_KEY_HANDLE* key);
