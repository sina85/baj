#pragma once
#include "common.h"

typedef struct _client_socket {
	SOCKET client_sock;
	char ip[16];
	int thread_number;
} client_socket, * pclient_socket;

DWORD WINAPI init_sock(void* _arg[2]);
bool listen_sock(void* arg[1]);