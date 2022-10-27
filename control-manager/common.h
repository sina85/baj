#pragma once
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_RAND_S
#define WIN32_LEAN_AND_MEAN
#define recvbuff_len 512
#define false 0
#define true 1

typedef unsigned int short bool;

#include <windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <ncrypt.h>
/*
#include <stdlib.h>
#include <ws2tcpip.h>
#include <process.h>
#include <limits.h>
//*/

#include <wow64apiset.h>


#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "bcrypt")
#pragma comment(lib, "ncrypt")

#define CLEAN(str) (strchr(str, '\n') != NULL) ? str[strlen(str) - 1] = '\0' : getch();
#define NT_SUCCESS(Status)	(((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL	((NTSTATUS)0xC0000001L)

#define CLIENT_KEY_DEF "GET /\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0\n"
#define HARDWARE_ID_DEF "GET /files/\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0\n"
#define INIT_DEF "GET http://developer.mozilla.org/en-US/docs/Web/HTTP/Messages HTTP/1.1"

bool terminate_flag = 0;