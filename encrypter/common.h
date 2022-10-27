#pragma once
#define _CRT_RAND_S
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS 
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <winsock2.h>
#include <stdlib.h>
#include <stdio.h>
#include <ncrypt.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <Shlobj.h>

//#include <process.h>
//#include <ws2tcpip.h>
//#include <tlhelp32.h>
//#pragma comment (lib, "Mswsock.lib")
//#pragma comment (lib, "AdvApi32.lib")


#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "ncrypt")

#define NT_SUCCESS(Status)	(((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL	((NTSTATUS)0xC0000001L)

#define CLIENT_KEY_DEF "GET /\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0\n"
#define HARDWARE_ID_DEF "GET /files/\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0\n"
#define DEFAULT_BUFLEN 512
#define MAXD 256


