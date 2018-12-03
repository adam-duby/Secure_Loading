/*
   Adam Duby, aduby@uccs.edu
   UCCS, Department of Computer Science
   Last Modified: Nov 14, 2018
*/

#define UNICODE
#define _UNICODE
#include <stdio.h>
#include <windows.h>
#include <winternl.h>
//#pragma comment(lib, "user32.lib")
#define WIN32_DEFAULT_LIBS

// Needed for native API calls that are not exported:
// ZwQueryInformationProcess
typedef NTSTATUS(__stdcall *ZW_QUERY_INFORMATION_PROCESS)(
	IN  HANDLE				ProcessHandle,
	IN  PROCESSINFOCLASS	ProcessInformationClass,
	OUT PVOID				ProcessInformation,
	IN  ULONG				ProcessInformationLength,
	OUT PULONG				ReturnLength);

/*
// Only when compiled for x86:
int * getPEB(){
	__asm
		{
			xor  eax, eax
			mov  eax, DWORD PTR gs:[30h]
		}
}
*/

INT WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrevInst, LPWSTR lpCmdLine, INT nShowCmd)
{
	// int result; // For MessageBox

	FILE * fp;
	/* open the file for writing*/
	fopen_s(&fp, "out.txt", "w");

	// Obtain handle for other process:
	// HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);

	// Obtain handle for current proces:
	HANDLE hProcess = GetCurrentProcess();
	 
	PEB peb;
	PROCESS_BASIC_INFORMATION pbi;
	PEB_LDR_DATA peb_ldr_data;
	ZW_QUERY_INFORMATION_PROCESS ZwQueryInformationProcessStruct;
	PULONG buffer;
	

	// Dynamically load ntdll.dll and get address of ZwQueryInformationProcess
	HMODULE hModule = LoadLibrary(L"ntdll.dll");
	ZwQueryInformationProcessStruct = (ZW_QUERY_INFORMATION_PROCESS)GetProcAddress(hModule, "ZwQueryInformationProcess");
	if (ZwQueryInformationProcessStruct == NULL) {
		fprintf(fp, "[ERROR] - Error Linking ZwQueryInformationProcess. Terminating.\n");
		//result = MessageBox(NULL, L"Error Linking ZwQueryInformationProcess. 'OK' to terminate process.", L"UCCS", MB_ICONERROR | MB_OK);
		//if (result == IDOK)
			ExitProcess(0);
	}

	/*
	// Call ZwQueryInformationProcess via alias
	NTSTATUS NtStatZwQueryInformationProcess = ZwQueryInformationProcessStruct(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &buffer);
	if (!NT_SUCCESS(NtStatZwQueryInformationProcess)) {
		fprintf(fp, "[ERROR] - Failed to obtain PEB. Terminating.");
		ExitProcess(0);
	}*/

	NTSTATUS NtStatNtQueryInformationProcess = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &buffer);
	if (!NT_SUCCESS(NtStatNtQueryInformationProcess)) {
		fprintf(fp, "[ERROR] - Failed to obtain PEB. Terminating.");
		ExitProcess(0);
	}

	// Get the PEB Base Address:
	DWORD dwSize;
	ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, 16, &dwSize);
	fprintf(fp, "PEB is located at 0x%08x\n", (unsigned int)pbi.PebBaseAddress);

	// Get the PEB_LDR_DATA structure:
	ReadProcessMemory(hProcess, peb.Ldr, &peb_ldr_data, sizeof(peb_ldr_data), &dwSize);
	fprintf(fp, "PEB_LDR_DATA is located at 0x%08x\n", (unsigned int)peb.Ldr);


	fclose(fp);
	ExitProcess(0);
}