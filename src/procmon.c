#include <windows.h>
#include <accctrl.h>
#include <aclapi.h>
#include <stdio.h>
#include "disinfect.h"
#include "procmon.h"
#include "detect.h"

typedef BOOL (WINAPI *lpfEnumProcesses)(DWORD *, DWORD cb, DWORD *);
typedef BOOL (WINAPI *lpfEnumProcessModules)(HANDLE, HMODULE *, DWORD, LPDWORD);
typedef DWORD (WINAPI *lpfGetModuleFileNameEx)(HANDLE, HMODULE, LPTSTR, DWORD);

static void adjust_token(void)
{
	TOKEN_PRIVILEGES tkp;
	HANDLE hToken;
	ACL acl;	
	LUID luid;
	
	memset(&acl, 0, sizeof(acl));
	InitializeAcl(&acl, sizeof(acl), ACL_REVISION);
	SetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &acl, 0);
	
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &hToken);

	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
	
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luid;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL);		
} 

static int local_disinfect(HANDLE hProcess, LPCSTR szFileName, int task)
{
	if (!TerminateProcess(hProcess, 0))
		 return GetLastError();
	
	WaitForSingleObject(hProcess, INFINITE);
	if (task == 2)
		 return (DeleteFile(szFileName) == 0) ? GetLastError() : 1;

	 return (disinfect(szFileName));
}

/* return 1=sucess or 0=failure. */
int scan_proc()
{
	lpfEnumProcesses EnumProcesses;
	lpfEnumProcessModules EnumProcessModules;
	lpfGetModuleFileNameEx GetModuleFileNameEx;
	HINSTANCE hInstLib;
	HANDLE hProcess;
	HMODULE hMod[20];
	LPDWORD lpdwPIDs = NULL;
	DWORD dwSize, dwSize2, dwIndex, tmp;
	char szFileName[MAX_PATH+256];

	adjust_token();
	hInstLib = LoadLibrary("psapi.dll");
	if (hInstLib == NULL)
		return 0;

	EnumProcesses = (lpfEnumProcesses)GetProcAddress(hInstLib, "EnumProcesses");
	EnumProcessModules = (lpfEnumProcessModules)GetProcAddress(hInstLib, "EnumProcessModules");
	GetModuleFileNameEx = (lpfGetModuleFileNameEx)GetProcAddress(hInstLib, "GetModuleFileNameExA");

	dwSize2 = 256 * sizeof(DWORD);	
	for (;;) {
		
		if (lpdwPIDs) {
			HeapFree(GetProcessHeap(), 0, lpdwPIDs);
			dwSize2 *= 2;
		}

		lpdwPIDs = HeapAlloc(GetProcessHeap(), 0, dwSize2);
		if (lpdwPIDs == NULL) {
			FreeLibrary(hInstLib);
			return 0;
		}

		if (!EnumProcesses(lpdwPIDs, dwSize2, &dwSize)) {
			HeapFree(GetProcessHeap(), 0, lpdwPIDs);
			FreeLibrary(hInstLib);
			return 0;
		}
		
		if (dwSize != dwSize2)
			break;
	}

	dwSize /= sizeof(DWORD);

	for (dwIndex = 0; dwIndex < dwSize; dwIndex++) {
		
		szFileName[0] = 0;
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lpdwPIDs[dwIndex]);

		if (hProcess != NULL) {			
			if (EnumProcessModules(hProcess, hMod, sizeof(hMod), &dwSize2 )) {
				if (GetModuleFileNameEx(hProcess, hMod[0], szFileName, sizeof(szFileName)))
					tmp = detect(szFileName);
				 
				 switch (tmp) {
					 case 1:
					 case 2:						 
						 // well, disinfect now.
						 local_disinfect(hProcess, szFileName, tmp);
						 break;
					 case 0:
						 // scanning szFileName failed
						 //printf("Scanning %s failed.\n", szFileName);
						 break;
				 }
			}
			CloseHandle(hProcess);
		}
	}	
	return 1;
}