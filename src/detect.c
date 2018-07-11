#define WIN32_LEAL_AND_NEAN

#include <windows.h>
#include <stdio.h>
#include "detect.h"

int detect(const char *filename)
{
	HANDLE hFile, hMap, hFileMap;
	DWORD dwSize, dwEnd=1, dwNormal;
	char sig[] = "0123456789ABCDEF";

	hFile = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);	
	
	if (hFile == INVALID_HANDLE_VALUE) {		
		return 0;
	}
	
	dwSize = GetFileSize(hFile, NULL);
	if (dwSize == INVALID_FILE_SIZE) {
		CloseHandle(hFile);		
		return 0;
	}	
	
	if (dwSize < 0x9c40) {
		CloseHandle (hFile);
		return 0;
	}

	hFileMap = CreateFileMapping (hFile, NULL, PAGE_READONLY, 0, dwSize, NULL);
	if (hFileMap == INVALID_HANDLE_VALUE) {
		CloseHandle (hFile);		
		return 0;
	}
	
	hMap = (LPBYTE)MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, dwSize);
	if (hMap == INVALID_HANDLE_VALUE) {
		CloseHandle (hFile);
		CloseHandle (hFileMap);
		return 0;
	}
	
	if (dwSize > 0x0AA0B)
		dwEnd = memcmp((LPBYTE)hMap+dwSize-0x01780, sig, sizeof(sig)-1); /* descard the terminating 0 */
	dwNormal = memcmp((LPBYTE)hMap+0x9280, sig, sizeof(sig)-1);
	
	UnmapViewOfFile(hMap);
	CloseHandle(hFileMap);
	CloseHandle(hFile);

	if (dwNormal == 0) return 2; // the virus itself
	else if (dwEnd == 0) return 1;
	return 3;
}
