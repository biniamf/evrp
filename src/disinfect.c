#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include "disinfect.h"
#include <stdio.h>

static DWORD ep_foffset(HANDLE hHeap, LONG e_lfanew, DWORD rva, int section, int flag)
{	
	PIMAGE_SECTION_HEADER pSec;

	pSec = (PIMAGE_SECTION_HEADER)((DWORD)hHeap + e_lfanew + sizeof(IMAGE_NT_HEADERS));
	while (section) {
		if ((rva >= pSec->VirtualAddress) && (rva < (pSec->VirtualAddress + pSec->SizeOfRawData))) {
			
			return (flag == 0) ? (rva - pSec->VirtualAddress + pSec->PointerToRawData) : section;
		}
		pSec++;
		section--;
	}	
	return 0;
}

static DWORD stub_offs(HANDLE hHeap, LONG e_lfanew, int section)
{
	PIMAGE_SECTION_HEADER pSec;
	PIMAGE_NT_HEADERS iNth;
	int sect;
	
	iNth = (PIMAGE_NT_HEADERS)((DWORD)hHeap + e_lfanew);
	pSec = (PIMAGE_SECTION_HEADER)((DWORD)hHeap + e_lfanew + sizeof(IMAGE_NT_HEADERS));

	if ((iNth->OptionalHeader.DataDirectory[2].Size + iNth->OptionalHeader.DataDirectory[2].VirtualAddress + 4096 > 
		iNth->OptionalHeader.DataDirectory[5].VirtualAddress || iNth->OptionalHeader.DataDirectory[2].Size == 0) && iNth->OptionalHeader.DataDirectory[5].Size > 0 ) {
		sect = ep_foffset(hHeap, e_lfanew, iNth->OptionalHeader.DataDirectory[5].VirtualAddress, iNth->FileHeader.NumberOfSections, 1);
	}
	else
		sect = ep_foffset(hHeap, e_lfanew, iNth->OptionalHeader.DataDirectory[2].VirtualAddress, iNth->FileHeader.NumberOfSections, 1);
	
	pSec += section - sect;

	return (pSec->PointerToRawData + pSec->SizeOfRawData);
}

static int dis_infect(const char *file)
{
	
	PIMAGE_DOS_HEADER iDOS;
 	PIMAGE_NT_HEADERS iNth;
	PIMAGE_SECTION_HEADER pSec;
	HANDLE hFile, hMap, hFileMap, hNew=NULL;
	DWORD dwSize, oep, dwStub, dwSectionOffset, flag=0, dwOEP[4], dwFOEP;
	BYTE *stub, szOEP[256];
	int i, j;

	hFile = CreateFile(file, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, 
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	
	if (hFile == INVALID_HANDLE_VALUE) return 2;
	
	dwSize = GetFileSize(hFile, NULL);
	if (dwSize == INVALID_FILE_SIZE) {
		CloseHandle(hFile);
		return 2;
	}
	
	hFileMap = CreateFileMapping (hFile, NULL, PAGE_READWRITE, 0, dwSize, NULL);
	if (hFileMap == INVALID_HANDLE_VALUE) {
		CloseHandle (hFile);
		return 2;
	}
	
	hMap = (LPBYTE)MapViewOfFile(hFileMap, FILE_MAP_ALL_ACCESS, 0, 0, dwSize);
	if (hMap == INVALID_HANDLE_VALUE) {
		CloseHandle (hFile);
		CloseHandle (hFileMap);
		return 2;
	}

	/* check if it has the DOS sig. */
	iDOS = (PIMAGE_DOS_HEADER)hMap;
	if (iDOS->e_magic != IMAGE_DOS_SIGNATURE)
		goto err;

	/* skip the DOS header */
	iNth = (PIMAGE_NT_HEADERS)((DWORD)hMap + iDOS->e_lfanew);
	if (iNth->Signature != IMAGE_NT_SIGNATURE)
		goto err;

	pSec = (PIMAGE_SECTION_HEADER)((DWORD)hMap + iDOS->e_lfanew + sizeof(IMAGE_NT_HEADERS));	
	
	/* calculate the offset for the section beyond the stub from the .rsrc */
	dwSectionOffset = stub_offs(hMap, iDOS->e_lfanew, iNth->FileHeader.NumberOfSections);
	if (dwSectionOffset == 0) {
		pSec += iNth->FileHeader.NumberOfSections-1;
		dwSectionOffset = pSec->PointerToRawData + pSec->SizeOfRawData;
	}
	
	dwStub = dwSize - dwSectionOffset;
	/* allocate memory to hold the data after the stub */
	stub = (BYTE*)HeapAlloc(GetProcessHeap(), 0, dwStub);
	if (stub == NULL) goto err;

	memcpy((BYTE*)stub, (LPBYTE)hMap+dwSectionOffset, dwStub);
	/* check the kal sig. */
	memcpy(szOEP, (LPBYTE)hMap+dwSectionOffset-0x7D0, sizeof(szOEP));
	
	if(memicmp(szOEP+76, "~kal^@204~", 10) == 0) {
		/* set oep */
		for (i=100, j=3; i<104; i++, j--) {
			dwOEP[j] = szOEP[i];
		}
		/* calculate final oep */
		dwFOEP  = dwOEP[0] * 0x10000000;
		dwFOEP += dwOEP[1] * 0x10000;
		dwFOEP += dwOEP[2] * 0x100;
		dwFOEP += dwOEP[3];
		
		/* do some cleaning around the entry point. but wait till we're sure that we have the original oep */
		/* find the .rsrc section and calculate the offset */
		/* reset the virus entry point */
		oep = ep_foffset(hMap, iDOS->e_lfanew, iNth->OptionalHeader.AddressOfEntryPoint, iNth->FileHeader.NumberOfSections, 0);
		if (oep != 0)
			memset((LPBYTE)hMap+oep-7, '\0', 107);
		/* now copy the original oep */
		iNth->OptionalHeader.AddressOfEntryPoint = dwFOEP;
		/* decrease SizeOfImage by 4096bytes */
		iNth->OptionalHeader.SizeOfImage -= 0x1000;		
		memcpy((LPBYTE)hMap+dwSectionOffset-0x7D0, stub, dwStub);
		/* now correct the .rsrc or the .reloc section */
	if ((iNth->OptionalHeader.DataDirectory[2].Size + iNth->OptionalHeader.DataDirectory[2].VirtualAddress + 4096 > 
		iNth->OptionalHeader.DataDirectory[5].VirtualAddress || iNth->OptionalHeader.DataDirectory[2].Size == 0) && iNth->OptionalHeader.DataDirectory[5].Size > 0 ) {
			i = ep_foffset(hMap, iDOS->e_lfanew, iNth->OptionalHeader.DataDirectory[5].VirtualAddress, iNth->FileHeader.NumberOfSections, 1);
			pSec += iNth->FileHeader.NumberOfSections - i;	
			pSec->Misc.VirtualSize = iNth->OptionalHeader.DataDirectory[5].Size;
		} else {
			i = ep_foffset(hMap, iDOS->e_lfanew, iNth->OptionalHeader.DataDirectory[2].VirtualAddress, iNth->FileHeader.NumberOfSections, 1);
			if (i == 0) i = iNth->FileHeader.NumberOfSections;
			pSec += iNth->FileHeader.NumberOfSections - i;
			if (i == iNth->FileHeader.NumberOfSections)
				pSec->Misc.VirtualSize -= 0x1000;

			else
				pSec->Misc.VirtualSize = iNth->OptionalHeader.DataDirectory[2].Size;
		}		
		pSec->SizeOfRawData -= 0x7d0;
		flag = 0x7D0;
	}
	
	HeapFree(GetProcessHeap(), 0, stub);
	FlushViewOfFile(hMap, 0);
    UnmapViewOfFile(hMap);
	CloseHandle(hFileMap);
	/* need to unmap and close the handle before setting eof */
    SetFilePointer(hFile, dwSize-0x0AA0B-flag, NULL, FILE_BEGIN);    
	SetEndOfFile(hFile);

    CloseHandle(hFile);
	return (flag == 0) ? 1 : 0;

err:
	FlushViewOfFile(hMap, 0);
    UnmapViewOfFile(hMap);
	CloseHandle(hFileMap);
	CloseHandle(hFile);
	return 2;

}

 /* 
  * before calling this function, be sure that the file is infected. 
  * this module assumes an infected file.
  */
/* 0=sucess, 1=done partially, 2=unable   */
int disinfect(const char *file)
{
	return dis_infect(file);
}
