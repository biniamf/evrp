#define WIN32_LEAN_AND_LEAN

#include <windows.h>
#include <winreg.h>
#include "enumsvc.h"
#include "detect.h"
#include "disinfect.h"
#include <stdio.h>

static int svc_image(const char *pval, const char *subkey)
{
	char szBuf[MAX_PATH], tmp[MAX_PATH+128], szData[MAX_PATH+128];	
	HKEY hkey;
	DWORD dwRet=sizeof(szBuf), dwData=sizeof(szData);
	int ret=0, cnt=0;

	lstrcpy(tmp, subkey);
	lstrcat(tmp, "\\");
	lstrcat(tmp, pval);
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, tmp, 0, KEY_READ, &hkey) == ERROR_SUCCESS) {
		for (;;) {
			ret = RegEnumValue(hkey, cnt++, szBuf, &dwRet, 0, NULL, szData, &dwData);
			if (dwData > 0) {
				if (lstrcmpi(szBuf, "ImagePath") == 0) {
					// call the scanning fucntion. if it returns "infected" 
					switch (detect(szData)) {
						case 2:
							DeleteFile(szData);
							break;
						case 1:
							switch (disinfect(szData)) {
								case 0:
									printf("%s - Cleaned!\n", szData);
									break;
								case 1:
									printf("%s - Partially cleaned!\n", szData);
									break;
								case 2:
									printf("%s - Unable to clean!\n", szData);
									break;

							}
					}
				}
					
				if (ret == ERROR_NO_MORE_ITEMS) break;
				dwRet = sizeof(szBuf);
				dwData = sizeof(szData);
			}
		}
	}
	return 0;
}

int svc_list()
{
	HKEY hkey;
	char szBuf[MAX_PATH], szSubKey[] = "SYSTEM\\CurrentControlSet\\Services";	
	DWORD dwRet=sizeof(szBuf);
	int ret=0, cnt=0;

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, szSubKey, 0, KEY_READ, &hkey) == ERROR_SUCCESS) {
		for (;;) {			
			ret = RegEnumKeyEx(hkey, cnt++, szBuf, &dwRet, 0, NULL, NULL,NULL);
			if (ret == ERROR_NO_MORE_ITEMS) break;
			if (szBuf[0] == '~' && szBuf[dwRet-1] == '~')
				// might be the virus so find the imagepath and scan and delete...
				svc_image(szBuf, szSubKey);
			dwRet = sizeof(szBuf);
		}
	}


	return 0;
}
