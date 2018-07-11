#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdio.h>
#include "disinfect.h"
#include "fmonitor.h"
#include "c_vb.h"

/* definition of file monitor flags */
#define FMON_FILL	 0
#define FMON_SEARCH	 1

struct file_mon {
	char *mfname[1024]; /* the module file names: assume max 4096 exes in the dir. */
	int count;
	int flag; /* reserved for future use */
};

struct fmon_s {
	char szDir[MAX_PATH];
	int subdir;
};

static int fmonitor(struct file_mon *fmon, int flag)
{
	WIN32_FIND_DATA FileData; 
	HANDLE hSearch;
	char szDirPath[MAX_PATH];
	char szStart[MAX_PATH];
	char before[128];
	int i=0;
	
	GetSystemDirectory(szDirPath, MAX_PATH);	
	lstrcpy(szStart, szDirPath);
	lstrcat(szStart, "\\*.exe");
	
	memset(&before, '\0', sizeof(before));	
	hSearch = FindFirstFile(szStart, &FileData); 	
	if (hSearch == INVALID_HANDLE_VALUE)
		return 0; 
 
	for (;;) {		
		 
		/* we dont need the dir path. b/c we know it's windows/32 */
		// check if it's fill and fill in the stack		
		if (flag == FMON_FILL) {
			/* NOTE: whenever we want to free, we have to loop thru the list  */
			fmon->mfname[fmon->count] = (char *)HeapAlloc(GetProcessHeap(), 0, lstrlen(FileData.cFileName)+1);
			lstrcpy(fmon->mfname[fmon->count++], FileData.cFileName);
			
		} 
		else {
			/*  */
			for (i=0;  i <= fmon->count;) {
				if (lstrcmpi(fmon->mfname[i++], FileData.cFileName) == 0)				
					break;
			}
			if (i > fmon->count)
				printf("%s is a new file. and i=%i\n", FileData.cFileName, i);
			// call scan(). if infected, call disinfect
			// better call scan_proc 1st in case it's still running...
			// disinfect(FileData.cFileName);
		}
		
		if (!FindNextFile(hSearch, &FileData)) {
			if (GetLastError() == ERROR_NO_MORE_FILES)
				break;
		}		
	}  	
	
	FindClose(hSearch);
	return 1;
}

/* call this thread with directory to watch + flag about subdir watching */
DWORD _stdcall filemon_main_th(LPVOID pv)
{
	struct file_mon fmon;	
	struct fmon_s *fmons = (struct fmon_s*)pv;
	HANDLE hChange;
	DWORD dwWaitStatus;
	char szSysDir[MAX_PATH];
	
	lstrcpy(szSysDir, fmons->szDir);
	if (szSysDir[lstrlen(szSysDir)-1] != '\\')
		lstrcat(szSysDir, "\\");
	memset(&fmon, 0, sizeof(fmon));		

	hChange = FindFirstChangeNotification(szSysDir, fmons->subdir, FILE_NOTIFY_CHANGE_FILE_NAME);
	if (hChange == INVALID_HANDLE_VALUE)
		goto err;
	fmonitor(&fmon, 0);
	
	for (;;) {

		dwWaitStatus = WaitForSingleObject(hChange, INFINITE);
		
		switch (dwWaitStatus) {
			
			case WAIT_OBJECT_0:
				fmonitor(&fmon, FMON_SEARCH);
				memset(&fmon, 0, sizeof(fmon));
				fmonitor(&fmon, FMON_FILL);

				if (FindNextChangeNotification(hChange) == FALSE)
					break;
			default:
				continue;
		}
	}

err:	
	ExitThread(0);
	return 0;

}

