#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include "newdevice.h"
#include <stdio.h>

char *drivelist[26];

int populate_drive()
{	
	int i;
	char buf[8]="B:\\";
	
	for (i=0; buf[0] < 'Z'; buf[0]++) {
		if (GetDriveType(buf) == DRIVE_REMOVABLE || GetDriveType(buf) == DRIVE_FIXED) {
			drivelist[i] = (char *)HeapAlloc(GetProcessHeap(), 0, 6);
			lstrcpy(drivelist[i++], buf);
		}						
	}
	return 0;
}

int scan_change()
{
	int i;
	char buf[8]="B:\\";

	for (; buf[0] < 'Z'; buf[0]++) {
		for (i=0; drivelist[i] != NULL; i++) {			
			if (lstrcmpi(drivelist[i], buf) == 0)
				break;
		}
		// found a new drive or an invalid path
		if (drivelist[i] == NULL) {
			if (GetDriveType(buf) == DRIVE_REMOVABLE || GetDriveType(buf) == DRIVE_FIXED)
				printf("%s is a new drive.", buf);
		}

	}
	populate_drive();
	return 0;
}

