/*
 *  Part of Emopia Virus Removal Pack (EVRP)
 *   
 *  This is a virus removal tool for a virus commonly 
 *  known as "Dulla" and by A/V vendors Win32.Agent.cb
 *
 *  the virus is very dangerious as it destroys almost all
 *  important documents in the computer in unrecovrable way.
 *  The virus is a PE infector meaning it's difficult to clean
 *  and easier to spread.
 *   
 *	Author: Biniam Fisseha Demissie
 *  
 *  Last modified: Jan 2009
 */ 

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "procmon.h"
#include "scan.h"
#include "c_vb.h"
#include "detect.h"
#include "disinfect.h"
#include "uninstall.h"
#include "enumsvc.h"
#include <stdio.h>

int scan_freezed = 0;

static DWORD scan_ext(const char *filename, char *p)
{
	static struct {
		char *ext;
		// DWORD fzLimit;
	} ext_scan[] = {"exe", "scr", NULL}; /* the struct will be used when there is a file size limit */
	
	register int j;
	for (j=0; ext_scan[j].ext != NULL; j++)
		if (instr(1, ext_scan[j].ext, p)) 
			return 1;
	return 0;
}

static void scan_dir_file(const char *path, unsigned long fsLow)
{	
	char ext[9]; /* not 8, avoid return value overwritting in case of larger ext names  */
	int i, j, wab=0;
	for (i=lstrlen(path)-1; i>=0 && path[i] != '.'; i--);
	for (j=0, i++; i>0 && i<lstrlen(path) && j<8; i++, j++)
		ext[j] = path[i]; 
	ext[j] = 0;
	/* avoid *.c, *.h, *.js(to avoid 2 character subsets)... and no ext files */
	if (j < 3) return;	
	/* NOTE: this is only for Dulla fix. it's based on the original infection length */
	//if (fsLow < 40000) return;
	
	if (scan_ext(path, ext) == 0)
		return;	
	
	if (scan_freezed) return;
	
	switch (detect(path)) {
		case 2: 
			DeleteFile(path);
			printf("%s - Cleaned by deletion!\n", path);
			break;
		case 1:
			switch (disinfect(path)) {
			/* 0=sucess, 1=done partially, 2=unable   */	
			case 0: 
				printf("%s - Cleaned!\n", path);
				break;
			case 1:
				printf("%s - Cleaned partially!\n", path);
				break;
			default:
				printf("%s - Unable to clean!\n", path);
			}
	}
}

static int scan_dir(const char *path)
{
	WIN32_FIND_DATA fd;
	HANDLE hFile;
	char buf[MAX_PATH+64];

	if (path == NULL) return 1;
	if (path[0] == 0) return 1;
	
	if (scan_freezed) return 0;

	lstrcpy(buf, path);
	if (buf[lstrlen(buf)-1] != '\\') lstrcat(buf, "\\");
	lstrcat(buf, "*.*");

	memset(&fd, 0, sizeof(fd));
	for (hFile=NULL;;) {
		if (hFile == NULL) {
			hFile = FindFirstFile(buf, &fd);
			if (hFile == INVALID_HANDLE_VALUE) hFile = NULL;
			if (hFile == NULL) break;
		} else {
			if (FindNextFile(hFile, &fd) == 0) break;
		}
		
		if (fd.cFileName[0] == '.') {
			if (fd.cFileName[1] == 0) continue;
			if (fd.cFileName[1] == '.')
				if (fd.cFileName[2] == 0) continue;
		}
		lstrcpy(buf, path);
		if (buf[lstrlen(buf)-1] != '\\') lstrcat(buf, "\\");
		lstrcat(buf, fd.cFileName);
		
		if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY)
			scan_dir(buf);
		else
			scan_dir_file(buf, fd.nFileSizeLow);
	}
	if (hFile != NULL) FindClose(hFile);
	return 0;
}

void scan_disks()
{
	char buf[MAX_PATH+128];
	//char root;
	
	memset(buf, 0, sizeof(buf));
	//GetSystemDirectory(buf, sizeof(buf));
	//root = buf[0];

	lstrcpy(buf+1, ":\\"); /* e.g. C:\ */		

	for (buf[0]='A'; buf[0]<='Z'; buf[0]++) {
		switch (GetDriveType(buf)) {
			case DRIVE_FIXED:
			case DRIVE_RAMDISK:
				break;
			case DRIVE_REMOTE:
				break;
			case DRIVE_REMOVABLE:
			default:
				continue;
		}	
		scan_dir(buf);
	}
}

int main(int argc, char *argv[])
{	
	scan_proc();
	svc_list();

	scan_disks();
	
	disinfect("C:\\b.cc");

	return 0;
}