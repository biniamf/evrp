#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winnt.h>
#include <winsvc.h>
#include <winuser.h>
#include <dbt.h>
#include "service.h"


SERVICE_STATUS          ServiceStatus; 
SERVICE_STATUS_HANDLE   ServiceStatusHandle; 

BOOL g_isRunning = 0;

static int uninstall_svc(const char *svc_name)
{	
    SC_HANDLE scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	SC_HANDLE scHandle;
    scHandle = OpenService(scmHandle, svc_name, SERVICE_ALL_ACCESS);
    DeleteService(scHandle);
	CloseServiceHandle(scHandle);
    CloseServiceHandle(scmHandle);
	return 0;
}

static int install_svc(const char *svc_name, const char *szPath)
{
	char szBuffer[255];    
	SC_HANDLE scHandle;
    SC_HANDLE scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);    
    
    lstrcpy(szBuffer, "\"");
    lstrcat(szBuffer, szPath);
    lstrcat(szBuffer, "\"");

	scHandle = CreateService(
							scmHandle, 
							svc_name, 
							"Emopia Labs AV Service2", 
							SERVICE_ALL_ACCESS, 
							SERVICE_WIN32_OWN_PROCESS, 
							SERVICE_AUTO_START, 
							SERVICE_ERROR_NORMAL, 
							szBuffer, NULL, NULL, NULL, NULL, NULL);

    CloseServiceHandle(scHandle);
    CloseServiceHandle(scmHandle);
	return 0;
}

DWORD WINAPI ServiceCtrlHandler(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext)
{
	switch(dwControl) 
    { 
        case SERVICE_CONTROL_PAUSE: 
            ServiceStatus.dwCurrentState = SERVICE_PAUSED; 
            break; 
 
        case SERVICE_CONTROL_CONTINUE: 
            ServiceStatus.dwCurrentState = SERVICE_RUNNING; 
            break; 
 
        case SERVICE_CONTROL_STOP: 
            
			ServiceStatus.dwWin32ExitCode = 0; 
            ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING; 
            ServiceStatus.dwCheckPoint = 0; 
            ServiceStatus.dwWaitHint = 0; 
			
            g_isRunning = 0;

            SetServiceStatus(ServiceStatusHandle, &ServiceStatus);       
			return 0; 
 
        case SERVICE_CONTROL_DEVICEEVENT:
			if (dwEventType == DBT_DEVICEARRIVAL) 
				// flash found...
            break; 
 
        default: 
			break;
    }  

    SetServiceStatus(ServiceStatusHandle, &ServiceStatus);

    return 0; 
}

void WINAPI ServiceMain( DWORD argc, LPTSTR *argv ) 
{ 
    ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS; 
    ServiceStatus.dwCurrentState = SERVICE_START_PENDING; 
    ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP; 
    ServiceStatus.dwWin32ExitCode = 0; 
    ServiceStatus.dwServiceSpecificExitCode = 0; 
    ServiceStatus.dwCheckPoint = 0; 
    ServiceStatus.dwWaitHint = 0; 
 
    ServiceStatusHandle = RegisterServiceCtrlHandlerEx("Emopia Labs AV Service2", ServiceCtrlHandler, NULL); 
 
    if (ServiceStatusHandle == (SERVICE_STATUS_HANDLE) 0)     
        return;    
 
    ServiceStatus.dwCurrentState = SERVICE_RUNNING; 
    ServiceStatus.dwCheckPoint = 0; 
    ServiceStatus.dwWaitHint = 0; 
 
    SetServiceStatus(ServiceStatusHandle, &ServiceStatus);

    g_isRunning = 1;
    
	// do some service-works here while => g_isRunning.
	for (;;) {
		
		Beep(1000, 2);
		Sleep(300);
		if (g_isRunning == 0)
			break;
	}

    ServiceStatus.dwCurrentState = SERVICE_STOPPED;     
	
    SetServiceStatus(ServiceStatusHandle, &ServiceStatus);	
	
    return; 
} 

int svc_dispatch(const char *svc_name)
{
	SERVICE_TABLE_ENTRY DispatchTable[] = { {svc_name, ServiceMain}, {0, 0} };

	return StartServiceCtrlDispatcher(DispatchTable);	
}
