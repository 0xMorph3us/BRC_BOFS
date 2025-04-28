#include <windows.h>
#include "badger_exports.h"
#include "main.h"
#include "helper.h"
#include "typedefs.h"

DWORD ConfigTargetService(SMBConfig* config, const WCHAR* serviceName, const WCHAR* binpath, DWORD errmode, DWORD state, WCHAR** dispatch) {
    DWORD dwResult = ERROR_SUCCESS;
    SC_HANDLE scManager = NULL;
    SC_HANDLE scService = NULL;

    scManager = ADVAPI32$OpenSCManagerW(config->hostname, SERVICES_ACTIVE_DATABASEW, SC_MANAGER_CONNECT);
    if (NULL == scManager) {
        dwResult = KERNEL32$GetLastError();
        BadgerDispatch(dispatch, "OpenSCManagerW failed (%lu)\n", dwResult);
        goto config_service_end;
    }

    scService = ADVAPI32$OpenServiceW(scManager, serviceName, SERVICE_CHANGE_CONFIG);
    if (NULL == scService) {
        dwResult = KERNEL32$GetLastError();
        BadgerDispatch(dispatch, "OpenServiceW failed (%lu)\n", dwResult);
        goto config_service_end;
    }

    if (FALSE == ADVAPI32$ChangeServiceConfigW(
        scService,
        SERVICE_NO_CHANGE,
        state,
        errmode,
        binpath,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
    )) {
        dwResult = KERNEL32$GetLastError();
        BadgerDispatch(dispatch, "ChangeServiceConfigW failed (%lu)\n", dwResult);
    }

config_service_end:
    if (scService) ADVAPI32$CloseServiceHandle(scService);
    if (scManager) ADVAPI32$CloseServiceHandle(scManager);
    return dwResult;
}

DWORD StopTargetService(SMBConfig* config, const WCHAR* serviceName, WCHAR** dispatch) {
    DWORD dwResult = ERROR_SUCCESS;
    SC_HANDLE scManager = NULL;
    SC_HANDLE scService = NULL;
    SERVICE_STATUS_PROCESS ssp;
    DWORD dwBytesNeeded = 0;

    scManager = ADVAPI32$OpenSCManagerW(config->hostname, SERVICES_ACTIVE_DATABASEW, SC_MANAGER_CONNECT);
    if (NULL == scManager) {
        dwResult = KERNEL32$GetLastError();
        BadgerDispatch(dispatch, "OpenSCManagerW failed (%lX)\n", dwResult);
        goto stop_service_end;
    }

    scService = ADVAPI32$OpenServiceW(scManager, serviceName, SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS);
    if (NULL == scService) {
        dwResult = KERNEL32$GetLastError();
        BadgerDispatch(dispatch, "OpenServiceW failed (%lX)\n", dwResult);
        goto stop_service_end;
    }

    if (!ADVAPI32$QueryServiceStatusEx(scService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
        dwResult = KERNEL32$GetLastError();
        BadgerDispatch(dispatch, "QueryServiceStatusEx failed (%lX)\n", dwResult);
        goto stop_service_end;
    }

    if (ssp.dwCurrentState == SERVICE_STOPPED) {
        BadgerDispatch(dispatch, "Service: %S\nService is already stopped.\n", serviceName);
        goto stop_service_end;
    }

    if (ssp.dwCurrentState == SERVICE_STOP_PENDING) {
        BadgerDispatch(dispatch, "Service stop pending...\n");
        goto stop_service_end;
    }

    if (!ADVAPI32$ControlService(scService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp)) {
        dwResult = KERNEL32$GetLastError();
        BadgerDispatch(dispatch, "ControlService failed (%lX)\n", dwResult);
    }

stop_service_end:
    if (scService) ADVAPI32$CloseServiceHandle(scService);
    if (scManager) ADVAPI32$CloseServiceHandle(scManager);
    return dwResult;
}


BOOL CheckServiceStatus(SMBConfig* config, const WCHAR* serviceName, WCHAR** dispatch) {
    SC_HANDLE scManager = NULL;
    SC_HANDLE scService = NULL;
    SERVICE_STATUS_PROCESS ssp;
    DWORD dwBytesNeeded;

    scManager = ADVAPI32$OpenSCManagerW(config->hostname, SERVICES_ACTIVE_DATABASEW, SC_MANAGER_CONNECT);
    if (!scManager) {
        BadgerDispatch(dispatch, "OpenSCManager failed (%lX)\n", KERNEL32$GetLastError());
        return FALSE;
    }

    scService = ADVAPI32$OpenServiceW(scManager, serviceName, SERVICE_QUERY_STATUS);
    if (!scService) {
        BadgerDispatch(dispatch, "OpenService failed (%lX)\n", KERNEL32$GetLastError());
        ADVAPI32$CloseServiceHandle(scManager);
        return FALSE;
    }

    if (!ADVAPI32$QueryServiceStatusEx(scService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
        BadgerDispatch(dispatch, "QueryServiceStatusEx failed (%lX)\n", KERNEL32$GetLastError());
        ADVAPI32$CloseServiceHandle(scService);
        ADVAPI32$CloseServiceHandle(scManager);
        return FALSE;
    }

    ADVAPI32$CloseServiceHandle(scService);
    ADVAPI32$CloseServiceHandle(scManager);
    return (ssp.dwCurrentState == SERVICE_RUNNING);
}

DWORD StartTargetService(SMBConfig* config, const WCHAR* serviceName, WCHAR** dispatch) {
    DWORD dwResult = ERROR_SUCCESS;
    SC_HANDLE scManager = NULL;
    SC_HANDLE scService = NULL;
    SERVICE_STATUS_PROCESS ssp;
    DWORD dwBytesNeeded = 0;

    scManager = ADVAPI32$OpenSCManagerW(config->hostname, SERVICES_ACTIVE_DATABASEW, SC_MANAGER_CONNECT);
    if (NULL == scManager) {
        dwResult = KERNEL32$GetLastError();
        BadgerDispatch(dispatch, "OpenSCManagerW failed (%lX)\n", dwResult);
        goto start_service_end;
    }

    scService = ADVAPI32$OpenServiceW(scManager, serviceName, SERVICE_START | SERVICE_QUERY_STATUS);
    if (NULL == scService) {
        dwResult = KERNEL32$GetLastError();
        BadgerDispatch(dispatch, "OpenServiceW failed (%lX)\n", dwResult);
        goto start_service_end;
    }

    if (!ADVAPI32$QueryServiceStatusEx(scService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
        dwResult = KERNEL32$GetLastError();
        BadgerDispatch(dispatch, "QueryServiceStatusEx failed (%lX)\n", dwResult);
        goto start_service_end;
    }

    if (ssp.dwCurrentState == SERVICE_RUNNING) {
        BadgerDispatch(dispatch, "  [*] %ls is already running, skipping StartServiceW\n", serviceName);
        dwResult = ERROR_SUCCESS;
        goto start_service_end;
    }

    if (!ADVAPI32$StartServiceW(scService, 0, NULL)) {
        dwResult = KERNEL32$GetLastError();
        if (dwResult == ERROR_SERVICE_ALREADY_RUNNING) {
            BadgerDispatch(dispatch, "  [*] %ls is already running.\n", serviceName);
            dwResult = ERROR_SUCCESS;
        } else {
            BadgerDispatch(dispatch, "StartServiceW failed (%lX)\n", dwResult);
        }
    }

start_service_end:
    if (scService) ADVAPI32$CloseServiceHandle(scService);
    if (scManager) ADVAPI32$CloseServiceHandle(scManager);
    return dwResult;
}


DWORD GetServiceStartType(SMBConfig* config, const WCHAR* serviceName, WCHAR** dispatch) {
    SC_HANDLE scManager = NULL;
    SC_HANDLE scService = NULL;
    DWORD startType = SERVICE_NO_CHANGE;
    LPQUERY_SERVICE_CONFIGW lpsc = NULL;
    DWORD dwBytesNeeded, cbBufSize;

    scManager = ADVAPI32$OpenSCManagerW(config->hostname, NULL, SC_MANAGER_CONNECT);
    if (!scManager) {
        BadgerDispatch(dispatch, "OpenSCManager failed with error: %lX\n", KERNEL32$GetLastError());
        return SERVICE_NO_CHANGE;
    }

    scService = ADVAPI32$OpenServiceW(scManager, serviceName, SERVICE_QUERY_CONFIG);
    if (!scService) {
        BadgerDispatch(dispatch, "OpenService failed with error: %lX\n", KERNEL32$GetLastError());
        ADVAPI32$CloseServiceHandle(scManager);
        return SERVICE_NO_CHANGE;
    }

    ADVAPI32$QueryServiceConfigW(scService, NULL, 0, &dwBytesNeeded);
    cbBufSize = dwBytesNeeded;
    lpsc = (LPQUERY_SERVICE_CONFIGW)KERNEL32$LocalAlloc(LMEM_FIXED, cbBufSize);
    if (!lpsc) {
        BadgerDispatch(dispatch, "LocalAlloc failed\n");
        ADVAPI32$CloseServiceHandle(scService);
        ADVAPI32$CloseServiceHandle(scManager);
        return SERVICE_NO_CHANGE;
    }

    if (ADVAPI32$QueryServiceConfigW(scService, lpsc, cbBufSize, &dwBytesNeeded)) {
        startType = lpsc->dwStartType;
        if (MSVCRT$_wcsicmp(serviceName, L"LanmanServer") == 0) BadgerMemcpy(config->lanmanBinPath, lpsc->lpBinaryPathName, (BadgerWcslen(lpsc->lpBinaryPathName) + 1) * sizeof(WCHAR));
        if (MSVCRT$_wcsicmp(serviceName, L"srv2") == 0) BadgerMemcpy(config->srv2BinPath, lpsc->lpBinaryPathName, (BadgerWcslen(lpsc->lpBinaryPathName) + 1) * sizeof(WCHAR));
        if (MSVCRT$_wcsicmp(serviceName, L"srvnet") == 0) BadgerMemcpy(config->srvnetBinPath, lpsc->lpBinaryPathName, (BadgerWcslen(lpsc->lpBinaryPathName) + 1) * sizeof(WCHAR));
    } else {
        BadgerDispatch(dispatch, "QueryServiceConfig failed with error: %lX\n", KERNEL32$GetLastError());
    }

    if (lpsc) KERNEL32$LocalFree(lpsc);
    if (scService) ADVAPI32$CloseServiceHandle(scService);
    if (scManager) ADVAPI32$CloseServiceHandle(scManager);
    return startType;
}

DWORD CheckProcessIntegrityLevel(WCHAR** dispatch) {
    HANDLE hToken;
    DWORD dwLengthNeeded;
    DWORD dwError = ERROR_SUCCESS;
    PTOKEN_MANDATORY_LABEL pTIL = NULL;
    DWORD dwIntegrityLevel;

    if (KERNEL32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        if (!ADVAPI32$GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLengthNeeded)) {
            dwError = KERNEL32$GetLastError();
            if (dwError == ERROR_INSUFFICIENT_BUFFER) {
                pTIL = (PTOKEN_MANDATORY_LABEL)KERNEL32$LocalAlloc(0, dwLengthNeeded);
                if (pTIL != NULL) {
                    if (ADVAPI32$GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLengthNeeded, &dwLengthNeeded)) {
                        dwIntegrityLevel = *ADVAPI32$GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*ADVAPI32$GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

                        if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) {
                            return SECURITY_MANDATORY_SYSTEM_RID;
                        } else if (dwIntegrityLevel == SECURITY_MANDATORY_HIGH_RID) {
                            return SECURITY_MANDATORY_HIGH_RID;
                        } else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) {
                            return SECURITY_MANDATORY_SYSTEM_RID;
                        } else {
                            return SECURITY_MANDATORY_LOW_RID;
                        }
                    }
                    KERNEL32$LocalFree(pTIL);
                }
            }
        }
        KERNEL32$CloseHandle(hToken);
    } else {
        BadgerDispatch(dispatch, "[!] Failed to open process token for integrity level check.\n");
    }
    return SECURITY_MANDATORY_LOW_RID;
}


void CheckSMBServices(SMBConfig* config, WCHAR** dispatch) {
    DWORD lanmanStartType = GetServiceStartType(config, config->lanmanService, dispatch);
    DWORD srv2StartType = GetServiceStartType(config, config->srv2Service, dispatch);
    DWORD srvnetStartType = GetServiceStartType(config, config->srvnetService, dispatch);

    BOOL lanmanRunning = CheckServiceStatus(config, config->lanmanService, dispatch);
    BOOL srv2Running = CheckServiceStatus(config, config->srv2Service, dispatch);
    BOOL srvnetRunning = CheckServiceStatus(config, config->srvnetService, dispatch);

    BadgerDispatch(dispatch, "\n  --------------------CHECKING SERVICES----------------------\n\n");
    BadgerDispatch(dispatch, "  [*] LanmanServer\n          |------- state:     %s\n", lanmanRunning ? "Running" : "Stopped");
    BadgerDispatch(dispatch, "          |------- starttype: %s\n",
        lanmanStartType == SERVICE_DEMAND_START ? "MANUAL" : 
        lanmanStartType == SERVICE_AUTO_START ? "AUTO" : 
        lanmanStartType == SERVICE_DISABLED ? "DISABLED" : "UNKNOWN");
    BadgerDispatch(dispatch, "          |------- path:      %ls\n\n", config->lanmanBinPath);

    BadgerDispatch(dispatch, "  [*] srv2\n          |------- state:     %s\n", srv2Running ? "Running" : "Stopped");
    BadgerDispatch(dispatch, "          |------- starttype: %s\n",
        srv2StartType == SERVICE_DEMAND_START ? "MANUAL" : 
        srv2StartType == SERVICE_AUTO_START ? "AUTO" : 
        srv2StartType == SERVICE_DISABLED ? "DISABLED" : "UNKNOWN");
    BadgerDispatch(dispatch, "          |------- path:      %ls\n\n", config->srv2BinPath);

    BadgerDispatch(dispatch, "  [*] srvnet\n          |------- state:     %s\n", srvnetRunning ? "Running" : "Stopped");
    BadgerDispatch(dispatch, "          |------- starttype: %s\n",
        srvnetStartType == SERVICE_DEMAND_START ? "MANUAL" : 
        srvnetStartType == SERVICE_AUTO_START ? "AUTO" : 
        srvnetStartType == SERVICE_DISABLED ? "DISABLED" : "UNKNOWN");
    BadgerDispatch(dispatch, "          |------- path:      %ls\n\n", config->srvnetBinPath);

    BadgerDispatch(dispatch, "  ----------------------------------------------------------\n\n\n");

    BadgerDispatch(dispatch, "  [+] 445/tcp bound - %s\n\n", srvnetRunning ? "TRUE" : "FALSE");
}


int coffee(char** argv, int argc, WCHAR** dispatch) {
    SMBConfig* config = (SMBConfig*)BadgerAlloc(sizeof(SMBConfig));
    if (!config) {
        BadgerDispatch(dispatch, "  [!] Failed to allocate memory for SMBConfig\n");
        return 1;
    }

    config->hostname = ConvertCharToWideString("127.0.0.1");
    config->lanmanService = ConvertCharToWideString("LanmanServer");
    config->srv2Service = ConvertCharToWideString("srv2");
    config->srvnetService = ConvertCharToWideString("srvnet");

    config->lanmanBinPath = (WCHAR*)BadgerAlloc(sizeof(WCHAR) * 1024);
    config->srv2BinPath = (WCHAR*)BadgerAlloc(sizeof(WCHAR) * 1024);
    config->srvnetBinPath = (WCHAR*)BadgerAlloc(sizeof(WCHAR) * 1024);

    if (!config->hostname || !config->lanmanService || !config->srv2Service || !config->srvnetService ||
        !config->lanmanBinPath || !config->srv2BinPath || !config->srvnetBinPath) {
        BadgerDispatch(dispatch, "  [!] Memory allocation failed for SMBConfig setup\n");
        goto cleanup;
    }

    if (argc > 0) {
        if (BadgerStrcmp(argv[0], "start") == 0) {
            if (CheckProcessIntegrityLevel(dispatch) != SECURITY_MANDATORY_SYSTEM_RID &&
                CheckProcessIntegrityLevel(dispatch) != SECURITY_MANDATORY_HIGH_RID) {
                BadgerDispatch(dispatch, "  [!] You should be running at a SYSTEM or HIGH integrity level for this functionality.\n");
                goto cleanup;
            }

            DWORD configResult = ConfigTargetService(config, config->lanmanService, NULL, 0, SERVICE_AUTO_START, dispatch);
            DWORD startResult = StartTargetService(config, config->lanmanService, dispatch);

            if (configResult == ERROR_SUCCESS && startResult == ERROR_SUCCESS) {
                BadgerDispatch(dispatch, "  ----------------RESUME SMB FUNCTIONALITY------------\n\n");
                BadgerDispatch(dispatch, "  [*] LanmanServer\n       |--- action: starttype=Auto\n\n");
                BadgerDispatch(dispatch, "  [*] LanmanServer\n       |--- action: Started\n\n");
                BadgerDispatch(dispatch, "  ----------------------------------------------------\n\n\n");
                BadgerDispatch(dispatch, "  [+] 445/tcp bound - TRUE\n\n");
            }

        } else if (BadgerStrcmp(argv[0], "stop") == 0) {
            if (CheckProcessIntegrityLevel(dispatch) != SECURITY_MANDATORY_SYSTEM_RID &&
                CheckProcessIntegrityLevel(dispatch) != SECURITY_MANDATORY_HIGH_RID) {
                BadgerDispatch(dispatch, "  [!] You should be running at a SYSTEM or HIGH integrity level for this functionality.\n");
                goto cleanup;
            }

            DWORD configResult = ConfigTargetService(config, config->lanmanService, NULL, 0, SERVICE_DISABLED, dispatch);
            DWORD stopLanman = StopTargetService(config, config->lanmanService, dispatch);
            DWORD stopSrv2 = StopTargetService(config, config->srv2Service, dispatch);
            DWORD stopSrvnet = StopTargetService(config, config->srvnetService, dispatch);

            if (configResult == ERROR_SUCCESS && stopLanman == ERROR_SUCCESS &&
                stopSrv2 == ERROR_SUCCESS && stopSrvnet == ERROR_SUCCESS) {
                BadgerDispatch(dispatch, "  -------------STOPPING SMB FUNCTIONALITY----------\n\n");
                BadgerDispatch(dispatch, "  [*] LanmanServer\n       |--- action: starttype=Disabled\n\n");
                BadgerDispatch(dispatch, "  [*] LanmanServer\n       |--- action: Stopped\n\n");
                BadgerDispatch(dispatch, "  [*] srv2\n       |--- action: Stopped\n\n");
                BadgerDispatch(dispatch, "  [*] srvnet\n       |--- action: Stopped\n\n");
                BadgerDispatch(dispatch, "  ----------------------------------------------------\n\n\n");
                BadgerDispatch(dispatch, "  [+] 445/tcp bound - FALSE\n\n");
            }

        } else if (BadgerStrcmp(argv[0], "check") == 0) {
            CheckSMBServices(config, dispatch);
        } else {
            BadgerDispatch(dispatch, "Unknown argument\n");
            goto cleanup;
        }
    } else {
        BadgerDispatch(dispatch, "Usage :\n  start - Start SMB services\n  stop - Stop SMB services\n  check - Check SMB services status\n");
        goto cleanup;
    }

cleanup:
    if (config->hostname) BadgerFree((PVOID*)&config->hostname);
    if (config->lanmanService) BadgerFree((PVOID*)&config->lanmanService);
    if (config->srv2Service) BadgerFree((PVOID*)&config->srv2Service);
    if (config->srvnetService) BadgerFree((PVOID*)&config->srvnetService);
    if (config->lanmanBinPath) BadgerFree((PVOID*)&config->lanmanBinPath);
    if (config->srv2BinPath) BadgerFree((PVOID*)&config->srv2BinPath);
    if (config->srvnetBinPath) BadgerFree((PVOID*)&config->srvnetBinPath);
    BadgerFree((PVOID*)&config);

    return 0;
}