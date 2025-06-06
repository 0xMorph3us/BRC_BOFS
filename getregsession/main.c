#include <windows.h>
#include "badger_exports.h"
#include <lm.h>
#include <winreg.h>

// API Function Declarations and Imports
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegOpenKeyExA(
    HKEY hKey,
    LPCSTR lpSubKey,
    DWORD ulOptions,
    REGSAM samDesired,
    PHKEY phkResult
);

DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegConnectRegistryA(
    LPCSTR lpMachineName,
    HKEY hKey,
    PHKEY phkResult
);

DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegEnumKeyExA(
    HKEY hKey,
    DWORD dwIndex,
    LPSTR lpName,
    LPDWORD lpcName,
    LPDWORD lpReserved,
    LPSTR lpClass,
    LPDWORD lpcClass,
    PFILETIME lpftLastWriteTime
);

DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegCloseKey(
    HKEY hKey
);

DECLSPEC_IMPORT BOOL WINAPI KERNEL32$GetComputerNameExW(
    COMPUTER_NAME_FORMAT NameType,
    LPWSTR lpBuffer,
    LPDWORD nSize
);

DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(
    UINT CodePage,
    DWORD dwFlags,
    LPCCH lpMultiByteStr,
    int cbMultiByte,
    LPWSTR lpWideCharStr,
    int cchWideChar
);

DECLSPEC_IMPORT PVOID BadgerAlloc(SIZE_T length);
DECLSPEC_IMPORT VOID BadgerFree(PVOID *memptr);

void Reg_EnumKey(const char *hostname, WCHAR **dispatch)
{
    DWORD dwresult = 0;
    HKEY rootkey = 0;
    HKEY RemoteKey = 0;
    int sessionCount = 0;
    wchar_t whostname[256] = {0};
    DWORD whostname_len = 256;

    if (hostname == NULL) {
        BadgerDispatch(dispatch, "[*] Querying local registry...\n");
        dwresult = ADVAPI32$RegOpenKeyExA(HKEY_USERS, NULL, 0, KEY_READ, &rootkey);

        if (dwresult) {
            goto END;
        }

        // Get FQDN name for localhost
        KERNEL32$GetComputerNameExW(ComputerNameDnsFullyQualified, (LPWSTR)&whostname, &whostname_len);
    } else {
        BadgerDispatch(dispatch, "[*] Querying registry on %s...\n", hostname);
        dwresult = ADVAPI32$RegConnectRegistryA(hostname, HKEY_USERS, &RemoteKey);

        if (dwresult) {
            BadgerDispatch(dispatch, "Failed to connect to registry on %s\n", hostname);
            goto END;
        }

        dwresult = ADVAPI32$RegOpenKeyExA(RemoteKey, NULL, 0, KEY_READ, &rootkey);

        if (dwresult) {
            BadgerDispatch(dispatch, "Failed to open remote registry key\n");
            goto END;
        }
    }

    DWORD index = 0;
    CHAR subkeyName[256];
    DWORD subkeyNameSize = sizeof(subkeyName);

    while ((dwresult = ADVAPI32$RegEnumKeyExA(rootkey, index, subkeyName, &subkeyNameSize, NULL, NULL, NULL, NULL)) == ERROR_SUCCESS) {
        BOOL isSID = TRUE;

        // Check if the subkey starts with S-1-5-21 and does not have an underscore
        if (subkeyName[0] == 'S' && subkeyName[1] == '-' && subkeyName[2] == '1' && subkeyName[3] == '-' && subkeyName[4] == '5' && subkeyName[5] == '-' && subkeyName[6] == '2' && subkeyName[7] == '1') {
            // Skip if the subkey has an underscore
            for (DWORD j = 0; j < subkeyNameSize; j++) {
                if (subkeyName[j] == '_') {
                    isSID = FALSE;
                    break;
                }
            }

            if (isSID) {
                sessionCount++;
                BadgerDispatch(dispatch, "-----------Registry Session---------\n");
                BadgerDispatch(dispatch, "UserSid: %s\n", subkeyName);
                if (hostname == NULL) {
                    BadgerDispatch(dispatch, "Host: %S\n", whostname);
                } else {
                    BadgerDispatch(dispatch, "Host: %s\n", hostname);
                }
                BadgerDispatch(dispatch, "---------End Registry Session-------\n\n");
            }
        }

        // Move to the next subkey
        index++;
        subkeyNameSize = sizeof(subkeyName);
    }

    BadgerDispatch(dispatch, "[*] Found %d sessions in the registry\n", sessionCount);

    if (dwresult != ERROR_NO_MORE_ITEMS) {
        goto END;
    }

END:
    if (rootkey) {
        ADVAPI32$RegCloseKey(rootkey);
    }

    if (RemoteKey) {
        ADVAPI32$RegCloseKey(RemoteKey);
    }
}

int coffee(char** argv, int argc, WCHAR** dispatch)
{
    const char *hostname = NULL;

    if (argc > 0 && argv[0] != NULL) {
        hostname = argv[0];
    }

    Reg_EnumKey(hostname, dispatch);

    return 0;
}
