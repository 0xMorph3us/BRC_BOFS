#include <windows.h>
#include "badger_exports.h"
#include <lm.h>

// API Function Declarations and Imports
DECLSPEC_IMPORT NET_API_STATUS NET_API_FUNCTION NETAPI32$NetWkstaUserEnum(
    LPCWSTR servername,
    DWORD level,
    LPBYTE* bufptr,
    DWORD prefmaxlen,
    LPDWORD entriesread,
    LPDWORD totalentries,
    LPDWORD resume_handle
);

DECLSPEC_IMPORT NET_API_STATUS NETAPI32$NetApiBufferFree(
    LPVOID Buffer
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

void getnetloggedon(wchar_t *servername, WCHAR** dispatch)
{
    PWKSTA_USER_INFO_1 output = NULL, current = NULL;
    DWORD entries = 0, pos = 0, totalentrieshint = 0; 
    DWORD resume = 0;
    NET_API_STATUS stat = 0;

    do {
        stat = NETAPI32$NetWkstaUserEnum(servername, 1, (LPBYTE*)&output, MAX_PREFERRED_LENGTH, &entries, &totalentrieshint, &resume);
        if(stat == ERROR_SUCCESS || stat == ERROR_MORE_DATA)
        {
            current = output;
            for(pos = 0; pos < entries; pos++)
            {
                BadgerDispatchW(dispatch, L"-----------Logged on User-----------\n");

                if (servername == NULL)
                {
                    wchar_t hostname[256] = {0};
                    DWORD hostname_len = 256;
                    KERNEL32$GetComputerNameExW(ComputerNameDnsFullyQualified, hostname, &hostname_len);
                    BadgerDispatchW(dispatch, L"Host: %s\n", hostname);
                }
                else {
                    BadgerDispatchW(dispatch, L"Host: %s\n", servername);
                }

                BadgerDispatchW(dispatch, L"Username: %s\n", current->wkui1_username);
                BadgerDispatchW(dispatch, L"Domain: %s\n", current->wkui1_logon_domain);
                BadgerDispatchW(dispatch, L"Oth_domains: %s\n", current->wkui1_oth_domains);
                BadgerDispatchW(dispatch, L"Logon server: %s\n", current->wkui1_logon_server);
                BadgerDispatchW(dispatch, L"---------End Logged on User---------\n\n");
                current++;
            }
        }
        else
        {
            BadgerDispatchW(dispatch, L"Unable to list logged on users : %ld\n", stat);
        }
        
        NETAPI32$NetApiBufferFree(output);
    } while(stat == ERROR_MORE_DATA);
}

int coffee(char** argv, int argc, WCHAR** dispatch)
{
    wchar_t *servername = NULL;

    if (argc > 0 && argv[0] != NULL)
    {
        // Determine the required buffer size for the wide-character string
        int len = KERNEL32$MultiByteToWideChar(CP_ACP, 0, argv[0], -1, NULL, 0);
        servername = (wchar_t*)BadgerAlloc(len * sizeof(wchar_t));

        // Convert the char string to wchar_t string
        KERNEL32$MultiByteToWideChar(CP_ACP, 0, argv[0], -1, servername, len);
    }

    getnetloggedon(servername, dispatch);

    if (servername)
    {
        BadgerFree((PVOID*)&servername);
    }

    return 0;
}
