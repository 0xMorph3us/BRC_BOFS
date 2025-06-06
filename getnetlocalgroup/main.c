#include <windows.h>
#include "badger_exports.h"
#include <lm.h>
#include <windns.h>

// API Function Declarations and Imports
DECLSPEC_IMPORT NET_API_STATUS NET_API_FUNCTION NETAPI32$NetLocalGroupGetMembers(
    LPCWSTR servername,
    LPCWSTR groupname,
    DWORD level,
    LPBYTE* bufptr,
    DWORD prefmaxlen,
    LPDWORD entriesread,
    LPDWORD totalentries,
    PDWORD_PTR resumehandle
);

DECLSPEC_IMPORT NET_API_STATUS NET_API_FUNCTION NETAPI32$NetApiBufferFree(
    LPVOID Buffer
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ConvertSidToStringSidW(
    PSID Sid,
    LPWSTR *StringSid
);

DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(
    UINT CodePage,
    DWORD dwFlags,
    LPCCH lpMultiByteStr,
    int cbMultiByte,
    LPWSTR lpWideCharStr,
    int cchWideChar
);

DECLSPEC_IMPORT BOOL WINAPI KERNEL32$GetComputerNameExW(
    COMPUTER_NAME_FORMAT NameType,
    LPWSTR lpBuffer,
    LPDWORD nSize
);

DECLSPEC_IMPORT PVOID BadgerAlloc(SIZE_T length);
DECLSPEC_IMPORT VOID BadgerFree(PVOID *memptr);

void ListServerGroupMembers(const wchar_t *server, const wchar_t *groupname, WCHAR **dispatch)
{
    PLOCALGROUP_MEMBERS_INFO_2 pBuff = NULL, p = NULL;
    DWORD dwTotal = 0, dwRead = 0;
    DWORD_PTR hResume = 0;
    NET_API_STATUS res = 0;

    do {
        res = NETAPI32$NetLocalGroupGetMembers(server, groupname, 2, (LPBYTE *)&pBuff, MAX_PREFERRED_LENGTH, &dwRead, &dwTotal, &hResume);
        if ((res == ERROR_SUCCESS) || (res == ERROR_MORE_DATA)) {
            p = pBuff;
            for (; dwRead > 0; dwRead--) {
                wchar_t *sidstr = NULL;
                ADVAPI32$ConvertSidToStringSidW(p->lgrmi2_sid, &sidstr);

                BadgerDispatch(dispatch, "----------Local Group Member----------\n");

                if (server == NULL) {
                    wchar_t hostname[256] = {0};
                    DWORD hostname_len = 256;
                    KERNEL32$GetComputerNameExW(ComputerNameDnsFullyQualified, hostname, &hostname_len);
                    BadgerDispatch(dispatch, "Host: %S\n", hostname);
                } else {
                    BadgerDispatch(dispatch, "Host: %S\n", server);
                }

                BadgerDispatch(dispatch, "Group: %S\n", groupname);
                BadgerDispatch(dispatch, "Member: %S\n", p->lgrmi2_domainandname);
                BadgerDispatch(dispatch, "MemberSid: %S\n", sidstr);

                switch (p->lgrmi2_sidusage) {
                    case SidTypeUser:
                        BadgerDispatch(dispatch, "MemberSidType: User\n");
                        break;
                    case SidTypeGroup:
                        BadgerDispatch(dispatch, "MemberSidType: Group\n");
                        break;
                    case SidTypeWellKnownGroup:
                        BadgerDispatch(dispatch, "MemberSidType: WellKnownGroup\n");
                        break;
                    case SidTypeDeletedAccount:
                        BadgerDispatch(dispatch, "MemberSidType: DeletedAccount\n");
                        break;
                    case SidTypeUnknown:
                        BadgerDispatch(dispatch, "MemberSidType: Unknown\n");
                        break;
                    default:
                        BadgerDispatch(dispatch, "MemberSidType: Other\n");
                        break;
                }

                BadgerDispatch(dispatch, "--------End Local Group Member--------\n\n");
                p++;
            }
            NETAPI32$NetApiBufferFree(pBuff);
        } else {
            BadgerDispatch(dispatch, "Error: %lu\n", res);
        }
    } while (res == ERROR_MORE_DATA);
}

int coffee(char** argv, int argc, WCHAR** dispatch)
{
    wchar_t *server = NULL;
    wchar_t *group = NULL;

    if (argc > 0 && argv[0] != NULL) {
        int len = KERNEL32$MultiByteToWideChar(CP_ACP, 0, argv[0], -1, NULL, 0);
        server = (wchar_t*)BadgerAlloc(len * sizeof(wchar_t));
        KERNEL32$MultiByteToWideChar(CP_ACP, 0, argv[0], -1, server, len);
    }

    if (argc > 1 && argv[1] != NULL) {
        int len = KERNEL32$MultiByteToWideChar(CP_ACP, 0, argv[1], -1, NULL, 0);
        group = (wchar_t*)BadgerAlloc(len * sizeof(wchar_t));
        KERNEL32$MultiByteToWideChar(CP_ACP, 0, argv[1], -1, group, len);
    }

    if (group == NULL) {
        BadgerDispatch(dispatch, "[*] Querying Remote Desktop Users...\n");
        ListServerGroupMembers(server, L"Remote Desktop Users", dispatch);

        BadgerDispatch(dispatch, "[*] Querying Distributed COM Users...\n");
        ListServerGroupMembers(server, L"Distributed COM Users", dispatch);

        BadgerDispatch(dispatch, "[*] Querying Remote Management Users...\n");
        ListServerGroupMembers(server, L"Remote Management Users", dispatch);

        BadgerDispatch(dispatch, "[*] Querying Administrators...\n");
        ListServerGroupMembers(server, L"Administrators", dispatch);
    } else {
        ListServerGroupMembers(server, group, dispatch);
    }

    if (server) {
        BadgerFree((PVOID*)&server);
    }

    if (group) {
        BadgerFree((PVOID*)&group);
    }

    return 0;
}
