#include <ws2tcpip.h> // Required for inet_ntop, struct in6_addr, and AF_INET6
#include <windows.h>
#include "badger_exports.h"
#include <lm.h>
#include <windns.h>
#include <iphlpapi.h> // Required for GetAdaptersAddresses

// API Function Declarations and Imports
DECLSPEC_IMPORT NET_API_STATUS NET_API_FUNCTION NETAPI32$NetSessionEnum(
    LPCWSTR servername,
    LPCWSTR UncClientName,
    LPCWSTR UserName,
    DWORD Level,
    LPBYTE* bufptr,
    DWORD prefmaxlen,
    LPDWORD entriesread,
    LPDWORD totalentries,
    LPDWORD resume_handle
);

DECLSPEC_IMPORT NET_API_STATUS NET_API_FUNCTION NETAPI32$NetWkstaGetInfo(
    LPCWSTR servername,
    DWORD level,
    LPBYTE* bufptr
);

DECLSPEC_IMPORT NET_API_STATUS NET_API_FUNCTION NETAPI32$NetApiBufferFree(
    LPVOID Buffer
);

DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(
    UINT CodePage,
    DWORD dwFlags,
    LPCCH lpMultiByteStr,
    int cbMultiByte,
    LPWSTR lpWideCharStr,
    int cchWideChar
);

DECLSPEC_IMPORT wchar_t* MSVCRT$wcschr(
    const wchar_t *str,
    wchar_t ch
);

DECLSPEC_IMPORT size_t MSVCRT$wcstombs(
    char *dest,
    const wchar_t *src,
    size_t n
);

DECLSPEC_IMPORT char* MSVCRT$strtok(
    char *str,
    const char *delim
);

DECLSPEC_IMPORT int MSVCRT$sprintf(
    char *str,
    const char *format,
    ...
);

DECLSPEC_IMPORT int WSAAPI WS2_32$GetAddrInfoW(
    PCWSTR pNodeName,
    PCWSTR pServiceName,
    const ADDRINFOW* pHints,
    PADDRINFOW* ppResult
);

DECLSPEC_IMPORT void WSAAPI WS2_32$FreeAddrInfoW(
    PADDRINFOW pAddrInfo
);

DECLSPEC_IMPORT int MSVCRT$wcscmp(
    const wchar_t *str1,
    const wchar_t *str2
);

DECLSPEC_IMPORT PCSTR WSAAPI WS2_32$inet_ntop(
    int Family,
    const void* pAddr,
    PSTR pStringBuf,
    size_t StringBufSize
);

DECLSPEC_IMPORT void* MSVCRT$memset(
    void* dest,
    int ch,
    size_t count
);

DECLSPEC_IMPORT BOOL WINAPI KERNEL32$GetComputerNameExW(
    COMPUTER_NAME_FORMAT NameType,
    LPWSTR lpBuffer,
    LPDWORD nSize
);

DECLSPEC_IMPORT PVOID BadgerAlloc(SIZE_T length);
DECLSPEC_IMPORT VOID BadgerFree(PVOID *memptr);

DECLSPEC_IMPORT DNS_STATUS WINAPI DNSAPI$DnsQuery_A(
    PCSTR pszName,
    WORD wType,
    DWORD Options,
    PVOID pExtra,
    PDNS_RECORD* ppQueryResultsSet,
    PVOID pReserved
);

DECLSPEC_IMPORT VOID WINAPI DNSAPI$DnsFree(
    PVOID pData,
    DNS_FREE_TYPE FreeType
);

DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(
    LPCSTR lpLibFileName
);

DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(
    HMODULE hModule,
    LPCSTR lpProcName
);

DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FreeLibrary(
    HMODULE hLibModule
);

DECLSPEC_IMPORT ULONG WINAPI IPHLPAPI$GetAdaptersAddresses(
    ULONG Family,
    ULONG Flags,
    PVOID Reserved,
    PIP_ADAPTER_ADDRESSES AdapterAddresses,
    PULONG SizePointer
);

typedef const char* (WSAAPI *my_inet_ntop)(
    int af,
    const void* src,
    char* dst,
    size_t size
);

// Helper function to query DNS records
void query_domain(const char *domainname, unsigned short wType, const char *dnsserver, PDNS_RECORD base, PIP4_ARRAY pSrvList, WCHAR **dispatch)
{
    PDNS_RECORD pdns = NULL;
    DWORD options = DNS_QUERY_WIRE_ONLY;
    DNS_FREE_TYPE freetype = DnsFreeRecordListDeep;
    DWORD status = 0;

    status = DNSAPI$DnsQuery_A(domainname, wType, options, pSrvList, &base, NULL);

    pdns = base;
    if (status != 0 || pdns == NULL)
    {
        BadgerDispatch(dispatch, "PTR: No PTR record found; reverse lookup failed\n");
        return;
    }

    do {
        if (pdns->wType == DNS_TYPE_PTR) {
            BadgerDispatch(dispatch, "PTR: %s\n", pdns->Data.PTR.pNameHost);
        }
        pdns = pdns->pNext;
    } while (pdns);

    if (base) {
        DNSAPI$DnsFree(base, freetype);
    }
}

// Helper function to get the primary IPv4 address for the hostname
BOOL GetIPv4ForHostname(const wchar_t* hostname, char* ipv4addr, size_t size) {
    ADDRINFOW hints;
    ADDRINFOW* result = NULL;
    ADDRINFOW* ptr = NULL;
    int ret = 0;
    
    MSVCRT$memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // IPv4 only

    ret = WS2_32$GetAddrInfoW(hostname, NULL, &hints, &result);
    if (ret != 0) {
        return FALSE;
    }

    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        struct sockaddr_in* sockaddr_ipv4 = (struct sockaddr_in*)ptr->ai_addr;
        if (WS2_32$inet_ntop(AF_INET, &sockaddr_ipv4->sin_addr, ipv4addr, size)) {
            WS2_32$FreeAddrInfoW(result);
            return TRUE;
        }
    }

    WS2_32$FreeAddrInfoW(result);
    return FALSE;
}

// NetSessions function with more verbose output
void NetSessions(wchar_t* hostname, unsigned short resolveMethod, char* dnsserver, WCHAR** dispatch)
{
    LPSESSION_INFO_10 pBuf = NULL;
    LPSESSION_INFO_10 pTmpBuf;
    DWORD dwLevel = 10;
    DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    DWORD dwResumeHandle = 0;
    DWORD i;
    DWORD dwTotalCount = 0;
    LPWSTR pszServerName = hostname;
    NET_API_STATUS nStatus;

    PDNS_RECORD base = NULL;
    my_inet_ntop inetntop_fn = NULL;
    HMODULE WS = NULL;
    PIP4_ARRAY pSrvList = NULL;
    WKSTA_INFO_100* pInfo = NULL;
    BOOL isLocalHost = FALSE;

    // Load ws2_32.dll for inet_ntop
    WS = KERNEL32$LoadLibraryA("ws2_32.dll");
    if (WS) {
        inetntop_fn = (my_inet_ntop)KERNEL32$GetProcAddress(WS, "inet_ntop");
        if (!inetntop_fn) {
            BadgerDispatch(dispatch, "[ERROR] Could not find inet_ntop function\n");
            return;
        }
    } else {
        BadgerDispatch(dispatch, "[ERROR] Could not load ws2_32.dll\n");
        return;
    }

    // If no hostname is provided, use localhost
    if (!hostname) {
        wchar_t localHostName[256];
        DWORD size = 256;
        if (KERNEL32$GetComputerNameExW(ComputerNameDnsFullyQualified, localHostName, &size)) {
            pszServerName = localHostName;
            isLocalHost = TRUE;
        }
    } else {
        // Check if the provided hostname matches the local machine's hostname
        wchar_t localHostName[256];
        DWORD size = 256;
        if (KERNEL32$GetComputerNameExW(ComputerNameDnsFullyQualified, localHostName, &size)) {
            if (MSVCRT$wcscmp(hostname, localHostName) == 0) {
                pszServerName = localHostName;
                isLocalHost = TRUE;
            }
        }
    }

    do
    {
        char ipv4addr[INET_ADDRSTRLEN] = { 0 };
        if (GetIPv4ForHostname(pszServerName, ipv4addr, sizeof(ipv4addr))) {
            BadgerDispatch(dispatch, "Server: %S [%s]\n", pszServerName, ipv4addr);
        } else {
            BadgerDispatch(dispatch, "Server: %S\n", pszServerName);
        }

        nStatus = NETAPI32$NetSessionEnum(pszServerName,
            NULL,
            NULL,
            dwLevel,
            (LPBYTE*)&pBuf,
            dwPrefMaxLen,
            &dwEntriesRead,
            &dwTotalEntries,
            &dwResumeHandle);

        if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
        {
            if ((pTmpBuf = pBuf) != NULL)
            {
                for (i = 0; (i < dwEntriesRead); i++)
                {
                    if (pTmpBuf == NULL)
                    {
                        BadgerDispatch(dispatch, "[ERROR] An access violation has occurred\n");
                        break;
                    }

                    BadgerDispatch(dispatch, "---------------Session--------------\n");

                    wchar_t* clientname = pTmpBuf->sesi10_cname;
                    char clientIPv4[INET_ADDRSTRLEN] = { 0 };

                    if (clientname[0] == L'\\' && clientname[1] == L'\\') {
                        clientname += 2;  // Move the pointer past the '\\'
                    }

                    // Resolve to IPv4 if running on localhost
                    if (isLocalHost && GetIPv4ForHostname(pszServerName, clientIPv4, sizeof(clientIPv4))) {
                        clientname = (wchar_t*)BadgerAlloc(INET_ADDRSTRLEN * sizeof(wchar_t));
                        KERNEL32$MultiByteToWideChar(CP_UTF8, 0, clientIPv4, -1, clientname, INET_ADDRSTRLEN);
                    }

                    BadgerDispatch(dispatch, "Client: \\\\%ls\n", clientname);

                    if (resolveMethod == 1)
                    {
                        // if the client name is an IP address, query the DNS server for the hostname (in arpa format)
                        if (clientname[0] >= L'0' && clientname[0] <= L'9') {
                            char ipAddress[16];
                            MSVCRT$wcstombs(ipAddress, clientname, sizeof(ipAddress));

                            char* octets[4];
                            int j = 0;
                            char* token = MSVCRT$strtok(ipAddress, ".");
                            while (token != NULL && j < 4) {
                                octets[j] = token;
                                token = MSVCRT$strtok(NULL, ".");
                                j++;
                            }

                            if (j != 4)
                            {
                                BadgerDispatch(dispatch, "PTR: Failed; Invalid IP address\n");
                            }
                            else
                            {
                                char arpaFormat[256];
                                MSVCRT$sprintf(arpaFormat, "%s.%s.%s.%s.in-addr.arpa", octets[3], octets[2], octets[1], octets[0]);
                                query_domain(arpaFormat, DNS_TYPE_PTR, NULL, base, pSrvList, dispatch);
                            }
                        }
                    }
                    else 
                    {
                        NET_API_STATUS stat = NETAPI32$NetWkstaGetInfo(clientname, 100, (LPBYTE*)&pInfo);
                        if (stat == NERR_Success)
                        {
                            BadgerDispatch(dispatch, "ComputerName: %S\n", pInfo->wki100_computername);
                            BadgerDispatch(dispatch, "ComputerDomain: %S\n", pInfo->wki100_langroup);
                        }
                        else
                        {
                            BadgerDispatch(dispatch, "ComputerName: NetWkstaGetInfo Failed; %lu\n", stat);
                            BadgerDispatch(dispatch, "ComputerDomain: NetWkstaGetInfo Failed; %lu\n", stat);
                        }

                        if (pInfo != NULL)
                        {
                            NETAPI32$NetApiBufferFree(pInfo);
                            pInfo = NULL;
                        }
                    }

                    BadgerDispatch(dispatch, "User: %ls\n", pTmpBuf->sesi10_username);
                    BadgerDispatch(dispatch, "Active: %lu\n", pTmpBuf->sesi10_time);
                    BadgerDispatch(dispatch, "Idle: %lu\n", pTmpBuf->sesi10_idle_time);
                    BadgerDispatch(dispatch, "-------------End Session------------\n\n");

                    pTmpBuf++;
                    dwTotalCount++;
                }
            }
        }
        else
        {
            BadgerDispatch(dispatch, "[ERROR] A system error has occurred: %lu\n", nStatus);
            if (nStatus == ERROR_BAD_NETPATH || nStatus == 53) { // 53 is ERROR_BAD_NETPATH
                BadgerDispatch(dispatch, "[INFO] Possibly the firewall is enabled on the target.\n");
            }
        }

        if (pBuf != NULL)
        {
            NETAPI32$NetApiBufferFree(pBuf);
            pBuf = NULL;
        }

    } while (nStatus == ERROR_MORE_DATA);

    if (pBuf != NULL)
    {
        NETAPI32$NetApiBufferFree(pBuf);
    }

    BadgerDispatch(dispatch, "\nTotal of %lu entries enumerated\n", dwTotalCount);

END:
    if (pSrvList != NULL)
    {
        BadgerFree((PVOID*)&pSrvList);
    }

    if (WS)
    {
        KERNEL32$FreeLibrary(WS);
    }
}


int coffee(char** argv, int argc, WCHAR** dispatch)
{
    wchar_t* hostname = NULL;
    unsigned short resolveMethod = 1; // Default to DNS if no argument provided
    char* dnsserver = NULL;

    if (argc > 0 && argv[0] != NULL)
    {
        int len = KERNEL32$MultiByteToWideChar(CP_ACP, 0, argv[0], -1, NULL, 0);
        hostname = (wchar_t*)BadgerAlloc(len * sizeof(wchar_t));
        KERNEL32$MultiByteToWideChar(CP_ACP, 0, argv[0], -1, hostname, len);
    }

    if (argc > 1)
    {
        resolveMethod = (unsigned short)BadgerAtoi(argv[1]);
    }

    if (argc > 2)
    {
        dnsserver = argv[2];
    }

    // Dispatch session enumeration
    NetSessions(hostname, resolveMethod, dnsserver, dispatch);

    if (hostname)
    {
        BadgerFree((PVOID*)&hostname);
    }

    return 0;
}
