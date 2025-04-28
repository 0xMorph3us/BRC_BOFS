//#define DEBUG_MODE
#ifdef DEBUG_MODE
#define DEBUG_PRINT(dispatch, ...) BadgerDispatch(dispatch, __VA_ARGS__)
#else
#define DEBUG_PRINT(dispatch, ...)
#endif

// Declarations for MSVC
DECLSPEC_IMPORT int MSVCRT$_itoa(int value, char* str, int radix);
DECLSPEC_IMPORT int MSVCRT$sprintf(char *str, const char *format, ...);
DECLSPEC_IMPORT int MSVCRT$swprintf(wchar_t* ws, size_t len, const wchar_t* format, ...);
DECLSPEC_IMPORT int MSVCRT$strcmp(const char *str1, const char *str2);
DECLSPEC_IMPORT int MSVCRT$strncmp(const char *str1, const char *str2, size_t num);
DECLSPEC_IMPORT void* MSVCRT$realloc(void* memblock, size_t size);
DECLSPEC_IMPORT int MSVCRT$_wcsicmp(const wchar_t* _Str1, const wchar_t* _Str2);
DECLSPEC_IMPORT wchar_t* MSVCRT$wcscat(wchar_t* _Dest, const wchar_t* _Source);
DECLSPEC_IMPORT wchar_t* MSVCRT$wcscpy(wchar_t* _Dest, const wchar_t* _Source);

// ADVAPI
DECLSPEC_IMPORT LSTATUS ADVAPI32$RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
DECLSPEC_IMPORT LSTATUS ADVAPI32$RegEnumKeyExA(HKEY hKey, DWORD dwIndex, LPSTR lpName, LPDWORD lpcchName, LPDWORD lpReserved, LPSTR lpClass, LPDWORD lpcchClass, PFILETIME lpftLastWriteTime);
DECLSPEC_IMPORT LSTATUS ADVAPI32$RegQueryValueExA(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
DECLSPEC_IMPORT LSTATUS ADVAPI32$RegCloseKey(HKEY hKey);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
DECLSPEC_IMPORT DWORD ADVAPI32$RegQueryInfoKeyA(HKEY hKey, LPSTR lpClass, LPDWORD lpcClass, LPDWORD lpReserved, LPDWORD lpcSubKeys, LPDWORD lpcMaxSubKeyLen, LPDWORD lpcMaxClassLen, LPDWORD lpcValues, LPDWORD lpcMaxValueNameLen, LPDWORD lpcMaxValueLen, LPDWORD lpcbSecurityDescriptor, PFILETIME lpftLastWriteTime);
DECLSPEC_IMPORT LSTATUS ADVAPI32$RegEnumValueA(HKEY hKey, DWORD dwIndex, LPSTR lpValueName, LPDWORD lpcchValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
WINADVAPI WINBOOL WINAPI ADVAPI32$OpenProcessToken (HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
DECLSPEC_IMPORT PVOID WINAPI ADVAPI32$FreeSid(PSID pSid);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegGetValueA(HKEY hkey, LPCSTR lpSubKey, LPCSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegGetValueW(HKEY hkey, LPCWSTR lpSubKey, LPCWSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData);
DECLSPEC_IMPORT PDWORD ADVAPI32$GetSidSubAuthority(PSID pSid, DWORD nSubAuthority);
DECLSPEC_IMPORT PUCHAR ADVAPI32$GetSidSubAuthorityCount(PSID pSid);
DECLSPEC_IMPORT SC_HANDLE ADVAPI32$OpenSCManagerW(LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess);
DECLSPEC_IMPORT SC_HANDLE ADVAPI32$OpenServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, DWORD dwDesiredAccess);
DECLSPEC_IMPORT BOOL ADVAPI32$ChangeServiceConfigW(SC_HANDLE hService, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCWSTR lpBinaryPathName, LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCWSTR lpDependencies, LPCWSTR lpServiceStartName, LPCWSTR lpPassword, LPCWSTR lpDisplayName);
DECLSPEC_IMPORT BOOL ADVAPI32$CloseServiceHandle(SC_HANDLE hSCObject);
DECLSPEC_IMPORT BOOL ADVAPI32$QueryServiceStatusEx(SC_HANDLE hService, SC_STATUS_TYPE InfoLevel, LPBYTE lpBuffer, DWORD cbBufSize, LPDWORD pcbBytesNeeded);
DECLSPEC_IMPORT BOOL ADVAPI32$ControlService(SC_HANDLE hService, DWORD dwControl, LPSERVICE_STATUS lpServiceStatus);
DECLSPEC_IMPORT BOOL ADVAPI32$StartServiceW(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCWSTR* lpServiceArgVectors);
DECLSPEC_IMPORT BOOL ADVAPI32$QueryServiceConfigW(SC_HANDLE hService, LPQUERY_SERVICE_CONFIGW lpServiceConfig, DWORD cbBufSize, LPDWORD pcbBytesNeeded);
DECLSPEC_IMPORT BOOL ADVAPI32$GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);


// KERNEL32
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess (VOID);
DECLSPEC_IMPORT DWORD KERNEL32$GetCurrentProcessId(VOID);
WINBASEAPI LPSTR WINAPI Kernel32$lstrcatA(LPSTR, LPCSTR);
WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA (LPCSTR lpLibFileName);
WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress (HMODULE hModule, LPCSTR lpProcName);
DECLSPEC_IMPORT int WINAPI KERNEL32$WideCharToMultiByte(
    UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar,
    LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError (VOID);
DECLSPEC_IMPORT BOOL KERNEL32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
DECLSPEC_IMPORT HLOCAL KERNEL32$LocalAlloc(UINT uFlags, SIZE_T uBytes);
DECLSPEC_IMPORT HLOCAL KERNEL32$LocalFree(HLOCAL hMem);
DECLSPEC_IMPORT DWORD KERNEL32$CloseHandle(HANDLE hObject);