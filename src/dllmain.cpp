#include <Windows.h>
#include <string>
#include <MinHook.h>
#include <algorithm>
#include <iphlpapi.h>

bool contains_w(std::wstring str, std::wstring substr) {
	std::transform(str.begin(), str.end(), str.begin(), towlower);
	std::transform(substr.begin(), substr.end(), substr.begin(), towlower);
	return str.find(substr) != std::wstring::npos;
}

bool contains(std::string str, std::string substr) {
	std::transform(str.begin(), str.end(), str.begin(), tolower);
	std::transform(substr.begin(), substr.end(), substr.begin(), tolower);
	return str.find(substr) != std::string::npos;
}

namespace AntiVM {
	namespace RegOpenKeyHooks {
		typedef LSTATUS(WINAPI* TRegOpenKeyW)(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult);
		TRegOpenKeyW oRegOpenKeyW;
		LSTATUS WINAPI
			hkRegOpenKeyW(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult) {
			if (contains_w(lpSubKey, L"vmware") || contains_w(lpSubKey, L"systeminformation")) {
				return ERROR_FILE_NOT_FOUND;
			}
			return oRegOpenKeyW(hKey, lpSubKey, phkResult);
		}

		typedef LSTATUS(WINAPI* TRegOpenKeyA)(HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult);
		TRegOpenKeyA oRegOpenKeyA;
		LSTATUS WINAPI hkRegOpenKeyA(HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult) {
			if (contains(lpSubKey, "vmware") || contains(lpSubKey, "systeminformation")) {
				return ERROR_FILE_NOT_FOUND;
			}
			return oRegOpenKeyA(hKey, lpSubKey, phkResult);
		}

		typedef LSTATUS(WINAPI* TRegOpenKeyExW)(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
		TRegOpenKeyExW oRegOpenKeyExW;
		LSTATUS WINAPI hkRegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult) {
			if (contains_w(lpSubKey, L"vmware") || contains_w(lpSubKey, L"systeminformation")) {
				return ERROR_FILE_NOT_FOUND;
			}
			return oRegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
		}

		typedef LSTATUS(WINAPI* TRegOpenKeyExA)(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
		TRegOpenKeyExA oRegOpenKeyExA;
		LSTATUS WINAPI hkRegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult) {
			if (contains(lpSubKey, "vmware") || contains(lpSubKey, "systeminformation")) {
				return ERROR_FILE_NOT_FOUND;
			}
			return oRegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult);
		}
	}

	namespace GetFileAttributesHooks {
		typedef DWORD(WINAPI* TGetFileAttributesW)(LPCWSTR lpFileName);
		TGetFileAttributesW oGetFileAttributesW;
		DWORD WINAPI hkGetFileAttributesW(LPCWSTR lpFileName) {
			if (contains_w(lpFileName, L"vm")) {
				return INVALID_FILE_ATTRIBUTES;
			}
			return oGetFileAttributesW(lpFileName);
		}

		typedef DWORD(WINAPI* TGetFileAttributesA)(LPCSTR lpFileName);
		TGetFileAttributesA oGetFileAttributesA;
		DWORD WINAPI hkGetFileAttributesA(LPCSTR lpFileName) {
			if (contains(lpFileName, "vm")) {
				return INVALID_FILE_ATTRIBUTES;
			}
			return oGetFileAttributesA(lpFileName);
		}

		typedef DWORD(WINAPI* TGetFileAttributesExW)(LPCWSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation);
		TGetFileAttributesExW oGetFileAttributesExW;
		DWORD WINAPI hkGetFileAttributesExW(LPCWSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation) {
			if (contains_w(lpFileName, L"vm")) {
				return INVALID_FILE_ATTRIBUTES;
			}
			return oGetFileAttributesExW(lpFileName, fInfoLevelId, lpFileInformation);
		}

		typedef DWORD(WINAPI* TGetFileAttributesExA)(LPCSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation);
		TGetFileAttributesExA oGetFileAttributesExA;
		DWORD WINAPI hkGetFileAttributesExA(LPCSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation) {
			if (contains(lpFileName, "vm")) {
				return INVALID_FILE_ATTRIBUTES;
			}
			return oGetFileAttributesExA(lpFileName, fInfoLevelId, lpFileInformation);
		}
	}

	namespace CreateFileHooks {
		typedef HANDLE(WINAPI* TCreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
		TCreateFileW oCreateFileW;
		HANDLE WINAPI hkCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
			if (contains_w(lpFileName, L"hgfs") || contains_w(lpFileName, L"vmci")) {
				return INVALID_HANDLE_VALUE;
			}
			return oCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
		}

		typedef HANDLE(WINAPI* TCreateFileA)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
		TCreateFileA oCreateFileA;
		HANDLE WINAPI hkCreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
			if (contains(lpFileName, "hgfs") || contains(lpFileName, "vmci")) {
				return INVALID_HANDLE_VALUE;
			}
			return oCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
		}
	}

	namespace GetAdaptersInfoHooks {
		typedef DWORD(WINAPI* TGetAdaptersInfo)(PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen);
		TGetAdaptersInfo oGetAdaptersInfo;
		DWORD WINAPI hkGetAdaptersInfo(PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen) {
			return ERROR_NOT_SUPPORTED;
		}
	}

	namespace GetSystemFirmwareTableHooks {
		typedef UINT(WINAPI* TGetSystemFirmwareTable)(DWORD FirmwareTableProviderSignature, DWORD FirmwareTableID, PVOID pFirmwareTableBuffer, DWORD BufferSize);
		TGetSystemFirmwareTable oGetSystemFirmwareTable;
		UINT WINAPI hkGetSystemFirmwareTable(DWORD FirmwareTableProviderSignature, DWORD FirmwareTableID, PVOID pFirmwareTableBuffer, DWORD BufferSize) {
			return ERROR_NOT_SUPPORTED;
		}
	}
}

void HookVMWareDetection() {
	MH_CreateHookApi(L"Iphlpapi.dll", "GetAdaptersInfo", &AntiVM::GetAdaptersInfoHooks::hkGetAdaptersInfo, reinterpret_cast<LPVOID*>(&AntiVM::GetAdaptersInfoHooks::oGetAdaptersInfo));
	MH_CreateHookApi(L"Kernel32.dll", "GetSystemFirmwareTable", &AntiVM::GetSystemFirmwareTableHooks::hkGetSystemFirmwareTable, reinterpret_cast<LPVOID*>(&AntiVM::GetSystemFirmwareTableHooks::oGetSystemFirmwareTable));

	MH_CreateHookApi(L"Kernel32.dll", "CreateFileW", &AntiVM::CreateFileHooks::hkCreateFileW, reinterpret_cast<LPVOID*>(&AntiVM::CreateFileHooks::oCreateFileW));
	MH_CreateHookApi(L"Kernel32.dll", "CreateFileA", &AntiVM::CreateFileHooks::hkCreateFileA, reinterpret_cast<LPVOID*>(&AntiVM::CreateFileHooks::oCreateFileA));

	MH_CreateHookApi(L"Kernel32.dll", "GetFileAttributesW", &AntiVM::GetFileAttributesHooks::hkGetFileAttributesW, reinterpret_cast<LPVOID*>(&AntiVM::GetFileAttributesHooks::oGetFileAttributesW));
	MH_CreateHookApi(L"Kernel32.dll", "GetFileAttributesA", &AntiVM::GetFileAttributesHooks::hkGetFileAttributesA, reinterpret_cast<LPVOID*>(&AntiVM::GetFileAttributesHooks::oGetFileAttributesA));
	MH_CreateHookApi(L"Kernel32.dll", "GetFileAttributesExW", &AntiVM::GetFileAttributesHooks::hkGetFileAttributesExW, reinterpret_cast<LPVOID*>(&AntiVM::GetFileAttributesHooks::oGetFileAttributesExW));
	MH_CreateHookApi(L"Kernel32.dll", "GetFileAttributesExA", &AntiVM::GetFileAttributesHooks::hkGetFileAttributesExA, reinterpret_cast<LPVOID*>(&AntiVM::GetFileAttributesHooks::oGetFileAttributesExA));

	MH_CreateHookApi(L"Advapi32.dll", "RegOpenKeyW", &AntiVM ::RegOpenKeyHooks::hkRegOpenKeyW, reinterpret_cast<LPVOID*>(&AntiVM::RegOpenKeyHooks::oRegOpenKeyW));
	MH_CreateHookApi(L"Advapi32.dll", "RegOpenKeyA", &AntiVM::RegOpenKeyHooks::hkRegOpenKeyA, reinterpret_cast<LPVOID*>(&AntiVM::RegOpenKeyHooks::oRegOpenKeyA));
	MH_CreateHookApi(L"Advapi32.dll", "RegOpenKeyExW", &AntiVM::RegOpenKeyHooks::hkRegOpenKeyExW, reinterpret_cast<LPVOID*>(&AntiVM::RegOpenKeyHooks::oRegOpenKeyExW));
	MH_CreateHookApi(L"Advapi32.dll", "RegOpenKeyExA", &AntiVM::RegOpenKeyHooks::hkRegOpenKeyExA, reinterpret_cast<LPVOID*>(&AntiVM::RegOpenKeyHooks::oRegOpenKeyExA));
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MH_Initialize();
		HookVMWareDetection();;
        MH_EnableHook(MH_ALL_HOOKS);
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}