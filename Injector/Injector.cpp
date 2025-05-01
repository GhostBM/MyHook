#include "Injector.h"
#include <malloc.h>
#include <StrSafe.h>

BOOL EnableDebugPrivilege(BOOL bEnable)
{
	// 附给本进程特权，以便访问系统进程
	BOOL bOk = FALSE;
	HANDLE hToken;

	// 打开一个进程的访问令牌
	if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		// 取得特权名称为“SetDebugPrivilege”的LUID
		LUID uID;
		::LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &uID);

		// 调整特权级别
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = uID;
		tp.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
		::AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
		bOk = (::GetLastError() == ERROR_SUCCESS);

		// 关闭访问令牌句柄
		::CloseHandle(hToken);
	}
	return bOk;
}

Injector::Injector():m_hProcess(NULL)
{
}

Injector::~Injector()
{
	if (m_hProcess == NULL)
		return;
	CloseHandle(m_hProcess);
}

BOOL Injector::SetTarProcessId(const DWORD& dwProcessId)
{
	//1.打开进程
	//EnableDebugPrivilege(true);
	HANDLE tempHandle = OpenProcess(PROCESS_QUERY_INFORMATION |PROCESS_CREATE_THREAD |PROCESS_VM_OPERATION |PROCESS_VM_WRITE|PROCESS_VM_READ,FALSE, dwProcessId);
	if (tempHandle == NULL)
	{
		return FALSE;
	}
	//2.关闭原有进程句柄
	if (m_hProcess != NULL)
	{
		CloseHandle(m_hProcess);
	}
	//3.赋值
	m_hProcess = tempHandle;
	return TRUE;
}

DWORD Injector::GetCurProcessId()
{
	if (m_hProcess == NULL)
		return -1;
	return GetProcessId(m_hProcess);
}

BOOL Injector::InjectW(PCWSTR pszLibFile)
{
	//1.是否选择进程
	if (m_hProcess == NULL)
	{
		return FALSE;
	}
	//2.计算需要申请的空间大小
	SIZE_T pathLength = (1 + wcslen(pszLibFile)) * sizeof(wchar_t);

	//3.在目标进程内申请内存
	LPVOID  pVirtual= (PWSTR)VirtualAllocEx(m_hProcess, NULL, pathLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (pVirtual==NULL)
	{
		return FALSE;
	}
	//4.写入地址
	if (!WriteProcessMemory(m_hProcess, pVirtual,(PVOID)pszLibFile, pathLength, NULL))
	{
		//4.1释放地址
		VirtualFreeEx(m_hProcess, pVirtual, 0, MEM_RELEASE);
		return FALSE;
	}
	//5.获取LoadLibraryW地址
	FARPROC pfnThreadRtn = GetProcAddress(GetModuleHandleW(L"Kernel32"), "LoadLibraryW");
	if (pfnThreadRtn == NULL)
	{
		//5.1释放地址
		VirtualFreeEx(m_hProcess, pVirtual, 0, MEM_RELEASE);
		return FALSE;
	}
	//6.创建远程线程调用
	HANDLE hThread = CreateRemoteThread(m_hProcess, NULL, 0,
		(LPTHREAD_START_ROUTINE)pfnThreadRtn, pVirtual, 0, NULL);
	if (hThread==NULL)
	{
		//6.1释放地址
		VirtualFreeEx(m_hProcess, pVirtual, 0, MEM_RELEASE);
		return FALSE;
	}
	WaitForSingleObject(hThread, INFINITE);
	DWORD exitCode = 0;
	GetExitCodeThread(hThread, &exitCode);
	if (exitCode == 0) {
		DWORD error = GetLastError();
		wprintf(L"[错误] LoadLibraryW 失败，可能原因：路径无效、权限不足或 DLL 依赖缺失。\n");
	}
	//7.释放地址与线程
	if (pVirtual != NULL)
		VirtualFreeEx(m_hProcess, pVirtual, 0, MEM_RELEASE);
	if (hThread != NULL)
		CloseHandle(hThread);
	return TRUE;
}

BOOL Injector::InjectA(PCSTR pszLibFile)
{
	//1.获取大小
	SIZE_T pathLength = lstrlenA(pszLibFile) + 1;
	PWSTR pszLibFileW = (PWSTR)_alloca(pathLength * sizeof(wchar_t));

	//2.转换为宽字符
	StringCchPrintfW(pszLibFileW, pathLength, L"%S", pszLibFile);

	//3.注入
	BOOL bReturn = InjectW(pszLibFileW);

	//4.释放内存
	_freea(pszLibFileW);
	return bReturn;
}

BOOL Injector::EjectW(PCWSTR pszLibFile)
{
	//1.判断库是否存在与进程
	BYTE* pModBaseAddr = ExistLibW(pszLibFile);
	if (pModBaseAddr == NULL)
	{
		return FALSE;
	}
	//2.获取LoadLibraryW地址
	HMODULE hModule= GetModuleHandleW(TEXT("Kernel32"));
	if (hModule == NULL)
	{
		return FALSE;
	}
	FARPROC pfnThreadRtn = GetProcAddress(hModule, "FreeLibrary");
	if (pfnThreadRtn == NULL)
	{
		return FALSE;
	}
	//3.创建远程线程进行卸载
	HANDLE hThread = CreateRemoteThread(m_hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pfnThreadRtn, pModBaseAddr, 0, NULL);
	if (hThread == NULL)
	{
		return FALSE;
	}
	//4.等待卸载
	WaitForSingleObject(hThread, INFINITE);

	//5.卸载进程
	if (hThread != NULL)
		CloseHandle(hThread);
	return TRUE;
}

BOOL Injector::EjectA(PCSTR pszLibFile)
{
	//1.获取大小
	SIZE_T pathLength = lstrlenA(pszLibFile) + 1;
	PWSTR pszLibFileW = (PWSTR)malloc(pathLength * sizeof(wchar_t));
	if (pszLibFileW == NULL)
	{
		return FALSE;
	}
	//2.转换为宽字符
	StringCchPrintfW(pszLibFileW, pathLength, L"%S", pszLibFile);

	//3.卸载
	BOOL bReturn = EjectW(pszLibFileW);

	//4.释放内存
	free(pszLibFileW);
	return bReturn;
}

BYTE* Injector::ExistLibW(PCWSTR pszLibFile)
{
	//1.获取模块快照信息
	MODULEENTRY32W pModuleStrct;
	if (!GetSnapshotInfoOfLib(pszLibFile, &pModuleStrct))
	{
		return NULL;
	}
	return pModuleStrct.modBaseAddr;
}

int Injector::GetLoadingTimesW(PCWSTR pszLibFile)
{
	//1.获取模块快照信息
	MODULEENTRY32W pModuleStrct;
	if (!GetSnapshotInfoOfLib(pszLibFile, &pModuleStrct))
	{
		return 0;
	}
	return pModuleStrct.ProccntUsage;
}

BOOL Injector::GetSnapshotInfoOfLib(PCWSTR pszLibFile, LPMODULEENTRY32W pModuleStrct)
{
	//1.是否选择进程
	if (m_hProcess == NULL)
	{
		return FALSE;
	}
	//2.获取快照句柄
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurProcessId());
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	//3.遍历快照信息
	*pModuleStrct = { sizeof(*pModuleStrct) };
	BOOL bFound = FALSE;
	BOOL bNext = Module32FirstW(hSnapshot, pModuleStrct);
	for (; bNext; bNext = Module32NextW(hSnapshot, pModuleStrct)) {
		bFound = (_wcsicmp(pModuleStrct->szModule, pszLibFile) == 0) || (_wcsicmp(pModuleStrct->szExePath, pszLibFile) == 0);
		if (bFound)
		{
			break;
		}
	}
	//4.关闭句柄
	CloseHandle(hSnapshot);
	if (!bFound)
	{
		return FALSE;
	}
	return TRUE;
}
