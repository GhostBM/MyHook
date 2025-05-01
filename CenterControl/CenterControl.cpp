#include "CenterControl.h"
#pragma comment(lib,"Injector.lib")
#define Milliseconds 30000
#define SendSize 1024*128
void SendFun(const CenterControl::HookControl& control)
{
	while (true)
	{
		DWORD dw = WaitForSingleObject(control.sMulex, NULL);
		if (control.hookState == CenterControl::HookState::UNHOOK)
		{
			break;
		}
		//1.获取传输数据
		SocketInfo newInfo;
		ReadSendInfo(control.pShareMemory, &newInfo);
		//4.通知中控
		ReleaseSemaphore(control.cMulex, 1, NULL);
	}
}

void RecvFun(const CenterControl::HookControl& control)
{
	while (true)
	{
		DWORD dw = WaitForSingleObject(control.sMulex, NULL);
		if (control.hookState == CenterControl::HookState::UNHOOK)
		{
			break;
		}
		//1.获取传输数据
		SocketInfo newInfo;
		ReadSendInfo(control.pShareMemory, &newInfo);
		printf("发送地址:%s,接受地址:%s,内容:%s\n", newInfo.strIP, newInfo.targetIP, newInfo.socketData);
		//4.通知中控
		ReleaseSemaphore(control.cMulex, 1, NULL);
	}
}

void RecvFromFun(const CenterControl::HookControl& control)
{
	while (true)
	{
		DWORD dw = WaitForSingleObject(control.sMulex, NULL);
		if (control.hookState == CenterControl::HookState::UNHOOK)
		{
			break;
		}
		//1.获取传输数据
		SocketInfo newInfo;
		ReadSendInfo(control.pShareMemory, &newInfo);
		//4.通知中控
		ReleaseSemaphore(control.cMulex, 1, NULL);
	}
}

void SendToFun(const CenterControl::HookControl& control)
{
	while (true)
	{
		DWORD dw = WaitForSingleObject(control.sMulex, NULL);
		if (control.hookState == CenterControl::HookState::UNHOOK)
		{
			break;
		}
		//1.获取传输数据
		SocketInfo newInfo;
		ReadSendInfo(control.pShareMemory, &newInfo);
		//4.通知中控
		ReleaseSemaphore(control.cMulex, 1, NULL);
	}
}


CenterControl::CenterControl()
{
	m_pInjector = new Injector();
}

CenterControl::~CenterControl()
{
	if (m_pInjector)
	{
		delete m_pInjector;
		m_pInjector = NULL;
	}
	std::map<long, std::vector<HookControl>> m_HookInfo;
	for (auto& pair : m_HookInfo)
	{
		for (HookControl& control : pair.second)
		{
			control.Restroy();
		}
	}
}

void CenterControl::InitControlHandle(HookControl& cControl, const long& PID, FunName type)
{
	wchar_t buffer[1024];
	wchar_t server[8] = { L"_server" };
	wchar_t client[8] = { L"_client" };
	wchar_t cfilemap[9] = { L"_filemap" };
	wchar_t pfunName[9];
	if (type == Send)
	{
		wcscpy_s(pfunName, L"send");
	}
	else if (type == SendTo)
	{
		wcscpy_s(pfunName, L"sendto");
	}
	else if (type == Recv)
	{
		wcscpy_s(pfunName, L"recv");
	}
	else if (type == RecvFrom)
	{
		wcscpy_s(pfunName, L"recvfrom");
	}
	//1.获取服务器信号量
	memset(buffer, 0, sizeof(buffer));
	swprintf_s(buffer, L"%ld", PID);
	wcscat_s(buffer, pfunName);
	wcscat_s(buffer, server);
	cControl.sMulex = CreateSemaphoreW(NULL,0,1, buffer);
	//0.获取客户端信号量
	memset(buffer, 0, sizeof(buffer));
	swprintf_s(buffer, L"%ld", PID);
	wcscat_s(buffer, pfunName);
	wcscat_s(buffer, client);
	cControl.cMulex = CreateSemaphoreW(NULL, 0, 1, buffer);
	//3.获取内存映射
	memset(buffer, 0, sizeof(buffer));
	swprintf_s(buffer, L"%ld", PID);
	wcscat_s(buffer, pfunName);
	wcscat_s(buffer, cfilemap);
	cControl.hExchange = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, SendSize, buffer);
	//4.得到共享内存的指针
	cControl.pShareMemory = (Param*)MapViewOfFile(cControl.hExchange, FILE_MAP_WRITE, 0, 0, SendSize);
}

bool CenterControl::HookFunction(__int64 PID, FunName type, const UserParamInfo& userParam)
{
	//1.获取当前PID所有Hook的对象
	std::vector<HookControl> &pControlVec= m_HookInfo[PID];
	HookControl* pHook = NULL;
	for (HookControl& cHook : pControlVec)
	{
		if (cHook.funType == type)
		{
			pHook = &cHook;
			break;
		}
	}
	if (NULL == pHook)
	{
		HookControl newControl;
		InitControlHandle(newControl, PID, type);
		pControlVec.push_back(newControl);
		pHook = &(*pControlVec.rbegin());
	}
	else
	{
		if (pHook->hookState == HOOK)
		{
			return false;
		}
	}
	if (type == Send)
	{
		WriteUserInfo(PID, L"ws2_32.dll", L"send", userParam,L"SHook");
		SendFun(*pHook);
	}
	else if (type == Recv)
	{
		WriteUserInfo(PID, L"ws2_32.dll", L"recv", userParam, L"SHook");
		RecvFun(*pHook);
	}
	else if (type == RecvFrom)
	{
		WriteUserInfo(PID, L"ws2_32.dll", L"recvfrom", userParam, L"SHook");
		RecvFromFun(*pHook);
	}
	else if (type == SendTo)
	{
		WriteUserInfo(PID, L"ws2_32.dll", L"sendto", userParam, L"SHook");
		SendToFun(*pHook);
	}
	return true;
}

bool CenterControl::UnHookFunction(__int64 PID, FunName type)
{
	//1.获取当前PID所有Hook的对象
	std::vector<HookControl>& pControlVec = m_HookInfo[PID];
	HookControl* pHook = NULL;
	for (HookControl& cHook : pControlVec)
	{
		if (cHook.funType == type)
		{
			pHook = &cHook;
			break;
		}
	}
	if (NULL == pHook|| pHook->hookState==UNHOOK)
	{
		return false;
	}
	UserParamInfo userParam;
	pHook->hookState = UNHOOK;
	const wchar_t* funName = NULL;
	
	if (type == Send)
	{
		funName = L"send";
	}
	else if (type == Recv)
	{
		funName = L"recv";
	}
	else if (type == RecvFrom)
	{
		funName = L"recvfrom";
	}
	else if (type == SendTo)
	{
		funName = L"sendto";
	}
	WriteUserInfo(PID, L"ws2_32.dll", funName, userParam, L"UnHook");
	return true;
}

void CenterControl::WriteUserInfo(__int64 pid, LPCWSTR moduleName, LPCWSTR functionName,const UserParamInfo&param, LPCWSTR executeFunName)
{
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD |
		PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, NULL, pid);
	if (NULL == hProcess)
	{
		return;
	}
	size_t iSize = (wcslen(moduleName)+1) * sizeof(wchar_t) + (wcslen(functionName)+1) * sizeof(wchar_t) + sizeof(param);
	LPVOID pMemory = (PWSTR)VirtualAllocEx(hProcess, NULL, iSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (pMemory == NULL)
		return;
	//2.写入内存
	try
	{
		WriteProcessMemory(hProcess, pMemory, &param, sizeof(param), NULL);
		__int64 tmpAddress = (__int64)pMemory + sizeof(param);
		WriteProcessMemory(hProcess, (LPVOID)tmpAddress, moduleName, (wcslen(moduleName) + 1) * sizeof(wchar_t), NULL);
		tmpAddress += (wcslen(moduleName)+1) * sizeof(wchar_t);
		WriteProcessMemory(hProcess, (LPVOID)tmpAddress
			, functionName, (wcslen(functionName)+1) * sizeof(wchar_t), NULL);
	}
	catch(...)
	{
		VirtualFreeEx(hProcess, pMemory, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return;
	}
	HMODULE pModuleAddress= GetRemoteDllBaseAddress(pid, L"HookTool.dll");
	do {
		if (NULL == pModuleAddress)
		{
			break;
		}
		PSTR tmpStr;
		WideCharToChar(executeFunName, tmpStr);
		FARPROC pLoadLibraryA = GetRemoteProcAddress(hProcess, pModuleAddress, tmpStr);
		delete tmpStr;

		if (NULL == pLoadLibraryA)
		{
			break;
		}
		HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (PTHREAD_START_ROUTINE)pLoadLibraryA, pMemory, 0, NULL);
		if (!hThread)
		{
			break;
		}
		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);
	} while (false);
	VirtualFreeEx(hProcess, pMemory, 0, MEM_RELEASE);
	CloseHandle(hProcess);
}

FARPROC CenterControl::GetRemoteProcAddress(HANDLE hProcess, HMODULE hModule, const char* funcName) {
	BYTE* moduleBase = reinterpret_cast<BYTE*>(hModule);

	// 读取DOS头
	IMAGE_DOS_HEADER dosHeader;
	if (!ReadProcessMemory(hProcess, moduleBase, &dosHeader, sizeof(dosHeader), nullptr) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
		return nullptr;
	}

	// 读取NT头
	IMAGE_NT_HEADERS ntHeaders;
	if (!ReadProcessMemory(hProcess, moduleBase + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders), nullptr) || ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
		return nullptr;
	}

	// 定位导出表
	IMAGE_DATA_DIRECTORY exportDir = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (exportDir.VirtualAddress == 0 || exportDir.Size == 0) {
		return nullptr;
	}

	// 读取导出表结构
	IMAGE_EXPORT_DIRECTORY exportTable;
	if (!ReadProcessMemory(hProcess, moduleBase + exportDir.VirtualAddress, &exportTable, sizeof(exportTable), nullptr)) {
		return nullptr;
	}

	// 获取导出函数名列表和地址表
	DWORD* nameRVAs = new DWORD[exportTable.NumberOfNames];
	WORD* ordinalTable = new WORD[exportTable.NumberOfNames];
	DWORD* funcRVAs = new DWORD[exportTable.NumberOfFunctions];

	ReadProcessMemory(hProcess, moduleBase + exportTable.AddressOfNames, nameRVAs, exportTable.NumberOfNames * sizeof(DWORD), nullptr);
	ReadProcessMemory(hProcess, moduleBase + exportTable.AddressOfNameOrdinals, ordinalTable, exportTable.NumberOfNames * sizeof(WORD), nullptr);
	ReadProcessMemory(hProcess, moduleBase + exportTable.AddressOfFunctions, funcRVAs, exportTable.NumberOfFunctions * sizeof(DWORD), nullptr);

	// 遍历函数名
	for (DWORD i = 0; i < exportTable.NumberOfNames; ++i) {
		char nameBuffer[256];
		ReadProcessMemory(hProcess, moduleBase + nameRVAs[i], nameBuffer, sizeof(nameBuffer), nullptr);
		if (strcmp(funcName, nameBuffer) == 0) {
			WORD ordinal = ordinalTable[i];
			DWORD funcRVA = funcRVAs[ordinal];
			delete[] nameRVAs;
			delete[] ordinalTable;
			delete[] funcRVAs;
			return (FARPROC)(moduleBase + funcRVA);
		}
	}

	// 清理资源
	delete[] nameRVAs;
	delete[] ordinalTable;
	delete[] funcRVAs;
	return nullptr;
}

HMODULE CenterControl::GetRemoteDllBaseAddress(DWORD processId, const wchar_t* dllName)
{
	MODULEENTRY32W me32 = { 0 };
	me32.dwSize = sizeof(MODULEENTRY32W);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return nullptr;
	if (!Module32FirstW(hSnapshot, &me32))
	{
		CloseHandle(hSnapshot);
		return nullptr;
	}	
	do
	{
		if (_wcsicmp(me32.szModule, dllName) == 0)
		{
			CloseHandle(hSnapshot);
			return me32.hModule; // DLL 基地址
		}
	} while (Module32NextW(hSnapshot, &me32));
	CloseHandle(hSnapshot);

	return nullptr;
}