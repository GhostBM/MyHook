#include "stdafx.h"
#include "HookManager.h"
using namespace Hook;

void WideCharToChar(PTSTR wStr, PSTR &str)
{
	int iSize = WideCharToMultiByte(CP_ACP, 0, wStr, -1, NULL, 0, NULL, NULL);
	str = new char[iSize];
	WideCharToMultiByte(CP_ACP, 0, wStr, -1, str, iSize, NULL, NULL);
}

HookManager::HookManager()
{
	m_pHookTool = new HookTool();
}

HookManager::~HookManager()
{
	if (m_pHookTool)
	{
		delete m_pHookTool;
	}
	for (HookControl* pControl:m_pLHookInfo)
	{
		delete pControl;
		pControl = NULL;
	}
	m_pLHookInfo.clear();
}

void HookManager::HookFunction(LPVOID pContentAddress)
{
	//1.获取用户传入参数
	Param pParam;
	HANDLE hProcess = GetCurrentProcess();
	if (NULL == hProcess)
	{
		return;
	}
	//2.写入内存
	ReadProcessMemory(hProcess, pContentAddress, &pParam.paramInfo, sizeof(pParam.paramInfo), NULL);

	LPVOID pTmpAddress = (LPVOID)((__int64)pContentAddress+sizeof(pParam.paramInfo));
	pParam.moduleName = (PTSTR)pTmpAddress;
	pTmpAddress= (LPVOID)((__int64)pTmpAddress + (wcslen(pParam.moduleName)+1)*sizeof(wchar_t));
	pParam.funName = (PTSTR)pTmpAddress;
	//2.获取Hook段大小
	int hookSize = GetHookSize(pParam);
	if (hookSize == 0)
	{
		return;
	}
	//3.创建需要hook函数信息
	HookControl* pControl = HookFunction(pParam, hookSize);
	if (NULL == pControl)
	{
		return;
	}
	//4.构造替换内容
	BYTE* pNewContent = CHookContent(pParam);
	if (pNewContent == NULL)
	{
		return;
	}
	pControl->pHookInfo->SetNewContent(pNewContent);
	//5.设置进程通信互斥量
	SetCommunicationMutex(pParam, pControl);
	//6.进行Hook
	m_pHookTool->SHook(pControl->pHookInfo);
}

void Hook::HookManager::UnHook(LPVOID pContentAddress)
{
	//1.获取用户传入参数
	Param pParam;
	HANDLE hProcess = GetCurrentProcess();
	if (NULL == hProcess)
	{
		return;
	}
	//2.写入内存
	ReadProcessMemory(hProcess, pContentAddress, &pParam.paramInfo, sizeof(pParam.paramInfo), NULL);

	LPVOID pTmpAddress = (LPVOID)((__int64)pContentAddress + sizeof(pParam.paramInfo));
	pParam.moduleName = (PTSTR)pTmpAddress;
	pTmpAddress = (LPVOID)((__int64)pTmpAddress + (wcslen(pParam.moduleName) + 1) * sizeof(wchar_t));
	pParam.funName = (PTSTR)pTmpAddress;
	//2.卸载Hook
	UnHook(pParam);
}

void Hook::HookManager::PHook(LPVOID pContentAddress)
{
	//1.获取用户传入参数
	Param* pParam = (Param*)(pContentAddress);
	if (NULL == pParam)
	{
		return;
	}
	//2.开启Hook
	StartHook(*pParam, true);
}

void Hook::HookManager::CHook(LPVOID pContentAddress)
{
	//1.获取用户传入参数
	Param* pParam = (Param*)(pContentAddress);
	if (NULL == pParam)
	{
		return;
	}
	//2.开启Hook
	StartHook(*pParam,false);
}

//char* HookManager::CHookContent(const Param& paramInfo)
//{
//	////外部释放
//	//char *pCode=new char[OverlaySize];
//	////mov r11 funAddress
//	//pCode[0] = 0X49;
//	//pCode[1] = 0XB8;
//	////INT64 FunAddr = hookInfo->GetHookAddress();
//	//memcpy(pCode + 2, &pVoidInfo, 8);
//	////jmp r11
//	//pCode[10] = 0X41;
//	//pCode[11] = 0XFF;
//	//pCode[12] = 0XE3;
//	//return pCode;
//}

//void HookManager::SetCommunicationMutex(Param& paramInfo)
//{
//	return;
//}

HookManager::HookControl* HookManager::HookFunction(const Param& paramInfo,int hookSize)
{
	//1.判断变量输入
	if (wcscmp(paramInfo.moduleName, L"") == 0 || wcscmp(paramInfo.funName, L"") == 0)
	{
		return NULL;
	}
	//2.获取模块句柄
	HMODULE hModule = GetModuleHandleW(paramInfo.moduleName);
	if (NULL == hModule)
	{
		return NULL;
	}
	//3.获取函数地址
	PSTR funName = NULL;
	WideCharToChar(paramInfo.funName, funName);
	FARPROC  funAddress = ::GetProcAddress(hModule, funName);
	delete[]funName;
	if (NULL == funAddress)
	{
		int error = GetLastError();
		printf("%d", error);
		return NULL;
	}
	//4.判断是否已经Hook
	HookControl* pTmpHook = FindHook(funAddress, m_pLHookInfo);
	if (NULL == pTmpHook)
	{
		pTmpHook = GetFirstUHook(m_pLHookInfo);
		if (pTmpHook)
		{
			pTmpHook->pHookInfo->Reset();
		}
	}
	//处理上一次的句柄
	if (pTmpHook)
	{
		pTmpHook->Restroy();
	}
	else
	{
		pTmpHook = new HookControl();
		m_pLHookInfo.push_back(pTmpHook);
	}
	if (NULL== pTmpHook->pHookInfo)
	{
		pTmpHook->pHookInfo = new Hook::HookInfo(hookSize);
	}
	pTmpHook->pHookInfo->SetHookAddress(funAddress);
	//9.获取已有的内容
	if (NULL == pTmpHook->pHookInfo->GetOldContent() || pTmpHook->pHookInfo->GetOldContent()==NULL)
	{
		BYTE *pCode=new BYTE[hookSize];
		ReadProcessMemory(GetCurrentProcess(), (FARPROC)pTmpHook->pHookInfo->GetHookAddress(), pCode, hookSize, NULL);
		pTmpHook->pHookInfo->SetOldContent(pCode);
		delete[]pCode;
	}
	pTmpHook->paramInfo = paramInfo.paramInfo;
	return pTmpHook;
}


bool HookManager::UnHook(const Param& paramInfo)
{
	//1.判断变量输入
	if (wcscmp(paramInfo.moduleName, L"") == 0 || wcscmp(paramInfo.funName, L"") == 0)
	{
		return false;
	}
	//2.获取模块句柄
	HMODULE hModule = GetModuleHandleW(paramInfo.moduleName);
	if (NULL == hModule)
	{
		return false;
	}
	//3.获取函数地址
	PSTR funName = NULL;
	WideCharToChar(paramInfo.funName, funName);
	FARPROC  funAddress = ::GetProcAddress(hModule, funName);
	delete[]funName;
	if (NULL == funAddress)
	{
		return false;
	}
	//4.判断是否已经Hook
	HookControl* pTmpHook = FindHook(funAddress, m_pLHookInfo);
	if (NULL == pTmpHook)
	{
		return false;
	}
	//5.判断Hook状态
	if (pTmpHook->pHookInfo->GetHookState() == HookInfo::HookState::HOOK)
	{
		return true;
	}
	m_pHookTool->UHook(pTmpHook->pHookInfo);
	if (pTmpHook->sMulex)
	{
		CloseHandle(pTmpHook->sMulex);
		pTmpHook->sMulex = NULL;
	}
	if (pTmpHook->cMulex)
	{
		CloseHandle(pTmpHook->cMulex);
		pTmpHook->cMulex = NULL;
	}
	if (pTmpHook->hExchange)
	{
		CloseHandle(pTmpHook->hExchange);
		pTmpHook->hExchange = NULL;
	}
	return true;
}

bool Hook::HookManager::StartHook(const Param& paramInfo, const bool& bPause)
{
	//1.判断变量输入
	if (wcscmp(paramInfo.moduleName, L"") == 0 || wcscmp(paramInfo.funName, L"") == 0)
	{
		return false;
	}
	//2.获取模块句柄
	HMODULE hModule = GetModuleHandleW(paramInfo.moduleName);
	if (NULL == hModule)
	{
		return false;
	}
	//3.获取函数地址
	PSTR funName = NULL;
	WideCharToChar(paramInfo.funName, funName);
	FARPROC  funAddress = ::GetProcAddress(hModule, funName);
	delete[]funName;
	if (NULL == funAddress)
	{
		return false;
	}
	//4.判断是否已经Hook
	HookControl* pTmpHook = FindHook(funAddress, m_pLHookInfo);
	if (NULL == pTmpHook)
	{
		return false;
	}
	//5.判断Hook状态
	if (pTmpHook->pHookInfo->GetHookState() == HookInfo::HookState::UNHOOK)
	{
		return false;
	}
	if (bPause)
	{
		if (pTmpHook->pHookInfo->GetHookState() == HookInfo::HookState::Pause)
		{
			return true;
		}
		m_pHookTool->PHook(pTmpHook->pHookInfo);
		return true;
	}
	if (pTmpHook->pHookInfo->GetHookState() == HookInfo::HookState::HOOK)
	{
		return true;
	}
	m_pHookTool->SHook(pTmpHook->pHookInfo);
	return true;

	return true;
}

HookManager::HookControl* HookManager::FindHook(FARPROC iAddress,const std::list<HookControl*>&pLHookControl)
{
	for (HookControl* pControl : pLHookControl)
	{
		//已经Hook了该地址
		HookInfo* pHook = pControl->pHookInfo;
		if (pHook == NULL)
		{
			continue;
		}
		if ((FARPROC)pHook->GetHookAddress() == iAddress)
		{
			return pControl;
		}
	}
	return nullptr;
}


HookManager::HookControl* HookManager::GetFirstUHook(const std::list<HookControl*>& pLHookControl)
{
	for (HookControl* pControl : pLHookControl)
	{
		//4.1已经Hook了该地址
		HookInfo* pHook = pControl->pHookInfo;
		if (pHook == NULL)
		{
			continue;
		}
		if (pHook->GetHookState() != HookInfo::HookState::UNHOOK)
		{
			continue;
		}
		return pControl;
	}
	return nullptr;
}