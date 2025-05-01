#pragma once
#include "../Injector/Injector.h"
#include "../DBHelpTool/DBStruct.h"
#include "map"
#include "vector"


class CenterControl
{
public:
	enum  FunName
	{
		Send,
		SendTo,
		Recv,
		RecvFrom
	};
	enum HookState
	{
		UNHOOK = 0,
		HOOK,
		Pause
	};
public:
	//№ЬАн
	struct HookControl
	{
		void Restroy()
		{
			if (cMulex)
			{
				CloseHandle(cMulex);
				cMulex = NULL;
			}
			if (sMulex)
			{
				CloseHandle(sMulex);
				sMulex = NULL;
			}
			if (hExchange)
			{
				CloseHandle(hExchange);
				hExchange = NULL;
			}
			if (pShareMemory)
			{
				UnmapViewOfFile(pShareMemory);
				pShareMemory = NULL;
			}
		}
		HANDLE cMulex = NULL;
		HANDLE sMulex = NULL;
		HANDLE hExchange = NULL;
		LPVOID pShareMemory = NULL;
		FunName  funType;
		HookState hookState;
	};
public:
	CenterControl();
	~CenterControl();

	bool HookFunction(__int64 PID, FunName type, const UserParamInfo& userParam);

	bool UnHookFunction(__int64 PID, FunName type);
	
private:
	void InitControlHandle(HookControl&control, const long& PID, FunName type);

	void WriteUserInfo(__int64 pid, LPCWSTR moduleName, LPCWSTR functionName, const UserParamInfo& param,LPCWSTR executeFunName);

	HMODULE GetRemoteDllBaseAddress(DWORD processId,const wchar_t* dllName);

	FARPROC GetRemoteProcAddress(HANDLE hProcess, HMODULE hModule, const char* funcName);
private:
	Injector* m_pInjector;
	std::map<__int64, std::vector<HookControl>> m_HookInfo;
};

