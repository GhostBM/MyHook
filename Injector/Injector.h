#pragma once
#include <windows.h>
#include <TlHelp32.h>

#ifdef UNICODE
#define Inject InjectW
#define Eject  EjectW
#else
#define Inject InjectA
#define Eject  EjectA
#endif

#ifdef _HOOKLIB
#define HOOKAPI __declspec(dllexport)
#else
#define HOOKAPI __declspec(dllimport)
#endif

class HOOKAPI Injector
{
public:
	Injector();
	~Injector();
public:
	//设置进程ID
	BOOL SetTarProcessId(const DWORD& dwProcessId);

	//获取当前进程ID
	DWORD GetCurProcessId();

	//注入(最好是绝对路径)
	BOOL InjectW(PCWSTR pszLibFile);
	BOOL InjectA(PCSTR pszLibFile);

	//卸载
	BOOL EjectW(PCWSTR pszLibFile);
	BOOL EjectA(PCSTR pszLibFile);

	//获取模块地址
	BYTE* ExistLibW(PCWSTR pszLibFile);

	//获取模块被加载次数(Win11测试有效,资料说明这个参数是无用的)
	int GetLoadingTimesW(PCWSTR pszLibFile);
private:
	BOOL GetSnapshotInfoOfLib(PCWSTR pszLibFile, LPMODULEENTRY32W moduleStrct);
private:
	HANDLE m_hProcess;		//当前进程ID
};

