#include "CenterControl.h"
#include <windows.h>
#include <TlHelp32.h>
#include <comdef.h>
DWORD GetProcessIdFromName(const char* name)
{
	HANDLE hsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hsnapshot == INVALID_HANDLE_VALUE)
	{
		return -1;
	}

	PROCESSENTRY32 processer;
	processer.dwSize = sizeof(PROCESSENTRY32);

	int flag = Process32First(hsnapshot, &processer);
	while (flag != 0)
	{
		_bstr_t processName(processer.szExeFile);  //WCHAR×Ö·û´®×ª»»³ÉCHAR×Ö·û´®
		if (strcmp(processName, name) == 0)
		{
			return processer.th32ProcessID;        //·µ»Ø½ø³ÌID
		}
		flag = Process32Next(hsnapshot, &processer);
	}

	CloseHandle(hsnapshot);
	return -2;
}

int main()
{
	Injector injector;
	DWORD ld = GetProcessIdFromName(".exe");
	injector.SetTarProcessId(ld);
	injector.InjectW(L"D:\\Code\\MyHook\\Injector\\x64\\Debug\\HookTool.dll");

	CenterControl control;
	UserParamInfo userParam;
	control.HookFunction(ld, CenterControl::FunName::Recv, userParam);
}