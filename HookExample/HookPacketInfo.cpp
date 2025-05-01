#include "stdafx.h"
#include "HookPacketInfo.h"

extern "C" uint64_t GetR11Value();

#define Milliseconds 30000
int _fastcall MyFakeSend(SOCKET Socket, char* sendAddr, int Size, int flag) //win32默认AIP函数  是WINDAPI //  x64默认是 fastcall约定
{
	//1.获取传输数据
	HookPacketInfo &manage= HookPacketInfo::GetInstance();
	uint64_t address = GetR11Value();  // 获取
	const Hook::HookManager::HookControl*  pControl=manage.FindHook((FARPROC)address);
	if (NULL == pControl)
	{
		return 0;
	}
	Hook::HookTool* pHookTool=manage.GetHookdll();
	//2.卸载Hook,避免冲突
	if (!pHookTool->PHook(pControl->pHookInfo)) {
		send(Socket, sendAddr, Size, flag);
		pHookTool->CHook(pControl->pHookInfo);
		return Size;
	}
	//3.构造通信信息
	if (pControl->pShareMemory == NULL)
	{
		send(Socket, sendAddr, Size, flag);
		return Size;
	}
	if (Size == 0)
	{
		int iSize= send(Socket, sendAddr, Size, flag);
		pHookTool->CHook(pControl->pHookInfo);
		return iSize;
	}
	WriteSendInfo(pControl->pShareMemory, Socket, sendAddr, Size, NULL, 0, pControl->paramInfo);
	//4.通知中控
	ReleaseSemaphore(pControl->sMulex, 1, NULL);
	//5.等到信号,超时则卸载
	DWORD dw = WaitForSingleObject(pControl->cMulex, Milliseconds);
	if (dw == WAIT_TIMEOUT)
	{
		pHookTool->UHook(pControl->pHookInfo);
		send(Socket, sendAddr, Size, flag);
		return Size;
	}
	SocketInfo newInfo;
	ReadSendInfo(pControl->pShareMemory, &newInfo);

	if (!newInfo.bSend)
	{
		newInfo.bSend = true;
		pHookTool->CHook(pControl->pHookInfo);
		return Size;
	}
	int iSize=send(newInfo.socket, newInfo.socketData, newInfo.strSize, flag);
	pHookTool->CHook(pControl->pHookInfo);
	return iSize;
}

int _fastcall MyFakeRecv(SOCKET Socket, char* sendAddr, int Size, int flag) //x64默认是 fastcall约定
{
	//1.获取传输数据
	HookPacketInfo& manage = HookPacketInfo::GetInstance();
	uint64_t address = GetR11Value();  // 获取
	const Hook::HookManager::HookControl* pControl = manage.FindHook((FARPROC)address);
	if (NULL == pControl)
	{
		return 0;
	}
	Hook::HookTool* pHookTool = manage.GetHookdll();
	//2.卸载Hook,避免冲突
	if (!pHookTool->PHook(pControl->pHookInfo)) {
		int iRecvSize=recv(Socket, sendAddr, Size, flag);
		pHookTool->CHook(pControl->pHookInfo);
		return iRecvSize;
	}
	//收包
	int RecvSize = recv(Socket, sendAddr, Size, flag);
	if (SOCKET_ERROR == RecvSize || RecvSize == 0)
	{
		pHookTool->CHook(pControl->pHookInfo);
		return RecvSize;
	}

	WriteSendInfo(pControl->pShareMemory, Socket, sendAddr, RecvSize, NULL, 0, pControl->paramInfo);
	//4.通知中控
	ReleaseSemaphore(pControl->sMulex, 1, NULL);
	//5.等到信号,超时则卸载
	DWORD dw = WaitForSingleObject(pControl->cMulex, Milliseconds);
	if (dw == WAIT_TIMEOUT)
	{
		pHookTool->UHook(pControl->pHookInfo);
		int iRecvSize = recv(Socket, sendAddr, Size, flag);
		return Size;
	}
	SocketInfo newInfo;
	ReadSendInfo(pControl->pShareMemory, &newInfo);

	if (!newInfo.bSend)
	{
		newInfo.bSend = true;
		pHookTool->CHook(pControl->pHookInfo);
		return Size;
	}
	ReadProcessMemory(GetCurrentProcess(), newInfo.socketData, sendAddr, newInfo.strSize, nullptr);
	pHookTool->CHook(pControl->pHookInfo);
	return newInfo.strSize;
}

int _fastcall MyFakeSendTo(SOCKET Socket, char* sendAddr, int Size, int flag, const struct sockaddr FAR* toStruct, int tolen) //win32默认AIP函数  是WINDAPI //  x64默认是 fastcall约定
{
	//1.获取传输数据
	HookPacketInfo& manage = HookPacketInfo::GetInstance();
	uint64_t address = GetR11Value();  // 获取
	const Hook::HookManager::HookControl* pControl = manage.FindHook((FARPROC)address);
	if (NULL == pControl)
	{
		return 0;
	}
	Hook::HookTool* pHookTool = manage.GetHookdll();
	//2.卸载Hook,避免冲突
	if (!pHookTool->PHook(pControl->pHookInfo)) {
		sendto(Socket, sendAddr, Size, flag, toStruct, tolen);
		pHookTool->CHook(pControl->pHookInfo);
		return Size;
	}
	//3.构造通信信息
	if (pControl->pShareMemory == NULL)
	{
		sendto(Socket, sendAddr, Size, flag, toStruct, tolen);
		return Size;
	}
	if (Size == 0)
	{
		int iSize = sendto(Socket, sendAddr, Size, flag, toStruct, tolen);
		pHookTool->CHook(pControl->pHookInfo);
		return iSize;
	}
	WriteSendInfo(pControl->pShareMemory, Socket, sendAddr, Size, toStruct, tolen, pControl->paramInfo);
	//4.通知中控
	ReleaseSemaphore(pControl->sMulex, 1, NULL);
	//5.等到信号,超时则卸载
	DWORD dw = WaitForSingleObject(pControl->cMulex, Milliseconds);
	if (dw == WAIT_TIMEOUT)
	{
		pHookTool->UHook(pControl->pHookInfo);
		int iSize = sendto(Socket, sendAddr, Size, flag, toStruct, tolen);
		return iSize;
	}
	SocketInfo newInfo;
	ReadSendInfo(pControl->pShareMemory, &newInfo);

	if (!newInfo.bSend)
	{
		newInfo.bSend = true;
		pHookTool->CHook(pControl->pHookInfo);
		return Size;
	}
	ReadProcessMemory(GetCurrentProcess(), newInfo.socketData, sendAddr, newInfo.strSize, nullptr);
	const sockaddr* data = (sockaddr*)&newInfo.farSocket;
	int iSize = sendto(newInfo.socket, newInfo.socketData, newInfo.strSize, flag, data, newInfo.farSize);
	pHookTool->CHook(pControl->pHookInfo);
	return iSize;
}

int _fastcall MyFakeRecvFrom(SOCKET Socket, char* sendAddr, int Size, int flag,
	sockaddr* toStruct, int* tolen) //win32默认AIP函数  是WINDAPI //  x64默认是 fastcall约定
{

	//1.获取传输数据
	HookPacketInfo& manage = HookPacketInfo::GetInstance();
	uint64_t address = GetR11Value();  // 获取
	const Hook::HookManager::HookControl* pControl = manage.FindHook((FARPROC)address);
	if (NULL == pControl)
	{
		return 0;
	}
	Hook::HookTool* pHookTool = manage.GetHookdll();
	//2.卸载Hook,避免冲突
	if (!pHookTool->PHook(pControl->pHookInfo)) {
		recvfrom(Socket, sendAddr, Size, flag, toStruct, tolen);
		pHookTool->CHook(pControl->pHookInfo);
		return Size;
	}
	//3.构造通信信息
	if (pControl->pShareMemory == NULL)
	{
		recvfrom(Socket, sendAddr, Size, flag, toStruct, tolen);
		return Size;
	}
	if (Size == 0)
	{
		int iSize = recvfrom(Socket, sendAddr, Size, flag, toStruct, tolen);
		pHookTool->CHook(pControl->pHookInfo);
		return iSize;
	}
	WriteSendInfo(pControl->pShareMemory, Socket, sendAddr, Size, toStruct, *tolen, pControl->paramInfo);
	//4.通知中控
	ReleaseSemaphore(pControl->sMulex, 1, NULL);
	//5.等到信号,超时则卸载
	DWORD dw = WaitForSingleObject(pControl->cMulex, Milliseconds);
	if (dw == WAIT_TIMEOUT)
	{
		pHookTool->UHook(pControl->pHookInfo);
		int iSize = recvfrom(Socket, sendAddr, Size, flag, toStruct, tolen);
		return iSize;
	}
	SocketInfo newInfo;
	ReadSendInfo(pControl->pShareMemory, &newInfo);

	if (!newInfo.bSend)
	{
		newInfo.bSend = true;
		pHookTool->CHook(pControl->pHookInfo);
		return Size;
	}
	ReadProcessMemory(GetCurrentProcess(), &newInfo.farSocket, toStruct, newInfo.farSize, nullptr);
	ReadProcessMemory(GetCurrentProcess(), &newInfo.farSize, tolen, sizeof(newInfo.farSize), nullptr);
	ReadProcessMemory(GetCurrentProcess(), newInfo.socketData, sendAddr, newInfo.strSize, nullptr);
	pHookTool->CHook(pControl->pHookInfo);
	return newInfo.farSize;
}


HookPacketInfo& HookPacketInfo::GetInstance()
{
	static HookPacketInfo packetInfo;
	return packetInfo;
}

const Hook::HookManager::HookControl* HookPacketInfo::FindHook(FARPROC iAddress)
{
	return Hook::HookManager::FindHook(iAddress,m_pLHookInfo);
}

Hook::HookTool* HookPacketInfo::GetHookdll()
{
	return m_pHookTool;
}


BYTE* HookPacketInfo::CHookContent(const Param& paramInfo)
{

		//1.获取模块句柄
	HMODULE hModule = GetModuleHandleW(paramInfo.moduleName);
	if (NULL == hModule)
	{
		return NULL;
	}
	//2.获取函数地址
	PSTR funName = NULL;
	WideCharToChar(paramInfo.funName, funName);
	FARPROC  funAddress = ::GetProcAddress(hModule, funName);
	delete[]funName;

	BYTE* pCode = new BYTE[GetHookSize(paramInfo)];
	pCode[0] = 0X49;
	pCode[1] = 0xBB;
	memcpy(pCode + 2, &funAddress, 8);
	pCode[10] = 0x49;
	pCode[11] = 0XBF;
	INT64 FunAddr = (INT64)MyFakeSend;
	if (wcscmp(paramInfo.funName, L"recv")==0)
	{
		FunAddr = (INT64)MyFakeRecv;
	}
	else if (wcscmp(paramInfo.funName, L"recvfrom") == 0)
	{
		FunAddr = (INT64)MyFakeRecvFrom;
	}
	else if (wcscmp(paramInfo.funName, L"sendto") == 0)
	{
		FunAddr = (INT64)MyFakeSendTo;
	}
	memcpy(pCode + 12, &FunAddr, 8);
	//jmp r11
	pCode[20] = 0X41;
	pCode[21] = 0XFF;
	pCode[22] = 0XE7;
	return pCode;
}

void HookPacketInfo::SetCommunicationMutex(Param& paramInfo, HookControl* pControl)
{
	wchar_t buffer[1024];
	wchar_t server[8] = { L"_server" };
	wchar_t client[8] = { L"_client" };
	wchar_t cfilemap[9] = { L"_filemap" };
	//获取服务器信号量
	memset(buffer, 0,sizeof(buffer));
	swprintf_s(buffer, L"%ld", GetCurrentProcessId());
	wcscat_s(buffer, paramInfo.funName);
	wcscat_s(buffer, server);
	pControl->sMulex = OpenSemaphoreW(SEMAPHORE_ALL_ACCESS, FALSE, buffer);
	//获取客户端信号量
	memset(buffer, 0, sizeof(buffer));
	swprintf_s(buffer, L"%ld", GetCurrentProcessId());
	wcscat_s(buffer, paramInfo.funName);
	wcscat_s(buffer, client);
	pControl->cMulex = OpenSemaphoreW(SEMAPHORE_ALL_ACCESS, FALSE, buffer);

	auto test = GetLastError();
	printf("%d", test);
	//获取内存映射
	memset(buffer, 0, sizeof(buffer));

	swprintf_s(buffer, L"%ld", GetCurrentProcessId());
	wcscat_s(buffer, paramInfo.funName);
	wcscat_s(buffer, cfilemap);
	pControl->hExchange = OpenFileMapping(FILE_MAP_ALL_ACCESS, NULL, buffer);
	if (pControl->hExchange)
	{
		pControl->pShareMemory = MapViewOfFile(pControl->hExchange, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	}
}

int HookPacketInfo::GetHookSize(const Param& paramInfo)
{
	return 23;
}

void SHook(LPVOID pContentAddress)
{
	HookPacketInfo::GetInstance().HookFunction(pContentAddress);
}

void UnHook(LPVOID pContentAddress)
{
	HookPacketInfo::GetInstance().UnHook(pContentAddress);
}