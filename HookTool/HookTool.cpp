#include "stdafx.h"
#include "HookTool.h"
using namespace Hook;
//Hook函数
bool HookTool::SHook(HookInfo* pHookInfo)
{
	//1.检测有效性
	if (pHookInfo->GetHookAddress() == NULL||pHookInfo->GetNewContent()==NULL)
	{
		return false;
	}
	//2.替换内容
	bool ret = WriteProcessMemory(GetCurrentProcess(), (LPVOID)pHookInfo->GetHookAddress(), pHookInfo->GetNewContent(), pHookInfo->GetHookSize(), NULL);
	if (ret)
	{
		pHookInfo->SetHookState(HookInfo::HookState::HOOK);
	}
	return ret;
}
//取消Hook
bool HookTool::UHook(Hook::HookInfo* pHookInfo)
{
	//1.检测有效性
	if (pHookInfo->GetHookAddress() == NULL || pHookInfo->GetOldContent() == NULL)
	{
		return false;
	}
	HookInfo::HookState hookState = pHookInfo->GetHookState();
	if (hookState == HookInfo::HookState::UNHOOK)
	{
		return true;
	}
	if (hookState == HookInfo::HookState::Pause)
	{
		pHookInfo->SetHookState(HookInfo::HookState::UNHOOK);
		return true;
	}
	//2.替换内容
	bool ret = WriteProcessMemory(GetCurrentProcess(), (LPVOID)pHookInfo->GetHookAddress(), pHookInfo->GetOldContent(), pHookInfo->GetHookSize(), NULL);
	if (ret)
	{
		pHookInfo->SetHookState(HookInfo::HookState::UNHOOK);
	}
	return ret;
}

//暂停
bool HookTool::PHook(HookInfo* pHookInfo)
{
	//1.判断是否为Hook状态
	if (pHookInfo->GetHookState() != HookInfo::HookState::HOOK)
	{
		return true;
	}
	//2.取消hook
	if (!UHook(pHookInfo))
	{
		return false;
	}
	//3.写入状态
	pHookInfo->SetHookState(HookInfo::HookState::Pause);
	return true;
}

//继续
bool HookTool::CHook(Hook::HookInfo* pHookInfo)
{
	//1.判断是否为Hook状态
	if (pHookInfo->GetHookState() == HookInfo::HookState::UNHOOK)
	{
		return false;
	}
	if (pHookInfo->GetHookState() == HookInfo::HookState::HOOK)
	{
		return true;
	}
	//2.hook
	return SHook(pHookInfo);
}