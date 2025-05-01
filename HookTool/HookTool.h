#pragma once
namespace Hook
{
	 class HookTool
	{
	public:
		//Hook²Ù×÷
		bool SHook(HookInfo*pHookInfo);
		bool UHook(HookInfo* pHookInfo);
		bool PHook(HookInfo* pHookInfo);
		bool CHook(HookInfo* pHookInfo);
	};
}