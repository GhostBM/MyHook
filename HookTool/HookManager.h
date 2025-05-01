#pragma once
namespace Hook
{
	 class HookManager
	{
	public:
		HookManager();
		virtual ~HookManager();
	public:
		//管理
		struct HookControl
		{
			~HookControl()
			{
				Restroy();
				if (pHookInfo)
				{
					delete pHookInfo;
					pHookInfo = NULL;
				}
			}
			void Restroy()
			{
				if (cMulex)
				{
					CloseHandle(sMulex);
					sMulex = NULL;
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
			UserParamInfo paramInfo = {};
			HookInfo* pHookInfo = NULL;
		};
	public:
		//Hook
		void HookFunction(LPVOID pContentAddress);
		//卸载
		void UnHook(LPVOID pContentAddress);
		//暂停
		void PHook(LPVOID pContentAddress);
		//继续
		void CHook(LPVOID pContentAddress);
	protected:
		//构造Hook内容
		virtual BYTE* CHookContent(const Param& paramInfo)=0;

		//设置通信的互斥量
		virtual void SetCommunicationMutex(Param& paramInfo, HookControl* pControl)=0;

		//返回hook段大小
		virtual int GetHookSize(const Param& paramInfo)=0;
	protected:
	
		HookControl* HookFunction(const Param& paramInfo,int hookSize);
		//取消Hook
		bool UnHook(const Param& paramInfo);

		//暂停Hook
		bool StartHook(const Param& paramInfo,const bool&bPause);

		//根据地址查找hook信息
		HookControl* FindHook(FARPROC iAddress, const std::list<HookControl*>& pLHookControl);

		//查找第一个已经被卸载的hook
		HookManager::HookControl* GetFirstUHook(const std::list<HookControl*>& pLHookControl);
		protected:
		std::list<HookControl*> m_pLHookInfo;
		HookTool* m_pHookTool;
	};
}