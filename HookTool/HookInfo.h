#pragma once
namespace Hook
{

	class HookTool;
	class HookManager;
	class HookInfo
	{
		public:
			enum HookState
			{
				UNHOOK = 0,
				HOOK,
				Pause
			};
		public:
			HookInfo(int iSize);

			~HookInfo();
		public:
			//获取用来替换的函数地址
			const BYTE* GetNewContent()const;

			//获取被替换的函数内容
			const BYTE* GetOldContent()const;

			//获取被替换的函数开始的地址
			FARPROC GetHookAddress();
		
			//获取hook状态
			HookState GetHookState();

			//获取替换的大小
			int GetHookSize();

			void Reset();
		protected:
			//被替换的内容
			void SetOldContent(const BYTE* pOldContent);
			//替换内容
			void SetNewContent(const BYTE* pNewContent);

			//设置被替换的函数地址
			void SetHookAddress(FARPROC address);

			//设置hook状态
			void SetHookState(HookState hookState);
		private:
			const int m_OverlaySize;
			//替换函数地址
			FARPROC m_iReplacedAddress;
			//被替换的内容
			BYTE* m_pOldContent;
			//被替换的地址
			BYTE* m_pNewContent;
			//hook状态
			HookState m_eHook;

			friend HookTool;
			friend HookManager;
	};
}
