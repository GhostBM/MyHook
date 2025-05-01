#pragma once

class HOOKAPI HookPacketInfo :public Hook::HookManager
{
public:
	// 获取单实例对象
	static HookPacketInfo& GetInstance();

	const HookControl* FindHook(FARPROC iAddress);

	Hook::HookTool* GetHookdll();
protected:
	BYTE* CHookContent(const Param& paramInfo)override;

	//设置通信的信号量
	void SetCommunicationMutex(Param& paramInfo, HookControl* pControl)override;

	//返回hook段大小
	int GetHookSize(const Param& paramInfo) override;
private:
	// 禁止外部构造
	HookPacketInfo() {};

	// 禁止外部析构
	~HookPacketInfo() {};

	// 禁止外部复制构造
	HookPacketInfo(const HookPacketInfo& signal) {};

	// 禁止外部赋值操作
	const HookPacketInfo& operator=(const HookPacketInfo& signal) { return *this; };
};

HOOKFun void  SHook(LPVOID pContentAddress);


HOOKFun void UnHook(LPVOID pContentAddress);