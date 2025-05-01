#include "stdafx.h"
#include "HookInfo.h"
using namespace Hook;

HookInfo::HookInfo(int iSize):m_OverlaySize(iSize),
m_iReplacedAddress(NULL),
m_pOldContent(NULL),
m_eHook(UNHOOK),
m_pNewContent(NULL)
{
}

HookInfo::~HookInfo()
{
	if (m_pOldContent != NULL)
	{
		delete []m_pOldContent;
		m_pOldContent = NULL;
	}
	if (m_pNewContent != NULL)
	{
		delete[]m_pNewContent;
		m_pNewContent = NULL;
	}
}

const BYTE* HookInfo::GetNewContent() const
{
	return m_pNewContent;
}

const BYTE* HookInfo::GetOldContent() const
{
	return m_pOldContent;
}

FARPROC HookInfo::GetHookAddress()
{
	return m_iReplacedAddress;
}

void HookInfo::SetHookAddress(FARPROC address)
{
	m_iReplacedAddress = address;
}

HookInfo::HookState HookInfo::GetHookState()
{
	return m_eHook;
}

int Hook::HookInfo::GetHookSize()
{
	return m_OverlaySize;
}

void HookInfo::Reset()
{
	SetHookAddress(0);
	SetHookState(UNHOOK);
	SetOldContent(NULL);
	SetNewContent(NULL);
}

void HookInfo::SetHookState(HookState hookState)
{
	m_eHook = hookState;
}

//void Hook::HookInfo::SetFunctionName(PTSTR fName)
//{
//	//获取当前名称大小
//	int oldSize=wcslen(m_pFunctionName);
//	int curSize=wcslen(fName);
//	//如果新的比原来的小则直接覆盖
//	if (curSize <= oldSize)
//	{
//		wcscpy_s(m_pFunctionName, curSize, fName);
//		m_pFunctionName[curSize - 1] = '\0';
//		return;
//	}
//	//如果新的比原来的大则新建内存
//	PTSTR newName = new WCHAR[curSize + curSize /2];
//	wcscpy_s(newName, curSize, fName);
//	//判断是否创建成功
//	if (newName == NULL)
//		return;
//	newName[curSize - 1] = '\0';
//	//释放原来的内存
//	delete m_pFunctionName;
//	m_pFunctionName = newName;
//}

void HookInfo::SetOldContent(const BYTE* pOldContent)
{
	if (NULL==pOldContent)
	{
		if (m_pOldContent)
		{
			delete[]m_pOldContent;
			m_pOldContent = NULL;
			return;
		}
	}
	if (m_pOldContent == NULL)
	{
		m_pOldContent = new BYTE[m_OverlaySize];
	}
	ReadProcessMemory(GetCurrentProcess(), pOldContent, m_pOldContent, GetHookSize(), nullptr);
}

void HookInfo::SetNewContent(const BYTE* pNewContent)
{
	if (NULL == pNewContent)
	{
		if (m_pNewContent)
		{
			delete[]m_pNewContent;
			m_pNewContent = NULL;
			return;
		}
	}
	if (m_pNewContent == NULL)
	{
		m_pNewContent = new BYTE[m_OverlaySize];
	}
	ReadProcessMemory(GetCurrentProcess(), pNewContent, m_pNewContent, GetHookSize(), nullptr);
}

