#pragma once
#ifdef _HOOKLIB
#define HOOKAPI __declspec(dllexport)
#else
#define HOOKAPI __declspec(dllimport)
#endif
#ifdef _HOOKLIB
#define HOOKFun  extern "C" __declspec(dllexport)
#else
#define HOOKFun extern "C" __declspec(dllimport)
#endif

#include <list>
#include <windows.h>

#include "../DBHelpTool/DBStruct.h"

#include "../HookTool/HookInfo.h"
#include "../HookTool/HookTool.h"
#include "../HookTool/HookManager.h"
