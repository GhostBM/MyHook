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

#pragma comment(lib, "HookTool.lib")
#pragma comment(linker, "/DELAYLOAD:HookTool.dll")

#include <list>
#include "../DBHelpTool/DBStruct.h"
#include "../HookTool/HookInfo.h"
#include "../HookTool/HookTool.h"
#include "../HookTool/HookManager.h"