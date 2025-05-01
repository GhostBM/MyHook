#pragma once
#include <windows.h>

struct UserParamInfo
{
	long param1 = 0;
	long param2 = 0;
	long param3 = 0;
	long param4 = 0;
};
struct Param
{
	UserParamInfo paramInfo;	//用户参数
	PTSTR  moduleName;	//模块名称
	PTSTR  funName;		//方法名称

};

struct  SocketInfo
{
	SOCKET socket; //套接字对象
	int strSize = 0;	//包大小
	char* strIP; //发送端地址
	u_short strSinPort = 0;//端口
	char* targetIP; //收包地址
	u_short targetPort = 0;//端口
	sockaddr_in farSocket;//远端端口使用
	int farSize = 0;
	bool bSend = true;
	UserParamInfo userParameter;
	char* socketData;//封包内容
};

 void WriteSendInfo(void* newInfo, SOCKET Socket, char* sendAddr, int iSize,
	const struct sockaddr FAR* toStruct, int tolen, const UserParamInfo& userParameter);

 void WriteSendInfo(SocketInfo* newInfo, const SocketInfo& oldInfo);

 void WideCharToChar(LPCWCH wStr, PSTR& str);

 void ReadSendInfo(void* oldInfo, SocketInfo* readInfo);
