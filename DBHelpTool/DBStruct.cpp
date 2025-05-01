#include "DBStruct.h"
#pragma comment(lib,"ws2_32.lib") //字节转换函数

void WriteSendInfo(void* newInfo, SOCKET Socket, char* sendAddr, int iSize,
	const struct sockaddr FAR* toStruct, int tolen, const UserParamInfo& userParameter)
{
	//1.记录地址
	__int64 address = (__int64)newInfo;
	//2.写入套接字对象
	memcpy((void*)address, &Socket, sizeof(Socket));
	address += sizeof(Socket);
	//3.写入包大小
	memcpy((void*)address, &iSize, sizeof(iSize));
	address += sizeof(iSize);

	//4.获取远程ip与端口
	sockaddr_in  clientAddr;
	memcpy(&clientAddr, sendAddr, sizeof(clientAddr));
	int   bufSize = sizeof(clientAddr);
	::getpeername(Socket, (SOCKADDR*)&clientAddr, &bufSize);
	u_short sendPort = htons(clientAddr.sin_port);
	PCSTR pstrIP = inet_ntoa(clientAddr.sin_addr);
	//5.写入发送端地址
	memcpy((void*)address, pstrIP, strlen(pstrIP) + 1);
	address += strlen(pstrIP) + 1;
	//6.写入发送端端口
	memcpy((void*)address, &sendPort, sizeof(sendPort));
	address += sizeof(sendPort);

	//7.获取接受端ip与端口
	sockaddr_in  localAddr;
	memcpy(&localAddr, sendAddr, sizeof(localAddr));
	int   addrLen = sizeof(localAddr);
	::getsockname(Socket, (sockaddr*)&localAddr, &addrLen);
	u_short targetPort = htons(localAddr.sin_port);
	PCSTR targetIP = inet_ntoa(localAddr.sin_addr);

	//8.写入发送端地址
	memcpy((void*)address, targetIP, strlen(targetIP) + 1);
	address += strlen(targetIP) + 1;
	//9.写入发送端端口
	memcpy((void*)address, &targetPort, sizeof(targetPort));
	address += sizeof(targetPort);
	//10.远端大小
	sockaddr_in sockaddr={0};
	if (NULL != toStruct)
	{
		sockaddr = *((sockaddr_in*)toStruct);
	}
	memcpy((void*)address, &sockaddr, tolen);
	address += sizeof(sockaddr);
	//10.远端大小
	memcpy((void*)address, &tolen, tolen);
	address += sizeof(tolen);
	//11. 是否发送 默认开启
	bool bState = true;
	memcpy((void*)address, &bState, sizeof(bState));
	address += sizeof(bState);
	//12. 用户参数写入
	memcpy((void*)address, &userParameter, sizeof(userParameter));
	address += sizeof(userParameter);

	//13. 封包内容
	memcpy((void*)address, sendAddr, iSize);
}

void WriteSendInfo(SocketInfo* newInfo, const SocketInfo& oldInfo)
{
	//1.记录地址
	__int64 address = (__int64) newInfo;
	memcpy((void*)address, &oldInfo.socket, sizeof(oldInfo.socket));
	address += sizeof(oldInfo.socket);
	//3.写入包大小
	memcpy((void*)address, &oldInfo.strSize, sizeof(oldInfo.strSize));
	address += sizeof(oldInfo.strSize);
	
	//5.写入发送端地址
	memcpy((void*)address, oldInfo.strIP, strlen(oldInfo.strIP) + 1);
	address += strlen(oldInfo.strIP) + 1;
	//6.写入发送端端口
	memcpy((void*)address, &oldInfo.strSinPort, sizeof(oldInfo.strSinPort));
	address += sizeof(oldInfo.strSinPort);
	
	//8.写入发送端地址
	memcpy((void*)address, oldInfo.targetIP, strlen(oldInfo.targetIP) + 1);
	address += strlen(oldInfo.targetIP) + 1;
	//9.写入发送端端口
	memcpy((void*)address, &oldInfo.targetPort, sizeof(oldInfo.targetPort));
	address += sizeof(oldInfo.targetPort);
	
	//10.写入远端地址
	memcpy((void*)address, &oldInfo.farSocket, oldInfo.farSize);
	address += oldInfo.farSize;
	//9.写入远端端口
	memcpy((void*)address, &oldInfo.farSize, sizeof(oldInfo.farSize));
	address += sizeof(oldInfo.farSize);
	memcpy((void*)address, &oldInfo.bSend, sizeof(oldInfo.bSend));
	address += sizeof(oldInfo.bSend);
	
	//12. 用户参数写入
	memcpy((void*)address, &oldInfo.userParameter, sizeof(oldInfo.userParameter));
	address += sizeof(oldInfo.userParameter);
	
	memcpy((void*)address, &oldInfo.socketData, oldInfo.strSize+1);
}


void ReadSendInfo(void* oldInfo,SocketInfo* readInfo)
{
	__int64 address = (__int64)oldInfo;
	//1.写入套接字
	readInfo->socket = *((SOCKET*)address);
	address += sizeof(readInfo->socket);
	//2.写入包大小
	readInfo->strSize = *(int*)address;
	address += sizeof(readInfo->strSize);
	//3.写入发送端地址
	readInfo->strIP = (char*)address;
	address += (strlen(readInfo->strIP) + 1);
	//4.写入发送端端口
	readInfo->strSinPort = *(u_short*)address;
	address += sizeof(readInfo->strSinPort);

	//5.写入接收端地址
	readInfo->targetIP = (char*)address;
	address += (strlen(readInfo->targetIP) + 1);
	//6.写入接收端端口
	readInfo->targetPort = *(u_short*)address;
	address += sizeof(readInfo->targetPort);

	//7.写入远端地址
	readInfo->farSocket = *(sockaddr_in*)address;
	address += sizeof(sockaddr_in);
	//9.写入远端数据大小
	readInfo->farSize = *(int*)address;
	address += sizeof(readInfo->farSize);

	//10.是否发送
	readInfo->bSend = *(bool*)address;
	address += sizeof(readInfo->bSend);

	//11. 用户参数写入
	readInfo->userParameter = *(UserParamInfo*)address;
	address += sizeof(readInfo->userParameter);

	//12.内容写入
	readInfo->socketData = (char*)address;
}

void WideCharToChar(LPCWCH wStr, PSTR& str)
{
	int iSize = WideCharToMultiByte(CP_ACP, 0, wStr, -1, NULL, 0, NULL, NULL);
	str = new char[iSize * sizeof(char)];
	WideCharToMultiByte(CP_ACP, 0, wStr, -1, str, iSize, NULL, NULL);
}
