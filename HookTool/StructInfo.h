#pragma once
struct UserParamInfo
{
	long param1=0;
	long param2=0;
	long param3=0;
	long param4=0;
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
	PCSTR* strIP; //发送端地址
	u_short strSinPort = 0;//端口
	PCSTR* targetIP; //收包地址
	u_short targetPort = 0;//端口
	PCSTR* farIP; //远端地址 //sendto用
	u_short farPort = 0;//远端端口
	int farSize = 0;
	bool bSend = true;
	UserParamInfo userParameter;
	char* socketData;//封包内容
};

void WriteSendInfo(SocketInfo* newInfo, SOCKET Socket, char* sendAddr, int iSize,const UserParamInfo& userParameter)
{
	//1.记录地址
	long address = (long)&newInfo;
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
	memcpy((void*)address, pstrIP, sizeof(pstrIP));
	address += sizeof(pstrIP);
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
	memcpy((void*)address, targetIP, sizeof(targetIP));
	address += sizeof(targetIP);
	//9.写入发送端端口
	memcpy((void*)address, &targetPort, sizeof(targetPort));
	address += sizeof(targetPort);

	//10.写入远端地址
	memcpy((void*)address, L"", sizeof(1));
	address += sizeof(L"");
	//9.写入远端端口
	memcpy((void*)address, 0, sizeof(int));
	address += sizeof(int);

	//10.远端大小
	memcpy((void*)address, 0, sizeof(int));
	address += sizeof(int);

	//11. 是否发送 默认开启
	bool bState = true;
	memcpy((void*)address, &bState, sizeof(bState));
	address += sizeof(bState);
	//12. 用户参数写入
	memcpy((void*)address, &userParameter, sizeof(userParameter));
	address += sizeof(userParameter);

	//13. 封包内容
	memcpy((void*)address, &sendAddr, sizeof(iSize));
}

void WriteSendInfo(SocketInfo* newInfo, const SocketInfo& oldInfo)
{
	//1.记录地址
	long address = (long)&newInfo;
	memcpy((void*)address, &oldInfo.socket, sizeof(oldInfo.socket));
	address += sizeof(oldInfo.socket);
	//3.写入包大小
	memcpy((void*)address, &oldInfo.strSize, sizeof(oldInfo.strSize));
	address += sizeof(oldInfo.strSize);

	//5.写入发送端地址
	memcpy((void*)address, oldInfo.strIP, sizeof(oldInfo.strIP));
	address += sizeof(oldInfo.strIP);
	//6.写入发送端端口
	memcpy((void*)address, &oldInfo.strSinPort, sizeof(oldInfo.strSinPort));
	address += sizeof(oldInfo.strSinPort);

	//8.写入发送端地址
	memcpy((void*)address, oldInfo.targetIP, sizeof(oldInfo.targetIP));
	address += sizeof(oldInfo.targetIP);
	//9.写入发送端端口
	memcpy((void*)address, &oldInfo.targetPort, sizeof(oldInfo.targetPort));
	address += sizeof(oldInfo.targetPort);

	//10.写入远端地址
	memcpy((void*)address, oldInfo.farIP, sizeof(oldInfo.farIP));
	address += sizeof(oldInfo.farIP);
	//9.写入远端端口
	memcpy((void*)address, &oldInfo.farPort, sizeof(oldInfo.farPort));
	address += sizeof(oldInfo.farPort);

	memcpy((void*)address, &oldInfo.farSize, sizeof(oldInfo.farSize));
	address += sizeof(oldInfo.farSize);
	memcpy((void*)address, &oldInfo.bSend, sizeof(oldInfo.bSend));
	address += sizeof(oldInfo.bSend);

	//12. 用户参数写入
	memcpy((void*)address, &oldInfo.userParameter, sizeof(oldInfo.userParameter));
	address += sizeof(oldInfo.userParameter);

	memcpy((void*)address, &oldInfo.socketData, sizeof(oldInfo.socketData));
}