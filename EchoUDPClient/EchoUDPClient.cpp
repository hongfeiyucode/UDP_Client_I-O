// EchoUDPClient.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <iostream>
using namespace std;
#include "SocketFrame.h"
int udp_client_fun_echo(FILE *fp, SOCKET s, SOCKADDR *servaddr, int servlen);
#define ECHOPORT "7210"
int main(int argc, char* argv[])
{
	CSocketFrame frame;
	int iResult;
	SOCKET ClientSocket;
	sockaddr_in servaddr;
	char *ip = "127.0.0.1";

	cout << "EchoUDPClient启动，开始尝试与服务器建立连接。。。\n";

	//Windows Sockets Dll初始化
	frame.start_up();
	
	//创建客户端的数据报套接字，并与服务器建立连接
	ClientSocket = frame.udp_client( ip, ECHOPORT, true );
	if ( ClientSocket == -1 )
		return -1;

	printf("连接建立成功，是否与服务器同步时间？(Y/N) ");
	//开始回射请求的发送与接收
	//指明服务器的地址peer为用户输入的IP和端口号
	if (frame.set_address( ip, ECHOPORT, &servaddr, "udp" ) !=0 )
		return 0;

	iResult = udp_client_fun_echo(stdin, ClientSocket, (SOCKADDR *)&servaddr, sizeof(sockaddr_in) );
	if(iResult == -1)
	    printf("当前回射过程出错!\n");

	frame.quit( ClientSocket );
    return iResult; 
}

/********************************************************
函数名：udp_client_fun_echo
输入参数：FILE *fp:指向FILE类型的对象
          SOCKET s:客户端的数据报套接字
		  SOCKADDR servaddr：服务器地址
		  int servlen：地址长度
输出参数：0：成功，-1：失败
功能：回射客户端的具体功能函数
*********************************************************/
int udp_client_fun_echo(FILE *fp, SOCKET s, SOCKADDR *servaddr, int servlen)
{
	int iResult;
    char sendline[MAXLINE],recvline[MAXLINE];
	memset(sendline,0,MAXLINE);
	memset(recvline,0,MAXLINE);

	//循环发送用户的输入数据，并接收服务器返回的应答，直到用户输入"Q"结束
	while(fgets(sendline,MAXLINE,fp)!=NULL)
	{
		if(*sendline == 'n'|| *sendline == 'N'){
			printf("断开连接 退出程序!\n");
			return 0;
		}
		iResult = sendto(s,sendline,strlen(sendline),0, (SOCKADDR *)servaddr, servlen);
		if(iResult == SOCKET_ERROR)
		{
			printf("sendto 函数调用错误，错误号： %ld\n", WSAGetLastError());
			return -1;
		}
		printf("\r\n客户端发送数据：%s\r\n", sendline);

	    memset(recvline,0,MAXLINE);
		iResult = recvfrom( s, recvline, MAXLINE, 0, NULL, NULL ) ;
		if (iResult > 0)
		{
			printf("与服务器同步时间成功！当前时间为：%s \r\n", recvline);
			printf("\n------------------------\n是否继续与服务器同步时间？(Y/N) ");
		}
		else{
 	        printf("recvfrom 函数调用错误，错误号: %d\n", WSAGetLastError());
			break;
		}
		memset(sendline,0,MAXLINE);
	}
	return iResult;
}

