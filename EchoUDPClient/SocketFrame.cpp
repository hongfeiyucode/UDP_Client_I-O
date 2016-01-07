#include "StdAfx.h"
#include "SocketFrame.h"
#include "ws2tcpip.h"
#include "mstcpip.h"
CSocketFrame::CSocketFrame(void)
{
}

CSocketFrame::~CSocketFrame(void)
{
}
/********************************************************
函数名：set_address
输入参数：char * hname：主机名 or 点分十进制表示的IP地址
          char * sname：端口号
		  struct sockaddr_in * sap：以sockaddr_in结构存储的地址（输出参数）
          char * protocol：字符串形式描述的协议类型，如"tcp"
输出参数：0表示成功，-1表示失败。
功能：根据给定的主机名或点分十进制表示的IP地址获得以sockaddr_in结构存储的地址
*********************************************************/
int CSocketFrame::set_address(char * hname, char * sname, struct sockaddr_in * sap, char * protocol)
{
	struct servent *sp;
	struct hostent *hp;
	char *endptr;
	unsigned short port;
	unsigned long ulAddr = INADDR_NONE;


    //对地址结构socketaddr_in初始化为0，并设置地址族为AF_INET
	memset( sap,0, sizeof( *sap ) );
	sap->sin_family = AF_INET;
	
	if ( hname != NULL )
	{
		//如果hname不为空，假定给出的hname为点分十进制表示的数字地址，转换地址为sockaddr_in类型
		ulAddr = inet_addr(hname);
		if ( ulAddr == INADDR_NONE || ulAddr == INADDR_ANY) {
			//printf("inet_addr 函数调用错误，错误号： %d\n", WSAGetLastError());
			//调用错误，表明给出的是主机名，调用gethostbyname获得主机地址
			hp = gethostbyname( hname );
			if ( hp == NULL ) {
				printf("未知的主机名，错误号： %d\n", WSAGetLastError());
				return -1;
			}
			sap->sin_addr = *( struct in_addr * )hp->h_addr;
        }      
		else
			sap->sin_addr.S_un.S_addr=ulAddr;		
	}
	else
		//如果调用者没有指定一个主机名或地址，则设置地址为通配地址INADDR_ANY
		sap->sin_addr.s_addr = htonl( INADDR_ANY );
	//尝试转换sname为一个整数
	port = (unsigned short )strtol( sname, &endptr, 0 );
	if ( *endptr == '\0' )
	{
		//如果成功则转换为网络字节顺序
		sap->sin_port = htons( port );
	}
	else
	{
		//如果失败，则假定是一个服务名称，通过调用getservbyname获得端口号
		sp = getservbyname( sname, protocol );
		if ( sp == NULL ) {
			printf("未知的服务，错误号： %d\n", WSAGetLastError());
			return -1;
		}
		sap->sin_port = sp->s_port;
	}
	return 0;
}

/********************************************************
函数名：start_up
输入参数：无
输出参数：0：成功，-1：失败
功能：初始化Windows Sockets DLL，协商版本号
*********************************************************/
int CSocketFrame::start_up(void)
{
	WORD wVersionRequested;
    WSADATA wsaData;
    int iResult;

    // 使用 MAKEWORD(lowbyte, highbyte) 宏，在Windef.h 中声明
    wVersionRequested = MAKEWORD(2, 2);

    iResult = WSAStartup(wVersionRequested, &wsaData);
    if (iResult != 0) {
        //告知用户无法找到合适可用的Winsock DLL
        printf("WSAStartup 函数调用错误，错误号： %d\n",  WSAGetLastError());
        return -1;
    }

    // 确认WinSock Dll支持版本2.2
    // 注意，如果DLL支持的版本比2.2更高，根据用户调用前的需求，仍然返回2.2版本号，存储于wsaData.wVersion

    if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
        // 告知用户无法找到可用的WinSock DLL.                              
        printf("无法找到可用的Winsock.dll版本\n");
        WSACleanup();
        return -1;
    }

	return 0;
}
/********************************************************
函数名：clean_up
输入参数：无
输出参数：0：成功，-1：失败
功能：终止Windows Sockets DLL的使用，释放资源 
*********************************************************/
int CSocketFrame::clean_up(void)
{
	int iResult;
	iResult = WSACleanup();
    if (iResult == SOCKET_ERROR) {
        // WSACleanup调用失败                  
        printf("WSACleanup 函数调用错误，错误号： %d\n",  WSAGetLastError());
        return -1;
    }

	return 0;
}
/********************************************************
函数名：quit
输入参数：SOCKET s:服务器的连接套接字
输出参数：0：成功，-1：失败
功能：关闭套接字，释放dll
*********************************************************/
int CSocketFrame::quit(SOCKET s)
{
    int iResult=0;
    iResult = closesocket(s);
    if (iResult == SOCKET_ERROR){
        printf("closesocket 函数调用错误，错误号：%d\n", WSAGetLastError());
        return -1;
    }
    iResult = clean_up();
    return iResult;
}
/********************************************************
函数名：tcp_server
输入参数：char * hname：服务器主机名 or 点分十进制表示的IP地址
          char * sname：服务端口号
输出参数：创建服务器端流式套接字并配置，-1：表示失败
功能：创建流式套接字，根据用户输入的地址和端口号，绑定套接字的服务地址
      将其转换为监听状态
*********************************************************/
SOCKET CSocketFrame::tcp_server( char *hname, char *sname )
{
	sockaddr_in local;
	SOCKET ListenSocket;
	const int on = 1;
	int iResult = 0;

    //为服务器的本地地址local设置用户输入的IP和端口号
	if (set_address( hname, sname, &local, "tcp" ) !=0 )
		return -1;
	
	//创建套接字
	ListenSocket = socket( AF_INET, SOCK_STREAM, 0 );
	if (ListenSocket == INVALID_SOCKET) {
        printf("socket 函数调用错误，错误号： %ld\n", WSAGetLastError());
        clean_up();
        return -1;
    }

	//设置服务器地址可重用选项
	iResult = setsockopt( ListenSocket, SOL_SOCKET, SO_REUSEADDR, ( char * )&on, sizeof( on ));
	if ( iResult == SOCKET_ERROR){
		printf("setsockopt函数调用错误，错误号： %d\n", WSAGetLastError());
        quit(ListenSocket);
        return -1;
    }

    //绑定服务器地址
	iResult = bind( ListenSocket, (struct sockaddr *) & local, sizeof (local));
    if (iResult == SOCKET_ERROR) {
        printf("bind 函数调用错误，错误号： %d\n", WSAGetLastError());
        quit(ListenSocket);
        return -1;
    }

	//设置服务器为监听状态，监听队列长度为NLISTEN
    iResult = listen(ListenSocket, SOMAXCONN);
	if (iResult == SOCKET_ERROR){
		printf("listen 函数调用错误，错误号： %d\n", WSAGetLastError());
		quit(ListenSocket);
		return -1;
    }

	return ListenSocket;
}
/********************************************************
函数名：tcp_client
输入参数：char * hname：服务器主机名 or 点分十进制表示的IP地址
          char * sname：服务端口号
输出参数：创建客户端流式套接字,-1：表示失败
功能：创建流式套接字，根据用户输入的地址和端口号，向服务地址
      请求建立连接
*********************************************************/
SOCKET CSocketFrame::tcp_client( char *hname, char *sname )
{
	struct sockaddr_in peer;
	SOCKET ClientSocket;
	int iResult = 0;

	//指明服务器的地址peer为用户输入的IP和端口号
	if (set_address( hname, sname, &peer, "tcp" ) !=0 )
		return -1;

	//创建套接字
	ClientSocket = socket( AF_INET, SOCK_STREAM, 0 );
	if (ClientSocket == INVALID_SOCKET) {
        printf("socket 函数调用错误，错误号： %ld\n", WSAGetLastError());
        clean_up();
        return -1;
    }

    //请求向服务器建立连接
	iResult =connect( ClientSocket, ( struct sockaddr * )&peer, sizeof( peer ) );
	if (iResult == SOCKET_ERROR){
		printf("connect 函数调用错误，错误号： %d\n", WSAGetLastError());
		quit(ClientSocket);
		return -1;
    }

	return ClientSocket;
}
/********************************************************
函数名：recvn
输入参数：SOCKET s:服务器的连接套接字
          char * recvbuf:存放接收到数据的缓冲区 
		  int fixedlen:固定的预接收数据长度
输出参数：>0：实际接收到的字节数，-1：失败
功能：在流式套接字中接收固定长度的数据
********************************************************/
int CSocketFrame::recvn(SOCKET s, char * recvbuf, unsigned int fixedlen)
{
	int iResult;//存储单次recv操作的返回值
	int cnt;//用于统计相对于固定长度，剩余多少字节尚未接收
	cnt = fixedlen;
	while ( cnt > 0 )
	{
        iResult = recv(s, recvbuf, cnt, 0);
        if ( iResult < 0 )
		{
			//数据接收出现错误，返回失败
			printf("接收发生错误: %d\n", WSAGetLastError());
		    return -1;
		}
	    if ( iResult == 0 )
		{
			//对方关闭连接，返回已接收到的小于fixedlen的字节数
	        printf("连接关闭\n");
			return fixedlen - cnt;
		}
	    //printf("接收到的字节数: %d\n", iResult);
		//接收缓存指针向后移动
		recvbuf +=iResult;
		//更新cnt值
		cnt -=iResult;         
	}
	return fixedlen;
}
/********************************************************
函数名：recvvl
输入参数：SOCKET s:服务器的连接套接字
          char * recvbuf:存放接收到数据的缓冲区 
		  int recvbuflen:接收缓冲区长度
输出参数：>0：实际接收到的字节数，-1：失败，0：连接关闭
功能：在流式套接字中接收可变长度的数据
********************************************************/
int CSocketFrame::recvvl(SOCKET s, char * recvbuf, unsigned int recvbuflen)
{
	int iResult;//存储单次recv操作的返回值
	unsigned int reclen; //用于存储报文头部存储的长度信息
	//获取接收报文长度信息
    iResult = recvn(s, ( char * )&reclen, sizeof( unsigned int ));
	if ( iResult !=sizeof ( unsigned int ))
	{
		//如果长度字段在接收时没有返回一个整型数据就返回0（连接关闭）或-1（发生错误）
		if ( iResult == -1 )
		{
	         printf("接收发生错误: %d\n", WSAGetLastError());
		     return -1;
		}
		else
		{
			 printf("连接关闭\n");
             return 0;
		}
	}
	//转换网络字节顺序到主机字节顺序
	reclen = ntohl( reclen );
	if ( reclen > recvbuflen )
	{
		//如果recvbuf没有足够的空间存储变长消息，则接收该消息并丢弃，返回错误
		while ( reclen > 0)
		{
			iResult = recvn( s, recvbuf, recvbuflen );
			if ( iResult != recvbuflen )
			{
				//如果变长消息在接收时没有返回足够的数据就返回0（连接关闭）或-1（发生错误）
				if ( iResult == -1 )
				{
					 printf("接收发生错误: %d\n", WSAGetLastError());
					 return -1;
				}
				else
				{
					 printf("连接关闭\n");
					 return 0;
				}
			}
			reclen -= recvbuflen;
			//处理最后一段数据长度
			if ( reclen < recvbuflen )
				recvbuflen = reclen;
		}
		printf("可变长度的消息超出预分配的接收缓存\r\n");
		return -1;
	}
	//接收可变长消息
	iResult = recvn( s, recvbuf, reclen );
	if ( iResult != reclen )
	{
        //如果消息在接收时没有返回足够的数据就返回0（连接关闭）或-1（发生错误）
		if ( iResult == -1 )
		{
	         printf("接收发生错误: %d\n", WSAGetLastError());
		     return -1;
		}
		else
		{
			 printf("连接关闭\n");
             return 0;
		}
	}
	return iResult;
}
/********************************************************
函数名：udp_server
输入参数：char * hname：服务器主机名 or 点分十进制表示的IP地址
          char * sname：服务端口号
输出参数：创建服务器端流式套接字并配置，-1：表示失败
功能：创建流式套接字，根据用户输入的地址和端口号，绑定套接字的服务地址
      将其转换为监听状态
*********************************************************/
SOCKET CSocketFrame::udp_server( char *hname, char *sname )
{
	sockaddr_in local;
	SOCKET ServerSocket;
	const int on = 1;
	int iResult = 0;

    //为服务器的本地地址local设置用户输入的IP和端口号
	if (set_address( hname, sname, &local, "udp" ) !=0 )
		return -1;
	
	//创建套接字
	ServerSocket = socket( AF_INET, SOCK_DGRAM, 0 );
	if (ServerSocket == INVALID_SOCKET) {
        printf("socket 函数调用错误，错误号： %ld\n", WSAGetLastError());
        clean_up();
        return -1;
    }

	//设置服务器地址可重用选项
	iResult = setsockopt( ServerSocket, SOL_SOCKET, SO_REUSEADDR, ( char * )&on, sizeof( on ));
	if ( iResult == SOCKET_ERROR){
		printf("setsockopt函数调用错误，错误号： %d\n", WSAGetLastError());
        quit(ServerSocket);
        return -1;
    }

    //绑定服务器地址
	iResult = bind( ServerSocket, (struct sockaddr *) & local, sizeof (local));
    if (iResult == SOCKET_ERROR) {
        printf("bind 函数调用错误，错误号： %d\n", WSAGetLastError());
        quit(ServerSocket);
        return -1;
    }

	return ServerSocket;
}
/********************************************************
函数名：udp_client
输入参数：char * hname：服务器主机名 or 点分十进制表示的IP地址
          char * sname：服务端口号
		  BOOL flag：工作模式标识，true表示连接模式，false表示非连接模式
输出参数：创建客户端流式套接字,-1：表示失败
功能：创建数据报套接字，根据用户输入的地址和端口号
*********************************************************/
SOCKET CSocketFrame::udp_client( char *hname, char *sname, BOOL flag)
{
	struct sockaddr_in peer;
	SOCKET ClientSocket;
	int iResult = -1;

	//指明服务器的地址peer为用户输入的IP和端口号
	if (set_address( hname, sname, &peer, "udp" ) ==1 )
		return -1;

	//创建套接字
	ClientSocket = socket( AF_INET, SOCK_DGRAM, 0 );
	if (ClientSocket == INVALID_SOCKET) {
        printf("socket 函数调用错误，错误号： %ld\n", WSAGetLastError());
        clean_up();
        return -1;
    }

	if( flag == TRUE)
	{
		//连接模式
		//请求向服务器建立连接
	    iResult =connect( ClientSocket, ( struct sockaddr * )&peer, sizeof( peer ) );
	    if (iResult == SOCKET_ERROR){
		    printf("connect 函数调用错误，错误号： %d\n", WSAGetLastError());
		    quit(ClientSocket);
		    return -1;
		}
    }
	
	return ClientSocket;
}
/********************************************************
函数名：check_sum
输入参数：
		  USHORT *pchBuffer：待计算校验和的缓冲区
		  int iSize：待计算校验和缓冲区长度
输出参数：校验和
功能：计算校验和
*********************************************************/
USHORT CSocketFrame::check_sum(USHORT *pchBuffer, int iSize)
{
    unsigned long ulCksum=0;
    while (iSize > 1) 
    {
        ulCksum += *pchBuffer++;
        iSize -= sizeof(USHORT);
    }
    if (iSize) 
    {
        ulCksum += *(UCHAR*)pchBuffer;
    }
    ulCksum = (ulCksum >> 16) + (ulCksum & 0xffff);
    ulCksum += (ulCksum >>16);
    return (USHORT)(~ulCksum);
}
/********************************************************
函数名：raw_socket
输入参数：
		  BOOL bSendflag：首部控制选项
		  BOOL bRecvflag：接收控制选项
		  int iProtocol：协议设置，具体内容参考MSDN对协议的定义，如#define IPPROTO_IP 0
		  sockaddr_in *pLocalIP：指向本地IP地址的指针，返回参数，如果存在多个接口地址，获取用户选择的本地地址
输出参数：创建客户端流式套接字,-1：表示失败
功能：创建数据报套接字，根据用户输入的地址和端口号
*********************************************************/
SOCKET CSocketFrame::raw_socket( BOOL bSendflag, BOOL bRecvflag, int iProtocol, sockaddr_in *pLocalIP)
{
	SOCKET RawSocket;
	int iResult = 0;
	struct hostent *local;
    char HostName[DEFAULT_NAMELEN];
	struct in_addr addr;
    int in=0,i=0;
    DWORD dwBufferLen[10];
 	DWORD Optval= 1 ;
    DWORD dwBytesReturned = 0 ;


	//创建套接字
	RawSocket = socket( AF_INET, SOCK_RAW, iProtocol );
	if (RawSocket == INVALID_SOCKET) {
        printf("socket 函数调用错误，错误号： %ld\n", WSAGetLastError());
        clean_up();
        return -1;
    }

	if( bSendflag == TRUE)
	{
		//设置IP_HDRINCL表示要构造IP头，需#include "ws2tcpip.h"
	    iResult = setsockopt(RawSocket,IPPROTO_IP,IP_HDRINCL,(char*)&bSendflag,sizeof(bSendflag));
		if (iResult == SOCKET_ERROR){
		    printf("setsockopt 函数调用错误，错误号： %d\n", WSAGetLastError());
		    quit(RawSocket);
		    return -1;
		}
    }
	if( bRecvflag == TRUE)
	{
		//设置I/O控制选项，接收全部IP包
		//获取本机名称
	    memset( HostName, 0, DEFAULT_NAMELEN);
	    iResult = gethostname( HostName, sizeof(HostName));
	    if ( iResult ==SOCKET_ERROR) {
	      printf("gethostname 函数调用错误，错误号： %ld\n", WSAGetLastError());
	      quit(RawSocket);
	      return -1;
	    }
	
	    //获取本机可用IP
	    local = gethostbyname( HostName);
	    printf ("\n本机可用的IP地址为：\n");
	    if( local ==NULL)
	    {
	        printf("gethostbyname 函数调用错误，错误号： %ld\n", WSAGetLastError());
	        quit(RawSocket);
	        return -1;
	    }
	    while (local->h_addr_list[i] != 0) {
	        addr.s_addr = *(u_long *) local->h_addr_list[i++];
	        printf("\tIP Address #%d: %s\n", i, inet_ntoa(addr));
	    }
	   
	    printf ("\n请选择捕获数据待使用的接口号：");
	    scanf_s( "%d", &in);
	    
	    memset( pLocalIP, 0, sizeof(sockaddr_in));
	    memcpy( &pLocalIP->sin_addr.S_un.S_addr, local->h_addr_list[in-1], sizeof(pLocalIP->sin_addr.S_un.S_addr));
	    pLocalIP->sin_family = AF_INET;
	    pLocalIP->sin_port = 0;
	
	    //绑定本地地址
	    iResult = bind( RawSocket, (struct sockaddr *) pLocalIP, sizeof(sockaddr_in));
	    if( iResult == SOCKET_ERROR){
	        printf("bind 函数调用错误，错误号： %ld\n", WSAGetLastError());
	        quit(RawSocket);
			return -1;
	    }
	    printf(" \n成功绑定套接字和#%d号接口地址", in);
	
	    //设置套接字接收命令
	    iResult = WSAIoctl(RawSocket, SIO_RCVALL , &Optval, sizeof(Optval),  &dwBufferLen, sizeof(dwBufferLen), &dwBytesReturned , NULL , NULL );
	    if ( iResult == SOCKET_ERROR ){
	        printf("WSAIoctl 函数调用错误，错误号： %ld\n", WSAGetLastError());
	        quit(RawSocket);
			return -1;
	    }
	}
	return RawSocket;
}