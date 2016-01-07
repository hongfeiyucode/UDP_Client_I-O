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
��������set_address
���������char * hname�������� or ���ʮ���Ʊ�ʾ��IP��ַ
          char * sname���˿ں�
		  struct sockaddr_in * sap����sockaddr_in�ṹ�洢�ĵ�ַ�����������
          char * protocol���ַ�����ʽ������Э�����ͣ���"tcp"
���������0��ʾ�ɹ���-1��ʾʧ�ܡ�
���ܣ����ݸ���������������ʮ���Ʊ�ʾ��IP��ַ�����sockaddr_in�ṹ�洢�ĵ�ַ
*********************************************************/
int CSocketFrame::set_address(char * hname, char * sname, struct sockaddr_in * sap, char * protocol)
{
	struct servent *sp;
	struct hostent *hp;
	char *endptr;
	unsigned short port;
	unsigned long ulAddr = INADDR_NONE;


    //�Ե�ַ�ṹsocketaddr_in��ʼ��Ϊ0�������õ�ַ��ΪAF_INET
	memset( sap,0, sizeof( *sap ) );
	sap->sin_family = AF_INET;
	
	if ( hname != NULL )
	{
		//���hname��Ϊ�գ��ٶ�������hnameΪ���ʮ���Ʊ�ʾ�����ֵ�ַ��ת����ַΪsockaddr_in����
		ulAddr = inet_addr(hname);
		if ( ulAddr == INADDR_NONE || ulAddr == INADDR_ANY) {
			//printf("inet_addr �������ô��󣬴���ţ� %d\n", WSAGetLastError());
			//���ô��󣬱�����������������������gethostbyname���������ַ
			hp = gethostbyname( hname );
			if ( hp == NULL ) {
				printf("δ֪��������������ţ� %d\n", WSAGetLastError());
				return -1;
			}
			sap->sin_addr = *( struct in_addr * )hp->h_addr;
        }      
		else
			sap->sin_addr.S_un.S_addr=ulAddr;		
	}
	else
		//���������û��ָ��һ�����������ַ�������õ�ַΪͨ���ַINADDR_ANY
		sap->sin_addr.s_addr = htonl( INADDR_ANY );
	//����ת��snameΪһ������
	port = (unsigned short )strtol( sname, &endptr, 0 );
	if ( *endptr == '\0' )
	{
		//����ɹ���ת��Ϊ�����ֽ�˳��
		sap->sin_port = htons( port );
	}
	else
	{
		//���ʧ�ܣ���ٶ���һ���������ƣ�ͨ������getservbyname��ö˿ں�
		sp = getservbyname( sname, protocol );
		if ( sp == NULL ) {
			printf("δ֪�ķ��񣬴���ţ� %d\n", WSAGetLastError());
			return -1;
		}
		sap->sin_port = sp->s_port;
	}
	return 0;
}

/********************************************************
��������start_up
�����������
���������0���ɹ���-1��ʧ��
���ܣ���ʼ��Windows Sockets DLL��Э�̰汾��
*********************************************************/
int CSocketFrame::start_up(void)
{
	WORD wVersionRequested;
    WSADATA wsaData;
    int iResult;

    // ʹ�� MAKEWORD(lowbyte, highbyte) �꣬��Windef.h ������
    wVersionRequested = MAKEWORD(2, 2);

    iResult = WSAStartup(wVersionRequested, &wsaData);
    if (iResult != 0) {
        //��֪�û��޷��ҵ����ʿ��õ�Winsock DLL
        printf("WSAStartup �������ô��󣬴���ţ� %d\n",  WSAGetLastError());
        return -1;
    }

    // ȷ��WinSock Dll֧�ְ汾2.2
    // ע�⣬���DLL֧�ֵİ汾��2.2���ߣ������û�����ǰ��������Ȼ����2.2�汾�ţ��洢��wsaData.wVersion

    if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
        // ��֪�û��޷��ҵ����õ�WinSock DLL.                              
        printf("�޷��ҵ����õ�Winsock.dll�汾\n");
        WSACleanup();
        return -1;
    }

	return 0;
}
/********************************************************
��������clean_up
�����������
���������0���ɹ���-1��ʧ��
���ܣ���ֹWindows Sockets DLL��ʹ�ã��ͷ���Դ 
*********************************************************/
int CSocketFrame::clean_up(void)
{
	int iResult;
	iResult = WSACleanup();
    if (iResult == SOCKET_ERROR) {
        // WSACleanup����ʧ��                  
        printf("WSACleanup �������ô��󣬴���ţ� %d\n",  WSAGetLastError());
        return -1;
    }

	return 0;
}
/********************************************************
��������quit
���������SOCKET s:�������������׽���
���������0���ɹ���-1��ʧ��
���ܣ��ر��׽��֣��ͷ�dll
*********************************************************/
int CSocketFrame::quit(SOCKET s)
{
    int iResult=0;
    iResult = closesocket(s);
    if (iResult == SOCKET_ERROR){
        printf("closesocket �������ô��󣬴���ţ�%d\n", WSAGetLastError());
        return -1;
    }
    iResult = clean_up();
    return iResult;
}
/********************************************************
��������tcp_server
���������char * hname�������������� or ���ʮ���Ʊ�ʾ��IP��ַ
          char * sname������˿ں�
�����������������������ʽ�׽��ֲ����ã�-1����ʾʧ��
���ܣ�������ʽ�׽��֣������û�����ĵ�ַ�Ͷ˿ںţ����׽��ֵķ����ַ
      ����ת��Ϊ����״̬
*********************************************************/
SOCKET CSocketFrame::tcp_server( char *hname, char *sname )
{
	sockaddr_in local;
	SOCKET ListenSocket;
	const int on = 1;
	int iResult = 0;

    //Ϊ�������ı��ص�ַlocal�����û������IP�Ͷ˿ں�
	if (set_address( hname, sname, &local, "tcp" ) !=0 )
		return -1;
	
	//�����׽���
	ListenSocket = socket( AF_INET, SOCK_STREAM, 0 );
	if (ListenSocket == INVALID_SOCKET) {
        printf("socket �������ô��󣬴���ţ� %ld\n", WSAGetLastError());
        clean_up();
        return -1;
    }

	//���÷�������ַ������ѡ��
	iResult = setsockopt( ListenSocket, SOL_SOCKET, SO_REUSEADDR, ( char * )&on, sizeof( on ));
	if ( iResult == SOCKET_ERROR){
		printf("setsockopt�������ô��󣬴���ţ� %d\n", WSAGetLastError());
        quit(ListenSocket);
        return -1;
    }

    //�󶨷�������ַ
	iResult = bind( ListenSocket, (struct sockaddr *) & local, sizeof (local));
    if (iResult == SOCKET_ERROR) {
        printf("bind �������ô��󣬴���ţ� %d\n", WSAGetLastError());
        quit(ListenSocket);
        return -1;
    }

	//���÷�����Ϊ����״̬���������г���ΪNLISTEN
    iResult = listen(ListenSocket, SOMAXCONN);
	if (iResult == SOCKET_ERROR){
		printf("listen �������ô��󣬴���ţ� %d\n", WSAGetLastError());
		quit(ListenSocket);
		return -1;
    }

	return ListenSocket;
}
/********************************************************
��������tcp_client
���������char * hname�������������� or ���ʮ���Ʊ�ʾ��IP��ַ
          char * sname������˿ں�
��������������ͻ�����ʽ�׽���,-1����ʾʧ��
���ܣ�������ʽ�׽��֣������û�����ĵ�ַ�Ͷ˿ںţ�������ַ
      ����������
*********************************************************/
SOCKET CSocketFrame::tcp_client( char *hname, char *sname )
{
	struct sockaddr_in peer;
	SOCKET ClientSocket;
	int iResult = 0;

	//ָ���������ĵ�ַpeerΪ�û������IP�Ͷ˿ں�
	if (set_address( hname, sname, &peer, "tcp" ) !=0 )
		return -1;

	//�����׽���
	ClientSocket = socket( AF_INET, SOCK_STREAM, 0 );
	if (ClientSocket == INVALID_SOCKET) {
        printf("socket �������ô��󣬴���ţ� %ld\n", WSAGetLastError());
        clean_up();
        return -1;
    }

    //�������������������
	iResult =connect( ClientSocket, ( struct sockaddr * )&peer, sizeof( peer ) );
	if (iResult == SOCKET_ERROR){
		printf("connect �������ô��󣬴���ţ� %d\n", WSAGetLastError());
		quit(ClientSocket);
		return -1;
    }

	return ClientSocket;
}
/********************************************************
��������recvn
���������SOCKET s:�������������׽���
          char * recvbuf:��Ž��յ����ݵĻ����� 
		  int fixedlen:�̶���Ԥ�������ݳ���
���������>0��ʵ�ʽ��յ����ֽ�����-1��ʧ��
���ܣ�����ʽ�׽����н��չ̶����ȵ�����
********************************************************/
int CSocketFrame::recvn(SOCKET s, char * recvbuf, unsigned int fixedlen)
{
	int iResult;//�洢����recv�����ķ���ֵ
	int cnt;//����ͳ������ڹ̶����ȣ�ʣ������ֽ���δ����
	cnt = fixedlen;
	while ( cnt > 0 )
	{
        iResult = recv(s, recvbuf, cnt, 0);
        if ( iResult < 0 )
		{
			//���ݽ��ճ��ִ��󣬷���ʧ��
			printf("���շ�������: %d\n", WSAGetLastError());
		    return -1;
		}
	    if ( iResult == 0 )
		{
			//�Է��ر����ӣ������ѽ��յ���С��fixedlen���ֽ���
	        printf("���ӹر�\n");
			return fixedlen - cnt;
		}
	    //printf("���յ����ֽ���: %d\n", iResult);
		//���ջ���ָ������ƶ�
		recvbuf +=iResult;
		//����cntֵ
		cnt -=iResult;         
	}
	return fixedlen;
}
/********************************************************
��������recvvl
���������SOCKET s:�������������׽���
          char * recvbuf:��Ž��յ����ݵĻ����� 
		  int recvbuflen:���ջ���������
���������>0��ʵ�ʽ��յ����ֽ�����-1��ʧ�ܣ�0�����ӹر�
���ܣ�����ʽ�׽����н��տɱ䳤�ȵ�����
********************************************************/
int CSocketFrame::recvvl(SOCKET s, char * recvbuf, unsigned int recvbuflen)
{
	int iResult;//�洢����recv�����ķ���ֵ
	unsigned int reclen; //���ڴ洢����ͷ���洢�ĳ�����Ϣ
	//��ȡ���ձ��ĳ�����Ϣ
    iResult = recvn(s, ( char * )&reclen, sizeof( unsigned int ));
	if ( iResult !=sizeof ( unsigned int ))
	{
		//��������ֶ��ڽ���ʱû�з���һ���������ݾͷ���0�����ӹرգ���-1����������
		if ( iResult == -1 )
		{
	         printf("���շ�������: %d\n", WSAGetLastError());
		     return -1;
		}
		else
		{
			 printf("���ӹر�\n");
             return 0;
		}
	}
	//ת�������ֽ�˳�������ֽ�˳��
	reclen = ntohl( reclen );
	if ( reclen > recvbuflen )
	{
		//���recvbufû���㹻�Ŀռ�洢�䳤��Ϣ������ո���Ϣ�����������ش���
		while ( reclen > 0)
		{
			iResult = recvn( s, recvbuf, recvbuflen );
			if ( iResult != recvbuflen )
			{
				//����䳤��Ϣ�ڽ���ʱû�з����㹻�����ݾͷ���0�����ӹرգ���-1����������
				if ( iResult == -1 )
				{
					 printf("���շ�������: %d\n", WSAGetLastError());
					 return -1;
				}
				else
				{
					 printf("���ӹر�\n");
					 return 0;
				}
			}
			reclen -= recvbuflen;
			//�������һ�����ݳ���
			if ( reclen < recvbuflen )
				recvbuflen = reclen;
		}
		printf("�ɱ䳤�ȵ���Ϣ����Ԥ����Ľ��ջ���\r\n");
		return -1;
	}
	//���տɱ䳤��Ϣ
	iResult = recvn( s, recvbuf, reclen );
	if ( iResult != reclen )
	{
        //�����Ϣ�ڽ���ʱû�з����㹻�����ݾͷ���0�����ӹرգ���-1����������
		if ( iResult == -1 )
		{
	         printf("���շ�������: %d\n", WSAGetLastError());
		     return -1;
		}
		else
		{
			 printf("���ӹر�\n");
             return 0;
		}
	}
	return iResult;
}
/********************************************************
��������udp_server
���������char * hname�������������� or ���ʮ���Ʊ�ʾ��IP��ַ
          char * sname������˿ں�
�����������������������ʽ�׽��ֲ����ã�-1����ʾʧ��
���ܣ�������ʽ�׽��֣������û�����ĵ�ַ�Ͷ˿ںţ����׽��ֵķ����ַ
      ����ת��Ϊ����״̬
*********************************************************/
SOCKET CSocketFrame::udp_server( char *hname, char *sname )
{
	sockaddr_in local;
	SOCKET ServerSocket;
	const int on = 1;
	int iResult = 0;

    //Ϊ�������ı��ص�ַlocal�����û������IP�Ͷ˿ں�
	if (set_address( hname, sname, &local, "udp" ) !=0 )
		return -1;
	
	//�����׽���
	ServerSocket = socket( AF_INET, SOCK_DGRAM, 0 );
	if (ServerSocket == INVALID_SOCKET) {
        printf("socket �������ô��󣬴���ţ� %ld\n", WSAGetLastError());
        clean_up();
        return -1;
    }

	//���÷�������ַ������ѡ��
	iResult = setsockopt( ServerSocket, SOL_SOCKET, SO_REUSEADDR, ( char * )&on, sizeof( on ));
	if ( iResult == SOCKET_ERROR){
		printf("setsockopt�������ô��󣬴���ţ� %d\n", WSAGetLastError());
        quit(ServerSocket);
        return -1;
    }

    //�󶨷�������ַ
	iResult = bind( ServerSocket, (struct sockaddr *) & local, sizeof (local));
    if (iResult == SOCKET_ERROR) {
        printf("bind �������ô��󣬴���ţ� %d\n", WSAGetLastError());
        quit(ServerSocket);
        return -1;
    }

	return ServerSocket;
}
/********************************************************
��������udp_client
���������char * hname�������������� or ���ʮ���Ʊ�ʾ��IP��ַ
          char * sname������˿ں�
		  BOOL flag������ģʽ��ʶ��true��ʾ����ģʽ��false��ʾ������ģʽ
��������������ͻ�����ʽ�׽���,-1����ʾʧ��
���ܣ��������ݱ��׽��֣������û�����ĵ�ַ�Ͷ˿ں�
*********************************************************/
SOCKET CSocketFrame::udp_client( char *hname, char *sname, BOOL flag)
{
	struct sockaddr_in peer;
	SOCKET ClientSocket;
	int iResult = -1;

	//ָ���������ĵ�ַpeerΪ�û������IP�Ͷ˿ں�
	if (set_address( hname, sname, &peer, "udp" ) ==1 )
		return -1;

	//�����׽���
	ClientSocket = socket( AF_INET, SOCK_DGRAM, 0 );
	if (ClientSocket == INVALID_SOCKET) {
        printf("socket �������ô��󣬴���ţ� %ld\n", WSAGetLastError());
        clean_up();
        return -1;
    }

	if( flag == TRUE)
	{
		//����ģʽ
		//�������������������
	    iResult =connect( ClientSocket, ( struct sockaddr * )&peer, sizeof( peer ) );
	    if (iResult == SOCKET_ERROR){
		    printf("connect �������ô��󣬴���ţ� %d\n", WSAGetLastError());
		    quit(ClientSocket);
		    return -1;
		}
    }
	
	return ClientSocket;
}
/********************************************************
��������check_sum
���������
		  USHORT *pchBuffer��������У��͵Ļ�����
		  int iSize��������У��ͻ���������
���������У���
���ܣ�����У���
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
��������raw_socket
���������
		  BOOL bSendflag���ײ�����ѡ��
		  BOOL bRecvflag�����տ���ѡ��
		  int iProtocol��Э�����ã��������ݲο�MSDN��Э��Ķ��壬��#define IPPROTO_IP 0
		  sockaddr_in *pLocalIP��ָ�򱾵�IP��ַ��ָ�룬���ز�����������ڶ���ӿڵ�ַ����ȡ�û�ѡ��ı��ص�ַ
��������������ͻ�����ʽ�׽���,-1����ʾʧ��
���ܣ��������ݱ��׽��֣������û�����ĵ�ַ�Ͷ˿ں�
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


	//�����׽���
	RawSocket = socket( AF_INET, SOCK_RAW, iProtocol );
	if (RawSocket == INVALID_SOCKET) {
        printf("socket �������ô��󣬴���ţ� %ld\n", WSAGetLastError());
        clean_up();
        return -1;
    }

	if( bSendflag == TRUE)
	{
		//����IP_HDRINCL��ʾҪ����IPͷ����#include "ws2tcpip.h"
	    iResult = setsockopt(RawSocket,IPPROTO_IP,IP_HDRINCL,(char*)&bSendflag,sizeof(bSendflag));
		if (iResult == SOCKET_ERROR){
		    printf("setsockopt �������ô��󣬴���ţ� %d\n", WSAGetLastError());
		    quit(RawSocket);
		    return -1;
		}
    }
	if( bRecvflag == TRUE)
	{
		//����I/O����ѡ�����ȫ��IP��
		//��ȡ��������
	    memset( HostName, 0, DEFAULT_NAMELEN);
	    iResult = gethostname( HostName, sizeof(HostName));
	    if ( iResult ==SOCKET_ERROR) {
	      printf("gethostname �������ô��󣬴���ţ� %ld\n", WSAGetLastError());
	      quit(RawSocket);
	      return -1;
	    }
	
	    //��ȡ��������IP
	    local = gethostbyname( HostName);
	    printf ("\n�������õ�IP��ַΪ��\n");
	    if( local ==NULL)
	    {
	        printf("gethostbyname �������ô��󣬴���ţ� %ld\n", WSAGetLastError());
	        quit(RawSocket);
	        return -1;
	    }
	    while (local->h_addr_list[i] != 0) {
	        addr.s_addr = *(u_long *) local->h_addr_list[i++];
	        printf("\tIP Address #%d: %s\n", i, inet_ntoa(addr));
	    }
	   
	    printf ("\n��ѡ�񲶻����ݴ�ʹ�õĽӿںţ�");
	    scanf_s( "%d", &in);
	    
	    memset( pLocalIP, 0, sizeof(sockaddr_in));
	    memcpy( &pLocalIP->sin_addr.S_un.S_addr, local->h_addr_list[in-1], sizeof(pLocalIP->sin_addr.S_un.S_addr));
	    pLocalIP->sin_family = AF_INET;
	    pLocalIP->sin_port = 0;
	
	    //�󶨱��ص�ַ
	    iResult = bind( RawSocket, (struct sockaddr *) pLocalIP, sizeof(sockaddr_in));
	    if( iResult == SOCKET_ERROR){
	        printf("bind �������ô��󣬴���ţ� %ld\n", WSAGetLastError());
	        quit(RawSocket);
			return -1;
	    }
	    printf(" \n�ɹ����׽��ֺ�#%d�Žӿڵ�ַ", in);
	
	    //�����׽��ֽ�������
	    iResult = WSAIoctl(RawSocket, SIO_RCVALL , &Optval, sizeof(Optval),  &dwBufferLen, sizeof(dwBufferLen), &dwBytesReturned , NULL , NULL );
	    if ( iResult == SOCKET_ERROR ){
	        printf("WSAIoctl �������ô��󣬴���ţ� %ld\n", WSAGetLastError());
	        quit(RawSocket);
			return -1;
	    }
	}
	return RawSocket;
}