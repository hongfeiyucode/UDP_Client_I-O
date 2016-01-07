// EchoUDPClient.cpp : �������̨Ӧ�ó������ڵ㡣
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

	cout << "EchoUDPClient��������ʼ������������������ӡ�����\n";

	//Windows Sockets Dll��ʼ��
	frame.start_up();
	
	//�����ͻ��˵����ݱ��׽��֣������������������
	ClientSocket = frame.udp_client( ip, ECHOPORT, true );
	if ( ClientSocket == -1 )
		return -1;

	printf("���ӽ����ɹ����Ƿ��������ͬ��ʱ�䣿(Y/N) ");
	//��ʼ��������ķ��������
	//ָ���������ĵ�ַpeerΪ�û������IP�Ͷ˿ں�
	if (frame.set_address( ip, ECHOPORT, &servaddr, "udp" ) !=0 )
		return 0;

	iResult = udp_client_fun_echo(stdin, ClientSocket, (SOCKADDR *)&servaddr, sizeof(sockaddr_in) );
	if(iResult == -1)
	    printf("��ǰ������̳���!\n");

	frame.quit( ClientSocket );
    return iResult; 
}

/********************************************************
��������udp_client_fun_echo
���������FILE *fp:ָ��FILE���͵Ķ���
          SOCKET s:�ͻ��˵����ݱ��׽���
		  SOCKADDR servaddr����������ַ
		  int servlen����ַ����
���������0���ɹ���-1��ʧ��
���ܣ�����ͻ��˵ľ��幦�ܺ���
*********************************************************/
int udp_client_fun_echo(FILE *fp, SOCKET s, SOCKADDR *servaddr, int servlen)
{
	int iResult;
    char sendline[MAXLINE],recvline[MAXLINE];
	memset(sendline,0,MAXLINE);
	memset(recvline,0,MAXLINE);

	//ѭ�������û����������ݣ������շ��������ص�Ӧ��ֱ���û�����"Q"����
	while(fgets(sendline,MAXLINE,fp)!=NULL)
	{
		if(*sendline == 'n'|| *sendline == 'N'){
			printf("�Ͽ����� �˳�����!\n");
			return 0;
		}
		iResult = sendto(s,sendline,strlen(sendline),0, (SOCKADDR *)servaddr, servlen);
		if(iResult == SOCKET_ERROR)
		{
			printf("sendto �������ô��󣬴���ţ� %ld\n", WSAGetLastError());
			return -1;
		}
		printf("\r\n�ͻ��˷������ݣ�%s\r\n", sendline);

	    memset(recvline,0,MAXLINE);
		iResult = recvfrom( s, recvline, MAXLINE, 0, NULL, NULL ) ;
		if (iResult > 0)
		{
			printf("�������ͬ��ʱ��ɹ�����ǰʱ��Ϊ��%s \r\n", recvline);
			printf("\n------------------------\n�Ƿ�����������ͬ��ʱ�䣿(Y/N) ");
		}
		else{
 	        printf("recvfrom �������ô��󣬴����: %d\n", WSAGetLastError());
			break;
		}
		memset(sendline,0,MAXLINE);
	}
	return iResult;
}

