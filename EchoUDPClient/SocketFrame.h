#pragma once
#include "winsock2.h"
#include "stdio.h"
#pragma comment(lib,"ws2_32.lib")
//定义网络框架程序中所需的宏
#define TRUE			1
#define FALSE			0
#define	MAXLINE		    200	    // max text line length 
#define	DEFAULT_NAMELEN 100 //默认的名字长度
//首部结构定义
typedef struct tagIPHDR
{
	UCHAR hdr_len :4;  // length of the header
    UCHAR version :4;  // version of IP
	UCHAR	TOS;	   // Type of service
	USHORT	TotLen;	   // Total length
	USHORT	ID;		   // Identification
	USHORT	FlagOff;   // Flags and fragment offset
	UCHAR	TTL;	   // Time-to-live
	UCHAR	Protocol;  // Protocol
	USHORT	Checksum;  // Checksum
	ULONG IPSrc;	   // Internet address, source
	ULONG IPDst;	   // Internet address, destination
} IPHDR, *PIPHDR;

typedef struct tagUDPHDR	//UDP头定义
{
	USHORT src_portno; 
	USHORT dst_portno; 
	USHORT udp_length; 
	USHORT udp_checksum; 
} UDPHDR,*PUDPHDR;

typedef struct tagTCPHDR		//TCP首部定义
{
	USHORT  sport;            //Source port 
    USHORT  dport;            //Destination port 
    ULONG   seq;              //Sequence number 
    ULONG   ack;              //Ack number 
    BYTE    hlen;             // TCP header len (num of bytes << 2) 
    BYTE    flags;            // Option flags 
    USHORT  window;           // Flow control credit (num of bytes) 
    USHORT  check;            // Checksum 
    USHORT  urgent;           // Urgent data pointer 
} TCPHDR,*PTCPHDR;
//TCP标志字段定义
#define TFIN        0x01    // Option flags: no more data 
#define TSYN        0x02    // sync sequence nums 
#define TRST        0x04    // reset connection 
#define TPUSH       0x08    // push buffered data 
#define TACK        0x10    // acknowledgement 
#define TURGE       0x20    // urgent 


typedef struct tagFHDR		//UDP伪首部定义
{
	ULONG IPSrc;	
	ULONG IPDst;	
	UCHAR zero;
	UCHAR protocol;
	USHORT udp_length;
} FHDR,*PFHDR;


//ICMP数据报头
typedef struct tagICMPHDR
{
    UCHAR type;  //8位类型
    UCHAR code;  //8位代码
    USHORT cksum;  //16位校验和
    USHORT id;   //16位标识符
    USHORT seq;  //16位序列号
} ICMPHDR,*PICMPHDR;

#pragma pack()
//ICMP类型字段
const BYTE ICMP_ECHO_REQUEST = 8; //请求回显
const BYTE ICMP_ECHO_REPLY  = 0; //回显应答
const BYTE ICMP_TIMEOUT   = 11; //传输超时
const DWORD DEF_ICMP_TIMEOUT = 3000; //默认超时时间，单位ms
const int DEF_ICMP_DATA_SIZE = 32; //默认ICMP数据部分长度
const int MAX_ICMP_PACKET_SIZE = 1024; //最大ICMP数据报的大小
const int DEF_MAX_HOP = 30;    //最大跳站数
class CSocketFrame
{
public:
	CSocketFrame(void);
	~CSocketFrame(void);
	int set_address(char * hname, char * sname, struct sockaddr_in * sap, char * protocol);
	int start_up(void);
	int clean_up(void);
	int quit(SOCKET s);
	USHORT check_sum(USHORT *pchBuffer, int iSize);
	SOCKET tcp_server( char *hname, char *sname );
	SOCKET udp_server( char *hname, char *sname );
	int recvn(SOCKET s, char * recvbuf, unsigned int fixedlen);
	int recvvl(SOCKET s, char * recvbuf, unsigned int recvbuflen);
	SOCKET tcp_client( char *hname, char *sname );
	SOCKET udp_client( char *hname, char *sname, BOOL flag);
    SOCKET raw_socket( BOOL bSendflag, BOOL bRecvflag, int iProtocol, sockaddr_in *pLocalIP);
};
