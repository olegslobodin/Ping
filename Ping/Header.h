#pragma once

#include <WinSock2.h>
#include <ws2tcpip.h>
#include <Ws2ipdef.h>
#include <windows.h>
#include <crtdbg.h>
#include <iostream>

#include <string>

using namespace std;

#pragma comment (lib,"ws2_32")

typedef struct ip_hdr //заголовок IP 
{
	unsigned char verhlen;
	unsigned char tos : 6;
	unsigned char additional : 2;
	unsigned short totallent;
	unsigned short id;
	unsigned short offset;
	unsigned char ttl;
	unsigned char proto;
	unsigned short checksum;
	unsigned int source;
	unsigned int destination;
}IpHeader;

typedef  struct icmp_hdr //заголовок ICMP
{
	unsigned char i_type;
	unsigned char i_code;
	unsigned short i_crc;
	unsigned short i_seq;
	unsigned short i_id;

}IcmpHeader;

void Input(string* ip, string* ipLocal);

SOCKET InitSocket(sockaddr_in my_addr);

sockaddr_in InitAddress(unsigned long addr);

void Work(SOCKET my_socket, string ip, string ipLocal, sockaddr_in remoteAddr);

IcmpHeader* GetIcmpPackage(int icmp_size, char* package_memory);

void InitIpPackage(char* ip_package, SOCKET my_socket, int ip_size, int icmp_size, IcmpHeader *icmp_package, string ip, string ipLocal);

void Ping(SOCKET my_socket, string ip, char* package, int package_size, sockaddr_in remoteAddr);

unsigned int Analize(char* data, SOCKADDR_IN* adr, DWORD time);

USHORT crc2(USHORT* addr, int count);

unsigned long inet_addr(string cp);