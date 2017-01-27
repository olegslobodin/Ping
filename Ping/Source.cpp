#include "Header.h"

using namespace std;

const int packageDataSize = 32;

int main()
{
	_CrtSetDbgFlag(33);
	string ip, ipLocal;

	Input(&ip, &ipLocal);

	sockaddr_in remoteAddr = InitAddress(inet_addr(ip));
	sockaddr_in myAddr = InitAddress(htonl(INADDR_ANY));

	SOCKET my_socket = InitSocket(myAddr);

	Work(my_socket, ip, ipLocal, remoteAddr);

	closesocket(my_socket);
	WSACleanup();

	system("Pause");
	return 0;
}

void Input(string* ip, string* ipLocal)
{
	cout << "Ping: ";
	getline(cin, *ip);
	if (ip->empty())
	{
		*ip = "213.180.204.3";
		system("cls");
		cout << "Ping: 213.180.204.3 [yandex.ru]" << endl;
	}

	cout << "Sender ip: ";
	getline(cin, *ipLocal);
}

SOCKET InitSocket(sockaddr_in my_addr)
{
	WSADATA wsd = { 0 };
	WSAStartup(0x202, &wsd);

	SOCKET my_socket = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, 0, 0, WSA_FLAG_OVERLAPPED);
	bind(my_socket, (sockaddr*)&my_addr, sizeof my_addr);
	int timeout = 3000;
	setsockopt(my_socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof timeout); //таймаут получения

	return my_socket;
}

void Work(SOCKET my_socket, string ip, string ipLocal, sockaddr_in remoteAddr)
{
	int icmp_size = sizeof(IcmpHeader) + packageDataSize;
	char* icmp = new char[icmp_size];
	IcmpHeader *icmp_package = GetIcmpPackage(icmp_size, icmp);

	if (!ipLocal.empty())  //установка ip отправителя вручную
	{
		int ip_size = sizeof(IpHeader) + icmp_size;
		char* ip_package = new char[ip_size];

		InitIpPackage(ip_package, my_socket, ip_size, icmp_size, icmp_package, ip, ipLocal);
		Ping(my_socket, ip, ip_package, ip_size, remoteAddr);

		delete[] ip_package;
	}
	else
		Ping(my_socket, ip, (char*)icmp_package, icmp_size, remoteAddr);

	delete[] icmp;
}

IcmpHeader* GetIcmpPackage(int icmp_size, char* package_memory)
{
	IcmpHeader icmpHeader = { 0 };
	icmpHeader.i_type = 8;
	icmpHeader.i_code = 0;
	icmpHeader.i_seq = 2;
	icmpHeader.i_crc = 0;
	icmpHeader.i_id = (USHORT)GetCurrentProcessId();//записать в ICMP идентификатор процесса.      

	//создаем довесок из данных в 32 байта заполненый буквой Z, чтоб было похоже на настоящее
	memcpy(package_memory, &icmpHeader, sizeof icmpHeader);
	memset(package_memory + sizeof icmpHeader, 'Z', packageDataSize);

	IcmpHeader *icmp_package = (IcmpHeader *)package_memory;
	icmp_package->i_crc = crc2((USHORT*)icmp_package, icmp_size);//считаем контрольную сумму пакета, заголовок+данные

	return icmp_package;
}

void InitIpPackage(char* ip_package, SOCKET my_socket, int ip_size, int icmp_size, IcmpHeader *icmp_package, string ip, string ipLocal)
{
	//здесь формируем IP заголовок вручную
	// и собираем пакет наш IP+Icmp+данные

	int param = 1;
	setsockopt(my_socket, IPPROTO_IP, IP_HDRINCL, (char*)&param, sizeof param);//сообщаем что сами слепим заголовок

	IpHeader IpHead = { 0 };
	IpHead.verhlen = 69;
	IpHead.ttl = 200;
	IpHead.source = inet_addr(ipLocal);
	IpHead.destination = inet_addr(ip);
	IpHead.totallent = ip_size - icmp_size;
	IpHead.proto = 1;

	memcpy(ip_package, &IpHead, sizeof(IpHeader));
	memcpy(ip_package + sizeof(IpHeader), icmp_package, icmp_size);

	//crc IP система посчитает сама, с ним можно не париться
	//однако для ICMP расчет обязателен 
}

void Ping(SOCKET my_socket, string ip, char* package, int package_size, sockaddr_in remoteAddr)
{
	cout << "Pinging " << ip << " with " << packageDataSize << " bytes of data:" << endl;

	for (int i = 0; i < 4; ++i)
	{
		DWORD sendTime = GetTickCount();

		sendto(my_socket, package, package_size, 0, (sockaddr*)&remoteAddr, sizeof remoteAddr);

		char bf[256] = { 0 };
		int outlent = sizeof(sockaddr_in);
		sockaddr_in out_ = { 0 };
		out_.sin_family = AF_INET;

		if (recvfrom(my_socket, bf, 256, 0, (sockaddr*)&out_, &outlent) == SOCKET_ERROR)
		{
			if (WSAGetLastError() == WSAETIMEDOUT)
			{
				cout << "Request timeout\n";
				continue;
			}
		}
		Analize(bf, &out_, GetTickCount() - sendTime);
		memset(bf, 0, 0);
		Sleep(1000);
	}
}

sockaddr_in InitAddress(unsigned long addr)
{
	sockaddr_in address = { 0 };
	address.sin_addr.S_un.S_addr = addr;
	address.sin_family = AF_INET;
	address.sin_port = htons(6666);
	return address;
}

unsigned int Analize(char* data, sockaddr_in* adr, DWORD time) //разбор ответа
{
	char* Ip = "";
	IpHeader *ipPacket = (IpHeader*)data;
	char Name[NI_MAXHOST] = { 0 };
	char servInfo[NI_MAXSERV] = { 0 };
	getnameinfo((struct sockaddr *) adr, sizeof(struct sockaddr), Name, NI_MAXHOST, servInfo, NI_MAXSERV, NI_NUMERICSERV);
	Ip = inet_ntoa(adr->sin_addr);

	int TTL = (int)ipPacket->ttl;
	data += sizeof(IpHeader);
	IcmpHeader *icmpPacket = (IcmpHeader*)data;
	if (GetCurrentProcessId() == icmpPacket->i_id)//проверка что это мы слали.
		cout << "Reply from " << Ip << ": time=" << time << "ms TTL=" << TTL << endl;
	else
		cout << "Fake packet\n";
	return ipPacket->source;
}

USHORT crc2(USHORT* addr, int count) //http://www.ietf.org/rfc/rfc1071.txt подсчет CRC
{
	long sum = 0;

	while (count > 1) {
		/*  This is the inner loop */
		sum += *(unsigned short*)addr++;
		count -= 2;
	}

	/*  Add left-over byte, if any */
	if (count > 0)
		sum += *(unsigned char *)addr;

	/*  Fold 32-bit sum to 16 bits */
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return (USHORT)~sum;
}

unsigned long inet_addr(string cp)
{
	return inet_addr(cp.c_str());
}