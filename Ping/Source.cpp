#include "Header.h"

using namespace std;

const int packageDataSize = 32;
const int TIMEOUT_MS = 2000;

int main()
{
#if  defined _WIN32 || defined _WIN64
	_CrtSetDbgFlag(33);
#endif;

	string ip, ipLocal;
	Input(&ip, &ipLocal);

	sockaddr_in remoteAddr = InitAddress(inet_addr(ip));
	sockaddr_in myAddr = InitAddress(htonl(INADDR_ANY));
	SOCKET my_socket = InitSocket(myAddr);

	Work(my_socket, ip, ipLocal, remoteAddr);

#if  defined _WIN32 || defined _WIN64
	closesocket(my_socket);
	WSACleanup();

	system("Pause");
#endif;

	return 0;
}

void Input(string* ip, string* ipLocal)
{
	cout << "Ping: ";
	getline(cin, *ip);
	if (ip->empty())
	{
		*ip = "213.180.204.3";
#if  defined _WIN32 || defined _WIN64
		system("cls");
#elif defined __linux__
		cout<<"\033[2j\033[1;1H";
#endif
		cout << "Ping: 213.180.204.3 [yandex.ru]" << endl;
	}

	cout << "Sender ip: ";
	getline(cin, *ipLocal);
}

SOCKET InitSocket(sockaddr_in my_addr)
{
#if  defined _WIN32 || defined _WIN64
	WSADATA wsd = { 0 };
	WSAStartup(0x202, &wsd);
	SOCKET my_socket = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, 0, 0, WSA_FLAG_OVERLAPPED);
#elif defined __linux__
	SOCKET my_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
#endif
	bind(my_socket, (sockaddr*)&my_addr, sizeof my_addr);
	setsockopt(my_socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&TIMEOUT_MS, sizeof TIMEOUT_MS);

	return my_socket;
}

void Work(SOCKET my_socket, string ip, string ipLocal, sockaddr_in remoteAddr)
{
	int icmp_size = sizeof(IcmpHeader) + packageDataSize;
	char* icmp = new char[icmp_size];
	IcmpHeader *icmp_package = GetIcmpPackage(icmp_size, icmp);

	if (!ipLocal.empty())  //manual set source IP
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
#if  defined _WIN32 || defined _WIN64
	icmpHeader.i_id = (USHORT)GetCurrentProcessId();
#elif defined __linux__
	icmpHeader.i_id = getpid();
#endif

	//add into package 32 bytes of data ('Z' letters)
	memcpy(package_memory, &icmpHeader, sizeof icmpHeader);
	memset(package_memory + sizeof icmpHeader, 'Z', packageDataSize);

	IcmpHeader *icmp_package = (IcmpHeader *)package_memory;
	icmp_package->i_crc = crc2((USHORT*)icmp_package, icmp_size);//count checksum

	return icmp_package;
}

void InitIpPackage(char* ip_package, SOCKET my_socket, int ip_size, int icmp_size, IcmpHeader *icmp_package, string ip, string ipLocal)
{
	//manually create IP header
	//gather our package: ip header + icmp header + data

	int param = 1;
	setsockopt(my_socket, IPPROTO_IP, IP_HDRINCL, (char*)&param, sizeof param);//say that we manually create header

	IpHeader IpHead = { 0 };
	IpHead.verhlen = 69;
	IpHead.ttl = 200;
	IpHead.source = inet_addr(ipLocal);
	IpHead.destination = inet_addr(ip);
	IpHead.totallent = ip_size - icmp_size;
	IpHead.proto = 1;

	memcpy(ip_package, &IpHead, sizeof(IpHeader));
	memcpy(ip_package + sizeof(IpHeader), icmp_package, icmp_size);

	//checksum counting automatic for IP
}

void Ping(SOCKET my_socket, string ip, char* package, int package_size, sockaddr_in remoteAddr)
{
	cout << "Pinging " << ip << " with " << packageDataSize << " bytes of data:" << endl;

	for (int i = 0; i < 4; ++i)
	{
#if  defined _WIN32 || defined _WIN64
		DWORD sendTime = GetTickCount();
#elif defined __linux__
        time_t sendTime = time(0);
#endif

		sendto(my_socket, package, package_size, 0, (sockaddr*)&remoteAddr, sizeof remoteAddr);

		char bf[256] = { 0 };
#if  defined _WIN32 || defined _WIN64
		int outlent = sizeof(sockaddr_in);
#elif defined __linux__
		socklen_t outlent = sizeof(sockaddr_in);
#endif
		sockaddr_in out_ = { 0 };
		out_.sin_family = AF_INET;

#if  defined _WIN32 || defined _WIN64
		if (recvfrom(my_socket, bf, 256, 0, (sockaddr*)&out_, &outlent) == SOCKET_ERROR)
		{
			if (WSAGetLastError() == WSAETIMEDOUT)
			{
				cout << "Request timeout\n";
				continue;
			}
		}
#elif defined __linux__
        switch (MySelect(my_socket)) {
            case -1:
                PrintLastError();
                return;
            case 0:
                cout << "Request timeout\n";
                continue;
            default:
                break;
        }
        if (recvfrom(my_socket, bf, 256, 0, (sockaddr*)&out_, &outlent) == SOCKET_ERROR)
            PrintLastError();
#endif
#if  defined _WIN32 || defined _WIN64
		Analize(bf, &out_, GetTickCount() - sendTime);
#elif defined __linux__
		Analize(bf, &out_, time(0) - sendTime);
#endif
		memset(bf, 0, 0);
#if  defined _WIN32 || defined _WIN64
        Sleep(1000);
#elif defined __linux__
        sleep(1);
#endif
	}
}

sockaddr_in InitAddress(unsigned long addr)
{
	sockaddr_in address = { 0 };
#if  defined _WIN32 || defined _WIN64
	address.sin_addr.S_un.S_addr = addr;
#elif defined __linux__
	address.sin_addr.s_addr = addr;
#endif
	address.sin_family = AF_INET;
	address.sin_port = htons(6666);
	return address;
}

unsigned int Analize(char* data, sockaddr_in* adr, DWORD time) //analize reply
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
#if  defined _WIN32 || defined _WIN64
	if (GetCurrentProcessId() == icmpPacket->i_id) //check if we sent it
#elif defined __linux__
	if (getpid() == icmpPacket->i_id) //check if we sent it
#endif
		cout << "Reply from " << Ip << ": time=" << time << "ms TTL=" << TTL << endl;
	else
		cout << "Fake packet\n";
	return ipPacket->source;
}

USHORT crc2(USHORT* addr, int count) //http://www.ietf.org/rfc/rfc1071.txt CRC counting
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

void PrintLastError() {
#if  defined _WIN32 || defined _WIN64
	wchar_t buf[256];
    FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf, 256, NULL);
    wcout << buf;
#elif defined __linux__
	int error = errno;
	cout << strerror(error);
#endif
}

unsigned long inet_addr(string cp)
{
	return inet_addr(cp.c_str());
}

#if defined __linux__
int MySelect(int socket) {
    fd_set fds;
    struct timeval tv;

    // Set up the file descriptor set.
    FD_ZERO(&fds);
    FD_SET(socket, &fds);

    // Set up the struct timeval for the timeout.
    tv.tv_sec = TIMEOUT_MS / 1000;
    tv.tv_usec = (TIMEOUT_MS % 1000) * 1000;

    // Wait until timeout or data received.
    return select(socket + 1, &fds, NULL, NULL, &tv);
}
#endif