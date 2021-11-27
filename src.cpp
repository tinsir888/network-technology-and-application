#define HAVE_REMOTE
#define WINDOWS_IGNORE_PACKING_MISMATCH
#pragma pack(1)
#include <Winsock2.h>
#include "pcap.h"
#include <iostream>
#include <cstdio>
#include <cstring>
#include <iomanip>
#pragma comment(lib,"ws2_32.lib")//必备
#pragma warning(disable:4996)
#pragma warning(disable:6011)
using namespace std;
#pragma pack(1)//参考教科书，声明帧头部，ARP帧结构
typedef struct FrameHeader_t//帧首部
{
	BYTE DesMAC[6];  //目的地址
	BYTE SrcMAC[6];  //源地址
	WORD FrameType;  //帧类型
}FrameHeader_t;
typedef struct ARPFrame_t//首部
{
	FrameHeader_t FrameHeader;
	WORD HardwareType;//硬件类型
	WORD ProtocolType;//协议类型
	BYTE HLen;//硬件地址长度
	BYTE PLen;//协议地址长度
	WORD Operation;//操作类型
	BYTE SendHa[6];//发送方MAC地址
	DWORD SendIP;//发送方IP地址
	BYTE RecvHa[6];//接收方MAC地址
	DWORD RecvIP;//接收方IP地址
}ARPFrame_t;
#pragma pack()
int pMACaddr(BYTE MACaddr[6])//输出MAC地址
{
	int i = 0;
	while (i <= 5)
	{
		cout << setw(2) << setfill('0') << hex << (int)MACaddr[i];
		if (i != 5)
			cout << "-";
		else
			cout << endl;
		i++;
	}
	return i;
}
int pIPaddr(DWORD IPaddr)//输出IP地址
{
	BYTE* p = (BYTE*)&IPaddr;
	int i = 0;
	while (i <= 3)
	{
		cout << dec << (int)*p;

		if (i != 3)
			cout << ".";
		else
			cout << endl;
		p++;
		i++;
	}
	return i;
}
int pARPframe(ARPFrame_t* IPPacket)//输出ARP帧
{
	cout << "本次捕获得到的ARP帧内容如下：" << endl;
	cout << "目的MAC地址："<< endl;
	pMACaddr(IPPacket->FrameHeader.DesMAC);
	cout << "源MAC地址：" << endl;
	pMACaddr(IPPacket->FrameHeader.SrcMAC);
	//ntoh():将一个16位数由网络字节顺序转换为主机字节顺序
	cout << "帧类型: " << hex << ntohs(IPPacket->FrameHeader.FrameType) << endl;
	cout << "硬件类型: " << hex << ntohs(IPPacket->HardwareType) << endl;
	cout << "协议类型: " << hex << ntohs(IPPacket->ProtocolType) << endl;
	cout << "硬件地址长度: " << hex << (int)IPPacket->HLen << endl;
	cout << "协议地址长度: " << hex << (int)IPPacket->PLen << endl;
	cout << "报文类型: " << hex << ntohs(IPPacket->Operation) << endl;
	//Operation 表示这个报文的类型，ARP 请求为 1，ARP 响应为 2，RARP 请求为 3，RARP 响应为 4。
	cout << "发送端 MAC 地址: ";
	pMACaddr(IPPacket->SendHa);
	cout << "发送端 IP 地址: ";
	pIPaddr(IPPacket->SendIP);
	cout << "目的端 MAC 地址: ";
	pMACaddr(IPPacket->RecvHa);
	cout << "目的端 IP 地址: ";
	pIPaddr(IPPacket->RecvIP);
	return 0;
}
int main()
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	pcap_addr_t* a;
	pcap_t* adhandle;
	BYTE* IP;
	char errbuf[PCAP_ERRBUF_SIZE];
	ARPFrame_t ARPFrame;
	ARPFrame_t* IPPacket;
	DWORD SIP, ReIP, MIP;
	u_int netmask;
	//获取设备列表，若发生错误进行错误处理
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,
		NULL,
		&alldevs,
		errbuf)
		== -1)
	{
		cout << "获取设备列表时发生错误" <<errbuf<< endl;
		throw -1;
	}
	int i = 0,inum;
	//参考上次实验中写的打开设备端口代码，对错误进行错误处理
	for (d = alldevs; d != NULL; d = d->next)
	{
		cout << ++i << " " << d->name << endl;
		if (d->description)
		{
			cout << d->description << endl;
		}
		else
		{
			cout << "No description available" << endl << "没有可用的描述！" << endl;
		}
		a = d->addresses;
		while (a != NULL) //相对第一次试验，增加输出IP地址，掩码，广播地址的代码
		{
			if (a->addr->sa_family == AF_INET)
			{
				cout << "  IP地址: " << inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr) << endl;
				//cout << "  网络掩码: " << inet_ntoa(((struct sockaddr_in*)(a->netmask))->sin_addr) << endl;
				//cout << "  广播地址: " << inet_ntoa(((struct sockaddr_in*)(a->broadaddr))->sin_addr) << endl;
			}
			a = a->next;
		}
	}
	if (i == 0)
	{
		cout << "Check NPcap" << endl << "没有找到端口！请检查NPcap！" << endl;
		throw -2;
	}
	cout << "Enter the interface number:(range:1-" << i << ")" << endl << "请输入进入的端口号:（范围：1-" << i << "）" << endl;
	cin >> inum;
	if (inum<1 || inum>i)
	{
		cout << "Interface number out of range!" << endl << "端口号不在正确范围内！" << endl;
		pcap_freealldevs(alldevs);
		throw -3;
	}
	/* 借助第一次实验代码，跳转到选中的适配器 */

	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	if ((adhandle = pcap_open(d->name,
		65535,
		PCAP_OPENFLAG_PROMISCUOUS,//设置为混杂模式
		1000,
		NULL,
		errbuf
	)) == NULL)
	{
		cout << stderr << endl << "Unable to open the adapter, maybe it is not supported by WinPcap" << endl << "无法打开，请检查是否受到NPcap支持！" << d->name;
		pcap_freealldevs(alldevs);
		throw -4;
	}
	cout <<"接入端口：" <<inum<<" "<< d->description << endl;

	//编写过滤器代码使其只捕获ARP数据包，对错误进行错误处理
	netmask = ((sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	struct bpf_program fcode;
	char packet_filter[] = "ether proto \\arp"; 
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		cout << "编译数据包过滤器时遇到错误！请检查过滤器语法" << endl;
		pcap_freealldevs(alldevs);
		throw -5;
	}
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		cout << "设置过滤器时发生错误！"<<endl;
		pcap_freealldevs(alldevs);
		throw -6;
	}
	//预处理将要发送的 ARP 数据报
	for (i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xFF;//表示广播
		ARPFrame.FrameHeader.SrcMAC[i] = 0x00;//设置为任意 MAC 地址
		ARPFrame.RecvHa[i] = 0;//置0
		ARPFrame.SendHa[i] = 0x11;//设置为任意 MAC 地址
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806);//帧类型为ARP
	ARPFrame.HardwareType = htons(0x0001);//硬件类型为以太网
	ARPFrame.ProtocolType = htons(0x0800);//协议类型为IP
	ARPFrame.HLen = 6;//硬件地址长度为6
	ARPFrame.PLen = 4;//协议地址长为4
	ARPFrame.Operation = htons(0x0001);//操作为ARP请求
	SIP = ARPFrame.SendIP = htonl(0x00000000);//设置为任意 IP 地址
	//将所选择的网卡的 IP 设置为请求的 IP 地址
	for (a = d->addresses; a != NULL; a = a->next)
	{
		if (a->addr->sa_family == AF_INET)
		{
			ReIP = ARPFrame.RecvIP = inet_addr(inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr));
		}
	}
	struct pcap_pkthdr* adhandleheader;
	const u_char* adhandledata;
	int tjdg = 0;
	//发送ARPFrame中的内容，报文长度为sizeof(ARPFrame_t)，如果发送成功，返回0
	if (pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		cout << "ARP数据包发送失败！" << endl;
		pcap_freealldevs(alldevs);
		throw -7;
	}
	else
	{
		cout << "ARP数据包发送成功！" << endl;
get_local_mac:	
		int jdg_catch_re_arp_p = pcap_next_ex(adhandle, &adhandleheader, &adhandledata);
		if (jdg_catch_re_arp_p == -1)
		{
			cout << "捕获ARP返回数据包时发生错误！" << endl;
			pcap_freealldevs(alldevs);
			throw -8;
		}
		else if (jdg_catch_re_arp_p == 0)
			{
				cout << "暂未获得数据报，请稍候" << endl;
				cout << "已尝试次数: " << ++tjdg << endl;
				if (tjdg > 20)
				{
					cout << "已多次尝试接收，请确认端口是否正常" << endl;
					pcap_freealldevs(alldevs);
					throw -9;
				}				
				goto get_local_mac;
			}
			else
			{
				IPPacket = (ARPFrame_t*)adhandledata;
				if(SIP==IPPacket->SendIP)
					if (ReIP == IPPacket->RecvIP)
					{
						cout << "确认正常！" << endl;
						goto get_local_mac;
					}
				if(SIP == IPPacket->RecvIP && ReIP == IPPacket->SendIP)
					{
						cout << "成功获取回复的数据报！" << endl; 
						pARPframe(IPPacket);
						cout << endl;
						cout << "获取到本机IP地址与MAC地址的对应关系如下：" << endl << "IP：";
						pIPaddr(IPPacket->SendIP);
						cout << "MAC: ";
						pMACaddr(IPPacket->SendHa);
						cout << endl;
					}
				else goto get_local_mac;
			}
	}
	cout << endl;
	cout << "向网络发送数据包" << endl;
	char pip[16];
	cout << "请输入目的IP地址" << endl;
	cin >> pip;
	ReIP = ARPFrame.RecvIP = inet_addr(pip);
	SIP = ARPFrame.SendIP =	IPPacket->SendIP;
	for (i = 0; i < 6; i++)
	{
		//将本机IP填入报文
		ARPFrame.SendHa[i] = ARPFrame.FrameHeader.SrcMAC[i] = IPPacket->SendHa[i];
	}
	if (pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		cout << "ARP数据包发送失败！" << endl;
		pcap_freealldevs(alldevs);
		throw -10;
	}
	else
	{
		cout << "ARP数据包发送成功！" << endl; 
		inum = 0;
get_distant_mac:
		int jdg_catch_re_arp_p = pcap_next_ex(adhandle, &adhandleheader, &adhandledata);
		if (jdg_catch_re_arp_p == -1)
		{
			cout << "捕获ARP返回数据包时发生错误！" << endl;
			pcap_freealldevs(alldevs);
			throw -11;
		}
		else
			if (jdg_catch_re_arp_p == 0)
			{
				cout << "暂未获得数据报，请稍候" << endl;
				cout << "已尝试次数：" <<dec<< ++inum << endl;
				if (inum > 20)
				{
					cout << "已多次尝试接收，请确认端口是否正常" << endl;
					pcap_freealldevs(alldevs);
					throw -12;
				}
				goto get_distant_mac;
			}
			else
			{
				IPPacket = (ARPFrame_t*)adhandledata;
				if (SIP == IPPacket->SendIP)
					if (ReIP == IPPacket->RecvIP)
					{
						cout << "确认发送正常！" << endl;
						goto get_distant_mac;
					}
				//收到了回应
				if (SIP == IPPacket->RecvIP && ReIP == IPPacket->SendIP)
				{
					cout << "成功获取回复的数据报！" << endl;
					pARPframe(IPPacket);
					cout << endl;
					cout << "获取到IP地址与MAC地址的对应关系如下：" << endl << "IP：";
					pIPaddr(IPPacket->SendIP);
					cout << "MAC: ";
					pMACaddr(IPPacket->SendHa);
					cout << endl;
				}
				else goto get_distant_mac;
			}
	}
	return 0;
}