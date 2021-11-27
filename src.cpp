#define HAVE_REMOTE
#include <Winsock2.h>
#include "pcap.h"
#include <iostream>
#include <iomanip>
#include <cstdio>
#pragma comment(lib,"ws2_32.lib")
#pragma warning(disable:4996)
#pragma warning(disable:6011)
using namespace std;
//存储MAC地址的结构体
struct ethernet_header
{
	uint8_t ether_final[6];//目的MAC地址
	uint8_t ether_from[6];//源MAC地址
	uint16_t ether_type;
};
//存储IP地址和校验和的结构体
struct ip_header
{
	uint8_t ip_header_length : 4,
		ip_version : 4;

	uint8_t ip_tos;
	uint16_t ip_length;
	uint16_t ip_checksum;//校验和字段
	struct in_addr  ip_source_address;//源地址
	struct in_addr  ip_destination_address;//目的地址
};
/* packet handler 函数 */
/* 每次捕获到数据包时，libpcap都会自动调用这个回调函数 */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	struct tm* ltime;
	struct ethernet_header* ethernet_protocol; /*以太网协议变量*/
	struct ip_header* ip_protocol;/*ip协议变量*/
	ip_protocol = (struct ip_header*)(pkt_data + 14); /*处理ip数据包的内容*/
	char timestr[16];
	time_t local_tv_sec;
	u_char* macsave;
	cout << "捕获到数据包!" << endl;
	/* 将时间戳转换成可识别的格式 */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	cout << "捕获时间:    ";
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
	cout << timestr << endl;
	cout << "数据包长度:  " << header->len << "字节" << endl;
	ethernet_protocol = (struct ethernet_header*)pkt_data;
	/*源MAC地址*/
	macsave = ethernet_protocol->ether_from;
	cout << "源MAC地址:   ";
	printf("%02x:%02x:%02x:%02x:%02x:%02x", *macsave, *(macsave + 1), *(macsave + 2), *(macsave + 3), *(macsave + 4), *(macsave + 5));//经过测试，cout会产生奇怪的bug，故用也能支持的printf来表示
	/*目的MAC地址*/
	cout << endl;
	macsave = ethernet_protocol->ether_final;
	cout << "目的MAC地址: ";
	printf("%02x:%02x:%02x:%02x:%02x:%02x", *macsave, *(macsave + 1), *(macsave + 2), *(macsave + 3), *(macsave + 4), *(macsave + 5));
	cout << endl;
	/*源ip地址*/
	cout << "源IP地址:    " << inet_ntoa(ip_protocol->ip_source_address) << endl;
	/*目的ip地址*/
	cout << "目的IP地址:  " << inet_ntoa(ip_protocol->ip_destination_address) << endl;
	//cout << "帧类型：" << "以太网帧" << endl;
	/*校验和字段*/
	cout << "校验和字段:  " << ip_protocol -> ip_checksum << endl;
	cout << endl << endl;
}
int main()
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	pcap_addr_t* a;
	pcap_t* adhandle;
	int inum;
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	cout << "Start!" << endl << "开始扫描端口！" << endl;
	//扫描所有端口并展示
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,
		NULL,
		&alldevs,
		errbuf
	) == -1)
	{
		cout << "error!" << endl << "获取端口错误！";
		exit(1);
	}
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
	}
	if (i == 0)
	{
		cout << "Check Winpcap" << endl << "没有找到端口！请检查 NPcap！" << endl;
		return -1;
	}
	cout << "Enter the interface number:(range:1-" << i << ")" << endl << "请输入进入的端口号:（范围：1-" << i << "）" << endl;
	cin >> inum;
	if (inum<1 || inum>i)
	{
		cout << "Interface number out of range!" << endl << "端口号不在正确范围内！" << endl;
		pcap_freealldevs(alldevs);
		return -1;
	}
	/* 跳转到选中的适配器 */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	if ((adhandle = pcap_open(d->name,
		65535,
		PCAP_OPENFLAG_PROMISCUOUS,
		1000,
		NULL,
		errbuf
	)) == NULL)
	{
		cout << stderr << endl << "Unable to open the adapter, it is not supported by NPcap" << endl << "无法打开，请检查是否受到 NPcap 支持！" << d->name;
		pcap_freealldevs(alldevs);
		return -1;
	}
	cout << "listening on : " << d->description << endl;
	pcap_freealldevs(alldevs);
	int pnum = 0;
	cout << "Enter the number of data package needed!" << endl << "输入捕获数据包数量" << endl;
	cin >> pnum;
	//main中通过调用pcap_loop来捕获pnum个数据包
	pcap_loop(adhandle, pnum, packet_handler, NULL);
	cout << "Packages caputuring finished!" << endl << "数据报捕获结束！" << endl;
	system("pause");
	return 0;
}