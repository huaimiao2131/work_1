#define WIN32
#define _CRT_SECURE_NO_WARNINGS 1
#include "pcap.h" 
//#include<pthread.h>
#define ETH_ARP         0x0806  //以太网帧类型表示后面数据的类型，对于ARP请求或应答来说，该字段的值为x0806
#define ARP_HARDWARE    1  //硬件类型字段值为表示以太网地址
#define ETH_IP          0x0800  //协议类型字段表示要映射的协议地址类型值为x0800表示IP地址
#define ARP_REQUEST     1   //ARP请求
#pragma comment ( lib, "wpcap.lib")

typedef struct EthernetHeader
{
	u_char DestMAC[6];    //目的MAC地址 6字节
	u_char SourMAC[6];    //源MAC地址 6字节
	u_short EthType;      //上一层协议类型，如0x0800代表上一层是IP协议，0x0806为arp  2字节
};

typedef struct ip_address {
	// 4 字节的 IP 地址
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}
ip_address;

typedef struct mac_address {
	// 6 字节的 MAC 地址   
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
}
mac_address;

// ARP 首部
typedef struct arp_header {
	u_short htype;
	//硬件类型 (16 bits)
	u_short ptype;
	//协议类型 (16 bits)
	u_char hlen;
	//硬件地址长度(8 bits)
	u_char plen;
	//协议长度(8 bits)
	u_short op;
	//操作类型(16 bits)
	mac_address smac;
	//发送方 MAC 地址（48 bits）
	ip_address saddr;
	//发送方 IP 地址（32 bits）
	mac_address dmac;
	//目标 MAC 地址（48 bits）
	ip_address daddr;
	//目标 IP 地址（32 bits）
	 //arp_header() {
	 //}
}
;

//函数定义
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char
	* pkt_data);
void ifprint(pcap_if_t* d);
void send_requestarp();
void operations();

//全局设备
pcap_if_t* d;
pcap_t* adhandle;
FILE* fp;
ip_address* tar_ip;
mac_address* tar_mac;

//初始化
int main() {
	//打开日志文件
	fp = fopen("D:\\demo.txt", "w+");

	//寻找设备链表
	pcap_if_t* alldevs;

	int inum;
	int i = 0;

	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "arp";
	struct bpf_program fcode;
	if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
		// 获得设备列表 
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	for (d = alldevs; d; d = d->next) {
		// 打印网络适配器列表
		printf("%d. %s", ++i, d->name);
		ifprint(d);
		if (d->description)
			printf(" (%s)\n", d->description); else
			printf(" (No description available)\n");
	}
	if (i == 0) {
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);
	if (inum < 1 || inum > i) {
		printf("\nInterface number out of range.\n");
		pcap_freealldevs(alldevs);
		//释放设备列表
		return -1;
	}
	//跳转到已选网络适配卡
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	if ((adhandle = pcap_open(d->name, 65536,
		PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL,
		errbuf) //打开网络适配卡
		) == NULL) {
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		pcap_freealldevs(alldevs);
		// 释放设备列表
		return -1;
	}

	// 检查数据链路层，只考虑以太网
	if (pcap_datalink(adhandle) != DLT_EN10MB) {
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		pcap_freealldevs(alldevs);
		// 释放设备列表
		return -1;
	}
	if (d->addresses != NULL)
		// 获得接口第一个地址的掩码
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else //如果接口没有地址，则假设一个 C 类的掩码
		netmask = 0xffffff;

	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0) //编译过滤器 
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		pcap_freealldevs(alldevs);
		// 释放设备列表
		return -1;
	}

	if (pcap_setfilter(adhandle, &fcode) < 0) //设置过滤器 
	{
		fprintf(stderr, "\nError setting the filter.\n");
		pcap_freealldevs(alldevs);
		// 释放设备列表
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);
	pcap_freealldevs(alldevs);

	operations();

	pcap_loop(adhandle, 0, packet_handler, NULL);


	fclose(fp);

	// 开始捕捉
	return 0;
}

//操作
void operations() {
	send_requestarp();
}

//pcap_t*
void send_requestarp() {
	//开始填充ARP包，填充数据写死在代码中，测试用时数据可随意填写
	unsigned char sendbuf[42]; //arp包结构大小，42个字节
	unsigned char smac[6] = { 0xd8,0xf3,0xbc,0x65,0x24,0xbf };
	//unsigned char sip[4] = { 10,24,13,74 };

	unsigned char sip[4] = { 192,168,212,207 };					//我的（源）IP地址
	//unsigned char smac[6] = { 0x2c,0x6d,0xc1,0x9e,0x96,0x0c };  //我的（源）MAC地址
//	unsigned char dmac[6] = { 0x18,0x56,0x80,0x94,0xc2,0x94 };  //我网关的mac
//	//unsigned char dmac[6] = { 0x1e,0xa6,0x17,0x8e,0xca,0xcd };  //我网关的mac
//	unsigned char dip[4]   =  {  192,168,43,119 };					//目的IP地址

	tar_mac = new mac_address();
	tar_mac->byte1 = 0xff;
	tar_mac->byte2 = 0xff;
	tar_mac->byte3 = 0xff;
	tar_mac->byte4 = 0xff;
	tar_mac->byte5 = 0xff;
	tar_mac->byte6 = 0xff;

	/*tar_ip->byte1 = */

	unsigned char dmac[6] = { tar_mac->byte1,tar_mac->byte2,tar_mac->byte3,tar_mac->byte4,tar_mac->byte5,tar_mac->byte6 };
	unsigned char dip[4];
	//unsigned char dip[4] = {tar_ip->byte1,tar_ip->byte2,tar_ip->byte3,tar_ip->byte4};

	printf("请输入目的ip地址：\n");
	scanf("%hhu.%hhu.%hhu.%hhu", &dip[0], &dip[1], &dip[2], &dip[3]);

	EthernetHeader eh;
	arp_header arph;
	//赋值MAC地址
	memcpy(eh.DestMAC, dmac, 6);   //以太网首部目的MAC地址，全为广播地址
	memcpy(eh.SourMAC, smac, 6);   //以太网首部源MAC地址
	eh.EthType = htons(ETH_ARP);   //htons：将主机的无符号短整形数转换成网络字节顺序

	arph.smac.byte1 = smac[0];
	arph.smac.byte2 = smac[1];
	arph.smac.byte3 = smac[2];
	arph.smac.byte4 = smac[3];
	arph.smac.byte5 = smac[4];
	arph.smac.byte6 = smac[5];

	arph.dmac.byte1 = dmac[0];
	arph.dmac.byte2 = dmac[1];
	arph.dmac.byte3 = dmac[2];
	arph.dmac.byte4 = dmac[3];
	arph.dmac.byte5 = dmac[4];
	arph.dmac.byte6 = dmac[5];

	arph.saddr.byte1 = sip[0];
	arph.saddr.byte2 = sip[1];
	arph.saddr.byte3 = sip[2];
	arph.saddr.byte4 = sip[3];

	arph.daddr.byte1 = dip[0];
	arph.daddr.byte2 = dip[1];
	arph.daddr.byte3 = dip[2];
	arph.daddr.byte4 = dip[3];

	arph.htype = htons(ARP_HARDWARE);
	arph.ptype = htons(ETH_IP);
	arph.hlen = 6;
	arph.plen = 4;
	arph.op = htons(ARP_REQUEST);

	//构造一个ARP请求
	memset(sendbuf, 0, sizeof(sendbuf));   //ARP清零
	memcpy(sendbuf, &eh, sizeof(eh));
	memcpy(sendbuf + sizeof(eh), &arph, sizeof(arph));
	//如果发送成功
	if (pcap_sendpacket(adhandle, sendbuf, 42) == 0) {
		printf("\nPacketSend succeed\n");
		fprintf(fp, "%s", "\nPacketSend succeed\n");
	}
	else {
		fprintf(fp, "%s %d", "PacketSendPacket in getmine Error: %d\n", GetLastError());
		printf("PacketSendPacket in getmine Error: %d\n", GetLastError());
	}
}

//回调函数，当收到每一个数据包时会被 libpcap 所调用
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char
	* pkt_data)
{
	struct tm* ltime;
	char timestr[16];
	arp_header* arph;

	time_t local_tv_sec;
	local_tv_sec = header->ts.tv_sec;
	//将时间戳转换成可识别的格式
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	//打印数据包的时间戳和长度
	printf("%s.%.6d len:%d \n", timestr, header->ts.tv_usec, header->len);

	arph = (arp_header*)(pkt_data + 14);
	//打印 IP 地址
	printf("ip\t from\t %d.%d.%d.%d \n",
		arph->saddr.byte1,
		arph->saddr.byte2,
		arph->saddr.byte3,
		arph->saddr.byte4

	
	);
	printf("ip\t to\t %d.%d.%d.%d\n",
	

		arph->daddr.byte1,
		arph->daddr.byte2,
		arph->daddr.byte3,
		arph->daddr.byte4
	);

	fprintf(fp, "ip   from    %d.%d.%d.%d  to  %d.%d.%d.%d\n", "PacketSendPacket in getmine Error: %d\n",
		arph->saddr.byte1,
		arph->saddr.byte2,
		arph->saddr.byte3,
		arph->saddr.byte4,

		arph->daddr.byte1,
		arph->daddr.byte2,
		arph->daddr.byte3,
		arph->daddr.byte4
	);

	//打印 MAC 地址
	printf("mac\t from\t %02x.%02x.%02x.%02x.%02x.%02x\n",
		arph->smac.byte1,
		arph->smac.byte2,
		arph->smac.byte3,
		arph->smac.byte4,
		arph->smac.byte5,
		arph->smac.byte6

	);
	printf("mac\t to\t %02x.%02x.%02x.%02x.%02x.%02x\n",
	

		arph->dmac.byte1,
		arph->dmac.byte2,
		arph->dmac.byte3,
		arph->dmac.byte4,
		arph->dmac.byte5,
		arph->dmac.byte6
	);

	fprintf(fp, "mac from % 02x. % 02x. % 02x. % 02x. % 02x. % 02x to % 02x. % 02x. % 02x. % 02x. % 02x. % 02x\n",
		arph->smac.byte1,
		arph->smac.byte2,
		arph->smac.byte3,
		arph->smac.byte4,
		arph->smac.byte5,
		arph->smac.byte6,

		arph->dmac.byte1,
		arph->dmac.byte2,
		arph->dmac.byte3,
		arph->dmac.byte4,
		arph->dmac.byte5,
		arph->dmac.byte6
	);

	printf("报文类型：");
	if (arph->op == 256)
	{
		printf("request\n");
		fprintf(fp, "报文类型：request\n");
	}
	else {
		printf("reply\n");
		fprintf(fp, "报文类型：reply\n");
		tar_ip = &arph->daddr;
		tar_mac = &arph->dmac;
	}
}

/* 将数字类型的IP地址转换成字符串类型的 */
#define IPTOSBUFFERS    12
char* iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char* p;
	p = (u_char*)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf_s(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}
char* ip6tos(struct sockaddr* sockaddr, char* address, int addrlen)
{
	socklen_t sockaddrlen;
	sockaddrlen = sizeof(struct sockaddr_storage);
	if (getnameinfo(sockaddr,
		sockaddrlen,
		address,
		addrlen,
		NULL,
		0,
		NI_NUMERICHOST) != 0) address = NULL;
	return address;
}
/* 打印所有可用信息 */
void ifprint(pcap_if_t* d)
{
	pcap_addr_t* a;
	char ip6str[128];
	/* 设备名(Name) */
	printf("%s\n", d->name);
	/* 设备描述(Description) */
	if (d->description)
		printf("\tDescription: %s\n", d->description);
	/* Loopback Address*/
	printf("\tLoopback: %s\n", (d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");
	/* IP addresses */
	for (a = d->addresses; a; a = a->next) {
		printf("\tAddress Family: #%d\n", a->addr->sa_family);
		switch (a->addr->sa_family)
		{
		case AF_INET:
			printf("\tAddress Family Name: AF_INET\n");
			if (a->addr)
				printf("\tAddress: %s\n", iptos(((struct sockaddr_in*)a->addr)->sin_addr.s_addr));
			if (a->netmask)
				printf("\tNetmask: %s\n", iptos(((struct sockaddr_in*)a->netmask)->sin_addr.s_addr));
			if (a->broadaddr)
				printf("\tBroadcast Address: %s\n", iptos(((struct sockaddr_in*)a->broadaddr)->sin_addr.s_addr));
			if (a->dstaddr)
				printf("\tDestination Address: %s\n", iptos(((struct sockaddr_in*)a->dstaddr)->sin_addr.s_addr));
			break;
		case AF_INET6:
			printf("\tAddress Family Name: AF_INET6\n");
			if (a->addr)
				printf("\tAddress: %s\n", ip6tos(a->addr, ip6str, sizeof(ip6str)));
			break;
		default:
			printf("\tAddress Family Name: Unknown\n");
			break;
		}
	}
	printf("\n");
}




