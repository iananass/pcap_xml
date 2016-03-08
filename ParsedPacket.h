#ifndef RANAP_PROBE_PARSEDPACKET_H
#define RANAP_PROBE_PARSEDPACKET_H

struct ethhdr;
struct tcphdr;
struct udphdr;
struct iphdr;
struct icmphdr;

#include <vector>
#include <sys/types.h>

struct vlanhdr
{

	union
	{
		u_int16_t vlan_tci;

		struct
		{
			u_int16_t vid : 12;
			u_int16_t dei : 1;
			u_int16_t pcp : 3;
		} tci_detailed;
	};
	u_int16_t nextProto;
} __attribute__((__packed__));

struct arpheader
{
	u_int16_t hd;
	u_int16_t pr;
	u_int8_t hdl;
	u_int8_t prl;
	u_int16_t op;
	u_int8_t sha[6];
	u_int32_t spa;
	u_int8_t dha[6];
	u_int32_t dpa;
} __attribute__((packed));
struct Packet;

class ParsedPacket
{
public:

	enum
	{
		ethStandardLen = 14,
		mplsStandardLen = 4,
		vlanStandardLen = 4,
		IpStandardLen = 20,
		tcpStandardLen = 20,
		udpStandardLen = 8,
		ProtoTCP = 6,
		ProtoUDP = 17,
		ProtoData = 0,
		ProtoEnd = 0xffff
	};

	ParsedPacket(u_char* data, int len);

	const std::vector<vlanhdr*>& VlanList()
	{
		return vlanList;
	}

	ethhdr* Eth()
	{
		return m_eth;
	}

	iphdr* IP()
	{
		return m_ip;
	}

	tcphdr* Tcp()
	{
		return m_tcp;
	}

	udphdr* Udp()
	{
		return m_udp;
	}

	arpheader* Arp()
	{
		return m_arp;
	}

	icmphdr* Icmp()
	{
		return m_icmp;
	}

	u_char* Data()
	{
		return m_payload;
	}

	int DataLen() const;
	int IpOffset() const;
	int TransportOffset() const;
	int DataOffset() const;

	void RecalcCRC();
	static u_int16_t ComputeIPChecksum(u_int8_t* data, int len);
	static u_int16_t ComputeTCPChecksum(u_int8_t* data, size_t len, u_int32_t src_addr, u_int32_t dest_addr);
private:
	u_char* m_packetBegin;
	u_char* m_payload;
	ethhdr* m_eth;
	iphdr* m_ip;
	tcphdr* m_tcp;
	udphdr* m_udp;
	arpheader* m_arp;
	icmphdr* m_icmp;
	std::vector<vlanhdr*> vlanList;
	int m_ipoffset;
	int m_dataoffset;
	int m_datasize;

	void Parse(u_char* data, int len);
	u_int16_t ParseEth(u_char*& data, int& len);
	u_int16_t ParseGre(u_char*& data, int& len);
	u_int16_t ParseARP(u_char*& data, int& len);
	u_int16_t ParseMPLS(u_char*& data, int& len);
	u_int16_t Parse8021q(u_char*& data, int& len);
	u_int16_t ParseIP(u_char*& data, int& len);
	u_int16_t ParseTCP(u_char*& data, int& len);
	u_int16_t ParseUDP(u_char*& data, int& len);
	u_int16_t ParseICMP(u_char*& data, int& len);
	u_int16_t ParseData(u_char*& data, int& len);
};

#endif //RANAP_PROBE_PARSEDPACKET_H
