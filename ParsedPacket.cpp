#include "ParsedPacket.h"
#include <inttypes.h>
#include <linux/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

struct mpls_hdr
{
	u_int32_t hdr;
} __attribute__((__packed__));

struct gre_hdr
{
	u_int8_t check_presented : 1;
	u_int8_t foo_1 : 1;
	u_int8_t key_presented : 1;
	u_int8_t seq_presented : 1;
	u_int8_t foo_2 : 4;
	u_int8_t foo_3;
	u_int16_t next_proto;

} __attribute__((__packed__));

u_int16_t ParsedPacket::ParseEth(u_char*& data, int& len)
{
	m_eth = reinterpret_cast<ethhdr*> (data);
	if (len <= ethStandardLen)
		return ProtoEnd;
	data += ethStandardLen;
	len -= ethStandardLen;

	return ntohs(m_eth->h_proto);
}

u_int16_t ParsedPacket::ParseGre(u_char*& data, int& len)
{
	gre_hdr* gre = reinterpret_cast<gre_hdr*> (data);
	if (u_int(len) <= sizeof(gre_hdr))
		return ProtoEnd;
	data += sizeof(gre_hdr) + gre->check_presented * 4 + gre->key_presented * 4 + gre->seq_presented * 4;
	len -= sizeof(gre_hdr) + gre->check_presented * 4 + gre->key_presented * 4 + gre->seq_presented * 4;

	return ntohs(gre->next_proto);
}

u_int16_t ParsedPacket::ParseARP(u_char*& data, int& len)
{
	m_arp = reinterpret_cast<arpheader*> (data);
	data += sizeof(arpheader);
	len -= sizeof(arpheader);
	return (len <= 0) ? ProtoEnd : ProtoData;
}

u_int16_t ParsedPacket::ParseMPLS(u_char*& data, int& len)
{
	data += mplsStandardLen;
	len -= mplsStandardLen;
	return ETH_P_IP;
}

u_int16_t ParsedPacket::Parse8021q(u_char*& data, int& len)
{
	vlanhdr* vlan = reinterpret_cast<vlanhdr*> (data);
	if (len <= vlanStandardLen)
		return ProtoEnd;
	vlanList.push_back(vlan);
	data += vlanStandardLen;
	len -= vlanStandardLen;
	return ntohs(vlan->nextProto);
}

u_int16_t ParsedPacket::ParseIP(u_char*& data, int& len)
{
	m_ip = reinterpret_cast<iphdr*> (data);
	int iplen = m_ip->ihl * 4;
	int totallen = ntohs(m_ip->tot_len);
	if (len < totallen)
		return ProtoEnd;

	data += iplen;
	len -= iplen;

	return m_ip->protocol;

}

u_int16_t ParsedPacket::ParseICMP(u_char*& data, int& len)
{
	m_icmp = reinterpret_cast<icmphdr*> (data);
	data += sizeof(icmphdr);
	len -= sizeof(icmphdr);
	return ProtoData;
}

u_int16_t ParsedPacket::ParseTCP(u_char*& data, int& len)
{
	m_tcp = reinterpret_cast<tcphdr*> (data);
	int tcplen = m_tcp->doff * 4;
	data += tcplen;
	len -= tcplen;
	return ProtoData;
}

u_int16_t ParsedPacket::ParseUDP(u_char*& data, int& len)
{
	m_udp = reinterpret_cast<udphdr*> (data);
	data += udpStandardLen;
	len -= udpStandardLen;
	return ProtoData;
}

u_int16_t ParsedPacket::ParseData(u_char*& data, int& len)
{
	m_datasize = len;
	return ProtoEnd;
}

void ParsedPacket::Parse(u_char* data, int len)
{
	m_packetBegin = data;
	int originalLen = len;
	u_int16_t proto = ParseEth(data, len);
	while (proto != ProtoEnd) {
		switch (proto) {
			case IPPROTO_IPIP:
			case ETH_P_IP:
				m_ipoffset = originalLen - len;
				proto = ParseIP(data, len);
				break;
			case ETH_P_ARP:
				proto = ParseARP(data, len);
				break;
			case ETH_P_8021Q:
				proto = Parse8021q(data, len);
				break;
			case ETH_P_MPLS_MC:
			case ETH_P_MPLS_UC:
				proto = ParseMPLS(data, len);
				break;
			case IPPROTO_GRE:
				proto = ParseGre(data, len);
				break;
			case IPPROTO_ICMP:
				proto = ParseICMP(data, len);
				break;
			case IPPROTO_TCP:
				proto = ParseTCP(data, len);
				break;
			case IPPROTO_UDP:
				proto = ParseUDP(data, len);
				break;
			case ProtoData:
				m_payload = data;
				m_dataoffset = originalLen - len;
				proto = ParseData(data, len);
				break;
			default:
				m_payload = data;
				m_dataoffset = originalLen - len;
				proto = ParseData(data, len);
				return;
		}
	}
}

ParsedPacket::ParsedPacket(u_char* data, int len)
	: m_packetBegin(0)
	  , m_payload(0)
	  , m_eth(0)
	  , m_ip(0)
	  , m_tcp(0)
	  , m_udp(0)
	  , m_arp(0)
	  , m_icmp(0)
	  , m_ipoffset(0)
	  , m_dataoffset(0)
	  , m_datasize(0)
{
	Parse(data, len);
}

u_int16_t ParsedPacket::ComputeIPChecksum(u_int8_t* data, int len)
{
	u_int32_t sum = 0; /* assume 32 bit long, 16 bit short */
	u_int16_t* temp = (u_int16_t*) data;

	while (len > 1) {
		sum += *temp++;
		if (sum & 0x80000000) /* if high order bit set, fold */
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}

	if (len) /* take care of left over byte */
		sum += (u_int16_t) * ((u_int8_t*) temp);

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return ~sum;
}

u_int16_t ParsedPacket::ComputeTCPChecksum(u_int8_t* data, size_t len, u_int32_t src_addr, u_int32_t dest_addr)
{
	uint16_t* buf = (uint16_t*) data;
	uint16_t* ip_src = (uint16_t * ) & src_addr, * ip_dst = (uint16_t * ) & dest_addr;
	uint32_t sum;
	size_t length = len;

	// Calculate the sum
	sum = 0;
	while (len > 1) {
		sum += *buf++;
		if (sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}

	if (len & 1)
		// Add the padding if the packet lenght is odd
		sum += *((uint8_t*) buf);

	// Add the pseudo-header
	sum += *(ip_src++);
	sum += *ip_src;
	sum += *(ip_dst++);
	sum += *ip_dst;
	sum += htons(IPPROTO_TCP);
	sum += htons(length);

	// Add the carries
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	// Return the one's complement of sum
	return ((uint16_t)(~sum));
}

void ParsedPacket::RecalcCRC()
{
	m_ip->check = 0;
	m_ip->check = ComputeIPChecksum((u_int8_t*) m_ip, (m_ip->ihl) * 4);
}

int ParsedPacket::DataLen() const
{
	return m_datasize;
};

int ParsedPacket::IpOffset() const
{
	return m_ipoffset;
}

int ParsedPacket::DataOffset() const
{
	return m_dataoffset;
}

