#include "XMLCoder.h"
#include "XMLBuilder.h"
#include "ParsedPacket.h"
#include <tinyxml.h>
#include <inttypes.h>
#include <linux/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

XMLCoder::XMLCoder(u_char* data, int len, TiXmlElement* xml)
: m_xml_packet(xml)
{
  Parse(data, len);
}

u_int16_t XMLCoder::ParseEth(u_char*& data, int& len)
{
	auto eth = reinterpret_cast<ethhdr*> (data);
	m_xml_packet->LinkEndChild(ToXml(eth));
	data += sizeof(ethhdr);
	len -= sizeof(ethhdr);

	return ntohs(eth->h_proto);
}

u_int16_t XMLCoder::ParseGre(u_char*& data, int& len)
{
	auto gre = reinterpret_cast<gre_hdr*> (data);
	m_xml_packet->LinkEndChild(ToXml(gre));
	int grelen = sizeof(gre_hdr) + gre->check_presented * 4 + gre->key_presented * 4 + gre->seq_presented * 4;
	if (u_int(len) <= grelen)
		return ProtoEnd;
	data += grelen;
	len -= grelen;

	return ntohs(gre->next_proto);
}

u_int16_t XMLCoder::ParseARP(u_char*& data, int& len)
{
	auto arp = reinterpret_cast<arpheader*> (data);
	m_xml_packet->LinkEndChild(ToXml(arp));
	data += sizeof(arpheader);
	len -= sizeof(arpheader);
	return (len <= 0) ? ProtoEnd : ProtoData;
}

u_int16_t XMLCoder::ParseMPLS(u_char*& data, int& len)
{
	auto  mpls = reinterpret_cast<mpls_hdr*>(data);
	m_xml_packet->LinkEndChild(ToXml(mpls));
	data += sizeof(mpls_hdr);
	len -= sizeof(mpls_hdr);
	if (mpls->stack_bottom() == 0)
		return ETH_P_MPLS_UC;
	u_char nxt = data[0] >> 4;
	if (nxt == 4)
		return ETH_P_IP;
	if (nxt == 6)
		return ETH_P_IPV6;
	u_char PW[] = {0,0,0,0}; // Pseudowire Eth Control Word (rfc4448)
	data += sizeof(PW);
	len -= sizeof(PW);
	m_xml_packet->LinkEndChild(ToXml(PW,  sizeof(PW), "PseudowireEthControlWord"));
	return ParseEth(data, len);
}

u_int16_t XMLCoder::Parse8021q(u_char*& data, int& len)
{
	auto vlan = reinterpret_cast<vlanhdr*> (data);
	m_xml_packet->LinkEndChild(ToXml(vlan));
	if (len <= sizeof(vlanhdr))
		return ProtoEnd;
	data += sizeof(vlanhdr);
	len -= sizeof(vlanhdr);
	return ntohs(vlan->nextProto);
}

u_int16_t XMLCoder::ParseIP(u_char*& data, int& len)
{
	auto ip = reinterpret_cast<iphdr*> (data);
	m_xml_packet->LinkEndChild(ToXml(ip));
	int iplen = ip->ihl * 4;
	int totallen = ntohs(ip->tot_len);
	if (len < totallen)
		return ProtoEnd;

	data += iplen;
	len -= iplen;

	return ip->protocol;

}

u_int16_t XMLCoder::ParseICMP(u_char*& data, int& len)
{
	auto icmp = reinterpret_cast<icmphdr*> (data);
	m_xml_packet->LinkEndChild(ToXml(icmp));
	data += sizeof(icmphdr);
	len -= sizeof(icmphdr);
	return ProtoData;
}

u_int16_t XMLCoder::ParseTCP(u_char*& data, int& len)
{
	auto tcp = reinterpret_cast<tcphdr*> (data);
	m_xml_packet->LinkEndChild(ToXml(tcp));
	int tcplen = tcp->doff * 4;
	data += tcplen;
	len -= tcplen;
	return ProtoData;
}

u_int16_t XMLCoder::ParseUDP(u_char*& data, int& len)
{
	auto udp = reinterpret_cast<udphdr*> (data);
	m_xml_packet->LinkEndChild(ToXml(udp));
	data += sizeof(udphdr);
	len -= sizeof(udphdr);
	return ProtoData;
}

u_int16_t XMLCoder::ParseData(u_char*& data, int& len)
{
	m_xml_packet->LinkEndChild(ToXml(data, len, "payload"));
	return ProtoEnd;
}

void XMLCoder::Parse(u_char* data, int len)
{
	u_int16_t proto = ParseEth(data, len);
	while (proto != ProtoEnd) {
		switch (proto) {
			case IPPROTO_IPIP:
			case ETH_P_IP:
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
				proto = ParseData(data, len);
				break;
			default:
				proto = ParseData(data, len);
				return;
		}
	}
}