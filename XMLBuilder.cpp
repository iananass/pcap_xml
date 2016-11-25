#include "XMLBuilder.h"
#include "ParsedPacket.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <tinyxml.h>
#include <linux/if_ether.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include <iomanip>
#include <netinet/ip_icmp.h>

static char *ipToString(u_int32_t long_address)
{
    struct in_addr addr;
    addr.s_addr = long_address;
    char *dot_ip = inet_ntoa(addr);
}


static std::string ByteArrayToString(u_char *array, size_t len, const char *delim)
{
    std::stringstream ss;
    ss << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << int(array[0]);
    for (size_t i = 1; i < len; ++i)
        ss << delim << std::hex << std::setw(2) << std::setfill('0') << int(array[i]);
    return ss.str();
}

static std::string MacAddrToString(u_char *mac)
{ return ByteArrayToString(mac, 6, ":"); }

static std::string intToHexString(u_int32_t i)
{ return ByteArrayToString(reinterpret_cast<u_char *>(&i), 4, ""); }

static std::string intToHexString(u_int16_t i)
{ return ByteArrayToString(reinterpret_cast<u_char *>(&i), 2, ""); }

TiXmlElement *ToXml(ethhdr *eth)
{
    TiXmlElement *eXML = new TiXmlElement("Ethernet");
    eXML->SetAttribute("dst", MacAddrToString(eth->h_dest));
    eXML->SetAttribute("src", MacAddrToString(eth->h_source));
    eXML->SetAttribute("proto", ntohs(eth->h_proto));
    return eXML;
}


TiXmlElement *ToXml(iphdr *ip)
{
    TiXmlElement *ipXML = new TiXmlElement("IP");
    ipXML->SetAttribute("header_len", ip->ihl);
    ipXML->SetAttribute("version", ip->version);
    ipXML->SetAttribute("tos", ip->tos);
    ipXML->SetAttribute("tot_len", ntohs(ip->tot_len));
    ipXML->SetAttribute("id", ntohs(ip->id));
    ipXML->SetAttribute("frag_off", ntohs(ip->frag_off));
    ipXML->SetAttribute("ttl", ip->ttl);
    ipXML->SetAttribute("protocol", ip->protocol);
    ipXML->SetAttribute("check", ntohs(ip->check));
    ipXML->SetAttribute("src", ipToString(ip->saddr));
    ipXML->SetAttribute("dst", ipToString(ip->daddr));
    if (ip->ihl > 5)
        ipXML->LinkEndChild(ToXml(reinterpret_cast<u_char *>(ip) + sizeof(iphdr), (ip->ihl - 5) * 4, "options"));
    return ipXML;

}

TiXmlElement *ToXml(tcphdr *tcp)
{
    TiXmlElement *tcpXML = new TiXmlElement("TCP");
    tcpXML->SetAttribute("source", ntohs(tcp->source));
    tcpXML->SetAttribute("dest", ntohs(tcp->dest));
    tcpXML->SetAttribute("seq", intToHexString(tcp->seq));
    tcpXML->SetAttribute("ack_seq", intToHexString(tcp->ack_seq));
    tcpXML->SetAttribute("header_len", tcp->doff);
    tcpXML->SetAttribute("flag_urg", tcp->urg);
    tcpXML->SetAttribute("flag_ack", tcp->ack);
    tcpXML->SetAttribute("flag_psh", tcp->psh);
    tcpXML->SetAttribute("flag_rst", tcp->rst);
    tcpXML->SetAttribute("flag_syn", tcp->syn);
    tcpXML->SetAttribute("flag_fin", tcp->fin);
    tcpXML->SetAttribute("window", ntohs(tcp->window));
    tcpXML->SetAttribute("check", ntohs(tcp->check));
    tcpXML->SetAttribute("urg_ptr", ntohs(tcp->urg_ptr));
    if (tcp->doff > 5)
        tcpXML->LinkEndChild(ToXml(reinterpret_cast<u_char *>(tcp) + sizeof(tcphdr), (tcp->doff - 5) * 4, "options"));

    return tcpXML;
}

TiXmlElement *ToXml(udphdr *udp)
{
    TiXmlElement *udpXML = new TiXmlElement("UDP");
    udpXML->SetAttribute("source", ntohs(udp->source));
    udpXML->SetAttribute("dest", ntohs(udp->dest));
    udpXML->SetAttribute("len", ntohs(udp->len));
    udpXML->SetAttribute("check", ntohs(udp->check));

    return udpXML;
}

TiXmlElement *ToXml(vlanhdr *vlan)
{
    TiXmlElement *vlanXML = new TiXmlElement("VLAN");
    vlanXML->SetAttribute("tci", ntohs(vlan->vlan_tci));
    vlanXML->SetAttribute("next_proto", ntohs(vlan->nextProto));
    return vlanXML;

}

TiXmlElement* ToXml(mpls_hdr* mpls)
{
    TiXmlElement *vlanXML = new TiXmlElement("MPLS");
    vlanXML->SetAttribute("label", mpls->label());
    vlanXML->SetAttribute("experimental", mpls->experimental());
    vlanXML->SetAttribute("stack_bottom", mpls->stack_bottom());
    vlanXML->SetAttribute("ttl", mpls->ttl());
    return vlanXML;
}

TiXmlElement *ToXml(arpheader *arp)
{
    TiXmlElement *arpXML = new TiXmlElement("ARP");
    arpXML->SetAttribute("h_type", ntohs(arp->hd));
    arpXML->SetAttribute("p_type", ntohs(arp->pr));
    arpXML->SetAttribute("h_len", arp->hdl);
    arpXML->SetAttribute("p_len", arp->prl);
    arpXML->SetAttribute("operation", htons(arp->op));
    arpXML->SetAttribute("sha", MacAddrToString(arp->sha));
    arpXML->SetAttribute("spa", ipToString(arp->spa));
    arpXML->SetAttribute("dha", MacAddrToString(arp->dha));
    arpXML->SetAttribute("dpa", ipToString(arp->dpa));
    return arpXML;
}

TiXmlElement *ToXml(icmphdr *icmp)
{
    TiXmlElement *icmpXML = new TiXmlElement("ICMP");
    icmpXML->SetAttribute("type", icmp->type);
    icmpXML->SetAttribute("code", icmp->code);
    icmpXML->SetAttribute("checksum", ntohs(icmp->checksum));
    icmpXML->LinkEndChild(ToXml(reinterpret_cast<u_char *>(&icmp->un), 4, "data"));
    return icmpXML;
}


TiXmlElement *ToXml(u_char *data, size_t len, const char *header)
{
    TiXmlElement *dataXML = new TiXmlElement(header);
    dataXML->SetAttribute("len", len);
    dataXML->SetAttribute("bytes", ByteArrayToString(data, len, " "));
    return dataXML;
}
