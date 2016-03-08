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
    ipXML->SetAttribute("ihl", ip->ihl);
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
    return ipXML;

}

TiXmlElement *ToXml(tcphdr *tcp)
{
    TiXmlElement *tcpXML = new TiXmlElement("TCP");
    tcpXML->SetAttribute("source", ntohs(tcp->source));
    tcpXML->SetAttribute("dest", ntohs(tcp->dest));
    tcpXML->SetAttribute("seq", intToHexString(tcp->seq));
    tcpXML->SetAttribute("ack_seq", intToHexString(tcp->ack_seq));
    tcpXML->SetAttribute("dataoffset", tcp->doff);
    tcpXML->SetAttribute("flag_urg", tcp->urg);
    tcpXML->SetAttribute("flag_ack", tcp->ack);
    tcpXML->SetAttribute("flag_psh", tcp->psh);
    tcpXML->SetAttribute("flag_rst", tcp->rst);
    tcpXML->SetAttribute("flag_syn", tcp->syn);
    tcpXML->SetAttribute("flag_fin", tcp->fin);
    tcpXML->SetAttribute("window", ntohs(tcp->window));
    tcpXML->SetAttribute("check", ntohs(tcp->check));
    tcpXML->SetAttribute("urg_ptr", ntohs(tcp->urg_ptr));
    return tcpXML;
}

TiXmlElement *ToXml(udphdr *udp)
{
    TiXmlElement *udpXML = new TiXmlElement("UDP");
    udpXML->SetAttribute("source", udp->source);
    udpXML->SetAttribute("dest", udp->dest);
    udpXML->SetAttribute("len", udp->len);
    udpXML->SetAttribute("check", udp->check);

    return udpXML;
}

TiXmlElement* ToXml(vlanhdr* vlan)
{
    TiXmlElement *vlanXML = new TiXmlElement("VLAN");
    vlanXML->SetAttribute("tci",ntohs(vlan->vlan_tci));
    vlanXML->SetAttribute("next_proto", ntohs(vlan->nextProto));
    return vlanXML;

}