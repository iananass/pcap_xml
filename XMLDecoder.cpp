#include "XMLDecoder.h"
#include "Dumper.h"
#include <tinyxml.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <tinyxml.h>
#include <linux/if_ether.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include "ParsedPacket.h"

bool MacStrToArray(const char *macStr, u_char *macArray)
{
    int values[6];

    if (6 == sscanf(macStr, "%x:%x:%x:%x:%x:%x",
                    &values[0], &values[1], &values[2],
                    &values[3], &values[4], &values[5])) {
        /* convert to uint8_t */
        for (int i = 0; i < 6; ++i)
            macArray[i] = (uint8_t) values[i];
    } else
        return false;
    std::cout << std::endl;
    return true;
}

int DecodeEthernet(TiXmlElement *ethXML, u_char *data)
{
    std::string src, dst;
    int proto;
    if (ethXML->QueryStringAttribute("dst", &dst) != TIXML_SUCCESS
        || ethXML->QueryStringAttribute("src", &src) != TIXML_SUCCESS
        || ethXML->QueryIntAttribute("proto", &proto) != TIXML_SUCCESS) {
        std::cerr << "Eth hdr parse error\n";
        return -1;
    }
    ethhdr *eth = reinterpret_cast<ethhdr *>(data);
    if (!MacStrToArray(src.c_str(), eth->h_source)
        || !MacStrToArray(dst.c_str(), eth->h_dest)) {
        std::cerr << "Eth hdr parse error\n";
        return -1;
    }
    eth->h_proto = htons(proto);
    return sizeof(ethhdr);
}

int DecodeData(TiXmlElement *elem, u_char *data)
{
    int len;
    std::string bytes;
    if (elem->QueryIntAttribute("len", &len) != TIXML_SUCCESS
        || elem->QueryStringAttribute("bytes", &bytes) != TIXML_SUCCESS) {
        std::cerr << "Byte Array parse error\n";
        return -1;
    }
    std::stringstream ss(bytes);
    for (int i = 0; i < len; ++i) {
        int tmp;
        ss >> std::hex >> tmp;
        data[i] = tmp;
    }
    return len;
}

int DecodeOptions(TiXmlElement *elem, u_char *data)
{
    TiXmlNode *opt = elem->FirstChild();
    if (!opt) {
        std::cerr << "Options parse error\n";
        return -1;
    }
    return DecodeData(opt->ToElement(), data);

}

int DecodeIP(TiXmlElement *xml, u_char *data)
{
    iphdr *ip = reinterpret_cast<iphdr *>(data);
    std::string saddr, daddr;
    int tos, ttl, protocol, ihl, version;
    if (xml->QueryValueAttribute("header_len", &ihl) != TIXML_SUCCESS
        || xml->QueryValueAttribute("version", &version) != TIXML_SUCCESS
        || xml->QueryIntAttribute("tos", &tos) != TIXML_SUCCESS
        || xml->QueryValueAttribute("tot_len", &ip->tot_len) != TIXML_SUCCESS
        || xml->QueryValueAttribute("id", &ip->id) != TIXML_SUCCESS
        || xml->QueryValueAttribute("frag_off", &ip->frag_off) != TIXML_SUCCESS
        || xml->QueryIntAttribute("ttl", &ttl) != TIXML_SUCCESS
        || xml->QueryIntAttribute("protocol", &protocol) != TIXML_SUCCESS
        || xml->QueryValueAttribute("check", &ip->check) != TIXML_SUCCESS
        || xml->QueryStringAttribute("src", &saddr) != TIXML_SUCCESS
        || xml->QueryStringAttribute("dst", &daddr) != TIXML_SUCCESS) {
        std::cerr << "IP hdr parse error\n";
        return -1;
    }
    ip->ihl = ihl;
    ip->version = version;
    ip->tos = tos;
    ip->ttl = ttl;
    ip->protocol = protocol;
    ip->saddr = inet_addr(saddr.c_str());
    ip->daddr = inet_addr(daddr.c_str());
    ip->tot_len = htons(ip->tot_len);
    ip->id = htons(ip->id);
    ip->frag_off = htons(ip->frag_off);
    ip->check = htons(ip->check);

    // check options
    if (ihl > 5) {
        if (DecodeOptions(xml, data + sizeof(iphdr)) == -1) {
            std::cerr << "IP Options error\n";
            return -1;
        }
    }

    return ihl * 4;
}

int DecodeVLAN(TiXmlElement *xml, u_char *data)
{ return sizeof(vlanhdr); }

//<TCP source="59260" dest="80" seq="9498EF24" ack_seq="00000000" header_len="10"
// flag_urg="0" flag_ack="0" flag_psh="0" flag_rst="0" flag_syn="1" flag_fin="0" window="29200" check="19820" urg_ptr="0">
int DecodeTCP(TiXmlElement *xml, u_char *data)
{
    tcphdr *tcp = reinterpret_cast<tcphdr *>(data);
    int syn, fin, rst, psh, ack, urg, doff;
    std::string seq, ack_seq;

    if (xml->QueryValueAttribute("source", &tcp->source) != TIXML_SUCCESS
        || xml->QueryValueAttribute("dest", &tcp->dest) != TIXML_SUCCESS
        || xml->QueryValueAttribute("seq", &seq) != TIXML_SUCCESS
        || xml->QueryValueAttribute("ack_seq", &ack_seq) != TIXML_SUCCESS
        || xml->QueryValueAttribute("header_len", &doff) != TIXML_SUCCESS
        || xml->QueryValueAttribute("flag_fin", &fin) != TIXML_SUCCESS
        || xml->QueryValueAttribute("flag_syn", &syn) != TIXML_SUCCESS
        || xml->QueryValueAttribute("flag_rst", &rst) != TIXML_SUCCESS
        || xml->QueryValueAttribute("flag_psh", &psh) != TIXML_SUCCESS
        || xml->QueryValueAttribute("flag_ack", &ack) != TIXML_SUCCESS
        || xml->QueryValueAttribute("flag_urg", &urg) != TIXML_SUCCESS
        || xml->QueryValueAttribute("window", &tcp->window) != TIXML_SUCCESS
        || xml->QueryValueAttribute("check", &tcp->check) != TIXML_SUCCESS
        || xml->QueryValueAttribute("urg_ptr", &tcp->urg_ptr) != TIXML_SUCCESS) {
        std::cerr << "TCP hdr parse error\n";
        return -1;
    }

    std::stringstream seq_stream(seq);
    seq_stream >> std::hex >> tcp->seq;
    std::stringstream ack_stream(ack_seq);
    ack_stream >> std::hex >> tcp->ack_seq;

    tcp->source = htons(tcp->source);
    tcp->dest = htons(tcp->dest);
    tcp->seq = htonl(tcp->seq);
    tcp->ack_seq = htonl(tcp->ack_seq);
    tcp->doff = doff;
    tcp->fin = fin;
    tcp->syn = syn;
    tcp->rst = rst;
    tcp->psh = psh;
    tcp->ack = ack;
    tcp->urg = urg;
    tcp->window = htons(tcp->window);
    tcp->check = htons(tcp->check);
    tcp->urg_ptr = htons(tcp->urg_ptr);
    // check options
    if (doff > 5) {
        if (DecodeOptions(xml, data + sizeof(tcphdr)) == -1) {
            std::cerr << "TCP Options error\n";
            return -1;
        }
    }

    return doff * 4;
}

int DecodeUDP(TiXmlElement *xml, u_char *data)
{ return sizeof(udphdr); }

int DecodeARP(TiXmlElement *xml, u_char *data)
{ return sizeof(arpheader); }

int DecodeICMP(TiXmlElement *xml, u_char *data)
{ return sizeof(icmphdr); }

void ParsePacket(TiXmlElement *pack, Dumper &dumper)
{
    std::cout << " --- packet ---\n";
    int len;
    int sec;
    int usec;
    if (pack->QueryIntAttribute("len", &len) != TIXML_SUCCESS
        || pack->QueryIntAttribute("ts_sec", &sec) != TIXML_SUCCESS
        || pack->QueryIntAttribute("ts_usec", &usec) != TIXML_SUCCESS) {
        std::cerr << "Packet parse error\n";
        return;
    }

    u_char packet[len];
    u_char *data = packet;

    for (auto layer = pack->FirstChild(); layer; layer = layer->NextSibling()) {
        std::string layerName(layer->Value());
        int parse = -1;
        if (layerName == "Ethernet") { parse = DecodeEthernet(layer->ToElement(), data); }
        else if (layerName == "VLAN") { parse = DecodeVLAN(layer->ToElement(), data); }
        else if (layerName == "IP") { parse = DecodeIP(layer->ToElement(), data); }
        else if (layerName == "TCP") { parse = DecodeTCP(layer->ToElement(), data); }
        else if (layerName == "UDP") { parse = DecodeUDP(layer->ToElement(), data); }
        else if (layerName == "ARP") { parse = DecodeARP(layer->ToElement(), data); }
        else if (layerName == "ICMP") { parse = DecodeICMP(layer->ToElement(), data); }
        else if (layerName == "payload") { parse = DecodeData(layer->ToElement(), data); }
        else std::cout << "Unknown layer: " << layerName << "\n";
        if (parse == -1) {
            std::cerr << "Parse Error\n";
            return;
        }
        data += parse;
    }

    dumper.DumpPacket(packet, len, sec, usec);
}
