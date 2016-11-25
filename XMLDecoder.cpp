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
    return true;
}

#define SwapUINT32(X) X = htonl(X)
#define SwapUINT16(X) X = htons(X)


int DecodeEthernet(TiXmlElement *ethXML, u_char *data)
{
    std::string src, dst;
    int proto;
    ethhdr *eth = reinterpret_cast<ethhdr *>(data);
    if (ethXML->QueryStringAttribute("dst", &dst) != TIXML_SUCCESS
        || ethXML->QueryStringAttribute("src", &src) != TIXML_SUCCESS
        || ethXML->QueryIntAttribute("proto", &proto) != TIXML_SUCCESS
        || !MacStrToArray(src.c_str(), eth->h_source)
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
    SwapUINT16(ip->tot_len);
    SwapUINT16(ip->id);
    SwapUINT16(ip->frag_off);
    SwapUINT16(ip->check);

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
{
    vlanhdr *vlan = reinterpret_cast<vlanhdr *> (data);
    if (xml->QueryValueAttribute("tci", &vlan->vlan_tci) != TIXML_SUCCESS
        || xml->QueryValueAttribute("next_proto", &vlan->nextProto) != TIXML_SUCCESS) {
        std::cerr << "VLAN hdr parse error\n";
        return -1;
    }
    SwapUINT16(vlan->vlan_tci);
    SwapUINT16(vlan->nextProto);
    return sizeof(vlanhdr);
}

int DecodeMPLS(TiXmlElement *xml, u_char *data)
{
    u_int32_t label;
    u_int16_t experimental;
    u_int16_t stack_bottom;
    u_int16_t ttl;

    if (xml->QueryValueAttribute("label", &label) != TIXML_SUCCESS
        || xml->QueryValueAttribute("experimental", &experimental) != TIXML_SUCCESS
        || xml->QueryValueAttribute("stack_bottom", &stack_bottom) != TIXML_SUCCESS
        || xml->QueryValueAttribute("ttl", &ttl) != TIXML_SUCCESS) {
        std::cerr << "MPLS hdr parse error\n";
        return -1;
    }

    mpls_hdr *mpls = reinterpret_cast<mpls_hdr *> (data);
    mpls->label(label);
    mpls->experimental(experimental);
    mpls->stack_bottom(stack_bottom);
    mpls->ttl(ttl);

    return sizeof(mpls_hdr);
}

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

    SwapUINT16(tcp->source);
    SwapUINT16(tcp->dest);
    SwapUINT32(tcp->seq);
    SwapUINT32(tcp->ack_seq);
    SwapUINT16(tcp->window);
    SwapUINT16(tcp->check);
    SwapUINT16(tcp->urg_ptr);
    tcp->doff = doff;
    tcp->fin = fin;
    tcp->syn = syn;
    tcp->rst = rst;
    tcp->psh = psh;
    tcp->ack = ack;
    tcp->urg = urg;
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
{
    udphdr *udp = reinterpret_cast<udphdr *>(data);
    if (xml->QueryValueAttribute("source", &udp->source) != TIXML_SUCCESS
        || xml->QueryValueAttribute("dest", &udp->dest) != TIXML_SUCCESS
        || xml->QueryValueAttribute("check", &udp->check) != TIXML_SUCCESS
        || xml->QueryValueAttribute("len", &udp->len) != TIXML_SUCCESS) {
        std::cerr << "UDP hdr parse error\n";
        return -1;
    }
    SwapUINT16(udp->source);
    SwapUINT16(udp->dest);
    SwapUINT16(udp->check);
    SwapUINT16(udp->len);

    return sizeof(udphdr);
}

int DecodeARP(TiXmlElement *xml, u_char *data)
{
    arpheader *arp = reinterpret_cast<arpheader *>(data);
    std::string sha, dha, spa, dpa;
    int hdl, prl;
    if (xml->QueryValueAttribute("h_type", &arp->hd) != TIXML_SUCCESS
        || xml->QueryValueAttribute("p_type", &arp->pr) != TIXML_SUCCESS
        || xml->QueryValueAttribute("h_len", &hdl) != TIXML_SUCCESS
        || xml->QueryValueAttribute("p_len", &prl) != TIXML_SUCCESS
        || xml->QueryValueAttribute("operation", &arp->op) != TIXML_SUCCESS
        || xml->QueryValueAttribute("spa", &spa) != TIXML_SUCCESS
        || xml->QueryValueAttribute("dpa", &dpa) != TIXML_SUCCESS
        || xml->QueryValueAttribute("sha", &sha) != TIXML_SUCCESS
        || xml->QueryValueAttribute("dha", &dha) != TIXML_SUCCESS
        || !MacStrToArray(sha.c_str(), arp->sha)
        || !MacStrToArray(dha.c_str(), arp->dha)) {
        std::cerr << "ARP header parse error\n";
        return -1;
    }
    arp->hdl = hdl;
    arp->prl = prl;
    SwapUINT16(arp->hd);
    SwapUINT16(arp->pr);
    SwapUINT16(arp->op);
    arp->spa = inet_addr(spa.c_str());
    arp->dpa = inet_addr(dpa.c_str());
    return sizeof(arpheader);
}

int DecodeICMP(TiXmlElement *xml, u_char *data)
{
    icmphdr *icmp = reinterpret_cast<icmphdr *>(data);
    int type, code;
    if (xml->QueryIntAttribute("type", &type) != TIXML_SUCCESS
        || xml->QueryValueAttribute("code", &code) != TIXML_SUCCESS
        || xml->QueryValueAttribute("checksum", &icmp->checksum) != TIXML_SUCCESS
        || !xml->FirstChild()
        || DecodeData(xml->FirstChild()->ToElement(), reinterpret_cast<u_char *>(&icmp->un)) == -1) {
        std::cerr << "ICMP parse error\n";
        return -1;
    }
    icmp->type = type;
    icmp->code = code;
    SwapUINT16(icmp->checksum);
    return sizeof(icmphdr);
}

void ParsePacket(TiXmlElement *pack, Dumper &dumper)
{
    int len = 0;
    int sec;
    int usec;
    if (pack->QueryIntAttribute("ts_sec", &sec) != TIXML_SUCCESS
        || pack->QueryIntAttribute("ts_usec", &usec) != TIXML_SUCCESS) {
        std::cerr << "Packet parse error\n";
        return;
    }

    u_char packet[4096];
    u_char *data = packet;

    for (auto layer = pack->FirstChild(); layer; layer = layer->NextSibling()) {
        if (layer->Type() != TiXmlNode::TINYXML_ELEMENT)
            continue;
        std::string layerName(layer->Value());
        int parse = -1;
        if (layerName == "Ethernet") { parse = DecodeEthernet(layer->ToElement(), data); }
        else if (layerName == "VLAN") { parse = DecodeVLAN(layer->ToElement(), data); }
        else if (layerName == "MPLS") { parse = DecodeMPLS(layer->ToElement(), data); }
        else if (layerName == "IP") { parse = DecodeIP(layer->ToElement(), data); }
        else if (layerName == "TCP") { parse = DecodeTCP(layer->ToElement(), data); }
        else if (layerName == "UDP") { parse = DecodeUDP(layer->ToElement(), data); }
        else if (layerName == "ARP") { parse = DecodeARP(layer->ToElement(), data); }
        else if (layerName == "ICMP") { parse = DecodeICMP(layer->ToElement(), data); }
        else if (layerName == "payload") { parse = DecodeData(layer->ToElement(), data); }
        else std::cerr << "Unknown layer: " << layerName << "\n";
        if (parse == -1) {
            std::cerr << "Parse Error\n";
            return;
        }
        data += parse;
        len += parse;
    }

    dumper.DumpPacket(packet, len, sec, usec);
}
