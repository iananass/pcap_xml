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


bool MacStrToArray(const char *macStr, u_char *macArray)
{
    int values[6];

    if (6 == sscanf(macStr, "%x:%x:%x:%x:%x:%x",
                    &values[0], &values[1], &values[2],
                    &values[3], &values[4], &values[5])) {
        /* convert to uint8_t */
        for (int i = 0; i < 6; ++i) {
            macArray[i] = (uint8_t) values[i];
            std::cout << std::hex << int(macArray[i]) << ":";
        }
    } else
        return false;
    std::cout << std::endl;
    return true;
}

void DecodeEthernet(TiXmlElement *ethXML, u_char *data)
{
    std::string src, dst;
    int proto;
    if (ethXML->QueryStringAttribute("dst", &dst) != TIXML_SUCCESS
        || ethXML->QueryStringAttribute("src", &src) != TIXML_SUCCESS
        || ethXML->QueryIntAttribute("proto", &proto) != TIXML_SUCCESS) {
        std::cerr << "Eth hdr parse error\n";
        return;
    }
    ethhdr *eth = reinterpret_cast<ethhdr *>(data);
    if (!MacStrToArray(src.c_str(), eth->h_source)
        || !MacStrToArray(dst.c_str(), eth->h_dest)) {
        std::cerr << "Eth hdr parse error\n";
        return;
    }
    eth->h_proto = htons(proto);

}


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

    u_char data[len];

    for (auto layer = pack->FirstChild(); layer; layer = layer->NextSibling()) {
        std::string layerName(layer->Value());
        if (layerName == "Ethernet") DecodeEthernet(layer->ToElement(), data);
    }

    dumper.DumpPacket(data, len, sec, usec);
}
