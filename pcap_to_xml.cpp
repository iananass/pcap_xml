#include <pcap.h>
#include <iostream>
#include <tinyxml.h>
#include "ParsedPacket.h"
#include "XMLBuilder.h"
#include <iostream>
#include <string>


int main(int argc, char **argv)
{
    const char *filename = "dump.cap";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_open_offline(filename, errbuf);
    if (!p) {
        std::cerr << "  Open " << filename << " error: " << errbuf << "\n";
        return 1;
    }

    TiXmlDocument doc;
    TiXmlDeclaration *decl = new TiXmlDeclaration("1.0", "", "");
    doc.LinkEndChild(decl);
    TiXmlElement *root = new TiXmlElement(filename);
    doc.LinkEndChild(root);

    u_char *data;
    pcap_pkthdr hdr;
    u_int packetIndex = 0;
    while (data = const_cast<u_char *>(pcap_next(p, &hdr))) {
        ParsedPacket pp(data, hdr.caplen);
        TiXmlElement *packet = new TiXmlElement(std::string("Packet"));
        packet->SetAttribute("number", packetIndex++);
        root->LinkEndChild(packet);
        if (pp.Eth())
            packet->LinkEndChild(ToXml(pp.Eth()));
        if (pp.IP())
            packet->LinkEndChild(ToXml(pp.IP()));
        if (pp.Tcp())
            packet->LinkEndChild(ToXml(pp.Tcp()));
        if (pp.Udp())
            packet->LinkEndChild(ToXml(pp.Udp()));
    }
    doc.Print(stdout);
}