#include <pcap.h>
#include <iostream>
#include <tinyxml.h>
#include "ParsedPacket.h"
#include "XMLBuilder.h"
#include <iostream>
#include <string>


int main(int argc, char **argv)
{
    const char *filename;
    if (argc == 1) filename = "dump.cap";
    else filename = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_open_offline(filename, errbuf);
    if (!p) {
        std::cerr << "  Open " << filename << " error: " << errbuf << "\n";
        return 1;
    }

    TiXmlDocument doc;
    TiXmlDeclaration *decl = new TiXmlDeclaration("1.0", "", "");
    doc.LinkEndChild(decl);
    TiXmlElement *root = new TiXmlElement("file");
    root->SetAttribute("name", filename);
    doc.LinkEndChild(root);

    u_char *data;
    pcap_pkthdr hdr;
    u_int packetIndex = 0;
    while (data = const_cast<u_char *>(pcap_next(p, &hdr))) {
        ParsedPacket pp(data, hdr.caplen);
        TiXmlElement *packet = new TiXmlElement(std::string("Packet"));
        packet->SetAttribute("len", hdr.caplen);
        packet->SetAttribute("ts_sec", hdr.ts.tv_sec);
        packet->SetAttribute("ts_usec", hdr.ts.tv_usec);
        packet->SetAttribute("number", packetIndex++);
        root->LinkEndChild(packet);
        if (pp.Eth())
            packet->LinkEndChild(ToXml(pp.Eth()));
        for (auto vlan : pp.VlanList())
            packet->LinkEndChild(ToXml(vlan));
        if (pp.Arp())
            packet->LinkEndChild(ToXml(pp.Arp()));
        if (pp.IP())
            packet->LinkEndChild(ToXml(pp.IP()));
        if (pp.Icmp())
            packet->LinkEndChild(ToXml(pp.Icmp()));
        if (pp.Tcp())
            packet->LinkEndChild(ToXml(pp.Tcp()));
        if (pp.Udp())
            packet->LinkEndChild(ToXml(pp.Udp()));
        if (pp.DataLen())
            packet->LinkEndChild(ToXml(pp.Data(), pp.DataLen()));
    }
    doc.Print(stdout);
}