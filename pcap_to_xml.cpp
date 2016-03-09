#include <pcap.h>
#include <iostream>
#include <tinyxml.h>
#include "ParsedPacket.h"
#include "XMLBuilder.h"
#include <iostream>
#include <string>

void usage(const char *app)
{
    std::cout << "\t" << app << "  input.cap [output.xml] \n";
    std::cout << "\t" << app << "  -h\n";
}

std::pair<char *, char *> ParseCLI(int argc, char **argv)
{
    if (argc == 2) {
        if (strcmp(argv[1], "-h") == 0) {
            usage(argv[0]);
            exit(0);
        }
        return std::pair<char *, char *>(argv[1], nullptr);
    } else if (argc == 3) {
        return std::pair<char *, char *>(argv[1], argv[2]);
    } else {
        usage(argv[0]);
        exit(1);
    }
}

int main(int argc, char **argv)
{
    std::pair<char *, char *> args = ParseCLI(argc, argv);


    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_open_offline(args.first, errbuf);
    if (!p) {
        std::cerr << "  Open " << args.first << " error: " << errbuf << "\n";
        return 1;
    }

    TiXmlDocument doc;
    TiXmlDeclaration *decl = new TiXmlDeclaration("1.0", "", "");
    doc.LinkEndChild(decl);
    TiXmlElement *root = new TiXmlElement("file");
    root->SetAttribute("name", args.first);
    doc.LinkEndChild(root);

    u_char *data;
    pcap_pkthdr hdr;
    u_int packetIndex = 0;
    while (data = const_cast<u_char *>(pcap_next(p, &hdr))) {
        ParsedPacket pp(data, hdr.caplen);
        TiXmlElement *packet = new TiXmlElement(std::string("Packet"));

        packet->LinkEndChild( new TiXmlComment((std::string("number ") + std::to_string(packetIndex++) ).c_str()) );
        packet->LinkEndChild( new TiXmlComment((std::string("len=") + std::to_string(hdr.caplen) ).c_str()) );

        packet->SetAttribute("ts_sec", hdr.ts.tv_sec);
        packet->SetAttribute("ts_usec", hdr.ts.tv_usec);
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
            packet->LinkEndChild(ToXml(pp.Data(), pp.DataLen(), "payload"));
    }
    if (!args.second)
        doc.Print(stdout);
    else
        doc.SaveFile(args.second);
}