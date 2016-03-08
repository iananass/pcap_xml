#ifndef PROJECT_XMLBUILDER_H
#define PROJECT_XMLBUILDER_H


struct ethhdr;
struct iphdr;
struct tcphdr;
struct udphdr;
struct vlanhdr;
class TiXmlElement;

TiXmlElement* ToXml(ethhdr* eth);
TiXmlElement* ToXml(iphdr* ip);
TiXmlElement* ToXml(tcphdr* tcp);
TiXmlElement* ToXml(udphdr* udp);
TiXmlElement* ToXml(vlanhdr* vlan);

#endif //PROJECT_XMLBUILDER_H
