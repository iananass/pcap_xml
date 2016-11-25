#ifndef PROJECT_XMLBUILDER_H
#define PROJECT_XMLBUILDER_H

#include <sys/types.h>

struct ethhdr;
struct iphdr;
struct tcphdr;
struct udphdr;
struct vlanhdr;
struct mpls_hdr;
struct arpheader;
struct icmphdr;
struct gre_hdr;
class TiXmlElement;

TiXmlElement* ToXml(ethhdr* eth);
TiXmlElement* ToXml(iphdr* ip);
TiXmlElement* ToXml(gre_hdr* gre);
TiXmlElement* ToXml(tcphdr* tcp);
TiXmlElement* ToXml(udphdr* udp);
TiXmlElement* ToXml(vlanhdr* vlan);
TiXmlElement* ToXml(mpls_hdr* mpls);
TiXmlElement* ToXml(arpheader* arp);
TiXmlElement* ToXml(icmphdr* icmp);
TiXmlElement *ToXml(u_char *data, size_t len, const char *header);

#endif //PROJECT_XMLBUILDER_H
