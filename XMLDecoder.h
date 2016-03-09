#ifndef PROJECT_XMLDECODER_H
#define PROJECT_XMLDECODER_H


struct TiXmlElement;
class Dumper;

void ParsePacket(TiXmlElement* pack, Dumper& dumper);

#endif //PROJECT_XMLDECODER_H
