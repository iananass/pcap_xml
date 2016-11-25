#ifndef __XML_CODER__H__
#define __XML_CODER__H__

#include <sys/types.h>

struct TiXmlElement;

class XMLCoder
{
public:

	enum
	{
		ProtoTCP = 6,
		ProtoUDP = 17,
		ProtoData = 0,
		ProtoEnd = 0xffff
	};

	XMLCoder(u_char* data, int len, TiXmlElement* xml);
private:
  
	TiXmlElement* m_xml_packet;
	void Parse(u_char* data, int len);
	u_int16_t ParseEth(u_char*& data, int& len);
	u_int16_t ParseGre(u_char*& data, int& len);
	u_int16_t ParseARP(u_char*& data, int& len);
	u_int16_t ParseMPLS(u_char*& data, int& len);
	u_int16_t Parse8021q(u_char*& data, int& len);
	u_int16_t ParseIP(u_char*& data, int& len);
	u_int16_t ParseTCP(u_char*& data, int& len);
	u_int16_t ParseUDP(u_char*& data, int& len);
	u_int16_t ParseICMP(u_char*& data, int& len);
	u_int16_t ParseData(u_char*& data, int& len);
};

#endif // __XML_CODER__H__