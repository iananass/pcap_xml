#ifndef RANAP_PROBE_PARSEDPACKET_H
#define RANAP_PROBE_PARSEDPACKET_H

#include <vector>
#include <sys/types.h>

struct vlanhdr
{

	union
	{
		u_int16_t vlan_tci;

		struct
		{
			u_int16_t vid : 12;
			u_int16_t dei : 1;
			u_int16_t pcp : 3;
		} tci_detailed;
	};
	u_int16_t nextProto;
} __attribute__((__packed__));

struct mpls_hdr
{
	u_int32_t label() const
	{ return (u_int32_t(bytes[0]) << 12)  | (u_int32_t(bytes[1]) << 4) | (u_int32_t(bytes[2]) >> 4); }
	void label(u_int32_t value)
	{
		bytes[0] = value >> 12;
		bytes[1] = value >> 4;
		bytes[2]  = (bytes[2] & 0x0f) | ((value & 0xf) << 4);
	}

	u_int16_t experimental() const
	{ return (bytes[2] >> 1) & 7; }
	void experimental(u_int8_t value)
	{ bytes[2]  = (bytes[2] & 0xf1) | ((value & 7) << 1); }

	u_int16_t stack_bottom() const
	{ return bytes[2] & 1; }
	void stack_bottom(u_int8_t value)
	{ bytes[2]  = (bytes[2] & 0xfe) | bool(value); }

	u_int16_t ttl() const
	{ return bytes[3]; }
	void ttl(u_char value)
	{ bytes[3] = value; }
private:
	u_char bytes[4];
} __attribute__((__packed__));

struct arpheader
{
	u_int16_t hd;
	u_int16_t pr;
	u_int8_t hdl;
	u_int8_t prl;
	u_int16_t op;
	u_int8_t sha[6];
	u_int32_t spa;
	u_int8_t dha[6];
	u_int32_t dpa;
} __attribute__((packed));

struct gre_hdr
{
    u_int8_t reserved1:4;
    u_int8_t seq_presented:1;
    u_int8_t key_presented:1;
    u_int8_t unused:1;
    u_int8_t check_presented:1;
    u_int8_t reserved2:5;
    u_int8_t version:3;
    u_int16_t next_proto;

} __attribute__((__packed__));

#endif //RANAP_PROBE_PARSEDPACKET_H
