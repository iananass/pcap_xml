#include "Dumper.h"

#include <sys/types.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>

typedef struct pcap_hdr_s {
    /*! Magic number - 0xa1b2c3d4 means no swap needed,
     *  0xd4c3b2a1 means we'll need to swap.
     */
    uint32_t magic_number;

    /*! Major version number (currently 2) */
    uint16_t version_major;

    /*! Minor version number (4 + ) */
    uint16_t version_minor;

    /*! GMT to local-time correction, in s */
    int32_t thiszone;

    /*! Accuracy of timestamps. In practice, always 0 */
    uint32_t sigfigs;

    /*! Snapshot length (typically 65535 + but might be limited) */
    uint32_t snaplen;


    /* These are network types - equivalent to WTAP_ENCAP_XXX in
     *  libpcap.c  . We only care about a few ..
     */

#define PCAP_NETWORK_TYPE_NONE 0
#define PCAP_NETWORK_TYPE_ETHERNET 1

    /*! Network type: Ethernet = 1 .. */
    uint32_t network;

} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
    uint32_t ts_sec; /* timestamp seconds */
    uint32_t ts_usec; /* timestamp microseconds */
    uint32_t incl_len; /* number of octets of packet saved in file */
    uint32_t orig_len; /* actual length of packet */
} pcaprec_hdr_t;

Dumper::Dumper()
{}

Dumper::Dumper ( const char* filename )
{
    OpenInternal ( filename );
}

bool Dumper::Open ( const char* filename )
{
    if ( IsOpened() )
        Close();
    return OpenInternal ( filename );
}

bool Dumper::IsOpened() const
{
    return m_out.is_open();
}

void Dumper::DumpPacket ( const u_char* data, u_int len, uint32_t sec, uint32_t usec)
{
    pcaprec_hdr_t pack_hdr;
    pack_hdr.ts_sec = sec;
    pack_hdr.ts_usec = usec;
    pack_hdr.incl_len = pack_hdr.orig_len = len;
    m_out.write ( reinterpret_cast<const char*> ( &pack_hdr ), sizeof ( pack_hdr ) );
    m_out.write ( reinterpret_cast<const char*>(data), len );
}
void Dumper::Flush()
{
    m_out.flush();
}
void Dumper::Close()
{
    m_out.close();
}

bool Dumper::OpenInternal ( const char* filename )
{
    m_out.open ( filename );
    if ( ! m_out.is_open() )
        return false;
    pcap_hdr_t d;

    d.magic_number = 0xa1b2c3d4;
    d.version_major = 2;
    d.version_minor = 4;
    d.sigfigs = 0;
    d.network = 1;
    d.snaplen = 0xffff;
    d.thiszone = 0;
    m_out.write ( reinterpret_cast<const char*> ( &d ), sizeof ( d ) );
    return true;
}
