#ifndef __DUMPER__H__
#define __DUMPER__H__

#include <fstream>
#include <sys/types.h>

class Dumper
{
public:
    Dumper();
    Dumper ( const char* filename );
    bool Open ( const char* filename );
    bool IsOpened() const;

    void DumpPacket ( const u_char* data, u_int len );
    void Flush();
    void Close();
private:
    bool OpenInternal ( const char* filename );

    std::ofstream m_out;
};

#endif // __DUMPER__H__
