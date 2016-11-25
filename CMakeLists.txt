cmake_minimum_required(VERSION 2.8)

add_definitions( -std=c++14 -g -gdwarf-2)

add_executable(xml_to_pcap xml_to_pcap.cpp Dumper.cpp XMLDecoder.cpp)
target_link_libraries(xml_to_pcap tinyxml)

add_executable(pcap_to_xml pcap_to_xml.cpp XMLBuilder.cpp XMLCoder.cpp)
target_link_libraries(pcap_to_xml pcap tinyxml)