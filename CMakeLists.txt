cmake_minimum_required(VERSION 2.8)

add_definitions( --std=gnu++0x)

add_executable(xml_to_pcap xml_to_pcap)

add_executable(pcap_to_xml pcap_to_xml.cpp ParsedPacket.cpp XMLBuilder.cpp XMLBuilder.h)
target_link_libraries(pcap_to_xml pcap tinyxml)