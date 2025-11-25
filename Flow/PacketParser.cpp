#include <cstring>
#include <iostream>
#include "PacketParser.h"

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

PacketParser::PacketParser() : bytesRemaining(0){}

bool PacketParser::parseBytes(const pcap_pkthdr* header, const u_char* pkt_data) {
	if(!pkt_data || !header) return false;
	
	bytesRemaining = header->caplen;
	cursor = reinterpret_cast<const uint8_t*>(pkt_data);

	if (!parseEthernet(header, pkt_data)) return false;
	if (!parseIPv4(header, pkt_data)) return false;
	if (!parseUDP(header, pkt_data)) return false;
	if (!parseTrailer(header, pkt_data)) return false;

	return true;
}

bool PacketParser::parseEthernet(const pcap_pkthdr* header, const u_char* pkt_data) {
	if (bytesRemaining == 0) return false;
	eth.start = cursor;
	size_t offset;

	offset = Ethernet_Dst_Length + Ethernet_Src_Length;
	if (bytesRemaining < offset) return false;
	cursor += offset;
	bytesRemaining -= offset;

	offset = Ethernet_VLAN_TPID_Length;
	if (bytesRemaining < offset) return false;
	uint16_t tpidValue;
	std::memcpy(&tpidValue, cursor, sizeof(tpidValue)); 
	tpidValue = ntohs(tpidValue);
	cursor += offset;
	bytesRemaining -= offset;

	uint16_t ethTypeValue;
	if (tpidValue == Ethernet_VLAN_TPID_Value) { //Is VLAN present
		offset = Ethernet_VLAN_TCI_Length;
		if (bytesRemaining < offset) return false;
		cursor += offset;
		bytesRemaining -= offset;

		offset = Ethernet_Type_Length;
		if (bytesRemaining < offset) return false;
		std::memcpy(&ethTypeValue, cursor, sizeof(ethTypeValue));
		ethTypeValue = ntohs(ethTypeValue);
		cursor += offset;
		bytesRemaining -= offset;
	}
	else
		ethTypeValue = tpidValue;

	if (ethTypeValue != IPv4_type)
		return false; // std::cout << "NOT IPv4" << std::endl; //debug

	return true;
}

bool PacketParser::parseIPv4(const pcap_pkthdr* header, const u_char* pkt_data) {
	if (bytesRemaining == 0) return false;
	ipv4.start = cursor;
	size_t offset;

	uint8_t options;
	std::memcpy(&options, cursor, sizeof(options));
	options = options & 0x0F;
	uint16_t optionsLength = options * IpV4_IHL_Header_Size / 8;

	offset = optionsLength;
	if (bytesRemaining < offset) return false;
	cursor += offset;
	bytesRemaining -= offset;

	return true;
}

bool PacketParser::parseUDP(const pcap_pkthdr* header, const u_char* pkt_data) {
	if (bytesRemaining == 0) return false;
	udp.start = cursor;
	size_t offset;

	offset = UDP_Src_Length ;
	if (bytesRemaining < offset) return false;
	cursor += offset;
	bytesRemaining -= offset;

	offset = UDP_Dst_Length;
	if (bytesRemaining < offset) return false;
	std::memcpy(&udp.port, cursor, sizeof(udp.port));
	udp.port = ntohs(udp.port);
	cursor += offset;
	bytesRemaining -= offset;

	offset = UDP_Len_Length;
	if (bytesRemaining < offset) return false;
	uint16_t dataLength;
	std::memcpy(&dataLength, cursor, sizeof(dataLength));
	dataLength = ntohs(dataLength) - UDP_Src_Length - UDP_Dst_Length - UDP_Len_Length - UDP_Checksum_Length;
	cursor += offset;
	bytesRemaining -= offset;

	offset = UDP_Checksum_Length;
	if (bytesRemaining < offset) return false;
	cursor += offset;
	bytesRemaining -= offset;

	offset = UDP_MDP_SEQ_Length;
	if (bytesRemaining < offset) return false;
	udp.seq = readLittleEndian32(cursor);

	offset = dataLength;
	if (bytesRemaining < offset) return false;
	cursor += dataLength; //Skip entire remaining UDP
	bytesRemaining -= dataLength;

	return true;
}

bool PacketParser::parseTrailer(const pcap_pkthdr* header, const u_char* pkt_data) {
	if (bytesRemaining < 20) return false;
	trailer.start = cursor;

	uint32_t seconds;
	std::memcpy(&seconds, cursor+ Trailer_Seconds_Offset, sizeof(seconds));
	seconds = ntohl(seconds);

	uint32_t nanoseconds;
	std::memcpy(&nanoseconds, cursor+ Trailer_Nanoseconds_Offset, sizeof(nanoseconds));
	nanoseconds = ntohl(nanoseconds);

	trailer.ns = (uint64_t)nanoseconds + (uint64_t)seconds * 1e9;

	return true;
}

uint32_t PacketParser::getSequence() {return udp.seq;}

uint16_t PacketParser::getPort() {return udp.port;}

uint64_t PacketParser::getTimestamp() {return trailer.ns;}
