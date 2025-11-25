#pragma once
#include <cstdint>
#include <pcap.h>

#define Ethernet_Dst_Length 6
#define Ethernet_Src_Length 6
#define Ethernet_VLAN_TPID_Length 2
#define Ethernet_VLAN_TCI_Length 2
#define Ethernet_Type_Length 2
#define Ethernet_VLAN_TPID_Value 0x8100

#define IPv4_Ver_IHL_Length 1
#define IPv4_DSCP_ECN_Length 1
#define IPv4_TotalLen_Length 2
#define IPv4_ID_Length 2
#define IPv4_Flags_Offset_Length 2
#define IPv4_TTL_Length 1
#define IPv4_Protocol_Length 1
#define IPv4_Checksum_Length 2
#define IPv4_Src_Length 4
#define IPv4_Dst_Length 4
#define IpV4_IHL_Header_Size 32

#define UDP_Src_Length 2
#define UDP_Dst_Length 2
#define UDP_Len_Length 2
#define UDP_Checksum_Length 2
#define UDP_MDP_SEQ_Length 4

#define Trailer_Seconds_Offset 8
#define Trailer_Nanoseconds_Offset 12
#define Trailer_Seconds_Length 4
#define Trailer_Nanoseconds_Length 4

#define IPv4_type 0x0800

/*
Parse 1 packet into internal views
*/
class PacketParser {
private:
	struct EthernetView {
		const uint8_t* start = nullptr; 
	};

	struct IPv4View {
		const uint8_t* start = nullptr;
	};

	struct UDPView {
		const uint8_t* start = nullptr;
		uint32_t seq = 0;
		uint16_t port = 0;
	};
	struct TrailerView {
		const uint8_t* start = nullptr;
		uint64_t ns = 0;
	};

	EthernetView eth{};
	IPv4View ipv4{};
	UDPView udp{};
	TrailerView trailer{};

public:
	PacketParser();
	~PacketParser() = default;

	/*
	Parse bytes of a single packet and extract relevant information (seq, port, ns)
	Return false if unable to parse entirely
	Inputs:
			header		-Packet header from PcapHandler
			pkt_data	-Packet data from PcapHandler
	Outputs:
			true/false	-True if packet parsing succeeded
	*/
	bool parseBytes(const pcap_pkthdr* header, const u_char* pkt_data);
	uint32_t getSequence();
	uint16_t getPort();
	uint64_t getTimestamp();

private:
	size_t bytesRemaining = 0;
	const uint8_t* cursor = nullptr;

	/*
	Helper functions
	Parse headers/trailer
	Leave cursor just after end of header
	Inputs:
			header		-Packet header from PcapHandler
			pkt_data	-Packet data from PcapHandler
	Outputs:
			true/false	-True if header/trailer parsing succeeded
	*/
	bool parseEthernet(const pcap_pkthdr* header, const u_char* pkt_data);
	bool parseIPv4(const pcap_pkthdr* header, const u_char* pkt_data);
	bool parseUDP(const pcap_pkthdr* header, const u_char* pkt_data);
	bool parseTrailer(const pcap_pkthdr* header, const u_char* pkt_data);

	/*
	Helper function
	Read a little-endian 32-bit integer
	Used for CME MDP MsgSeqNum
	Inputs:
			ptr			-Pointer to start of 32bit data
	Outputs:
			uint32_t	-Value
	*/
	uint32_t readLittleEndian32(const uint8_t* ptr) {
		return (uint32_t)ptr[0]
			| (uint32_t)ptr[1] << 8
			| (uint32_t)ptr[2] << 16
			| (uint32_t)ptr[3] << 24;
	}

};