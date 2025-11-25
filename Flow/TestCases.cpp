#pragma once

#include <iostream>
#include <pcap.h>
#include "PacketParser.h"
#include "Stats.h"
#include <vector>

class TestCases {
private:
	//Helper functions to write big and little endian
	void be16(std::vector<uint8_t>& data, uint16_t value) {
		data.push_back(uint8_t(value >> 8));
		data.push_back(uint8_t(value & 0xFF));
	}
	void be32(std::vector<uint8_t>& data, uint32_t value) {
		data.push_back(uint8_t(value >> 24));
		data.push_back(uint8_t((value >> 16) & 0xFF));
		data.push_back(uint8_t((value >> 8) & 0xFF));
		data.push_back(uint8_t(value & 0xFF));
	}
	void le32(std::vector<uint8_t>& data, uint32_t value) {
		data.push_back(uint8_t(value & 0xFF));
		data.push_back(uint8_t((value >> 8) & 0xFF));
		data.push_back(uint8_t((value >> 16) & 0xFF));
		data.push_back(uint8_t(value >> 24));
	}

	struct Packet {
		std::vector<uint8_t> data;
		pcap_pkthdr hdr{};
	};

	struct Results {
		size_t passed = 0;
		size_t failed = 0;
	};

	Packet makeBasicPacket(uint16_t udpPort, uint32_t udpSeq, uint32_t trailerSec, uint32_t trailerNanoSec, bool vlan = false, size_t ihlOptionsLength = 0) {
		//Set arbitrary values
		Packet out;
		auto& packetData = out.data;
		packetData.reserve(256); //arbitrary

		//Ethernet
		for (int i = 0; i < Ethernet_Dst_Length; ++i) packetData.push_back(0x01); //dst
		for (int i = 0; i < Ethernet_Src_Length; ++i) packetData.push_back(0x02); //src
		if (vlan) { be16(packetData, Ethernet_VLAN_TPID_Value); be16(packetData, 0x0001); be16(packetData, 0x0800); } //vlan + type
		else { be16(packetData, 0x0800); } //type

		//IPv4
		uint8_t ihlVal = IPv4_Ver_IHL_Length
			+ IPv4_DSCP_ECN_Length
			+ IPv4_TotalLen_Length
			+ IPv4_ID_Length
			+ IPv4_Flags_Offset_Length
			+ IPv4_TTL_Length
			+ IPv4_Protocol_Length
			+ IPv4_Checksum_Length
			+ IPv4_Src_Length
			+ IPv4_Dst_Length
			+ ihlOptionsLength;
		packetData.push_back(ihlVal * 8 / IpV4_IHL_Header_Size); //ver + ihl (0 options = 20 total length)
		packetData.push_back(0x00); //dscp + ecn
		be16(packetData, ihlVal); //Total Length
		be16(packetData, 0x1234); //id
		be16(packetData, 0x0000); //Flags + fragment offset
		packetData.push_back(32); //TTL
		packetData.push_back(17); //Protocol
		be16(packetData, 0);  //Checksum
		be32(packetData, 0x00000001); //src
		be32(packetData, 0x00000002); //dst
		for (int i = 0; i < ihlOptionsLength; ++i) packetData.push_back(0x05);  //options

		//UDP
		be16(packetData, 8010); //src port
		be16(packetData, udpPort); //dst port = Side
		be16(packetData, UDP_Src_Length + UDP_Dst_Length + UDP_Len_Length + UDP_Checksum_Length + UDP_MDP_SEQ_Length); //Length
		be16(packetData, 0); //Checksum
		le32(packetData, udpSeq); //MDP

		//Trailer
		for (int i = 0; i < 8; ++i) packetData.push_back(0x01); // bytes 0-7
		be32(packetData, trailerSec);		// byte 8-11 : seconds
		be32(packetData, trailerNanoSec);	// byte 12-15 : nanoseconds
		for (int i = 0; i < 4; ++i) packetData.push_back(0x02); // bytes 16-19

		//packet header
		out.hdr.caplen = out.hdr.len = static_cast<bpf_u_int32>(packetData.size());
		out.hdr.ts.tv_sec = out.hdr.ts.tv_usec = 0;

		return out;
	}

	Packet makePacket_BadTrailer(uint16_t udpPort, uint32_t udpSeq) {
		Packet out = makeBasicPacket(udpPort, udpSeq, 1, 2);
		out.data.resize(out.data.size() - 10);
		out.hdr.caplen = out.hdr.len = static_cast<bpf_u_int32>(out.data.size());
		return out;
	}

	void TEST(const char* name, bool pass, Results& r) {
		if (pass) { std::cout << "[PASS] " << name << std::endl; ++r.passed; }
		else { std::cout << "[FAIL] " << name << std::endl; ++r.failed; }
	}

public:
	//Test Basic packet, no vlan
	bool Test1() {
		Packet curPacket = makeBasicPacket(14310, 0x12345678, 2, 3);
		PacketParser parser;

		if (!parser.parseBytes(&curPacket.hdr, curPacket.data.data())) return false;
		if (parser.getPort() != 14310) return false;
		if (parser.getSequence() != 0x12345678) return false;
		uint64_t expectedTs = (uint64_t)3 + (uint64_t)2 * 1e9;
		if (parser.getTimestamp() != expectedTs) return false;
		return true;
	}

	//Test Basic packet, yes vlan
	bool Test2() {
		Packet curPacket = makeBasicPacket(14310, 0x12345678, 2, 3, true);
		PacketParser parser;

		if (!parser.parseBytes(&curPacket.hdr, curPacket.data.data())) return false;
		if (parser.getPort() != 14310) return false;
		if (parser.getSequence() != 0x12345678) return false;
		uint64_t expectedTs = (uint64_t)3 + (uint64_t)2 * 1e9;
		if (parser.getTimestamp() != expectedTs) return false;
		return true;
	}

	//Test Basic packet, with VLAN, with non-zero IHL options
	bool Test3() {
		Packet curPacket = makeBasicPacket(14310, 0x12345678, 2, 3, true, 4);
		PacketParser parser;

		if (!parser.parseBytes(&curPacket.hdr, curPacket.data.data())) return false;
		if (parser.getPort() != 14310) return false;
		if (parser.getSequence() != 0x12345678) return false;
		uint64_t expectedTs = (uint64_t)3 + (uint64_t)2 * 1e9;
		if (parser.getTimestamp() != expectedTs) return false;
		return true;
	}

	//Test Basic packet, with VLAN, with non-zero IHL options
	bool Test4() {
		Packet curPacket = makeBasicPacket(14310, 0x12345678, 2, 3, false, 4);
		PacketParser parser;

		if (!parser.parseBytes(&curPacket.hdr, curPacket.data.data())) return false;
		if (parser.getPort() != 14310) return false;
		if (parser.getSequence() != 0x12345678) return false;
		uint64_t expectedTs = (uint64_t)3 + (uint64_t)2 * 1e9;
		if (parser.getTimestamp() != expectedTs) return false;
		return true;
	}

	//Test Basic packet, with bad trailer (truncated)
	bool Test5() {
		Packet curPacket = makePacket_BadTrailer(14310, 0x12345678);
		PacketParser parser;

		return !parser.parseBytes(&curPacket.hdr, curPacket.data.data());
	}

	//Tess stats
	bool Test6() {
		Stats stats;

		//Seq 1: A faster by 50
		stats.add(Stats::Side::A, 1, 100);
		stats.add(Stats::Side::B, 1, 150);

		//Seq 2: B faster by 30
		stats.add(Stats::Side::A, 2, 100);
		stats.add(Stats::Side::B, 2, 70);

		//Seq 3: Only A
		stats.add(Stats::Side::A, 3, 100);

		//Seq 4: Only B
		stats.add(Stats::Side::B, 4, 100);
		
		stats.generateStats();
		return true;
	}

	int runAll() {
		Results r;
		TEST("Basic parser without VLAN", Test1(), r);
		TEST("Basic parser with VLAN", Test2(), r);
		TEST("Basic parser with VLAN with IHL options", Test3(), r);
		TEST("Basic parser without VLAN with IHL options", Test4(), r);
		TEST("Basic parser with truncated trailer", Test5(), r);
		TEST("Basic parser with stats", Test6(), r);

		std::cout << std::endl;
		std::cout << "Summary: " << r.passed << " passed, " << r.failed << " failed" << std::endl;
		return r.failed != 0 ? 1 : 0;
	}

};