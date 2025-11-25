#pragma once
#include <cstdint>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <optional>

#define packetLogSize 25000

/*
Aggregates sequence arbitration results between A/B feeds
-Ingest packets from both sides, keyed by MsgSeqNum
-For each side, track earliest timestamp and packet count
-Compute uniques, matches, who was faster, and average speed advantage

Usage:
-Call add(side, seq, ts_ns) for each parsed packet
-Call generateStats()n once at the end to print a summary
*/
class Stats {
public:
	enum class Side: uint16_t { A = 14310, B = 15310 }; //UDP Dst Port
	static std::optional<Side> toSide(uint16_t port) {
		if (port == static_cast<uint16_t>(Side::A)) return Side::A;
		if (port == static_cast<uint16_t>(Side::B)) return Side::B;
		return std::nullopt;
	}

private:
	struct SideInfo {
		bool valid = false;
		uint64_t earliest_ts = 0;
		size_t count = 0;
	};

	struct Entry {
		SideInfo A;
		SideInfo B;
	};

	std::unordered_map<uint32_t, Entry> packetLog;
	size_t totalA = 0;
	size_t totalB = 0;

public:
	Stats();
	~Stats() = default;

	/*
	Ingest a packet into stats
	Inputs:
			side	-Which feed this packet came from
			seq	-MsgSeqNum
			ts_ns	-timestamp (nanoseconds)
	*/
	void add(Side side, uint32_t seq, uint64_t ts_ns);

	/*
	Compute A and B arbitration statistics
	-Walk every unique sequence and aggregate outcomes
	*/
	void generateStats() const;
};