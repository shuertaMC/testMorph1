#include <algorithm>
#include <iostream>
#include <iomanip>
#include "Stats.h"

Stats::Stats() {
	packetLog.reserve(packetLogSize);
}

void Stats::add(Side side, uint32_t seq, uint64_t ts_ns) {
	Entry& curEntry = packetLog[seq];
	SideInfo& curSide = (side == Side::A) ? curEntry.A : curEntry.B;
	curSide.earliest_ts = (curSide.count == 0) ? ts_ns : std::min(curSide.earliest_ts, ts_ns);
	++curSide.count;
	curSide.valid = true;

	if (side == Side::A) ++totalA;
	else ++totalB;
}

void Stats::generateStats() const {
	uint64_t onlyA = 0, onlyB = 0;
	uint64_t AFasterCount = 0, BFasterCount = 0;
	double averageAdvA = 0.0, averageAdvB = 0.0;
	uint64_t AFasterAdvSum = 0,  BFasterAdvSum = 0;
	size_t matched = 0, ties = 0;

	for (auto& [seq, entry] : packetLog) {
		if (entry.A.valid && !entry.B.valid) 
			++onlyA;
		else if (!entry.A.valid && entry.B.valid)
			++onlyB;
		else if (entry.A.valid && entry.B.valid) {
			++matched;
			if (entry.A.earliest_ts < entry.B.earliest_ts) {
				++AFasterCount;
				AFasterAdvSum += (entry.B.earliest_ts - entry.A.earliest_ts);
			}
			else if (entry.B.earliest_ts < entry.A.earliest_ts) {
				++BFasterCount;
				BFasterAdvSum += (entry.A.earliest_ts - entry.B.earliest_ts);
			}
			else
				++ties;
		}
	}
	averageAdvA = (AFasterCount == 0) ? 0.0 : AFasterAdvSum / AFasterCount;
	averageAdvB = (BFasterCount == 0) ? 0.0 : BFasterAdvSum / BFasterCount;

	std::cout << "===== Feed Summary =====\n";
	std::cout << std::left << std::setw(30) << "Channels:" << "A = " << static_cast<uint16_t>(Side::A) << std::endl;
	std::cout << std::left << std::setw(30) << "" << "B = " << static_cast<uint16_t>(Side::B) << std::endl;

	std::cout << std::endl;
	std::cout << std::left << std::setw(30) << "Total unique seqs" << packetLog.size() << std::endl;
	std::cout << std::left << std::setw(30) << "Total packets from A" << totalA << std::endl;
	std::cout << std::left << std::setw(30) << "Total packets from B" << totalB << std::endl;

	std::cout << std::endl;
	std::cout << std::left << std::setw(30) << "Matched seqs" << matched << std::endl;
	std::cout << std::left << std::setw(30) << "Only in A" << onlyA << std::endl;
	std::cout << std::left << std::setw(30) << "Only in B" << onlyB << std::endl;

	std::cout << std::endl;
	std::cout << std::left << std::setw(30) << "A faster count" << AFasterCount << std::endl;
	std::cout << std::left << std::setw(30) << "A avg speed advantage" << averageAdvA << " ns" << std::endl;
	std::cout << std::left << std::setw(30) << "B faster count" << BFasterCount << std::endl;
	std::cout << std::left << std::setw(30) << "B avg speed advantage" << averageAdvB << " ns" << std::endl;
	std::cout << std::left << std::setw(30) << "Packets with same speed" << ties << std::endl;

}