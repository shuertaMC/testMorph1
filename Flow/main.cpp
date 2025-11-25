#include <stdio.h>
#include <iostream>
#include <vector>
#include <filesystem>
#include <pcap.h>
#include "Stats.h"
#include "PcapHandler.h"
#include "PacketParser.h"
#include "TestCases.cpp"

void usage(const char* progName) {
	printf("usage: %s <directory>", progName);
}

/*
	Find pcap files ina  given directory
	Inputs:
			dirPath	-directory to search
	Outputs:
			{Succcess, vector-of-filepaths}	-List of pcap files if successful
	*/
std::pair<bool, std::vector<std::string>> findPcapFiles(const std::string& dirPath) {
	std::vector<std::string> ret;

	if (!std::filesystem::exists(dirPath)) {
		std::cerr << "Error: directory does not exist." << std::endl;
		return { false, ret };
	}

	if (!std::filesystem::is_directory(dirPath)) {
		std::cerr << "Error: path is not a directory." << std::endl;
		return { false, ret };
	}

	for (auto& file : std::filesystem::directory_iterator(dirPath)) {
		if (file.is_regular_file() && file.path().extension() == ".pcap")
			ret.push_back(file.path().string());
	}

	return { true, ret };
}

int main(int argc, char** argv)
{
	//TEST CASES
	//TestCases t;
	//t.runAll();
	//return 0;

	if (argc != 2){
		usage(argv[0]);
		return 1;
	}

	//Find all pcap files
	auto [success, fileList] = findPcapFiles(argv[1]);
	if (!success) return 1;

	if (fileList.size() != 2) {
		std::cerr << "Error: directory must contain exactly 2 channels." << std::endl; //TODO: Support multiple channels
		return 1;
	}

	//Parse packets and log
	PacketParser parser;
	Stats stats;
	for (std::string& file : fileList) {
		PcapHandler channel(file.c_str());
		if (!channel.isValid()){
			std::cerr << "Couldn't load " << file << std::endl;
			continue;
		}
		
		while (channel.getNextPacket() == PcapHandler::NextResult::Success) {
			if (parser.parseBytes(channel.getHeader(), channel.getData())) {
				std::optional<Stats::Side> curSide = Stats::toSide(parser.getPort());
				if(curSide) stats.add(*curSide, parser.getSequence(), parser.getTimestamp());
			}
		}
	}

	stats.generateStats();

	return 0;
}

//TODO: confirm dst port for A or B
//TODO: Properly parse/view all fields instead of skipping/jumping
//TODO: get each view
//TODO: Make headers optional, they might be missing
//TODO: Dont assume EtherType (Could be length)
//TODO: Dont assume windows i.e. winsock2.h
//TODO: Save pointer to data instead of copy
//TODO: Walk trailer backwards per spec
//TODO: instead of assume/hardcode side A and B, segregate by  channel port
//TODO: Edge handling for malformed or truncated packets
//TODO: Error logging (count parse drops)
//TODO: More robust test cases
//TODO: check for udp before assuming, for ipv4 before assuming, etc