#include <iostream>
#include <cstring>
#include "PcapHandler.h"

#ifdef _WIN32
bool PcapHandler::LoadNpcapDlls()
{
	_TCHAR npcap_dir[512];
	if (!GetSystemDirectory(npcap_dir, 480)) {
		std::cerr << "Error in GetSystemDirectory: " << GetLastError() << std::endl;
		return false;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		std::cerr << "Error in SetDllDirectory: " << GetLastError() << std::endl;
		return false;
	}
	return true;
}
#endif

PcapHandler::PcapHandler(const char* filename): valid(true), fp(nullptr), pkt_header(nullptr), pkt_data(nullptr) {
#ifdef _WIN32
	if (!(valid = LoadNpcapDlls())) return;
#endif

	//Open the capture file
	if ((fp = pcap_open_offline(filename, errbuf)) == NULL){
		valid = false;
		std::cerr << "Unable to open the file: " << filename << std::endl;
	}
}
PcapHandler::~PcapHandler() { if (fp) pcap_close(fp); }

PcapHandler::PcapHandler(PcapHandler&& other) noexcept : valid(other.valid), pkt_header(other.pkt_header), pkt_data(other.pkt_data), fp(other.fp){
	std::memcpy(errbuf, other.errbuf, sizeof(errbuf));
	
	other.valid = false;
	other.pkt_header = nullptr;
	other.pkt_data = nullptr;
	other.fp = nullptr;
	other.errbuf[0] = '\0';
}

PcapHandler& PcapHandler::operator=(PcapHandler&& other) noexcept {
	if (this == &other) return *this;

	valid = other.valid;
	pkt_header = other.pkt_header;
	pkt_data = other.pkt_data;
	if (fp) pcap_close(fp);
	fp = other.fp;
	std::memcpy(errbuf, other.errbuf, sizeof(errbuf));

	other.valid = false;
	other.pkt_header = nullptr;
	other.pkt_data = nullptr;
	other.fp = nullptr;
	other.errbuf[0] = '\0';

	return *this;
}

bool PcapHandler::isValid() const { return valid; }

PcapHandler::NextResult PcapHandler::getNextPacket() {
	//auto retxx = pcap_datalink(fp);
	NextResult ret = (NextResult)pcap_next_ex(fp, &pkt_header, &pkt_data);
	if (ret == NextResult::Error) std::cerr << pcap_geterr(fp) << std::endl;
	return ret;
}

const pcap_pkthdr* PcapHandler::getHeader() const {
	return pkt_header;
}

const u_char* PcapHandler::getData() const {
	return pkt_data;
}
