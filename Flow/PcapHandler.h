#pragma once

#include <pcap.h>
#ifdef _WIN32
#include <tchar.h>
#endif

//From pcap.h
#define PCAP_ERROR			-1	/* generic error code */
#define PCAP_ERROR_BREAK		-2	/* loop terminated by pcap_breakloop */
#define PCAP_ERROR_NOT_ACTIVATED	-3	/* the capture needs to be activated */

/*
Wrapper class to open, handle, and close pcap file
*/
class PcapHandler {
public:
	enum NextResult {Success = 1, Timeout = 0, Eof = PCAP_ERROR_BREAK, Error = PCAP_ERROR, Inactive = PCAP_ERROR_NOT_ACTIVATED};
	
private:
	bool valid = false;;
	struct pcap_pkthdr* pkt_header{};
	const u_char* pkt_data = nullptr;
	pcap_t* fp = nullptr;
	char errbuf[PCAP_ERRBUF_SIZE] = { 0 };
	
public:
	/*
	Open a pcap file for offline reading
	Inputs:
			filename	-pcap file path
	*/
	PcapHandler(const char* filename);
	~PcapHandler();
	PcapHandler(const PcapHandler&) = delete; //We own pcap_t* fp, care for file close
	PcapHandler& operator=(const PcapHandler&) = delete;
	PcapHandler(PcapHandler&& other) noexcept; //Move is safe
	PcapHandler& operator=(PcapHandler&& other) noexcept;

	bool isValid() const;
	/*
	Fetch the next packet from file
	Outputs:
			enum NextResult	-Packet read status
				(1) Success
				(0) Timeout
				(PCAP_ERROR_BREAK) Eof, loop terminated by pcap_breakloop
				(PCAP_ERROR) Error, generic error code
				(PCAP_ERROR_NOT_ACTIVATED) Inactive, the capture needs to be activated
	*/
	PcapHandler::NextResult getNextPacket();
	const pcap_pkthdr* getHeader() const;
	const u_char* getData() const;

private:
	/*
	Set DLL search path for npcap
	Taken from npcap-sdk examples
	Outputs:
			true/false	-True if success
	*/
#ifdef _WIN32
	bool LoadNpcapDlls();
#endif

};
