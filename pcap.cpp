#include <iostream>
#include <pcap.h>
#include <map>
#include <string>
#include <sstream>
#include <iomanip>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

struct IPStats {
    unsigned int packets = 0;
    unsigned int bytes = 0;
    unsigned int sendPackets = 0;
    unsigned int receivePackets = 0;
    unsigned int sendBytes = 0;
    unsigned int receiveBytes = 0;
};

struct EthernetStats {
    unsigned int txPackets = 0;
    unsigned int rxPackets = 0;
    unsigned long txBytes = 0;
    unsigned long rxBytes = 0;
};

struct ConversationKey {
    std::string srcIP;
    std::string dstIP;
    unsigned short srcPort = 0;
    unsigned short dstPort = 0;
    std::string protocol;

    bool operator<(const ConversationKey& other) const {
        return std::tie(srcIP, dstIP, srcPort, dstPort, protocol) <
               std::tie(other.srcIP, other.dstIP, other.srcPort, other.dstPort, other.protocol);
    }
};

std::map<std::string, IPStats> ipStatsMap;
std::map<ConversationKey, IPStats> conversationStats;
std::map<std::string, EthernetStats> ethernetStatsMap;

// MAC 주소를 문자열로 변환
std::string macToString(const u_char* addr) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        oss << std::setw(2) << (int)addr[i];
        if (i != 5) oss << ":";
    }
    return oss.str();
}

void packetHandler(u_char *userData, const struct pcap_pkthdr *header, const u_char *packet) {
    const struct ether_header *ethHeader = (const struct ether_header *)packet;
    if (ntohs(ethHeader->ether_type) != ETHERTYPE_IP) return;

    // 이더넷 헤더에서 MAC 주소 추출함
    std::string srcMAC = macToString(ethHeader->ether_shost);
    std::string dstMAC = macToString(ethHeader->ether_dhost);

    ethernetStatsMap[srcMAC].txPackets++;
    ethernetStatsMap[srcMAC].txBytes += header->len;
    ethernetStatsMap[dstMAC].rxPackets++;
    ethernetStatsMap[dstMAC].rxBytes += header->len;

    const struct ip *ipHeader = (const struct ip *)(packet + sizeof(struct ether_header));
    std::string srcIP = inet_ntoa(ipHeader->ip_src);
    std::string dstIP = inet_ntoa(ipHeader->ip_dst);
    unsigned int bytes = header->len;

    ipStatsMap[srcIP].sendPackets++;
    ipStatsMap[srcIP].sendBytes += bytes;
    ipStatsMap[srcIP].packets++;
    ipStatsMap[srcIP].bytes += bytes;

    ipStatsMap[dstIP].receivePackets++;
    ipStatsMap[dstIP].receiveBytes += bytes;
    ipStatsMap[dstIP].packets++;
    ipStatsMap[dstIP].bytes += bytes;

    unsigned short srcPort = 0, dstPort = 0;
    std::string protocol;

    // 프로토콜 확인 및 포트 번호 할당
    if (ipHeader->ip_p == IPPROTO_TCP) {
        const struct tcphdr *tcpHeader = (const struct tcphdr *)(packet + sizeof(struct ether_header) + ipHeader->ip_hl * 4);
        srcPort = ntohs(tcpHeader->source);
        dstPort = ntohs(tcpHeader->dest);
        protocol = "TCP";
    } else if (ipHeader->ip_p == IPPROTO_UDP) {
        const struct udphdr *udpHeader = (const struct udphdr *)(packet + sizeof(struct ether_header) + ipHeader->ip_hl * 4);
        srcPort = ntohs(udpHeader->source);
        dstPort = ntohs(udpHeader->dest);
        protocol = "UDP";
    }

    if (!protocol.empty()) {
        ConversationKey key{srcIP, dstIP, srcPort, dstPort, protocol};
        conversationStats[key].sendPackets++;
        conversationStats[key].sendBytes += bytes;
        
        ConversationKey reverseKey{dstIP, srcIP, dstPort, srcPort, protocol};
        conversationStats[reverseKey].receivePackets++;
        conversationStats[reverseKey].receiveBytes += bytes;
    }
}

void printStats() {
    std::cout << "IPv4:\n";
    for (const auto &entry : ipStatsMap) {
        std::cout << "IP 주소: " << entry.first
                  << ", Packets: " << entry.second.packets
                  << ", Bytes: " << entry.second.bytes
                  << ", Tx Packets: " << entry.second.sendPackets
                  << ", Rx Packets: " << entry.second.receivePackets
                  << ", Tx Bytes: " << entry.second.sendBytes
                  << ", Rx Bytes: " << entry.second.receiveBytes << std::endl;
    }

    std::cout << "\nConversations (TCP/UDP):\n";
    for (const auto &entry : conversationStats) {
        std::cout << "Conversation: " << entry.first.srcIP << ":" << entry.first.srcPort
                  << " -> " << entry.first.dstIP << ":" << entry.first.dstPort
                  << " (" << entry.first.protocol << ")"
                  << ", Tx Packets: " << entry.second.sendPackets
                  << ", Rx Packets: " << entry.second.receivePackets
                  << ", Tx Bytes: " << entry.second.sendBytes
                  << ", Rx Bytes: " << entry.second.receiveBytes << std::endl;
    }

    std::cout << "\nEthernet MAC Statistics:\n";
    for (const auto& entry : ethernetStatsMap) {
        std::cout << "MAC: " << entry.first
                  << ", Tx Packets: " << entry.second.txPackets
                  << ", Rx Packets: " << entry.second.rxPackets
                  << ", Tx Bytes: " << entry.second.txBytes
                  << ", Rx Bytes: " << entry.second.rxBytes << std::endl;
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap file>" << std::endl;
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(argv[1], errbuf);
    if (!handle) {
        std::cerr << "Could not open file " << argv[1] << ": " << errbuf << std::endl;
        return -2;
    }

    pcap_loop(handle, 0, packetHandler, NULL);

    printStats();

    pcap_close(handle);
    
    return 0;
}
