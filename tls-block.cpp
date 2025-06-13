#include <iostream>
#include <pcap.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"
#include "mac.h"

Mac localMac;

struct Key {
    uint32_t srcIp;
    uint32_t dstIp;
    uint16_t srcPort;
    uint16_t dstPort;
    bool operator<(const Key& other) const {
        return std::tie(srcIp, dstIp, srcPort, dstPort) < std::tie(other.srcIp, other.dstIp, other.srcPort, other.dstPort);
    }
};

Mac getLocalMac(const std::string& interface) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ - 1);
    ioctl(sock, SIOCGIFHWADDR, &ifr);
    close(sock);
    return Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
}

uint16_t calculateChecksum(uint16_t* data, int len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *data++;
        len -= 2;
    }
    if (len == 1) sum += *(uint8_t*)data;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

std::string parseSNI(const uint8_t* data, int dataLen) {
    const uint8_t* ptr = data + 5 + 4 + 34; 
    if (ptr > data + dataLen) return "";

    uint8_t sessionIdLen = *ptr; ptr += 1 + sessionIdLen;
    if (ptr > data + dataLen) return "";

    uint16_t cipherLen = (ptr[0] << 8) | ptr[1]; ptr += 2 + cipherLen;
    if (ptr > data + dataLen) return "";

    uint8_t compLen = *ptr; ptr += 1 + compLen;
    if (ptr > data + dataLen) return "";

    uint16_t extLen = (ptr[0] << 8) | ptr[1]; ptr += 2;
    const uint8_t* extEnd = ptr + extLen;
    if (extEnd > data + dataLen) return "";

    while (ptr + 4 <= extEnd) {
        uint16_t extType = (ptr[0] << 8) | ptr[1];
        uint16_t extSize = (ptr[2] << 8) | ptr[3];
        ptr += 4;
        if (extType == 0x00) {
            uint16_t sniListLen = (ptr[0] << 8) | ptr[1]; ptr += 2;
            uint8_t nameType = *ptr; ptr++;
            uint16_t nameLen = (ptr[0] << 8) | ptr[1]; ptr += 2;
            if (ptr + nameLen > extEnd) return "";
            return std::string((const char*)ptr, nameLen);
        }
        ptr += extSize;
    }
    return "";
}

void injectRstPacket(bool isForward, pcap_t* handle, const EthHdr* eth, const IpHdr* ip, const TcpHdr* tcp, int payloadSize) {
    uint8_t packet[1500] = {};

    if (isForward) {
        int ipHeaderLen = ip->header_len();
        int tcpHeaderLen = tcp->header_len();
        int totalLen = sizeof(EthHdr) + ipHeaderLen + tcpHeaderLen;

        EthHdr* ethNew = (EthHdr*)packet;
        *ethNew = *eth;
        ethNew->smac_ = localMac;

        IpHdr* ipNew = (IpHdr*)(packet + sizeof(EthHdr));
        memcpy(ipNew, ip, ipHeaderLen);
        ipNew->total_length = htons(ipHeaderLen + tcpHeaderLen);
        ipNew->checksum = 0;
        ipNew->checksum = calculateChecksum((uint16_t*)ipNew, ipHeaderLen);

        TcpHdr* tcpNew = (TcpHdr*)((uint8_t*)ipNew + ipHeaderLen);
        memcpy(tcpNew, tcp, tcpHeaderLen);
        tcpNew->seq_ = htonl(ntohl(tcp->seq_) + payloadSize);
        tcpNew->flags_ = TcpHdr::RST | TcpHdr::ACK;
        tcpNew->win_ = 0;
        tcpNew->sum_ = 0;

        pseudo_header ph = { ipNew->sip_, ipNew->dip_, 0, IPPROTO_TCP, htons(tcpHeaderLen) };
        std::vector<uint8_t> pseudoBuf(sizeof(ph) + tcpHeaderLen);
        memcpy(pseudoBuf.data(), &ph, sizeof(ph));
        memcpy(pseudoBuf.data() + sizeof(ph), tcpNew, tcpHeaderLen);
        tcpNew->sum_ = calculateChecksum((uint16_t*)pseudoBuf.data(), pseudoBuf.size());

        pcap_sendpacket(handle, packet, totalLen);
    } else {
        int ipHeaderLen = ip->header_len();
        int tcpHeaderLen = tcp->header_len();
        int totalLen = ipHeaderLen + tcpHeaderLen;

        IpHdr* ipNew = (IpHdr*)packet;
        memcpy(ipNew, ip, ipHeaderLen);
        std::swap(ipNew->sip_, ipNew->dip_);
        ipNew->total_length = htons(totalLen);
        ipNew->checksum = 0;
        ipNew->checksum = calculateChecksum((uint16_t*)ipNew, ipHeaderLen);

        TcpHdr* tcpNew = (TcpHdr*)(packet + ipHeaderLen);
        memcpy(tcpNew, tcp, tcpHeaderLen);
        std::swap(tcpNew->sport_, tcpNew->dport_);
        tcpNew->seq_ = tcp->ack_;
        tcpNew->ack_ = tcp->seq_;
        tcpNew->flags_ = TcpHdr::RST | TcpHdr::ACK;
        tcpNew->win_ = 0;
        tcpNew->sum_ = 0;

        pseudo_header ph = { ipNew->sip_, ipNew->dip_, 0, IPPROTO_TCP, htons(tcpHeaderLen) };
        std::vector<uint8_t> pseudoBuf(sizeof(ph) + tcpHeaderLen);
        memcpy(pseudoBuf.data(), &ph, sizeof(ph));
        memcpy(pseudoBuf.data() + sizeof(ph), tcpNew, tcpHeaderLen);
        tcpNew->sum_ = calculateChecksum((uint16_t*)pseudoBuf.data(), pseudoBuf.size());

        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        int optval = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval));

        sockaddr_in sin = {};
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = ipNew->dip_;
        sendto(sock, packet, totalLen, 0, (sockaddr*)&sin, sizeof(sin));
        close(sock);
    }
}

void usage() {
    std::cout << "Usage: tls-block <interface> <server name>\n";
}

int main(int argc, char* argv[]) {
    if (argc != 3) { usage(); return -1; }

    std::string interface = argv[1], targetSNI = argv[2];
    localMac = getLocalMac(interface);
    std::map<Key, std::string> segments;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1, errbuf);
    if (!handle) return -1;

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res != 1) continue;

        const EthHdr* eth = (EthHdr*)packet;
        if (ntohs(eth->type_) != EthHdr::Ip4) continue;
        const IpHdr* ip = (IpHdr*)(packet + sizeof(EthHdr));
        if (ip->protocol != IpHdr::TCP) continue;

        int ipLen = ip->header_len();
        const TcpHdr* tcp = (TcpHdr*)((uint8_t*)ip + ipLen);
        int tcpLen = tcp->header_len();
        int totalLen = ntohs(ip->total_length);
        int payloadSize = totalLen - ipLen - tcpLen;
        if (payloadSize <= 0) continue;

        const uint8_t* payload = (const uint8_t*)tcp + tcpLen;
        Key flowKey{ip->sip_, ip->dip_, ntohs(tcp->sport_), ntohs(tcp->dport_)};

        std::string& buffer = segments[flowKey];
        buffer.append((char*)payload, payloadSize);

        if (buffer.size() >= 6 && buffer[0] == 0x16 && buffer[5] == 0x01) {
            std::string sni = parseSNI((const uint8_t*)buffer.data(), buffer.size());
            if (!sni.empty()) {
                std::cout << "Captured SNI: " << sni << std::endl;
                if (sni.find(targetSNI) != std::string::npos) {
                    std::cout << "Blocking connection targeting: " << sni << std::endl;
                    injectRstPacket(true, handle, eth, ip, tcp, payloadSize);
                    injectRstPacket(false, handle, eth, ip, tcp, payloadSize);
                    segments.erase(flowKey);
                }
            }
        }
    }
    pcap_close(handle);
    return 0;
}

