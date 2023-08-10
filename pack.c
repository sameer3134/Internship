#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include<netinet/ip.h>	
#include<netinet/ip_icmp.h>
#include<netinet/ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <time.h>
#include<string.h>


void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packetData)
{
    struct ether_header* ethernetHeader;
    struct ip* ipHeader;
    struct icmphdr* icmpHeader;
    struct tcphdr* tcpHeader;
    struct udphdr* udpHeader;
    char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
    struct ether_addr sourceMAC, destMAC;
    time_t ticks;

    ethernetHeader = (struct ether_header*)packetData;

    memcpy(&sourceMAC, ethernetHeader->ether_shost, sizeof(struct ether_addr));
    memcpy(&destMAC, ethernetHeader->ether_dhost, sizeof(struct ether_addr));

    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
        ipHeader = (struct ip*)(packetData + sizeof(struct ether_header));
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);
    if(ipHeader->ip_p == IPPROTO_ICMP ||ipHeader->ip_p == IPPROTO_TCP ||ipHeader->ip_p == IPPROTO_UDP){
        ticks = time(NULL);
        printf("time:");    // display the time
        printf(ctime(&ticks));
            printf("Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", sourceMAC.ether_addr_octet[0],            //display source and destination mac address 
        sourceMAC.ether_addr_octet[1], sourceMAC.ether_addr_octet[2], sourceMAC.ether_addr_octet[3],
        sourceMAC.ether_addr_octet[4], sourceMAC.ether_addr_octet[5]);
            printf("Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", destMAC.ether_addr_octet[0],
        destMAC.ether_addr_octet[1], destMAC.ether_addr_octet[2], destMAC.ether_addr_octet[3],
        destMAC.ether_addr_octet[4], destMAC.ether_addr_octet[5]);
        if(ipHeader->ip_p == IPPROTO_ICMP) {                                                  // for icmp packet
            icmpHeader = (struct icmphdr*)(packetData + sizeof(struct ether_header) + sizeof(struct ip));
            printf("Protocol: ICMP\n");
            printf("Source IP: %s\n", sourceIP);
            printf("Destination IP: %s\n", destIP);
            unsigned int dataLen = ntohs(ipHeader->ip_len) - sizeof(struct ip) - sizeof(struct icmphdr);
            printf("Data Length: %u\n", dataLen);
            printf("\n\n");          
        }else if(ipHeader->ip_p == IPPROTO_TCP) {                                          // for tcp packet
            tcpHeader = (struct tcphdr*)(packetData + sizeof(struct ethhdr) + sizeof(struct ip));
            printf("Protocol: TCP\n");
            printf("Source IP: %s\n", sourceIP);
            printf("Destination IP: %s\n", destIP);
            printf("Source Port: %u\n", ntohs(tcpHeader->th_sport));
            printf("Destination Port: %u\n", ntohs(tcpHeader->th_dport));
            unsigned int dataOffset = (tcpHeader->doff * 4);
            unsigned int dataLen = ntohs(ipHeader->ip_len) - sizeof(struct ip) - dataOffset;
            printf("Data Length: %u\n", dataLen);
            printf("\n\n");
        }else if (ipHeader->ip_p == IPPROTO_UDP) {                                          // for udp packet
            udpHeader = (struct udphdr*)(packetData + sizeof(struct ethhdr) + sizeof(struct ip));
            printf("Protocol: UDP\n");
            printf("Source IP: %s\n", sourceIP);
            printf("Destination IP: %s\n", destIP);
            printf("Source Port: %u\n", ntohs(udpHeader->uh_sport));
            printf("Destination Port: %u\n", ntohs(udpHeader->uh_dport));
            unsigned int dataOffset = sizeof(struct udphdr);
            unsigned int dataLen = ntohs(udpHeader->uh_ulen) - sizeof(struct udphdr);
            printf("Data Length: %u\n", dataLen);
            printf("\n\n");
        }
    }
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];  
    struct bpf_program fp;
    char filter_exp[] = "";  // for all tcp, udp, icmp packet
    bpf_u_int32 net;

    handle = pcap_open_live("enp1s0", BUFSIZ, 1, 1000, errbuf);   // live session

    pcap_compile(handle, &fp, filter_exp, 0, net);              
    if (pcap_setfilter(handle, &fp) !=0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, -1, got_packet, NULL);                    // Capture packet

    pcap_close(handle);  
    return 0;
}
