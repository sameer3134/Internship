#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *ethernetHeader = (struct ether_header *)packet;
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    struct icmp *icmp_header = (struct icmp *)(packet + sizeof(struct ether_header) + sizeof(struct ip));

    char src_mac[ETHER_ADDR_LEN];
    char dest_mac[ETHER_ADDR_LEN];
    char src_ip[INET_ADDRSTRLEN];
    int data_len = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct icmp));

    // Get source MAC address
    ether_ntoa_r((struct ether_addr *)ethernetHeader->ether_shost, src_mac);
    ether_ntoa_r((struct ether_addr *)ethernetHeader->ether_dhost, dest_mac);
    // Get source IP address
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);

    // Print MAC address, IP address, and data length
    printf("Source MAC: %s\n", src_mac);
    printf("Dest MAC: %s\n", dest_mac);
    printf("Source IP: %s\n", src_ip);
    printf("Data Length: %d bytes\n", data_len);
    printf("-----------------------------------\n");
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_pkthdr header;

    // Open the network device for packet capture
    handle = pcap_open_live("enp1s0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        return 1;
    }

    // Set the filter to capture ICMP packets only
    struct bpf_program fp;
    char filter_exp[] = "icmp";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    // Start packet capture loop
    pcap_loop(handle, -1, packet_handler, NULL);

    // Close the capture handle
    pcap_close(handle);

    return 0;
}