#include<stdio.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<features.h>
#include<linux/if_packet.h>
#include<linux/if_ether.h>
#include<errno.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include<netinet/ip_icmp.h>	
#include <string.h>
//#include<linux/ip.h>
//#include<linux/tcp.h>
#include<netinet/in.h>
#include <time.h>

int CreateRawSocket(int protocol_to_sniff){
	int rawsock;
	if((rawsock = socket(PF_PACKET,SOCK_RAW,htons(protocol_to_sniff)))== -1){
		perror("Error ceateing raw socket");
		exit(-1);
	}
	return rawsock;
}
int BindRawSocketToInterface(char *device, int rawsock, int protocol){
	struct sockaddr_ll sll;
	struct ifreq ifr;

	bzero(&sll, sizeof(sll));
	bzero(&ifr, sizeof(ifr));

	strncpy((char *)ifr.ifr_name, device,IFNAMSIZ);
	if((ioctl(rawsock,SIOCGIFINDEX, &ifr))==-1){
		printf("error \n");
		exit(-1);
	}

	sll.sll_family=AF_PACKET;
	sll.sll_ifindex= ifr.ifr_ifindex;
	sll.sll_protocol= htons(protocol);

	if((bind(rawsock, (struct sockaddr*)&sll, sizeof(sll)))==-1){
		perror("error binding \n");
		exit(-1);
	} 
	return 1;
}
void PrintPacketInHex(unsigned char *packet, int len){
	unsigned char *p= packet;
	time_t ticks;
	printf("\n\n packet start  \n");
	while(len--){
		printf("%.2x ", *p);
		p++;
	}
	printf(" \n\n packet ends \n ");
	ticks = time(NULL);
	printf("time:");
    printf(ctime(&ticks));
}
int ParseEtherHeader(unsigned char *packet, int len){
    struct ethhdr *ethernet_header;
    if(len>sizeof(struct ethhdr)){
        ethernet_header=(struct ethhdr *)packet;
        PrintinHex("Destination Mac: ",ethernet_header->h_dest,6);
        printf("\n");
        PrintinHex("Source Mac: ", ethernet_header->h_source,6);
        printf("\n");
        PrintinHex("Protocol: ",(void *)&ethernet_header->h_proto,2);
		printf("\n");
    }
}
int PrintinHex(char *mesg, unsigned char *p, int len){
    printf(mesg);
    while(len--){
        printf("%.2x ",*p);
        p++; 
    }
}
int ParseIpHeader(unsigned char *packet, int len){
    struct ethhdr *ethernet_header;
    struct iphdr *ip_header;
    ethernet_header=(struct ethhdr *)packet;	
    if(ntohs(ethernet_header->h_proto)== ETH_P_IP){
        if(len>= sizeof(struct ethhdr)+ sizeof(struct iphdr)){
            ip_header=(struct iphdr*)(packet + sizeof(struct ethhdr));
            printf("Dest IP address: %s\n ", inet_ntoa(*(struct in_addr*)&ip_header->daddr));
            printf("Sorurce IP address: %s\n ", inet_ntoa(*(struct in_addr*)&ip_header->saddr));
			printf("TIme to live: %d \n",ip_header->ttl);
        }else {
            printf("not possible");
        }
    }else{
        printf("nop");
    }
}
int ParseTcpUdpHeader(unsigned char *packet , int len)
{
	struct ethhdr *ethernet_header;
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;
    struct udphdr *udp_header;
	struct icmphdr *icmp_header;
    unsigned char *data;
	int data_len;
// for tcp
	if(len >= (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)))
	{
		ethernet_header = (struct ethhdr *)packet;
		if(ntohs(ethernet_header->h_proto) == ETH_P_IP)
		{
			ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
			if(ip_header->protocol == IPPROTO_TCP)
			{
			    printf("TCP protocol\n");						
				tcp_header = (struct tcphdr*)(packet + sizeof(struct ethhdr) + ip_header->ihl*4 );
				printf("Source Port: %d\n", ntohs(tcp_header->source));
				printf("Dest Port: %d\n", ntohs(tcp_header->dest));
		        data = (packet + sizeof(struct ethhdr) + ip_header->ihl*4 +sizeof(struct tcphdr));
		        data_len = ntohs(ip_header->tot_len) - ip_header->ihl*4 - sizeof(struct tcphdr);
                if(data_len)
                {
                    printf("Data Len : %d\n", data_len);
                    PrintinHex("Data : ", data, data_len);
                    printf("\n\n");		
                    return 1;	
                }
                else
                {
                    printf("No Data in packet\n");
                    return 0;
                }
//for udp
			}else if(ip_header->protocol == IPPROTO_UDP)
			{
				printf("UDP protocol\n");						
				udp_header = (struct udphdr*)(packet + sizeof(struct ethhdr) + ip_header->ihl*4 );
				printf("Source Port: %d\n", ntohs(udp_header->source));
				printf("Dest Port: %d\n", ntohs(udp_header->dest));
                data = (packet + sizeof(struct ethhdr) + ip_header->ihl*4 +sizeof(struct udphdr));
		        data_len = ntohs(ip_header->tot_len) - ip_header->ihl*4 - sizeof(struct udphdr);
                if(data_len)
                {
                    printf("Data Len : %d\n", data_len);
                    PrintinHex("Data : ", data, data_len);
                    printf("\n\n");		
                    return 1;	
                }
                else
                {
                    printf("No Data in packet\n");
                    return 0;
                }
			}
			else if(ip_header->protocol == IPPROTO_ICMP)
			{
				printf("ICMP protocol\n");						
				icmp_header = (struct icmphdr*)(packet + sizeof(struct ethhdr) + ip_header->ihl*4 );
                data = (packet + sizeof(struct ethhdr) + ip_header->ihl*4 +sizeof(struct icmphdr));
		        data_len = ntohs(ip_header->tot_len) - ip_header->ihl*4 - sizeof(struct icmphdr);
                if(data_len)
                {
                    printf("Data Len : %d\n", data_len);
                    PrintinHex("Data : ", data, data_len);
                    printf("\n\n");		
                    return 1;	
                }
                else
                {
                    printf("No Data in packet\n");
                    return 0;
                }
			}
			else
			{
				printf("Not a TCP/UDP  packet\n");
			}
		}
		else
		{
			printf("Not an IP packet\n");
		}	
		
	}
	else
	{
		printf("TCP Header not present \n");

	} 
}
int main(int argc, char **argv){
	int raw;
	unsigned char packet_buffer[2048];
	int len;
	int packets_to_sniff;
	struct sockaddr_ll packet_info;
	int packet_info_size= sizeof(packet_info);


	raw= CreateRawSocket(ETH_P_IP);

	BindRawSocketToInterface(argv[1],raw,ETH_P_IP);
	
    packets_to_sniff=atoi(argv[2]);

	while(packets_to_sniff--){
		if((len= recvfrom(raw,packet_buffer, 2048,0, (struct sockaddr*)&packet_info, &packet_info_size)) == -1){
			perror("recv from returened -1");
			exit(-1);
		}else{
			PrintPacketInHex(packet_buffer,len);
            ParseEtherHeader(packet_buffer,len);
            ParseIpHeader(packet_buffer,len);
			ParseTcpUdpHeader(packet_buffer,len);
		}
	} 
	return 0;
}