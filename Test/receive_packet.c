#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <netinet/ip.h>   // the IP protocol
#include <net/ethernet.h> // the L2 protocols

#include "utils.h"

int main() {
    int sock_r;
    unsigned char *buffer = (unsigned char *) malloc(65536);
    memset(buffer, 0, 65536);
    struct sockaddr_ll saddr;
    int saddr_len = sizeof(saddr);

    sock_r = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sock_r < 0) {
        perror("Socket Error");
        return -1;
    }

    while(1) {
        int buflen = recvfrom(sock_r, buffer, 65536, 0, (struct sockaddr*)&saddr, (socklen_t *)&saddr_len);
        if (buflen < 0) {
            printf("Error in reading recvfrom function\n");
            return -1;
        }

        struct ethhdr *eth_header = (struct ethhdr *)buffer;
        // Check EtherType
        if (ntohs(eth_header->h_proto) == ETH_P_ARP) {
            printf("Received ARP packet\n");
        } else if (ntohs(eth_header->h_proto) == ETH_P_IP) {
            struct iphdr *ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));
            if (ip_header->protocol == IPPROTO_ICMP) {
                printf("Received ICMP packet\n");
                // Further processing for ICMP packet
                //print_headers(buffer);
            }
        }
    }

    //close(sock_r);
    return 0;
}
