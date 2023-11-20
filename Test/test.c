#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include "protocol.h"  // Assuming this is your custom header file

int main() {
    int sock_r;
    unsigned char *buffer = (unsigned char *) malloc(65536);
    memset(buffer, 0, 65536);
    struct sockaddr saddr;
    int saddr_len = sizeof(saddr);

    // Create a raw socket for ICMP
    sock_r = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(sock_r < 0) {
        perror("Socket Error");
        return -1;
    }

    while(1) {
        int buflen = recvfrom(sock_r, buffer, 65536, 0, &saddr, (socklen_t *)&saddr_len);
        if (buflen < 0) {
            printf("Error in reading recvfrom function\n");
            return -1;
        }

        // Process the packet using the custom IP header
        struct ip_header *ip_hdr = (struct ip_header *)buffer;
        if (ip_hdr->protocol == IPPROTO_ICMP) {
            struct icmphdr *icmp_hdr = (struct icmphdr *)(buffer + (ip_hdr->ihl * 4));
            printf("Received ICMP packet\n");
        }
    }

    //close(sock_r); 
    return 0;
}
