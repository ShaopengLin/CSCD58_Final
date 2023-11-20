#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
// TODO: replace these library with protocol.h

int main() {
    int sock_r;
    unsigned char *buffer = (unsigned char *) malloc(65536);
    memset(buffer, 0, 65536);
    struct sockaddr saddr;
    int saddr_len = sizeof(saddr);

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

        // Process the packet
        struct iphdr *ip_hdr = (struct iphdr *)buffer;
        if (ip_hdr->protocol == IPPROTO_ICMP) {
            struct icmphdr *icmp_hdr = (struct icmphdr *)(buffer + (ip_hdr->ihl * 4));
            printf("received icmp\n");
        }
    }

    //close(sock_r);
    return 0;
}
