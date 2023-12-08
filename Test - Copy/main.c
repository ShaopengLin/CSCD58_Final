#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <pthread.h>      // pthread library
#include <unistd.h>

#include "utils.h"
// #include "protocol.h"
#include "sendpacket.h"
#include "handlepacket.h"

#include <arpa/inet.h>

// Function that will run in a separate thread
void *packet_receiver(void *arg) {
    int sock_r = *(int*)arg;
    unsigned char *buffer = (unsigned char *) malloc(65536);
    memset(buffer, 0, 65536);
    struct sockaddr_ll saddr;
    int saddr_len = sizeof(saddr);

    while(1) {
        int buflen = recvfrom(sock_r, buffer, 65536, 0, (struct sockaddr*)&saddr, (socklen_t *)&saddr_len);
        if (buflen < 0) {
            printf("Error in reading recvfrom function\n");
            break; // Exit loop on error
        }

        if (saddr.sll_pkttype == PACKET_OUTGOING) {
            continue; // Skip processing this packet
        }

        struct ethhdr *eth_header = (struct ethhdr *)buffer;
        // Check EtherType
        if (ntohs(eth_header->h_proto) == ETH_P_ARP) {
            printf("Received ARP packet\n");
            handle_arp(buffer);
        } 
        else if (ntohs(eth_header->h_proto) == ETH_P_IP) {
            struct iphdr *ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));
            if (ip_header->protocol == IPPROTO_ICMP) {
                printf("Received ICMP packet\n");
                // Further processing for ICMP packet
                print_headers(buffer);
            }
        }
    }

    free(buffer);
    return NULL;
}

int main(int argc, char** argv) {
    int sock_r;
    pthread_t thread_id;

    sock_r = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sock_r < 0) {
        perror("Socket Error");
        return -1;
    }

    // Create a separate thread for receiving packets
    if(pthread_create(&thread_id, NULL, packet_receiver, &sock_r)) {
        fprintf(stderr, "Error creating thread\n");
        return -1;
    }

    // Optionally wait for the thread to finish
    // pthread_join(thread_id, NULL);





    const char *ip_str = "10.0.0.2";
    uint32_t targetIp = inet_addr(ip_str);

    if (targetIp == INADDR_NONE) {
        fprintf(stderr, "Invalid IP address format: %s\n", ip_str);
        return 1;
    }

    send_arp_packet(targetIp);
    // Wait for thread to finish (if not using pthread_join)
    while(1) {
        sleep(1); // This is just to keep the main thread alive
    }

    //close(sock_r);
    return 0;
}
