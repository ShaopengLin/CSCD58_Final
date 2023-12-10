#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <pthread.h>      // pthread library
#include <unistd.h>
#include "tcp_protocol.h"
#include "utils.h"
// #include "protocol.h"
#include "sendpacket.h"
#include "handlepacket.h"

#include <arpa/inet.h>

uint8_t DEST_MAC[6];

volatile int arp_header_ready = 0;

struct arp_header* receive_arp_header;

// Function that will run in a separate thread
void *packet_receiver(void *arg) {
    int sock_r = *(int*)arg;
    unsigned char *buffer = (unsigned char *) malloc(65536);
    memset(buffer, 0, 65536);
    struct sockaddr_ll saddr;
    int saddr_len = sizeof(saddr);
    int arp_check = 1;

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
        if (ntohs(eth_header->h_proto) == ETH_P_ARP && arp_check) {
            printf("Received ARP packet\n");
            memcpy(receive_arp_header, buffer + sizeof(struct ethhdr), sizeof(struct arp_header));

            if(handle_arp(buffer) == 1){
                printf("1\n");
                // receive_arp_header = (struct arp_header *)(buffer + sizeof(struct ethhdr));
                // memcpy(receive_arp_header, buffer + sizeof(struct ethhdr), sizeof(struct arp_header));
                print_ARP_headers(receive_arp_header);
            }
            arp_check = 0;
            arp_header_ready = 1;


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

    // free(buffer);
    return NULL;
}

int main(int argc, char** argv) {
    int sock_r;
    pthread_t thread_id;
    receive_arp_header = malloc(sizeof(struct arp_header));

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





    const char *ip_str = "10.1.1.2";
    uint32_t targetIp = inet_addr(ip_str);

    if (targetIp == INADDR_NONE) {
        fprintf(stderr, "Invalid IP address format: %s\n", ip_str);
        return 1;
    }

    send_arp_packet(targetIp);
    while(!arp_header_ready){
        sleep(1);
    }
    printf("1");
    print_ARP_headers(receive_arp_header);
    printf("1");
    if(receive_arp_header != NULL){
        // print_ARP_headers(receive_arp_header);
        send_ip_packet(receive_arp_header);
    }
    printf("sending tcp now");
    tcp_hdr_t tcp_header;
    uint8_t *data; // Pointer to your TCP payload data
    uint16_t len;  // Length of your TCP payload data

    // TCP/IP parameters
    uint32_t src_ip = inet_addr("10.1.1.1");  // Source IP address
    uint32_t dst_ip = inet_addr("10.1.1.2");  // Destination IP address
    uint16_t src_port = 12345;                   // Source TCP port
    uint16_t dst_port = 80;                      // Destination TCP port

    uint32_t seq_num = 0;    // Sequence number
    uint32_t ack_num = 0;    // Acknowledgment number
    uint8_t flags = 0x02;    // TCP flags, 0x02 for SYN
    uint16_t window = 65535; // Window size
    const char *message = "Hello, TCP!";
    data = (uint8_t *)message;
    len = strlen(message);
    // tcp_gen_packet(&tcp_header, data, len, src_ip, dst_ip, src_port, dst_port, seq_num, ack_num, flags, window);
    tcp_gen_syn (&tcp_header, src_ip, dst_ip, src_port, dst_port, seq_num, window);
    warpHeaderAndSendTcp(&tcp_header, sizeof(tcp_hdr_t), dst_ip, receive_arp_header->sha);
    tcp_gen_packet(&tcp_header, data, len, src_ip, dst_ip, src_port, dst_port, seq_num, ack_num, flags, window);
    warpHeaderAndSendTcp(&tcp_header, sizeof(tcp_hdr_t)+ len, dst_ip, receive_arp_header->sha);

    //close(sock_r);
    return 0;
}