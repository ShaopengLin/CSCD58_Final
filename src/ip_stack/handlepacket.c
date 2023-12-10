#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "protocol.h"

int handle_arp(unsigned char * buffer){
    
    // print_headers(buffer);

    struct eth_header *receive_eth_header = (struct eth_header *)buffer;
    // extern uint8_t DEST_MAC = receive_eth_header-> source;
    struct arp_header *receive_arp_header = (struct arp_header *)(buffer + sizeof(struct ethhdr));
    if(receive_arp_header->operation == htons(arp_reply)){
        printf("-------------------------------------------------------------\n");
        size_t send_buffer_size = sizeof(struct eth_header) + sizeof(struct ip_header) + sizeof(struct icmp_echo);
        uint8_t *send_buffer = (uint8_t *)malloc(send_buffer_size);

        struct eth_header* send_eth = malloc(sizeof(struct eth_header)); // Use your struct
        create_eth_header(send_eth, receive_eth_header->destination, receive_eth_header->source, ether_ip);

        struct ip_header* send_ip = malloc(sizeof(struct ip_header)); // Use your struct
        create_ip_header(send_ip, receive_arp_header->tip, receive_arp_header->sip, ip_protocol_icmp, sizeof(struct ip_header)+sizeof(struct icmp_echo));
        send_ip->checksum = cksum(send_ip, 20 + sizeof(struct icmp_header));
        
        struct icmp_echo* send_icmp = malloc(sizeof(struct icmp_echo)); // Use your struct
        create_icmp_echo_header(send_icmp);

        memcpy(send_buffer, send_eth, sizeof(struct eth_header));
        memcpy(send_buffer + sizeof(struct eth_header), send_ip, sizeof(struct ip_header));
        memcpy(send_buffer + sizeof(struct eth_header) + sizeof(struct ip_header), send_icmp, sizeof(struct icmp_echo));



        printf("Size of ip_header: %lu\n", sizeof(struct ip_header));
        printf("Size of icmp_header: %lu\n", sizeof(struct icmp_echo));
        printf("Size of eth_header: %lu\n", sizeof(struct eth_header));
        // print_headers(send_buffer);

        send_raw_icmp_packet(send_buffer, send_buffer_size);
        free(send_eth);
        free(send_ip);
        free(send_icmp);
        free(send_buffer);
    }
    return 1;


}
