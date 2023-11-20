#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include "protocol.h"

/*this variable is used to make sure to assign unique id to each packet*/
static uint16_t global_ip_id = 0;

/*calculates the ip checksum for the packet*/
uint16_t ip_checksum(void *header, int len) {
    /*to process each byte*/
    uint8_t *thisbyte = (uint8_t *) header;
    /*use the 32 bit checksum to ensure all the calulations are included*/
    uint32_t checksum = 0;
    /*loop through the header by 16 bits at one time*/
    for (len > 1; thisbyte += 2; len -= 2) {
        /*addes to the check sum for this 16 bits data*/
        checksum += (thisbyte[0] << 8) | thisbyte[1];
    }
    /*if len = 1 we have odd number of bits we add to acc*/
    if (len == 1) {
        checksum += (thisbyte[0] << 8);
    }

    /*add first 16 bits to the lower side as carry bit continously till is less than 0xffff*/
    while (checksum > 0xffff) {
        checksum = (checksum & 0xffff) + (checksum >> 16);
    }
    return htons(~checksum);
}

void create_ip_header(struct ip_header *header, uint32_t src_addr, uint32_t dest_addr, 
                      uint8_t protocol, uint16_t packet_len) {
    header->ihl = 5;
    header->version = 4;
    header->tos = 0;       
    header->len = htons(packet_len);
    header->id = htons(global_ip_id++);
    header->offset = 0; // No fragment
    header->ttl = 64; // Default TTL set to 64
    header->protocol = protocol; // No need for byte order conversion
    header->checksum = 0; // Initialize to 0 before checksum calculation
    header->saddr = src_addr;
    header->daddr = dest_addr;

    // Calculate checksum after filling all fields
    header->checksum = ip_checksum(header, header->ihl * 4);
}


void create_arp_header(struct arp_header *header, uint16_t operation, uint8_t *src_mac, uint32_t src_ip, 
                       uint8_t *dest_mac, uint32_t dest_ip) {
    header->hardware = htons(1); // Ethernet as default
    header->protocol = htons(0x0800); // IPv4 as default
    header->hlen = EthernetAddrLen; // Length of MAC address
    header->plen = IpAddrLen; // Length of IP address
    header->operation = htons(operation);
    memcpy(header->sha, src_mac, EthernetAddrLen);
    header->sip = src_ip;
    memcpy(header->tha, dest_mac, EthernetAddrLen);
    header->tip = dest_ip;
}


void create_eth_header(struct eth_header *header, uint8_t *src_mac, uint8_t *dest_mac, uint16_t type) {
    memcpy(header->destination, dest_mac, EthernetAddrLen);
    memcpy(header->source, src_mac, EthernetAddrLen);
    header->type = htons(type);
}
