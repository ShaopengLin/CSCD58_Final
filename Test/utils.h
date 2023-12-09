// packet_utils.h

#ifndef PACKET_UTILS_H
#define PACKET_UTILS_H

#include <netinet/ip.h>      // For IP header
#include <netinet/tcp.h>     // For TCP header
#include <netinet/ip_icmp.h> // For ICMP header
#include <net/ethernet.h>    // For Ethernet header

void print_headers(unsigned char *buffer);

#endif // PACKET_UTILS_H
