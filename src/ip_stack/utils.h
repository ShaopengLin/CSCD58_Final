// packet_utils.h

#ifndef PACKET_UTILS_H
#define PACKET_UTILS_H

#include <netinet/ip.h>      // For IP header
#include <netinet/tcp.h>     // For TCP header
#include <netinet/ip_icmp.h> // For ICMP header
#include <net/ethernet.h>    // For Ethernet header

void print_headers(unsigned char *buffer);
uint64_t getNano ();
uint64_t SEC_TO_NS (time_t sec);
#endif // PACKET_UTILS_H
