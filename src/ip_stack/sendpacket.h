#include "protocol.h"
#include <arpa/inet.h>

#include <linux/if_packet.h>
#include <net/ethernet.h> // For ETH_P_ALL
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

char *find_active_interface ();
int get_mac_ip (const char *iface, uint8_t *mac, uint32_t *ip);
int send_arp_packet (uint32_t targetIp);
int send_raw_icmp_packet (uint8_t *buffer, size_t buffer_size);
int warpHeaderAndSendTcp (uint8_t *tcpbuff, int tcpTotalLen, uint32_t *dest_ip,
                          uint8_t *dest_mac);

uint16_t send_ip_packet (struct arp_header *receive_arp_header, int size);
int initTCPSocket ();