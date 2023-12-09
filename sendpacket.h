#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>  // For ETH_P_ALL
#include "protocol.h"
#include <sys/ioctl.h>

char* find_active_interface();
int get_mac_ip(const char *iface, uint8_t *mac, uint32_t *ip);
int send_arp_packet(uint32_t targetIp);
int warpHeaderAndSendTcp(uint8_t* tcpbuff, int tcpTotalLen, uint32_t* dest_ip, uint8_t* dest_mac);
