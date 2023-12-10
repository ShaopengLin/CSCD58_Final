#include "../tcp/tcp_protocol.h"
#include <arpa/inet.h>
#include <net/ethernet.h>    // For Ethernet header
#include <net/if_arp.h>      // For ARP header
#include <netinet/ip.h>      // For IP header
#include <netinet/ip_icmp.h> // For ICMP header
#include <netinet/tcp.h>     // For TCP header
#include <stdio.h>
#include <time.h>
#include "utils.h"

uint64_t
SEC_TO_NS (time_t sec)
{
  return (sec) * 1000000000;
}
void
print_headers (unsigned char *buffer)
{
  struct ethhdr *eth_header = (struct ethhdr *)buffer;
  printf ("Ethernet Header\n");
  printf ("\t|-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
          eth_header->h_source[0], eth_header->h_source[1],
          eth_header->h_source[2], eth_header->h_source[3],
          eth_header->h_source[4], eth_header->h_source[5]);
  printf ("\t|-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
          eth_header->h_dest[0], eth_header->h_dest[1], eth_header->h_dest[2],
          eth_header->h_dest[3], eth_header->h_dest[4], eth_header->h_dest[5]);
  printf ("\t|-Protocol            : %u \n", ntohs (eth_header->h_proto));

  if (ntohs (eth_header->h_proto) == ETH_P_IP)
    {
      struct iphdr *ip_header
          = (struct iphdr *)(buffer + sizeof (struct ethhdr));
      printf ("IP Header\n");
      printf ("\t|-Version              : %d\n",
              (unsigned int)ip_header->version);
      printf ("\t|-Internet Header Length  : %d DWORDS or %d Bytes\n",
              (unsigned int)ip_header->ihl,
              ((unsigned int)(ip_header->ihl)) * 4);
      printf ("\t|-Type Of Service   : %d\n", (unsigned int)ip_header->tos);
      printf ("\t|-Total Length      : %d Bytes\n",
              ntohs (ip_header->tot_len));
      printf ("\t|-Identification    : %d\n", ntohs (ip_header->id));
      printf ("\t|-TTL               : %d\n", (unsigned int)ip_header->ttl);
      printf ("\t|-Protocol          : %d\n",
              (unsigned int)ip_header->protocol);
      printf ("\t|-Checksum          : %d\n", ntohs (ip_header->check));
      printf ("\t|-Source IP         : %s\n",
              inet_ntoa (*(struct in_addr *)&ip_header->saddr));
      printf ("\t|-Destination IP    : %s\n",
              inet_ntoa (*(struct in_addr *)&ip_header->daddr));

      if (ip_header->protocol == IPPROTO_TCP)
        {
          struct tcp_hdr *tcp_header
              = (struct tcphdr *)(buffer + ip_header->ihl * 4
                                  + sizeof (struct ethhdr));
          printf ("TCP Header\n");
          printf ("\t|-Source Port      : %u\n", ntohs (tcp_header->src_port));
          printf ("\t|-Destination Port : %u\n", ntohs (tcp_header->des_port));
          printf ("\t|-Sequence Number    : %u\n",
                  ntohl (tcp_header->seq_num));
          printf ("\t|-Acknowledge Number : %u\n",
                  ntohl (tcp_header->ack_num));
          // Flags and other fields can be added here
        }
      else if (ip_header->protocol == IPPROTO_ICMP)
        {
          struct icmphdr *icmp_header
              = (struct icmphdr *)(buffer + ip_header->ihl * 4
                                   + sizeof (struct ethhdr));
          printf ("ICMP Header\n");
          printf ("\t|-Type : %d\n", (unsigned int)(icmp_header->type));
          printf ("\t|-Code : %d\n", (unsigned int)(icmp_header->code));
          printf ("\t|-Checksum : %d\n", ntohs (icmp_header->checksum));
          // Other fields can be added here
        }
    }
  else if (ntohs (eth_header->h_proto) == ETH_P_ARP)
    {
      struct arphdr *arp_header
          = (struct arphdr *)(buffer + sizeof (struct ethhdr));

      // Printing basic ARP header info
      printf ("ARP Header\n");
      printf ("\t|-Hardware type: %d\n", ntohs (arp_header->ar_hrd));
      printf ("\t|-Protocol type: %d\n", ntohs (arp_header->ar_pro));
      printf ("\t|-Hardware size: %d\n", arp_header->ar_hln);
      printf ("\t|-Protocol size: %d\n", arp_header->ar_pln);
      printf ("\t|-Opcode: %d\n", ntohs (arp_header->ar_op));

      unsigned char *sender_mac = (unsigned char *)(arp_header + 1);
      unsigned char *sender_ip = sender_mac + arp_header->ar_hln;
      unsigned char *target_mac = sender_ip + arp_header->ar_pln;
      unsigned char *target_ip = target_mac + arp_header->ar_hln;

      // Printing Sender MAC address
      printf ("\t|-Sender MAC: ");
      for (int i = 0; i < arp_header->ar_hln; i++)
        printf ("%02X:", sender_mac[i]);
      printf ("\n");

      // Printing Sender IP address
      printf ("\t|-Sender IP: ");
      for (int i = 0; i < arp_header->ar_pln; i++)
        printf ("%d.", sender_ip[i]);
      printf ("\n");

      // Printing Target MAC address
      printf ("\t|-Target MAC: ");
      for (int i = 0; i < arp_header->ar_hln; i++)
        printf ("%02X:", target_mac[i]);
      printf ("\n");

      // Printing Target IP address
      printf ("\t|-Target IP: ");
      for (int i = 0; i < arp_header->ar_pln; i++)
        printf ("%d.", target_ip[i]);
      printf ("\n");
    }
}

void
print_ARP_headers (struct arp_header *buffer)
{
  struct arphdr *arp_header = buffer;

  // Printing basic ARP header info
  printf ("ARP Header\n");
  printf ("\t|-Hardware type: %d\n", ntohs (arp_header->ar_hrd));
  printf ("\t|-Protocol type: %d\n", ntohs (arp_header->ar_pro));
  printf ("\t|-Hardware size: %d\n", arp_header->ar_hln);
  printf ("\t|-Protocol size: %d\n", arp_header->ar_pln);
  printf ("\t|-Opcode: %d\n", ntohs (arp_header->ar_op));

  unsigned char *sender_mac = (unsigned char *)(arp_header + 1);
  unsigned char *sender_ip = sender_mac + arp_header->ar_hln;
  unsigned char *target_mac = sender_ip + arp_header->ar_pln;
  unsigned char *target_ip = target_mac + arp_header->ar_hln;

  // Printing Sender MAC address
  printf ("\t|-Sender MAC: ");
  for (int i = 0; i < arp_header->ar_hln; i++)
    printf ("%02X:", sender_mac[i]);
  printf ("\n");

  // Printing Sender IP address
  printf ("\t|-Sender IP: ");
  for (int i = 0; i < arp_header->ar_pln; i++)
    printf ("%d.", sender_ip[i]);
  printf ("\n");

  // Printing Target MAC address
  printf ("\t|-Target MAC: ");
  for (int i = 0; i < arp_header->ar_hln; i++)
    printf ("%02X:", target_mac[i]);
  printf ("\n");

  // Printing Target IP address
  printf ("\t|-Target IP: ");
  for (int i = 0; i < arp_header->ar_pln; i++)
    printf ("%d.", target_ip[i]);
  printf ("\n");
}
uint64_t
getNano ()
{
  uint64_t nanoseconds;
  struct timespec ts;
  int return_code = timespec_get (&ts, TIME_UTC);
  if (return_code == 0)
    {
      perror ("Cannot get time for some reason");
      exit (-1);
    }
  else
    nanoseconds = SEC_TO_NS ((uint64_t)ts.tv_sec) + (uint64_t)ts.tv_nsec;
  return nanoseconds;
}
