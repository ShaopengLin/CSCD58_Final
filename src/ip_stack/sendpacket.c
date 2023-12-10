#include "sendpacket.h"
#include "utils.h"
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> // For ETH_P_ALL
#include <net/if.h>
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

char *
find_active_interface ()
{
  struct ifaddrs *ifaddr, *ifa;
  int family, s;
  char *interface_name = NULL;

  if (getifaddrs (&ifaddr) == -1)
    {
      perror ("getifaddrs");
      return NULL;
    }
  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
      if (ifa->ifa_addr == NULL)
        continue;

      family = ifa->ifa_addr->sa_family;

      // Check interfaces which is up and not a loopback
      if ((family == AF_INET || family == AF_INET6)
          && (ifa->ifa_flags & IFF_UP) && !(ifa->ifa_flags & IFF_LOOPBACK))
        {
          interface_name = strdup (ifa->ifa_name);
          break;
        }
    }

  freeifaddrs (ifaddr);
  return interface_name;
}

int
get_mac_ip (const char *iface, uint8_t *mac, uint32_t *ip)
{
  int sockfd;
  struct ifreq ifr;
  sockfd = socket (AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0)
    {
      perror ("socket");
      return -1;
    }

  strncpy (ifr.ifr_name, iface, IFNAMSIZ);

  // Get MAC address
  if (ioctl (sockfd, SIOCGIFHWADDR, &ifr) < 0)
    {
      perror ("ioctl-SIOCGIFHWADDR");
      close (sockfd);
      return -1;
    }
  memcpy (mac, ifr.ifr_hwaddr.sa_data, 6);

  // Get IP address
  if (ioctl (sockfd, SIOCGIFADDR, &ifr) < 0)
    {
      perror ("ioctl-SIOCGIFADDR");
      close (sockfd);
      return -1;
    }
  *ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

  close (sockfd);
  return 0;
}

int
send_arp_packet (uint32_t targetIp)
{
  uint8_t mac[6];
  uint32_t ip;
  char *iface = find_active_interface ();
  get_mac_ip (iface, mac, &ip); // Corrected to pass the address of ip

  int sockfd = socket (AF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
  if (sockfd < 0)
    {
      perror ("the socket fails to be created");
    }

  uint8_t destmac[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

  struct eth_header *eth = malloc (sizeof (struct eth_header));
  create_eth_header (eth, mac, destmac, ether_arp);
  struct arp_header *arp = malloc (sizeof (struct arp_header));
  create_arp_header (arp, arp_request, mac, ip, destmac, targetIp);
  size_t buffer_size = sizeof (struct eth_header) + sizeof (struct arp_header);
  uint8_t *buffer = (uint8_t *)malloc (buffer_size);
  memcpy (buffer, eth, sizeof (struct eth_header));
  memcpy (buffer + sizeof (struct eth_header), arp,
          sizeof (struct arp_header));

  struct sockaddr_ll socket_address;
  memset (&socket_address, 0, sizeof (struct sockaddr_ll));
  socket_address.sll_family = AF_PACKET;
  socket_address.sll_protocol = htons (ether_arp);
  socket_address.sll_ifindex = if_nametoindex (iface); // Use iface variable
  socket_address.sll_halen = ETH_ALEN;
  memcpy (socket_address.sll_addr, eth->destination, ETH_ALEN);

  // Sending
  ssize_t bytes_sent
      = sendto (sockfd, buffer, buffer_size, 0,
                (struct sockaddr *)&socket_address, sizeof (socket_address));
  if (bytes_sent < 0)
    {
      perror ("sendto");
    }
  free (buffer);
  free (eth); // Free allocated memory
  free (arp); // Free allocated memory
  close (sockfd);
}

int
warpHeaderAndSendTcp (uint8_t *tcpbuff, int tcpTotalLen, uint32_t *dest_ip,
                      uint8_t *dest_mac)
{
  uint8_t mac[6];
  uint32_t ip;
  char *iface = find_active_interface ();
  get_mac_ip (iface, mac, &ip); // Corrected to pass the address of ip
  int sockfd = socket (AF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
  if (sockfd < 0)
    {
      perror ("the socket fails to be created");
    }
  struct eth_header *eth = malloc (sizeof (struct eth_header));
  create_eth_header (eth, mac, dest_mac, ether_ip);

  struct ip_header *iph = malloc (sizeof (struct ip_header));
  create_ip_header (iph, ip, dest_ip, IPPROTO_TCP, 20 + tcpTotalLen);
  iph->checksum = cksum (iph, 20);

  uint8_t *buffer = malloc (sizeof (struct eth_header)
                            + sizeof (struct ip_header) + tcpTotalLen);
  memcpy (buffer, eth, sizeof (struct eth_header));
  memcpy (buffer + sizeof (struct eth_header), iph, sizeof (struct ip_header));
  memcpy (buffer + sizeof (struct eth_header) + sizeof (struct ip_header),
          tcpbuff, tcpTotalLen);
  struct sockaddr_ll socket_address;
  memset (&socket_address, 0, sizeof (struct sockaddr_ll));
  socket_address.sll_family = AF_PACKET;
  socket_address.sll_protocol = htons (ether_ip);
  socket_address.sll_ifindex = if_nametoindex (iface); // Use iface variable
  socket_address.sll_halen = ETH_ALEN;
  memcpy (socket_address.sll_addr, eth->destination, ETH_ALEN);

  // Sending
  ssize_t bytes_sent = sendto (
      sockfd, buffer,
      sizeof (struct eth_header) + sizeof (struct ip_header) + tcpTotalLen, 0,
      (struct sockaddr *)&socket_address, sizeof (socket_address));
  // if (bytes_sent < 0)
  //   {
  //     perror ("sendto");
  //   }
  // else
  //   {
  //     printf ("Packet sent. %zd bytes.\n", bytes_sent);
  //   }
  // print_headers (buffer);
  free (buffer);
  free (eth);
  free (iph);
  return 1;
}

int
send_raw_icmp_packet (uint8_t *buffer, size_t buffer_size)
{
  int sockfd;
  struct sockaddr_ll socket_address;
  ssize_t bytes_sent;

  // Create a raw socket that shall be used to send the packet
  sockfd = socket (AF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
  if (sockfd < 0)
    {
      perror ("Socket creation failed");
      return -1;
    }

  // Find the index of the interface to send the packet on
  char *iface = find_active_interface (); // Replace with your interface name
  socket_address.sll_ifindex = if_nametoindex (iface);
  if (socket_address.sll_ifindex == 0)
    {
      perror ("Interface not found");
      close (sockfd);
      return -1;
    }

  // Fill in the destination MAC and other details for the socket_address
  struct ethhdr *eth = (struct ethhdr *)buffer;
  socket_address.sll_family = AF_PACKET;
  socket_address.sll_protocol = htons (ETH_P_IP);
  socket_address.sll_halen = ETH_ALEN;
  memcpy (socket_address.sll_addr, eth->h_dest, ETH_ALEN);

  // Send the packet
  bytes_sent
      = sendto (sockfd, buffer, buffer_size, 0,
                (struct sockaddr *)&socket_address, sizeof (socket_address));
  if (bytes_sent < 0)
    {
      perror ("Packet send failed");
      close (sockfd);
      return -1;
    }

  printf ("Packet sent. %zd bytes sent.\n", bytes_sent);

  // Close the socket
  close (sockfd);
  return 0;
}

int
send_ip_packet (struct arp_header *receive_arp_header)
{
  printf ("-------------------------------------------------------------\n");
  size_t send_buffer_size = sizeof (struct eth_header)
                            + sizeof (struct ip_header)
                            + sizeof (struct icmp_echo);
  uint8_t *send_buffer = (uint8_t *)malloc (send_buffer_size);

  struct eth_header *send_eth
      = malloc (sizeof (struct eth_header)); // Use your struct
  create_eth_header (send_eth, receive_arp_header->tha,
                     receive_arp_header->sha, ether_ip);

  struct ip_header *send_ip
      = malloc (sizeof (struct ip_header)); // Use your struct
  create_ip_header (send_ip, receive_arp_header->tip, receive_arp_header->sip,
                    ip_protocol_icmp,
                    sizeof (struct ip_header) + sizeof (struct icmp_echo));

  struct icmp_echo *send_icmp
      = malloc (sizeof (struct icmp_echo)); // Use your struct
  create_icmp_echo_header (send_icmp);

  memcpy (send_buffer, send_eth, sizeof (struct eth_header));
  memcpy (send_buffer + sizeof (struct eth_header), send_ip,
          sizeof (struct ip_header));
  memcpy (send_buffer + sizeof (struct eth_header) + sizeof (struct ip_header),
          send_icmp, sizeof (struct icmp_echo));

  printf ("Size of ip_header: %lu\n", sizeof (struct ip_header));
  printf ("Size of icmp_header: %lu\n", sizeof (struct icmp_echo));
  printf ("Size of eth_header: %lu\n", sizeof (struct eth_header));
  // print_headers(send_buffer);

  send_raw_icmp_packet (send_buffer, send_buffer_size);
  free (send_eth);
  free (send_ip);
  free (send_icmp);
  free (send_buffer);
}
