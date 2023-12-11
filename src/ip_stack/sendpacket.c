#include "sendpacket.h"
#include "utils.h"
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> 
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

//global socket used to send tcp requests instead of create and close it in sending each packet
int sockfd;
struct sockaddr_ll socket_address;

//using in main funciton to set one sockfd and socket_address and use it to send packets
int
initTCPSocket ()
{
  sockfd = socket (AF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
  char *iface = find_active_interface ();
  memset (&socket_address, 0, sizeof (struct sockaddr_ll));
  socket_address.sll_family = AF_PACKET;
  socket_address.sll_protocol = htons (ether_arp);
  socket_address.sll_ifindex = if_nametoindex (iface); // Use iface variable
  socket_address.sll_halen = ETH_ALEN;
  free (iface);
}

//get the current interface neame of the host
char *
find_active_interface ()
{
  struct ifaddrs *head, *current;
  int family;
  char *interface_name = NULL;

  if (getifaddrs (&head) == -1)
    {
      perror ("getifaddrs");
      return NULL;
    }
  //loop throught the interfaces to see if the interface is usable
  for (current = head; current != NULL; current = current->ifa_next)
    {
      if (current->ifa_addr == NULL)
        continue;

      family = current->ifa_addr->sa_family;

      // Check interfaces which is up and not a loopback
      if ((family == AF_INET || family == AF_INET6)
          && (current->ifa_flags & IFF_UP) && !(current->ifa_flags & IFF_LOOPBACK))
        {
          interface_name = strdup (current->ifa_name);
          break;
        }
    }

  freeifaddrs (head);
  return interface_name;
}

//get the mac address and ip of the current interface to determine the source mac and ip
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

// send a arp request of the target IP
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

  //use the broadcast address to send out the arp request
  uint8_t destmac[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

  //set up ethernet header
  struct eth_header *eth = malloc (sizeof (struct eth_header));
  create_eth_header (eth, mac, destmac, ether_arp);

  //set up arp header
  struct arp_header *arp = malloc (sizeof (struct arp_header));
  create_arp_header (arp, arp_request, mac, ip, destmac, targetIp);

  //coppy to buffer
  uint8_t *buffer = (uint8_t *)malloc (sizeof (struct eth_header) + sizeof (struct arp_header));
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
      = sendto (sockfd, buffer, sizeof (struct eth_header) + sizeof (struct arp_header), 0,
                (struct sockaddr *)&socket_address, sizeof (socket_address));
  if (bytes_sent < 0)
    {
      perror ("sendto");
    }
  free (buffer);
  free (eth); // Free allocated memory
  free (arp); // Free allocated memory
  free (iface);
  close (sockfd);
}

int
warpHeaderAndSendTcp (uint8_t *tcpbuff, int tcpTotalLen, uint32_t *dest_ip,
                      uint8_t *dest_mac)
{
  uint8_t mac[6];
  uint32_t ip;
  //find current interface
  char *iface = find_active_interface ();
  //get the interface mac address and ip
  get_mac_ip (iface, mac, &ip);

  //create ethernet header
  struct eth_header *eth = malloc (sizeof (struct eth_header));
  create_eth_header (eth, mac, dest_mac, ether_ip);

  //create ip header
  struct ip_header *iph = malloc (sizeof (struct ip_header));
  create_ip_header (iph, ip, dest_ip, IPPROTO_TCP, 20 + tcpTotalLen);
  iph->checksum = cksum (iph, 20);

  //put all headers into the buffer
  uint8_t *buffer = malloc (sizeof (struct eth_header)
                            + sizeof (struct ip_header) + tcpTotalLen);
  memcpy (buffer, eth, sizeof (struct eth_header));
  memcpy (buffer + sizeof (struct eth_header), iph, sizeof (struct ip_header));
  memcpy (buffer + sizeof (struct eth_header) + sizeof (struct ip_header),
          tcpbuff, tcpTotalLen);
  memcpy (socket_address.sll_addr, eth->destination, ETH_ALEN);

  //send using global socket
  ssize_t bytes_sent = sendto (sockfd, buffer, sizeof (struct eth_header) + sizeof (struct ip_header) + tcpTotalLen, 0,
      (struct sockaddr *)&socket_address, sizeof (socket_address));
  if(bytes_sent<0){
    perror("error in sending tcp packets");
  }
  free (buffer);
  free (eth);
  free (iph);
  free (iface);
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
  char *iface = find_active_interface ();
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

  // Close the socket
  close (sockfd);
  free (iface);
  return 0;
}

uint16_t
send_ip_packet (struct arp_header *receive_arp_header, int size)
{
  size_t send_buffer_size
      = sizeof (struct eth_header) + sizeof (struct ip_header)
        + sizeof (struct icmp_echo) + size * sizeof (uint8_t);
  uint8_t *send_buffer = (uint8_t *)malloc (send_buffer_size);

  struct eth_header *send_eth = calloc (1, sizeof (struct eth_header));
  create_eth_header (send_eth, receive_arp_header->tha,
                     receive_arp_header->sha, ether_ip);

  struct ip_header *send_ip = calloc (1, sizeof (struct ip_header));
  create_ip_header (send_ip, receive_arp_header->tip, receive_arp_header->sip,
                    ip_protocol_icmp,
                    sizeof (struct ip_header) + sizeof (struct icmp_echo)
                        + size * sizeof (uint8_t));
  send_ip->checksum = cksum (send_ip, 20 + sizeof (struct icmp_header));

  struct icmp_echo *send_icmp
      = calloc (1, sizeof (struct icmp_echo) + size * sizeof (uint8_t));
  create_icmp_echo_header (send_icmp, size);

  // Copy our raw data to buffer and ready to send
  memcpy (send_buffer, send_eth, sizeof (struct eth_header));
  memcpy (send_buffer + sizeof (struct eth_header), send_ip,
          sizeof (struct ip_header));
  memcpy (send_buffer + sizeof (struct eth_header) + sizeof (struct ip_header),
          send_icmp, sizeof (struct icmp_echo) + size * sizeof (uint8_t));
  uint16_t id = send_icmp->identifier;

  // Send raw socket
  send_raw_icmp_packet (send_buffer, send_buffer_size);

  free (send_eth);
  free (send_ip);
  free (send_icmp);
  free (send_buffer);

  // Return id so we can add to icmp list
  return (id);
}
