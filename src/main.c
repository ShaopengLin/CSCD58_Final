/*
        Raw TCP packets
*/
#include "ip_stack/sendpacket.h"
#include "pthread.h"
#include "tcp/mt19937ar.h"
#include "tcp/tcp_op.h"
#include "tcp/tcp_protocol.h"
#include <arpa/inet.h> // inet_addr
#include <errno.h>     //For errno - the error number
#include <linux/if_packet.h>
#include <net/ethernet.h> // the L2 protocols
#include <netinet/ip.h>   // the IP protocol
#include <netinet/tcp.h>  //Provides declarations for tcp header
#include <pthread.h>
#include <stdio.h>      //for printf
#include <stdlib.h>     //for exit(0);
#include <string.h>     //memset
#include <sys/socket.h> //for socket ofcourse
#include <time.h>
#include <unistd.h> // sleep()
/*
        96 bit (12 bytes) pseudo header needed for tcp header checksum
   calculation
*/
uint8_t DEST_MAC[6];

int arp_header_ready = 0;

struct arp_header *receive_arp_header;
// Function that will run in a separate thread
void *
packet_receiver (void *arg)
{
  int sock_r = *(int *)arg;
  unsigned char *buffer = (unsigned char *)malloc (65536);
  memset (buffer, 0, 65536);
  struct sockaddr_ll saddr;
  int saddr_len = sizeof (saddr);
  int arp_check = 1;

  while (1)
    {
      int buflen
          = recvfrom (sock_r, buffer, 65536, 0, (struct sockaddr *)&saddr,
                      (socklen_t *)&saddr_len);
      if (buflen < 0)
        {
          printf ("Error in reading recvfrom function\n");
          break; // Exit loop on error
        }

      if (saddr.sll_pkttype == PACKET_OUTGOING)
        {
          continue; // Skip processing this packet
        }

      struct ethhdr *eth_header = (struct ethhdr *)buffer;
      // Check EtherType
      if (ntohs (eth_header->h_proto) == ETH_P_ARP && arp_check)
        {
          printf ("Received ARP packet\n");
          memcpy (receive_arp_header, buffer + sizeof (struct ethhdr),
                  sizeof (struct arp_header));

          if (handle_arp (buffer) == 1)
            {
              printf ("1\n");
              // receive_arp_header = (struct arp_header *)(buffer +
              // sizeof(struct ethhdr)); memcpy(receive_arp_header, buffer +
              // sizeof(struct ethhdr), sizeof(struct arp_header));
              print_ARP_headers (receive_arp_header);
            }
          arp_check = 0;
          arp_header_ready = 1;
        }
      if (ntohs (eth_header->h_proto) == ETH_P_IP)
        {
          struct iphdr *ip_header
              = (struct iphdr *)(buffer + sizeof (struct ethhdr));
          if (ip_header->protocol == IPPROTO_ICMP)
            {
              printf ("Received ICMP packet\n");
              // Further processing for ICMP packet
              print_headers (buffer);
            }
          else if (ip_header->protocol == IPPROTO_TCP)
            {
              tcp_hdr_t *tcp_header
                  = (tcp_hdr_t *)(buffer + sizeof (struct ethhdr)
                                  + sizeof (struct iphdr));
              tcp_hdr_t *input = (tcp_hdr_t *)calloc (1, sizeof (tcp_hdr_t));
              memcpy (input, tcp_header, sizeof (tcp_hdr_t));
              handle_tcp (input);
            }
        }
    }

  // free(buffer);
  return NULL;
}

void
main (int argc, char **argv)
{
  int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  struct sockaddr_ll socket_address;
  memset(&socket_address, 0, sizeof(struct sockaddr_ll));
  socket_address.sll_family = AF_PACKET;
  socket_address.sll_protocol = htons(ether_arp);
  socket_address.sll_ifindex = if_nametoindex(find_active_interface()); // Use iface variable
  socket_address.sll_halen = ETH_ALEN;
  initSocket(sockfd, socket_address);
  int sock_r;
  pthread_t thread_id;
  receive_arp_header = malloc (sizeof (struct arp_header));

  sock_r = socket (AF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
  if (sock_r < 0)
    {
      perror ("Socket Error");
      return -1;
    }

  init_genrand (0);
  SEQNUM = genrand_int32 ();
  const uint32_t PORT = atoi (argv[1]);
  const uint32_t num_bytes = atoi (argv[2]);
  TAILQ_INIT (&tcp_inq);
  TAILQ_INIT (&tcp_ckq);
  pthread_t recv_tid;
  pthread_t timer_tid;
  if (pthread_mutex_init (&inq_lock, NULL) != 0)
    exit (-1);
  if (pthread_cond_init (&inq_cond, NULL) != 0)
    exit (-1);

  // Packet Reciever

  // Create a separate thread for receiving packets
  if (pthread_create (&thread_id, NULL, packet_receiver, &sock_r))
    {
      fprintf (stderr, "Error creating thread\n");
      return -1;
    }

  // if (pthread_create (&recv_tid, NULL, &recv_func, NULL) != 0)
  //   exit (-1);
  if (pthread_create (&timer_tid, NULL, &tcp_check_timeout, NULL) != 0)
    exit (-1);
  // Create a raw socket
  int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
  if (s == -1)
    {
      // socket creation failed, may be because of non-root privileges
      perror ("Failed to create socket");
      exit (1);
    }
  // Optionally wait for the thread to finish
  // pthread_join(thread_id, NULL);

  const char *ip_str = "10.1.1.2";
  uint32_t targetIp = inet_addr (ip_str);

  if (targetIp == INADDR_NONE)
    {
      fprintf (stderr, "Invalid IP address format: %s\n", ip_str);
      return 1;
    }

  send_arp_packet (targetIp);
  while (!arp_header_ready)
    {
      sleep (1);
    }
  printf ("1");
  print_ARP_headers (receive_arp_header);
  printf ("1");
  // if (receive_arp_header != NULL)
  //   {
  //     // print_ARP_headers(receive_arp_header);
  //     send_ip_packet (receive_arp_header);
  //   }

  // close(sock_r);
  // return 0;

  // Datagram to represent the packet
  char source_ip[32];
  struct sockaddr_in sin;

  // some address resolution
  strcpy (source_ip, "10.0.0.1");
  sin.sin_family = AF_INET;
  sin.sin_port = htons (PORT);
  sin.sin_addr.s_addr = inet_addr ("10.0.0.2");

  // IP_HDRINCL to tell the kernel that headers are included in the packet
  int one = 1;
  const int *val = &one;

  if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
      perror ("Error setting IP_HDRINCL");
      exit (0);
    }

  perror ("Handshaking");
  uint32_t ack_num
      = tcp_handshake (1234, PORT, targetIp, receive_arp_header->sha);
  // ack_num = tcp_stop_and_wait (1234, PORT, targetIp,
  // receive_arp_header->sha,
  //                              ack_num, num_bytes);
  // ack_num = tcp_send_sliding_window_test (s, inet_addr (source_ip), sin,
  //                                         ack_num, num_bytes);
  // ack_num = tcp_send_sliding_window_fixed (
  //     1234, PORT, targetIp, receive_arp_header->sha, ack_num, num_bytes);
  ack_num = tcp_send_sliding_window_slowS_fastR (
      1234, PORT, targetIp, receive_arp_header->sha, ack_num, num_bytes);
  tcp_teardown (1234, PORT, targetIp, receive_arp_header->sha, ack_num);
}