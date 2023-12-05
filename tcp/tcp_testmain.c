/*
        Raw TCP packets
*/
#include "mt19937ar.h"
#include "pthread.h"
#include "tcp_op.h"
#include "tcp_protocol.h"
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
#include <unistd.h>     // sleep()
#define PORT 4462
/*
        96 bit (12 bytes) pseudo header needed for tcp header checksum
   calculation
*/
struct pseudo_header
{
  u_int32_t source_address;
  u_int32_t dest_address;
  u_int8_t placeholder;
  u_int8_t protocol;
  u_int16_t tcp_length;
};

void
open ()
{
  struct sockaddr_in addr;
  int fd;

  fd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fd == -1)
    {
      printf ("Error opening socket\n");
      return -1;
    }

  addr.sin_port = htons (1234);
  addr.sin_addr.s_addr = 0;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_family = AF_INET;

  if (bind (fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1)
    {
      printf ("Error binding socket\n");
      return -1;
    }

  printf ("Successfully bound to port %u\n", 1234);

  // Now server is ready to listen and verification
  if ((listen (fd, 5)) != 0)
    {
      printf ("Listen failed...\n");
      exit (0);
    }
}
tcp_hdr_t
recving (int s)
{
  int sock_r;
  unsigned char *buffer = (unsigned char *)malloc (65536);
  memset (buffer, 0, 65536);
  struct sockaddr_ll saddr;
  int saddr_len = sizeof (saddr);

  sock_r = socket (AF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
  if (sock_r < 0)
    {
      perror ("Socket Error");
      exit (129);
    }

  while (1)
    {
      int buflen
          = recvfrom (sock_r, buffer, 65536, 0, (struct sockaddr *)&saddr,
                      (socklen_t *)&saddr_len);
      if (buflen < 0)
        {
          printf ("Error in reading recvfrom function\n");
          exit (129);
        }
      if (saddr.sll_pkttype == PACKET_HOST)
        {
          struct ethhdr *eth_header = (struct ethhdr *)buffer;
          // Check EtherType
          if (ntohs (eth_header->h_proto) == ETH_P_ARP)
            {
              printf ("Received ARP packet\n");
            }
          else if (ntohs (eth_header->h_proto) == ETH_P_IP)
            {
              struct iphdr *ip_header
                  = (struct iphdr *)(buffer + sizeof (struct ethhdr));
              if (ip_header->protocol == IPPROTO_ICMP)
                {
                  printf ("Received ICMP packet\n");
                  struct in_addr add;
                  add.s_addr = ip_header->daddr;
                  printf ("DST IP: %s\n", inet_ntoa (add));
                  // Further processing for ICMP packet
                  // print_headers(buffer);
                }
              else if (ip_header->protocol == IPPROTO_TCP)
                {
                  tcp_hdr_t *tcp_header
                      = (tcp_hdr_t *)(buffer + sizeof (struct ethhdr)
                                      + sizeof (struct iphdr));
                  if (ntohs (tcp_header->des_port) == 1234)
                    {
                      print_tcp_hdr (tcp_header);
                      tcp_hdr_t ret = *tcp_header;
                      free (buffer);
                      return ret;
                    }
                }
            }
        }
    }
}

void *
recv_func ()
{
  int sock_r;
  unsigned char *buffer = (unsigned char *)malloc (65536);
  memset (buffer, 0, 65536);
  struct sockaddr_ll saddr;
  int saddr_len = sizeof (saddr);

  sock_r = socket (AF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
  if (sock_r < 0)
    {
      perror ("Socket Error");
      exit (129);
    }

  while (1)
    {
      int buflen
          = recvfrom (sock_r, buffer, 65536, 0, (struct sockaddr *)&saddr,
                      (socklen_t *)&saddr_len);
      if (buflen < 0)
        {
          printf ("Error in reading recvfrom function\n");
          exit (129);
        }
      if (saddr.sll_pkttype == PACKET_HOST)
        {
          struct ethhdr *eth_header = (struct ethhdr *)buffer;
          if (ntohs (eth_header->h_proto) == ETH_P_IP)
            {
              struct iphdr *ip_header
                  = (struct iphdr *)(buffer + sizeof (struct ethhdr));
              if (ip_header->protocol == IPPROTO_TCP)
                {
                  tcp_hdr_t *tcp_header
                      = (tcp_hdr_t *)(buffer + sizeof (struct ethhdr)
                                      + sizeof (struct iphdr));
                  tcp_hdr_t *input
                      = (tcp_hdr_t *)calloc (1, sizeof (tcp_hdr_t));
                  memcpy (input, tcp_header, sizeof (tcp_hdr_t));
                  handle_tcp (input);
                }
            }
        }
    }
}

int
main (void)
{
  init_genrand (0);
  uint32_t init_seq = genrand_int32 ();

  TAILQ_INIT (&pq);
  pthread_t ptid;
  if (pthread_create (&ptid, NULL, &recv_func, NULL) != 0)
    exit (-1);
  // Create a raw socket
  int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
  if (s == -1)
    {
      // socket creation failed, may be because of non-root privileges
      perror ("Failed to create socket");
      exit (1);
    }

  // Datagram to represent the packet
  char datagram[4096], source_ip[32], *data, *pseudogram;
  char buffer[5804];
  // zero out the packet buffer
  memset (datagram, 0, 4096);
  memset (buffer, 0, 5804);
  // IP header
  struct iphdr *iph = (struct iphdr *)datagram;

  // TCP header
  tcp_hdr_t *tcph = (tcp_hdr_t *)(datagram + sizeof (struct ip));
  struct sockaddr_in sin;
  struct pseudo_header psh;

  // Data part
  // data = datagram + sizeof (struct iphdr) + sizeof (tcp_hdr_t);
  // strcpy (data, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");

  // some address resolution
  strcpy (source_ip, "10.0.0.1");
  sin.sin_family = AF_INET;
  sin.sin_port = htons (PORT);
  sin.sin_addr.s_addr = inet_addr ("10.0.0.2");

  // Fill in the IP Header
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof (struct iphdr) + sizeof (tcp_hdr_t);
  iph->id = htonl (54321); // Id of this packet
  iph->frag_off = 0;
  iph->ttl = 255;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0;                     // Set to 0 before calculating checksum
  iph->saddr = inet_addr (source_ip); // Spoof the source ip address
  iph->daddr = sin.sin_addr.s_addr;

  // Ip checksum
  iph->check = tcp_cksum ((unsigned short *)datagram, iph->tot_len);

  // TCP Header
  tcp_gen_syn (tcph, inet_addr (source_ip), sin.sin_addr.s_addr, 1234, PORT,
               init_seq, 5840);

  // IP_HDRINCL to tell the kernel that headers are included in the packet
  int one = 1;
  const int *val = &one;

  if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
      perror ("Error setting IP_HDRINCL");
      exit (0);
    }

  // loop if you want to flood :)
  // Send the packet
  if (sendto (s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin,
              sizeof (sin))
      < 0)
    {
      perror ("sendto failed");
    }
  // Data send successfully
  else
    {
      printf ("Packet Send. Length : %d \n", iph->tot_len);
    }

  sleep (2);
  // // sleep for 1 seconds
  // tcp_hdr_t synack_hdr = recving (s);
  // print_tcp_hdr (&synack_hdr);
  // memset (tcph, 0, sizeof (tcp_hdr_t));
  // tcp_gen_ack (tcph, inet_addr (source_ip), sin.sin_addr.s_addr, 1234, PORT,
  //              ++init_seq, ntohl (synack_hdr.seq_num) + 1, 5840);
  // print_tcp_hdr (tcph);

  // iph->id = htonl (54322); // Id of this packet
  // iph->check = 0;
  // iph->check = tcp_cksum ((unsigned short *)datagram, iph->tot_len);

  // if (sendto (s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin,
  //             sizeof (sin))
  //     < 0)
  //   {
  //     perror ("sendto failed");
  //   }
  // // Data send successfully
  // else
  //   {
  //     printf ("Packet Send. Length : %d \n", iph->tot_len);
  //   }
  // sleep (1);

  // // Data part
  // data = datagram + sizeof (struct iphdr) + sizeof (tcp_hdr_t);
  // strcpy (data, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");

  // iph->id = htonl (54323); // Id of this packet
  // iph->tot_len = sizeof (struct iphdr) + sizeof (tcp_hdr_t) + strlen (data);
  // iph->check = 0;
  // iph->check = tcp_cksum ((unsigned short *)datagram, iph->tot_len);

  // tcp_gen_packet (tcph, (uint8_t *)data, strlen (data), inet_addr
  // (source_ip),
  //                 sin.sin_addr.s_addr, 1234, PORT, init_seq,
  //                 ntohl (synack_hdr.seq_num) + 1, (uint8_t)(ACK_FLAG),
  //                 5840);
  // print_tcp_hdr (tcph);
  // if (sendto (s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin,
  //             sizeof (sin))
  //     < 0)
  //   {
  //     perror ("sendto failed");
  //   }
  // // Data send successfully
  // else
  //   {
  //     printf ("Packet Send. Length : %d \n", iph->tot_len);
  //   }

  // tcp_hdr_t dataack_hdr = recving (s);
  // iph->id = htonl (54324); // Id of this packet
  // iph->tot_len = sizeof (struct iphdr) + sizeof (tcp_hdr_t);
  // iph->check = 0;
  // iph->check = tcp_cksum ((unsigned short *)datagram, iph->tot_len);

  // init_seq += 26;
  // tcp_gen_packet (tcph, 0, 0, inet_addr (source_ip), sin.sin_addr.s_addr,
  // 1234,
  //                 PORT, init_seq, ntohl (dataack_hdr.seq_num),
  //                 (uint8_t)(FIN_FLAG | ACK_FLAG), 5840);
  // print_tcp_hdr (tcph);
  // if (sendto (s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin,
  //             sizeof (sin))
  //     < 0)
  //   {
  //     perror ("sendto failed");
  //   }
  // // Data send successfully
  // else
  //   {
  //     printf ("Packet Send. Length : %d \n", iph->tot_len);
  //   }

  // tcp_hdr_t finack_hdr = recving (s);
  // iph->id = htonl (54325); // Id of this packet
  // iph->tot_len = sizeof (struct iphdr) + sizeof (tcp_hdr_t);
  // iph->check = 0;
  // iph->check = tcp_cksum ((unsigned short *)datagram, iph->tot_len);

  // printf ("%u, %u\n", init_seq, ntohl (finack_hdr.ack_num));
  // tcp_gen_packet (tcph, 0, 0, inet_addr (source_ip), sin.sin_addr.s_addr,
  // 1234,
  //                 PORT, ++init_seq, ntohl (finack_hdr.seq_num) + 1,
  //                 (uint8_t)(ACK_FLAG), 5840);
  // print_tcp_hdr (tcph);
  // if (sendto (s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin,
  //             sizeof (sin))
  //     < 0)
  //   {
  //     perror ("sendto failed");
  //   }
  // // Data send successfully
  // else
  //   {
  //     printf ("Packet Send. Length : %d \n", iph->tot_len);
  //   }
  return 0;
}