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
#include <time.h>
#include <unistd.h> // sleep()
/*
        96 bit (12 bytes) pseudo header needed for tcp header checksum
   calculation
*/

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
main (int argc, char **argv)
{
  init_genrand (0);
  SEQNUM = genrand_int32 ();
  const uint32_t PORT = atoi (argv[1]);
  const uint32_t num_bytes = atoi (argv[2]);
  TAILQ_INIT (&tcp_inq);
  TAILQ_INIT (&tcp_ckq);
  pthread_t ptid;
  if (pthread_create (&ptid, NULL, &recv_func, NULL) != 0)
    exit (-1);

  if (pthread_mutex_init (&inq_lock, NULL) != 0)
    exit (-1);
  if (pthread_cond_init (&inq_cond, NULL) != 0)
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

  uint32_t ack_num = tcp_handshake (s, inet_addr (source_ip), sin);
  ack_num
      = tcp_stop_and_wait (s, inet_addr (source_ip), sin, ack_num, num_bytes);
  tcp_teardown (s, inet_addr (source_ip), sin, ack_num);

  return 0;
}