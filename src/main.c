/*
        Raw TCP packets
*/
#include "ip_stack/sendpacket.h"
#include "tcp/mt19937ar.h"
#include "tcp/tcp_helpers.h"
#include "tcp/tcp_op.h"
#include "tcp/tcp_protocol.h"
#include "tcp/tcp_stat.h"
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
uint8_t DST_MAC[6];

/* Stop when we recieved ARP reply */
int arp_header_ready = 0;

// Store instead of cache ARP since we will need to be able to send packets
// really frequently.
struct arp_header *receive_arp_header;

// Thread Function to ran until end of program. Handles ARP and TCP packet
// retrieval
void *
packet_receiver (void *arg)
{
  // Initializes buffers and raw socket to capture packets
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

      // We only accept packets coming toward our HOST
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
          arp_check = 0;
          arp_header_ready = 1;
        }
      if (ntohs (eth_header->h_proto) == ETH_P_IP)
        {
          struct iphdr *ip_header
              = (struct iphdr *)(buffer + sizeof (struct ethhdr));
          if (ip_header->protocol == IPPROTO_TCP)
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

int
main (int argc, char **argv)
{
  // Resets IP tables settings and drop the auto RST response on ports
  system ("iptables -P OUTPUT ACCEPT");
  system ("iptables -F OUTPUT");
  system ("iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP");

  initializeTCP (argc, argv);
  // Initializes the socket and resourcesused to recieve packets
  int sock_r;
  pthread_t thread_id;
  receive_arp_header = malloc (sizeof (struct arp_header));

  sock_r = socket (AF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
  if (sock_r < 0)
    {
      perror ("Socket Error");
      return -1;
    }

  pthread_t recv_tid;
  if (pthread_create (&thread_id, NULL, packet_receiver, &sock_r))
    {
      fprintf (stderr, "Error creating thread\n");
      return -1;
    }

  send_arp_packet (DST_IP);
  while (!arp_header_ready)
    {
      sleep (1);
    }
  perror ("ARP packet recieved");
  memcpy (DST_MAC, receive_arp_header->sha, 6);
  perror ("Handshaking");
  uint32_t ack_num = tcp_handshake ();
  printf ("***** TCP Analytics *****\n");
  printf ("***** \n");
  if (strcmp (VARIANT, "SAW") == 0)
    tcp_stop_and_wait (ack_num);
  else if (strcmp (VARIANT, "SWCC") == 0)
    tcp_send_sliding_window_slowS_fastR (ack_num);
  else if (strcmp (VARIANT, "SWF") == 0)
    tcp_send_sliding_window_fixed (10, ack_num);
  else
    printf ("Invalid Variant %s", VARIANT);
  tcp_teardown (ack_num);

  FILE *fp;
  fp = fopen ("tcprtt.txt", "w");

  tcp_rtt_entry_t *rtt_e = NULL;
  int rtt_count = 1;
  long double rtt_avg = 0;
  long double rtt_max = 0;
  long double rtt_min = SEC_TO_NS (20); //  Unlikely to have 20s RTT
  TAILQ_FOREACH (rtt_e, &tcp_rttQ, entry)
  {
    rtt_avg += rtt_e->rtt;
    rtt_max = rtt_max >= rtt_e->rtt ? rtt_max : rtt_e->rtt;
    rtt_min = rtt_min < rtt_e->rtt ? rtt_min : rtt_e->rtt;
    fprintf (fp, "%d %Lf\n", rtt_count, rtt_e->rtt);
    rtt_count++;
  }
  close (fp);
  rtt_avg = rtt_avg / (rtt_count - 1);

  tcp_bandwidth_entry_t *bw_e = NULL;
  long double bw = 0;
  int bandwidth_count = 0;
  TAILQ_FOREACH (bw_e, &tcp_bwQ, entry)
  {
    bw += bw_e->bw;
    bandwidth_count++;
  }
  bw = bw / bandwidth_count;

  tcp_congest_entry_t *cwnd_e = NULL;
  int cwnd_count = 1;

  fp = fopen ("tcpcong.txt", "w");
  TAILQ_FOREACH (cwnd_e, &tcp_congQ, entry)
  {
    fprintf (fp, "%d %u\n", cwnd_count, cwnd_e->cwnd);
    cwnd_count++;
  }
  printf ("***** Average RTT: %Lf ms\n", rtt_avg);
  printf ("***** Maximum RTT: %Lf ms\n", rtt_max);
  printf ("***** Minimum RTT: %Lf ms\n", rtt_min);
  printf ("***** Bandwidth Estimate: %Lf Kbits/s\n", bw);
  printf (
      "***** Sliding Window Size Best Estimate Based on Bandwidth: %Lf byte\n",
      (rtt_avg / 1000) * (bw * 1000) / 8);
  printf ("***** \n");
  printf ("*******************************\n");
  system ("iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP");

  // ... fill the array somehow ...

  fclose (fp);
  return 0;
}