#include "tcp_op.h"
#include "mt19937ar.h"
#include <netinet/ip.h> // the IP protocol
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
uint32_t SEQNUM;

void *
tcp_check_timeout ()
{
  tcp_check_entry_t *ckq_e = NULL;
  pthread_mutex_lock (&inq_lock);

  TAILQ_FOREACH (ckq_e, &tcp_ckq, entry)
  {
    if (ckq_e->timeout <= time (0))
      {
        pthread_cond_signal (&inq_cond);
        return NULL;
      }
  }
  pthread_mutex_unlock (&inq_lock);
  return NULL;
}

void
handle_tcp (tcp_hdr_t *hdr)
{
  if (ntohs (hdr->des_port) == 1234)
    {
      tcp_packet_entry_t *e
          = (tcp_packet_entry_t *)calloc (1, sizeof (tcp_packet_entry_t));
      e->hdr = hdr;
      pthread_mutex_lock (&inq_lock);
      TAILQ_INSERT_HEAD (&tcp_inq, e, entry);
      pthread_cond_signal (&inq_cond);
      pthread_mutex_unlock (&inq_lock);
    }
}

tcp_hdr_t *
tcp_wait_packet (uint32_t target_ack, time_t timeout, uint8_t flag)
{
  tcp_check_entry_t *syn_check
      = (tcp_check_entry_t *)calloc (1, sizeof (tcp_check_entry_t));
  syn_check->timeout = timeout;
  syn_check->hdr = (tcp_hdr_t *)calloc (1, sizeof (tcp_hdr_t));
  tcp_gen_packet (syn_check->hdr, NULL, 0, 0, 0, 0, 0, 0, target_ack, flag, 0);
  TAILQ_INSERT_HEAD (&tcp_ckq, syn_check, entry);

  while (1)
    {
      // Shouldn't happen
      if (TAILQ_EMPTY (&tcp_ckq))
        return NULL;

      tcp_packet_entry_t *inq_e = NULL;
      tcp_check_entry_t *ckq_e = NULL;
      pthread_mutex_lock (&inq_lock);
      while (TAILQ_EMPTY (&tcp_inq))
        pthread_cond_wait (&inq_cond, &inq_lock);

      TAILQ_FOREACH (ckq_e, &tcp_ckq, entry)
      {
        TAILQ_FOREACH (inq_e, &tcp_inq, entry)
        {
          /* Match packet */
          if (tcp_cmp_flag (inq_e->hdr, ckq_e->hdr)
              && inq_e->hdr->ack_num == ckq_e->hdr->ack_num)
            {
              tcp_hdr_t *ret = inq_e->hdr;
              TAILQ_REMOVE (&tcp_inq, inq_e, entry);
              TAILQ_REMOVE (&tcp_ckq, ckq_e, entry);
              free (ckq_e->hdr);
              free (inq_e);
              free (ckq_e);
              pthread_mutex_unlock (&inq_lock);
              return ret;
            }
        }

        /* Timeout */

        if (ckq_e->timeout <= time (0))
          {
            printf ("Timeout\n");
            TAILQ_REMOVE (&tcp_ckq, ckq_e, entry);
            pthread_mutex_unlock (&inq_lock);
            return NULL;
          }
      }
      pthread_mutex_unlock (&inq_lock);
    }

  return NULL;
}

uint32_t
tcp_handshake (int socket, in_addr_t src_ip, struct sockaddr_in sin)
{
  // Datagram to represent the packet
  char datagram[4096];
  memset (datagram, 0, 4096);
  struct iphdr *iph = (struct iphdr *)datagram;
  uint16_t dst_port = ntohs (sin.sin_port);
  // TCP header
  tcp_hdr_t *tcph = (tcp_hdr_t *)(datagram + sizeof (struct iphdr));

  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof (struct iphdr) + sizeof (tcp_hdr_t);
  iph->id = htonl (54321); // Id of this packet
  iph->frag_off = 0;
  iph->ttl = 255;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0;      // Set to 0 before calculating checksum
  iph->saddr = src_ip; // Spoof the source ip address
  iph->daddr = sin.sin_addr.s_addr;

  iph->check = tcp_cksum ((unsigned short *)datagram, iph->tot_len);

  /* Send TCP SYN packet */
  tcp_gen_syn (tcph, src_ip, sin.sin_addr.s_addr, 1234, dst_port, SEQNUM,
               5840);
  if (sendto (socket, datagram, iph->tot_len, 0, (struct sockaddr *)&sin,
              sizeof (sin))
      < 0)
    {
      exit (-1);
    }

  /* Recieve TCP SYN ACK */
  SEQNUM++;
  tcp_hdr_t *synack_hdr = tcp_wait_packet (SEQNUM, time (0) + DEFAULT_RTO,
                                           (uint8_t)(SYN_FLAG | ACK_FLAG));
  uint32_t ack_num = ntohl (synack_hdr->seq_num) + 1;
  free (synack_hdr);
  /* Send TCP ACKs */
  tcp_gen_ack (tcph, src_ip, sin.sin_addr.s_addr, 1234, dst_port, SEQNUM,
               ack_num, 5840);

  if (sendto (socket, datagram, iph->tot_len, 0, (struct sockaddr *)&sin,
              sizeof (sin))
      < 0)
    {
      exit (-1);
    }
  return ack_num;
}

uint32_t
tcp_stop_and_wait (int socket, in_addr_t src_ip, struct sockaddr_in sin,
                   uint32_t ack_num, uint32_t num_byte)
{
  uint32_t quotient = num_byte / 1000;
  uint32_t remainder = num_byte % 1000;

  char datagram[4096];
  memset (datagram, 0, 4096);
  uint8_t *data
      = (uint8_t *)(datagram + sizeof (struct iphdr) + sizeof (tcp_hdr_t));
  strcpy ((char *)data, "A");
  struct iphdr *iph = (struct iphdr *)datagram;
  uint16_t dst_port = ntohs (sin.sin_port);
  // TCP header
  tcp_hdr_t *tcph = (tcp_hdr_t *)(datagram + sizeof (struct iphdr));

  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof (struct iphdr) + sizeof (tcp_hdr_t) + 1000;
  iph->id = htonl (54321); // Id of this packet
  iph->frag_off = 0;
  iph->ttl = 255;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0;      // Set to 0 before calculating checksum
  iph->saddr = src_ip; // Spoof the source ip address
  iph->daddr = sin.sin_addr.s_addr;

  iph->check = tcp_cksum ((unsigned short *)datagram, sizeof (struct iphdr));

  while (quotient != 0)
    {
      tcp_gen_packet (tcph, (uint8_t *)data, 1000, src_ip, sin.sin_addr.s_addr,
                      1234, dst_port, SEQNUM, ack_num,
                      (uint8_t)(PSH_FLAG | ACK_FLAG), 5840);
      if (sendto (socket, datagram, iph->tot_len, 0, (struct sockaddr *)&sin,
                  sizeof (sin))
          < 0)
        {
          exit (-1);
        }
      SEQNUM += 1000;
      tcp_hdr_t *dataack_hdr = tcp_wait_packet (SEQNUM, time (0) + DEFAULT_RTO,
                                                (uint8_t)(ACK_FLAG));
      ack_num = ntohl (dataack_hdr->seq_num);
      free (dataack_hdr);
      quotient--;
    }

  if (remainder == 0)
    return ack_num;
  iph->tot_len = sizeof (struct iphdr) + sizeof (tcp_hdr_t) + remainder;
  iph->check = 0;
  iph->check = tcp_cksum ((unsigned short *)datagram, sizeof (struct iphdr));
  tcp_gen_packet (tcph, (uint8_t *)data, remainder, src_ip,
                  sin.sin_addr.s_addr, 1234, dst_port, SEQNUM, ack_num,
                  (uint8_t)(PSH_FLAG | ACK_FLAG), 5840);
  if (sendto (socket, datagram, iph->tot_len, 0, (struct sockaddr *)&sin,
              sizeof (sin))
      < 0)
    {
      exit (-1);
    }
  SEQNUM += remainder;
  tcp_hdr_t *dataack_hdr
      = tcp_wait_packet (SEQNUM, time (0) + DEFAULT_RTO, (uint8_t)(ACK_FLAG));
  ack_num = ntohl (dataack_hdr->seq_num);
  free (dataack_hdr);
  return ack_num;
}

void
tcp_teardown (int socket, in_addr_t src_ip, struct sockaddr_in sin,
              uint32_t ack_num)
{
  // Datagram to represent the packet
  char datagram[4096];
  memset (datagram, 0, 4096);
  struct iphdr *iph = (struct iphdr *)datagram;
  uint16_t dst_port = ntohs (sin.sin_port);
  // TCP header
  tcp_hdr_t *tcph = (tcp_hdr_t *)(datagram + sizeof (struct iphdr));

  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof (struct iphdr) + sizeof (tcp_hdr_t);
  iph->id = htonl (54321); // Id of this packet
  iph->frag_off = 0;
  iph->ttl = 255;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0;      // Set to 0 before calculating checksum
  iph->saddr = src_ip; // Spoof the source ip address
  iph->daddr = sin.sin_addr.s_addr;

  iph->check = tcp_cksum ((unsigned short *)datagram, iph->tot_len);

  /* Send TCP FIN ACK packet */
  tcp_gen_packet (tcph, 0, 0, src_ip, sin.sin_addr.s_addr, 1234, dst_port,
                  SEQNUM, ack_num, (uint8_t)(FIN_FLAG | ACK_FLAG), 5840);
  if (sendto (socket, datagram, iph->tot_len, 0, (struct sockaddr *)&sin,
              sizeof (sin))
      < 0)
    {
      exit (-1);
    }

  /* Recieve TCP FIN ACK */
  SEQNUM++;
  tcp_hdr_t *finack_hdr = tcp_wait_packet (SEQNUM, time (0) + DEFAULT_RTO,
                                           (uint8_t)(FIN_FLAG | ACK_FLAG));
  ack_num = ntohl (finack_hdr->seq_num) + 1;
  free (finack_hdr);
  /* Send TCP ACK */
  tcp_gen_packet (tcph, 0, 0, src_ip, sin.sin_addr.s_addr, 1234, dst_port,
                  SEQNUM, ack_num, (uint8_t)(ACK_FLAG), 5840);

  if (sendto (socket, datagram, iph->tot_len, 0, (struct sockaddr *)&sin,
              sizeof (sin))
      < 0)
    {
      exit (-1);
    }
}