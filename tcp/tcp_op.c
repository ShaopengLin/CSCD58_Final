#include "tcp_op.h"
#include "mt19937ar.h"
#include <netinet/ip.h> // the IP protocol
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
uint32_t SEQNUM;
uint16_t RWND;

uint64_t
SEC_TO_NS (time_t sec)
{
  return (sec) * 1000000000;
};

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

void *
tcp_check_timeout ()
{
  while (1)
    {
      tcp_check_entry_t *ckq_e = NULL;
      pthread_mutex_lock (&inq_lock);

      TAILQ_FOREACH (ckq_e, &tcp_ckq, entry)
      {
        if (ckq_e->timeout <= getNano ())
          pthread_cond_signal (&inq_cond);
      }
      pthread_mutex_unlock (&inq_lock);
    }

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
      TAILQ_INSERT_TAIL (&tcp_inq, e, entry);
      pthread_cond_signal (&inq_cond);
      pthread_mutex_unlock (&inq_lock);
    }
}

tcp_hdr_t *
tcp_wait_packet (uint32_t target_ack, uint64_t timeout, uint8_t flag)
{
  tcp_check_entry_t *syn_check
      = (tcp_check_entry_t *)calloc (1, sizeof (tcp_check_entry_t));
  syn_check->timeout = timeout;
  syn_check->hdr = (tcp_hdr_t *)calloc (1, sizeof (tcp_hdr_t));
  tcp_gen_packet (syn_check->hdr, NULL, 0, 0, 0, 0, 0, 0, target_ack, flag, 0);
  pthread_mutex_lock (&inq_lock);
  TAILQ_INSERT_TAIL (&tcp_ckq, syn_check, entry);
  pthread_mutex_unlock (&inq_lock);
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

        if (ckq_e->timeout <= getNano ())
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

void
tcp_add_sw_packet (uint32_t target_ack, uint64_t sent_time, uint64_t timeout,
                   size_t len)
{
  tcp_check_entry_t *syn_check
      = (tcp_check_entry_t *)calloc (1, sizeof (tcp_check_entry_t));
  syn_check->sent_time = sent_time;
  syn_check->timeout = sent_time + timeout;
  syn_check->hdr = (tcp_hdr_t *)calloc (1, sizeof (tcp_hdr_t));
  syn_check->len = len;
  syn_check->RTT_counted = false;
  tcp_gen_packet (syn_check->hdr, NULL, 0, 0, 0, 0, 0, 0, target_ack,
                  (uint8_t)(ACK_FLAG), 0);
  TAILQ_INSERT_TAIL (&tcp_ckq, syn_check, entry);
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
  tcp_hdr_t *synack_hdr = tcp_wait_packet (SEQNUM, getNano () + DEFAULT_RTO,
                                           (uint8_t)(SYN_FLAG | ACK_FLAG));
  uint32_t ack_num = ntohl (synack_hdr->seq_num) + 1;
  RWND = ntohs (synack_hdr->window);
  printf ("\nWINDOW: %u\n", RWND);
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
  size_t size = 100;
  uint32_t quotient = num_byte / size;
  uint32_t remainder = num_byte % size;

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
  iph->tot_len = sizeof (struct iphdr) + sizeof (tcp_hdr_t) + size;
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
      tcp_gen_packet (tcph, (uint8_t *)data, size, src_ip, sin.sin_addr.s_addr,
                      1234, dst_port, SEQNUM, ack_num,
                      (uint8_t)(PSH_FLAG | ACK_FLAG), 5840);
      if (sendto (socket, datagram, iph->tot_len, 0, (struct sockaddr *)&sin,
                  sizeof (sin))
          < 0)
        {
          exit (-1);
        }
      SEQNUM += size;
      free (tcp_wait_packet (SEQNUM, getNano () + DEFAULT_RTO,
                             (uint8_t)(ACK_FLAG)));
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
  tcp_hdr_t *dataack_hdr = tcp_wait_packet (SEQNUM, getNano () + DEFAULT_RTO,
                                            (uint8_t)(ACK_FLAG));
  ack_num = ntohl (dataack_hdr->seq_num);
  free (dataack_hdr);
  return ack_num;
}

uint32_t
tcp_send_sliding_window_fixed (int socket, in_addr_t src_ip,
                               struct sockaddr_in sin, uint32_t ack_num,
                               uint32_t num_byte)

{
  size_t size = 1460;
  uint32_t num_packet = num_byte / size;
  num_packet += num_byte % size > 0 ? 1 : 0;
  uint32_t MAX_ACK = SEQNUM;
  uint16_t CWND = size * 5;
  uint32_t WND_SENT = 0;
  uint32_t BYTE_SENT = 0;
  uint32_t next_size
      = num_byte - BYTE_SENT >= size ? size : num_byte - BYTE_SENT;
  char datagram[4096];
  memset (datagram, 0, 4096);
  uint8_t *data
      = (uint8_t *)(datagram + sizeof (struct iphdr) + sizeof (tcp_hdr_t));
  struct iphdr *iph = (struct iphdr *)datagram;
  uint16_t dst_port = ntohs (sin.sin_port);
  // TCP header
  tcp_hdr_t *tcph = (tcp_hdr_t *)(datagram + sizeof (struct iphdr));

  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof (struct iphdr) + sizeof (tcp_hdr_t) + next_size;
  iph->id = htonl (54321); // Id of this packet
  iph->frag_off = 0;
  iph->ttl = 255;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0;      // Set to 0 before calculating checksum
  iph->saddr = src_ip; // Spoof the source ip address
  iph->daddr = sin.sin_addr.s_addr;

  iph->check = tcp_cksum ((unsigned short *)datagram, sizeof (struct iphdr));

  while (num_packet != 0)
    {
      pthread_mutex_lock (&inq_lock);
      // printf ("QUOTIENT: %u\n", quotient);

      /* When CWND full, we restart only when new packets or timeout happen
       */
      if (WND_SENT + next_size > CWND)
        {
          pthread_cond_wait (&inq_cond, &inq_lock);
        }
      /* Handle Timeout. Later need to do retransmit, changing SENT and SEQ
       */
      tcp_check_entry_t *ckq_e = NULL;
      bool retrans = false;
      TAILQ_FOREACH (ckq_e, &tcp_ckq, entry)
      {
        if (ckq_e->timeout <= getNano ())
          {
            SEQNUM = ntohl (ckq_e->hdr->ack_num) - ckq_e->len;
            retrans = true;
            perror ("RETRANSMIT");
            break;
          }
      }

      tcp_packet_entry_t *inq_e = NULL;
      ckq_e = NULL;
      if (retrans)
        {
          while (!TAILQ_EMPTY (&tcp_ckq))
            {
              ckq_e = TAILQ_FIRST (&tcp_ckq);
              TAILQ_REMOVE (&tcp_ckq, ckq_e, entry);
              WND_SENT -= ckq_e->len;
              BYTE_SENT -= ckq_e->len;
              free (ckq_e->hdr);
              free (ckq_e);
            }
          while (!TAILQ_EMPTY (&tcp_inq))
            {
              inq_e = TAILQ_FIRST (&tcp_inq);
              TAILQ_REMOVE (&tcp_inq, inq_e, entry);
              free (inq_e->hdr);
              free (inq_e);
            }
          next_size
              = num_byte - BYTE_SENT >= size ? size : num_byte - BYTE_SENT;
        }

      /* Handle current recieved packet. The update max ack, and consider
         packets will <= ack recieved.
       */
      while (!TAILQ_EMPTY (&tcp_inq))
        {
          inq_e = TAILQ_FIRST (&tcp_inq);
          uint32_t e_ack = ntohl (inq_e->hdr->ack_num);
          MAX_ACK = MAX_ACK < e_ack ? e_ack : MAX_ACK;

          TAILQ_REMOVE (&tcp_inq, inq_e, entry);
          free (inq_e->hdr);
          free (inq_e);
        }
      /* Continued, remove ckq entries with less than MAX_ACK and update
      window
       */
      while (!TAILQ_EMPTY (&tcp_ckq))
        {
          ckq_e = TAILQ_FIRST (&tcp_ckq);
          uint32_t e_ack = ntohl (ckq_e->hdr->ack_num);
          if (e_ack > MAX_ACK)
            break;
          TAILQ_REMOVE (&tcp_ckq, ckq_e, entry);
          free (ckq_e->hdr);
          free (ckq_e);
          WND_SENT -= ckq_e->len;
          num_packet--;
        }

      /* Start sending, increment SENT decrement quotient. */
      while (WND_SENT + next_size <= CWND && BYTE_SENT < num_byte)
        {
          if (next_size != size)
            {
              iph->tot_len
                  = sizeof (struct iphdr) + sizeof (tcp_hdr_t) + next_size;
              iph->check = 0;
              iph->check = tcp_cksum ((unsigned short *)datagram,
                                      sizeof (struct iphdr));
            }
          sprintf ((char *)data, "%u ", BYTE_SENT / size);
          tcp_gen_packet (tcph, (uint8_t *)data, next_size, src_ip,
                          sin.sin_addr.s_addr, 1234, dst_port, SEQNUM, ack_num,
                          (uint8_t)(PSH_FLAG | ACK_FLAG), 5840);
          if (sendto (socket, datagram, iph->tot_len, 0,
                      (struct sockaddr *)&sin, sizeof (sin))
              < 0)
            {
              exit (-1);
            }
          BYTE_SENT += next_size;
          SEQNUM += next_size;
          WND_SENT += next_size;

          tcp_add_sw_packet (SEQNUM, getNano (), DEFAULT_RTO, next_size);
          next_size
              = num_byte - BYTE_SENT >= size ? size : num_byte - BYTE_SENT;
        }
      pthread_mutex_unlock (&inq_lock);
    }
  return ack_num;
}

uint32_t
tcp_send_sliding_window_fastR_slowS (int socket, in_addr_t src_ip,
                                     struct sockaddr_in sin, uint32_t ack_num,
                                     uint32_t num_byte)
{
  size_t size = 1460;
  uint32_t total_recv = 0;
  uint32_t num_packet = num_byte / size;
  num_packet += num_byte % size > 0 ? 1 : 0;
  const uint32_t max_packet = num_packet;
  uint32_t rACK_counter = 0;
  uint32_t MAX_ACK = SEQNUM;
  uint16_t CWND = size;
  uint16_t THRESHOLD = RWND;
  uint32_t WND_SENT = 0;
  uint32_t BYTE_SENT = 0;
  uint64_t AVG_RTT = DEFAULT_RTO;
  uint64_t DEV_RTT = 0;
  uint32_t next_size
      = num_byte - BYTE_SENT >= size ? size : num_byte - BYTE_SENT;
  bool is_additive = false;
  char datagram[4096];
  memset (datagram, 0, 4096);
  uint8_t *data
      = (uint8_t *)(datagram + sizeof (struct iphdr) + sizeof (tcp_hdr_t));
  struct iphdr *iph = (struct iphdr *)datagram;
  uint16_t dst_port = ntohs (sin.sin_port);
  // TCP header
  tcp_hdr_t *tcph = (tcp_hdr_t *)(datagram + sizeof (struct iphdr));

  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof (struct iphdr) + sizeof (tcp_hdr_t) + next_size;
  iph->id = htonl (54321); // Id of this packet
  iph->frag_off = 0;
  iph->ttl = 255;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0;      // Set to 0 before calculating checksum
  iph->saddr = src_ip; // Spoof the source ip address
  iph->daddr = sin.sin_addr.s_addr;
  while (num_packet != 0)
    {
      // printf ("CWND %u\n", CWND / size);
      pthread_mutex_lock (&inq_lock);
      // printf ("QUOTIENT: %u\n", quotient);

      /* When CWND full, we restart only when new packets or timeout happen
       */
      if (WND_SENT + next_size > CWND)
        {
          pthread_cond_wait (&inq_cond, &inq_lock);
        }
      /* Handle Timeout. Later need to do retransmit, changing SENT and SEQ
       */
      tcp_check_entry_t *ckq_e = NULL;
      tcp_packet_entry_t *inq_e = NULL;
      bool retrans = false;
      bool handled_slow = false;
      TAILQ_FOREACH (ckq_e, &tcp_ckq, entry)
      {
        if (ckq_e->timeout <= getNano ())
          {
            SEQNUM = MAX_ACK;
            retrans = true;
            is_additive = false;
            THRESHOLD = (CWND / 2) < size ? size : CWND / 2;
            CWND = size;
            break;
          }
      }

      if (retrans)
        {
          // perror ("SLOWR");
          while (!TAILQ_EMPTY (&tcp_ckq))
            {
              ckq_e = TAILQ_FIRST (&tcp_ckq);
              TAILQ_REMOVE (&tcp_ckq, ckq_e, entry);
              WND_SENT -= ckq_e->len;
              BYTE_SENT -= ckq_e->len;
              free (ckq_e->hdr);
              free (ckq_e);
            }
          while (!TAILQ_EMPTY (&tcp_inq))
            {
              inq_e = TAILQ_FIRST (&tcp_inq);
              TAILQ_REMOVE (&tcp_inq, inq_e, entry);
              free (inq_e->hdr);
              free (inq_e);
            }
          next_size
              = num_byte - BYTE_SENT >= size ? size : num_byte - BYTE_SENT;
          rACK_counter = 0;
          retrans = false;
          handled_slow = true;
        }

      /* Handle current recieved packet. The update max ack, and consider
         packets will <= ack recieved.
       */
      TAILQ_FOREACH (inq_e, &tcp_inq, entry)
      {
        uint32_t e_ack = ntohl (inq_e->hdr->ack_num);
        if (MAX_ACK < e_ack)
          {
            MAX_ACK = e_ack;
            rACK_counter = 0;
          }
      }

      while (!TAILQ_EMPTY (&tcp_inq))
        {
          inq_e = TAILQ_FIRST (&tcp_inq);
          uint32_t e_ack = ntohl (inq_e->hdr->ack_num);
          if (MAX_ACK == e_ack)
            rACK_counter++;
          if (rACK_counter >= 3)
            retrans = true;

          TAILQ_REMOVE (&tcp_inq, inq_e, entry);
          free (inq_e->hdr);
          free (inq_e);
        }
      /* Continued, remove ckq entries with less than MAX_ACK and update
      window
       */
      while (!TAILQ_EMPTY (&tcp_ckq))
        {

          ckq_e = TAILQ_FIRST (&tcp_ckq);
          uint32_t e_ack = ntohl (ckq_e->hdr->ack_num);
          if (!ckq_e->RTT_counted)
            {
              uint64_t SampleRTT = getNano () - ckq_e->sent_time;
              SampleRTT -= (AVG_RTT >> 3);
              AVG_RTT += SampleRTT;
              if (SampleRTT < 0)
                SampleRTT = -SampleRTT;
              SampleRTT -= (DEV_RTT >> 3);
              DEV_RTT += SampleRTT;
              ckq_e->RTT_counted = true;
            }
          if (e_ack > MAX_ACK)
            break;
          TAILQ_REMOVE (&tcp_ckq, ckq_e, entry);
          free (ckq_e->hdr);
          free (ckq_e);
          WND_SENT -= ckq_e->len;
          num_packet--;

          if (!is_additive)
            {
              if (CWND + size > THRESHOLD)
                {
                  is_additive = true;
                }
              else if (CWND + size < RWND)
                CWND += size; // Every recieved packet increases window size by
                              // 2
            }
          else if (CWND + size < RWND)
            {
              CWND += (uint32_t)(size * ((float)size / (float)CWND));
            }
        }
      // printf ("AVGRTT: %u", AVG_RTT);
      if (retrans && !handled_slow)
        {
          SEQNUM = MAX_ACK;
          CWND = (CWND / 2) < size ? size : CWND / 2;
          // perror ("FASTR");
          while (!TAILQ_EMPTY (&tcp_ckq))
            {
              ckq_e = TAILQ_FIRST (&tcp_ckq);
              TAILQ_REMOVE (&tcp_ckq, ckq_e, entry);
              WND_SENT -= ckq_e->len;
              BYTE_SENT -= ckq_e->len;
              free (ckq_e->hdr);
              free (ckq_e);
            }
          next_size
              = num_byte - BYTE_SENT >= size ? size : num_byte - BYTE_SENT;
          rACK_counter = 0;
          is_additive = true;
        }
      /* Start sending, increment SENT decrement quotient. */
      while (WND_SENT + next_size <= CWND && BYTE_SENT < num_byte)
        {
          if (next_size != size)
            {
              iph->tot_len
                  = sizeof (struct iphdr) + sizeof (tcp_hdr_t) + next_size;
              iph->check = 0;
              iph->check = tcp_cksum ((unsigned short *)datagram,
                                      sizeof (struct iphdr));
            }
          else
            {
              iph->tot_len = sizeof (struct iphdr) + sizeof (tcp_hdr_t) + size;
              iph->check = 0;
              iph->check = tcp_cksum ((unsigned short *)datagram,
                                      sizeof (struct iphdr));
            }
          // sprintf ((char *)data, "%u ", BYTE_SENT / size);
          tcp_gen_packet (tcph, (uint8_t *)data, next_size, src_ip,
                          sin.sin_addr.s_addr, 1234, dst_port, SEQNUM, ack_num,
                          (uint8_t)(PSH_FLAG | ACK_FLAG), 5840);
          if (sendto (socket, datagram, iph->tot_len, 0,
                      (struct sockaddr *)&sin, sizeof (sin))
              < 0)
            {
              exit (-1);
            }
          BYTE_SENT += next_size;
          SEQNUM += next_size;
          WND_SENT += next_size;
          tcp_add_sw_packet (SEQNUM, getNano (),
                             AVG_RTT == 0 ? DEFAULT_RTO
                                          : (AVG_RTT >> 3) + (DEV_RTT >> 1),
                             next_size);
          next_size
              = num_byte - BYTE_SENT >= size ? size : num_byte - BYTE_SENT;
        }
      pthread_mutex_unlock (&inq_lock);
    }
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
  tcp_hdr_t *finack_hdr = tcp_wait_packet (SEQNUM, getNano () + DEFAULT_RTO,
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