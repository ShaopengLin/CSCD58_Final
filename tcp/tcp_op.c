#include "tcp_op.h"
#include "mt19937ar.h"
#include "sendpacket.h"
#include <netinet/ip.h> // the IP protocol
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
uint32_t SEQNUM;
uint32_t RWND;

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
      pthread_mutex_lock (&inq_lock);

      tcp_check_entry_t *ckq_e;
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
  syn_check->rAck = 0;
  syn_check->retransmitted = false;
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
  size_t size = 1460;
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
  uint32_t CWND = 80 * size;
  uint32_t INITSEQ = SEQNUM;

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
            printf ("%u\n", (SEQNUM - INITSEQ) / size);
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
          WND_SENT = 0;
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
tcp_send_sliding_window_test (int socket, in_addr_t src_ip,
                              struct sockaddr_in sin, uint32_t ack_num,
                              uint32_t num_byte)
{
  size_t size = 1460;
  uint32_t num_packet = num_byte / size;
  num_packet += num_byte % size > 0 ? 1 : 0;
  uint32_t total_packet = num_packet;
  uint32_t MAX_ACK = SEQNUM;
  uint32_t CWND = size;
  uint32_t INITSEQ = SEQNUM;
  uint32_t WND_SENT = 0;
  RWND = 3810000;
  uint32_t TRSH_WND = RWND;

  uint64_t EstimatedRTT = SEC_TO_NS (1);
  uint64_t Deviation = SEC_TO_NS (1) / 2;
  uint64_t TimeOut = 0;
  uint32_t BYTE_SENT = 0;
  uint32_t next_size
      = num_byte - BYTE_SENT >= size ? size : num_byte - BYTE_SENT;
  bool is_AIMD = false;
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
      // printf ("WND %u %u %u\n", WND_SENT / size, CWND / size,
      //         total_packet - num_packet);
      // printf ("Deviation %u\n", Deviation);
      // printf ("timeout %lu\n", TimeOut);
      uint64_t curTime = getNano ();
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

      tcp_packet_entry_t *inq_e = NULL;

      /* Handle current recieved packet. The update max ack recieved
       */
      TAILQ_FOREACH (inq_e, &tcp_inq, entry)
      {
        uint32_t e_ack = ntohl (inq_e->hdr->ack_num);
        MAX_ACK = MAX_ACK < e_ack ? e_ack : MAX_ACK;
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

          if (!ckq_e->retransmitted)
            {
              uint64_t SampleRTT = curTime - ckq_e->sent_time;
              EstimatedRTT
                  = (uint64_t)((long double)ALPHA * EstimatedRTT)
                    + (uint64_t)((long double)(1 - ALPHA) * SampleRTT);
              // TimeOut = 2 * EstimatedRTT;
            }
          TimeOut = 2 * EstimatedRTT;
          if (is_AIMD)
            {
              CWND += (uint16_t)(size * ((float)size / (float)CWND));
            }
          else
            {
              CWND += size;
              if (CWND > TRSH_WND)
                {
                  CWND = TRSH_WND;
                  is_AIMD = true;
                }
            }
          if (CWND > RWND)
            CWND = RWND;
        }

      /* Find repeating ACK count for the head packet */
      ckq_e = NULL;
      if (!TAILQ_EMPTY (&tcp_ckq))
        {
          ckq_e = TAILQ_FIRST (&tcp_ckq);
        }
      while (!TAILQ_EMPTY (&tcp_inq))
        {
          inq_e = TAILQ_FIRST (&tcp_inq);
          uint32_t e_seq = ntohl (inq_e->hdr->ack_num);

          if (ckq_e && MAX_ACK == (ntohl (ckq_e->hdr->ack_num) - ckq_e->len)
              && e_seq == MAX_ACK)
            {
              if (ckq_e->retransmitted)
                {
                  CWND += size;
                  if (CWND > RWND)
                    {
                      CWND = RWND;
                    }
                }
              else
                ckq_e->rAck++;
            }

          TAILQ_REMOVE (&tcp_inq, inq_e, entry);
          free (inq_e->hdr);
          free (inq_e);
        }

      if (ckq_e && ckq_e->rAck >= 3)
        {
          ckq_e = TAILQ_FIRST (&tcp_ckq);
          TimeOut = 2 * TimeOut;
          // perror ("FASTRRRRR");
          iph->tot_len
              = sizeof (struct iphdr) + sizeof (tcp_hdr_t) + ckq_e->len;
          iph->check = 0;
          iph->check
              = tcp_cksum ((unsigned short *)datagram, sizeof (struct iphdr));

          tcp_gen_packet (tcph, (uint8_t *)data, ckq_e->len, src_ip,
                          sin.sin_addr.s_addr, 1234, dst_port,
                          ntohl (ckq_e->hdr->ack_num) - ckq_e->len, ack_num,
                          (uint8_t)(PSH_FLAG | ACK_FLAG), 65535);
          if (sendto (socket, datagram, iph->tot_len, 0,
                      (struct sockaddr *)&sin, sizeof (sin))
              < 0)
            {
              exit (-1);
            }
          ckq_e->sent_time = curTime;
          ckq_e->timeout = curTime + (TimeOut == 0 ? DEFAULT_RTO : TimeOut);
          CWND = CWND / 2 < size ? size : CWND / 2;
          CWND = CWND + 3 * size > RWND ? RWND : CWND + 3 * size;
          ckq_e->rAck = 0;
          ckq_e->retransmitted = true;
          is_AIMD = true;
        }
      if (!TAILQ_EMPTY (&tcp_ckq))
        {
          ckq_e = TAILQ_FIRST (&tcp_ckq);
          if (ckq_e->timeout <= curTime)
            {
              // SEQNUM = ntohl (ckq_e->hdr->ack_num) - ckq_e->len;
              retrans = true;
              CWND = size;
              TRSH_WND = CWND / 2 < size ? size : CWND / 2;
            }
        }
      if (retrans)
        {
          // perror ("SLOWRRRR");
          ckq_e = TAILQ_FIRST (&tcp_ckq);
          TimeOut = 2 * TimeOut;
          TAILQ_FOREACH (ckq_e, &tcp_ckq, entry)
          {
            iph->tot_len
                = sizeof (struct iphdr) + sizeof (tcp_hdr_t) + ckq_e->len;
            iph->check = 0;
            iph->check = tcp_cksum ((unsigned short *)datagram,
                                    sizeof (struct iphdr));

            tcp_gen_packet (tcph, (uint8_t *)data, ckq_e->len, src_ip,
                            sin.sin_addr.s_addr, 1234, dst_port,
                            ntohl (ckq_e->hdr->ack_num) - ckq_e->len, ack_num,
                            (uint8_t)(PSH_FLAG | ACK_FLAG), 65535);
            if (sendto (socket, datagram, iph->tot_len, 0,
                        (struct sockaddr *)&sin, sizeof (sin))
                < 0)
              {
                exit (-1);
              }
            ckq_e->sent_time = curTime;
            ckq_e->timeout = curTime + (TimeOut == 0 ? DEFAULT_RTO : TimeOut);
            ckq_e->rAck = 0;
            ckq_e->retransmitted = true;
            retrans = false;
            is_AIMD = false;
          }
        }
      while (!TAILQ_EMPTY (&tcp_inq))
        {
          inq_e = TAILQ_FIRST (&tcp_inq);
          TAILQ_REMOVE (&tcp_inq, inq_e, entry);
          free (inq_e->hdr);
          free (inq_e);
        }
      /* Start sending, increment SENT decrement quotient. */
      while (WND_SENT + next_size <= CWND && BYTE_SENT < num_byte)
        {

          iph->tot_len
              = sizeof (struct iphdr) + sizeof (tcp_hdr_t) + next_size;
          iph->check = 0;
          iph->check
              = tcp_cksum ((unsigned short *)datagram, sizeof (struct iphdr));

          tcp_gen_packet (tcph, (uint8_t *)data, next_size, src_ip,
                          sin.sin_addr.s_addr, 1234, dst_port, SEQNUM, ack_num,
                          (uint8_t)(PSH_FLAG | ACK_FLAG), 65535);
          if (sendto (socket, datagram, iph->tot_len, 0,
                      (struct sockaddr *)&sin, sizeof (sin))
              < 0)
            {
              exit (-1);
            }
          BYTE_SENT += next_size;
          SEQNUM += next_size;
          WND_SENT += next_size;

          tcp_add_sw_packet (SEQNUM, curTime,
                             TimeOut == 0 ? DEFAULT_RTO / 10 : TimeOut,
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