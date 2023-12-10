#include "tcp_op.h"
#include "../ip_stack/sendpacket.h"
#include "mt19937ar.h"
#include <netinet/ip.h> // the IP protocol
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
uint32_t SEQNUM;
uint32_t RWND;


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
tcp_handshake (uint16_t src_port, uint16_t dst_port, uint32_t *dest_ip,
               uint8_t *dest_mac)
{
  // TCP header
  tcp_hdr_t *tcph = (tcp_hdr_t *)calloc (1, sizeof (tcp_hdr_t));
  uint8_t mac;
  uint32_t src_ip;
  get_mac_ip (find_active_interface (), &mac, &src_ip);

  /* Send TCP SYN packet */
  tcp_gen_syn (tcph, src_ip, dest_ip, src_port, dst_port, SEQNUM, 5840);
  warpHeaderAndSendTcp (tcph, sizeof (tcp_hdr_t), dest_ip, dest_mac);

  /* Recieve TCP SYN ACK */
  SEQNUM++;
  tcp_hdr_t *synack_hdr = tcp_wait_packet (SEQNUM, getNano () + DEFAULT_RTO,
                                           (uint8_t)(SYN_FLAG | ACK_FLAG));
  uint32_t ack_num = ntohl (synack_hdr->seq_num) + 1;
  RWND = ntohs (synack_hdr->window);
  printf ("\nWINDOW: %u\n", RWND);
  free (synack_hdr);

  /* Send TCP ACKs */
  tcp_gen_ack (tcph, src_ip, dest_ip, src_port, dst_port, SEQNUM, ack_num,
               5840);

  warpHeaderAndSendTcp (tcph, sizeof (tcp_hdr_t), dest_ip, dest_mac);
  free (tcph);
  return ack_num;
}

uint32_t
tcp_stop_and_wait (uint16_t src_port, uint16_t dst_port, uint32_t *dest_ip,
                   uint8_t *dest_mac, uint32_t ack_num, uint32_t num_byte)
{
  size_t size = 1460;
  uint32_t quotient = num_byte / size;
  uint32_t remainder = num_byte % size;
  uint8_t mac;
  uint32_t src_ip;
  get_mac_ip (find_active_interface (), &mac, &src_ip);

  char datagram[4096];
  memset (datagram, 0, 4096);
  uint8_t *data = (uint8_t *)(datagram + sizeof (tcp_hdr_t));
  strcpy ((char *)data, "A");
  // TCP header
  tcp_hdr_t *tcph = (tcp_hdr_t *)(datagram);

  while (quotient != 0)
    {
      tcp_gen_packet (tcph, (uint8_t *)data, size, src_ip, dest_ip, src_port,
                      dst_port, SEQNUM, ack_num,
                      (uint8_t)(PSH_FLAG | ACK_FLAG), 5840);
      warpHeaderAndSendTcp (tcph, sizeof (tcp_hdr_t) + size, dest_ip,
                            dest_mac);
      SEQNUM += size;
      free (tcp_wait_packet (SEQNUM, getNano () + DEFAULT_RTO,
                             (uint8_t)(ACK_FLAG)));
      quotient--;
    }

  if (remainder == 0)
    return ack_num;
  tcp_gen_packet (tcph, (uint8_t *)data, remainder, src_ip, dest_ip, src_port,
                  dst_port, SEQNUM, ack_num, (uint8_t)(PSH_FLAG | ACK_FLAG),
                  5840);
  warpHeaderAndSendTcp (tcph, sizeof (tcp_hdr_t) + remainder, dest_ip,
                        dest_mac);
  SEQNUM += remainder;
  tcp_hdr_t *dataack_hdr = tcp_wait_packet (SEQNUM, getNano () + DEFAULT_RTO,
                                            (uint8_t)(ACK_FLAG));
  ack_num = ntohl (dataack_hdr->seq_num);
  free (dataack_hdr);
  return ack_num;
}

uint32_t
tcp_send_sliding_window_fixed (uint16_t src_port, uint16_t dst_port,
                               uint32_t *dest_ip, uint8_t *dest_mac,
                               uint32_t ack_num, uint32_t num_byte)

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

  uint8_t mac;
  uint32_t src_ip;
  get_mac_ip (find_active_interface (), &mac, &src_ip);

  char datagram[4096];
  memset (datagram, 0, 4096);
  uint8_t *data = (uint8_t *)(datagram + sizeof (tcp_hdr_t));
  // TCP header
  tcp_hdr_t *tcph = (tcp_hdr_t *)(datagram);

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
          tcp_gen_packet (tcph, (uint8_t *)data, next_size, src_ip, dest_ip,
                          src_port, dst_port, SEQNUM, ack_num,
                          (uint8_t)(PSH_FLAG | ACK_FLAG), 5840);
          warpHeaderAndSendTcp (tcph, sizeof (tcp_hdr_t) + next_size, dest_ip,
                                dest_mac);
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
tcp_send_sliding_window_slowS_fastR (uint16_t src_port, uint16_t dst_port,
                                     uint32_t *dest_ip, uint8_t *dest_mac,
                                     uint32_t ack_num, uint32_t num_byte)
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

  uint8_t mac;
  uint32_t src_ip;
  get_mac_ip (find_active_interface (), &mac, &src_ip);

  char datagram[4096];
  memset (datagram, 0, 4096);
  // TCP header
  tcp_hdr_t *tcph = (tcp_hdr_t *)(datagram);
  uint8_t *data = (uint8_t *)(datagram + sizeof (tcp_hdr_t));
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
          tcp_gen_packet (tcph, (uint8_t *)data, ckq_e->len, src_ip, dest_ip,
                          src_port, dst_port,
                          ntohl (ckq_e->hdr->ack_num) - ckq_e->len, ack_num,
                          (uint8_t)(PSH_FLAG | ACK_FLAG), 65535);
          warpHeaderAndSendTcp (tcph, sizeof (tcp_hdr_t) + ckq_e->len, dest_ip,
                                dest_mac);
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
            tcp_gen_packet (tcph, (uint8_t *)data, ckq_e->len, src_ip, dest_ip,
                            src_port, dst_port,
                            ntohl (ckq_e->hdr->ack_num) - ckq_e->len, ack_num,
                            (uint8_t)(PSH_FLAG | ACK_FLAG), 65535);
            warpHeaderAndSendTcp (tcph, sizeof (tcp_hdr_t) + ckq_e->len,
                                  dest_ip, dest_mac);
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

          tcp_gen_packet (tcph, (uint8_t *)data, next_size, src_ip, dest_ip,
                          src_port, dst_port, SEQNUM, ack_num,
                          (uint8_t)(PSH_FLAG | ACK_FLAG), 65535);
          warpHeaderAndSendTcp (tcph, sizeof (tcp_hdr_t) + next_size, dest_ip,
                                dest_mac);
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
tcp_teardown (uint16_t src_port, uint16_t dst_port, uint32_t *dest_ip,
              uint8_t *dest_mac, uint32_t ack_num)
{
  // TCP header
  tcp_hdr_t *tcph = (tcp_hdr_t *)calloc (1, sizeof (tcp_hdr_t));
  uint8_t mac;
  uint32_t src_ip;
  get_mac_ip (find_active_interface (), &mac, &src_ip);

  /* Send TCP FIN ACK packet */
  tcp_gen_packet (tcph, 0, 0, src_ip, dest_ip, src_port, dst_port, SEQNUM,
                  ack_num, (uint8_t)(FIN_FLAG | ACK_FLAG), 5840);
  warpHeaderAndSendTcp (tcph, sizeof (tcp_hdr_t), dest_ip, dest_mac);

  /* Recieve TCP FIN ACK */
  SEQNUM++;
  tcp_hdr_t *finack_hdr = tcp_wait_packet (SEQNUM, getNano () + DEFAULT_RTO,
                                           (uint8_t)(FIN_FLAG | ACK_FLAG));
  ack_num = ntohl (finack_hdr->seq_num) + 1;
  free (finack_hdr);
  /* Send TCP ACK */

  tcp_gen_packet (tcph, 0, 0, src_ip, dest_ip, src_port, dst_port, SEQNUM,
                  ack_num, (uint8_t)(ACK_FLAG), 5840);
  warpHeaderAndSendTcp (tcph, sizeof (tcp_hdr_t), dest_ip, dest_mac);
}