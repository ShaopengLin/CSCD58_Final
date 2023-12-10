#include "tcp_op.h"
#include "../ip_stack/sendpacket.h"
#include "mt19937ar.h"
#include "tcp_helpers.h"
#include <netinet/ip.h> // the IP protocol
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint32_t RWND;
char DATAGRAM[4096];

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

uint32_t
tcp_handshake ()
{
  // TCP header
  tcp_hdr_t *tcph = (tcp_hdr_t *)calloc (1, sizeof (tcp_hdr_t));

  /* Send TCP SYN packet */
  tcp_gen_syn (tcph, SRC_IP, DST_IP, SRC_PORT, DST_PORT, SEQNUM, 65535);
  warpHeaderAndSendTcp (tcph, sizeof (tcp_hdr_t), DST_IP, DST_MAC);

  /* Recieve TCP SYN ACK */
  SEQNUM++;
  tcp_hdr_t *synack_hdr
      = tcp_wait_packet (tcph, 1, getNano (), (uint8_t)(SYN_FLAG | ACK_FLAG));

  uint32_t ack_num = ntohl (synack_hdr->seq_num) + 1;

  // Initializes RWND from TCP SYNACK
  RWND = ntohs (synack_hdr->window);

  printf ("\nWINDOW: %u\n", RWND);
  free (synack_hdr);

  /* Send TCP ACKs */
  tcp_gen_ack (tcph, SRC_IP, DST_IP, SRC_PORT, DST_PORT, SEQNUM, ack_num,
               65535);

  warpHeaderAndSendTcp (tcph, sizeof (tcp_hdr_t), DST_IP, DST_MAC);

  free (tcph);
  return ack_num;
}

void
tcp_stop_and_wait (uint32_t ack_num)
{
  uint32_t byte_sent = 0;
  uint32_t next_size
      = NUM_BYTES - byte_sent >= PKT_SIZE ? PKT_SIZE : NUM_BYTES - byte_sent;

  /* Init Data*/
  memset (DATAGRAM, 0, 4096);
  uint8_t *data = (uint8_t *)(DATAGRAM + sizeof (tcp_hdr_t));

  // TCP header
  tcp_hdr_t *tcph = (tcp_hdr_t *)(DATAGRAM);

  while (NUM_BYTES > byte_sent)
    {
      tcp_gen_packet (tcph, data, next_size, SRC_IP, DST_IP, SRC_PORT,
                      DST_PORT, SEQNUM, ack_num,
                      (uint8_t)(PSH_FLAG | ACK_FLAG), 65535);
      warpHeaderAndSendTcp (tcph, sizeof (tcp_hdr_t) + next_size, DST_IP,
                            DST_MAC);
      SEQNUM += next_size;
      free (
          tcp_wait_packet (tcph, next_size, getNano (), (uint8_t)(ACK_FLAG)));
      byte_sent += next_size;
      next_size = NUM_BYTES - byte_sent >= PKT_SIZE ? PKT_SIZE
                                                    : NUM_BYTES - byte_sent;
    }
}

// uint32_t
// tcp_send_sliding_window_fixed (uint32_t window_size, uint32_t ack_num)

// {
//   uint32_t num_packet = NUM_BYTES / PKT_SIZE;
//   num_packet += NUM_BYTES % PKT_SIZE > 0 ? 1 : 0;
//   uint32_t MAX_ACK = SEQNUM;
//   uint32_t CWND = window_size * PKT_SIZE;
//   uint32_t INITSEQ = SEQNUM;

//   uint32_t WND_SENT = 0;
//   uint32_t BYTE_SENT = 0;
//   uint32_t next_size
//       = NUM_BYTES - BYTE_SENT >= PKT_SIZE ? PKT_SIZE : NUM_BYTES -
//       BYTE_SENT;

//   /* Init Data*/
//   memset (DATAGRAM, 0, 4096);
//   uint8_t *data = (uint8_t *)(DATAGRAM + sizeof (tcp_hdr_t));

//   // TCP header
//   tcp_hdr_t *tcph = (tcp_hdr_t *)(DATAGRAM);

//   while (num_packet != 0)
//     {
//       pthread_mutex_lock (&inq_lock);

//       /* When CWND full, we restart only when new packets or timeout happen
//        */
//       if (WND_SENT + next_size > CWND)
//         {
//           pthread_cond_wait (&inq_cond, &inq_lock);
//         }

//       /* Handle Timeout. Later need to do retransmit, changing SENT and SEQ
//        */
//       tcp_check_entry_t *ckq_e = NULL;
//       bool retrans = false;
//       TAILQ_FOREACH (ckq_e, &tcp_ckq, entry)
//       {
//         if (ckq_e->timeout <= getNano ())
//           {
//             SEQNUM = ntohl (ckq_e->hdr->ack_num) - ckq_e->len;
//             printf ("%u\n", (SEQNUM - INITSEQ) / size);
//             retrans = true;
//             break;
//           }
//       }

//       tcp_packet_entry_t *inq_e = NULL;
//       ckq_e = NULL;
//       if (retrans)
//         {
//           while (!TAILQ_EMPTY (&tcp_ckq))
//             {
//               ckq_e = TAILQ_FIRST (&tcp_ckq);
//               TAILQ_REMOVE (&tcp_ckq, ckq_e, entry);
//               BYTE_SENT -= ckq_e->len;
//               free (ckq_e->hdr);
//               free (ckq_e);
//             }
//           while (!TAILQ_EMPTY (&tcp_inq))
//             {
//               inq_e = TAILQ_FIRST (&tcp_inq);
//               TAILQ_REMOVE (&tcp_inq, inq_e, entry);
//               free (inq_e->hdr);
//               free (inq_e);
//             }
//           next_size
//               = num_byte - BYTE_SENT >= size ? size : num_byte - BYTE_SENT;
//           WND_SENT = 0;
//         }

//       /* Handle current recieved packet. The update max ack, and consider
//          packets will <= ack recieved.
//        */
//       while (!TAILQ_EMPTY (&tcp_inq))
//         {
//           inq_e = TAILQ_FIRST (&tcp_inq);
//           uint32_t e_ack = ntohl (inq_e->hdr->ack_num);
//           MAX_ACK = MAX_ACK < e_ack ? e_ack : MAX_ACK;

//           TAILQ_REMOVE (&tcp_inq, inq_e, entry);
//           free (inq_e->hdr);
//           free (inq_e);
//         }
//       /* Continued, remove ckq entries with less than MAX_ACK and update
//       window
//        */
//       while (!TAILQ_EMPTY (&tcp_ckq))
//         {
//           ckq_e = TAILQ_FIRST (&tcp_ckq);
//           uint32_t e_ack = ntohl (ckq_e->hdr->ack_num);
//           if (e_ack > MAX_ACK)
//             break;
//           TAILQ_REMOVE (&tcp_ckq, ckq_e, entry);
//           free (ckq_e->hdr);
//           free (ckq_e);
//           WND_SENT -= ckq_e->len;
//           num_packet--;
//         }

//       /* Start sending, increment SENT decrement quotient. */
//       while (WND_SENT + next_size <= CWND && BYTE_SENT < num_byte)
//         {
//           tcp_gen_packet (tcph, (uint8_t *)data, next_size, src_ip, dest_ip,
//                           src_port, dst_port, SEQNUM, ack_num,
//                           (uint8_t)(PSH_FLAG | ACK_FLAG), 5840);
//           warpHeaderAndSendTcp (tcph, sizeof (tcp_hdr_t) + next_size,
//           dest_ip,
//                                 dest_mac);
//           BYTE_SENT += next_size;
//           SEQNUM += next_size;
//           WND_SENT += next_size;

//           tcp_add_sw_packet (SEQNUM, getNano (), DEFAULT_RTO, next_size);
//           next_size
//               = num_byte - BYTE_SENT >= size ? size : num_byte - BYTE_SENT;
//         }
//       pthread_mutex_unlock (&inq_lock);
//     }
//   return ack_num;
// }

uint32_t
tcp_send_sliding_window_slowS_fastR (uint32_t ack_num)
{
  uint32_t num_packet = NUM_BYTES / PKT_SIZE;
  num_packet += NUM_BYTES % PKT_SIZE > 0 ? 1 : 0;
  uint32_t total_packet = num_packet;
  uint32_t MAX_ACK = SEQNUM;
  uint32_t CWND = PKT_SIZE;
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

  uint8_t mac[6];
  uint32_t src_ip;
  char *iface = find_active_interface ();
  get_mac_ip (iface, &mac, &src_ip);
  free (iface);

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
          WND_SENT -= ckq_e->len;
          num_packet--;

          if (!ckq_e->retransmitted)
            {
              uint64_t SampleRTT = curTime - ckq_e->sent_time;
              EstimatedRTT
                  = (uint64_t)((long double)ALPHA * EstimatedRTT)
                    + (uint64_t)((long double)(1 - ALPHA) * SampleRTT);
              TimeOut = 2 * EstimatedRTT;
            }
          // TimeOut = 2 * EstimatedRTT;
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
          TAILQ_REMOVE (&tcp_ckq, ckq_e, entry);
          free (ckq_e->hdr);
          free (ckq_e);
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
tcp_teardown (uint32_t ack_num)
{
  // TCP header
  tcp_hdr_t *tcph = (tcp_hdr_t *)calloc (1, sizeof (tcp_hdr_t));

  /* Send TCP FIN ACK packet */
  tcp_gen_packet (tcph, 0, 0, SRC_IP, DST_IP, SRC_PORT, DST_PORT, SEQNUM,
                  ack_num, (uint8_t)(FIN_FLAG | ACK_FLAG), 5840);
  warpHeaderAndSendTcp (tcph, sizeof (tcp_hdr_t), DST_IP, DST_MAC);

  /* Recieve TCP FIN ACK */
  tcp_hdr_t *finack_hdr
      = tcp_wait_packet (tcph, 1, getNano (), (uint8_t)(FIN_FLAG | ACK_FLAG));
  ack_num = ntohl (finack_hdr->seq_num) + 1;
  free (finack_hdr);
  /* Send TCP ACK */

  tcp_gen_packet (tcph, 0, 0, SRC_IP, DST_IP, SRC_PORT, DST_PORT, SEQNUM,
                  ack_num, (uint8_t)(ACK_FLAG), 5840);
  warpHeaderAndSendTcp (tcph, sizeof (tcp_hdr_t), DST_IP, DST_MAC);
  free (tcph);
}