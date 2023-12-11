#include "tcp_op.h"
#include "../ip_stack/sendpacket.h"
#include "mt19937ar.h"
#include "tcp_helpers.h"
#include "tcp_stat.h"
#include <netinet/ip.h> // the IP protocol
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint32_t RWND;
char DATAGRAM[4096];
uint64_t total_packet = 0;

void *
tcp_check_timeout ()
{
  uint64_t prevTime = getNano ();
  uint32_t prevSeq = SEQNUM;
  while (1)
    {
      pthread_mutex_lock (&inq_lock);
      uint64_t curTime = getNano ();
      if (curTime - prevTime >= 1000000000)
        {
          // Get total bytes transfered in a second and convert to Kbits
          if (RWND > 0)
            {
              printf ("***** SENT: %Lf KBytes, Bandwidth %Lf Kbits/s\n",
                      (long double)(SEQNUM - prevSeq) / 1024,
                      8 * (long double)(SEQNUM - prevSeq) / 1000);
              add_BW (8 * (long double)(SEQNUM - prevSeq) / 1000);
              prevSeq = SEQNUM;
            }

          prevTime = curTime;
        }
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
  PKT_SIZE = RWND < PKT_SIZE ? RWND : PKT_SIZE;

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

  /* Init Data*/
  memset (DATAGRAM, 0, 4096);
  uint8_t *data = (uint8_t *)(DATAGRAM + sizeof (tcp_hdr_t));

  // TCP header
  tcp_hdr_t *tcph = (tcp_hdr_t *)(DATAGRAM);
  uint64_t end = getNano () + TESTING_PERIOD;
  while (getNano () <= end)
    {
      tcp_gen_packet (tcph, data, PKT_SIZE, SRC_IP, DST_IP, SRC_PORT, DST_PORT,
                      SEQNUM, ack_num, (uint8_t)(PSH_FLAG | ACK_FLAG), 65535);
      warpHeaderAndSendTcp (tcph, sizeof (tcp_hdr_t) + PKT_SIZE, DST_IP,
                            DST_MAC);
      SEQNUM += PKT_SIZE;
      free (tcp_wait_packet (tcph, PKT_SIZE, getNano (), (uint8_t)(ACK_FLAG)));
    }
}

uint32_t
tcp_send_sliding_window_fixed (uint32_t window_size, uint32_t ack_num)

{
  uint32_t MAX_ACK = SEQNUM;
  uint32_t CWND
      = window_size * PKT_SIZE > RWND ? RWND : window_size * PKT_SIZE;
  uint32_t WND_SENT = 0;
  uint32_t TRSH_WND = RWND;
  tcp_check_entry_t *ckq_e = NULL;
  tcp_packet_entry_t *inq_e = NULL;
  bool is_AIMD = false;

  memset (DATAGRAM, 0, 4096);
  uint8_t *data = (uint8_t *)(DATAGRAM + sizeof (tcp_hdr_t));

  // TCP header
  tcp_hdr_t *tcph = (tcp_hdr_t *)(DATAGRAM);

  tcp_send_entry_t *sq_e = NULL;
  uint32_t pktgen_seqnum = SEQNUM;
  init_sendQ_packets (&pktgen_seqnum, 2 * (RWND / PKT_SIZE));

  uint64_t end = getNano () + TESTING_PERIOD;
  while (getNano () <= end)
    {

      pthread_mutex_lock (&inq_lock);
      uint64_t curTime = getNano ();

      /* When CWND full, we restart only when new packets or timeout happen
       */
      if (WND_SENT + PKT_SIZE > CWND)
        {
          pthread_cond_wait (&inq_cond, &inq_lock);
        }

      /* Handle current recieved packet. The update max ack recieved
       */
      MAX_ACK = get_max_ack (MAX_ACK);

      /* Continued, remove ckq entries with less than MAX_ACK and update
      window
       */
      while (!TAILQ_EMPTY (&tcp_ckq))
        {
          ckq_e = TAILQ_FIRST (&tcp_ckq);
          uint32_t e_ack = ntohl (ckq_e->hdr->ack_num);
          if (e_ack > MAX_ACK)
            break;

          WND_SENT = WND_SENT < PKT_SIZE ? 0 : WND_SENT - ckq_e->len;
          add_RTT (ckq_e->sent_time, curTime);
          if (!ckq_e->retransmitted)
            calculateERTT (ckq_e->sent_time, curTime);
          init_sendQ_packets (&pktgen_seqnum, 1);
          TAILQ_REMOVE (&tcp_ckq, ckq_e, entry);
          free (ckq_e->hdr);
          free (ckq_e);
        }

      handle_simple_fast_retransmit (&WND_SENT, MAX_ACK);
      handle_simple_timeout_retransmit (&WND_SENT, curTime);

      while (!TAILQ_EMPTY (&tcp_inq))
        {
          inq_e = TAILQ_FIRST (&tcp_inq);
          TAILQ_REMOVE (&tcp_inq, inq_e, entry);

          free (inq_e->hdr);
          free (inq_e);
        }

      /* Start sending, increment SENT decrement quotient. */
      while (WND_SENT + PKT_SIZE <= CWND)
        {
          sq_e = TAILQ_FIRST (&tcp_sdq);
          send_sw (tcph, data, sq_e->len, NULL, ack_num);
          if (!sq_e->is_retrans)
            {
              SEQNUM += sq_e->len;
              WND_SENT += sq_e->len;

              tcp_add_sw_packet (SEQNUM, curTime, TIMEOUT, sq_e->len);
            }

          TAILQ_REMOVE (&tcp_sdq, sq_e, entry);
          free (sq_e);
        }
      pthread_mutex_unlock (&inq_lock);
    }
  return ack_num;
}

void
tcp_send_sliding_window_slowS_fastR (uint32_t ack_num)
{
  uint32_t MAX_ACK = SEQNUM;
  uint32_t CWND = PKT_SIZE;
  uint32_t WND_SENT = 0;
  uint32_t TRSH_WND = RWND;
  tcp_check_entry_t *ckq_e = NULL;
  tcp_packet_entry_t *inq_e = NULL;
  bool is_AIMD = false;

  memset (DATAGRAM, 0, 4096);
  uint8_t *data = (uint8_t *)(DATAGRAM + sizeof (tcp_hdr_t));

  // TCP header
  tcp_hdr_t *tcph = (tcp_hdr_t *)(DATAGRAM);

  tcp_send_entry_t *sq_e = NULL;
  uint32_t pktgen_seqnum = SEQNUM;
  init_sendQ_packets (&pktgen_seqnum, 2 * (RWND / PKT_SIZE));

  uint64_t end = getNano () + TESTING_PERIOD;
  uint32_t total_out = 2 * (RWND / PKT_SIZE);
  add_CWND (CWND);
  while (getNano () <= end && total_out != 0)
    {

      pthread_mutex_lock (&inq_lock);
      uint64_t curTime = getNano ();

      /* When CWND full, we restart only when new packets or timeout happen
       */
      if (WND_SENT + PKT_SIZE > CWND)
        {
          pthread_cond_wait (&inq_cond, &inq_lock);
        }

      /* Handle current recieved packet. The update max ack recieved
       */
      MAX_ACK = get_max_ack (MAX_ACK);

      /* Continued, remove ckq entries with less than MAX_ACK and update
      window
       */
      while (!TAILQ_EMPTY (&tcp_ckq))
        {
          ckq_e = TAILQ_FIRST (&tcp_ckq);
          uint32_t e_ack = ntohl (ckq_e->hdr->ack_num);
          if (e_ack > MAX_ACK)
            break;

          WND_SENT = WND_SENT < PKT_SIZE ? 0 : WND_SENT - ckq_e->len;

          if (!ckq_e->retransmitted)
            calculateERTT (ckq_e->sent_time, curTime);
          add_RTT (ckq_e->sent_time, curTime);
          add_CWND (CWND);
          init_sendQ_packets (&pktgen_seqnum, 1);
          CWND = handle_SS_inc (CWND, TRSH_WND, &is_AIMD);
          add_CWND (CWND);
          TAILQ_REMOVE (&tcp_ckq, ckq_e, entry);
          free (ckq_e->hdr);
          free (ckq_e);
        }

      handle_SS_fast_retransmit (MAX_ACK, &CWND, &is_AIMD);
      handle_SS_timeout_retransmit (curTime, &TRSH_WND, &CWND, &WND_SENT,
                                    &is_AIMD);

      while (!TAILQ_EMPTY (&tcp_inq))
        {
          inq_e = TAILQ_FIRST (&tcp_inq);
          TAILQ_REMOVE (&tcp_inq, inq_e, entry);

          free (inq_e->hdr);
          free (inq_e);
        }

      /* Start sending, increment SENT decrement quotient. */
      while (WND_SENT + PKT_SIZE <= CWND && PKT_SIZE < NUM_BYTES)
        {
          sq_e = TAILQ_FIRST (&tcp_sdq);
          send_sw (tcph, data, sq_e->len, NULL, ack_num);
          SEQNUM += sq_e->len;
          WND_SENT += sq_e->len;

          tcp_add_sw_packet (SEQNUM, curTime, TIMEOUT, sq_e->len);

          TAILQ_REMOVE (&tcp_sdq, sq_e, entry);
          free (sq_e);
        }
      pthread_mutex_unlock (&inq_lock);
    }

  return ack_num;
}

void
tcp_teardown (uint32_t ack_num)
{
  tcp_check_entry_t *ckq_e = NULL;
  tcp_packet_entry_t *inq_e = NULL;
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