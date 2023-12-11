#include "tcp_helpers.h"
#include "../ip_stack/sendpacket.h"
#include "../ip_stack/utils.h"
#include "tcp_stat.h"
#include <linux/in.h>
uint32_t SEQNUM;
uint16_t SRC_PORT;
uint16_t DST_PORT;
uint32_t DST_IP;
uint32_t NUM_BYTES;
uint32_t PKT_SIZE;
uint32_t SRC_IP;
uint64_t ERTT;
uint64_t TIMEOUT;
uint64_t TESTING_PERIOD;
char *VARIANT;
struct tcp_iq tcp_inq;
struct tcp_cq tcp_ckq;
struct tcp_sq tcp_sdq;
struct tcp_rtt_q tcp_rttQ;
struct tcp_bw_q tcp_bwQ;
struct tcp_cong_q tcp_congQ;
pthread_mutex_t inq_lock;
pthread_cond_t inq_cond;

void
initializeTCP (int argc, char **argv)
{
  // Initializes SEQNUM, locks and conditional variable and define user inputs
  // init_genrand (0);
  // SEQNUM = genrand_int32 ();
  SEQNUM = 0;

  VARIANT = argv[1];
  NUM_BYTES = INTMAX_MAX;
  PKT_SIZE = atoi (argv[3]);
  DST_IP = inet_addr (argv[4]);
  SRC_PORT = atoi (argv[5]);
  DST_PORT = atoi (argv[6]);
  TESTING_PERIOD = SEC_TO_NS (atoi (argv[7]));

  if (DST_IP == INADDR_NONE)
    {
      fprintf (stderr, "Invalid IP address format: %s\n", argv[3]);
      return 1;
    }
  TAILQ_INIT (&tcp_inq);
  TAILQ_INIT (&tcp_ckq);
  TAILQ_INIT (&tcp_sdq);
  TAILQ_INIT (&tcp_rttQ);
  TAILQ_INIT (&tcp_bwQ);
  TAILQ_INIT (&tcp_congQ);
  if (pthread_mutex_init (&inq_lock, NULL) != 0)
    exit (-1);
  if (pthread_cond_init (&inq_cond, NULL) != 0)
    exit (-1);

  // Initializes the socket used to send TCP packets
  initTCPSocket ();

  ERTT = SEC_TO_NS (1);
  TIMEOUT = DEFAULT_RTO;
  // Initialize the source IP address
  uint8_t mac[6];
  char *iface = find_active_interface ();
  get_mac_ip (iface, &mac, &SRC_IP);
  free (iface);

  // Initializes the packet
  pthread_t timer_tid;
  if (pthread_create (&timer_tid, NULL, &tcp_check_timeout, NULL) != 0)
    exit (-1);

  RWND = 0;
}

void
calculateERTT (uint64_t prevTime, uint64_t curTime)
{

  uint64_t SampleRTT = curTime - prevTime;
  if (ERTT == SEC_TO_NS (1))
    ERTT = SampleRTT;
  else
    {
      ERTT = (uint64_t)((long double)ALPHA * ERTT)
             + (uint64_t)((long double)(1 - ALPHA) * ERTT);
    }

  TIMEOUT = 2 * ERTT;
}

tcp_hdr_t *
tcp_wait_packet (tcp_hdr_t *hdr, uint32_t len, uint64_t start, uint8_t flag)
{
  tcp_check_entry_t *syn_check
      = (tcp_check_entry_t *)calloc (1, sizeof (tcp_check_entry_t));
  syn_check->sent_time = start;
  syn_check->timeout = start + TIMEOUT;
  syn_check->retransmitted = false;
  syn_check->hdr = (tcp_hdr_t *)calloc (1, sizeof (tcp_hdr_t));
  tcp_gen_packet (syn_check->hdr, NULL, 0, 0, 0, 0, 0, 0,
                  ntohl (hdr->seq_num) + len, flag, 0);
  pthread_mutex_lock (&inq_lock);
  TAILQ_INSERT_TAIL (&tcp_ckq, syn_check, entry);
  pthread_mutex_unlock (&inq_lock);

  while (1)
    {
      tcp_packet_entry_t *inq_e = NULL;
      tcp_hdr_t *ret = NULL;
      pthread_mutex_lock (&inq_lock);
      while (TAILQ_EMPTY (&tcp_inq))
        pthread_cond_wait (&inq_cond, &inq_lock);
      // TAILQ_FOREACH (ckq_e, &tcp_ckq, entry)
      // {
      uint64_t curTime = getNano ();
      while (!TAILQ_EMPTY (&tcp_inq))
        {
          inq_e = TAILQ_FIRST (&tcp_inq);
          ret = inq_e->hdr;
          TAILQ_REMOVE (&tcp_inq, inq_e, entry);
          free (inq_e);
          /* Match packet */
          if (tcp_cmp_flag (ret, syn_check->hdr)
              && ret->ack_num >= syn_check->hdr->ack_num)
            {
              if (!syn_check->retransmitted)
                calculateERTT (syn_check->sent_time, curTime);
              add_RTT (syn_check->sent_time, curTime);
              TAILQ_REMOVE (&tcp_ckq, syn_check, entry);

              free (syn_check->hdr);
              free (syn_check);

              pthread_mutex_unlock (&inq_lock);
              return ret;
            }
          else
            free (ret);
        }

      /* Timeout */

      if (syn_check->timeout <= curTime)
        {
          perror ("RETRANS");
          TIMEOUT *= 2;
          syn_check->sent_time = curTime;
          syn_check->timeout = curTime + TIMEOUT;
          syn_check->retransmitted = true;
          warpHeaderAndSendTcp (
              hdr,
              sizeof (tcp_hdr_t)
                  + (syn_check->hdr->syn == 1 || syn_check->hdr->fin == 1
                         ? 0
                         : len),
              DST_IP, DST_MAC);
        }
      pthread_mutex_unlock (&inq_lock);
    }
  TAILQ_REMOVE (&tcp_ckq, syn_check, entry);
  free (syn_check->hdr);
  free (syn_check);
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

void
send_sw (tcp_hdr_t *hdr, uint8_t *data, uint32_t len, tcp_check_entry_t *ckq_e,
         uint32_t ack_num)
{
  tcp_gen_packet (hdr, data, len, SRC_IP, DST_IP, SRC_PORT, DST_PORT,
                  ckq_e ? ntohl (ckq_e->hdr->ack_num) - len : SEQNUM, ack_num,
                  (uint8_t)(PSH_FLAG | ACK_FLAG), 65535);
  warpHeaderAndSendTcp (hdr, sizeof (tcp_hdr_t) + len, DST_IP, DST_MAC);
}

uint32_t
handle_SS_inc (uint32_t c_wnd, uint32_t t_wnd, bool *is_AIMD)
{
  if (&is_AIMD)
    {
      c_wnd += (uint16_t)(PKT_SIZE
                          * ((long double)PKT_SIZE / (long double)c_wnd));
    }
  else
    {
      c_wnd += PKT_SIZE;
      if (c_wnd > t_wnd)
        {
          c_wnd = t_wnd;
          *is_AIMD = true;
        }
    }
  if (c_wnd > RWND)
    c_wnd = RWND;
  return c_wnd;
}

void
handle_SS_fast_retransmit (uint32_t max_ack, uint32_t *c_wnd, bool *is_AIMD)
{
  tcp_check_entry_t *ckq_e = NULL;
  tcp_packet_entry_t *inq_e = NULL;
  if (!TAILQ_EMPTY (&tcp_ckq))
    {
      ckq_e = TAILQ_FIRST (&tcp_ckq);
    }
  while (!TAILQ_EMPTY (&tcp_inq))
    {
      inq_e = TAILQ_FIRST (&tcp_inq);
      uint32_t e_seq = ntohl (inq_e->hdr->ack_num);

      if (ckq_e && max_ack == (ntohl (ckq_e->hdr->ack_num) - ckq_e->len)
          && e_seq == max_ack)
        {
          if (ckq_e->retransmitted)
            {
              *c_wnd += PKT_SIZE;
              if (*c_wnd > RWND)
                {
                  *c_wnd = RWND;
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
      TIMEOUT *= 2;

      SEQNUM -= ckq_e->len;
      // perror ("FASTRRRRR");
      tcp_send_entry_t *sq_e;
      ckq_e = TAILQ_FIRST (&tcp_ckq);
      sq_e = (tcp_send_entry_t *)calloc (1, sizeof (tcp_send_entry_t));
      sq_e->len = ckq_e->len;
      sq_e->seq_num = ntohl (ckq_e->hdr->ack_num) - ckq_e->len;
      sq_e->is_retrans = false;
      TAILQ_INSERT_HEAD (&tcp_sdq, sq_e, entry);

      TAILQ_REMOVE (&tcp_ckq, ckq_e, entry);
      free (ckq_e->hdr);
      free (ckq_e);

      *c_wnd = *c_wnd / 2 < PKT_SIZE ? PKT_SIZE : *c_wnd / 2;
      *c_wnd = *c_wnd + 3 * PKT_SIZE > RWND ? RWND : *c_wnd + 3 * PKT_SIZE;
      *is_AIMD = true;
    }
  return c_wnd;
}

void
handle_simple_fast_retransmit (uint32_t *s_wnd, uint32_t max_ack)
{
  tcp_check_entry_t *ckq_e = NULL;
  tcp_packet_entry_t *inq_e = NULL;
  if (!TAILQ_EMPTY (&tcp_ckq))
    {
      ckq_e = TAILQ_FIRST (&tcp_ckq);
    }
  while (!TAILQ_EMPTY (&tcp_inq))
    {
      inq_e = TAILQ_FIRST (&tcp_inq);
      uint32_t e_seq = ntohl (inq_e->hdr->ack_num);

      if (ckq_e && max_ack == (ntohl (ckq_e->hdr->ack_num) - ckq_e->len)
          && e_seq == max_ack)
        {
          ckq_e->rAck++;
        }

      TAILQ_REMOVE (&tcp_inq, inq_e, entry);
      free (inq_e->hdr);
      free (inq_e);
    }

  if (ckq_e && ckq_e->rAck >= 3)
    {
      ckq_e = TAILQ_FIRST (&tcp_ckq);
      TIMEOUT *= 2;
      SEQNUM -= ckq_e->len;
      // perror ("FASTRRRRR");
      tcp_send_entry_t *sq_e;
      ckq_e = TAILQ_FIRST (&tcp_ckq);
      sq_e = (tcp_send_entry_t *)calloc (1, sizeof (tcp_send_entry_t));
      sq_e->len = ckq_e->len;
      sq_e->seq_num = ntohl (ckq_e->hdr->ack_num) - ckq_e->len;
      sq_e->is_retrans = false;
      TAILQ_INSERT_HEAD (&tcp_sdq, sq_e, entry);

      TAILQ_REMOVE (&tcp_ckq, ckq_e, entry);
      free (ckq_e->hdr);
      free (ckq_e);
    }
}
void
handle_SS_timeout_retransmit (uint64_t curTime, uint32_t *t_cwnd,
                              uint32_t *c_wnd, uint32_t *s_wnd, bool *is_AIMD)
{

  tcp_check_entry_t *ckq_e = NULL;
  bool retrans = false;
  // tcp_packet_entry_t *inq_e = NULL;
  if (!TAILQ_EMPTY (&tcp_ckq))
    {
      ckq_e = TAILQ_FIRST (&tcp_ckq);
      if (ckq_e->timeout <= curTime)
        {
          retrans = true;
          *t_cwnd = *c_wnd / 2 < PKT_SIZE ? PKT_SIZE : *c_wnd / 2;
          *c_wnd = PKT_SIZE;
        }
    }
  if (retrans)
    {
      // perror ("SLOWRRRR");

      TIMEOUT *= 2;
      SEQNUM = ntohl (ckq_e->hdr->ack_num) - ckq_e->len;
      *s_wnd = 0;
      tcp_send_entry_t *sq_e;
      tcp_send_entry_t *prev = NULL;
      while (!TAILQ_EMPTY (&tcp_ckq))
        {
          ckq_e = TAILQ_FIRST (&tcp_ckq);
          sq_e = (tcp_send_entry_t *)calloc (1, sizeof (tcp_send_entry_t));
          sq_e->len = ckq_e->len;
          sq_e->seq_num = ntohl (ckq_e->hdr->ack_num) - ckq_e->len;
          if (!prev)
            {
              TAILQ_INSERT_HEAD (&tcp_sdq, sq_e, entry);
            }
          else
            {
              TAILQ_INSERT_AFTER (&tcp_sdq, prev, sq_e, entry);
            }
          prev = sq_e;
          TAILQ_REMOVE (&tcp_ckq, ckq_e, entry);
          free (ckq_e->hdr);
          free (ckq_e);
        }

      *is_AIMD = false;
    }
}
void
handle_simple_timeout_retransmit (uint32_t *s_wnd, uint64_t curTime)
{
  tcp_check_entry_t *ckq_e = NULL;
  bool retrans = false;
  // tcp_packet_entry_t *inq_e = NULL;
  if (!TAILQ_EMPTY (&tcp_ckq))
    {
      ckq_e = TAILQ_FIRST (&tcp_ckq);
      if (ckq_e->timeout <= curTime)
        {
          retrans = true;
        }
    }
  if (retrans)
    {
      // perror ("SLOWRRRR");

      TIMEOUT *= 2;
      SEQNUM = ntohl (ckq_e->hdr->ack_num) - ckq_e->len;
      *s_wnd = 0;
      tcp_send_entry_t *sq_e;
      tcp_send_entry_t *prev = NULL;
      while (!TAILQ_EMPTY (&tcp_ckq))
        {
          ckq_e = TAILQ_FIRST (&tcp_ckq);
          sq_e = (tcp_send_entry_t *)calloc (1, sizeof (tcp_send_entry_t));
          sq_e->len = ckq_e->len;
          sq_e->seq_num = ntohl (ckq_e->hdr->ack_num) - ckq_e->len;
          sq_e->is_retrans = false;
          if (!prev)
            {
              TAILQ_INSERT_HEAD (&tcp_sdq, sq_e, entry);
            }
          else
            {
              TAILQ_INSERT_AFTER (&tcp_sdq, prev, sq_e, entry);
            }
          prev = sq_e;
          TAILQ_REMOVE (&tcp_ckq, ckq_e, entry);
          free (ckq_e->hdr);
          free (ckq_e);
        }
    }
}
uint32_t
get_max_ack (uint32_t max_ack)
{
  tcp_check_entry_t *ckq_e = NULL;
  tcp_packet_entry_t *inq_e = NULL;
  TAILQ_FOREACH (inq_e, &tcp_inq, entry)
  {
    uint32_t e_ack = ntohl (inq_e->hdr->ack_num);
    max_ack = max_ack < e_ack ? e_ack : max_ack;
  }

  return max_ack;
}

void
init_sendQ_packets (int32_t *pktgen_seqnum, uint32_t count)
{

  tcp_send_entry_t *sq_e = NULL;
  for (int i = 0; i < count; i++)
    {
      sq_e = (tcp_send_entry_t *)calloc (1, sizeof (tcp_send_entry_t));
      sq_e->len = PKT_SIZE;
      sq_e->seq_num = *pktgen_seqnum;
      sq_e->is_retrans = false;

      TAILQ_INSERT_TAIL (&tcp_sdq, sq_e, entry);
      *pktgen_seqnum += PKT_SIZE;
    }
}