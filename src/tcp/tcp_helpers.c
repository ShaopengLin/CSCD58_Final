#include "tcp_helpers.h"
#include "../ip_stack/sendpacket.h"
#include "../ip_stack/utils.h"
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
char *VARIANT;

struct tcp_iq tcp_inq;
struct tcp_cq tcp_ckq;
pthread_mutex_t inq_lock;
pthread_cond_t inq_cond;

void
initializeTCP (int argc, char **argv)
{
  // Initializes SEQNUM, locks and conditional variable and define user inputs
  init_genrand (0);
  SEQNUM = genrand_int32 ();

  VARIANT = argv[1];
  NUM_BYTES = atoi (argv[2]);
  PKT_SIZE = atoi (argv[3]);
  DST_IP = inet_addr (argv[4]);
  SRC_PORT = atoi (argv[5]);
  DST_PORT = atoi (argv[6]);

  if (DST_IP == INADDR_NONE)
    {
      fprintf (stderr, "Invalid IP address format: %s\n", argv[3]);
      return 1;
    }
  TAILQ_INIT (&tcp_inq);
  TAILQ_INIT (&tcp_ckq);

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
}

void
calculateERTT (uint64_t prevTime, uint64_t curTime)
{
  uint64_t SampleRTT = curTime - prevTime;
  ERTT = (uint64_t)((long double)ALPHA * ERTT)
         + (uint64_t)((long double)(1 - ALPHA) * ERTT);
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
          if (tcp_cmp_flag (inq_e->hdr, syn_check->hdr)
              && inq_e->hdr->ack_num == syn_check->hdr->ack_num)
            {
              if (!syn_check->retransmitted)
                calculateERTT (start, curTime);

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
          // perror ("RETRANS");
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