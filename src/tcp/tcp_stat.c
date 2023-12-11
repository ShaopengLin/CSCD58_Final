#include "tcp_stat.h"
#include "tcp_op.h"
#include <unistd.h>
void
add_RTT (uint64_t start, uint64_t end)
{
  tcp_rtt_entry_t *r = (tcp_rtt_entry_t *)calloc (1, sizeof (tcp_rtt_entry_t));
  r->rtt = (long double)(end - start) / 1000000;
  TAILQ_INSERT_TAIL (&tcp_rttQ, r, entry);
}

void
add_BW (long double bandwidth)
{
  tcp_bandwidth_entry_t *bw_e
      = (tcp_bandwidth_entry_t *)calloc (1, sizeof (tcp_bandwidth_entry_t));
  bw_e->bw = bandwidth;
  TAILQ_INSERT_TAIL (&tcp_bwQ, bw_e, entry);
}

void
add_CWND (uint32_t cwnd)
{
  tcp_congest_entry_t *cwnd_e
      = (tcp_congest_entry_t *)calloc (1, sizeof (tcp_congest_entry_t));
  cwnd_e->cwnd = cwnd;
  TAILQ_INSERT_TAIL (&tcp_congQ, cwnd_e, entry);
}

void
print_result ()
{
  FILE *fp;
  fp = fopen ("tcprtt.txt", "w");

  /* Calculate RTT stats and write the entries to file for graphing */
  tcp_rtt_entry_t *rtt_e = NULL;
  int rtt_count = 1;
  long double rtt_avg = 0;
  long double rtt_max = 0;
  long double rtt_min = 1000; //  Unlikely to have 20s RTT
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

  /* Calculate bandwidth */
  tcp_bandwidth_entry_t *bw_e = NULL;
  long double bw = 0;
  int bandwidth_count = 0;
  TAILQ_FOREACH (bw_e, &tcp_bwQ, entry)
  {
    bw += bw_e->bw;
    bandwidth_count++;
  }
  bw = bw / bandwidth_count;

  /* Calculate and print congestion window to the file */
  tcp_congest_entry_t *cwnd_e = NULL;
  int cwnd_count = 1;

  fp = fopen ("tcpcong.txt", "w");
  TAILQ_FOREACH (cwnd_e, &tcp_congQ, entry)
  {
    fprintf (fp, "%d %u\n", cwnd_count,
             cwnd_e->cwnd / 1000); // Scale down for better graph
    cwnd_count++;
  }
  printf ("***** \n");
  printf ("***** Average RTT: %Lf ms\n", rtt_avg);
  printf ("***** Maximum RTT: %Lf ms\n", rtt_max);
  printf ("***** Minimum RTT: %Lf ms\n", rtt_min);
  printf ("***** Bandwidth Estimate: %Lf Kbits/s\n", bw);
  printf (
      "***** Sliding Window Size Best Estimate Based on Bandwidth: %Lf byte\n",
      (rtt_avg / 1000) * (bw * 1000) / 8); // Algorithm for window size
  printf ("***** \n");
  printf ("*******************************\n");
  close (fp);
}

void
printSWFF (uint32_t ack_num)
{
  printf ("\n***** FIXED WINDOW FINDING OPTIMAL WND\n");
  printf ("\n***** STOP WHEN BANDWIDTH NO LONGER INCREASE\n");
  long double best_band = 0;
  int best_band_size = 1;

  /* Runs the sliding window algorithm until we see decrease in performance */
  for (int i = 1; i < RWND / PKT_SIZE; i += 5)
    {
      printf ("\n***** INCREASING WND TO: %u byte\n", i * PKT_SIZE);
      TESTING_PERIOD = SEC_TO_NS (3);
      tcp_send_sliding_window_fixed (i, ack_num);

      /* Calculate bandwidth and remove all the records used */
      tcp_bandwidth_entry_t *bw_e = NULL;
      long double bw = 0;
      int bandwidth_count = 0;
      while (!TAILQ_EMPTY (&tcp_bwQ))
        {
          bw_e = TAILQ_FIRST (&tcp_bwQ);
          bw += bw_e->bw;
          bandwidth_count++;
          TAILQ_REMOVE (&tcp_bwQ, bw_e, entry);
          free (bw_e);
        }
      while (!TAILQ_EMPTY (&tcp_congQ))
        {
          tcp_congest_entry_t *cong_e = TAILQ_FIRST (&tcp_congQ);
          TAILQ_REMOVE (&tcp_congQ, cong_e, entry);
          free (cong_e);
        }
      while (!TAILQ_EMPTY (&tcp_rttQ))
        {
          tcp_rtt_entry_t *rtt_e = TAILQ_FIRST (&tcp_rttQ);
          TAILQ_REMOVE (&tcp_rttQ, rtt_e, entry);
          free (rtt_e);
        }

      /* Stop if performance dropped */
      bw = bw / bandwidth_count;
      if (best_band != 0 && best_band > bw)
        {
          printf ("\n***** BW vs BEST Bandwidth: %Lf,%Lf \n", bw, best_band);
          break;
        }

      if (best_band < bw)
        {
          best_band = bw;
          best_band_size = i;
        }

      printf ("\n***** BW vs BEST Bandwidth: %Lf,%Lf \n", bw, best_band);
    }
  printf ("\n***** Best Bandwidth: %Lf\n", best_band);

  printf ("\n***** RUNNING RESULT WITH WINDOW: %u\n", best_band_size);

  /* Run on the assumede optimal space */
  TESTING_PERIOD = SEC_TO_NS (5);
  tcp_send_sliding_window_fixed (best_band, ack_num);
}

void
printDescription ()
{
  printf ("\n***** Reciever Window Size %u\n", RWND);
  printf ("\n***** Packet Size %u \n", PKT_SIZE);
  printf ("\n***** Source Port %u \n", SRC_PORT);
  printf ("\n***** Destination Port %u \n", DST_PORT);
}