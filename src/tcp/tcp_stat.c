#include "tcp_stat.h"
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
  printf ("***** \n");
  printf ("***** Average RTT: %Lf ms\n", rtt_avg);
  printf ("***** Maximum RTT: %Lf ms\n", rtt_max);
  printf ("***** Minimum RTT: %Lf ms\n", rtt_min);
  printf ("***** Bandwidth Estimate: %Lf Kbits/s\n", bw);
  printf (
      "***** Sliding Window Size Best Estimate Based on Bandwidth: %Lf byte\n",
      (rtt_avg / 1000) * (bw * 1000) / 8);
  printf ("***** \n");
  printf ("*******************************\n");
  close (fp);
}