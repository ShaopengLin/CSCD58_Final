#include "tcp_stat.h"

void
add_RTT (uint64_t start, uint64_t end)
{
  tcp_rtt_entry_t *r = (tcp_rtt_entry_t *)calloc (1, sizeof (tcp_rtt_entry_t));
  r->rtt = (long double)(start - end) / 1000000;
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