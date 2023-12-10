#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>
#ifndef TCP_STATS_H
#define TCP_STATS_H
struct tcp_rtt_entry
{
  TAILQ_ENTRY (tcp_rtt_entry) entry;
  long double rtt;
} __attribute__ ((packed));
typedef struct tcp_rtt_entry tcp_rtt_entry_t;

struct tcp_bandwidth_entry
{
  TAILQ_ENTRY (tcp_bandwidth_entry) entry;
  long double bw;
} __attribute__ ((packed));
typedef struct tcp_bandwidth_entry tcp_bandwidth_entry_t;

struct tcp_congest_entry
{
  TAILQ_ENTRY (tcp_congest_entry) entry;
  uint32_t cwnd;
} __attribute__ ((packed));
typedef struct tcp_congest_entry tcp_congest_entry_t;

TAILQ_HEAD (tcp_rtt_q, tcp_rtt_entry);
extern struct tcp_rtt_q tcp_rttQ;

TAILQ_HEAD (tcp_bw_q, tcp_bandwidth_entry);
extern struct tcp_bw_q tcp_bwQ;

TAILQ_HEAD (tcp_cong_q, tcp_congest_entry);
extern struct tcp_cong_q tcp_congQ;

void add_RTT (uint64_t start, uint64_t end);
void add_BW (long double bandwidth);
void add_CWND (uint32_t cwnd);
#endif /* -- TCP_STATS_H -- */