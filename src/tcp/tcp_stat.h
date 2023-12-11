#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>
#ifndef TCP_STATS_H
#define TCP_STATS_H

/* Entry keeping record of RTT. rtt in ms*/
struct tcp_rtt_entry
{
  TAILQ_ENTRY (tcp_rtt_entry) entry;
  long double rtt;
} __attribute__ ((packed));
typedef struct tcp_rtt_entry tcp_rtt_entry_t;

/* Entry keeping record of Bandwidth with repsect to time. bw in float Kbit */
struct tcp_bandwidth_entry
{
  TAILQ_ENTRY (tcp_bandwidth_entry) entry;
  long double bw;
} __attribute__ ((packed));
typedef struct tcp_bandwidth_entry tcp_bandwidth_entry_t;

/* Entry keeping record of congestion window with repect to RTT. cwnd in byte
 */
struct tcp_congest_entry
{
  TAILQ_ENTRY (tcp_congest_entry) entry;
  uint32_t cwnd;
} __attribute__ ((packed));
typedef struct tcp_congest_entry tcp_congest_entry_t;

// List of rtts
TAILQ_HEAD (tcp_rtt_q, tcp_rtt_entry);
extern struct tcp_rtt_q tcp_rttQ;

// List of bandwidths
TAILQ_HEAD (tcp_bw_q, tcp_bandwidth_entry);
extern struct tcp_bw_q tcp_bwQ;

// List of congestions
TAILQ_HEAD (tcp_cong_q, tcp_congest_entry);
extern struct tcp_cong_q tcp_congQ;

/* Add a RTT entry to tcp_rttQ. Start being the sent time while end means
 * arrival */
void add_RTT (uint64_t start, uint64_t end);

/* Add a bandwidth entry to tcp_bwQ. bandwidth assumed in Kbits/s */
void add_BW (long double bandwidth);

/* Add a congestion entry to tcp_congQ. cwnd assumed in bytes */
void add_CWND (uint32_t cwnd);

/* Run and print the result of finding a optimal sliding window */
void printSWFF ();

/* Print user input  */
void printDescription ();

/* Calculate final statistics and print to user. */
void print_result ();
#endif /* -- TCP_STATS_H -- */