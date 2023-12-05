#include "tcp_protocol.h"
#include <pthread.h>
#include <sys/queue.h>
#include <time.h>

#ifndef TCP_OP_H
#define TCP_OP_H

#define DEFAULT_RTO 3

struct tcp_packet_entry
{
  TAILQ_ENTRY (tcp_packet_entry) entry;
  tcp_hdr_t *hdr;
};
typedef struct tcp_packet_entry tcp_packet_entry_t;

struct tcp_check_entry
{
  TAILQ_ENTRY (tcp_check_entry) entry;
  tcp_hdr_t *hdr;
  time_t timeout;
} __attribute__ ((packed));
typedef struct tcp_check_entry tcp_check_entry_t;

TAILQ_HEAD (tcp_iq, tcp_packet_entry);
struct tcp_iq tcp_inq;

TAILQ_HEAD (tcp_cq, tcp_check_entry);
struct tcp_cq tcp_ckq;

pthread_mutex_t inq_lock;

void handle_tcp (tcp_hdr_t *hdr);
tcp_hdr_t *tcp_wait_packet (uint32_t target_ack, time_t timeout, uint8_t flag);

void tcp_handshake ();
#endif /* -- TCP_OP_H -- */