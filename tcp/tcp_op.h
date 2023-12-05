#include "tcp_protocol.h"
#include <sys/queue.h>
#ifndef TCP_OP_H
#define TCP_OP_H

#define RTO 3

struct tcp_packet_entry
{
  TAILQ_ENTRY (tcp_packet_entry) entry;
  tcp_hdr_t *hdr;
};
typedef struct tcp_packet_entry tcp_packet_entry_t;

TAILQ_HEAD (tcpq, tcp_packet_entry);
struct tcpq pq;

void handle_tcp (tcp_hdr_t *hdr);
#endif /* -- TCP_OP_H -- */