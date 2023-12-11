#include "../ip_stack/utils.h"
#include "tcp_protocol.h"
#include <pthread.h>
#include <stdbool.h>
#include <sys/queue.h>
#include <time.h>

#ifndef TCP_OP_H
#define TCP_OP_H

#define DEFAULT_RTO SEC_TO_NS (3)
#define ALPHA 0.9
extern uint32_t NUM_BYTES;
extern uint16_t SRC_PORT;  // Source port global
extern uint32_t SRC_IP;    // Source IP global
extern uint16_t DST_PORT;  // Destination port global
extern uint32_t DST_IP;    // Destination IP global
extern uint32_t SEQNUM;    // Sequence number global
extern uint8_t DST_MAC[6]; // Destination mac address
extern uint32_t RWND;      // Reciever window size
extern uint32_t sent_size; // sent_size
extern uint32_t PKT_SIZE;  // Packet size global
extern char *VARIANT;      // VARIANT Global
extern uint64_t ERTT;      // Estimated RTT Global
extern uint64_t TIMEOUT;   // RTO GLobal
extern uint64_t TESTING_PERIOD;

/* Recieving packet timeout */
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
  size_t len;
  uint64_t timeout;
  uint64_t sent_time;
  uint32_t rAck;
  bool retransmitted;
  bool RTT_counted;
} __attribute__ ((packed));
typedef struct tcp_check_entry tcp_check_entry_t;

struct tcp_send_entry
{
  TAILQ_ENTRY (tcp_send_entry) entry;
  tcp_check_entry_t *ckq_e;
  uint32_t seq_num;
  size_t len;
  bool is_retrans;
} __attribute__ ((packed));
typedef struct tcp_send_entry tcp_send_entry_t;

TAILQ_HEAD (tcp_iq, tcp_packet_entry);
extern struct tcp_iq tcp_inq;

TAILQ_HEAD (tcp_cq, tcp_check_entry);
extern struct tcp_cq tcp_ckq;

TAILQ_HEAD (tcp_sq, tcp_send_entry);
extern struct tcp_sq tcp_sdq;

extern pthread_mutex_t inq_lock;
extern pthread_cond_t inq_cond;

/*  */
void *tcp_check_timeout ();
void handle_tcp (tcp_hdr_t *hdr);

uint32_t tcp_handshake ();
void tcp_stop_and_wait (uint32_t ack_num);
uint32_t tcp_send_sliding_window_fixed (uint32_t window_size,
                                        uint32_t ack_num);
void tcp_send_sliding_window_slowS_fastR (uint32_t ack_num);

void tcp_teardown (uint32_t ack_num);

#endif /* -- TCP_OP_H -- */