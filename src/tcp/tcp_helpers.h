#include "tcp_op.h"
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#ifndef TCP_HELPERS_H
#define TCP_HELPERS_H

void initializeTCP (int argc, char **argv);
void calculateERTT (uint64_t prevTime, uint64_t curTime);
tcp_hdr_t *tcp_wait_packet (tcp_hdr_t *hdr, uint32_t len, uint64_t start,
                            uint8_t flag);
void tcp_add_sw_packet (uint32_t target_ack, uint64_t sent_time, uint64_t RTT,
                        size_t len);
void send_sw (tcp_hdr_t *hdr, uint8_t *data, uint32_t len,
              tcp_check_entry_t *ckq_e, uint32_t ack_num);
uint32_t handle_SS_inc (uint32_t c_wnd, uint32_t t_wnd, bool *is_AIMD);
uint32_t get_max_ack (uint32_t max_ack);
void init_sendQ_packets (int32_t *pktgen_seqnum, uint32_t count);
void handle_SS_fast_retransmit (uint32_t max_ack, uint32_t *c_wnd,
                                bool *is_AIMD);
void handle_simple_fast_retransmit (uint32_t *s_wnd, uint32_t max_ack);
void handle_SS_timeout_retransmit (uint64_t curTime, uint32_t *t_cwnd,
                                   uint32_t *c_wnd, uint32_t *s_wnd,
                                   bool *is_AIMD);
void handle_simple_timeout_retransmit (uint32_t *s_wnd, uint64_t curTime);

#endif /* -- TCP_HELPERS_H -- */