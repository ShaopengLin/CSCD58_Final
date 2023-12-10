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

#endif /* -- TCP_HELPERS_H -- */