#include <arpa/inet.h>
#include <endian.h>
#include <stdbool.h>
#include <stdint.h>

#ifndef TCP_PROTOCOL_H
#define TCP_PROTOCOL_H

/* TODO: Macros for timeout, etc*/

struct tcp_hdr
{
  uint16_t src_port; // TCP source port
  uint16_t des_port; // TCP destination port
  uint32_t seq_num;  // sequence number
  uint32_t ack_num;  // acknowledgment number

#if BYTE_ORDER == LITTLE_ENDIAN
  uint8_t rsrvd : 4;   // Unused, set to 0
  uint8_t doffset : 4; // offset where data begins
  uint8_t fin : 1;
  uint8_t syn : 1;
  uint8_t rst : 1;
  uint8_t psh : 1;
  uint8_t ack : 1;
  uint8_t urg : 1;
  uint8_t ece : 1;
  uint8_t cwr : 1;
#elif BYTE_ORDER == BIG_ENDIAN
  uint8_t doffset : 4; // Unused, set to 0
  uint8_t rsrvd : 4;   // offset where data begins
  uint8_t cwr : 1;
  uint8_t ece : 1;
  uint8_t urg : 1;
  uint8_t ack : 1;
  uint8_t psh : 1;
  uint8_t rst : 1;
  uint8_t syn : 1;
  uint8_t fin : 1;
#else
#error "Byte ordering ot specified "
#endif

  uint16_t window; // Advertised sliding window size
  uint16_t cksum;  // Checksum of pseudo + tcp + data
  uint16_t urgptr; // Urgent pointer indicate end of urgent portion in data.
} __attribute__ ((packed));
typedef struct tcp_hdr tcp_hdr_t;

struct tcp_pseudo_hdr
{
  uint32_t src; // source ip
  uint32_t dst; // destination ip
  uint8_t zero; // Unused, set to 0
  uint8_t pro;  // Protocol number same as the one used in IP datagram
  uint16_t len; // length of tcp + data. Not including pseudo.
} __attribute__ ((packed));
typedef struct tcp_pseudo_hdr tcp_pseudo_hdr_t;

#define FLAG_OFS 13
#define CWR_FLAG (0 | (1U << 7))
#define ECE_FLAG (0 | (1U << 6))
#define URG_FLAG (0 | (1U << 5))
#define ACK_FLAG (0 | (1U << 4))
#define PSH_FLAG (0 | (1U << 3))
#define RST_FLAG (0 | (1U << 2))
#define SYN_FLAG (0 | (1U << 1))
#define FIN_FLAG (0 | (1U))

/* Generate a network encoded tcp header onto the *header variable */
void tcp_gen_packet (tcp_hdr_t *header, uint8_t *data, uint16_t len,
                     uint32_t src_ip, uint32_t dst_ip, uint32_t src_port,
                     uint16_t dst_port, uint32_t seq_num, uint32_t ack_num,
                     uint8_t flags, uint16_t window);
/* Helper to generate syn */
void tcp_gen_syn (tcp_hdr_t *header, uint32_t src_ip, uint32_t dst_ip,
                  uint32_t src_port, uint16_t dst_port, uint32_t seq_num,
                  uint16_t window);
/* Helper to generate ack */
void tcp_gen_ack (tcp_hdr_t *header, uint32_t src_ip, uint32_t dst_ip,
                  uint32_t src_port, uint16_t dst_port, uint32_t seq_num,
                  uint32_t ack_num, uint16_t window);

/* Print function for tcp */
void print_tcp_hdr (tcp_hdr_t *hdr);

bool tcp_verify_packet (uint8_t *packet, uint16_t len, uint16_t tcp_off,
                        uint32_t src_ip, uint32_t dst_ip);
uint16_t tcp_cksum (const void *_data, int len);

/* Given two headers, check if their flags are he same. */
bool tcp_cmp_flag (tcp_hdr_t *hdr1, tcp_hdr_t *hdr2);
#endif /* -- TCP_PROTOCOL_H -- */