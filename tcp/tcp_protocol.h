#include <endian.h>
#include <stdint.h>

#ifndef TCP_PROTOCOL_H
#define TCP_PROTOCOL_H

/* TODO: Macros for flags, attributes in hdr, timeout, etc*/

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
  uint8_t doffset : 4;
  uint8_t rsrvd : 4;
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

#endif /* -- TCP_PROTOCOL_H -- */