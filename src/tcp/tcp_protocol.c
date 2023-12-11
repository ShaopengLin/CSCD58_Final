#include "tcp_protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint16_t
tcp_cksum (const void *_data, int len)
{
  const uint8_t *data = _data;
  uint32_t sum;

  for (sum = 0; len >= 2; data += 2, len -= 2)
    sum += data[0] << 8 | data[1];
  if (len > 0)
    sum += data[0] << 8;
  while (sum > 0xffff)
    sum = (sum >> 16) + (sum & 0xffff);
  sum = htons (~sum);
  return sum ? sum : 0xffff;
}

void
tcp_gen_packet (tcp_hdr_t *header, uint8_t *data, uint16_t len,
                uint32_t src_ip, uint32_t dst_ip, uint32_t src_port,
                uint16_t dst_port, uint32_t seq_num, uint32_t ack_num,
                uint8_t flags, uint16_t window)
{
  memset (header, 0, sizeof (tcp_hdr_t));
  header->src_port = htons (src_port);
  header->des_port = htons (dst_port);
  header->seq_num = htonl (seq_num);
  header->ack_num = htonl (ack_num);

  header->doffset = 5;

  /* Need to assign at exact offset */
  *(((uint8_t *)header) + FLAG_OFS) = flags;

  header->window = htons (window);

  /* Generate pseudo header for the TCP checksum */
  tcp_pseudo_hdr_t p_hdr;
  p_hdr.src = src_ip;
  p_hdr.dst = dst_ip;
  p_hdr.zero = 0;
  p_hdr.pro = 6;
  p_hdr.len = htons (len + sizeof (tcp_hdr_t));

  uint8_t *cksum_buf = (uint8_t *)calloc (
      1, sizeof (tcp_hdr_t) + sizeof (tcp_pseudo_hdr_t) + len);
  memcpy (cksum_buf, &p_hdr, sizeof (tcp_pseudo_hdr_t));
  memcpy (cksum_buf + sizeof (tcp_pseudo_hdr_t), header, sizeof (tcp_hdr_t));
  memcpy (cksum_buf + sizeof (tcp_pseudo_hdr_t) + sizeof (tcp_hdr_t), data,
          len);
  header->cksum = 0;
  header->cksum = tcp_cksum (cksum_buf, sizeof (tcp_hdr_t)
                                            + sizeof (tcp_pseudo_hdr_t) + len);
  free (cksum_buf);
}

void
print_tcp_hdr (tcp_hdr_t *hdr)
{
  printf ("TCP Header :\n");
  printf ("\t Source Port : %u\n", ntohs (hdr->src_port));
  printf ("\t Destination Port : %u\n", ntohs (hdr->des_port));
  printf ("\t Sequence Number : %u\n", ntohl (hdr->seq_num));
  printf ("\t Acknowledgment Number : %u\n", ntohl (hdr->ack_num));
  printf ("\t Reserved : %u\n", hdr->rsrvd);
  printf ("\t Data Offset : %u\n", hdr->doffset);
  printf ("\t Flags :\n");
  printf ("\t\t FIN : %u\n", hdr->fin);
  printf ("\t\t SYN : %u\n", hdr->syn);
  printf ("\t\t RST : %u\n", hdr->rst);
  printf ("\t\t PSH : %u\n", hdr->psh);
  printf ("\t\t ACK : %u\n", hdr->ack);
  printf ("\t\t URG : %u\n", hdr->urg);
  printf ("\t\t ECE : %u\n", hdr->ece);
  printf ("\t\t CWR : %u\n", hdr->cwr);
  printf ("\t Window : %u\n", ntohs (hdr->window));
  printf ("\t Checksum : %u\n", ntohs (hdr->cksum));
  printf ("\t Urgent Pointer : %u\n", ntohs (hdr->urgptr));
}

/* TODO: Method to verify tcp header */
bool
tcp_verify_packet (uint8_t *packet, uint16_t len, uint16_t tcp_off,
                   uint32_t src_ip, uint32_t dst_ip)
{
  return true;
}

/* TODO: Generate SYN, SYNACK, packets, etc*/
void
tcp_gen_syn (tcp_hdr_t *header, uint32_t src_ip, uint32_t dst_ip,
             uint32_t src_port, uint16_t dst_port, uint32_t seq_num,
             uint16_t window)
{
  tcp_gen_packet (header, 0, 0, src_ip, dst_ip, src_port, dst_port, seq_num, 0,
                  (uint8_t)(SYN_FLAG), window);
}

void
tcp_gen_ack (tcp_hdr_t *header, uint32_t src_ip, uint32_t dst_ip,
             uint32_t src_port, uint16_t dst_port, uint32_t seq_num,
             uint32_t ack_num, uint16_t window)
{
  tcp_gen_packet (header, 0, 0, src_ip, dst_ip, src_port, dst_port, seq_num,
                  ack_num, (uint8_t)(ACK_FLAG), window);
}

bool
tcp_cmp_flag (tcp_hdr_t *hdr1, tcp_hdr_t *hdr2)
{
  return *(((uint8_t *)hdr1) + FLAG_OFS) == *(((uint8_t *)hdr2) + FLAG_OFS);
}