#include "protocol.h"
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

/*calculates the ip checksum for the packet*/
uint16_t
cksum (const void *_data, int len)
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
create_ip_header (struct ip_header *header, uint32_t src_addr,
                  uint32_t dest_addr, uint8_t protocol, uint16_t packet_len)
{
  header->ihl = 5;
  header->version = 4;
  header->tos = 0;
  header->len = htons (packet_len);
  global_ip_id++;
  header->id = htons (global_ip_id);

  header->frag_offset = htons (0x4000); /*default offset of the packet*/
  header->ttl = 64;                     /*default ttl set to 64*/
  header->protocol = protocol;
  header->saddr = src_addr;
  header->daddr = dest_addr;
  header->checksum = 0;
}

void create_icmp_echo_header(struct icmp_echo *header,int size){
    header->icmp_type = 8;
    header->icmp_code = 0;
    header->icmp_checksum = 0;
    header->identifier = global_ip_id;
    header->sequence_number = htons(1);
    header->icmp_checksum = cksum(header, sizeof(header));
    for(int i=0;i<size;i++){
      header->data[i] = 0;
    }
}

void
create_arp_header (struct arp_header *header, uint16_t operation,
                   uint8_t *src_mac, uint32_t src_ip, uint8_t *dest_mac,
                   uint32_t dest_ip)
{
  header->hardware = htons (1);      /*set to ethernext as default*/
  header->protocol = htons (0x0800); /*set to Ipv4*/
  header->hlen = EthernetAddrLen;
  header->plen = IpAddrLen;
  header->operation = htons (operation);
  memcpy (header->sha, src_mac, sizeof (uint8_t) * EthernetAddrLen);
  header->sip = src_ip;
  memcpy (header->tha, dest_mac, sizeof (uint8_t) * EthernetAddrLen);
  header->tip = dest_ip;
}

void
create_eth_header (struct eth_header *header, uint8_t *src_mac,
                   uint8_t *dest_mac, uint16_t type)
{
  memcpy (header->destination, dest_mac, sizeof (uint8_t) * EthernetAddrLen);
  memcpy (header->source, src_mac, sizeof (uint8_t) * EthernetAddrLen);
  header->type = htons (type);
}
