#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>

#define EthernetAddrLen 6
#define IpAddrLen 4

/*this variable is used to make sure to assign unique id to each packet*/
static uint16_t global_ip_id = 0;

struct ip_header {
    unsigned int  ihl:4;
    unsigned int  version:4; /*we are using IPV4 protocol*/
    uint8_t  tos; /*type of service we use*/
    uint16_t len; /*length of the packet*/
    uint16_t id; 
    uint16_t offset; /*offset of the packet*/
    uint8_t  ttl;   /*time to live for the packet*/
    uint8_t  protocol; /*protocol for this packet*/
    uint16_t checksum;
    uint32_t saddr, daddr; /*source and destination address in ip*/
};

struct arp_header {
    uint16_t hardware;    /*hardware type*/
    uint16_t protocol;
    uint8_t hlen;      /*hardware address length*/
    uint8_t plen;      /*protocol length*/
    uint16_t operation;     /*arp request or arp reply*/
    uint8_t sha[EthernetAddrLen];    /*source hardware*/
    uint32_t sip;    /*source ip*/
    uint8_t tha[EthernetAddrLen];    /*receiver hardware*/
    uint32_t tip;    /*destination ip*/
};

struct eth_header {
    uint8_t  destination[EthernetAddrLen];  
    uint8_t  source[EthernetAddrLen]; 
    uint16_t type;
}; 

enum ethernetTypes {
  ether_arp = 0x0806,
  ether_ip = 0x0800,
};


enum arpOperations {
  arp_request = 0x0001,
  arp_reply = 0x0002,
};
/*generates the checksum of this ip header please give me the header length not the length of whole packet usually */
uint16_t ip_checksum(void *header, int len);
/*creates the ip header which is ipv4 and has ip header length4 and offset is 0, ttl is 64 and using non repeated ids*/
void create_ip_header(struct ip_header *header, uint32_t src_addr, uint32_t dest_addr, 
                        uint8_t protocol, uint16_t packet_len);
/*creates the arp header which has the default hardware type of ethernet and protocol with ipv4*/
void create_arp_header(struct arp_header *header, uint16_t operation, uint8_t *src_mac, uint32_t src_ip, 
                        uint8_t *dest_mac, uint32_t dest_ip);

void create_eth_header(struct eth_header *header, uint8_t *src_mac, uint8_t *dest_mac, uint16_t type);

