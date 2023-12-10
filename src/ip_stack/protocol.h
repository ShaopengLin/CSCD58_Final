#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>

#define EthernetAddrLen 6
#define IpAddrLen 4

/*this variable is used to make sure to assign unique id to each packet*/
static uint16_t global_ip_id = 0;

struct __attribute__((packed)) ip_header {
    unsigned int  ihl:4;         // Internet Header Length
    unsigned int  version:4;     // Version (4 for IPv4)
    uint8_t  tos;                // Type of Service
    uint16_t len;                // Total length of the packet (header + data)
    uint16_t id;                 // Identification
    uint16_t frag_offset;     // Fragment Offset (13 bits) - for fragmentation
    uint8_t  ttl;                // Time to Live
    uint8_t  protocol;           // Protocol (e.g., TCP is 6, ICMP is 1)
    uint16_t checksum;           // Header Checksum
    uint32_t saddr;              // Source Address
    uint32_t daddr;              // Destination Address
    // Optional fields and padding might go here, depending on IHL value
};


struct __attribute__((packed)) icmp_header {
  uint8_t icmp_type;
  uint8_t icmp_code;
  uint16_t icmp_sum;
  
};

struct __attribute__((packed)) icmp_echo {
    uint8_t icmp_type;    // Type of ICMP message (8 for Echo Request, 0 for Echo Reply)
    uint8_t icmp_code;    // Code for the ICMP message (should be 0 for Echo Request/Reply)
    uint16_t icmp_checksum; // Checksum for the ICMP segment

    uint16_t identifier;  // Used to match echoes and replies
    uint16_t sequence_number; // Sequence number to match requests with replies
    uint8_t data[];

    // This would be followed by the data payload of the message, which is variable length
};



struct __attribute__((packed)) arp_header {
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

struct icmp_list{
    uint16_t id;
    clock_t start;
    struct icmp_list *next;
};

enum ethernetTypes {
  ether_arp = 0x0806,
  ether_ip = 0x0800,
};

enum ip_protocol {
  ip_protocol_icmp = 0x0001,
};

enum arpOperations {
  arp_request = 0x0001,
  arp_reply = 0x0002,
};
/*generates the checksum of this ip header please give me the header length not the length of whole packet usually */
uint16_t cksum (const void *_data, int len);
/*creates the ip header which is ipv4 and has ip header length 5 and offset is 0, ttl is 64 and using non repeated ids*/
void create_ip_header(struct ip_header *header, uint32_t src_addr, uint32_t dest_addr, 
                        uint8_t protocol, uint16_t packet_len);
void create_icmp_echo_header(struct icmp_echo *header,int size);
/*creates the arp header which has the default hardware type of ethernet and protocol with ipv4*/
void create_arp_header(struct arp_header *header, uint16_t operation, uint8_t *src_mac, uint32_t src_ip, 
                        uint8_t *dest_mac, uint32_t dest_ip);

void create_eth_header(struct eth_header *header, uint8_t *src_mac, uint8_t *dest_mac, uint16_t type);
