#include <stdio.h>
#include <arpa/inet.h>
#include "protocol.h"
#include "sendpacket.h"

int main(){
    const char *ip_str = "10.1.1.2";
    uint32_t targetIp = inet_addr(ip_str);

    if (targetIp == INADDR_NONE) {
        fprintf(stderr, "Invalid IP address format: %s\n", ip_str);
        return 1;
    }
    while(1){
        send_arp_packet(targetIp);
    }
    return 0;
}