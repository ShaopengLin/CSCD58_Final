#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>  

#include "utils.h"
#include "protocol.h"
#include <semaphore.h>
#include <time.h>




// Go over the linked list, if find same id, return the head, else return NULL
struct icmp_list * check_list(struct icmp_echo *receive_icmp_header, struct icmp_list *head){
    if(head == NULL) return NULL;
    if(receive_icmp_header->identifier == head->id) return head;
    return(check_list(receive_icmp_header, head->next));
}



double handle_icmp(unsigned char * buffer, struct icmp_list *head){
    // Create a end time to see time interval of packet
    double time;
    uint64_t end = getNano();
    struct icmp_echo *receive_icmp_header = (struct icmp_echo *)(buffer + sizeof(struct ethhdr) + sizeof(struct ip_header));

    // Check if receive icmp id is in out linked list
    struct icmp_list * temp = check_list(receive_icmp_header, head);

    if(temp == NULL){
        printf("Not IN List: %hu\n", (unsigned int)receive_icmp_header->identifier);
        return -1;
    } 

    // Return time interval
    time = end - temp->start;

    return (long double)time/1000000;
} 