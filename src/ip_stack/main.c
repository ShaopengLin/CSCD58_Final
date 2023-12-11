#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <pthread.h>      // pthread library
#include <unistd.h>
#include <semaphore.h>

#include <time.h>

#include "utils.h"
// #include "protocol.h"
#include "sendpacket.h"
#include "handlepacket.h"
#include <float.h>
#include <arpa/inet.h>

pthread_mutex_t mutex;
struct arp_header* receive_arp_header;
struct icmp_list *head = NULL;

// Functions about icmp list

// Create a new node with a icmp ID and send time
struct icmp_list* create_node(uint16_t id, uint64_t start) {
    struct icmp_list *new_node = malloc(sizeof(struct icmp_list));
    if (new_node != NULL) {
        new_node->id = id;
        new_node->start = start;
        new_node->next = NULL;
    }
    return new_node;
}

// Insert to linked list when send a icmp echo
void insert_at_head(uint16_t id, uint64_t start) {
    struct icmp_list *new_node = create_node(id, start);
    if (new_node != NULL) {
        new_node->next = head;
        head = new_node;
    }
}

// Clear all list
void free_list() {
    struct icmp_list *tmp;
    while (head != NULL) {
        tmp = head;
        head = head->next;
        free(tmp);
    }
}



// Receive packet function
void *packet_receiver(void *arg) {
    int sock_r = *(int*)arg;
    unsigned char *buffer = (unsigned char *) malloc(65536);
    memset(buffer, 0, 65536);
    struct sockaddr_ll saddr;
    int saddr_len = sizeof(saddr);
    int arp_check = 1; 
    int i = 0;

    // Clear the output file
    FILE *filePtr;
    filePtr = fopen("log", "w");
    fclose(filePtr);

    while(1) {
        // Receive all packet passing through out device
        int buflen = recvfrom(sock_r, buffer, 65536, 0, (struct sockaddr*)&saddr, (socklen_t *)&saddr_len);
        if (buflen < 0) {
            printf("Error in reading recvfrom function\n");
            break; // Exit loop on error
        }

        if (saddr.sll_pkttype == PACKET_OUTGOING) {
            continue; // Skip processing packet outgoing
        }

        struct ethhdr *eth_header = (struct ethhdr *)buffer;
        if (ntohs(eth_header->h_proto) == ETH_P_ARP && arp_check) {
            printf("Received ARP packet\n");
            // Receive ARP Packet
            pthread_mutex_lock(&mutex);
            memcpy(receive_arp_header, buffer + sizeof(struct ethhdr), sizeof(struct arp_header));
            pthread_mutex_unlock(&mutex);
            arp_check = 0;
        } 
        else if (ntohs(eth_header->h_proto) == ETH_P_IP) {
            struct iphdr *ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));
            if (ip_header->protocol == IPPROTO_ICMP) {
                
                printf("Received ICMP packet\n");
                // Receive ICMP Packet
                filePtr = fopen("log", "a");
                char str[50];

                pthread_mutex_lock(&mutex);
                double x = handle_icmp(buffer, head);
                pthread_mutex_unlock(&mutex);

                if(x != -1){
                    sprintf(str, "%d %f\n", i,x);
                }
                
                
                fputs(str, filePtr);
                fclose(filePtr);
                i++;
            }
        }
    }

    free(buffer);
    return NULL;
}

int main(int argc, char** argv) {
    //------------------------------------------------------------------------------
        // Command Line Arguments
    //------------------------------------------------------------------------------
    if (pthread_mutex_init(&mutex, NULL)!=0){
        exit(-1);
    }
    int packet_to_send = 1;
    int packet_size = 0;
    int packet_interval = 1;
    const char *ip_str = NULL;

        for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0) {
            // Next argument is the number of packets to send
            if (i + 1 < argc) {
                packet_to_send = atoi(argv[++i]);
            } else {
                fprintf(stderr, "Option -c requires a numeric argument.\n");
                return 1;
            }
        } else if (strcmp(argv[i], "-s") == 0) {
            // Next argument is the packet size
            if (i + 1 < argc) {
                packet_size = atoi(argv[++i]);
            } else {
                fprintf(stderr, "Option -s requires a numeric argument.\n");
                return 1;
            }
        } else if (strcmp(argv[i], "-i") == 0) {
            // Next argument is the packet interval
            if (i + 1 < argc) {
                packet_interval = atoi(argv[++i]);
            } else {
                fprintf(stderr, "Option -i requires a numeric argument.\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "-ip") == 0) {
            // Next argument is the IP address
            if (i + 1 < argc) {
                ip_str = argv[++i];
            } else {
                fprintf(stderr, "Option -ip requires an IP address argument.\n");
                return 1;
            }
        }
    }

    if(packet_size > 500) packet_size = 500;
    
    // Display the values for testing purposes
    printf("Packet to send: %d\n", packet_to_send);
    printf("Packet size: %d\n", packet_size);
    printf("Packet interval: %d\n", packet_interval);
    if(ip_str == NULL){
        printf("IP required\n");
        return -1;
    }
    
    //------------------------------------------------------------------------------
        // initialize
    //------------------------------------------------------------------------------
    int sock_r;
    pthread_t thread_id;
    sock_r = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sock_r < 0) {
        perror("Socket Error");
        return -1;
    }
    // Create a separate thread for receiving packets
    if(pthread_create(&thread_id, NULL, packet_receiver, &sock_r)) {
        fprintf(stderr, "Error creating thread\n");
        return -1;
    }
    //------------------------------------------------------------------------------

    
    uint32_t targetIp = inet_addr(ip_str);
    if (targetIp == INADDR_NONE) {
        fprintf(stderr, "Invalid IP address format: %s\n", ip_str);
        return 1;
    }
    receive_arp_header = malloc(sizeof(struct arp_header));
    if (!receive_arp_header) {
        perror("Memory allocation for receive_arp_header failed");
        exit(EXIT_FAILURE);
    }

    send_arp_packet(targetIp);
    sleep(1);
    
    for(int i=0; i<packet_to_send; i++){
        pthread_mutex_lock(&mutex); 
        insert_at_head(send_ip_packet(receive_arp_header,packet_size), getNano());
        pthread_mutex_unlock(&mutex); 
        sleep(packet_interval);
    }

    pthread_mutex_destroy(&mutex);
    free_list();
    
    free(receive_arp_header);
    close(sock_r);

        FILE *file;
    file = fopen("log", "r");

    if (file == NULL) {
        perror("Error opening file");
        return -1;
    }

    double value, min = DBL_MAX, max = -DBL_MAX, sum = 0;
    int count = 0;
    while (fscanf(file, "%*d %lf", &value) == 1) {
        if (value < min) min = value;
        if (value > max) max = value;
        sum += value;
        count++;
    }

    fclose(file);

    if (count > 0) {
        double average = sum / count;
        printf("Min: %f\nMax: %f\nAverage: %f\n", min, max, average);
    } else {
        printf("No data or invalid data format.\n");
    }
    return 0;
}
