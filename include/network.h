/*
    UDP/IP implementation.
*/

#ifndef _NETWORK_H_
#define _NETWORK_H_

#include "common.h"
#include "arena.h"

in_addr_t local_addr(char* target_ip);

int make_sockfd_for_spoof();

int make_sockfd_for_probe();

int make_sockfd_for_verify(signed long long verify_usec);

int make_sockfd_for_dns(unsigned int timeout_sec);

size_t make_udp_packet(uint8_t* buff_in, size_t len_in, uint32_t src_addr, uint32_t dst_addr,
        uint16_t src_port, uint16_t dst_port, uint8_t* payload, size_t payload_len);

void send_udp_packet(Arena* arena, int sockfd, uint8_t* packet, size_t packet_len, uint32_t src_addr,
        uint32_t dst_addr, uint16_t src_port, uint16_t dst_port);

struct sendres {
    int* positions; // 动态数组，
    size_t count;
};

void send_sltd_udp_packet(
    Arena* arena,
    int sockfd,
    uint8_t *packet,
    size_t packet_len,
    uint32_t src_addr,
    uint32_t dst_addr,
    uint16_t src_port,
    uint16_t dst_port,
    struct sendres *pos);

#define MTU 1500
#define MAX_FRAGMENTS 6


#endif // !_NETWORK_H
