/*
    UDP/IP implementation.
*/

#include "common.h"
#include "network.h"
#include "util.h"

static in_addr_t g_local_addr = 0;

/* Get local IP address. */
in_addr_t local_addr(char* target_ip) {
    // If already got.
    if (g_local_addr)
        return g_local_addr;

    int fd;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof (addr);

    errno = 0;
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
#ifdef _DEBUG
        printf("local_addr: Fail to create socket.\n");
#endif
        abort();
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(target_ip);
    addr.sin_port = htons(53);

    connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));

    getsockname(fd, (struct sockaddr *)&addr, &addr_len);
    close(fd);

    g_local_addr = addr.sin_addr.s_addr;
    return g_local_addr;
}

/* Create a new socket FD. */
int make_sockfd_for_spoof() {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (!sockfd) {
#ifdef _DEBUG
        printf("make_sockfd_for_spoof: Fail to create socket.\n");
#endif
        abort();
    }
    int tmp = 1;
    if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof(tmp)) < 0) {
#ifdef _DEBUG
        printf("make_sockfd_for_spoof: Fail to set socket options.\n");
#endif
        abort();
    }
    return sockfd;
}

/* Get socket FD for probe. */
int make_sockfd_for_probe() {
    int sockfd_probe = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (!sockfd_probe) {
#ifdef _DEBUG
        printf("make_sockfd_for_probe: Fail to create RAW Socket.\n");
#endif
        abort();
    }

    int tmp = 1;
    if(setsockopt(sockfd_probe, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof(tmp)) < 0) {
#ifdef _DEBUG
        printf("make_sockfd_for_probe: Fail to set raw socket option.\n");
#endif
        close(sockfd_probe);
        abort();
    }

    return sockfd_probe;
}

/* Get socket FD for verify. */
int make_sockfd_for_verify(signed long long verify_usec) {
    int sockfd_verify = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (!sockfd_verify) {
#ifdef _DEBUG
        printf("make_sockfd_for_verify: Fail to create RAW Socket.\n");
#endif
        abort();
    }

    struct timeval tv = {
        .tv_sec = 0,
        .tv_usec = verify_usec
    };
    int tmp = 1;
    if(setsockopt(sockfd_verify, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof(tmp)) < 0) {
#ifdef _DEBUG
        printf("make_sockfd_for_verify: Fail to set raw socket option.\n");
#endif
        abort();
    }
    if(setsockopt(sockfd_verify, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
#ifdef _DEBUG
        printf("make_sockfd_for_verify: Fail to set raw socket option.\n");
#endif
        abort();
    }

    return sockfd_verify;
}

/* Get socket FD for DNS client and server. */
int make_sockfd_for_dns(unsigned int timeout_sec) {
    int sockfd_udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (!sockfd_udp) {
#ifdef _DEBUG
        printf("make_sockfd_for_dns: Fail to create RAW Socket.\n");
#endif
        abort();
    }

    struct timeval tv = {
        .tv_sec = timeout_sec,
        .tv_usec = 0
    };
    if(setsockopt(sockfd_udp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
#ifdef _DEBUG
        printf("make_sockfd_for_dns: Fail to set socket option.\n");
#endif
        abort();
    }

    return sockfd_udp;
}

/* IP packet checksum. */
static uint16_t ip_checksum(unsigned short *buf, int count) {
    register uint64_t sum = 0;

    while (count > 1) {
        sum += *buf++;
        count -= 2;
    }
    if (count > 0) {
        sum += *(unsigned char *)buf;
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

/* UDP checksum. */
static uint16_t udp_checksum(struct iphdr *iph, void *buff, uint16_t data_len, int len) {
    const uint16_t *buf = buff;
    uint32_t ip_src = iph->saddr;
    uint32_t ip_dst = iph->daddr;
    uint32_t sum = 0;
    int length = len;
    
    while (len > 1) {
        sum += *buf;
        buf++;
        len -= 2;
    }

    if (len == 1)
        sum += *((uint8_t *) buf);

    sum += (ip_src >> 16) & 0xFFFF;
    sum += ip_src & 0xFFFF;
    sum += (ip_dst >> 16) & 0xFFFF;
    sum += ip_dst & 0xFFFF;
    sum += htons(iph->protocol);
    sum += data_len;

    while (sum >> 16) 
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)(~sum);
}

/* Make an UDP packet. */
size_t make_udp_packet(uint8_t* buff_in, size_t len_in, uint32_t src_addr, uint32_t dst_addr,
        uint16_t src_port, uint16_t dst_port, uint8_t* payload, size_t payload_len) {
    // Check length.
    if (len_in < sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len) {
#ifdef _DEBUG
        printf("make_udp_packet: len_in is not enough.\n");
#endif
        abort();
    }
    
    struct iphdr* iph = (struct iphdr*)buff_in;
    struct udphdr* udph = (struct udphdr*)(buff_in + sizeof(struct iphdr));
    uint8_t* pay = buff_in + sizeof(struct iphdr) + sizeof(struct udphdr);

    // IP header. (fix the htons)
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len);
    // iph->id = htons(rand() % 65535 + 1);
    iph->id = htons(1);
    iph->frag_off = 0;
    iph->ttl = MAXTTL;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = src_addr;
    iph->daddr = dst_addr;

    // UDP header.
    udph->len = htons(sizeof(struct udphdr) + payload_len);
    udph->source = htons(src_port);
    udph->dest = htons(dst_port);
    udph->check = 0;

    // Copy payload.
    memcpy(pay, payload, payload_len);

    return sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len;
}

/* Split UDP packet into fragments */

size_t frag_udp_packet(uint8_t* packet, size_t packet_len, uint8_t** packets_ptrptr) {
    // TODO: Implement fragmentation logic.
    if (packet_len <= MTU) {

#ifdef _DEBUG
        printf("frag_udp_packet: No fragmentation needed.\n");
#endif
        return -1;
    } else {
        // offset in the udp's
        uint16_t offset = 0;
        // same use as offset, the remaining length need fraging
        uint16_t len = packet_len - sizeof(struct iphdr);
        // original IP header
        struct iphdr* origin_iph = (struct iphdr*)packet;
        // fragments
        size_t frag = 0;
        // max payload can be used in the case
        size_t payload = (MTU - sizeof(struct iphdr)) & ~7;
        for (frag = 0; frag < MAX_FRAGMENTS; frag++) {
            if (len == 0) {
#ifdef _DEBUG
                printf("frag_udp_packet: frag already over with %d packets(MAX is %d)\n", frag, MAX_FRAGMENTS);
#endif
                break;
            }
            uint8_t* packets_ptr = *(packets_ptrptr + frag);
            struct iphdr* iph = (struct iphdr*)packets_ptr;
            uint8_t* packet_payload = (uint8_t*)(packets_ptr + sizeof(struct iphdr));
            uint8_t* origin_packet = packet + offset + sizeof(struct iphdr); 
            memcpy(iph, origin_iph, sizeof(struct iphdr));
            memcpy(packet_payload, origin_packet, MIN(payload, len));
            iph->tot_len = htons((uint16_t)(len > payload) ? MTU : len + sizeof(struct iphdr));
            uint16_t mf_flag = (len > payload) ? 0x2000 : 0;

            iph->frag_off = htons((offset / 8) | mf_flag);
            // iph->check = ip_checksum((uint16_t*)iph, ntohs(iph->tot_len));
            iph->check = ip_checksum((uint16_t*)iph, sizeof(struct iphdr));
            len -= (payload > len) ? len : payload;
            offset += payload;
        }
        if (len > 0) {
#ifdef _DEBUG
            printf("frag_udp_packet: error, packets too large!!!\n");
#endif
            return -1;
        }
        return frag;
    }
}

/* Free used space */
void free_space(uint8_t** space_ptr, size_t len) {
    for (size_t i = 0; i < len; i++) {
        uint8_t* space = *(space_ptr + i);
        free(space);
    }
    free(space_ptr);
}

/* Send UDP packet to given target. */
void send_udp_packet(int sockfd, uint8_t* packet, size_t packet_len, uint32_t src_addr,
        uint32_t dst_addr, uint16_t src_port, uint16_t dst_port) {
    struct iphdr* iph = (struct iphdr*)packet;
    struct udphdr* udph = (struct udphdr*)(packet + sizeof(struct iphdr));

    // Set values in packet.
    iph->saddr = src_addr;
    iph->daddr = dst_addr;
    udph->uh_sport = htons(src_port);
    udph->uh_dport = htons(dst_port);
    udph->check = 0;
    udph->check = udp_checksum(iph, udph, udph->len, ntohs(udph->len));
    iph->check = 0;

    // later to check the IP 
    // iph->check = ip_checksum((uint16_t*)packet, iph->tot_len);
    
    // Set values in sockaddr.
    struct sockaddr_in dest_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(dst_port),
        .sin_addr.s_addr = dst_addr
    };
    memset(dest_addr.sin_zero, '\x00', sizeof(dest_addr.sin_zero));

    // Send packet.
    size_t len;
    if (packet_len <= MTU) {
        iph->check = ip_checksum((uint16_t*)packet, sizeof(struct iphdr));
        len = sendto(sockfd, packet, packet_len, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
        if (len < 0) {
#ifdef _DEBUG
            perror("send_udp_packet_raw");
#endif
            abort();
        }
    } else {
        uint8_t** packets_ptrptr = (uint8_t**)alloc_memory(sizeof(uint8_t*) * MAX_FRAGMENTS);
        for (size_t i = 0; i < MAX_FRAGMENTS; i++) {
            *(packets_ptrptr + i) = (uint8_t*)alloc_memory(MTU * sizeof(uint8_t));    
        }
        size_t num = frag_udp_packet(packet, packet_len, packets_ptrptr);
        if (0 < num && num <= MAX_FRAGMENTS) {
            for (size_t i = 0; i < num; i++) {
                uint8_t* packets_ptr = *(packets_ptrptr + i);
                size_t plen = ntohs(((struct iphdr*)packets_ptr)->tot_len);
                len = sendto(sockfd, packets_ptr, plen, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
                if (len < 0) {
#ifdef _DEBUG
                    perror("send_udp_packet_raw");
#endif
                    free_space(packets_ptrptr, MAX_FRAGMENTS);
                    abort();
                }
            }
        }
        free_space(packets_ptrptr, MAX_FRAGMENTS);
    }
}

/* 
    Send only selected fragments
*/

void send_sltd_udp_packet(
    int sockfd, 
    uint8_t* packet, 
    size_t packet_len, 
    uint32_t src_addr,
    uint32_t dst_addr, 
    uint16_t src_port, 
    uint16_t dst_port,
    struct sendres* pos
) {
    struct iphdr* iph = (struct iphdr*)packet;
    struct udphdr* udph = (struct udphdr*)(packet + sizeof(struct iphdr));

    // Set values in packet.
    iph->saddr = src_addr;
    iph->daddr = dst_addr;
    udph->uh_sport = htons(src_port);
    udph->uh_dport = htons(dst_port);
    udph->check = 0;
    udph->check = udp_checksum(iph, udph, udph->len, ntohs(udph->len));
    iph->check = 0;

    // later to check the IP 
    // iph->check = ip_checksum((uint16_t*)packet, iph->tot_len);
    
    // Set values in sockaddr.
    struct sockaddr_in dest_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(dst_port),
        .sin_addr.s_addr = dst_addr
    };
    memset(dest_addr.sin_zero, '\x00', sizeof(dest_addr.sin_zero));

    // Send packet.
    size_t len;
    if (packet_len <= MTU) {
#ifdef _DEBUG
        printf("send_sltd_udp_packet: packet too small\n");
#endif
        abort();
    } else {
        uint8_t** packets_ptrptr = (uint8_t**)alloc_memory(sizeof(uint8_t*) * MAX_FRAGMENTS);
        for (size_t i = 0; i < MAX_FRAGMENTS; i++) {
            *(packets_ptrptr + i) = (uint8_t*)alloc_memory(MTU * sizeof(uint8_t));    
        }
        size_t num = frag_udp_packet(packet, packet_len, packets_ptrptr);
        if (0 < num && num <= MAX_FRAGMENTS) {
            bool shbe_sent[num];
            memset(shbe_sent, 0, sizeof(shbe_sent));
            for (size_t i = 0; i < pos->count; i++) {
                int pac = pos->positions[i];
                if (pac < 0 || pac >= num) {
#ifdef _DEBUG
                    printf("send_sltd_udp_packet: invalid pos %d(0 < pos < %d)\n", pac, num);
#endif
                }
                shbe_sent[pac] = true;
            }
            for (size_t i = 0; i < num; i++) {
                if (!shbe_sent[i]) continue;
                uint8_t* packets_ptr = *(packets_ptrptr + i);
                size_t plen = ntohs(((struct iphdr*)packets_ptr)->tot_len);
                len = sendto(sockfd, packets_ptr, plen, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
                if (len < 0) {
#ifdef _DEBUG
                    perror("send_udp_packet_raw");
#endif
                    free_space(packets_ptrptr, MAX_FRAGMENTS);
                    abort();
                }
            }
        }
        free_space(packets_ptrptr, MAX_FRAGMENTS);
    }
}
