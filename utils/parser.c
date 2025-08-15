// ======== parser.c ========
#include "parser.h"
#include "util.h" // For alloc_memory

/*
    IP Layer Parsing
*/
bool unpack_ip_packet(const uint8_t* raw_packet, size_t raw_len, parsed_ip_packet_t* out_packet) {
    if (raw_len < sizeof(struct iphdr)) {
        return false; // Packet too small for an IP header
    }

    out_packet->ip_header = (struct iphdr*)raw_packet;
    size_t ip_header_len = out_packet->ip_header->ihl * 4;

    if (raw_len < ip_header_len) {
        return false; // Packet too small for the specified IP header length
    }

    // Check if the total length specified in the IP header is valid
    size_t total_len = ntohs(out_packet->ip_header->tot_len);
    if (total_len > raw_len) {
        return false; // Declared length is greater than actual buffer size
    }

    out_packet->payload = raw_packet + ip_header_len;
    out_packet->payload_len = total_len - ip_header_len;
    
    return true;
}

/*
    UDP Layer Parsing
*/
bool unpack_udp_packet(const uint8_t* ip_payload, size_t ip_payload_len, parsed_udp_packet_t* out_packet) {
    if (ip_payload_len < sizeof(struct udphdr)) {
        return false; // IP payload too small for a UDP header
    }

    out_packet->udp_header = (struct udphdr*)ip_payload;
    size_t udp_total_len = ntohs(out_packet->udp_header->len);
    
    if (udp_total_len > ip_payload_len) {
        return false; // Declared UDP length is greater than the containing IP payload
    }

    out_packet->payload = ip_payload + sizeof(struct udphdr);
    out_packet->payload_len = udp_total_len - sizeof(struct udphdr);

    return true;
}


/*
    DNS Layer Parsing
*/

// Helper to decompress DNS names (handles pointers)
static int dns_decompress_name(const uint8_t* packet_start, const uint8_t* current_pos, char* out_name, size_t out_len) {
    const uint8_t* p = current_pos;
    char* out_p = out_name;
    int bytes_consumed = 0;
    int jumps = 0; // To prevent infinite loops from malformed packets

    while (*p != 0 && jumps < 10) {
        // Check for a pointer (first two bits are 11)
        if ((*p & 0xC0) == 0xC0) {
            if (bytes_consumed == 0) bytes_consumed = (p - current_pos) + 2;
            
            uint16_t offset = ntohs(*(uint16_t*)p) & 0x3FFF;
            p = packet_start + offset;
            jumps++;
            continue;
        }

        // It's a length label
        uint8_t label_len = *p;
        p++;
        
        if ((out_p - out_name) + label_len + 1 >= out_len) return -1; // Buffer overflow
        
        memcpy(out_p, p, label_len);
        p += label_len;
        out_p += label_len;
        *out_p = '.';
        out_p++;
    }

    if (bytes_consumed == 0) {
        bytes_consumed = (p - current_pos) + 1; // +1 for the final null byte
    }
    
    if (out_p > out_name) {
        *(out_p - 1) = '\0'; // Replace last dot with null terminator
    } else {
        *out_p = '\0';
    }

    return bytes_consumed;
}

// Helper to parse a section of Resource Records
static const uint8_t* parse_rr_section(const uint8_t* packet_start, const uint8_t* current_pos, uint16_t count, dns_parsed_rr_t** list_head) {
    dns_parsed_rr_t* tail = NULL;
    for (int i = 0; i < count; i++) {
        dns_parsed_rr_t* rr = (dns_parsed_rr_t*)alloc_memory(sizeof(dns_parsed_rr_t));
        
        int consumed = dns_decompress_name(packet_start, current_pos, rr->name, sizeof(rr->name));
        if (consumed < 0) { free(rr); return NULL; }
        current_pos += consumed;

        // Directly map the struct fields, being careful about alignment
        struct r_info* info = (struct r_info*)current_pos;
        rr->rtype = ntohs(info->type);
        rr->rclass = ntohs(info->dclass);
        rr->ttl = ntohl(info->ttl);
        rr->rdlength = ntohs(info->len);
        
        current_pos += offsetof(struct r_info, data); // Advance to data part

        if (rr->rdlength <= sizeof(rr->rdata)) {
            memcpy(rr->rdata, current_pos, rr->rdlength);
        }
        current_pos += rr->rdlength;
        
        // Append to linked list
        if (*list_head == NULL) {
            *list_head = rr;
        } else {
            tail->next = rr;
        }
        tail = rr;
    }
    return current_pos;
}


bool unpack_dns_packet(const uint8_t* udp_payload, size_t udp_payload_len, parsed_dns_packet_t* out_dns) {
    if (udp_payload_len < sizeof(struct dnshdr)) {
        return false;
    }
    
    out_dns->dns_header = (struct dnshdr*)udp_payload;
    out_dns->questions = NULL;
    out_dns->answers = NULL;
    out_dns->authorities = NULL;
    out_dns->additionals = NULL;

    const uint8_t* current_pos = udp_payload + sizeof(struct dnshdr);
    
    // Parse Questions
    uint16_t qdcount = ntohs(out_dns->dns_header->qdcount);
    dns_parsed_question_t* q_tail = NULL;
    for (int i = 0; i < qdcount; i++) {
        dns_parsed_question_t* q = (dns_parsed_question_t*)alloc_memory(sizeof(dns_parsed_question_t));
        
        int consumed = dns_decompress_name(udp_payload, current_pos, q->name, sizeof(q->name));
        if (consumed < 0) { free(q); free_parsed_dns_packet(out_dns); return false; }
        current_pos += consumed;

        q->qtype = ntohs(*(uint16_t*)current_pos);
        current_pos += 2;
        q->qclass = ntohs(*(uint16_t*)current_pos);
        current_pos += 2;

        if (out_dns->questions == NULL) {
            out_dns->questions = q;
        } else {
            q_tail->next = q;
        }
        q_tail = q;
    }

    // Parse RR sections
    current_pos = parse_rr_section(udp_payload, current_pos, ntohs(out_dns->dns_header->ancount), &out_dns->answers);
    if (!current_pos) { free_parsed_dns_packet(out_dns); return false; }
    
    current_pos = parse_rr_section(udp_payload, current_pos, ntohs(out_dns->dns_header->nscount), &out_dns->authorities);
    if (!current_pos) { free_parsed_dns_packet(out_dns); return false; }

    current_pos = parse_rr_section(udp_payload, current_pos, ntohs(out_dns->dns_header->arcount), &out_dns->additionals);
    if (!current_pos) { free_parsed_dns_packet(out_dns); return false; }

    return true;
}

void free_parsed_dns_packet(parsed_dns_packet_t* dns_packet) {
    dns_parsed_question_t* q = dns_packet->questions;
    while(q) {
        dns_parsed_question_t* next_q = q->next;
        free(q);
        q = next_q;
    }

    dns_parsed_rr_t* rr = dns_packet->answers;
    while(rr) {
        dns_parsed_rr_t* next_rr = rr->next;
        free(rr);
        rr = next_rr;
    }

    rr = dns_packet->authorities;
    while(rr) {
        dns_parsed_rr_t* next_rr = rr->next;
        free(rr);
        rr = next_rr;
    }

    rr = dns_packet->additionals;
    while(rr) {
        dns_parsed_rr_t* next_rr = rr->next;
        free(rr);
        rr = next_rr;
    }
}


void print_parsed_dns_packet(const parsed_dns_packet_t* dns_packet) {
    if (!dns_packet || !dns_packet->dns_header) return;
    
    struct dnshdr* h = dns_packet->dns_header;
    printf(";; ->>HEADER<<- opcode: QUERY, status: %d, id: %u\n", (ntohs(h->flags) >> 11) & 0xF, ntohs(h->id));
    printf(";; flags: %s; QUERY: %u, ANSWER: %u, AUTHORITY: %u, ADDITIONAL: %u\n\n",
        (ntohs(h->flags) & 0x8000) ? "qr" : "",
        ntohs(h->qdcount), ntohs(h->ancount), ntohs(h->nscount), ntohs(h->arcount));
    
    if (dns_packet->questions) {
        printf(";; QUESTION SECTION:\n");
        for (dns_parsed_question_t* q = dns_packet->questions; q; q = q->next) {
            printf(";%-30s IN\tA\n", q->name);
        }
        printf("\n");
    }

    if (dns_packet->answers) {
        printf(";; ANSWER SECTION:\n");
        for (dns_parsed_rr_t* rr = dns_packet->answers; rr; rr = rr->next) {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, rr->rdata, ip_str, INET_ADDRSTRLEN);
            printf("%-30s %-8u IN\tA\t%s\n", rr->name, rr->ttl, ip_str);
        }
        printf("\n");
    }
    
    if (dns_packet->authorities) {
        printf(";; AUTHORITY SECTION:\n");
        for (dns_parsed_rr_t* rr = dns_packet->authorities; rr; rr = rr->next) {
             char ns_name[256];
             dns_decompress_name((const uint8_t*)h, rr->rdata, ns_name, sizeof(ns_name));
             printf("%-30s %-8u IN\tNS\t%s\n", rr->name, rr->ttl, ns_name);
        }
        printf("\n");
    }

    if (dns_packet->additionals) {
        printf(";; ADDITIONAL SECTION:\n");
        for (dns_parsed_rr_t* rr = dns_packet->additionals; rr; rr = rr->next) {
            if (rr->rtype == RR_TYPE_A) {
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, rr->rdata, ip_str, INET_ADDRSTRLEN);
                printf("%-30s %-8u IN\tA\t%s\n", rr->name, rr->ttl, ip_str);
            } else {
                // Could be an OPT record, etc. Just print basic info.
                printf("%-30s %-8u IN\tTYPE %u\t(data length %u)\n", rr->name, rr->ttl, rr->rtype, rr->rdlength);
            }
        }
        printf("\n");
    }
}