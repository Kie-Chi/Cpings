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
static const uint8_t* parse_rr_section(Arena* arena, const uint8_t* packet_start, const uint8_t* current_pos, uint16_t count, dns_parsed_rr_t** list_head) {
    ARENA_ASSERT(arena != NULL);
    dns_parsed_rr_t* tail = NULL;
    for (int i = 0; i < count; i++) {
        dns_parsed_rr_t* rr = (dns_parsed_rr_t*)arena_alloc_memory(arena, sizeof(dns_parsed_rr_t));
        
        int consumed = dns_decompress_name(packet_start, current_pos, rr->name, sizeof(rr->name));
        if (consumed < 0) {
            return NULL; 
        }
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


bool unpack_dns_packet(Arena* arena, const uint8_t* udp_payload, size_t udp_payload_len, parsed_dns_packet_t* out_dns) {
    ARENA_ASSERT(arena != NULL);

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
        dns_parsed_question_t* q = (dns_parsed_question_t*)arena_alloc_memory(arena, sizeof(dns_parsed_question_t));
        
        int consumed = dns_decompress_name(udp_payload, current_pos, q->name, sizeof(q->name));
        if (consumed < 0) {
            return false; 
        }
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
    current_pos = parse_rr_section(arena, udp_payload, current_pos, ntohs(out_dns->dns_header->ancount), &out_dns->answers);
    if (!current_pos) {
        return false;
    }

    current_pos = parse_rr_section(arena, udp_payload, current_pos, ntohs(out_dns->dns_header->nscount), &out_dns->authorities);
    if (!current_pos) {
        return false;
    }

    current_pos = parse_rr_section(arena, udp_payload, current_pos, ntohs(out_dns->dns_header->arcount), &out_dns->additionals);
    if (!current_pos) {
        return false;
    }

    return true;
}

// Helper lambda/function for printing different RR types
    // This avoids code duplication between sections
    void print_rr(struct dnshdr* h, const char* section_name, dns_parsed_rr_t* rr_list) {
        if (!rr_list) return;
        printf(";; %s SECTION:\n", section_name);
        for (dns_parsed_rr_t* rr = rr_list; rr; rr = rr->next) {
            switch (rr->rtype) {
                case RR_TYPE_A: {
                    char ip_str[INET_ADDRSTRLEN];
                    if (rr->rdlength == 4) {
                         inet_ntop(AF_INET, rr->rdata, ip_str, INET_ADDRSTRLEN);
                         printf("%-30s %-8u IN\tA\t%s\n", rr->name, rr->ttl, ip_str);
                    }
                    break;
                }
                case RR_TYPE_NS:
                case RR_TYPE_CNAME: {
                    char rdata_name[256] = {0};
                    // The first argument to decompress must be the start of the whole DNS packet
                    dns_decompress_name((const uint8_t*)h, rr->rdata, rdata_name, sizeof(rdata_name));
                    const char* type_str = (rr->rtype == RR_TYPE_NS) ? "NS" : "CNAME";
                    printf("%-30s %-8u IN\t%s\t%s\n", rr->name, rr->ttl, type_str, rdata_name);
                    break;
                }
                default: {
                    printf("%-30s %-8u IN\tTYPE %-5u\t(data length %u)\n", rr->name, rr->ttl, rr->rtype, rr->rdlength);
                    break;
                }
            }
        }
        printf("\n");
    }

void print_parsed_dns_packet(const parsed_dns_packet_t* dns_packet) {
    if (!dns_packet || !dns_packet->dns_header) return;
    
    struct dnshdr* h = dns_packet->dns_header;
    int rcode = ntohs(h->flags) & DNS_MASK_RCODE;
    // Note: This opcode parsing is slightly off. Opcode is in the middle of flags.
    int opcode = (ntohs(h->flags) & DNS_MASK_OPCODE) >> DNS_SHIFT_OPCODE;

    printf(";; ->>HEADER<<- opcode: %d, status: %d, id: %u\n", opcode, rcode, ntohs(h->id));
    printf(";; flags: %s%s%s%s%s; QUERY: %u, ANSWER: %u, AUTHORITY: %u, ADDITIONAL: %u\n\n",
        (ntohs(h->flags) & DNS_FLAG_QR) ? "qr " : "",
        (ntohs(h->flags) & DNS_FLAG_AA) ? "aa " : "",
        (ntohs(h->flags) & DNS_FLAG_TC) ? "tc " : "",
        (ntohs(h->flags) & DNS_FLAG_RD) ? "rd " : "",
        (ntohs(h->flags) & DNS_FLAG_RA) ? "ra" : "",
        ntohs(h->qdcount), ntohs(h->ancount), ntohs(h->nscount), ntohs(h->arcount));
    
    if (dns_packet->questions) {
        printf(";; QUESTION SECTION:\n");
        for (dns_parsed_question_t* q = dns_packet->questions; q; q = q->next) {
            // Assuming QTYPE A for simplicity, a full implementation would check q->qtype
            printf(";%-30s IN\tA\n", q->name);
        }
        printf("\n");
    }

    print_rr(h, "ANSWER", dns_packet->answers);
    print_rr(h, "AUTHORITY", dns_packet->authorities);
    print_rr(h, "ADDITIONAL", dns_packet->additionals);
}