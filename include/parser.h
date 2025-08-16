// ======== parser.h ========
#ifndef _PARSER_H_
#define _PARSER_H_

#include "common.h"
#include "dns.h"
#include "network.h"
#include "arena.h"

/*
    Structures to hold parsed packet data
*/

// Parsed IP Packet
typedef struct
{
    struct iphdr *ip_header;
    const uint8_t *payload;
    size_t payload_len;
} parsed_ip_packet_t;

// Parsed UDP Packet
typedef struct
{
    struct udphdr *udp_header;
    const uint8_t *payload;
    size_t payload_len;
} parsed_udp_packet_t;

// Linked list for DNS Questions
typedef struct dns_parsed_question_s
{
    char name[256]; // Decoded domain name
    uint16_t qtype;
    uint16_t qclass;
    struct dns_parsed_question_s *next;
} dns_parsed_question_t;

// Linked list for DNS Resource Records (Answer, Authority, Additional)
typedef struct dns_parsed_rr_s
{
    char name[256]; // Decoded domain name
    uint16_t rtype;
    uint16_t rclass;
    uint32_t ttl;
    uint16_t rdlength;
    uint8_t rdata[512]; // Raw resource data
    struct dns_parsed_rr_s *next;
} dns_parsed_rr_t;

// Parsed DNS Packet
typedef struct
{
    struct dnshdr *dns_header;
    dns_parsed_question_t *questions;
    dns_parsed_rr_t *answers;
    dns_parsed_rr_t *authorities;
    dns_parsed_rr_t *additionals;
} parsed_dns_packet_t;

/*
    Packet Unpacking/Parsing Functions
*/

/**
 * @brief Parses a raw network packet to extract the IP header and its payload.
 * @param raw_packet Pointer to the start of the raw packet data.
 * @param raw_len Total length of the raw packet data.
 * @param out_packet Pointer to a structure to be filled with parsed IP data.
 * @return True on successful parsing, false otherwise.
 */
bool unpack_ip_packet(const uint8_t *raw_packet, size_t raw_len, parsed_ip_packet_t *out_packet);

/**
 * @brief Parses an IP payload to extract the UDP header and its payload.
 * @param ip_payload Pointer to the start of the IP payload (where the UDP header should be).
 * @param ip_payload_len Length of the IP payload.
 * @param out_packet Pointer to a structure to be filled with parsed UDP data.
 * @return True on successful parsing, false otherwise.
 */
bool unpack_udp_packet(const uint8_t *ip_payload, size_t ip_payload_len, parsed_udp_packet_t *out_packet);

/**
 * @brief Parses a UDP payload to extract all components of a DNS message.
 *        This function allocates memory for the linked lists, which must be freed
 *        by calling free_parsed_dns_packet().
 * @param arena Pointer to the memory arena to use for allocations.
 * @param udp_payload Pointer to the start of the UDP payload (where the DNS header should be).
 * @param udp_payload_len Length of the UDP payload.
 * @param out_dns Pointer to a structure to be filled with parsed DNS data.
 * @return True on successful parsing, false otherwise.
 */
bool unpack_dns_packet(Arena* arena, const uint8_t *udp_payload, size_t udp_payload_len, parsed_dns_packet_t *out_dns);


/**
 * @brief A utility function to print the contents of a parsed DNS packet in a human-readable format.
 * @param dns_packet The parsed DNS packet to print.
 */
void print_parsed_dns_packet(const parsed_dns_packet_t *dns_packet);

#endif // !_PARSER_H_