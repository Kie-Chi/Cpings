#ifndef _SENDER_H_
#define _SENDER_H_

#include "common.h"
#include "dns.h"
#include "network.h"
#include "util.h"
#include <uv.h>
#include <fcntl.h>
#define NOERROR 0
#define BROKEN_ERROR -1 // 缺失必要属性
#define INIT_ERROR -2 // 初始化失败
#define MAKE_ERROR -3 // 生成数据包失败
#define SEND_ERROR -4 // 发送数据包失败

typedef struct packet_s packet_t;
typedef struct packet_queue_s packet_queue_t;
typedef struct packet_work_s packet_work_t;
typedef struct sender_strategy_s sender_strategy_t;
typedef struct sender_s sender_t;
typedef bool (*make_packet_func)(packet_queue_t *queue, void *args);
typedef bool (*make_packet_init)(packet_queue_t **queue_ptr);
typedef void (*packet_free)(packet_queue_t *packet);
typedef ssize_t (*send_packet_func)(sender_t *sender, packet_t *packet, void *send_args);
typedef bool (*stop_func)(void* state);
typedef void (*free_func)(void* data);

struct packet_s {
    uint8_t* data;
    size_t size;
    size_t capacity;
    packet_t* next;
    // Options...
};

typedef struct {
    char* src_ip;
    char* dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    char* domain_name;

    // More Options
} default_make_args_t;

typedef struct {
    default_make_args_t default_args;

    uint32_t count;
} pps_make_args_t;

typedef struct {
    // NULL, but can add more things
    // More Options 
} default_send_args_t;

typedef struct {
    uv_work_cb build_cb;
    uv_after_work_cb after_build_cb;
    make_packet_init init_func;
    packet_free free_func;
    make_packet_func make_func;
    void* packet_args;

    // More Options
} default_strategy_data_t;

struct packet_queue_s {
    packet_t* head;
    packet_t* tail;
};

struct packet_work_s {
    uv_work_t work_req;

    int error_code;
    packet_queue_t* queue;

    sender_t* sender_handle;
    // Options...
};

struct sender_strategy_s {
    void (*start)(sender_t* sender, void* strategy_data);
    void (*stop)(sender_t* sender, void* strategy_data);
    void (*free_data)(void* strategy_data);
    send_packet_func send_func;
    void *send_args;
    void* data; // strategy_data_t
};

struct sender_s {
    uv_loop_t* loop;
    
    uv_poll_t* poll_handle;
    uv_async_t* stop_async;
    int sockfd;
    struct sockaddr_in addr;

    sender_strategy_t* strategy;
    packet_queue_t* send_queue;

    volatile bool is_running;

    uv_timer_t* stop_timer;
    stop_func stop_func;
    void* state;
    free_func free_func;
};


void default_free(packet_queue_t* queue);
bool default_init(packet_queue_t** queue_ptr);
bool default_make(packet_queue_t* queue, void* args);
ssize_t default_send(sender_t* sender, packet_t* packet, void* send_args);
void default_build_work_cb(uv_work_t *req);
void default_after_work_cb(uv_work_t *req, int status);
bool pps_make(packet_queue_t *queue, void *args);

int sender_init(sender_t *sender, uv_loop_t *loop, const char *ip, int port);
int sender_set_strategy(sender_t *sender, sender_strategy_t* strategy); 
void sender_free(sender_t *sender);
void sender_start(sender_t *sender);
void sender_stop(sender_t *sender);
void sender_poll_cb(uv_poll_t *handle, int status, int events);
void sender_add_to_queue(sender_t *sender, packet_queue_t *packet_queue);
int sender_set_stop_cond(
    sender_t *sender,
    stop_func stop_func,
    void *state,
    free_func free_func,
    uint64_t interval // MilliSeconds
);

#endif