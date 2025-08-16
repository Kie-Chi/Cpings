#ifndef _SENDER_H_
#define _SENDER_H_

#include "common.h"
#include "dns.h"
#include "network.h"
#include "util.h"
#include "arena.h"
#include <uv.h>
#include <fcntl.h>
#define NOERROR 0
#define BROKEN_ERROR -1 // lack of necessary attributes
#define INIT_ERROR -2 // initialization failed
#define MAKE_ERROR -3 // packet creation failed
#define SEND_ERROR -4 // packet sending failed

typedef struct packet_s packet_t;
typedef struct packet_queue_s packet_queue_t;
typedef struct packet_batch_s packet_batch_t;
typedef struct sender_queue_s sender_queue_t;
typedef struct packet_work_s packet_work_t;
typedef struct sender_strategy_s sender_strategy_t;
typedef struct sender_s sender_t;
typedef bool (*make_packet_func)(Arena* arena, packet_queue_t* queue, void *args);
typedef ssize_t (*send_packet_func)(sender_t *sender, packet_t *packet, void *send_args);
typedef bool (*stop_func)(void* state);
typedef void (*free_func)(void* data);

/*
    Class: packet_t
    Type: packet

    Class used to describe a packet
    Parent Class of All packet types
    
    void -> packet_t
*/
struct packet_s {
    uint8_t* data; // Raw data of packet
    size_t size; // Size of Raw data
    struct sockaddr_in dest_addr; // NULL for use sender default sockaddr
    packet_t* next; // Pointer to next packet in the queue
    // Options...
};

/*
    Class: default_make_args_t
    Type: packet-make-args

    Class used to how to make a packet
    Parent Class of All packet-make-args types

    void -> default_make_args_t
*/
typedef struct {
    char* src_ip; // Source IP of packet
    char* dst_ip; // Dest IP of packet
    uint16_t src_port; // Source port of packet
    uint16_t dst_port; // Dest port of packet
    char* domain_name; // Domain of packet

    // More Options
} default_make_args_t;

/*
    Class: pps_make_args_t
    Type: packet-make-args
    
    Class used to describe how to make a pps-strategy-packet

    default_make_args_t -> pps_make_args_t
*/
typedef struct {
    default_make_args_t default_args;

    uint32_t count;
} pps_make_args_t;


/*
    Class: default_send_args_t
    Type: packet-send-args

    Class used to describe how to send a packet
    Parent Class of All packet-send-args types

    void -> default_send_args_t
*/
typedef struct {
    // NULL, but can add more things
    // More Options 
} default_send_args_t;


/*
    Class: default_strategy_data_t
    Type: strategy-data

    Class used to describe what strategy can do
    Parent Class of All strategy-data types

    void -> default_strategy_data_t
*/
typedef struct {
    uv_work_cb build_cb;
    uv_after_work_cb after_build_cb;
    make_packet_func make_func;
    void* packet_args;
    free_func free_packet_args_func;

    // More Options
} default_strategy_data_t;


/*
    Class used to define maker-queue of packets
*/
struct packet_queue_s {
    packet_t* head;
    packet_t* tail;
};


/*
    Wrapper used to manage packets and memory
*/
struct packet_batch_s {
    packet_queue_t packets;
    Arena arena;
    packet_batch_t* next;
};


/*
    Class used to define a batch of packets
*/
struct sender_queue_s {
    packet_batch_t* head;
    packet_batch_t* tail;
};


/*
    Class: packet_work_t
    Type: packet-make-task

    Class used to describe a packet-make task
    Parent Class of All packet-make-task types

    void -> packet_work_t
*/
struct packet_work_s {
    uv_work_t work_req;

    int error_code;
    packet_batch_t* batch;

    sender_t* sender_handle;
    // Options...
};

/*
    Class: sender_strategy_t
    Type: sender-strategy

    Class used to describe what and how a sender can do
*/
struct sender_strategy_s {
    void (*start)(sender_t* sender, void* strategy_data);
    void (*stop)(sender_t* sender, void* strategy_data);
    void (*free_data)(void* strategy_data);
    send_packet_func send_func;
    void *send_args;
    free_func free_send_args_func;
    void* data; // strategy_data_t
};


/*
    Class: sender_t

    Class used to describe a sender
*/
struct sender_s {
    uv_loop_t* loop;
    
    uv_poll_t* poll_handle;
    int sockfd;
    struct sockaddr_in addr; // will not be used if packet has addr

    sender_strategy_t* strategy;
    sender_queue_t* send_queue; // Queue of packets to send
    packet_batch_t* current_batch;
    packet_t* current_packet;

    volatile bool is_running;

    uv_async_t *stop_async;
    uv_timer_t* stop_timer;
    stop_func stop_func;
    void* state;
    free_func free_func;
};


bool default_make(Arena* arena, packet_queue_t* queue, void* args);
ssize_t default_send(sender_t* sender, packet_t* packet, void* send_args);
void default_build_work_cb(uv_work_t *req);
void default_after_work_cb(uv_work_t *req, int status);
void free_batch_queue(sender_queue_t *queue);
bool pps_make(Arena *arena, packet_queue_t *queue, void *args);

int sender_init(sender_t *sender, uv_loop_t *loop, const char *ip, int port);
int sender_set_strategy(sender_t *sender, sender_strategy_t* strategy); 
void sender_free(sender_t *sender);
void sender_start(sender_t *sender);
void sender_stop(sender_t *sender);
void sender_poll_cb(uv_poll_t *handle, int status, int events);
void sender_add_batch_to_queue(sender_t *sender, packet_batch_t *batch);
int sender_set_stop_cond(
    sender_t *sender,
    stop_func stop_func,
    void *state,
    free_func free_func,
    uint64_t interval // MilliSeconds
);

#endif